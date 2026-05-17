from __future__ import annotations

import json
import logging
import queue
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Tuple

from ibc_monitor.config import Config
from ibc_monitor.metrics import (
    ACKNOWLEDGED_PACKETS,
    ACK_PACKET_EVENTS,
    CHANNEL_LABELS,
    INFLIGHT_PACKET_OLDEST_SEQ,
    INFLIGHT_PACKET_OLDEST_TIMESTAMP,
    INFLIGHT_PACKET_SIZE,
    ORPHAN_PACKET_EVENTS,
    PACKET_ACK_DURATION,
    PACKET_INDEXER_ERRORS,
    PACKET_INDEXER_LAST_EVENT_TIME,
    PACKET_INDEXER_LAST_PROCESSED_HEIGHT,
    PACKET_INDEXER_QUEUE_SIZE,
    PACKET_RELAY_DURATION,
    PACKET_TIMEOUT_DURATION,
    PENDING_ACK_PACKET_OLDEST_SEQ,
    PENDING_ACK_PACKET_OLDEST_TIMESTAMP,
    PENDING_ACK_PACKET_SIZE,
    RECV_PACKET_EVENTS,
    RPC_ENDPOINT_SWITCHES,
    RPC_ERRORS,
    RPC_HEALTH,
    RPC_LATEST_BLOCK_HEIGHT,
    RPC_LATEST_BLOCK_TIMESTAMP,
    SEND_PACKET_EVENTS,
    SUCCESSFULLY_RELAYED_PACKETS,
    TIMED_OUT_PACKETS,
    TIMEOUT_PACKET_EVENTS,
    WEBSOCKET_HEALTH,
    WEBSOCKET_RECONNECTS,
    WRITE_ACK_PACKET_EVENTS,
)
from ibc_monitor.packet_events import (
    DESTINATION_CHAIN_EVENTS,
    PacketEvent,
    SOURCE_CHAIN_EVENTS,
    extract_block_timestamp,
    extract_height,
    parse_packet_events,
)
from ibc_monitor.packet_store import PacketLifecycleSummary, PacketStore
from ibc_monitor.rpc_client import RPCClient, parse_rpc_time

logger = logging.getLogger(__name__)

PACKET_SUBSCRIPTIONS = (
    "tm.event='Tx' AND send_packet.packet_sequence EXISTS",
    "tm.event='Tx' AND recv_packet.packet_sequence EXISTS",
    "tm.event='Tx' AND write_acknowledgement.packet_sequence EXISTS",
    "tm.event='Tx' AND acknowledge_packet.packet_sequence EXISTS",
    "tm.event='Tx' AND timeout_packet.packet_sequence EXISTS",
    "tm.event='Tx' AND timeout_on_close_packet.packet_sequence EXISTS",
    "tm.event='NewBlock'",
)


@dataclass(frozen=True)
class PacketPath:
    labels: Tuple[str, ...]

    def as_dict(self) -> Dict[str, str]:
        return dict(zip(CHANNEL_LABELS, self.labels))


class PacketTopology:
    def __init__(self):
        self.source_paths: Dict[Tuple[str, str, str], PacketPath] = {}
        self.destination_paths: Dict[Tuple[str, str, str, str, str], PacketPath] = {}
        self.known_labelsets: set[Tuple[str, ...]] = set()

    @classmethod
    def from_scanner(cls, home_chain_id: str, scanner) -> "PacketTopology":
        topology = cls()
        for conn, port, channel, cp_port, cp_channel, cp_chain in getattr(scanner, "channels", []):
            topology.add_path(
                (
                    home_chain_id,
                    conn,
                    port,
                    channel,
                    cp_chain,
                    cp_port,
                    cp_channel,
                )
            )
        for cp_chain, cp_conn, port, channel, cp_port, cp_channel, home in getattr(scanner, "cp_channels", []):
            topology.add_path(
                (
                    cp_chain,
                    cp_conn,
                    port,
                    channel,
                    home,
                    cp_port,
                    cp_channel,
                )
            )
        return topology

    def add_path(self, labels: Tuple[str, ...]) -> None:
        path = PacketPath(labels=tuple(labels))
        (
            chain_id,
            _connection_id,
            port_id,
            channel_id,
            counterparty_chain_id,
            counterparty_port_id,
            counterparty_channel_id,
        ) = path.labels
        self.known_labelsets.add(path.labels)
        self.source_paths[(chain_id, port_id, channel_id)] = path
        self.destination_paths[
            (
                counterparty_chain_id,
                counterparty_port_id,
                counterparty_channel_id,
                port_id,
                channel_id,
            )
        ] = path

    def resolve(self, event: PacketEvent) -> PacketPath | None:
        if event.event_type in SOURCE_CHAIN_EVENTS:
            return self.source_paths.get(
                (event.emitter_chain_id, event.src_port, event.src_channel)
            )
        if event.event_type in DESTINATION_CHAIN_EVENTS:
            return self.destination_paths.get(
                (
                    event.emitter_chain_id,
                    event.dst_port,
                    event.dst_channel,
                    event.src_port,
                    event.src_channel,
                )
            )
        return None


class PacketIndexer:
    def __init__(self, cfg: Config, scanner=None):
        self.cfg = cfg
        self.store = PacketStore(cfg.packet_indexer_store_path)
        self.topology = PacketTopology.from_scanner(cfg.home_chain.chain_id, scanner) if scanner else PacketTopology()
        self.rpc_by_chain: Dict[str, RPCClient] = {}
        for chain in cfg.chains:
            if not chain.rpcs and not cfg.enable_chain_registry_fallbacks:
                logger.warning(
                    "No RPC endpoints configured for chain %s; packet indexing will be unavailable",
                    chain.chain_id,
                )
                continue
            primary_rpc = chain.rpcs[0] if chain.rpcs else ""
            self.rpc_by_chain[chain.chain_id] = RPCClient(
                primary_rpc,
                chain.chain_id,
                chain.name,
                fallback_endpoints=chain.rpcs[1:],
                websocket_endpoints=getattr(chain, "websockets", []),
                enable_chain_registry_fallbacks=cfg.enable_chain_registry_fallbacks,
            )

        self.queue: queue.Queue[Tuple[str, Mapping, int]] = queue.Queue(
            maxsize=cfg.packet_indexer_queue_size
        )
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.processor_thread: threading.Thread | None = None
        self._started = False
        self._lifecycle_labelsets: set[Tuple[str, ...]] = set()
        self._rpc_health_labelsets: set[Tuple[str, str]] = set()
        self._websocket_health_labelsets: set[Tuple[str, str]] = set()
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self.refresh_rpc_health()
        self._backfill_on_start()
        self.processor_thread = threading.Thread(
            target=self._processor_loop,
            name="packet-indexer-processor",
            daemon=True,
        )
        self.processor_thread.start()
        for chain_id in self.rpc_by_chain:
            thread = threading.Thread(
                target=self._websocket_loop,
                args=(chain_id,),
                name=f"packet-indexer-{chain_id}",
                daemon=True,
            )
            self.threads.append(thread)
            thread.start()
        logger.info("Packet indexer started for %d chain(s)", len(self.rpc_by_chain))

    def stop(self) -> None:
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=2)
        if self.processor_thread:
            self.processor_thread.join(timeout=2)
        self.store.close()

    def update_topology(self, scanner) -> None:
        with self._lock:
            self.topology = PacketTopology.from_scanner(self.cfg.home_chain.chain_id, scanner)
        self.update_lifecycle_gauges()

    def refresh_rpc_health(self) -> None:
        for chain in self.cfg.chains:
            client = self.rpc_by_chain.get(chain.chain_id)
            if not client:
                self._set_rpc_health(chain.chain_id, "unavailable", False)
                PACKET_INDEXER_ERRORS.labels(
                    chain_id=chain.chain_id,
                    stage="rpc_unavailable",
                ).inc()
                continue
            before = client.endpoint
            try:
                healthy = client.health(timeout=self.cfg.packet_indexer_rpc_timeout)
                endpoint = client.endpoint or "unavailable"
                if healthy and before and before != endpoint:
                    RPC_ENDPOINT_SWITCHES.labels(
                        chain_id=chain.chain_id,
                        from_endpoint=before,
                        to_endpoint=endpoint,
                    ).inc()
                self._set_rpc_health(chain.chain_id, endpoint, healthy)
                if healthy:
                    status = client.status(timeout=self.cfg.packet_indexer_rpc_timeout)
                    RPC_LATEST_BLOCK_HEIGHT.labels(chain_id=chain.chain_id).set(status.latest_height)
                    if status.latest_timestamp:
                        RPC_LATEST_BLOCK_TIMESTAMP.labels(chain_id=chain.chain_id).set(
                            status.latest_timestamp
                        )
            except Exception:
                endpoint = client.endpoint or "unavailable"
                logger.exception("RPC health refresh failed for %s", chain.chain_id)
                self._set_rpc_health(chain.chain_id, endpoint, False)
                RPC_ERRORS.labels(
                    chain_id=chain.chain_id,
                    endpoint=endpoint,
                    stage="health",
                ).inc()
                PACKET_INDEXER_ERRORS.labels(
                    chain_id=chain.chain_id,
                    stage="rpc_health",
                ).inc()

    def process_message(self, chain_id: str, raw: Mapping, observed_at: int | None = None) -> None:
        observed = observed_at or int(time.time())
        height = extract_height(raw)
        event_time = extract_block_timestamp(raw) or observed
        if height:
            self.store.record_progress(chain_id, height, event_time)
            PACKET_INDEXER_LAST_PROCESSED_HEIGHT.labels(chain_id=chain_id).set(height)
            PACKET_INDEXER_LAST_EVENT_TIME.labels(chain_id=chain_id).set(event_time)
        for event in parse_packet_events(raw, chain_id, observed_at=observed):
            self.process_packet_event(event)

    def process_packet_event(self, event: PacketEvent) -> None:
        with self._lock:
            path = self.topology.resolve(event)
        if path is None:
            self._inc_orphan(event)
            PACKET_INDEXER_ERRORS.labels(
                chain_id=event.emitter_chain_id,
                stage="topology_miss",
            ).inc()
            return

        labels = path.as_dict()
        result = self.store.apply_event(event, labels)
        if not result.event_inserted:
            return

        self._inc_event_counter(event, labels)
        if "successfully_relayed" in result.transitions:
            SUCCESSFULLY_RELAYED_PACKETS.labels(**labels).inc()
        if "acknowledged" in result.transitions:
            ACKNOWLEDGED_PACKETS.labels(**labels).inc()
        if "timed_out" in result.transitions:
            TIMED_OUT_PACKETS.labels(**labels, timeout_type=result.timeout_type).inc()

        if "relay" in result.durations:
            PACKET_RELAY_DURATION.labels(**labels).observe(result.durations["relay"])
        if "ack" in result.durations:
            PACKET_ACK_DURATION.labels(**labels).observe(result.durations["ack"])
        if "timeout" in result.durations:
            PACKET_TIMEOUT_DURATION.labels(
                **labels,
                timeout_type=result.timeout_type,
            ).observe(result.durations["timeout"])

        PACKET_INDEXER_LAST_EVENT_TIME.labels(chain_id=event.emitter_chain_id).set(
            event.timestamp
        )
        if event.height:
            PACKET_INDEXER_LAST_PROCESSED_HEIGHT.labels(
                chain_id=event.emitter_chain_id
            ).set(event.height)
        self.update_lifecycle_gauges()

    def update_lifecycle_gauges(self) -> None:
        with self._lock:
            known = set(self.topology.known_labelsets)
        active_labelsets: set[Tuple[str, ...]] = set()
        for summary in self.store.lifecycle_summaries(known):
            self._record_lifecycle_summary(summary)
            active_labelsets.add(summary.labels)

        stale = self._lifecycle_labelsets - active_labelsets
        for label_values in stale:
            for metric in (
                INFLIGHT_PACKET_SIZE,
                INFLIGHT_PACKET_OLDEST_SEQ,
                INFLIGHT_PACKET_OLDEST_TIMESTAMP,
                PENDING_ACK_PACKET_SIZE,
                PENDING_ACK_PACKET_OLDEST_SEQ,
                PENDING_ACK_PACKET_OLDEST_TIMESTAMP,
            ):
                try:
                    metric.remove(*label_values)
                except KeyError:
                    pass
        self._lifecycle_labelsets = active_labelsets

    @staticmethod
    def _record_lifecycle_summary(summary: PacketLifecycleSummary) -> None:
        labels = dict(zip(CHANNEL_LABELS, summary.labels))
        INFLIGHT_PACKET_SIZE.labels(**labels).set(summary.inflight_size)
        INFLIGHT_PACKET_OLDEST_SEQ.labels(**labels).set(summary.inflight_oldest_sequence)
        INFLIGHT_PACKET_OLDEST_TIMESTAMP.labels(**labels).set(
            summary.inflight_oldest_timestamp
        )
        PENDING_ACK_PACKET_SIZE.labels(**labels).set(summary.pending_ack_size)
        PENDING_ACK_PACKET_OLDEST_SEQ.labels(**labels).set(
            summary.pending_ack_oldest_sequence
        )
        PENDING_ACK_PACKET_OLDEST_TIMESTAMP.labels(**labels).set(
            summary.pending_ack_oldest_timestamp
        )

    @staticmethod
    def _inc_event_counter(event: PacketEvent, labels: Mapping[str, str]) -> None:
        if event.event_type == "send_packet":
            SEND_PACKET_EVENTS.labels(**labels).inc()
        elif event.event_type == "recv_packet":
            RECV_PACKET_EVENTS.labels(**labels).inc()
        elif event.event_type == "write_acknowledgement":
            WRITE_ACK_PACKET_EVENTS.labels(**labels).inc()
        elif event.event_type == "acknowledge_packet":
            ACK_PACKET_EVENTS.labels(**labels).inc()
        elif event.event_type in {"timeout_packet", "timeout_on_close_packet"}:
            TIMEOUT_PACKET_EVENTS.labels(**labels, timeout_type=event.timeout_type).inc()

    @staticmethod
    def _inc_orphan(event: PacketEvent) -> None:
        labels = {
            "chain_id": event.emitter_chain_id,
            "connection_id": "unknown",
            "port_id": event.src_port or "unknown",
            "channel_id": event.src_channel or "unknown",
            "counterparty_chain_id": "unknown",
            "counterparty_port_id": event.dst_port or "unknown",
            "counterparty_channel_id": event.dst_channel or "unknown",
            "event_type": event.event_type,
        }
        ORPHAN_PACKET_EVENTS.labels(**labels).inc()

    def _set_rpc_health(self, chain_id: str, endpoint: str, healthy: bool) -> None:
        endpoint = endpoint or "unavailable"
        for old_chain_id, old_endpoint in list(self._rpc_health_labelsets):
            if old_chain_id == chain_id and old_endpoint != endpoint:
                RPC_HEALTH.labels(chain_id=old_chain_id, endpoint=old_endpoint).set(0)
        RPC_HEALTH.labels(chain_id=chain_id, endpoint=endpoint).set(1 if healthy else 0)
        self._rpc_health_labelsets.add((chain_id, endpoint))

    def _set_websocket_health(self, chain_id: str, endpoint: str, healthy: bool) -> None:
        endpoint = endpoint or "unavailable"
        for old_chain_id, old_endpoint in list(self._websocket_health_labelsets):
            if old_chain_id == chain_id and old_endpoint != endpoint:
                WEBSOCKET_HEALTH.labels(chain_id=old_chain_id, endpoint=old_endpoint).set(0)
        WEBSOCKET_HEALTH.labels(chain_id=chain_id, endpoint=endpoint).set(
            1 if healthy else 0
        )
        self._websocket_health_labelsets.add((chain_id, endpoint))

    def _processor_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                chain_id, raw, observed_at = self.queue.get(timeout=1)
            except queue.Empty:
                PACKET_INDEXER_QUEUE_SIZE.set(self.queue.qsize())
                continue
            try:
                self.process_message(chain_id, raw, observed_at)
            except Exception:
                logger.exception("Packet indexer processing failed for %s", chain_id)
                PACKET_INDEXER_ERRORS.labels(
                    chain_id=chain_id,
                    stage="process",
                ).inc()
            finally:
                self.queue.task_done()
                PACKET_INDEXER_QUEUE_SIZE.set(self.queue.qsize())

    def _websocket_loop(self, chain_id: str) -> None:
        try:
            import websocket
        except ImportError:
            logger.error("websocket-client package is required for packet indexing")
            PACKET_INDEXER_ERRORS.labels(
                chain_id=chain_id,
                stage="websocket_dependency",
            ).inc()
            self._set_websocket_health(chain_id, "unavailable", False)
            return

        backoff = self.cfg.packet_indexer_reconnect_initial_seconds
        while not self.stop_event.is_set():
            client = self.rpc_by_chain[chain_id]
            self.refresh_rpc_health()
            endpoint = client.websocket_endpoint()
            if not endpoint:
                self._set_websocket_health(chain_id, "unavailable", False)
                PACKET_INDEXER_ERRORS.labels(
                    chain_id=chain_id,
                    stage="websocket_unavailable",
                ).inc()
                time.sleep(backoff)
                backoff = self._next_backoff(backoff)
                continue

            ws = None
            try:
                ws = websocket.create_connection(
                    endpoint,
                    timeout=self.cfg.packet_indexer_rpc_timeout,
                )
                self._set_websocket_health(chain_id, endpoint, True)
                backoff = self.cfg.packet_indexer_reconnect_initial_seconds
                for idx, query in enumerate(PACKET_SUBSCRIPTIONS):
                    ws.send(
                        json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "method": "subscribe",
                                "id": f"{chain_id}-{idx}",
                                "params": {"query": query},
                            }
                        )
                    )

                while not self.stop_event.is_set():
                    payload = ws.recv()
                    if not payload:
                        continue
                    try:
                        raw = json.loads(payload)
                    except json.JSONDecodeError:
                        PACKET_INDEXER_ERRORS.labels(
                            chain_id=chain_id,
                            stage="decode",
                        ).inc()
                        continue
                    try:
                        self.queue.put(
                            (chain_id, raw, int(time.time())),
                            timeout=1,
                        )
                    except queue.Full:
                        PACKET_INDEXER_ERRORS.labels(
                            chain_id=chain_id,
                            stage="queue_full",
                        ).inc()
            except Exception:
                logger.exception("Websocket connection failed for %s", chain_id)
                self._set_websocket_health(chain_id, endpoint, False)
                WEBSOCKET_RECONNECTS.labels(chain_id=chain_id, endpoint=endpoint).inc()
                PACKET_INDEXER_ERRORS.labels(
                    chain_id=chain_id,
                    stage="websocket",
                ).inc()
                self._gap_backfill(chain_id)
                time.sleep(backoff + random.random())
                backoff = self._next_backoff(backoff)
            finally:
                if ws is not None:
                    try:
                        ws.close()
                    except Exception:
                        pass

    def _next_backoff(self, backoff: int) -> int:
        return min(
            int(backoff * 2),
            int(self.cfg.packet_indexer_reconnect_max_seconds),
        )

    def _backfill_on_start(self) -> None:
        blocks = self.cfg.packet_indexer_backfill_on_start_blocks
        if blocks <= 0:
            return
        for chain_id, client in self.rpc_by_chain.items():
            try:
                status = client.status(timeout=self.cfg.packet_indexer_rpc_timeout)
                latest = status.latest_height
                stored = self.store.last_processed_height(chain_id)
                start = max(1, latest - blocks + 1)
                if stored:
                    start = max(start, stored + 1)
                if start <= latest:
                    self.backfill_chain(chain_id, start, latest)
            except Exception:
                logger.exception("Startup packet backfill failed for %s", chain_id)
                PACKET_INDEXER_ERRORS.labels(
                    chain_id=chain_id,
                    stage="backfill",
                ).inc()

    def _gap_backfill(self, chain_id: str) -> None:
        if not self.cfg.packet_indexer_gap_backfill:
            return
        client = self.rpc_by_chain.get(chain_id)
        if not client:
            return
        try:
            status = client.status(timeout=self.cfg.packet_indexer_rpc_timeout)
            stored = self.store.last_processed_height(chain_id)
            if stored and status.latest_height > stored + 1:
                self.backfill_chain(chain_id, stored + 1, status.latest_height)
        except Exception:
            logger.debug("Gap backfill failed for %s", chain_id, exc_info=True)

    def backfill_chain(self, chain_id: str, start_height: int, end_height: int) -> None:
        client = self.rpc_by_chain.get(chain_id)
        if not client:
            return
        start = int(start_height)
        end = int(end_height)
        workers = int(getattr(self.cfg, "packet_indexer_backfill_workers", 1))
        if workers <= 1:
            for height in range(start, end + 1):
                if self.stop_event.is_set():
                    break
                self._backfill_height(chain_id, client, height)
            return

        batch_size = int(getattr(self.cfg, "packet_indexer_backfill_batch_size", 100))
        for batch_start in range(start, end + 1, batch_size):
            if self.stop_event.is_set():
                break
            batch_end = min(end, batch_start + batch_size - 1)
            self._backfill_height_batch(chain_id, client, batch_start, batch_end, workers)

    def _backfill_height_batch(
        self,
        chain_id: str,
        client: RPCClient,
        start_height: int,
        end_height: int,
        workers: int,
    ) -> None:
        fetched: Dict[int, Tuple[int, list[Mapping]]] = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._fetch_backfill_height, client, height): height
                for height in range(start_height, end_height + 1)
                if not self.stop_event.is_set()
            }
            for future in as_completed(futures):
                height = futures[future]
                if self.stop_event.is_set():
                    break
                try:
                    observed_at, messages = future.result()
                    fetched[height] = (observed_at, messages)
                except Exception:
                    logger.exception("Backfill fetch failed for %s height %s", chain_id, height)
                    PACKET_INDEXER_ERRORS.labels(
                        chain_id=chain_id,
                        stage="backfill_fetch",
                    ).inc()

        for height in sorted(fetched):
            if self.stop_event.is_set():
                break
            observed_at, messages = fetched[height]
            for raw in messages:
                self.process_message(chain_id, raw, observed_at=observed_at)

    def _backfill_height(self, chain_id: str, client: RPCClient, height: int) -> None:
        try:
            observed_at, messages = self._fetch_backfill_height(client, height)
            for raw in messages:
                self.process_message(chain_id, raw, observed_at=observed_at)
        except Exception:
            logger.exception("Backfill failed for %s height %s", chain_id, height)
            PACKET_INDEXER_ERRORS.labels(
                chain_id=chain_id,
                stage="backfill",
            ).inc()

    def _fetch_backfill_height(
        self,
        client: RPCClient,
        height: int,
    ) -> Tuple[int, list[Mapping]]:
        rpc = client.clone()
        block_time = self._block_time(rpc, height)
        results = rpc.block_results(
            height,
            timeout=self.cfg.packet_indexer_rpc_timeout,
        )
        observed_at = block_time or int(time.time())
        return (
            observed_at,
            list(self._messages_from_block_results(results, height, block_time)),
        )

    def _block_time(self, client: RPCClient, height: int) -> int | None:
        block = client.block(height, timeout=self.cfg.packet_indexer_rpc_timeout)
        header = (
            ((block.get("result") or {}).get("block") or {}).get("header") or {}
        )
        return parse_rpc_time(header.get("time"))

    @staticmethod
    def _messages_from_block_results(
        raw: Mapping,
        height: int,
        block_time: int | None,
    ) -> Iterable[Mapping]:
        result = raw.get("result", {}) or {}
        header = {
            "height": str(height),
            "time": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(block_time or int(time.time())),
            ),
        }
        for tx_result in result.get("txs_results", []) or []:
            yield {
                "result": {
                    "data": {
                        "value": {
                            "TxResult": {
                                "height": str(height),
                                "result": {"events": tx_result.get("events", []) or []},
                            },
                            "block": {"header": header},
                        }
                    }
                }
            }
        yield {
            "result": {
                "data": {
                    "value": {
                        "block": {"header": header},
                        "BeginBlock": {
                            "events": result.get("begin_block_events", []) or []
                        },
                        "EndBlock": {"events": result.get("end_block_events", []) or []},
                    }
                }
            }
        }
