import time
import logging
from urllib.parse import quote_plus
from prometheus_client import start_http_server
from ibc_monitor.rest_client import RESTClient
from ibc_monitor.config import Config, ChainConfig
from ibc_monitor.state_scanner import StateScanner
from ibc_monitor.metrics import (
    REST_HEALTH,
    CLIENT_TRUSTING_PERIOD,
    CLIENT_LAST_UPDATE,
    BACKLOG_SIZE,
    BACKLOG_OLDEST_SEQ,
    BACKLOG_OLDEST_TIMESTAMP,
    ACK_OLDEST_SEQ,
    ACK_OLDEST_TIMESTAMP,
    BACKLOG_UPDATED,
)
import datetime
import re

logger = logging.getLogger(__name__)

DURATION_RE = re.compile(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?")

def parse_duration(dur: str) -> int:
    m = DURATION_RE.match(dur)
    if not m:
        return 0
    hours = int(m.group(1) or 0)
    minutes = int(m.group(2) or 0)
    seconds = int(m.group(3) or 0)
    return hours * 3600 + minutes * 60 + seconds

BATCH = 100  # sequences per filtered-ack/unreceived_acks request

def _chunked(seqs):
    seqs = list(seqs)
    for i in range(0, len(seqs), BATCH):
        yield seqs[i:i+BATCH]

def _params_repeat(key: str, values):
    return "&".join(f"{key}={quote_plus(str(v))}" for v in values)

class IBCExporter:
    def __init__(self, cfg: Config):
        self.cfg = cfg

        # Determine home chain and counterparties from config
        self.home_chain_cfg: ChainConfig = cfg.home_chain
        self.cp_chain_cfgs = [c for c in cfg.chains if not c.home_chain]
        self.cp_chain_ids = [c.chain_id for c in self.cp_chain_cfgs]

        # Build one REST client for the home chain
        if not self.home_chain_cfg.rests:
            raise ValueError(f"No REST endpoints configured for home chain {self.home_chain_cfg.chain_id}")
        self.home_client = RESTClient(self.home_chain_cfg.rests[0], self.home_chain_cfg.chain_id, self.home_chain_cfg.name)

        # Build REST clients for counterparties (one per chain)
        self.rest_by_chain = {}
        for c in self.cp_chain_cfgs:
            if not c.rests:
                logger.warning("No REST endpoints configured for counterparty chain %s; it will be skipped", c.chain_id)
                continue
            self.rest_by_chain[c.chain_id] = RESTClient(c.rests[0], c.chain_id, c.name)

        # Single scanner rooted at the *home* chain; scanner itself will explicitly query CPs.
        self.scanner = StateScanner(
            client=self.home_client,
            cfg=self.home_chain_cfg,
            counterparty_chain_ids=self.cp_chain_ids,
            rest_by_chain=self.rest_by_chain,
            home_chain_id=self.home_chain_cfg.chain_id,
        )

        # in-memory tracking
        # key: (chain_id, conn, port, channel) -> {seq: first_seen_ts}
        self.pending_packets = {}
        self.pending_acks = {}

    # -------- helpers --------

    def _query_all_list(self, client: RESTClient, path: str, list_key: str):
        """Follow pagination.next_key for list endpoints on the given client."""
        items = []
        next_key = None
        while True:
            qpath = path if not next_key else f"{path}{'&' if '?' in path else '?'}pagination.key={quote_plus(next_key)}"
            res = client.query(qpath)
            items.extend(res.get(list_key, []) or [])
            next_key = (res.get("pagination") or {}).get("next_key")
            if not next_key:
                break
        return items

    def _filtered_ack_sequences(self, client: RESTClient, port: str, channel: str, seqs):
        """Ask only for acks that correspond to the provided commitment sequences."""
        acked = set()
        if not seqs:
            return acked
        base = f"/ibc/core/channel/v1/channels/{quote_plus(channel)}/ports/{quote_plus(port)}/packet_acknowledgements"
        for batch in _chunked(seqs):
            q = _params_repeat("packet_commitment_sequences", batch)
            res = client.query(f"{base}?{q}")
            for a in res.get("acknowledgements", []) or []:
                try:
                    acked.add(int(a.get("sequence", 0)))
                except (TypeError, ValueError):
                    continue
        return acked

    def _unreceived_acks(self, client: RESTClient, port: str, channel: str, ack_seqs):
        """Return the subset of ack_seqs that the given chain has NOT received yet."""
        unreceived = set()
        if not ack_seqs:
            return unreceived
        base = f"/ibc/core/channel/v1/channels/{quote_plus(channel)}/ports/{quote_plus(port)}/unreceived_acks"
        for batch in _chunked(ack_seqs):
            q = _params_repeat("packet_ack_sequences", batch)
            res = client.query(f"{base}?{q}")
            for s in res.get("sequences", []) or []:
                try:
                    unreceived.add(int(s))
                except (TypeError, ValueError):
                    continue
        return unreceived

    def run(self):
        # start prometheus server
        start_http_server(self.cfg.port, addr=self.cfg.address)
        logger.info(f"Exporter listening on {self.cfg.address}:{self.cfg.port}")
        while True:
            self.update_metrics()
            time.sleep(self.cfg.update_interval)

    def update_metrics(self):
        now = int(time.time())

        # Health checks for home + counterparties
        home_healthy = self.home_client.health()
        REST_HEALTH.labels(
            chain_id=self.home_chain_cfg.chain_id,
            endpoint=self.home_client.endpoint
        ).set(1 if home_healthy else 0)

        for cid, rc in self.rest_by_chain.items():
            healthy = rc.health()
            REST_HEALTH.labels(
                chain_id=cid,
                endpoint=rc.endpoint
            ).set(1 if healthy else 0)

        if not home_healthy:
            logger.debug("Home chain %s endpoint unhealthy; skipping scan/metrics this cycle", self.home_chain_cfg.chain_id)
            return

        # Refresh state (home + explicit CP scans)
        self.scanner.scan()

        # -------- client state metrics (home) --------
        for cid in self.scanner.clients:
            # trusting period
            cs = self.home_client.query(f"/ibc/core/client/v1/client_states/{cid}")
            client_state = cs.get('client_state', {})
            tp_str = client_state.get('trusting_period', '')
            tp = parse_duration(tp_str)
            cp_chain = client_state.get('chain_id', '')
            cp_client = self.scanner.client_counterparty_client_ids.get(cid, '')
            CLIENT_TRUSTING_PERIOD.labels(
                client_id=cid,
                chain_id=self.home_chain_cfg.chain_id,
                counterparty_chain_id=cp_chain,
                counterparty_client_id=cp_client,
            ).set(tp)

            # last update
            cons = self.home_client.query(f"/ibc/core/client/v1/consensus_states/{cid}")
            ts_str = cons.get('consensus_state', {}).get('timestamp', '')
            if ts_str:
                dt = datetime.datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                last_ts = int(dt.timestamp())
            else:
                last_ts = now
            CLIENT_LAST_UPDATE.labels(
                client_id=cid,
                chain_id=self.home_chain_cfg.chain_id,
                counterparty_chain_id=cp_chain,
                counterparty_client_id=cp_client,
            ).set(last_ts)

        # -------- backlog metrics per channel (home) --------
        for conn, port, channel, cp_port, cp_channel, cp_chain in self.scanner.channels:
            key_home = (self.home_chain_cfg.chain_id, conn, port, channel)

            # send packet backlog (paginated)
            sp_items = self._query_all_list(
                self.home_client,
                f"/ibc/core/channel/v1/channels/{channel}/ports/{port}/packet_commitments",
                "commitments",
            )
            seqs = [int(c['sequence']) for c in sp_items]
            valid_seqs = [
                s for s in seqs
                if not self.cfg.excluded_sequences.is_excluded(channel, s)
            ]
            pending = self.pending_packets.setdefault(key_home, {})
            for s in list(pending.keys()):
                if s not in valid_seqs:
                    del pending[s]
            for s in valid_seqs:
                if s not in pending:
                    pending[s] = now
            size = len(pending)
            oldest_seq = min(pending) if pending else 0
            oldest_ts = pending.get(oldest_seq, 0)
            BACKLOG_SIZE.labels(
                chain_id=self.home_chain_cfg.chain_id,
                connection_id=conn,
                port_id=port,
                channel_id=channel,
                counterparty_chain_id=cp_chain,
                counterparty_port_id=cp_port,
                counterparty_channel_id=cp_channel,
            ).set(size)
            BACKLOG_OLDEST_SEQ.labels(
                chain_id=self.home_chain_cfg.chain_id,
                connection_id=conn,
                port_id=port,
                channel_id=channel,
                counterparty_chain_id=cp_chain,
                counterparty_port_id=cp_port,
                counterparty_channel_id=cp_channel,
            ).set(oldest_seq)
            BACKLOG_OLDEST_TIMESTAMP.labels(
                chain_id=self.home_chain_cfg.chain_id,
                connection_id=conn,
                port_id=port,
                channel_id=channel,
                counterparty_chain_id=cp_chain,
                counterparty_port_id=cp_port,
                counterparty_channel_id=cp_channel,
            ).set(oldest_ts)

            # ---- FAST ACK BACKLOG (home) ----
            rc = self.rest_by_chain.get(cp_chain)
            if rc and valid_seqs:
                acked_on_cp = self._filtered_ack_sequences(rc, cp_port, cp_channel, valid_seqs)
                unreceived = self._unreceived_acks(self.home_client, port, channel, acked_on_cp)
            else:
                unreceived = set()

            apending = self.pending_acks.setdefault(key_home, {})
            for s in list(apending.keys()):
                if s not in unreceived:
                    del apending[s]
            for s in unreceived:
                if s not in apending:
                    apending[s] = now
            aoldest_seq = min(apending) if apending else 0
            aoldest_ts = apending.get(aoldest_seq, 0)

            ACK_OLDEST_SEQ.labels(
                chain_id=self.home_chain_cfg.chain_id,
                connection_id=conn,
                port_id=port,
                channel_id=channel,
                counterparty_chain_id=cp_chain,
                counterparty_port_id=cp_port,
                counterparty_channel_id=cp_channel,
            ).set(aoldest_seq)
            ACK_OLDEST_TIMESTAMP.labels(
                chain_id=self.home_chain_cfg.chain_id,
                connection_id=conn,
                port_id=port,
                channel_id=channel,
                counterparty_chain_id=cp_chain,
                counterparty_port_id=cp_port,
                counterparty_channel_id=cp_channel,
            ).set(aoldest_ts)

            logger.info(
                "[%s %s/%s] backlog=%d oldest=%d age=%ds ack_backlog=%d ack_oldest=%d ack_age=%ds",
                self.home_chain_cfg.chain_id,
                port,
                channel,
                size,
                oldest_seq,
                now - oldest_ts if oldest_ts else 0,
                len(apending),
                aoldest_seq,
                now - aoldest_ts if aoldest_ts else 0,
            )

        # -------- backlog metrics per channel (counterparties) --------
        # tuples: (cp_chain, cp_conn, port, channel, cp_port, cp_channel, home_chain_id)
        for (cp_chain, cp_conn, port, channel, cp_port, cp_channel, home_chain_id) in self.scanner.cp_channels:
            rc = self.rest_by_chain.get(cp_chain)
            if not rc:
                continue

            key_cp = (cp_chain, cp_conn, port, channel)

            # send packet backlog on CP (paginated)
            sp_items = self._query_all_list(
                rc,
                f"/ibc/core/channel/v1/channels/{channel}/ports/{port}/packet_commitments",
                "commitments",
            )
            seqs = [int(c['sequence']) for c in sp_items]
            valid_seqs = [
                s for s in seqs
                if not self.cfg.excluded_sequences.is_excluded(channel, s)
            ]
            pending = self.pending_packets.setdefault(key_cp, {})
            for s in list(pending.keys()):
                if s not in valid_seqs:
                    del pending[s]
            for s in valid_seqs:
                if s not in pending:
                    pending[s] = now
            size = len(pending)
            oldest_seq = min(pending) if pending else 0
            oldest_ts = pending.get(oldest_seq, 0)
            BACKLOG_SIZE.labels(
                chain_id=cp_chain,
                connection_id=cp_conn,
                port_id=port,
                channel_id=channel,
                counterparty_chain_id=home_chain_id,
                counterparty_port_id=cp_port,
                counterparty_channel_id=cp_channel,
            ).set(size)
            BACKLOG_OLDEST_SEQ.labels(
                chain_id=cp_chain,
                connection_id=cp_conn,
                port_id=port,
                channel_id=channel,
                counterparty_chain_id=home_chain_id,
                counterparty_port_id=cp_port,
                counterparty_channel_id=cp_channel,
            ).set(oldest_seq)
            BACKLOG_OLDEST_TIMESTAMP.labels(
                chain_id=cp_chain,
                connection_id=cp_conn,
                port_id=port,
                channel_id=channel,
                counterparty_chain_id=home_chain_id,
                counterparty_port_id=cp_port,
                counterparty_channel_id=cp_channel,
            ).set(oldest_ts)

            # ---- FAST ACK BACKLOG (counterparty side) ----
            acked_on_home = self._filtered_ack_sequences(
                self.home_client, cp_port, cp_channel, valid_seqs
            )
            unreceived_cp = self._unreceived_acks(
                rc, port, channel, acked_on_home
            )

            apending = self.pending_acks.setdefault(key_cp, {})
            for s in list(apending.keys()):
                if s not in unreceived_cp:
                    del apending[s]
            for s in unreceived_cp:
                if s not in apending:
                    apending[s] = now
            aoldest_seq = min(apending) if apending else 0
            aoldest_ts = apending.get(aoldest_seq, 0)
            ACK_OLDEST_SEQ.labels(
                chain_id=cp_chain,
                connection_id=cp_conn,
                port_id=port,
                channel_id=channel,
                counterparty_chain_id=home_chain_id,
                counterparty_port_id=cp_port,
                counterparty_channel_id=cp_channel,
            ).set(aoldest_seq)
            ACK_OLDEST_TIMESTAMP.labels(
                chain_id=cp_chain,
                connection_id=cp_conn,
                port_id=port,
                channel_id=channel,
                counterparty_chain_id=home_chain_id,
                counterparty_port_id=cp_port,
                counterparty_channel_id=cp_channel,
            ).set(aoldest_ts)

            logger.info(
                "[%s %s/%s] backlog=%d oldest=%d age=%ds ack_backlog=%d ack_oldest=%d ack_age=%ds",
                cp_chain,
                port,
                channel,
                size,
                oldest_seq,
                now - oldest_ts if oldest_ts else 0,
                len(apending),
                aoldest_seq,
                now - aoldest_ts if aoldest_ts else 0,
            )

        # ---- last update time for ALL chains (home + counterparties) ----
        BACKLOG_UPDATED.labels(chain_id=self.home_chain_cfg.chain_id).set(now)
        for cid in self.rest_by_chain.keys():
            BACKLOG_UPDATED.labels(chain_id=cid).set(now)

        logger.info("Metrics updated")
