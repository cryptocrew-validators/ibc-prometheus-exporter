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
    m = DURATION_RE.match(dur or "")
    if not m:
        return 0
    hours = int(m.group(1) or 0)
    minutes = int(m.group(2) or 0)
    seconds = int(m.group(3) or 0)
    return hours * 3600 + minutes * 60 + seconds

# RFC3339 (with arbitrary fractional seconds) -> epoch seconds
_TS_TZ_RE = re.compile(r"^(?P<prefix>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?(?P<tz>Z|[+\-]\d{2}:\d{2})$")

def _parse_rfc3339_to_epoch(ts: str) -> int | None:
    """
    Parse timestamps like '2025-08-11T11:02:48.284737546+00:00' or with 'Z'.
    We trim fractional seconds to microseconds since datetime.fromisoformat
    only supports up to 6 digits.
    """
    if not ts:
        return None
    try:
        m = _TS_TZ_RE.match(ts.replace("z", "Z"))
        if not m:
            # last resort: try replacing trailing 'Z' and drop fractional part entirely
            t = ts.replace("Z", "+00:00")
            if "." in t:
                base, rest = t.split(".", 1)
                if "+" in rest:
                    _, tz = rest.split("+", 1)
                    t = f"{base}+{tz}"
                elif "-" in rest:
                    _, tz = rest.split("-", 1)
                    t = f"{base}-{tz}"
            return int(datetime.datetime.fromisoformat(t).timestamp())
        prefix = m.group("prefix")
        frac = (m.group("frac") or "")
        tz = m.group("tz")
        if tz == "Z":
            tz = "+00:00"
        if frac:
            # keep up to 6 digits (microseconds), right-pad if needed
            digits = frac[1:]
            digits = (digits[:6]).ljust(6, "0")
            ts_norm = f"{prefix}.{digits}{tz}"
        else:
            ts_norm = f"{prefix}{tz}"
        return int(datetime.datetime.fromisoformat(ts_norm).timestamp())
    except Exception as e:
        logger.debug("Failed to parse RFC3339 timestamp '%s': %s", ts, e)
        return None

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
        unreceived = set()
        if not ack_seqs:
            return unreceived

        base = f"/ibc/core/channel/v1/channels/{quote_plus(channel)}/ports/{quote_plus(port)}/packet_commitments/{{seqs}}/unreceived_acks"
        for batch in _chunked(ack_seqs):
            seqs_seg = ",".join(str(s) for s in batch)
            res = client.query(base.format(seqs=quote_plus(seqs_seg)))
            for s in res.get("sequences", []) or []:
                try:
                    unreceived.add(int(s))
                except (TypeError, ValueError):
                    continue
        return unreceived

    # ---- consensus timestamp helpers ----

    def _latest_consensus_timestamp(self, rc: RESTClient, client_id: str, now: int) -> int:
        # 1) via latest_height from client_state
        try:
            cs = rc.query(f"/ibc/core/client/v1/client_states/{client_id}")
            st = (cs.get("client_state") or {})
            h = (st.get("latest_height") or {})
            rev = h.get("revision_number")
            hei = h.get("revision_height")
            if rev is not None and hei is not None:
                res = rc.query(
                    f"/ibc/core/client/v1/consensus_states/{client_id}/revision/{rev}/height/{hei}"
                )
                ts = ((res.get("consensus_state") or {}).get("timestamp") or "")
                epoch = _parse_rfc3339_to_epoch(ts)
                if epoch is not None:
                    return epoch
        except Exception as e:
            logger.debug("latest consensus by client_state.latest_height failed for %s: %s", client_id, e)

        # 2) fallback: list endpoint -> pick the highest height
        try:
            res = rc.query(f"/ibc/core/client/v1/consensus_states/{client_id}")
            lst = res.get("consensus_states")
            if isinstance(lst, list) and lst:
                def _hkey(el):
                    hh = (el.get("height") or {})
                    return (int(hh.get("revision_number") or 0), int(hh.get("revision_height") or 0))
                last = max(lst, key=_hkey)
                ts = ((last.get("consensus_state") or {}).get("timestamp") or "")
                epoch = _parse_rfc3339_to_epoch(ts)
                if epoch is not None:
                    return epoch
            # some LCDs/tests return a single object at top-level
            ts = ((res.get("consensus_state") or {}).get("timestamp") or "")
            epoch = _parse_rfc3339_to_epoch(ts)
            if epoch is not None:
                return epoch
        except Exception as e:
            logger.debug("fallback consensus states list fetch failed for %s: %s", client_id, e)

        # 3) last resort -> unknown
        return 0

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
            client_state = cs.get('client_state', {}) or {}
            tp_str = client_state.get('trusting_period', '') or ''
            tp = parse_duration(tp_str)
            cp_chain = client_state.get('chain_id', '') or ''
            cp_client = self.scanner.client_counterparty_client_ids.get(cid, '') or ''
            CLIENT_TRUSTING_PERIOD.labels(
                client_id=cid,
                chain_id=self.home_chain_cfg.chain_id,
                counterparty_chain_id=cp_chain,
                counterparty_client_id=cp_client,
            ).set(tp)

            # last update
            last_ts = self._latest_consensus_timestamp(self.home_client, cid, now)
            CLIENT_LAST_UPDATE.labels(
                client_id=cid,
                chain_id=self.home_chain_cfg.chain_id,
                counterparty_chain_id=cp_chain,
                counterparty_client_id=cp_client,
            ).set(last_ts)

        # -------- client state metrics (counterparties) --------
        # Build a set of cp-clients per cp-chain from what we learned on the home chain
        cp_clients_by_chain = {}
        for local_cid in self.scanner.clients:
            cp_chain = self.scanner.client_chain_map.get(local_cid, "")
            cp_client = self.scanner.client_counterparty_client_ids.get(local_cid, "")
            if cp_chain and cp_client:
                cp_clients_by_chain.setdefault(cp_chain, set()).add((cp_client, local_cid))  # (cp_client, home_client)

        for cp_chain, pairs in cp_clients_by_chain.items():
            rc = self.rest_by_chain.get(cp_chain)
            if not rc or not rc.health():
                continue

            for cp_client, home_client in pairs:
                # trusting period on the counterparty
                try:
                    cs_cp = rc.query(f"/ibc/core/client/v1/client_states/{cp_client}")
                    cp_state = cs_cp.get("client_state", {}) or {}
                    tp_str_cp = cp_state.get("trusting_period", "") or ""
                    tp_cp = parse_duration(tp_str_cp)
                    CLIENT_TRUSTING_PERIOD.labels(
                        client_id=cp_client,
                        chain_id=cp_chain,
                        counterparty_chain_id=self.home_chain_cfg.chain_id,
                        counterparty_client_id=home_client,
                    ).set(tp_cp)
                except Exception as e:
                    logger.debug("cp client_states failed for %s on %s: %s", cp_client, cp_chain, e)
                    continue

                # last update on the counterparty
                try:
                    last_ts_cp = self._latest_consensus_timestamp(rc, cp_client, now)
                    CLIENT_LAST_UPDATE.labels(
                        client_id=cp_client,
                        chain_id=cp_chain,
                        counterparty_chain_id=self.home_chain_cfg.chain_id,
                        counterparty_client_id=home_client,
                    ).set(last_ts_cp)
                except Exception as e:
                    logger.debug("cp consensus_states failed for %s on %s: %s", cp_client, cp_chain, e)

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
