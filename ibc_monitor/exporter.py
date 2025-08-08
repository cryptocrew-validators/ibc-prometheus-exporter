import time
import logging
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

class IBCExporter:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.scanners = []  # List of (chain_cfg, rest_client, scanner)
        self.pending_packets = {}
        self.pending_acks = {}
        home_id = cfg.home_chain.chain_id
        for chain in cfg.chains:
            if chain.home_chain:
                counterparties = [c.chain_id for c in cfg.chains if not c.home_chain]
            else:
                counterparties = [home_id]
            for rest in chain.rests:
                client = RESTClient(rest, chain.chain_id, chain.name)
                scanner = StateScanner(client, chain, counterparties)
                self.scanners.append((chain, client, scanner))

    def run(self):
        # start prometheus server
        start_http_server(self.cfg.port, addr=self.cfg.address)
        logger.info(f"Exporter listening on {self.cfg.address}:{self.cfg.port}")
        while True:
            self.update_metrics()
            time.sleep(self.cfg.update_interval)

    def update_metrics(self):
        now = int(time.time())
        for chain_cfg, client, scanner in self.scanners:
            healthy = client.health()
            REST_HEALTH.labels(
                chain_id=chain_cfg.chain_id,
                endpoint=client.endpoint
            ).set(1 if healthy else 0)

            if not healthy:
                continue

            # refresh on-chain state if needed
            scanner.scan()

            # client state metrics
            for cid in scanner.clients:
                # trusting period
                cs = client.query(f"/ibc/core/client/v1/client_states/{cid}")
                client_state = cs.get('client_state', {})
                tp_str = client_state.get('trusting_period', '')
                tp = parse_duration(tp_str)
                cp_chain = client_state.get('chain_id', '')
                cp_client = scanner.client_counterparty_client_ids.get(cid, '')
                CLIENT_TRUSTING_PERIOD.labels(
                    client_id=cid,
                    chain_id=chain_cfg.chain_id,
                    counterparty_chain_id=cp_chain,
                    counterparty_client_id=cp_client,
                ).set(tp)

                # last update
                cons = client.query(f"/ibc/core/client/v1/consensus_states/{cid}")
                ts_str = cons.get('consensus_state', {}).get('timestamp', '')
                if ts_str:
                    dt = datetime.datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    last_ts = int(dt.timestamp())
                else:
                    last_ts = now
                CLIENT_LAST_UPDATE.labels(
                    client_id=cid,
                    chain_id=chain_cfg.chain_id,
                    counterparty_chain_id=cp_chain,
                    counterparty_client_id=cp_client,
                ).set(last_ts)

            # backlog metrics per channel
            for conn, port, channel, cp_port, cp_channel, cp_chain in scanner.channels:
                key = (chain_cfg.chain_id, conn, port, channel)
                # send packet backlog
                sp = client.query(
                    f"/ibc/core/channel/v1/channels/{channel}/ports/{port}/packet_commitments"
                )
                seqs = [int(c['sequence']) for c in sp.get('commitments', [])]
                valid_seqs = [
                    s for s in seqs
                    if not self.cfg.excluded_sequences.is_excluded(channel, s)
                ]
                pending = self.pending_packets.setdefault(key, {})
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
                    chain_id=chain_cfg.chain_id,
                    connection_id=conn,
                    port_id=port,
                    channel_id=channel,
                    counterparty_chain_id=cp_chain,
                    counterparty_port_id=cp_port,
                    counterparty_channel_id=cp_channel,
                ).set(size)
                BACKLOG_OLDEST_SEQ.labels(
                    chain_id=chain_cfg.chain_id,
                    connection_id=conn,
                    port_id=port,
                    channel_id=channel,
                    counterparty_chain_id=cp_chain,
                    counterparty_port_id=cp_port,
                    counterparty_channel_id=cp_channel,
                ).set(oldest_seq)
                BACKLOG_OLDEST_TIMESTAMP.labels(
                    chain_id=chain_cfg.chain_id,
                    connection_id=conn,
                    port_id=port,
                    channel_id=channel,
                    counterparty_chain_id=cp_chain,
                    counterparty_port_id=cp_port,
                    counterparty_channel_id=cp_channel,
                ).set(oldest_ts)

                # ack packet backlog
                ack = client.query(
                    f"/ibc/core/channel/v1/channels/{channel}/ports/{port}/packet_acknowledgements"
                )
                aseqs = [int(c['sequence']) for c in ack.get('acknowledgements', [])]
                valid_aseqs = [
                    s for s in aseqs
                    if not self.cfg.excluded_sequences.is_excluded(channel, s)
                ]
                apending = self.pending_acks.setdefault(key, {})
                for s in list(apending.keys()):
                    if s not in valid_aseqs:
                        del apending[s]
                for s in valid_aseqs:
                    if s not in apending:
                        apending[s] = now
                aoldest_seq = min(apending) if apending else 0
                aoldest_ts = apending.get(aoldest_seq, 0)
                ACK_OLDEST_SEQ.labels(
                    chain_id=chain_cfg.chain_id,
                    connection_id=conn,
                    port_id=port,
                    channel_id=channel,
                    counterparty_chain_id=cp_chain,
                    counterparty_port_id=cp_port,
                    counterparty_channel_id=cp_channel,
                ).set(aoldest_seq)
                ACK_OLDEST_TIMESTAMP.labels(
                    chain_id=chain_cfg.chain_id,
                    connection_id=conn,
                    port_id=port,
                    channel_id=channel,
                    counterparty_chain_id=cp_chain,
                    counterparty_port_id=cp_port,
                    counterparty_channel_id=cp_channel,
                ).set(aoldest_ts)

                logger.info(
                    "[%s %s/%s] backlog=%d oldest=%d age=%ds ack_backlog=%d ack_oldest=%d ack_age=%ds",
                    chain_cfg.chain_id,
                    port,
                    channel,
                    size,
                    oldest_seq,
                    now - oldest_ts if oldest_ts else 0,
                    len(apending),
                    aoldest_seq,
                    now - aoldest_ts if aoldest_ts else 0,
                )

            # update timestamp per chain
            BACKLOG_UPDATED.labels(
                chain_id=chain_cfg.chain_id,
            ).set(now)

        logger.info("Metrics updated")
