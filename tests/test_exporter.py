import ibc_monitor.metrics as metrics
from ibc_monitor.exporter import IBCExporter
from ibc_monitor.config import ChainConfig, ExcludedSequences, Config
import toml


# ---- Fakes for the home-anchored exporter ----

class FakeHomeClient:
    def __init__(self):
        self.endpoint = "http://home"

    def health(self):
        return True

    def query(self, path, params=None):
        # Local commitments: 1,2,3 (2 is excluded by config in the test)
        if "packet_commitments" in path:
            return {"commitments": [{"sequence": "1"}, {"sequence": "2"}, {"sequence": "3"}]}
        # Local unreceived_acks: if CP says it acked [2,3], pretend we still need to receive ack for 3
        if "unreceived_acks" in path:
            return {"sequences": ["3"]}
        # These are only hit if scanner.clients is non-empty; we keep it empty in the test
        if "/client/v1/client_states/" in path:
            return {"client_state": {"trusting_period": "1s", "chain_id": "chain-2"}}
        if "/client/v1/consensus_states/" in path:
            return {"consensus_state": {"timestamp": "2020-01-01T00:00:00Z"}}
        return {}


class FakeCounterpartyClient:
    def __init__(self):
        self.endpoint = "http://cp"

    def health(self):
        return True

    def query(self, path, params=None):
        # Simulate filtered acks endpoint (the exporter calls with packet_commitment_sequences)
        # Say CP has acks for sequences 2 and 3.
        if "packet_acknowledgements" in path:
            return {"acknowledgements": [{"sequence": "2"}, {"sequence": "3"}]}
        # Not used in this test otherwise
        return {}


class FakeScanner:
    def __init__(self):
        # No client metrics in this test (keep empty)
        self.clients = []
        # One path: local (conn1, port1/ch1) <-> counterparty (port2/ch2) on chain-2
        self.channels = [("connection-1", "port1", "ch1", "port2", "ch2", "chain-2")]
        self.client_counterparty_client_ids = {}
        # New exporter iterates this for CP-side metrics; keep empty for this test
        self.cp_channels = []

    def scan(self):
        pass


def build_home_anchored_exporter():
    # Minimal config shell (only excluded_sequences used below)
    chain_cfg = ChainConfig(
        name="chain",
        chain_id="chain-1",
        rpcs=["http://rpc"],
        rests=["http://rest"],
        whitelist_clients=[],
        blacklist_clients=[],
        whitelist_connections=[],
        blacklist_connections=[],
        whitelist_channels=[],
        blacklist_channels=[],
        state_refresh_interval=1,
        state_scan_timeout=1,
    )

    exporter = IBCExporter.__new__(IBCExporter)
    exporter.cfg = type("Cfg", (), {})()
    exporter.cfg.excluded_sequences = ExcludedSequences({"ch1": [2]})
    exporter.cfg.address = "127.0.0.1"
    exporter.cfg.port = 0
    exporter.cfg.update_interval = 1

    # Home-anchored attributes expected by the new exporter
    exporter.home_chain_cfg = chain_cfg
    exporter.home_client = FakeHomeClient()
    exporter.rest_by_chain = {"chain-2": FakeCounterpartyClient()}
    exporter.scanner = FakeScanner()

    # in-memory trackers
    exporter.pending_packets = {}
    exporter.pending_acks = {}

    return exporter


# ---- Tests ----

def test_excluded_sequences_filtered():
    metrics.BACKLOG_SIZE.clear()
    metrics.BACKLOG_OLDEST_SEQ.clear()
    metrics.ACK_OLDEST_SEQ.clear()
    metrics.BACKLOG_UPDATED.clear()

    exporter = build_home_anchored_exporter()
    exporter.update_metrics()

    labels = dict(
        chain_id="chain-1",
        connection_id="connection-1",
        port_id="port1",
        channel_id="ch1",
        counterparty_chain_id="chain-2",
        counterparty_port_id="port2",
        counterparty_channel_id="ch2",
    )

    # Commitments: [1,2,3], exclude 2 => pending {1,3}
    assert metrics.BACKLOG_SIZE.labels(**labels)._value.get() == 2
    assert metrics.BACKLOG_OLDEST_SEQ.labels(**labels)._value.get() == 1

    # Fast-ack path: CP acks {2,3}; home unreceived_acks({2,3}) => {3}; oldest = 3
    assert metrics.ACK_OLDEST_SEQ.labels(**labels)._value.get() == 3


def test_home_chain_counterparties(tmp_path):
    data = {
        "chains": [
            {"name": "h", "chain_id": "h-1", "rests": ["http://h"], "home_chain": True},
            {"name": "a", "chain_id": "a-1", "rests": ["http://a"], "home_chain": False},
            {"name": "b", "chain_id": "b-1", "rests": ["http://b"], "home_chain": False},
        ]
    }
    p = tmp_path / "c.toml"
    p.write_text(toml.dumps(data))
    cfg = Config(p)

    # Construct the real exporter; it won't hit the network until update_metrics()
    exp = IBCExporter(cfg)

    # New shape: one home-anchored scanner; counterparties are exposed via:
    #  - exp.scanner.counterparty_chain_ids
    #  - exp.rest_by_chain keys
    assert sorted(exp.scanner.counterparty_chain_ids) == ["a-1", "b-1"]
    assert set(exp.rest_by_chain.keys()) == {"a-1", "b-1"}
