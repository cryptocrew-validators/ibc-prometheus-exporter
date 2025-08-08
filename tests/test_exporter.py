import ibc_monitor.metrics as metrics
from ibc_monitor.exporter import IBCExporter
from ibc_monitor.config import ChainConfig, ExcludedSequences, Config
import toml


class FakeClient:
    def __init__(self):
        self.endpoint = 'http://rpc'

    def health(self):
        return True

    def query(self, path, params=None):
        if 'packet_commitments' in path:
            return {'commitments': [{'sequence': '1'}, {'sequence': '2'}, {'sequence': '3'}]}
        if 'packet_acknowledgements' in path:
            return {'acknowledgements': [{'sequence': '2'}, {'sequence': '4'}]}
        if 'client_states' in path:
            return {'client_state': {'trusting_period': '1s', 'chain_id': 'chain-2'}}
        if 'consensus_states' in path:
            return {'consensus_state': {'timestamp': '2020-01-01T00:00:00Z'}}
        return {}


class FakeScanner:
    def __init__(self):
        self.clients = []
        self.channels = [('conn1', 'port1', 'ch1', 'port2', 'ch2', 'chain-2')]
        self.client_counterparty_client_ids = {}

    def scan(self):
        pass


def build_exporter():
    chain_cfg = ChainConfig(
        name='chain',
        chain_id='chain-1',
        rpcs=['http://rpc'],
        rests=['http://rest'],
        whitelist_clients=[],
        blacklist_clients=[],
        whitelist_connections=[],
        blacklist_connections=[],
        whitelist_channels=[],
        blacklist_channels=[],
        state_refresh_interval=1,
        state_scan_timeout=1,
    )
    cfg = IBCExporter.__new__(IBCExporter)
    cfg.chains = [chain_cfg]
    cfg.excluded_sequences = ExcludedSequences({'ch1': [2]})
    cfg.address = '127.0.0.1'
    cfg.port = 0
    cfg.update_interval = 1
    exporter = IBCExporter.__new__(IBCExporter)
    exporter.cfg = cfg
    exporter.scanners = [(chain_cfg, FakeClient(), FakeScanner())]
    exporter.pending_packets = {}
    exporter.pending_acks = {}
    return exporter


def test_excluded_sequences_filtered():
    metrics.BACKLOG_SIZE.clear()
    metrics.BACKLOG_OLDEST_SEQ.clear()
    metrics.ACK_OLDEST_SEQ.clear()
    metrics.BACKLOG_UPDATED.clear()
    exporter = build_exporter()
    exporter.update_metrics()
    labels = dict(
        chain_id='chain-1',
        connection_id='conn1',
        port_id='port1',
        channel_id='ch1',
        counterparty_chain_id='chain-2',
        counterparty_port_id='port2',
        counterparty_channel_id='ch2',
    )
    assert metrics.BACKLOG_SIZE.labels(**labels)._value.get() == 2
    assert metrics.BACKLOG_OLDEST_SEQ.labels(**labels)._value.get() == 1
    assert metrics.ACK_OLDEST_SEQ.labels(**labels)._value.get() == 4


def test_home_chain_counterparties(tmp_path):
    data = {
        'chains': [
            {'name': 'h', 'chain_id': 'h-1', 'rests': ['http://h'], 'home_chain': True},
            {'name': 'a', 'chain_id': 'a-1', 'rests': ['http://a'], 'home_chain': False},
            {'name': 'b', 'chain_id': 'b-1', 'rests': ['http://b'], 'home_chain': False},
        ]
    }
    p = tmp_path / 'c.toml'
    p.write_text(toml.dumps(data))
    cfg = Config(p)
    exporter = IBCExporter(cfg)
    mapping = {c.chain_id: s.counterparty_chain_ids for c, _, s in exporter.scanners}
    assert mapping['h-1'] == ['a-1', 'b-1']
    assert mapping['a-1'] == ['h-1']
    assert mapping['b-1'] == ['h-1']

