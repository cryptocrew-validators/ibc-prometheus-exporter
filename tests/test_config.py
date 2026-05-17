import tempfile
from pathlib import Path
import toml
import pytest
from ibc_monitor.config import Config, ChainConfig, ExcludedSequences

def build_config(tmp_path):
    data = {
        'chains': [
            {
                'name': 'testchain',
                'chain_id': 'test-1',
                'rpcs': ['http://localhost:26657'],
                'rests': ['http://localhost:1317'],
                'home_chain': True,
                'whitelist_clients': ['c1'],
                'blacklist_clients': ['c2'],
                'whitelist_connections': [],
                'blacklist_connections': [],
                'whitelist_channels': ['p1/ch1'],
                'blacklist_channels': [],
                'state_refresh_interval': 123,
                'state_scan_timeout': 45,
                'excluded_sequences': {'ch1': ['1', '2-3']},
            }
        ],
        'exporter': {
            'address': '127.0.0.1',
            'port': 9000,
            'update_interval_seconds': 45,
            'log_level': 'DEBUG',
            'omit_closed_channels': True,
            'omit_inactive_clients': True,
        },
    }
    p = tmp_path / 'config.toml'
    p.write_text(toml.dumps(data))
    return Config(p)

def test_config_parsing(tmp_path):
    cfg = build_config(tmp_path)
    assert len(cfg.chains) == 1
    chain = cfg.chains[0]
    assert isinstance(chain, ChainConfig)
    assert chain.name == 'testchain'
    assert chain.chain_id == 'test-1'
    assert chain.rpcs == ['http://localhost:26657']
    assert chain.websockets == []
    assert chain.rests == ['http://localhost:1317']
    assert chain.home_chain
    assert chain.whitelist_clients == ['c1']
    assert chain.blacklist_clients == ['c2']
    assert chain.state_refresh_interval == 123
    assert chain.state_scan_timeout == 45
    # exporter
    assert cfg.address == '127.0.0.1'
    assert cfg.port == 9000
    assert cfg.update_interval == 45
    assert cfg.log_level == 'DEBUG'
    assert cfg.omit_closed_channels is True
    assert cfg.omit_inactive_clients is True
    assert cfg.packet_indexer_enabled is False
    assert cfg.packet_indexer_store_path == 'packet-indexer.sqlite'
    assert cfg.packet_indexer_backfill_on_start_blocks == 0
    assert cfg.packet_indexer_gap_backfill is True
    assert cfg.packet_indexer_backfill_workers == 1
    assert cfg.packet_indexer_backfill_batch_size == 100
    assert chain.omit_closed_channels is True
    assert chain.omit_inactive_clients is True
    assert chain.excluded_sequences == {'ch1': ['1', '2-3']}
    assert cfg.home_chain is chain
    # excluded sequences
    ex = cfg.excluded_sequences
    assert ex.is_excluded('ch1', 1, 'test-1')
    assert ex.is_excluded('ch1', 2, 'test-1')
    assert ex.is_excluded('ch1', 3, 'test-1')
    assert not ex.is_excluded('ch1', 4, 'test-1')
    assert not ex.is_excluded('ch1', 1, 'other-1')


def test_rejects_top_level_excluded_sequences(tmp_path):
    data = {
        'chains': [
            {'name': 'home', 'chain_id': 'home-1', 'rests': ['http://home'], 'home_chain': True},
        ],
        'excluded_sequences': {'home-1': {'channel-0': [1]}},
    }
    p = tmp_path / 'c.toml'
    p.write_text(toml.dumps(data))
    with pytest.raises(ValueError, match='inside each'):
        Config(p)


def test_requires_single_home_chain(tmp_path):
    data = {
        'chains': [
            {'name': 'a', 'chain_id': 'a-1', 'rests': ['http://a']},
            {'name': 'b', 'chain_id': 'b-1', 'rests': ['http://b']},
        ]
    }
    p = tmp_path / 'c.toml'
    p.write_text(toml.dumps(data))
    with pytest.raises(ValueError):
        Config(p)


def test_empty_counterparty_endpoints_are_ignored(tmp_path):
    data = {
        'chains': [
            {'name': 'home', 'chain_id': 'home-1', 'rests': ['http://home'], 'home_chain': True},
            {'name': 'cp', 'chain_id': 'cp-1', 'rests': [''], 'rpcs': [''], 'home_chain': False},
        ]
    }
    p = tmp_path / 'c.toml'
    p.write_text(toml.dumps(data))
    cfg = Config(p)
    assert cfg.chains[1].rests == []
    assert cfg.chains[1].rpcs == []


def test_home_chain_requires_valid_rest_endpoint(tmp_path):
    data = {
        'chains': [
            {'name': 'home', 'chain_id': 'home-1', 'rests': [''], 'home_chain': True},
        ]
    }
    p = tmp_path / 'c.toml'
    p.write_text(toml.dumps(data))
    with pytest.raises(ValueError, match='Home chain'):
        Config(p)


def test_rejects_invalid_endpoint_url(tmp_path):
    data = {
        'chains': [
            {'name': 'home', 'chain_id': 'home-1', 'rests': ['http://home'], 'home_chain': True},
            {'name': 'cp', 'chain_id': 'cp-1', 'rests': ['not-a-url'], 'home_chain': False},
        ]
    }
    p = tmp_path / 'c.toml'
    p.write_text(toml.dumps(data))
    with pytest.raises(ValueError, match='invalid URL'):
        Config(p)
    data['chains'][0]['home_chain'] = True
    data['chains'][1]['home_chain'] = True
    p.write_text(toml.dumps(data))
    with pytest.raises(ValueError):
        Config(p)


def test_packet_indexer_config_parsing(tmp_path):
    data = {
        'chains': [
            {
                'name': 'home',
                'chain_id': 'home-1',
                'rests': ['http://home-rest'],
                'rpcs': ['https://home-rpc'],
                'websockets': ['wss://home-rpc/websocket'],
                'home_chain': True,
            },
        ],
        'indexer': {
            'enabled': True,
            'store_path': 'packets.sqlite',
            'backfill_on_start_blocks': 25,
            'gap_backfill': False,
            'backfill_workers': 4,
            'backfill_batch_size': 50,
            'queue_size': 1234,
            'prune_after_seconds': 3600,
            'rpc_timeout_seconds': 7,
            'reconnect_initial_seconds': 2,
            'reconnect_max_seconds': 40,
        },
    }
    p = tmp_path / 'c.toml'
    p.write_text(toml.dumps(data))

    cfg = Config(p)

    assert cfg.chains[0].websockets == ['wss://home-rpc/websocket']
    assert cfg.packet_indexer_enabled is True
    assert cfg.packet_indexer_store_path == 'packets.sqlite'
    assert cfg.packet_indexer_backfill_on_start_blocks == 25
    assert cfg.packet_indexer_gap_backfill is False
    assert cfg.packet_indexer_backfill_workers == 4
    assert cfg.packet_indexer_backfill_batch_size == 50
    assert cfg.packet_indexer_queue_size == 1234
    assert cfg.packet_indexer_prune_after_seconds == 3600
    assert cfg.packet_indexer_rpc_timeout == 7
    assert cfg.packet_indexer_reconnect_initial_seconds == 2
    assert cfg.packet_indexer_reconnect_max_seconds == 40


def test_rejects_invalid_indexer_table(tmp_path):
    data = {
        'chains': [
            {'name': 'home', 'chain_id': 'home-1', 'rests': ['http://home'], 'home_chain': True},
        ],
        'indexer': 'enabled',
    }
    p = tmp_path / 'c.toml'
    p.write_text(toml.dumps(data))
    with pytest.raises(ValueError, match='indexer must be a table'):
        Config(p)
