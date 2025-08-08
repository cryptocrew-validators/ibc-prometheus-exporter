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
            }
        ],
        'excluded_sequences': {'ch1': ['1', '2-3']},
        'exporter': {
            'address': '127.0.0.1',
            'port': 9000,
            'update_interval_seconds': 45,
            'log_level': 'DEBUG',
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
    assert cfg.home_chain is chain
    # excluded sequences
    ex = cfg.excluded_sequences
    assert ex.is_excluded('ch1', 1)
    assert ex.is_excluded('ch1', 2)
    assert ex.is_excluded('ch1', 3)
    assert not ex.is_excluded('ch1', 4)


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
    data['chains'][0]['home_chain'] = True
    data['chains'][1]['home_chain'] = True
    p.write_text(toml.dumps(data))
    with pytest.raises(ValueError):
        Config(p)
