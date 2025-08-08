import pytest
from ibc_monitor.state_scanner import StateScanner
from requests.exceptions import HTTPError
from requests import Response


class DummyClient:
    def __init__(self, data):
        self._data = data
        self.expected_chain_id = 'unused'

    def query(self, path, params=None, timeout=None):
        # return based on path
        return self._data.get(path, {})

    def health(self):
        return True

class DummyCfg:
    whitelist_clients = []
    blacklist_clients = []
    whitelist_connections = []
    blacklist_connections = []
    whitelist_channels = []
    blacklist_channels = []
    state_refresh_interval = 0
    state_scan_timeout = 1

@pytest.fixture
def scanner():
    data = {
        '/ibc/core/client/v1/client_states': {
            'client_states': [
                {'client_id': 'c1', 'client_state': {'chain_id': 'cp'}},
                {'client_id': 'c2', 'client_state': {'chain_id': 'cp'}},
            ]
        },
        '/ibc/core/connection/v1/client_connections/c1': {
            'connection_paths': ['conn1']
        },
        '/ibc/core/connection/v1/client_connections/c2': {
            'connection_paths': []
        },
        '/ibc/core/channel/v1/connections/conn1/channels': {
            'channels': [{'port_id': 'p', 'channel_id': 'c', 'counterparty': {'port_id': 'cp', 'channel_id': 'cc'}}]
        },
    }
    client = DummyClient(data)
    cfg = DummyCfg()
    return StateScanner(client, cfg, ['cp'])


def test_scan_all(scanner):
    scanner.scan()
    assert scanner.clients == ['c1']
    assert scanner.connections == ['conn1']
    assert ('conn1', 'p', 'c', 'cp', 'cc', 'cp') in scanner.channels


class DummyClientWith404(DummyClient):
    def __init__(self, data, error_paths):
        super().__init__(data)
        self.error_paths = error_paths

    def query(self, path, params=None, timeout=None):
        if path in self.error_paths:
            resp = Response()
            resp.status_code = 404
            raise HTTPError(response=resp)
        return super().query(path, params, timeout)


def test_scan_ignores_missing_connections():
    data = {
        '/ibc/core/client/v1/client_states': {
            'client_states': [
                {'client_id': 'c1', 'client_state': {'chain_id': 'cp'}},
            ]
        },
    }
    client = DummyClientWith404(
        data, {'/ibc/core/connection/v1/client_connections/c1'}
    )
    cfg = DummyCfg()
    scanner = StateScanner(client, cfg, ['cp'])
    scanner.scan()
    assert scanner.clients == []
    assert scanner.connections == []
    assert scanner.channels == []


def test_scan_ignores_missing_channels():
    data = {
        '/ibc/core/client/v1/client_states': {
            'client_states': [
                {'client_id': 'c1', 'client_state': {'chain_id': 'cp'}},
            ]
        },
        '/ibc/core/connection/v1/client_connections/c1': {
            'connection_paths': ['conn1']
        },
    }
    client = DummyClientWith404(
        data, {'/ibc/core/channel/v1/connections/conn1/channels'}
    )
    cfg = DummyCfg()
    scanner = StateScanner(client, cfg, ['cp'])
    scanner.scan()
    assert scanner.clients == ['c1']
    assert scanner.connections == ['conn1']
    assert scanner.channels == []


def test_skips_wrong_counterparty():
    data = {
        '/ibc/core/client/v1/client_states': {
            'client_states': [
                {'client_id': 'c1', 'client_state': {'chain_id': 'cp'}},
                {'client_id': 'c2', 'client_state': {'chain_id': 'other'}},
            ]
        },
        '/ibc/core/connection/v1/client_connections/c1': {
            'connection_paths': ['conn1']
        },
        '/ibc/core/connection/v1/client_connections/c2': {
            'connection_paths': ['conn2']
        },
    }
    client = DummyClient(data)
    cfg = DummyCfg()
    scanner = StateScanner(client, cfg, ['cp'])
    scanner.scan()
    assert scanner.clients == ['c1']
    assert scanner.connections == ['conn1']

