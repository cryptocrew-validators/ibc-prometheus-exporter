import pytest
import requests
from ibc_monitor.rest_client import RESTClient


class DummyResponse:
    def __init__(self, json_data, status=200):
        self._json = json_data
        self.status_code = status

    def raise_for_status(self):
        if self.status_code != 200:
            raise requests.HTTPError()

    def json(self):
        return self._json


@pytest.fixture
def patch_health(monkeypatch):
    calls = {"chainjson": 0, "node_info": 0}

    def fake_get(url, params=None, timeout=3):
        if "chain-registry" in url:
            calls["chainjson"] += 1
            return DummyResponse({"apis": {"rest": [{"address": "http://fb1"}, {"address": "http://fb2"}]}})
        elif url.endswith("/cosmos/base/tendermint/v1beta1/node_info"):
            calls["node_info"] += 1
            return DummyResponse({"default_node_info": {"network": "test-1"}})
        else:
            pytest.skip(f"Unexpected URL: {url}")

    monkeypatch.setattr(requests, "get", fake_get)
    return calls


def test_health_primary_and_fallback(patch_health):
    calls = patch_health
    client = RESTClient('http://primary', 'test-1', 'testchain')
    # first health loads fallbacks and checks primary + fallbacks
    ok = client.health()
    assert ok
    # endpoint switched if unable? Here primary returns correct network so stays
    assert client.endpoint == 'http://primary'
    assert calls['chainjson'] == 1
    assert calls['node_info'] >= 1


def test_query_switches_to_healthy_fallback(monkeypatch):
    def fake_get(url, params=None, timeout=3):
        if 'chain-registry' in url:
            return DummyResponse({'apis': {'rest': [{'address': 'http://fb1'}]}})
        if url.endswith('/cosmos/base/tendermint/v1beta1/node_info'):
            return DummyResponse({'default_node_info': {'network': 'test-1'}})
        if url == 'http://primary/foo':
            raise requests.RequestException('boom')
        if url == 'http://fb1/foo':
            return DummyResponse({'ok': 1})
        pytest.fail(f'Unexpected URL {url}')

    monkeypatch.setattr(requests, 'get', fake_get)
    client = RESTClient('http://primary', 'test-1', 'testchain')
    data = client.query('/foo')
    assert data == {'ok': 1}
    assert client.endpoint == 'http://fb1'
    assert 'http://primary' in client.unhealthy


def test_query_returns_empty_when_all_fail(monkeypatch):
    def fake_get(url, params=None, timeout=3):
        if 'chain-registry' in url:
            return DummyResponse({'apis': {'rest': [{'address': 'http://fb1'}]}})
        if url.endswith('/cosmos/base/tendermint/v1beta1/node_info'):
            return DummyResponse({'default_node_info': {'network': 'test-1'}})
        raise requests.RequestException('boom')

    monkeypatch.setattr(requests, 'get', fake_get)
    client = RESTClient('http://primary', 'test-1', 'testchain')
    data = client.query('/foo')
    assert data == {}
