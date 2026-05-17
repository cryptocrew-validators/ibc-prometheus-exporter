import pytest
import requests

from ibc_monitor.rpc_client import RPCClient, RPCQueryError, websocket_url_for_rpc


class DummyResponse:
    def __init__(self, json_data, status=200):
        self._json = json_data
        self.status_code = status

    def raise_for_status(self):
        if self.status_code != 200:
            raise requests.HTTPError()

    def json(self):
        return self._json


def status(chain_id="test-1", height="10"):
    return {
        "result": {
            "node_info": {"network": chain_id},
            "sync_info": {
                "latest_block_height": height,
                "latest_block_time": "2026-01-02T03:04:05Z",
            },
        }
    }


def test_websocket_url_for_rpc():
    assert websocket_url_for_rpc("https://rpc.example.com") == "wss://rpc.example.com/websocket"
    assert websocket_url_for_rpc("http://rpc.example.com/base") == "ws://rpc.example.com/base/websocket"


def test_rpc_health_validates_chain_and_status(monkeypatch):
    def fake_get(url, params=None, timeout=3):
        if url == "http://primary/status":
            return DummyResponse(status())
        pytest.fail(f"Unexpected URL {url}")

    monkeypatch.setattr(requests, "get", fake_get)
    client = RPCClient("http://primary", "test-1", "testchain")

    assert client.health() is True
    rpc_status = client.status()
    assert rpc_status.chain_id == "test-1"
    assert rpc_status.latest_height == 10
    assert rpc_status.latest_timestamp == 1767323045


def test_rpc_query_switches_to_fallback(monkeypatch):
    def fake_get(url, params=None, timeout=3):
        if url == "http://primary/foo":
            raise requests.RequestException("boom")
        if url == "http://fb/status":
            return DummyResponse(status())
        if url == "http://fb/foo":
            return DummyResponse({"ok": 1})
        pytest.fail(f"Unexpected URL {url}")

    monkeypatch.setattr(requests, "get", fake_get)
    client = RPCClient("http://primary", "test-1", "testchain", fallback_endpoints=["http://fb"])

    assert client.query("/foo") == {"ok": 1}
    assert client.endpoint == "http://fb"
    assert "http://primary" in client.unhealthy


def test_rpc_query_raises_when_all_endpoints_fail(monkeypatch):
    def fake_get(url, params=None, timeout=3):
        raise requests.RequestException("boom")

    monkeypatch.setattr(requests, "get", fake_get)
    client = RPCClient("http://primary", "test-1", "testchain")

    with pytest.raises(RPCQueryError):
        client.query("/foo")
