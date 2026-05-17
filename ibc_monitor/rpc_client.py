from __future__ import annotations

import datetime
import logging
from typing import List, Optional, Set
from urllib.parse import urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)


class RPCClientError(Exception):
    """Base error for RPC client failures."""


class RPCQueryError(RPCClientError):
    """Raised when a query cannot be completed against any RPC endpoint."""

    def __init__(self, path: str, endpoint: str, cause: Exception | None = None):
        self.path = path
        self.endpoint = endpoint
        self.cause = cause
        self.status_code = getattr(getattr(cause, "response", None), "status_code", None)
        msg = f"RPC query failed for {path} on {endpoint or '<empty endpoint>'}"
        if cause is not None:
            msg = f"{msg}: {cause}"
        super().__init__(msg)


def parse_rpc_time(ts: str | None) -> int | None:
    """Parse CometBFT RFC3339 timestamps into epoch seconds."""
    if not ts:
        return None
    try:
        normalized = str(ts).replace("Z", "+00:00")
        if "." in normalized:
            prefix, rest = normalized.split(".", 1)
            tz_pos = max(rest.rfind("+"), rest.rfind("-"))
            if tz_pos >= 0:
                frac = rest[:tz_pos]
                tz = rest[tz_pos:]
                normalized = f"{prefix}.{frac[:6].ljust(6, '0')}{tz}"
        return int(datetime.datetime.fromisoformat(normalized).timestamp())
    except Exception:
        logger.debug("Failed to parse RPC timestamp %r", ts, exc_info=True)
        return None


def websocket_url_for_rpc(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    path = parsed.path.rstrip("/")
    if not path.endswith("/websocket"):
        path = f"{path}/websocket" if path else "/websocket"
    return urlunparse((scheme, parsed.netloc, path, "", "", ""))


class RPCStatus:
    def __init__(self, chain_id: str, latest_height: int, latest_timestamp: int | None):
        self.chain_id = chain_id
        self.latest_height = latest_height
        self.latest_timestamp = latest_timestamp


class RPCClient:
    """CometBFT RPC client with endpoint fallback and chain-id validation."""

    def __init__(
        self,
        primary_endpoint: str,
        expected_chain_id: str,
        chain_name: str,
        fallback_endpoints: Optional[List[str]] = None,
        websocket_endpoints: Optional[List[str]] = None,
        enable_chain_registry_fallbacks: bool = False,
    ):
        self.primary = (primary_endpoint or "").strip().rstrip("/")
        self.expected_chain_id = expected_chain_id
        self.chain_name = chain_name
        self.fallbacks: List[str] = []
        for endpoint in fallback_endpoints or []:
            endpoint = endpoint.strip().rstrip("/")
            if endpoint and endpoint != self.primary and endpoint not in self.fallbacks:
                self.fallbacks.append(endpoint)
        self.websocket_overrides = [
            endpoint.strip().rstrip("/")
            for endpoint in websocket_endpoints or []
            if endpoint and endpoint.strip()
        ]
        if not self.primary and not self.fallbacks and not enable_chain_registry_fallbacks:
            raise ValueError(f"No RPC endpoints configured for chain {expected_chain_id}")
        self.endpoint = self.primary or (self.fallbacks[0] if self.fallbacks else "")
        self.enable_chain_registry_fallbacks = enable_chain_registry_fallbacks
        self._loaded_fallbacks = not enable_chain_registry_fallbacks
        self.unhealthy: Set[str] = set()

    def _load_fallbacks(self) -> None:
        """Load RPC fallbacks from the Cosmos chain-registry."""
        if not self.enable_chain_registry_fallbacks:
            self._loaded_fallbacks = True
            return
        try:
            url = (
                "https://raw.githubusercontent.com/cosmos/chain-registry/master/"
                f"{self.chain_name}/chain.json"
            )
            resp = requests.get(url, timeout=3)
            resp.raise_for_status()
            data = resp.json()
            for api in data.get("apis", {}).get("rpc", []):
                addr = api.get("address", "").strip().rstrip("/")
                if addr and addr != self.primary and addr not in self.fallbacks:
                    self.fallbacks.append(addr)
            logger.info(
                "Loaded %d fallback RPC endpoint(s) for chain %s",
                len(self.fallbacks),
                self.chain_name,
            )
        except Exception as e:  # pragma: no cover - network failures
            logger.warning("Failed to load fallback RPC endpoints for %s: %s", self.chain_name, e)
        finally:
            self._loaded_fallbacks = True

    def endpoints(self) -> List[str]:
        if not self._loaded_fallbacks:
            self._load_fallbacks()
        endpoints = []
        for endpoint in [self.primary] + self.fallbacks:
            if endpoint and endpoint not in endpoints:
                endpoints.append(endpoint)
        if self.endpoint not in endpoints and endpoints:
            self.endpoint = endpoints[0]
        return endpoints

    def websocket_endpoint(self) -> str:
        if self.websocket_overrides:
            return self.websocket_overrides[0]
        return websocket_url_for_rpc(self.endpoint) if self.endpoint else ""

    def clone(self) -> "RPCClient":
        """Return an independent client with the same known endpoints."""
        self.endpoints()
        clone = RPCClient(
            self.primary,
            self.expected_chain_id,
            self.chain_name,
            fallback_endpoints=list(self.fallbacks),
            websocket_endpoints=list(self.websocket_overrides),
            enable_chain_registry_fallbacks=False,
        )
        clone.endpoint = self.endpoint
        clone.unhealthy = set(self.unhealthy)
        return clone

    def status(self, timeout: int = 3) -> RPCStatus:
        data = self.query("/status", timeout=timeout)
        return self._parse_status(data)

    @staticmethod
    def _parse_status(data: dict) -> RPCStatus:
        result = data.get("result", {}) or {}
        node_info = result.get("node_info", {}) or {}
        sync_info = result.get("sync_info", {}) or {}
        chain_id = node_info.get("network", "")
        try:
            height = int(sync_info.get("latest_block_height") or 0)
        except (TypeError, ValueError):
            height = 0
        timestamp = parse_rpc_time(sync_info.get("latest_block_time"))
        return RPCStatus(chain_id=chain_id, latest_height=height, latest_timestamp=timestamp)

    def health(self, timeout: int = 3) -> bool:
        endpoints = self.endpoints()
        if not endpoints:
            return False
        if len(self.unhealthy) >= len(endpoints):
            self.unhealthy.clear()
        for ep in endpoints:
            if ep in self.unhealthy:
                continue
            previous = self.endpoint
            self.endpoint = ep
            try:
                resp = requests.get(f"{ep}/status", timeout=timeout)
                resp.raise_for_status()
                status = self._parse_status(resp.json())
                if status.chain_id != self.expected_chain_id:
                    logger.error(
                        "Chain ID mismatch on RPC %s: got %s, expected %s",
                        ep,
                        status.chain_id,
                        self.expected_chain_id,
                    )
                    self.unhealthy.add(ep)
                    self.endpoint = previous
                    continue
                return True
            except Exception as e:  # pragma: no cover - network failures
                logger.warning("RPC health check failed for %s: %s", ep, e)
                self.unhealthy.add(ep)
                self.endpoint = previous
                continue
        return False

    def query(self, path: str, params: Optional[dict] = None, timeout: int = 3) -> dict:
        if not path.startswith("/"):
            raise ValueError(f"RPC query path must start with '/': {path}")

        attempts = 0
        last_error: Exception | None = None
        endpoints = self.endpoints()
        if not endpoints:
            raise RPCQueryError(path, self.endpoint, ValueError("no RPC endpoints available"))
        while attempts < len(endpoints):
            url = f"{self.endpoint}{path}"
            logger.debug("RPC GET %s params=%s", url, params)
            try:
                r = requests.get(url, params=params or {}, timeout=timeout)
                logger.debug("RPC response %s -> %s", url, r.status_code)
                r.raise_for_status()
                return r.json()
            except Exception as e:  # pragma: no cover - network failures
                last_error = e
                logger.warning("RPC query failed for %s: %s", url, e)
                self.unhealthy.add(self.endpoint)
                if not self.health(timeout=timeout):
                    break
                endpoints = self.endpoints()
            attempts += 1
        logger.error("All RPC endpoints failed for %s", path)
        raise RPCQueryError(path, self.endpoint, last_error)

    def block_results(self, height: int, timeout: int = 3) -> dict:
        return self.query("/block_results", params={"height": str(height)}, timeout=timeout)

    def block(self, height: int, timeout: int = 3) -> dict:
        return self.query("/block", params={"height": str(height)}, timeout=timeout)
