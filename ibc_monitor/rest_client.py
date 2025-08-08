import logging
from typing import List, Optional, Set

import requests

logger = logging.getLogger(__name__)


class RESTClient:
    """Simple REST client with fallback endpoint support.

    The client will attempt to use the configured primary endpoint and fall back
    to additional endpoints defined in the Cosmos chain-registry if the primary
    becomes unavailable.  Health checks are performed against the gRPC-gateway
    ``node_info`` endpoint which exposes the chain ID of the node.
    """

    def __init__(self, primary_endpoint: str, expected_chain_id: str, chain_name: str):
        self.primary = primary_endpoint.rstrip("/")
        self.expected_chain_id = expected_chain_id
        self.chain_name = chain_name
        self.endpoint = self.primary
        self.fallbacks: List[str] = []
        self._loaded_fallbacks = False
        self.unhealthy: Set[str] = set()

    def _load_fallbacks(self) -> None:
        """Load REST fallbacks from the Cosmos chain-registry."""
        try:
            url = (
                "https://raw.githubusercontent.com/cosmos/chain-registry/master/"
                f"{self.chain_name}/chain.json"
            )
            resp = requests.get(url, timeout=3)
            resp.raise_for_status()
            data = resp.json()
            for api in data.get("apis", {}).get("rest", []):
                addr = api.get("address", "").rstrip("/")
                if addr and addr != self.primary:
                    self.fallbacks.append(addr)
            logger.info(
                "Loaded %d fallback REST endpoint(s) for chain %s",
                len(self.fallbacks),
                self.chain_name,
            )
        except Exception as e:  # pragma: no cover - network failures
            logger.warning("Failed to load fallback REST endpoints for %s: %s", self.chain_name, e)
        finally:
            self._loaded_fallbacks = True

    def health(self) -> bool:
        """Check the health of the current endpoint and switch if necessary."""
        if not self._loaded_fallbacks:
            self._load_fallbacks()
        endpoints = [self.primary] + self.fallbacks
        if len(self.unhealthy) >= len(endpoints):
            self.unhealthy.clear()
        for ep in endpoints:
            if ep in self.unhealthy:
                continue
            try:
                url = f"{ep}/cosmos/base/tendermint/v1beta1/node_info"
                resp = requests.get(url, timeout=3)
                resp.raise_for_status()
                chain_id = resp.json().get("default_node_info", {}).get("network", "")
                if chain_id != self.expected_chain_id:
                    logger.error(
                        "Chain ID mismatch on %s: got %s, expected %s",
                        ep,
                        chain_id,
                        self.expected_chain_id,
                    )
                    self.unhealthy.add(ep)
                    continue
                if ep != self.endpoint:
                    logger.info("Switching endpoint from %s to %s", self.endpoint, ep)
                    self.endpoint = ep
                return True
            except Exception as e:  # pragma: no cover - network failures
                logger.warning("REST health check failed for %s: %s", ep, e)
                self.unhealthy.add(ep)
                continue
        return False

    def query(self, path: str, params: Optional[dict] = None, timeout: int = 3) -> dict:
        """Perform a GET request on the current REST endpoint."""
        attempts = 0
        while attempts < len([self.primary] + self.fallbacks):
            url = f"{self.endpoint}{path}"
            logger.debug("GET %s params=%s", url, params)
            try:
                r = requests.get(url, params=params or {}, timeout=timeout)
                logger.debug("Response %s -> %s", url, r.status_code)
                r.raise_for_status()
                return r.json()
            except Exception as e:  # pragma: no cover - network failures
                logger.warning("REST query failed for %s: %s", url, e)
                self.unhealthy.add(self.endpoint)
                if not self.health():
                    break
            attempts += 1
        logger.error("All REST endpoints failed for %s", path)
        return {}

