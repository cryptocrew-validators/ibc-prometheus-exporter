import toml
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

ListStr = List[str]
DEFAULT_MAX_PAGINATION_PAGES = 1000
DEFAULT_PAGINATION_LIMIT = 100


class ChainConfig:
    def __init__(
        self,
        name: str,
        chain_id: str,
        rpcs: List[str],
        rests: List[str],
        whitelist_clients: ListStr,
        blacklist_clients: ListStr,
        whitelist_connections: ListStr,
        blacklist_connections: ListStr,
        whitelist_channels: ListStr,
        blacklist_channels: ListStr,
        state_refresh_interval: int,
        state_scan_timeout: int,
        home_chain: bool = False,
        max_pagination_pages: int = DEFAULT_MAX_PAGINATION_PAGES,
        pagination_limit: int = DEFAULT_PAGINATION_LIMIT,
    ):
        self.name = name
        self.chain_id = chain_id
        self.rpcs = rpcs
        self.rests = rests
        self.whitelist_clients = whitelist_clients
        self.blacklist_clients = blacklist_clients
        self.whitelist_connections = whitelist_connections
        self.blacklist_connections = blacklist_connections
        self.whitelist_channels = whitelist_channels
        self.blacklist_channels = blacklist_channels
        self.state_refresh_interval = state_refresh_interval
        self.state_scan_timeout = state_scan_timeout
        self.home_chain = home_chain
        self.max_pagination_pages = max_pagination_pages
        self.pagination_limit = pagination_limit


class ExcludedSequences:
    def __init__(self, raw: Dict[str, List[Any]]):
        self.map: Dict[str, set[int]] = {}
        for channel, seqs in raw.items():
            if not isinstance(channel, str) or not channel:
                raise ValueError("excluded_sequences keys must be non-empty channel IDs")
            if not isinstance(seqs, list):
                raise ValueError(f"excluded_sequences.{channel} must be a list")
            parsed: List[int] = []
            for s in seqs:
                if isinstance(s, str) and '-' in s:
                    start, end = map(int, s.split('-', 1))
                    if start <= 0 or end <= 0 or start > end:
                        raise ValueError(f"Invalid excluded sequence range {s!r} for {channel}")
                    parsed.extend(range(start, end + 1))
                else:
                    seq = int(s)
                    if seq <= 0:
                        raise ValueError(f"Invalid excluded sequence {s!r} for {channel}")
                    parsed.append(seq)
            self.map[channel] = set(parsed)

    def is_excluded(self, channel: str, seq: int) -> bool:
        return seq in self.map.get(channel, set())


class Config:
    def __init__(self, path: Path):
        try:
            import tomli
            with open(path, 'rb') as f:
                data = tomli.load(f)
        except ImportError:
            data = toml.load(path)
        raw_chains = data.get('chains', [])
        if not isinstance(raw_chains, list):
            raise ValueError('chains must be a list of chain tables')

        self.chains: List[ChainConfig] = []
        seen_chain_ids: set[str] = set()
        for c in raw_chains:
            if not isinstance(c, dict):
                raise ValueError('Each chain entry must be a table')
            name = self._required_str(c, 'name')
            chain_id = self._required_str(c, 'chain_id')
            if chain_id in seen_chain_ids:
                raise ValueError(f"Duplicate chain_id in config: {chain_id}")
            seen_chain_ids.add(chain_id)

            state_refresh_interval = self._positive_int(
                c.get('state_refresh_interval', 1800),
                f"{chain_id}.state_refresh_interval",
            )
            state_scan_timeout = self._positive_int(
                c.get('state_scan_timeout', 60),
                f"{chain_id}.state_scan_timeout",
            )
            self.chains.append(
                ChainConfig(
                    name=name,
                    chain_id=chain_id,
                    rpcs=self._endpoint_list(c.get('rpcs', []), f"{chain_id}.rpcs"),
                    rests=self._endpoint_list(c.get('rests', []), f"{chain_id}.rests"),
                    whitelist_clients=self._str_list(c.get('whitelist_clients', []), f"{chain_id}.whitelist_clients"),
                    blacklist_clients=self._str_list(c.get('blacklist_clients', []), f"{chain_id}.blacklist_clients"),
                    whitelist_connections=self._str_list(c.get('whitelist_connections', []), f"{chain_id}.whitelist_connections"),
                    blacklist_connections=self._str_list(c.get('blacklist_connections', []), f"{chain_id}.blacklist_connections"),
                    whitelist_channels=self._str_list(c.get('whitelist_channels', []), f"{chain_id}.whitelist_channels"),
                    blacklist_channels=self._str_list(c.get('blacklist_channels', []), f"{chain_id}.blacklist_channels"),
                    state_refresh_interval=state_refresh_interval,
                    state_scan_timeout=state_scan_timeout,
                    home_chain=c.get('home_chain', False),
                    max_pagination_pages=self._positive_int(
                        c.get('max_pagination_pages', DEFAULT_MAX_PAGINATION_PAGES),
                        f"{chain_id}.max_pagination_pages",
                    ),
                    pagination_limit=self._positive_int(
                        c.get('pagination_limit', DEFAULT_PAGINATION_LIMIT),
                        f"{chain_id}.pagination_limit",
                    ),
                )
            )
        home = [c for c in self.chains if c.home_chain]
        if len(home) != 1:
            raise ValueError('Exactly one chain must be marked as home_chain')
        self.home_chain = home[0]
        if not self.home_chain.rests:
            raise ValueError(f"Home chain {self.home_chain.chain_id} must define at least one valid REST endpoint")
        excluded_sequences = data.get('excluded_sequences', {})
        if not isinstance(excluded_sequences, dict):
            raise ValueError('excluded_sequences must be a table')
        self.excluded_sequences = ExcludedSequences(excluded_sequences)
        exporter = data.get('exporter', {})
        if not isinstance(exporter, dict):
            raise ValueError('exporter must be a table')
        self.address = self._optional_str(exporter.get('address', '0.0.0.0'), 'exporter.address')
        self.port = self._port(exporter.get('port', 8000))
        self.update_interval = self._positive_int(
            exporter.get('update_interval_seconds', 30),
            'exporter.update_interval_seconds',
        )
        self.log_level = self._optional_str(exporter.get('log_level', 'INFO'), 'exporter.log_level')
        self.enable_chain_registry_fallbacks = self._bool(
            exporter.get('enable_chain_registry_fallbacks', False),
            'exporter.enable_chain_registry_fallbacks',
        )
        self.max_pagination_pages = self._positive_int(
            exporter.get('max_pagination_pages', DEFAULT_MAX_PAGINATION_PAGES),
            'exporter.max_pagination_pages',
        )
        self.pagination_limit = self._positive_int(
            exporter.get('pagination_limit', DEFAULT_PAGINATION_LIMIT),
            'exporter.pagination_limit',
        )

    @staticmethod
    def _required_str(data: Dict[str, Any], key: str) -> str:
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Missing or invalid required string field: {key}")
        return value.strip()

    @staticmethod
    def _optional_str(value: Any, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _str_list(value: Any, name: str) -> List[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError(f"{name} must be a list of strings")
        out: List[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"{name} must contain only strings")
            item = item.strip()
            if item:
                out.append(item)
        return out

    @classmethod
    def _endpoint_list(cls, value: Any, name: str) -> List[str]:
        endpoints = []
        for endpoint in cls._str_list(value, name):
            parsed = urlparse(endpoint)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"{name} contains invalid URL: {endpoint}")
            endpoints.append(endpoint.rstrip("/"))
        return endpoints

    @staticmethod
    def _positive_int(value: Any, name: str) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"{name} must be a positive integer")
        if parsed <= 0:
            raise ValueError(f"{name} must be a positive integer")
        return parsed

    @staticmethod
    def _bool(value: Any, name: str) -> bool:
        if not isinstance(value, bool):
            raise ValueError(f"{name} must be a boolean")
        return value

    @classmethod
    def _port(cls, value: Any) -> int:
        port = cls._positive_int(value, 'exporter.port')
        if port > 65535:
            raise ValueError('exporter.port must be between 1 and 65535')
        return port
