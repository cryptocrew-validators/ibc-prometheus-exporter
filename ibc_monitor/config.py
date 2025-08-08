import toml
from pathlib import Path
from typing import Any, Dict, List
import fnmatch

ListStr = List[str]


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


class ExcludedSequences:
    def __init__(self, raw: Dict[str, List[Any]]):
        self.map: Dict[str, set[int]] = {}
        for channel, seqs in raw.items():
            parsed: List[int] = []
            for s in seqs:
                if isinstance(s, str) and '-' in s:
                    start, end = map(int, s.split('-'))
                    parsed.extend(range(start, end + 1))
                else:
                    parsed.append(int(s))
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
        self.chains: List[ChainConfig] = []
        for c in data.get('chains', []):
            self.chains.append(
                ChainConfig(
                    name=c['name'],
                    chain_id=c['chain_id'],
                    rpcs=c.get('rpcs', []),
                    rests=c.get('rests', []),
                    whitelist_clients=c.get('whitelist_clients', []),
                    blacklist_clients=c.get('blacklist_clients', []),
                    whitelist_connections=c.get('whitelist_connections', []),
                    blacklist_connections=c.get('blacklist_connections', []),
                    whitelist_channels=c.get('whitelist_channels', []),
                    blacklist_channels=c.get('blacklist_channels', []),
                    state_refresh_interval=c.get('state_refresh_interval', 1800),
                    state_scan_timeout=c.get('state_scan_timeout', 60),
                    home_chain=c.get('home_chain', False),
                )
            )
        home = [c for c in self.chains if c.home_chain]
        if len(home) != 1:
            raise ValueError('Exactly one chain must be marked as home_chain')
        self.home_chain = home[0]
        self.excluded_sequences = ExcludedSequences(
            data.get('excluded_sequences', {})
        )
        exporter = data.get('exporter', {})
        self.address = exporter.get('address', '0.0.0.0')
        self.port = exporter.get('port', 8000)
        self.update_interval = exporter.get('update_interval_seconds', 30)
        self.log_level = exporter.get('log_level', 'INFO')

