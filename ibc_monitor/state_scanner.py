import time
import logging
from typing import List, Tuple, Dict, Set, Optional
import fnmatch
from requests.exceptions import HTTPError
from urllib.parse import quote_plus
from ibc_monitor.rest_client import RESTClient

logger = logging.getLogger(__name__)

class StateScanner:
    """
    Scans IBC state starting from a single *home* chain and then explicitly
    queries counterparties using the connection IDs discovered on the home chain.

    Home chain flow:
      client_states (paginated) -> filter by counterparty chain_id (allowlist)
      -> client_connections/{cid} (paginated)
      -> connections/{conn} (single)
      -> channels for {conn} (paginated)

    Counterparty flow:
      For each counterparty chain_id, use the *derived* counterparty.connection_id
      from the home connection state and list channels for that connection.
      No enumeration of /client_states on counterparties.
    """

    def __init__(
        self,
        client: RESTClient,                     # home chain REST client
        cfg,
        counterparty_chain_ids: List[str],
        rest_by_chain: Optional[Dict[str, RESTClient]] = None,  # cp chain_id -> RESTClient
        home_chain_id: Optional[str] = None,
    ):
        self.rest = client
        self.cfg = cfg
        self.counterparty_chain_ids = set(counterparty_chain_ids)
        self.rest_by_chain = rest_by_chain or {}
        self.home_chain_id = home_chain_id or getattr(self.rest, "expected_chain_id", "")

        self.last_scan = 0

        # home-side state (kept for backward compatibility with exporter)
        self.clients: List[str] = []
        self.connections: List[str] = []
        self.client_chain_map: Dict[str, str] = {}
        self.client_counterparty_client_ids: Dict[str, str] = {}
        self.connection_client_map: Dict[str, str] = {}
        # (connection, port, channel, counterparty_port, counterparty_channel, counterparty_chain)
        self.channels: List[Tuple[str, str, str, str, str, str]] = []

        # counterparty-side state (optional, informational)
        # cp_connections: chain_id -> list of cp connection ids we scanned
        self.cp_connections: Dict[str, List[str]] = {}
        # (cp_chain, connection, port, channel, counterparty_port, counterparty_channel, counterparty_chain)
        self.cp_channels: List[Tuple[str, str, str, str, str, str, str]] = []

    # ------------- helpers -------------

    def _query_all(self, path: str, list_key: str, timeout: int, ignore_404: bool = False):
        """
        Follow pagination.next_key for list endpoints on the *home* REST client.
        Expects: { "<list_key>": [...], "pagination": {"next_key": "<base64>|null"} }
        """
        items: List = []
        next_key = None
        while True:
            qpath = path if not next_key else f"{path}{'&' if '?' in path else '?'}pagination.key={quote_plus(next_key)}"
            try:
                res = self.rest.query(qpath, timeout=timeout)
            except HTTPError as e:
                if ignore_404 and e.response is not None and e.response.status_code == 404:
                    return []
                raise
            items.extend(res.get(list_key, []) or [])
            next_key = (res.get("pagination") or {}).get("next_key")
            if not next_key:
                break
        return items

    def _query_all_on(self, rc: RESTClient, path: str, list_key: str, timeout: int, ignore_404: bool = False):
        """Follow pagination.next_key for list endpoints on a *given* REST client (counterparty)."""
        items: List = []
        next_key = None
        while True:
            qpath = path if not next_key else f"{path}{'&' if '?' in path else '?'}pagination.key={quote_plus(next_key)}"
            try:
                res = rc.query(qpath, timeout=timeout)
            except HTTPError as e:
                if ignore_404 and e.response is not None and e.response.status_code == 404:
                    return []
                raise
            items.extend(res.get(list_key, []) or [])
            next_key = (res.get("pagination") or {}).get("next_key")
            if not next_key:
                break
        return items

    def _filter_list(self, items: List[str], whitelist: List[str], blacklist: List[str]) -> List[str]:
        if whitelist:
            return [i for i in items if any(fnmatch.fnmatch(i, pat) for pat in whitelist)]
        return [i for i in items if not any(fnmatch.fnmatch(i, pat) for pat in blacklist)]

    def _match_any(self, item: str, whitelist: List[str], blacklist: List[str]) -> bool:
        if whitelist:
            return any(fnmatch.fnmatch(item, pat) for pat in whitelist)
        return not any(fnmatch.fnmatch(item, pat) for pat in blacklist)

    # ------------- main scan -------------

    def scan(self):
        now = time.time()
        if now - self.last_scan < self.cfg.state_refresh_interval:
            return
        self.last_scan = now

        # Only scan fully when this scanner runs on the designated *home* chain.
        current_chain = getattr(self.rest, "expected_chain_id", "")
        if current_chain != self.home_chain_id:
            logger.debug(
                "Skipping full scan on non-home chain %s (home=%s)",
                current_chain, self.home_chain_id
            )
            return

        home_chain_id = self.home_chain_id
        logger.debug("Scanning IBC state (home=%s)", home_chain_id)

        # 1) HOME: list all clients, keep only those whose client_state.chain_id is in the counterparty allowlist
        all_clients = self._query_all(
            "/ibc/core/client/v1/client_states",
            "client_states",
            timeout=self.cfg.state_scan_timeout,
        )

        client_chain_map: Dict[str, str] = {}
        local_clients: List[str] = []
        for c in all_clients:
            cid = c.get("client_id")
            chain_id = (c.get("client_state") or {}).get("chain_id")
            if not cid or not chain_id:
                continue
            if chain_id not in self.counterparty_chain_ids:
                logger.debug("Skipping client %s with counterparty chain %s", cid, chain_id)
                continue
            local_clients.append(cid)
            client_chain_map[cid] = chain_id

        # Apply client white/blacklists
        self.clients = self._filter_list(local_clients, self.cfg.whitelist_clients, self.cfg.blacklist_clients)
        self.client_chain_map = {cid: client_chain_map[cid] for cid in self.clients}
        logger.debug("Relevant clients (home): %s", self.clients)

        # 2) HOME: for each relevant client -> client_connections (paginated) -> connection state
        connection_client_map: Dict[str, str] = {}
        client_cp_client_ids: Dict[str, str] = {}
        all_conns: List[str] = []
        cp_conn_per_chain: Dict[str, Set[str]] = {}   # cp_chain_id -> {cp_connection_id}

        for cid in self.clients:
            conn_ids = self._query_all(
                f"/ibc/core/connection/v1/client_connections/{cid}",
                "connection_paths",
                timeout=self.cfg.state_scan_timeout,
                ignore_404=True,
            )
            if not conn_ids:
                logger.debug("No connections for client %s", cid)
                continue

            for conn in conn_ids:
                connection_client_map[conn] = cid
                # Single connection state
                try:
                    conn_res = self.rest.query(
                        f"/ibc/core/connection/v1/connections/{conn}",
                        timeout=self.cfg.state_scan_timeout,
                    ).get("connection", {}) or {}
                except HTTPError as e:
                    if e.response is not None and e.response.status_code == 404:
                        conn_res = {}
                    else:
                        raise

                cp = conn_res.get("counterparty") or {}
                cp_client_id = cp.get("client_id", "")
                cp_connection_id = cp.get("connection_id", "")

                if cp_client_id and cid not in client_cp_client_ids:
                    client_cp_client_ids[cid] = cp_client_id

                cp_chain = self.client_chain_map.get(cid)  # from client_state
                if cp_chain and cp_connection_id:
                    cp_conn_per_chain.setdefault(cp_chain, set()).add(cp_connection_id)

            all_conns.extend(conn_ids)

        # Apply connection white/blacklists
        self.connection_client_map = connection_client_map
        self.client_counterparty_client_ids = client_cp_client_ids
        filtered_conns = self._filter_list(all_conns, self.cfg.whitelist_connections, self.cfg.blacklist_connections)
        self.connections = filtered_conns
        logger.debug("Relevant connections (home): %s", self.connections)

        # 3) HOME: channels per relevant connection (paginated)
        chan_list: List[Tuple[str, str, str, str, str, str]] = []
        for conn in self.connections:
            chs = self._query_all(
                f"/ibc/core/channel/v1/connections/{conn}/channels",
                "channels",
                timeout=self.cfg.state_scan_timeout,
                ignore_404=True,
            )
            if not chs:
                logger.debug("No channels for connection %s", conn)
                continue

            local_client = self.connection_client_map.get(conn, "")
            cp_chain = self.client_chain_map.get(local_client, "")
            for ch in chs:
                port, channel = ch.get("port_id"), ch.get("channel_id")
                cp = ch.get("counterparty") or {}
                cp_port = cp.get("port_id", "")
                cp_channel = cp.get("channel_id", "")
                # (connection, port, channel, counterparty_port, counterparty_channel, counterparty_chain)
                chan_list.append((conn, port, channel, cp_port, cp_channel, cp_chain))

        # Apply channel white/blacklists (home)
        self.channels = [
            (conn, p, c, cp_p, cp_c, cp_chain)
            for (conn, p, c, cp_p, cp_c, cp_chain) in chan_list
            if self._match_any(f"{p}/{c}", self.cfg.whitelist_channels, self.cfg.blacklist_channels)
        ]

        # 4) COUNTERPARTIES: scan explicitly using cp connection ids from the *home* connection state
        self.cp_connections = {}
        self.cp_channels = []

        for cp_chain, cp_conn_ids in cp_conn_per_chain.items():
            rc = self.rest_by_chain.get(cp_chain)
            if not rc:
                logger.debug("No REST client configured for counterparty chain %s; skipping", cp_chain)
                continue

            cp_conn_ids_filtered = self._filter_list(
                list(cp_conn_ids),
                self.cfg.whitelist_connections,
                self.cfg.blacklist_connections,
            )
            self.cp_connections[cp_chain] = cp_conn_ids_filtered

            for cp_conn in cp_conn_ids_filtered:
                chs = self._query_all_on(
                    rc,
                    f"/ibc/core/channel/v1/connections/{cp_conn}/channels",
                    "channels",
                    timeout=self.cfg.state_scan_timeout,
                    ignore_404=True,
                )
                if not chs:
                    logger.debug("No channels on %s for counterparty %s", cp_conn, cp_chain)
                    continue

                for ch in chs:
                    port, channel = ch.get("port_id"), ch.get("channel_id")
                    cp = ch.get("counterparty") or {}
                    cp_port = cp.get("port_id", "")
                    cp_channel = cp.get("channel_id", "")
                    # On the CP side, the counterparty chain is the HOME chain
                    self.cp_channels.append((cp_chain, cp_conn, port, channel, cp_port, cp_channel, home_chain_id))

        logger.info(
            "StateScanner[%s] -> home: %d clients, %d connections, %d channels | "
            "cp: %d chains, %d connections, %d channels",
            home_chain_id,
            len(self.clients), len(self.connections), len(self.channels),
            len(self.cp_connections), sum(len(v) for v in self.cp_connections.values()), len(self.cp_channels)
        )
