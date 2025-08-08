import time
import logging
from typing import List, Tuple, Dict
import fnmatch
from requests.exceptions import HTTPError
from ibc_monitor.rest_client import RESTClient

logger = logging.getLogger(__name__)

class StateScanner:
    def __init__(self, client: RESTClient, cfg, counterparty_chain_ids: List[str]):
        self.rest = client
        self.cfg = cfg
        self.counterparty_chain_ids = counterparty_chain_ids
        self.last_scan = 0
        self.clients: List[str] = []
        self.connections: List[str] = []
        self.client_chain_map: Dict[str, str] = {}
        self.client_counterparty_client_ids: Dict[str, str] = {}
        self.connection_client_map: Dict[str, str] = {}
        # (connection, port, channel, counterparty_port, counterparty_channel, counterparty_chain)
        self.channels: List[Tuple[str, str, str, str, str, str]] = []

    def scan(self):
        now = time.time()
        if now - self.last_scan < self.cfg.state_refresh_interval:
            return
        self.last_scan = now
        logger.debug("Scanning IBC state for %s", self.rest.expected_chain_id)
        # 1) scan on-chain clients
        all_clients = self.rest.query(
            "/ibc/core/client/v1/client_states", timeout=self.cfg.state_scan_timeout
        ).get("client_states", [])
        client_ids: List[str] = []
        client_chain_map: Dict[str, str] = {}
        for c in all_clients:
            cid = c.get("client_id")
            chain_id = c.get("client_state", {}).get("chain_id")
            if chain_id not in self.counterparty_chain_ids:
                logger.debug(
                    "Skipping client %s with counterparty chain %s", cid, chain_id
                )
                continue
            client_ids.append(cid)
            client_chain_map[cid] = chain_id
        self.clients = self._filter_list(
            client_ids,
            self.cfg.whitelist_clients,
            self.cfg.blacklist_clients,
        )
        self.client_chain_map = {cid: client_chain_map[cid] for cid in self.clients}
        logger.debug("Found clients: %s", self.clients)
        # 2) scan connections for each client
        conns: List[str] = []
        valid_clients: List[str] = []
        connection_client_map: Dict[str, str] = {}
        client_cp_client_ids: Dict[str, str] = {}
        for cid in self.clients:
            try:
                res = self.rest.query(
                    f"/ibc/core/connection/v1/client_connections/{cid}", timeout=self.cfg.state_scan_timeout
                ).get("connection_paths", [])
            except HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    logger.debug("No connections found for client %s", cid)
                    continue
                raise
            if not res:
                logger.debug("No connections found for client %s", cid)
                continue
            valid_clients.append(cid)
            for conn in res:
                connection_client_map[conn] = cid
                try:
                    conn_res = self.rest.query(
                        f"/ibc/core/connection/v1/connections/{conn}", timeout=self.cfg.state_scan_timeout
                    ).get("connection", {})
                except HTTPError as e:
                    if e.response is not None and e.response.status_code == 404:
                        conn_res = {}
                    else:
                        raise
                cp_cid = conn_res.get("counterparty", {}).get("client_id", "")
                if cid not in client_cp_client_ids:
                    client_cp_client_ids[cid] = cp_cid
            conns.extend(res)
        self.clients = valid_clients
        self.connection_client_map = connection_client_map
        self.client_counterparty_client_ids = client_cp_client_ids
        self.connections = self._filter_list(
            conns,
            self.cfg.whitelist_connections,
            self.cfg.blacklist_connections,
        )
        logger.debug("Found connections: %s", self.connections)
        # 3) scan channels for each connection
        chan_list: List[Tuple[str, str, str, str, str, str]] = []
        for conn in self.connections:
            try:
                res = self.rest.query(
                    f"/ibc/core/channel/v1/connections/{conn}/channels", timeout=self.cfg.state_scan_timeout
                ).get("channels", [])
            except HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    logger.debug("No channels found for connection %s", conn)
                    continue
                raise
            for ch in res:
                port, channel = ch.get("port_id"), ch.get("channel_id")
                cp = ch.get("counterparty", {})
                cp_port = cp.get("port_id", "")
                cp_channel = cp.get("channel_id", "")
                local_client = self.connection_client_map.get(conn, "")
                cp_chain = self.client_chain_map.get(local_client, "")
                chan_list.append((conn, port, channel, cp_port, cp_channel, cp_chain))
        self.channels = [
            (conn, p, c, cp_p, cp_c, cp_chain)
            for conn, p, c, cp_p, cp_c, cp_chain in chan_list
            if self._match_any(f"{p}/{c}", self.cfg.whitelist_channels, self.cfg.blacklist_channels)
        ]
        logger.info(
            f"StateScanner[{self.rest.expected_chain_id}] -> {len(self.clients)} clients, "
            f"{len(self.connections)} connections, {len(self.channels)} channels"
        )

    def _filter_list(self, items: List[str], whitelist: List[str], blacklist: List[str]) -> List[str]:
        if whitelist:
            return [i for i in items if any(fnmatch.fnmatch(i, pat) for pat in whitelist)]
        return [i for i in items if not any(fnmatch.fnmatch(i, pat) for pat in blacklist)]

    def _match_any(self, item: str, whitelist: List[str], blacklist: List[str]) -> bool:
        if whitelist:
            return any(fnmatch.fnmatch(item, pat) for pat in whitelist)
        return not any(fnmatch.fnmatch(item, pat) for pat in blacklist)
