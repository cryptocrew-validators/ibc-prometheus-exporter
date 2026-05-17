# IBC Prometheus Exporter

This exporter monitors Inter-Blockchain Communication (IBC) activity and
exposes detailed metrics in a format consumable by Prometheus. It keeps track
of REST endpoint health, RPC endpoint health, client state updates, packet
backlogs, and optionally live packet lifecycle events across chains.

## Requirements

Install dependencies with:

```bash
pip install -r requirements.txt
```

For local test/development dependencies:

```bash
pip install -r requirements-dev.txt
```

## Usage

1. Configure chains and REST endpoints in `config.toml`.
2. Run the exporter:

    ```bash
    python -m ibc_monitor.main --config config.toml
    ```

Metrics are exposed on the configured address and port and can be scraped by
Prometheus.

## Grafana Dashboard

An importable Grafana dashboard is available at
`grafana/ibc-exporter-dashboard.json`. Import it in Grafana and select the
Prometheus datasource that scrapes this exporter.

The dashboard includes REST endpoint health, send and acknowledgement backlog
size and age, client trust-period freshness, channel states, exporter update
duration, and error-rate panels. It also provides filters for chain,
counterparty chain, connection, port, channel, client status, channel state,
and error stage.

Configured REST and RPC endpoints are used in order. Chain-registry fallback
discovery is disabled by default for predictable production behavior; enable it
explicitly with `enable_chain_registry_fallbacks = true` under `[exporter]` if
desired.

By default the exporter reports all discovered clients and channels. Set
`omit_inactive_clients = true` to keep only active clients, and
`omit_closed_channels = true` under `[exporter]` to skip closed channels and
their backlog metrics.

Excluded packet sequences are scoped by chain and channel:

```toml
[chains.excluded_sequences]
channel-7 = ["2-6"]
```

## Packet Indexer

The packet indexer is disabled by default. Enable it to process IBC packet
events from CometBFT websocket subscriptions and expose counters, lifecycle
gauges, latency histograms, RPC health, and websocket health:

```toml
[indexer]
enabled = true
store_path = "packet-indexer.sqlite"
backfill_on_start_blocks = 100
gap_backfill = true
backfill_workers = 4
backfill_batch_size = 100
```

Each indexed chain needs an RPC endpoint in `rpcs`, or chain-registry fallback
discovery must be enabled. Websocket URLs are derived from the active RPC
endpoint, for example `https://rpc.example` becomes
`wss://rpc.example/websocket`. Set `websockets = [...]` on a chain to override
the derived URL.

Backfill requests run sequentially by default. Increase `backfill_workers` to
fetch multiple heights concurrently; `backfill_batch_size` limits how many
heights are submitted to the worker pool at once.

## Metrics

The following metrics are exported:

<!-- METRICS_START -->
| Metric | Description | Labels |
|---|---|---|
| `ibc_ack_packet_backlog_oldest_sequence` | Oldest AcknowledgementPacket sequence | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_ack_packet_backlog_oldest_timestamp_seconds` | Timestamp of oldest AcknowledgementPacket in backlog | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_ack_packet_backlog_size` | Total AcknowledgementPacket events backlog | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_ack_packet_events_total` | Total AcknowledgePacket events observed | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_acknowledged_packet_total` | Total packets observed as fully acknowledged on the source chain | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_backlog_last_update_time_seconds` | Last successful update time for backlog metrics | chain_id |
| `ibc_channel_state` | IBC channel state as a labeled gauge with value 1 for the current state | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id, state |
| `ibc_client_last_update_timestamp_seconds` | Last consensus state update time | client_id, chain_id, counterparty_chain_id, counterparty_client_id |
| `ibc_client_status` | IBC client status as a labeled gauge with value 1 for the current status | client_id, chain_id, counterparty_chain_id, counterparty_client_id, status |
| `ibc_client_trusting_period_seconds` | Trusting period for IBC client | client_id, chain_id, counterparty_chain_id, counterparty_client_id |
| `ibc_exporter_update_duration_seconds` | Duration of the most recent exporter update cycle | chain_id |
| `ibc_exporter_update_errors_total` | Total exporter update errors | chain_id, stage |
| `ibc_inflight_packet_oldest_sequence` | Oldest inflight packet sequence | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_inflight_packet_oldest_timestamp_seconds` | Timestamp of oldest inflight packet | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_inflight_packet_size` | Total sent packets not yet received, acknowledged, or timed out | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_packet_ack_duration_seconds` | Duration from SendPacket to AcknowledgePacket | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_packet_indexer_errors_total` | Total packet indexer errors | chain_id, stage |
| `ibc_packet_indexer_last_event_time_seconds` | Last time a packet indexer event was processed | chain_id |
| `ibc_packet_indexer_last_processed_height` | Last block height processed by packet indexer | chain_id |
| `ibc_packet_indexer_queue_size` | Current queued websocket messages waiting for packet indexer processing |  |
| `ibc_packet_orphan_events_total` | Total packet events that could not be matched to configured channel topology | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id, event_type |
| `ibc_packet_relay_duration_seconds` | Duration from SendPacket to RecvPacket | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_packet_timeout_duration_seconds` | Duration from SendPacket to timeout | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id, timeout_type |
| `ibc_pending_ack_packet_oldest_sequence` | Oldest pending acknowledgement packet sequence | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_pending_ack_packet_oldest_timestamp_seconds` | Timestamp of oldest pending acknowledgement packet | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_pending_ack_packet_size` | Total received or write-ack packets not yet acknowledged on source | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_recv_packet_events_total` | Total RecvPacket events observed | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_rest_health` | Health status of IBC REST endpoint (1=up, 0=down) | chain_id, endpoint |
| `ibc_rpc_endpoint_switches_total` | Total RPC endpoint switches after health failures | chain_id, from_endpoint, to_endpoint |
| `ibc_rpc_errors_total` | Total RPC errors | chain_id, endpoint, stage |
| `ibc_rpc_health` | Health status of IBC RPC endpoint (1=up, 0=down) | chain_id, endpoint |
| `ibc_rpc_latest_block_height` | Latest block height reported by active RPC endpoint | chain_id |
| `ibc_rpc_latest_block_timestamp_seconds` | Latest block timestamp reported by active RPC endpoint | chain_id |
| `ibc_send_packet_backlog_oldest_sequence` | Oldest SendPacket sequence | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_send_packet_backlog_oldest_timestamp_seconds` | Timestamp of oldest SendPacket in backlog | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_send_packet_backlog_size` | Total SendPacket events backlog | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_send_packet_events_total` | Total SendPacket events observed | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_successfully_relayed_packet_total` | Total packets observed as successfully received on the destination chain | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_timed_out_packet_total` | Total packets observed as timed out | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id, timeout_type |
| `ibc_timeout_packet_events_total` | Total TimeoutPacket events observed | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id, timeout_type |
| `ibc_websocket_health` | Health status of IBC websocket connection (1=up, 0=down) | chain_id, endpoint |
| `ibc_websocket_reconnects_total` | Total websocket reconnects | chain_id, endpoint |
| `ibc_write_ack_packet_events_total` | Total WriteAcknowledgement events observed | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
<!-- METRICS_END -->

> This section is generated automatically from
> `ibc_monitor/metrics.py` by `scripts/generate_readme_metrics.py`.
