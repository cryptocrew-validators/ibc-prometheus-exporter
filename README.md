# IBC Prometheus Exporter

This exporter monitors Inter-Blockchain Communication (IBC) activity and
exposes detailed metrics in a format consumable by Prometheus. It keeps track
of REST endpoint health, client state updates, and packet backlogs across
chains.

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

Configured REST endpoints are used in order. Chain-registry fallback discovery
is disabled by default for predictable production behavior; enable it explicitly
with `enable_chain_registry_fallbacks = true` under `[exporter]` if desired.

By default the exporter reports all discovered clients and channels. Set
`omit_inactive_clients = true` to keep only active clients, and
`omit_closed_channels = true` under `[exporter]` to skip closed channels and
their backlog metrics.

Excluded packet sequences are scoped by chain and channel:

```toml
[chains.excluded_sequences]
channel-7 = ["2-6"]
```

## Metrics

The following metrics are exported:

<!-- METRICS_START -->
| Metric | Description | Labels |
|---|---|---|
| `ibc_ack_packet_backlog_oldest_sequence` | Oldest AcknowledgementPacket sequence | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_ack_packet_backlog_oldest_timestamp_seconds` | Timestamp of oldest AcknowledgementPacket in backlog | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_ack_packet_backlog_size` | Total AcknowledgementPacket events backlog | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_backlog_last_update_time_seconds` | Last successful update time for backlog metrics | chain_id |
| `ibc_channel_state` | IBC channel state as a labeled gauge with value 1 for the current state | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id, state |
| `ibc_client_last_update_timestamp_seconds` | Last consensus state update time | client_id, chain_id, counterparty_chain_id, counterparty_client_id |
| `ibc_client_status` | IBC client status as a labeled gauge with value 1 for the current status | client_id, chain_id, counterparty_chain_id, counterparty_client_id, status |
| `ibc_client_trusting_period_seconds` | Trusting period for IBC client | client_id, chain_id, counterparty_chain_id, counterparty_client_id |
| `ibc_exporter_update_duration_seconds` | Duration of the most recent exporter update cycle | chain_id |
| `ibc_exporter_update_errors_total` | Total exporter update errors | chain_id, stage |
| `ibc_rest_health` | Health status of IBC REST endpoint (1=up, 0=down) | chain_id, endpoint |
| `ibc_send_packet_backlog_oldest_sequence` | Oldest SendPacket sequence | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_send_packet_backlog_oldest_timestamp_seconds` | Timestamp of oldest SendPacket in backlog | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_send_packet_backlog_size` | Total SendPacket events backlog | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
<!-- METRICS_END -->

> This section is generated automatically from
> `ibc_monitor/metrics.py` by `scripts/generate_readme_metrics.py`.
