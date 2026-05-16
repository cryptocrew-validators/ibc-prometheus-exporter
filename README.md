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

Configured REST endpoints are used in order. Chain-registry fallback discovery
is disabled by default for predictable production behavior; enable it explicitly
with `enable_chain_registry_fallbacks = true` under `[exporter]` if desired.

## Metrics

The following metrics are exported:

<!-- METRICS_START -->
| Metric | Description | Labels |
|---|---|---|
| `ibc_ack_packet_backlog_oldest_sequence` | Oldest AcknowledgementPacket sequence | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_ack_packet_backlog_oldest_timestamp_seconds` | Timestamp of oldest AcknowledgementPacket in backlog | chain_id, connection_id, port_id, channel_id, counterparty_chain_id, counterparty_port_id, counterparty_channel_id |
| `ibc_backlog_last_update_time_seconds` | Last successful update time for backlog metrics | chain_id |
| `ibc_client_last_update_timestamp_seconds` | Last consensus state update time | client_id, chain_id, counterparty_chain_id, counterparty_client_id |
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
