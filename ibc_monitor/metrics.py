from prometheus_client import Gauge

# REST endpoint health metric
REST_HEALTH = Gauge(
    'ibc_rest_health',
    'Health status of IBC REST endpoint (1=up, 0=down)',
    ['chain_id', 'endpoint'],
)

# Client metrics
CLIENT_TRUSTING_PERIOD = Gauge(
    'ibc_client_trusting_period_seconds',
    'Trusting period for IBC client',
    ['client_id', 'chain_id', 'counterparty_chain_id', 'counterparty_client_id'],
)
CLIENT_LAST_UPDATE = Gauge(
    'ibc_client_last_update_timestamp_seconds',
    'Last consensus state update time',
    ['client_id', 'chain_id', 'counterparty_chain_id', 'counterparty_client_id'],
)

# Packet backlog metrics
BACKLOG_SIZE = Gauge(
    'ibc_send_packet_backlog_size',
    'Total SendPacket events backlog',
    ['chain_id', 'connection_id', 'port_id', 'channel_id', 'counterparty_chain_id', 'counterparty_port_id', 'counterparty_channel_id'],
)
BACKLOG_OLDEST_SEQ = Gauge(
    'ibc_send_packet_backlog_oldest_sequence',
    'Oldest SendPacket sequence',
    ['chain_id', 'connection_id', 'port_id', 'channel_id', 'counterparty_chain_id', 'counterparty_port_id', 'counterparty_channel_id'],
)
BACKLOG_OLDEST_TIMESTAMP = Gauge(
    'ibc_send_packet_backlog_oldest_timestamp_seconds',
    'Timestamp of oldest SendPacket in backlog',
    ['chain_id', 'connection_id', 'port_id', 'channel_id', 'counterparty_chain_id', 'counterparty_port_id', 'counterparty_channel_id'],
)
ACK_OLDEST_SEQ = Gauge(
    'ibc_ack_packet_backlog_oldest_sequence',
    'Oldest AcknowledgementPacket sequence',
    ['chain_id', 'connection_id', 'port_id', 'channel_id', 'counterparty_chain_id', 'counterparty_port_id', 'counterparty_channel_id'],
)
ACK_OLDEST_TIMESTAMP = Gauge(
    'ibc_ack_packet_backlog_oldest_timestamp_seconds',
    'Timestamp of oldest AcknowledgementPacket in backlog',
    ['chain_id', 'connection_id', 'port_id', 'channel_id', 'counterparty_chain_id', 'counterparty_port_id', 'counterparty_channel_id'],
)
BACKLOG_UPDATED = Gauge(
    'ibc_backlog_last_update_time_seconds',
    'Last update time for backlog metrics',
    ['chain_id'],
)