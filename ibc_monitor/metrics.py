from prometheus_client import Counter, Gauge, Histogram

CHANNEL_LABELS = [
    'chain_id',
    'connection_id',
    'port_id',
    'channel_id',
    'counterparty_chain_id',
    'counterparty_port_id',
    'counterparty_channel_id',
]

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
CLIENT_STATUS = Gauge(
    'ibc_client_status',
    'IBC client status as a labeled gauge with value 1 for the current status',
    ['client_id', 'chain_id', 'counterparty_chain_id', 'counterparty_client_id', 'status'],
)
CHANNEL_STATE = Gauge(
    'ibc_channel_state',
    'IBC channel state as a labeled gauge with value 1 for the current state',
    CHANNEL_LABELS + ['state'],
)

# Packet backlog metrics
BACKLOG_SIZE = Gauge(
    'ibc_send_packet_backlog_size',
    'Total SendPacket events backlog',
    CHANNEL_LABELS,
)
BACKLOG_OLDEST_SEQ = Gauge(
    'ibc_send_packet_backlog_oldest_sequence',
    'Oldest SendPacket sequence',
    CHANNEL_LABELS,
)
BACKLOG_OLDEST_TIMESTAMP = Gauge(
    'ibc_send_packet_backlog_oldest_timestamp_seconds',
    'Timestamp of oldest SendPacket in backlog',
    CHANNEL_LABELS,
)
ACK_OLDEST_SEQ = Gauge(
    'ibc_ack_packet_backlog_oldest_sequence',
    'Oldest AcknowledgementPacket sequence',
    CHANNEL_LABELS,
)
ACK_BACKLOG_SIZE = Gauge(
    'ibc_ack_packet_backlog_size',
    'Total AcknowledgementPacket events backlog',
    CHANNEL_LABELS,
)
ACK_OLDEST_TIMESTAMP = Gauge(
    'ibc_ack_packet_backlog_oldest_timestamp_seconds',
    'Timestamp of oldest AcknowledgementPacket in backlog',
    CHANNEL_LABELS,
)
BACKLOG_UPDATED = Gauge(
    'ibc_backlog_last_update_time_seconds',
    'Last successful update time for backlog metrics',
    ['chain_id'],
)
UPDATE_DURATION = Gauge(
    'ibc_exporter_update_duration_seconds',
    'Duration of the most recent exporter update cycle',
    ['chain_id'],
)
UPDATE_ERRORS = Counter(
    'ibc_exporter_update_errors_total',
    'Total exporter update errors',
    ['chain_id', 'stage'],
)

# RPC and websocket health metrics
RPC_HEALTH = Gauge(
    'ibc_rpc_health',
    'Health status of IBC RPC endpoint (1=up, 0=down)',
    ['chain_id', 'endpoint'],
)
RPC_LATEST_BLOCK_HEIGHT = Gauge(
    'ibc_rpc_latest_block_height',
    'Latest block height reported by active RPC endpoint',
    ['chain_id'],
)
RPC_LATEST_BLOCK_TIMESTAMP = Gauge(
    'ibc_rpc_latest_block_timestamp_seconds',
    'Latest block timestamp reported by active RPC endpoint',
    ['chain_id'],
)
RPC_ENDPOINT_SWITCHES = Counter(
    'ibc_rpc_endpoint_switches_total',
    'Total RPC endpoint switches after health failures',
    ['chain_id', 'from_endpoint', 'to_endpoint'],
)
RPC_ERRORS = Counter(
    'ibc_rpc_errors_total',
    'Total RPC errors',
    ['chain_id', 'endpoint', 'stage'],
)
WEBSOCKET_HEALTH = Gauge(
    'ibc_websocket_health',
    'Health status of IBC websocket connection (1=up, 0=down)',
    ['chain_id', 'endpoint'],
)
WEBSOCKET_RECONNECTS = Counter(
    'ibc_websocket_reconnects_total',
    'Total websocket reconnects',
    ['chain_id', 'endpoint'],
)

# Packet indexer event and lifecycle metrics
SEND_PACKET_EVENTS = Counter(
    'ibc_send_packet_events_total',
    'Total SendPacket events observed',
    CHANNEL_LABELS,
)
RECV_PACKET_EVENTS = Counter(
    'ibc_recv_packet_events_total',
    'Total RecvPacket events observed',
    CHANNEL_LABELS,
)
WRITE_ACK_PACKET_EVENTS = Counter(
    'ibc_write_ack_packet_events_total',
    'Total WriteAcknowledgement events observed',
    CHANNEL_LABELS,
)
ACK_PACKET_EVENTS = Counter(
    'ibc_ack_packet_events_total',
    'Total AcknowledgePacket events observed',
    CHANNEL_LABELS,
)
TIMEOUT_PACKET_EVENTS = Counter(
    'ibc_timeout_packet_events_total',
    'Total TimeoutPacket events observed',
    CHANNEL_LABELS + ['timeout_type'],
)
ORPHAN_PACKET_EVENTS = Counter(
    'ibc_packet_orphan_events_total',
    'Total packet events that could not be matched to configured channel topology',
    CHANNEL_LABELS + ['event_type'],
)
SUCCESSFULLY_RELAYED_PACKETS = Counter(
    'ibc_successfully_relayed_packet_total',
    'Total packets observed as successfully received on the destination chain',
    CHANNEL_LABELS,
)
ACKNOWLEDGED_PACKETS = Counter(
    'ibc_acknowledged_packet_total',
    'Total packets observed as fully acknowledged on the source chain',
    CHANNEL_LABELS,
)
TIMED_OUT_PACKETS = Counter(
    'ibc_timed_out_packet_total',
    'Total packets observed as timed out',
    CHANNEL_LABELS + ['timeout_type'],
)
INFLIGHT_PACKET_SIZE = Gauge(
    'ibc_inflight_packet_size',
    'Total sent packets not yet received, acknowledged, or timed out',
    CHANNEL_LABELS,
)
INFLIGHT_PACKET_OLDEST_SEQ = Gauge(
    'ibc_inflight_packet_oldest_sequence',
    'Oldest inflight packet sequence',
    CHANNEL_LABELS,
)
INFLIGHT_PACKET_OLDEST_TIMESTAMP = Gauge(
    'ibc_inflight_packet_oldest_timestamp_seconds',
    'Timestamp of oldest inflight packet',
    CHANNEL_LABELS,
)
PENDING_ACK_PACKET_SIZE = Gauge(
    'ibc_pending_ack_packet_size',
    'Total received or write-ack packets not yet acknowledged on source',
    CHANNEL_LABELS,
)
PENDING_ACK_PACKET_OLDEST_SEQ = Gauge(
    'ibc_pending_ack_packet_oldest_sequence',
    'Oldest pending acknowledgement packet sequence',
    CHANNEL_LABELS,
)
PENDING_ACK_PACKET_OLDEST_TIMESTAMP = Gauge(
    'ibc_pending_ack_packet_oldest_timestamp_seconds',
    'Timestamp of oldest pending acknowledgement packet',
    CHANNEL_LABELS,
)
PACKET_RELAY_DURATION = Histogram(
    'ibc_packet_relay_duration_seconds',
    'Duration from SendPacket to RecvPacket',
    CHANNEL_LABELS,
)
PACKET_ACK_DURATION = Histogram(
    'ibc_packet_ack_duration_seconds',
    'Duration from SendPacket to AcknowledgePacket',
    CHANNEL_LABELS,
)
PACKET_TIMEOUT_DURATION = Histogram(
    'ibc_packet_timeout_duration_seconds',
    'Duration from SendPacket to timeout',
    CHANNEL_LABELS + ['timeout_type'],
)
PACKET_INDEXER_LAST_EVENT_TIME = Gauge(
    'ibc_packet_indexer_last_event_time_seconds',
    'Last time a packet indexer event was processed',
    ['chain_id'],
)
PACKET_INDEXER_LAST_PROCESSED_HEIGHT = Gauge(
    'ibc_packet_indexer_last_processed_height',
    'Last block height processed by packet indexer',
    ['chain_id'],
)
PACKET_INDEXER_ERRORS = Counter(
    'ibc_packet_indexer_errors_total',
    'Total packet indexer errors',
    ['chain_id', 'stage'],
)
PACKET_INDEXER_QUEUE_SIZE = Gauge(
    'ibc_packet_indexer_queue_size',
    'Current queued websocket messages waiting for packet indexer processing',
    [],
)
