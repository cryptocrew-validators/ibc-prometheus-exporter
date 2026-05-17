from ibc_monitor.packet_events import PacketEvent
from ibc_monitor.metrics import CHANNEL_LABELS
from ibc_monitor.packet_store import PacketStore


LABELS = {
    "chain_id": "chain-a",
    "connection_id": "connection-0",
    "port_id": "transfer",
    "channel_id": "channel-0",
    "counterparty_chain_id": "chain-b",
    "counterparty_port_id": "transfer",
    "counterparty_channel_id": "channel-1",
}
LABELSET = tuple(LABELS[name] for name in CHANNEL_LABELS)


def event(event_type, timestamp):
    return PacketEvent(
        event_type=event_type,
        emitter_chain_id="chain-a",
        height=10 + timestamp,
        timestamp=timestamp,
        sequence=1,
        src_port="transfer",
        src_channel="channel-0",
        dst_port="transfer",
        dst_channel="channel-1",
    )


def test_packet_store_dedupes_and_tracks_lifecycle():
    store = PacketStore(":memory:")

    send = store.apply_event(event("send_packet", 100), LABELS)
    duplicate_send = store.apply_event(event("send_packet", 100), LABELS)
    recv = store.apply_event(event("recv_packet", 105), LABELS)

    assert send.event_inserted is True
    assert "send" in send.transitions
    assert duplicate_send.event_inserted is False
    assert recv.event_inserted is True
    assert "successfully_relayed" in recv.transitions
    assert recv.durations["relay"] == 5

    summaries = store.lifecycle_summaries()
    assert len(summaries) == 1
    assert summaries[0].inflight_size == 0
    assert summaries[0].pending_ack_size == 1
    assert summaries[0].pending_ack_oldest_sequence == 1
    assert summaries[0].pending_ack_oldest_timestamp == 105

    ack = store.apply_event(event("acknowledge_packet", 120), LABELS)
    assert "acknowledged" in ack.transitions
    assert ack.durations["ack"] == 20
    assert store.lifecycle_summaries([LABELSET])[0].pending_ack_size == 0

    store.close()


def test_packet_store_records_timeout_duration():
    store = PacketStore(":memory:")
    store.apply_event(event("send_packet", 100), LABELS)
    timed_out = store.apply_event(event("timeout_on_close_packet", 130), LABELS)

    assert "timed_out" in timed_out.transitions
    assert timed_out.timeout_type == "timeout_on_close"
    assert timed_out.durations["timeout"] == 30
    assert store.lifecycle_summaries([LABELSET])[0].inflight_size == 0

    store.close()
