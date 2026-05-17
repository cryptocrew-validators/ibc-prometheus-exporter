import threading
import time

from ibc_monitor.packet_events import PacketEvent
from ibc_monitor.packet_indexer import PacketIndexer, PacketTopology


class DummyScanner:
    channels = [
        (
            "connection-0",
            "transfer",
            "channel-0",
            "transfer",
            "channel-1",
            "chain-b",
        )
    ]
    cp_channels = [
        (
            "chain-b",
            "connection-1",
            "transfer",
            "channel-1",
            "transfer",
            "channel-0",
            "chain-a",
        )
    ]


def packet_event(event_type, emitter_chain_id):
    return PacketEvent(
        event_type=event_type,
        emitter_chain_id=emitter_chain_id,
        height=10,
        timestamp=100,
        sequence=1,
        src_port="transfer",
        src_channel="channel-0",
        dst_port="transfer",
        dst_channel="channel-1",
    )


def test_packet_topology_resolves_source_and_destination_events():
    topology = PacketTopology.from_scanner("chain-a", DummyScanner())

    send_path = topology.resolve(packet_event("send_packet", "chain-a"))
    recv_path = topology.resolve(packet_event("recv_packet", "chain-b"))

    assert send_path is not None
    assert send_path.as_dict()["chain_id"] == "chain-a"
    assert send_path.as_dict()["channel_id"] == "channel-0"
    assert recv_path == send_path


def test_packet_topology_resolves_counterparty_source_events():
    topology = PacketTopology.from_scanner("chain-a", DummyScanner())
    event = PacketEvent(
        event_type="send_packet",
        emitter_chain_id="chain-b",
        height=10,
        timestamp=100,
        sequence=2,
        src_port="transfer",
        src_channel="channel-1",
        dst_port="transfer",
        dst_channel="channel-0",
    )

    path = topology.resolve(event)

    assert path is not None
    assert path.as_dict()["chain_id"] == "chain-b"
    assert path.as_dict()["counterparty_chain_id"] == "chain-a"


def test_parallel_backfill_fetches_concurrently_and_processes_in_height_order():
    indexer = PacketIndexer.__new__(PacketIndexer)
    indexer.stop_event = threading.Event()
    indexer.cfg = type("Cfg", (), {"packet_indexer_rpc_timeout": 1})()
    processed = []
    lock = threading.Lock()
    active = {"current": 0, "max": 0}

    def fake_fetch(_client, height):
        with lock:
            active["current"] += 1
            active["max"] = max(active["max"], active["current"])
        time.sleep(0.02)
        with lock:
            active["current"] -= 1
        return height, [{"height": height}]

    def fake_process(_chain_id, raw, observed_at=None):
        processed.append((raw["height"], observed_at))

    indexer._fetch_backfill_height = fake_fetch
    indexer.process_message = fake_process

    indexer._backfill_height_batch("chain-a", object(), 1, 6, workers=3)

    assert active["max"] > 1
    assert processed == [(height, height) for height in range(1, 7)]
