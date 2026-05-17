from ibc_monitor.packet_events import parse_packet_events


def test_parse_packet_events_from_indexed_event_map():
    raw = {
        "result": {
            "events": {
                "tx.height": ["123"],
                "send_packet.packet_sequence": ["7"],
                "send_packet.packet_src_port": ["transfer"],
                "send_packet.packet_src_channel": ["channel-0"],
                "send_packet.packet_dst_port": ["transfer"],
                "send_packet.packet_dst_channel": ["channel-1"],
            }
        }
    }

    events = parse_packet_events(raw, "chain-a", observed_at=100)

    assert len(events) == 1
    event = events[0]
    assert event.event_type == "send_packet"
    assert event.emitter_chain_id == "chain-a"
    assert event.height == 123
    assert event.timestamp == 100
    assert event.sequence == 7
    assert event.src_port == "transfer"
    assert event.src_channel == "channel-0"
    assert event.dst_channel == "channel-1"


def test_parse_packet_events_from_tx_event_list():
    raw = {
        "result": {
            "data": {
                "value": {
                    "TxResult": {
                        "height": "124",
                        "result": {
                            "events": [
                                {
                                    "type": "recv_packet",
                                    "attributes": [
                                        {"key": "packet_sequence", "value": "8"},
                                        {"key": "packet_src_port", "value": "transfer"},
                                        {"key": "packet_src_channel", "value": "channel-0"},
                                        {"key": "packet_dst_port", "value": "transfer"},
                                        {"key": "packet_dst_channel", "value": "channel-1"},
                                    ],
                                }
                            ]
                        },
                    }
                }
            }
        }
    }

    events = parse_packet_events(raw, "chain-b", observed_at=101)

    assert len(events) == 1
    assert events[0].event_type == "recv_packet"
    assert events[0].height == 124
    assert events[0].sequence == 8
