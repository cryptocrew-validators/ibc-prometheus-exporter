from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping

from ibc_monitor.rpc_client import parse_rpc_time

logger = logging.getLogger(__name__)

PACKET_EVENT_TYPES = (
    "send_packet",
    "recv_packet",
    "write_acknowledgement",
    "acknowledge_packet",
    "timeout_packet",
    "timeout_on_close_packet",
)

SOURCE_CHAIN_EVENTS = {
    "send_packet",
    "acknowledge_packet",
    "timeout_packet",
    "timeout_on_close_packet",
}
DESTINATION_CHAIN_EVENTS = {
    "recv_packet",
    "write_acknowledgement",
}


@dataclass(frozen=True)
class PacketEvent:
    event_type: str
    emitter_chain_id: str
    height: int
    timestamp: int
    sequence: int
    src_port: str
    src_channel: str
    dst_port: str
    dst_channel: str
    tx_hash: str = ""
    event_index: int = 0

    @property
    def timeout_type(self) -> str:
        if self.event_type == "timeout_on_close_packet":
            return "timeout_on_close"
        return "timeout"

    def event_id(self) -> str:
        parts = (
            self.event_type,
            self.emitter_chain_id,
            str(self.height),
            self.src_port,
            self.src_channel,
            self.dst_port,
            self.dst_channel,
            str(self.sequence),
        )
        return "|".join(parts)


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _maybe_decode(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode()
        except UnicodeDecodeError:
            return ""
    text = str(value)
    if not text:
        return ""
    try:
        decoded = base64.b64decode(text, validate=True)
        if decoded and all(32 <= b <= 126 for b in decoded):
            return decoded.decode()
    except Exception:
        pass
    return text


def _merge_events_map(target: Dict[str, List[str]], events_map: Mapping[str, Any]) -> None:
    for key, values in events_map.items():
        key_text = _maybe_decode(key)
        if not key_text:
            continue
        target.setdefault(key_text, [])
        for value in _as_list(values):
            value_text = _maybe_decode(value)
            if value_text:
                target[key_text].append(value_text)


def _merge_event_list(target: Dict[str, List[str]], events: Iterable[Mapping[str, Any]]) -> None:
    for event in events or []:
        event_type = _maybe_decode(event.get("type"))
        if not event_type:
            continue
        for attr in event.get("attributes", []) or []:
            key = _maybe_decode(attr.get("key"))
            value = _maybe_decode(attr.get("value"))
            if not key or not value:
                continue
            target.setdefault(f"{event_type}.{key}", []).append(value)


def _extract_events(raw: Mapping[str, Any]) -> Dict[str, List[str]]:
    events: Dict[str, List[str]] = {}
    result = raw.get("result", {}) or {}
    if isinstance(result.get("events"), Mapping):
        _merge_events_map(events, result.get("events", {}))

    value = ((result.get("data") or {}).get("value") or {})
    tx_result = value.get("TxResult") or value.get("tx_result") or {}
    tx_events = ((tx_result.get("result") or {}).get("events") or [])
    _merge_event_list(events, tx_events)

    begin_block_events = value.get("BeginBlock", {}).get("events", []) if isinstance(value.get("BeginBlock"), Mapping) else []
    end_block_events = value.get("EndBlock", {}).get("events", []) if isinstance(value.get("EndBlock"), Mapping) else []
    _merge_event_list(events, begin_block_events)
    _merge_event_list(events, end_block_events)
    return events


def _first_int(*values: Any) -> int:
    for value in values:
        for item in _as_list(value):
            try:
                return int(item)
            except (TypeError, ValueError):
                continue
    return 0


def extract_height(raw: Mapping[str, Any]) -> int:
    result = raw.get("result", {}) or {}
    events = result.get("events", {}) or {}
    value = ((result.get("data") or {}).get("value") or {})
    tx_result = value.get("TxResult") or value.get("tx_result") or {}
    block = value.get("block", {}) or {}
    header = (
        value.get("header")
        or (block.get("header") if isinstance(block, Mapping) else {})
        or {}
    )
    return _first_int(
        events.get("tx.height"),
        events.get("block.height"),
        tx_result.get("height"),
        header.get("height"),
    )


def extract_block_timestamp(raw: Mapping[str, Any]) -> int | None:
    result = raw.get("result", {}) or {}
    value = ((result.get("data") or {}).get("value") or {})
    block = value.get("block", {}) or {}
    header = (
        value.get("header")
        or (block.get("header") if isinstance(block, Mapping) else {})
        or {}
    )
    return parse_rpc_time(header.get("time"))


def _attr(events: Mapping[str, List[str]], event_type: str, name: str, index: int) -> str:
    values = events.get(f"{event_type}.{name}", [])
    if not values:
        return ""
    if index < len(values):
        return values[index]
    return values[-1]


def parse_packet_events(
    raw: Mapping[str, Any],
    chain_id: str,
    observed_at: int | None = None,
) -> List[PacketEvent]:
    events = _extract_events(raw)
    height = extract_height(raw)
    timestamp = extract_block_timestamp(raw) or observed_at or int(time.time())
    packet_events: List[PacketEvent] = []
    event_index = 0

    for event_type in PACKET_EVENT_TYPES:
        sequences = events.get(f"{event_type}.packet_sequence", [])
        for idx, raw_sequence in enumerate(sequences):
            try:
                sequence = int(raw_sequence)
            except (TypeError, ValueError):
                logger.debug("Skipping malformed %s sequence %r", event_type, raw_sequence)
                continue

            event = PacketEvent(
                event_type=event_type,
                emitter_chain_id=chain_id,
                height=height,
                timestamp=timestamp,
                sequence=sequence,
                src_port=_attr(events, event_type, "packet_src_port", idx),
                src_channel=_attr(events, event_type, "packet_src_channel", idx),
                dst_port=_attr(events, event_type, "packet_dst_port", idx),
                dst_channel=_attr(events, event_type, "packet_dst_channel", idx),
                tx_hash=_attr(events, "tx", "hash", idx),
                event_index=event_index,
            )
            if event.src_port and event.src_channel and event.dst_port and event.dst_channel:
                packet_events.append(event)
                event_index += 1
    return packet_events
