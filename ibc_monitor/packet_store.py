from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Tuple

from ibc_monitor.metrics import CHANNEL_LABELS
from ibc_monitor.packet_events import PacketEvent

TERMINAL_STATUSES = {"acknowledged", "timed_out"}


@dataclass
class PacketStoreResult:
    event_inserted: bool
    transitions: set[str] = field(default_factory=set)
    durations: Dict[str, float] = field(default_factory=dict)
    timeout_type: str = "timeout"


@dataclass
class PacketLifecycleSummary:
    labels: Tuple[str, ...]
    inflight_size: int = 0
    inflight_oldest_sequence: int = 0
    inflight_oldest_timestamp: int = 0
    pending_ack_size: int = 0
    pending_ack_oldest_sequence: int = 0
    pending_ack_oldest_timestamp: int = 0


class PacketStore:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._init_schema()

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_events (
                    event_id TEXT PRIMARY KEY,
                    chain_id TEXT NOT NULL,
                    height INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    processed_at INTEGER NOT NULL
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS packets (
                    chain_id TEXT NOT NULL,
                    connection_id TEXT NOT NULL,
                    port_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    counterparty_chain_id TEXT NOT NULL,
                    counterparty_port_id TEXT NOT NULL,
                    counterparty_channel_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    send_time INTEGER,
                    send_height INTEGER,
                    recv_time INTEGER,
                    write_ack_time INTEGER,
                    ack_time INTEGER,
                    timeout_time INTEGER,
                    timeout_type TEXT,
                    relay_duration_recorded INTEGER NOT NULL DEFAULT 0,
                    ack_duration_recorded INTEGER NOT NULL DEFAULT 0,
                    timeout_duration_recorded INTEGER NOT NULL DEFAULT 0,
                    updated_time INTEGER NOT NULL,
                    PRIMARY KEY (chain_id, port_id, channel_id, sequence)
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_progress (
                    chain_id TEXT PRIMARY KEY,
                    last_processed_height INTEGER NOT NULL,
                    last_event_time INTEGER NOT NULL,
                    updated_time INTEGER NOT NULL
                )
                """
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_packets_status ON packets(status)"
            )

    @staticmethod
    def _label_tuple(labels: Mapping[str, str]) -> Tuple[str, ...]:
        return tuple(str(labels.get(name, "")) for name in CHANNEL_LABELS)

    @staticmethod
    def _packet_key(labels: Mapping[str, str], sequence: int) -> Tuple[str, str, str, int]:
        return (
            str(labels.get("chain_id", "")),
            str(labels.get("port_id", "")),
            str(labels.get("channel_id", "")),
            int(sequence),
        )

    @staticmethod
    def _status_after(current: str | None, event_type: str) -> str:
        if current in TERMINAL_STATUSES:
            return current
        if event_type == "send_packet":
            return current or "sent"
        if event_type == "recv_packet":
            return "received"
        if event_type == "write_acknowledgement":
            return "write_acknowledged"
        if event_type == "acknowledge_packet":
            return "acknowledged"
        if event_type in {"timeout_packet", "timeout_on_close_packet"}:
            return "timed_out"
        return current or "unknown"

    def apply_event(self, event: PacketEvent, labels: Mapping[str, str]) -> PacketStoreResult:
        event_id = event.event_id()
        now = int(time.time())
        timeout_type = event.timeout_type
        result = PacketStoreResult(event_inserted=False, timeout_type=timeout_type)
        label_values = dict(zip(CHANNEL_LABELS, self._label_tuple(labels)))
        key = self._packet_key(label_values, event.sequence)

        with self.lock, self.conn:
            try:
                self.conn.execute(
                    """
                    INSERT INTO processed_events(event_id, chain_id, height, event_type, processed_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (event_id, event.emitter_chain_id, event.height, event.event_type, now),
                )
            except sqlite3.IntegrityError:
                return result

            result.event_inserted = True
            row = self.conn.execute(
                """
                SELECT * FROM packets
                WHERE chain_id = ? AND port_id = ? AND channel_id = ? AND sequence = ?
                """,
                key,
            ).fetchone()

            if row is None:
                self._insert_packet(event, label_values, now)
                if event.event_type == "send_packet":
                    result.transitions.add("send")
                elif event.event_type == "recv_packet":
                    result.transitions.add("successfully_relayed")
                elif event.event_type == "write_acknowledgement":
                    result.transitions.add("write_ack")
                elif event.event_type == "acknowledge_packet":
                    result.transitions.add("acknowledged")
                elif event.event_type in {"timeout_packet", "timeout_on_close_packet"}:
                    result.transitions.add("timed_out")
                return result

            updates: Dict[str, object] = {
                "status": self._status_after(row["status"], event.event_type),
                "updated_time": now,
            }
            self._apply_event_updates(row, event, updates, result)
            assignments = ", ".join(f"{name} = ?" for name in updates)
            values = list(updates.values()) + list(key)
            self.conn.execute(
                f"""
                UPDATE packets SET {assignments}
                WHERE chain_id = ? AND port_id = ? AND channel_id = ? AND sequence = ?
                """,
                values,
            )
            self._record_progress(event.emitter_chain_id, event.height, event.timestamp, now)
        return result

    def _insert_packet(
        self,
        event: PacketEvent,
        labels: Mapping[str, str],
        now: int,
    ) -> None:
        status = self._status_after(None, event.event_type)
        values = {name: labels.get(name, "") for name in CHANNEL_LABELS}
        values.update(
            sequence=event.sequence,
            status=status,
            send_time=event.timestamp if event.event_type == "send_packet" else None,
            send_height=event.height if event.event_type == "send_packet" else None,
            recv_time=event.timestamp if event.event_type == "recv_packet" else None,
            write_ack_time=event.timestamp if event.event_type == "write_acknowledgement" else None,
            ack_time=event.timestamp if event.event_type == "acknowledge_packet" else None,
            timeout_time=event.timestamp
            if event.event_type in {"timeout_packet", "timeout_on_close_packet"}
            else None,
            timeout_type=event.timeout_type
            if event.event_type in {"timeout_packet", "timeout_on_close_packet"}
            else None,
            updated_time=now,
        )
        self.conn.execute(
            """
            INSERT INTO packets(
                chain_id, connection_id, port_id, channel_id,
                counterparty_chain_id, counterparty_port_id, counterparty_channel_id,
                sequence, status, send_time, send_height, recv_time, write_ack_time,
                ack_time, timeout_time, timeout_type, updated_time
            )
            VALUES (
                :chain_id, :connection_id, :port_id, :channel_id,
                :counterparty_chain_id, :counterparty_port_id, :counterparty_channel_id,
                :sequence, :status, :send_time, :send_height, :recv_time, :write_ack_time,
                :ack_time, :timeout_time, :timeout_type, :updated_time
            )
            """,
            values,
        )
        self._record_progress(event.emitter_chain_id, event.height, event.timestamp, now)

    def _apply_event_updates(
        self,
        row: sqlite3.Row,
        event: PacketEvent,
        updates: Dict[str, object],
        result: PacketStoreResult,
    ) -> None:
        send_time = row["send_time"]
        if event.event_type == "send_packet":
            if row["send_time"] is None:
                updates["send_time"] = event.timestamp
                updates["send_height"] = event.height
                result.transitions.add("send")
                send_time = event.timestamp
            self._maybe_record_existing_durations(row, send_time, updates, result)
            return

        if event.event_type == "recv_packet":
            if row["recv_time"] is None:
                updates["recv_time"] = event.timestamp
                result.transitions.add("successfully_relayed")
                self._maybe_record_duration(
                    "relay",
                    send_time,
                    event.timestamp,
                    row["relay_duration_recorded"],
                    updates,
                    result,
                )
            return

        if event.event_type == "write_acknowledgement":
            if row["write_ack_time"] is None:
                updates["write_ack_time"] = event.timestamp
                result.transitions.add("write_ack")
            return

        if event.event_type == "acknowledge_packet":
            if row["ack_time"] is None:
                updates["ack_time"] = event.timestamp
                result.transitions.add("acknowledged")
                self._maybe_record_duration(
                    "ack",
                    send_time,
                    event.timestamp,
                    row["ack_duration_recorded"],
                    updates,
                    result,
                )
            return

        if event.event_type in {"timeout_packet", "timeout_on_close_packet"}:
            if row["timeout_time"] is None:
                updates["timeout_time"] = event.timestamp
                updates["timeout_type"] = event.timeout_type
                result.transitions.add("timed_out")
                self._maybe_record_duration(
                    "timeout",
                    send_time,
                    event.timestamp,
                    row["timeout_duration_recorded"],
                    updates,
                    result,
                )

    @staticmethod
    def _maybe_record_duration(
        name: str,
        send_time: int | None,
        event_time: int,
        already_recorded: int,
        updates: Dict[str, object],
        result: PacketStoreResult,
    ) -> None:
        if send_time is None or already_recorded:
            return
        duration = max(0, int(event_time) - int(send_time))
        result.durations[name] = duration
        updates[f"{name}_duration_recorded"] = 1

    def _maybe_record_existing_durations(
        self,
        row: sqlite3.Row,
        send_time: int | None,
        updates: Dict[str, object],
        result: PacketStoreResult,
    ) -> None:
        if send_time is None:
            return
        if row["recv_time"] is not None:
            self._maybe_record_duration(
                "relay",
                send_time,
                row["recv_time"],
                row["relay_duration_recorded"],
                updates,
                result,
            )
        if row["ack_time"] is not None:
            self._maybe_record_duration(
                "ack",
                send_time,
                row["ack_time"],
                row["ack_duration_recorded"],
                updates,
                result,
            )
        if row["timeout_time"] is not None:
            self._maybe_record_duration(
                "timeout",
                send_time,
                row["timeout_time"],
                row["timeout_duration_recorded"],
                updates,
                result,
            )

    def _record_progress(self, chain_id: str, height: int, event_time: int, now: int) -> None:
        if not height:
            return
        self.conn.execute(
            """
            INSERT INTO chain_progress(chain_id, last_processed_height, last_event_time, updated_time)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(chain_id) DO UPDATE SET
                last_processed_height = MAX(last_processed_height, excluded.last_processed_height),
                last_event_time = CASE
                    WHEN excluded.last_processed_height >= last_processed_height
                    THEN excluded.last_event_time
                    ELSE last_event_time
                END,
                updated_time = excluded.updated_time
            """,
            (chain_id, height, event_time, now),
        )

    def record_progress(self, chain_id: str, height: int, event_time: int) -> None:
        now = int(time.time())
        with self.lock, self.conn:
            self._record_progress(chain_id, height, event_time, now)

    def last_processed_height(self, chain_id: str) -> int:
        with self.lock:
            row = self.conn.execute(
                "SELECT last_processed_height FROM chain_progress WHERE chain_id = ?",
                (chain_id,),
            ).fetchone()
            return int(row[0]) if row else 0

    def lifecycle_summaries(
        self,
        known_labelsets: Iterable[Tuple[str, ...]] = (),
    ) -> List[PacketLifecycleSummary]:
        summaries = {
            tuple(labelset): PacketLifecycleSummary(labels=tuple(labelset))
            for labelset in known_labelsets
        }
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT * FROM packets
                WHERE status IN ('sent', 'received', 'write_acknowledged')
                """
            ).fetchall()

        for row in rows:
            labels = tuple(row[name] for name in CHANNEL_LABELS)
            summary = summaries.setdefault(labels, PacketLifecycleSummary(labels=labels))
            if row["status"] == "sent":
                summary.inflight_size += 1
                self._maybe_set_oldest(
                    summary,
                    "inflight",
                    int(row["sequence"]),
                    int(row["send_time"] or 0),
                )
            elif row["status"] in {"received", "write_acknowledged"}:
                summary.pending_ack_size += 1
                timestamp = int(row["recv_time"] or row["write_ack_time"] or row["send_time"] or 0)
                self._maybe_set_oldest(
                    summary,
                    "pending_ack",
                    int(row["sequence"]),
                    timestamp,
                )
        return list(summaries.values())

    @staticmethod
    def _maybe_set_oldest(
        summary: PacketLifecycleSummary,
        prefix: str,
        sequence: int,
        timestamp: int,
    ) -> None:
        seq_attr = f"{prefix}_oldest_sequence"
        ts_attr = f"{prefix}_oldest_timestamp"
        current_seq = getattr(summary, seq_attr)
        if not current_seq or sequence < current_seq:
            setattr(summary, seq_attr, sequence)
            setattr(summary, ts_attr, timestamp)

    def prune(self, older_than_seconds: int) -> None:
        cutoff = int(time.time()) - int(older_than_seconds)
        with self.lock, self.conn:
            self.conn.execute(
                "DELETE FROM packets WHERE status IN ('acknowledged', 'timed_out') AND updated_time < ?",
                (cutoff,),
            )
            self.conn.execute(
                "DELETE FROM processed_events WHERE processed_at < ?",
                (cutoff,),
            )
