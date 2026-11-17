"""采集协调器：站点验真、完整包检查、幂等游标、原子提交及隔离。"""
from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import catalog, credentials, handoff, protocol, store
from .normalize import ObservationError, normalize_batch, parse_time


class IngestError(ValueError):
    def __init__(self, code: str, message: str, *, quarantine_id: int | None = None):
        super().__init__(message)
        self.code = code
        self.quarantine_id = quarantine_id

    def as_dict(self) -> dict[str, Any]:
        return {"status": "rejected", "code": self.code, "message": str(self),
                "quarantine_id": self.quarantine_id}


@dataclass(frozen=True)
class IngestResult:
    status: str
    station_id: str
    sequence: int
    batch_id: int
    observation_count: int
    handoff_count: int
    packet_id: str
    credential_id: str
    key_fingerprint: str

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _reject(connection: sqlite3.Connection, code: str, message: str, source_name: str,
            content_digest: str, station_id: str | None, sequence: int | None, when: str,
            credential_id: str | None = None) -> IngestError:
    with store.transaction(connection):
        quarantine_id = store.quarantine(connection, station_id, sequence, source_name, content_digest,
                                         code, message, when, credential_id)
        store.record_activity(connection, "packet_rejected", "quarantine", str(quarantine_id), when,
                              {"code": code, "station_id": station_id, "sequence": sequence,
                               "credential_id": credential_id})
    return IngestError(code, message, quarantine_id=quarantine_id)


def _validate_envelope(packet: protocol.Packet, *, when: str) -> None:
    created = parse_time(packet.envelope.created_at, 1, "created_at")
    received = parse_time(when, 1, "received_at")
    from datetime import timedelta
    if created > received + timedelta(minutes=10):
        raise IngestError("packet_future", "包创建时间超过未来允许窗口")
    if received - created > timedelta(days=30):
        raise IngestError("packet_stale", "包创建时间超过历史允许窗口")


def _check_sequence(connection: sqlite3.Connection, packet: protocol.Packet, packet_id: str) -> tuple[str, dict[str, Any] | None]:
    station_id = packet.envelope.station_id
    sequence = packet.envelope.sequence
    current = store.station_cursor(connection, station_id)
    if current is None:
        raise IngestError("station_unknown", "站点尚未登记")
    station = catalog.station(connection, station_id)
    if not station or not station["active"]:
        raise IngestError("station_inactive", "站点未启用")
    previous = store.batch_for_sequence(connection, station_id, sequence)
    if previous is not None:
        if previous["packet_id"] == packet_id:
            return "duplicate", previous
        raise IngestError("sequence_conflict", "相同站点序号对应不同观测包")
    expected = current["committed_sequence"] + 1
    if sequence != expected:
        if sequence < expected:
            raise IngestError("sequence_old", "序号落后于已提交游标")
        raise IngestError("sequence_gap", f"等待序号 {expected}，尚不能提交序号 {sequence}")
    return "new", None


def _admit(connection: sqlite3.Connection, packet: protocol.Packet, sidecar: dict[str, Any] | None,
           authority: credentials.AdmissionAuthority, timestamp: str) -> credentials.AdmissionResult:
    decision = authority.decide(packet, sidecar, when=timestamp)
    if not decision.admitted:
        store.record_activity(connection, "packet_rejected", "credential",
                              decision.credential_id or "unknown", timestamp,
                              {"code": decision.code, "station_id": packet.envelope.station_id,
                               "sequence": packet.envelope.sequence,
                               "key_fingerprint": decision.key_fingerprint})
    return decision


def ingest_packet(connection: sqlite3.Connection, packet: protocol.Packet,
                  authority: credentials.AdmissionAuthority,
                  *, sidecar: dict[str, Any] | None = None, when: str | None = None) -> IngestResult:
    timestamp = when or catalog.utc_now()
    packet_id = protocol.packet_identity(packet)
    station_id = packet.envelope.station_id
    sequence = packet.envelope.sequence

    # 先验真：未通过当前准入决定的包不得进入去重或序号逻辑。
    decision = _admit(connection, packet, sidecar, authority, timestamp)
    if not decision.admitted:
        assert decision.credential_id is not None or decision.code in {"signature_missing"}
        raise _reject(connection, decision.code, decision.message, packet.source_name, packet_id,
                      station_id, sequence, timestamp, decision.credential_id)
    assert decision.credential_id is not None and decision.key_fingerprint is not None
    credential_id = decision.credential_id
    key_fingerprint = decision.key_fingerprint

    try:
        _validate_envelope(packet, when=timestamp)
        normalized = normalize_batch(packet.records, station_id, packet.envelope.created_at)
    except (IngestError, ObservationError) as exc:
        raise _reject(connection, exc.code, str(exc), packet.source_name, packet_id, station_id,
                      sequence, timestamp, credential_id) from exc
    try:
        with store.transaction(connection):
            status, previous = _check_sequence(connection, packet, packet_id)
            if status == "duplicate":
                assert previous is not None
                handoff_count = int(connection.execute(
                    "SELECT COUNT(*) FROM handoffs h JOIN observations o USING(observation_id) WHERE o.batch_id=?",
                    (previous["batch_id"],)).fetchone()[0])
                store.record_activity(connection, "packet_duplicate", "batch", str(previous["batch_id"]), timestamp,
                                      {"station_id": station_id, "sequence": sequence,
                                       "credential_id": credential_id,
                                       "batch_credential_id": previous["credential_id"]})
                return IngestResult("duplicate", station_id, sequence, previous["batch_id"],
                                    previous["record_count"], handoff_count, packet_id,
                                    previous["credential_id"], previous["key_fingerprint"])
            for observation in normalized:
                existing = store.one(connection, "SELECT observation_id FROM observations WHERE station_id=? AND external_id=?",
                                     (station_id, observation.external_id))
                if existing:
                    raise IngestError("observation_conflict", "观测标识已由站点提交")
            batch_id = store.insert_batch(connection, station_id, sequence, packet_id, packet.canonical_digest,
                                          packet.envelope.created_at, timestamp, packet.source_name,
                                          len(normalized), credential_id, key_fingerprint)
            handoff_count = 0
            for observation in normalized:
                observation_id = store.insert_observation(connection, batch_id, station_id, observation.as_dict())
                handoff_count += handoff.route_observation(connection, observation_id, observation, timestamp)
            store.update_cursor(connection, station_id, sequence, batch_id, timestamp)
            store.record_activity(connection, "batch_committed", "batch", str(batch_id), timestamp,
                                  {"station_id": station_id, "sequence": sequence,
                                   "observations": len(normalized), "handoffs": handoff_count,
                                   "credential_id": credential_id, "key_fingerprint": key_fingerprint})
            return IngestResult("accepted", station_id, sequence, batch_id, len(normalized),
                                handoff_count, packet_id, credential_id, key_fingerprint)
    except IngestError as exc:
        raise _reject(connection, exc.code, str(exc), packet.source_name, packet_id, station_id,
                      sequence, timestamp, credential_id) from exc
    except sqlite3.IntegrityError as exc:
        raise _reject(connection, "integrity_conflict", str(exc), packet.source_name, packet_id,
                      station_id, sequence, timestamp, credential_id) from exc


def ingest_bytes(connection: sqlite3.Connection, data: bytes, authority: credentials.AdmissionAuthority,
                 *, source_name: str = "<memory>", sidecar: dict[str, Any] | None = None,
                 when: str | None = None) -> IngestResult:
    timestamp = when or catalog.utc_now()
    try:
        packet = protocol.parse_packet_bytes(data, source_name)
    except protocol.PacketError as exc:
        digest = hashlib.sha256(data).hexdigest()
        raise _reject(connection, exc.code, str(exc), source_name, digest, None, None, timestamp) from exc
    return ingest_packet(connection, packet, authority, sidecar=sidecar, when=timestamp)


def ingest_file(connection: sqlite3.Connection, path: str | Path, authority: credentials.AdmissionAuthority,
                *, when: str | None = None) -> IngestResult:
    source = Path(path)
    timestamp = when or catalog.utc_now()
    try:
        data = source.read_bytes()
    except OSError as exc:
        digest = hashlib.sha256(str(source).encode()).hexdigest()
        raise _reject(connection, "source_unreadable", str(exc), source.name, digest, None, None,
                      timestamp) from exc
    try:
        sidecar = credentials.read_sidecar(source)
    except credentials.CredentialError as exc:
        digest = hashlib.sha256(data).hexdigest()
        raise _reject(connection, exc.code, str(exc), source.name, digest, None, None, timestamp) from exc
    return ingest_bytes(connection, data, authority, source_name=source.name, sidecar=sidecar, when=timestamp)


def ingest_directory(connection: sqlite3.Connection, path: str | Path, authority: credentials.AdmissionAuthority,
                     *, stop_on_error: bool = False, when: str | None = None) -> list[dict[str, Any]]:
    directory = Path(path)
    if not directory.is_dir():
        raise IngestError("directory_missing", "采集目录不存在")
    results = []
    for entry in sorted(directory.iterdir()):
        if not entry.is_file() or entry.suffix.lower() != ".jsonl":
            continue
        try:
            result = ingest_file(connection, entry, authority, when=when)
            results.append({"source_name": entry.name, **result.as_dict()})
        except IngestError as exc:
            results.append({"source_name": entry.name, **exc.as_dict()})
            if stop_on_error:
                break
    return results
