"""站点凭据：HMAC 验真、密钥库边界、轮换与准入判定。

秘密材料只允许写入库外的密钥库文件（0600 权限）；数据库、活动审计与导出中
只出现非秘密的凭据身份（credential_id 与密钥指纹）。准入判定的时间基准始终是
网关接收时刻，包自称的创建时间不得影响凭据效力。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import protocol, store
from .normalize import ObservationError, iso_utc, parse_time

ALGORITHM = "HMAC-SHA256"
SIDECAR_KIND = "packet_signature"
SIGNING_DOMAIN = "orbitbridge.packet-signature.v1"
KEYSTORE_SCHEMA = 1
CREDENTIAL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")


class CredentialError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AdmissionResult:
    """一次准入判定的非秘密结论。"""

    admitted: bool
    code: str
    message: str
    credential_id: str | None = None
    key_fingerprint: str | None = None
    revoked_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"admitted": self.admitted, "code": self.code, "message": self.message,
                "credential_id": self.credential_id, "key_fingerprint": self.key_fingerprint,
                "revoked_at": self.revoked_at}


def generate_secret() -> bytes:
    return secrets.token_bytes(32)


def key_fingerprint(secret: bytes) -> str:
    return hashlib.sha256(secret).hexdigest()


def signing_payload(packet: protocol.Packet, credential_id: str) -> bytes:
    """签名负载覆盖完整包身份：站点、序号、创建时间与正文摘要均被绑定。"""
    return protocol.canonical_json({
        "kind": SIGNING_DOMAIN,
        "credential_id": credential_id,
        "station_id": packet.envelope.station_id,
        "sequence": packet.envelope.sequence,
        "created_at": packet.envelope.created_at,
        "digest": packet.canonical_digest,
    })


def build_signature(packet: protocol.Packet, credential_id: str, secret: bytes) -> dict[str, Any]:
    if not CREDENTIAL_ID.fullmatch(credential_id):
        raise CredentialError("credential_id", "凭据标识无效")
    signature = hmac.new(secret, signing_payload(packet, credential_id), hashlib.sha256).hexdigest()
    return {"schema": 1, "kind": SIDECAR_KIND, "algorithm": ALGORITHM,
            "credential_id": credential_id, "station_id": packet.envelope.station_id,
            "sequence": packet.envelope.sequence, "digest": packet.canonical_digest,
            "signature": signature}


def parse_sidecar(value: object) -> dict[str, Any]:
    expected = {"schema", "kind", "algorithm", "credential_id", "station_id", "sequence", "digest", "signature"}
    if not isinstance(value, dict) or set(value) != expected:
        raise CredentialError("sidecar_fields", "签名侧车字段不完整或包含未知字段")
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise CredentialError("sidecar_schema", "仅支持签名侧车版本 1")
    if value["kind"] != SIDECAR_KIND or value["algorithm"] != ALGORITHM:
        raise CredentialError("sidecar_kind", "签名侧车类型或算法无效")
    cid = value["credential_id"]
    if not isinstance(cid, str) or not CREDENTIAL_ID.fullmatch(cid):
        raise CredentialError("credential_id", "凭据标识无效")
    station = value["station_id"]
    if not isinstance(station, str) or not (1 <= len(station) <= 64):
        raise CredentialError("sidecar_station", "侧车站点标识无效")
    if type(value["sequence"]) is not int or value["sequence"] < 1:
        raise CredentialError("sidecar_sequence", "侧车序号无效")
    digest = value["digest"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise CredentialError("sidecar_digest", "侧车摘要格式无效")
    signature = value["signature"]
    if not isinstance(signature, str) or len(signature) != 64 or any(c not in "0123456789abcdef" for c in signature):
        raise CredentialError("sidecar_signature", "侧车签名格式无效")
    return value


def sidecar_path(packet_path: str | Path) -> Path:
    return Path(str(packet_path) + ".sig.json")


def read_sidecar(packet_path: str | Path) -> dict[str, Any] | None:
    path = sidecar_path(packet_path)
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CredentialError("sidecar_unreadable", f"无法读取签名侧车：{path.name}") from exc
    return parse_sidecar(value)


class KeyStore:
    """库外密钥库：秘密材料的唯一归宿，文件强制 0600。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._data: dict[str, Any] | None = None

    @classmethod
    def create(cls, path: str | Path) -> "KeyStore":
        store_obj = cls(path)
        if store_obj.path.exists():
            raise CredentialError("keystore_exists", "密钥库已存在，拒绝覆盖")
        store_obj._data = {"schema": KEYSTORE_SCHEMA, "algorithm": ALGORITHM, "keys": {}}
        store_obj._save()
        return store_obj

    def load(self) -> "KeyStore":
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CredentialError("keystore_unreadable", "密钥库不存在或无法读取") from exc
        if not isinstance(value, dict) or value.get("schema") != KEYSTORE_SCHEMA \
                or value.get("algorithm") != ALGORITHM or not isinstance(value.get("keys"), dict):
            raise CredentialError("keystore_format", "密钥库格式无效")
        self._data = value
        return self

    @classmethod
    def open(cls, path: str | Path) -> "KeyStore":
        target = cls(path)
        if not target.path.exists():
            return target.create(path)
        return target.load()

    def _save(self) -> None:
        assert self._data is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".keystore-", dir=str(self.path.parent))
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(self._data, handle, ensure_ascii=False, sort_keys=True)
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        except BaseException:
            os.unlink(temporary)
            raise
        os.chmod(self.path, 0o600)

    def put(self, credential_id: str, secret: bytes) -> None:
        if self._data is None:
            self.load()
        assert self._data is not None
        if credential_id in self._data["keys"]:
            raise CredentialError("key_exists", "密钥库中已存在该凭据的秘密材料")
        self._data["keys"][credential_id] = {
            "fingerprint": key_fingerprint(secret),
            "secret_b64": base64.b64encode(secret).decode("ascii"),
        }
        self._save()

    def remove(self, credential_id: str) -> None:
        if self._data is None:
            self.load()
        assert self._data is not None
        self._data["keys"].pop(credential_id, None)
        self._save()

    def secret(self, credential_id: str) -> bytes | None:
        if self._data is None:
            self.load()
        assert self._data is not None
        entry = self._data["keys"].get(credential_id)
        if entry is None:
            return None
        try:
            return base64.b64decode(entry["secret_b64"], validate=True)
        except (ValueError, KeyError) as exc:
            raise CredentialError("keystore_format", "密钥库条目无效") from exc

    def has(self, credential_id: str) -> bool:
        return self.secret(credential_id) is not None


def _parse_boundary(value: str | None, field: str, default: str) -> str:
    if value is None:
        value = default
    try:
        return iso_utc(parse_time(value, 1, field))
    except ObservationError as exc:
        raise CredentialError(exc.code, f"{field} 时间无效") from exc


def _validate_scope(seq_from: int, seq_to: int | None, valid_from: str, valid_until: str | None) -> None:
    if type(seq_from) is not int or seq_from < 1:
        raise CredentialError("seq_from", "凭据起始序号须为正整数")
    if seq_to is not None and (type(seq_to) is not int or seq_to < seq_from):
        raise CredentialError("seq_to", "凭据截止序号不得小于起始序号")
    if valid_until is not None and valid_until <= valid_from:
        raise CredentialError("valid_until", "凭据失效时间须晚于生效时间")


def register_credential(connection: sqlite3.Connection, keystore: KeyStore, station_id: str,
                        credential_id: str, *, seq_from: int = 1, seq_to: int | None = None,
                        valid_from: str | None = None, valid_until: str | None = None,
                        secret: bytes | None = None, when: str | None = None) -> dict[str, Any]:
    if not CREDENTIAL_ID.fullmatch(credential_id):
        raise CredentialError("credential_id", "凭据标识无效")
    station = store.one(connection, "SELECT station_id FROM stations WHERE station_id=?", (station_id,))
    if station is None:
        raise CredentialError("station_missing", "站点不存在")
    if store.get_credential(connection, credential_id) is not None:
        raise CredentialError("credential_exists", "凭据标识已存在")
    timestamp = when or _now()
    start = _parse_boundary(valid_from, "valid_from", timestamp)
    until = _parse_boundary(valid_until, "valid_until", timestamp) if valid_until else None
    _validate_scope(seq_from, seq_to, start, until)
    material = secret or generate_secret()
    fingerprint = key_fingerprint(material)
    with store.transaction(connection):
        store.insert_credential(connection, credential_id, station_id, fingerprint, seq_from, seq_to,
                                start, until, timestamp)
        store.record_activity(connection, "credential_registered", "credential", credential_id, timestamp,
                              {"station_id": station_id, "key_fingerprint": fingerprint,
                               "seq_from": seq_from, "seq_to": seq_to,
                               "valid_from": start, "valid_until": until})
    try:
        keystore.put(credential_id, material)
    except BaseException:
        with store.transaction(connection):
            connection.execute("DELETE FROM station_credentials WHERE credential_id=?", (credential_id,))
        raise
    result = store.get_credential(connection, credential_id)
    assert result is not None
    result["secret_b64"] = base64.b64encode(material).decode("ascii")
    return result


def rotate_credential(connection: sqlite3.Connection, keystore: KeyStore, station_id: str,
                      new_credential_id: str, *, reason: str, seq_from: int | None = None,
                      seq_to: int | None = None, valid_from: str | None = None,
                      valid_until: str | None = None, when: str | None = None) -> dict[str, Any]:
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 300:
        raise CredentialError("reason", "轮换原因无效")
    station = store.one(connection, "SELECT station_id,committed_sequence FROM stations s "
                        "JOIN station_cursors c USING(station_id) WHERE s.station_id=?", (station_id,))
    if station is None:
        raise CredentialError("station_missing", "站点不存在")
    timestamp = when or _now()
    if seq_from is None:
        seq_from = int(station["committed_sequence"]) + 1
    start = _parse_boundary(valid_from, "valid_from", timestamp)
    until = _parse_boundary(valid_until, "valid_until", timestamp) if valid_until else None
    _validate_scope(seq_from, seq_to, start, until)
    material = generate_secret()
    fingerprint = key_fingerprint(material)
    previous = store.many(connection, "SELECT credential_id FROM station_credentials "
                          "WHERE station_id=? AND status='active' ORDER BY credential_id", (station_id,))
    with store.transaction(connection):
        for row in previous:
            store.revoke_credential_row(connection, row["credential_id"], timestamp, reason.strip())
        store.insert_credential(connection, new_credential_id, station_id, fingerprint, seq_from, seq_to,
                                start, until, timestamp)
        store.record_activity(connection, "credential_rotated", "credential", new_credential_id, timestamp,
                              {"station_id": station_id, "replaced": [row["credential_id"] for row in previous],
                               "key_fingerprint": fingerprint, "seq_from": seq_from, "seq_to": seq_to,
                               "valid_from": start, "valid_until": until, "reason": reason.strip()})
    try:
        keystore.put(new_credential_id, material)
    except BaseException:
        with store.transaction(connection):
            connection.execute("DELETE FROM station_credentials WHERE credential_id=?", (new_credential_id,))
        raise
    result = store.get_credential(connection, new_credential_id)
    assert result is not None
    result["secret_b64"] = base64.b64encode(material).decode("ascii")
    return result


def revoke_credential(connection: sqlite3.Connection, credential_id: str, reason: str,
                      *, when: str | None = None) -> dict[str, Any]:
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 300:
        raise CredentialError("reason", "撤销原因无效")
    existing = store.get_credential(connection, credential_id)
    if existing is None:
        raise CredentialError("credential_missing", "凭据不存在")
    timestamp = when or _now()
    with store.transaction(connection):
        store.revoke_credential_row(connection, credential_id, timestamp, reason.strip())
        store.record_activity(connection, "credential_revoked", "credential", credential_id, timestamp,
                              {"station_id": existing["station_id"], "reason": reason.strip()})
    result = store.get_credential(connection, credential_id)
    assert result is not None
    return result


def list_credentials(connection: sqlite3.Connection, station_id: str | None = None) -> list[dict[str, Any]]:
    return store.list_credentials(connection, station_id)


def _now() -> str:
    import datetime as dt
    return iso_utc(dt.datetime.now(dt.timezone.utc))


class AdmissionAuthority:
    """对单个包执行当前准入决定；无状态，结论可重复重核。"""

    def __init__(self, connection: sqlite3.Connection, keystore: KeyStore):
        self.connection = connection
        self.keystore = keystore

    def _deny(self, code: str, message: str, *, credential_id: str | None = None,
              fingerprint: str | None = None, revoked_at: str | None = None) -> AdmissionResult:
        return AdmissionResult(False, code, message, credential_id, fingerprint, revoked_at)

    def decide(self, packet: protocol.Packet, sidecar: dict[str, Any] | None, *, when: str) -> AdmissionResult:
        if sidecar is None:
            return self._deny("signature_missing", "缺少签名侧车，无法确认提交站点")
        try:
            sidecar = parse_sidecar(sidecar)
        except CredentialError as exc:
            return self._deny(exc.code, str(exc), credential_id=sidecar.get("credential_id")
                              if isinstance(sidecar, dict) else None)
        credential_id = sidecar["credential_id"]
        envelope = packet.envelope
        if sidecar["station_id"] != envelope.station_id or sidecar["sequence"] != envelope.sequence \
                or sidecar["digest"] != packet.canonical_digest:
            return self._deny("signature_mismatch", "签名侧车与包身份或正文摘要不一致",
                              credential_id=credential_id)
        credential = store.get_credential(self.connection, credential_id)
        if credential is None:
            return self._deny("credential_unknown", "凭据未登记", credential_id=credential_id)
        fingerprint = credential["key_fingerprint"]
        if credential["station_id"] != envelope.station_id:
            return self._deny("credential_station_mismatch", "凭据不属于包声明的站点",
                              credential_id=credential_id, fingerprint=fingerprint)
        secret = self.keystore.secret(credential_id)
        if secret is None:
            return self._deny("key_material_missing", "密钥库缺少该凭据的秘密材料",
                              credential_id=credential_id, fingerprint=fingerprint)
        if key_fingerprint(secret) != fingerprint:
            return self._deny("key_fingerprint_mismatch", "密钥材料与登记指纹不一致",
                              credential_id=credential_id, fingerprint=fingerprint)
        expected = hmac.new(secret, signing_payload(packet, credential_id), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sidecar["signature"]):
            return self._deny("signature_invalid", "签名验真失败",
                              credential_id=credential_id, fingerprint=fingerprint)
        sequence = envelope.sequence
        if sequence < credential["seq_from"] or (credential["seq_to"] is not None and sequence > credential["seq_to"]):
            scope = f"{credential['seq_from']}..{credential['seq_to'] or 'open'}"
            return self._deny("credential_sequence_scope", f"序号 {sequence} 超出凭据适用序号范围 {scope}",
                              credential_id=credential_id, fingerprint=fingerprint)
        # 时间基准固定为网关接收时刻；包自称的 created_at 不参与效力判断。
        received = parse_time(when, 1, "received_at")
        valid_from = parse_time(credential["valid_from"], 1, "valid_from")
        if received < valid_from:
            return self._deny("credential_not_yet_valid", "接收时刻早于凭据生效时间",
                              credential_id=credential_id, fingerprint=fingerprint)
        if credential["valid_until"] is not None:
            valid_until = parse_time(credential["valid_until"], 1, "valid_until")
            if received > valid_until:
                return self._deny("credential_expired", "接收时刻晚于凭据失效时间",
                                  credential_id=credential_id, fingerprint=fingerprint)
        if credential["status"] == "revoked":
            return self._deny("credential_revoked",
                              f"凭据已于 {credential['revoked_at']} 撤销：{credential['revoke_reason']}",
                              credential_id=credential_id, fingerprint=fingerprint,
                              revoked_at=credential["revoked_at"])
        return AdmissionResult(True, "admitted", "验真通过", credential_id, fingerprint)


def write_sidecar(packet_path: str | Path, sidecar: dict[str, Any]) -> Path:
    target = sidecar_path(packet_path)
    if target.exists():
        raise CredentialError("sidecar_exists", "签名侧车已存在，拒绝覆盖")
    target.write_text(json.dumps(sidecar, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return target
