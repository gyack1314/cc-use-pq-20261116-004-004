from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from orbitbridge import catalog, credentials, protocol, store

STAMP = "2026-10-28T12:03:00Z"
PACKET_TIME = "2026-10-28T12:02:00Z"
CREDENTIAL_ID = "sat-a-key-1"


def observation(identifier: str = "sim-1", *, region: str = "north", severity: int = 4,
                confidence: str = "0.8", observed_at: str = "2026-10-28T12:01:00Z",
                latitude: object = 31.2, longitude: object = 121.4, source: str = "infrared") -> dict:
    return {"kind": "observation", "id": identifier, "observed_at": observed_at, "region": region,
            "latitude": latitude, "longitude": longitude, "confidence": confidence,
            "severity": severity, "source": source}


def packet(sequence: int = 1, records: list[dict] | None = None, *, station: str = "sat-a",
           created_at: str = PACKET_TIME) -> bytes:
    return protocol.encode_packet(station, sequence, created_at, records or [observation()])


def sign(raw: bytes, credential_id: str = CREDENTIAL_ID, *, keystore: credentials.KeyStore | None = None) -> dict:
    assert keystore is not None
    return credentials.build_signature(protocol.parse_packet_bytes(raw), credential_id,
                                       keystore.secret(credential_id))


class DatabaseCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.db_path = self.root / "store.sqlite3"
        self.db = store.open_database(self.db_path)
        self.addCleanup(lambda: self.db.close())
        self.keystore = credentials.KeyStore.create(self.root / "keystore.json")
        catalog.register_station(self.db, "sat-a", "合成观测站", when=STAMP)
        catalog.register_subscription(self.db, "north-watch", "north", 3, "0.7", when=STAMP)
        credentials.register_credential(self.db, self.keystore, "sat-a", CREDENTIAL_ID,
                                        seq_from=1, when=STAMP)
        self.authority = credentials.AdmissionAuthority(self.db, self.keystore)

    def write_packet(self, sequence: int = 1, records: list[dict] | None = None, *,
                     name: str | None = None, station: str = "sat-a",
                     signed: bool = True, credential_id: str = CREDENTIAL_ID) -> Path:
        path = self.root / (name or f"packet-{sequence}.jsonl")
        raw = packet(sequence, records, station=station)
        path.write_bytes(raw)
        if signed:
            credentials.write_sidecar(path, sign(raw, credential_id, keystore=self.keystore))
        return path

    def write_signed_bytes(self, raw: bytes, *, name: str = "incoming.jsonl",
                           credential_id: str = CREDENTIAL_ID) -> Path:
        path = self.root / name
        path.write_bytes(raw)
        credentials.write_sidecar(path, sign(raw, credential_id, keystore=self.keystore))
        return path

    def ingest_signed(self, raw: bytes, *, when: str = STAMP, source_name: str = "<memory>",
                      credential_id: str = CREDENTIAL_ID):
        return ingest_module().ingest_bytes(
            self.db, raw, self.authority, source_name=source_name,
            sidecar=sign(raw, credential_id, keystore=self.keystore), when=when)

    def rotate(self, new_id: str = "sat-a-key-2", *, seq_from: int | None = None,
               reason: str = "例行轮换", when: str = STAMP) -> dict:
        return credentials.rotate_credential(self.db, self.keystore, "sat-a", new_id,
                                             reason=reason, seq_from=seq_from, when=when)


def ingest_module():
    from orbitbridge import ingest
    return ingest
