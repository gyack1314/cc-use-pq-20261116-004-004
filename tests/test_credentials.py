from __future__ import annotations

import base64
import json
import os
import stat

from orbitbridge import audit, credentials, diagnostics, export, ingest, protocol, recovery, store
from helpers import CREDENTIAL_ID
from helpers import DatabaseCase, STAMP, packet, sign


def obs(identifier: str = "sim-1") -> dict:
    return {"kind": "observation", "id": identifier, "observed_at": "2026-10-28T12:01:00Z",
            "region": "north", "latitude": 31.2, "longitude": 121.4, "confidence": "0.8",
            "severity": 4, "source": "infrared"}


class CredentialAdmissionTests(DatabaseCase):
    def test_signature_binds_full_packet_identity(self):
        raw = packet()
        decision = self.authority.decide(protocol.parse_packet_bytes(raw),
                                         sign(raw, keystore=self.keystore), when=STAMP)
        self.assertTrue(decision.admitted)
        # 另一个合法包的签名不能复用到本包：摘要不同即判失配。
        other = packet(1, [obs("sim-other")])
        decision = self.authority.decide(protocol.parse_packet_bytes(raw),
                                         sign(other, keystore=self.keystore), when=STAMP)
        self.assertFalse(decision.admitted)
        self.assertEqual(decision.code, "signature_mismatch")

    def test_forged_signature_is_rejected(self):
        raw = packet()
        sidecar = sign(raw, keystore=self.keystore)
        sidecar["signature"] = "0" * 64
        decision = self.authority.decide(protocol.parse_packet_bytes(raw), sidecar, when=STAMP)
        self.assertEqual(decision.code, "signature_invalid")

    def test_unknown_credential_and_missing_key_material(self):
        raw = packet()
        sidecar = sign(raw, keystore=self.keystore)
        sidecar["credential_id"] = "ghost-key"
        self.assertEqual(self.authority.decide(protocol.parse_packet_bytes(raw), sidecar, when=STAMP).code,
                         "credential_unknown")
        # 数据库仍登记该凭据，但库外密钥库已丢失材料。
        self.keystore.remove(CREDENTIAL_ID)
        decision = self.authority.decide(protocol.parse_packet_bytes(raw),
                                         self._sidecar_for_registered(raw), when=STAMP)
        self.assertEqual(decision.code, "key_material_missing")

    def _sidecar_for_registered(self, raw: bytes) -> dict:
        material = credentials.generate_secret()
        spare = credentials.KeyStore.create(self.root / "spare.json")
        spare.put(CREDENTIAL_ID, material)
        return sign(raw, keystore=spare)

    def test_revoked_credential_cannot_be_revived_by_packet_timestamp(self):
        raw = packet()
        path = self.write_signed_bytes(raw)
        self.assertEqual(ingest.ingest_file(self.db, path, self.authority, when=STAMP).status, "accepted")
        credentials.revoke_credential(self.db, CREDENTIAL_ID, "应急撤销", when=STAMP)
        # 延迟包自称的创建时间仍在撤销之前；接收时刻在撤销之后，必须拒收。
        late = self.write_signed_bytes(raw, name="late.jsonl")
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_file(self.db, late, self.authority, when="2026-10-28T13:00:00Z")
        self.assertEqual(error.exception.code, "credential_revoked")
        quarantined = audit.list_quarantine(self.db)
        self.assertEqual(quarantined[-1]["credential_id"], CREDENTIAL_ID)

    def test_expired_and_pending_credentials_use_receive_time(self):
        credentials.register_credential(self.db, self.keystore, "sat-a", "future-key",
                                        valid_from="2026-10-29T00:00:00Z", when=STAMP)
        raw = packet()
        sidecar = sign(raw, "future-key", keystore=self.keystore)
        self.assertEqual(self.authority.decide(protocol.parse_packet_bytes(raw), sidecar,
                                               when=STAMP).code, "credential_not_yet_valid")
        self.assertTrue(self.authority.decide(protocol.parse_packet_bytes(raw), sidecar,
                                              when="2026-10-29T01:00:00Z").admitted)
        credentials.register_credential(self.db, self.keystore, "sat-a", "old-key",
                                        valid_from="2026-09-01T00:00:00Z",
                                        valid_until="2026-10-01T00:00:00Z", when=STAMP)
        sidecar = sign(raw, "old-key", keystore=self.keystore)
        self.assertEqual(self.authority.decide(protocol.parse_packet_bytes(raw), sidecar,
                                               when=STAMP).code, "credential_expired")

    def test_sequence_scope_is_enforced(self):
        credentials.register_credential(self.db, self.keystore, "sat-a", "narrow-key",
                                        seq_from=5, seq_to=10, when=STAMP)
        raw = packet(3)
        decision = self.authority.decide(protocol.parse_packet_bytes(raw),
                                         sign(raw, "narrow-key", keystore=self.keystore), when=STAMP)
        self.assertEqual(decision.code, "credential_sequence_scope")
        raw_ok = packet(5)
        self.assertTrue(self.authority.decide(protocol.parse_packet_bytes(raw_ok),
                                              sign(raw_ok, "narrow-key", keystore=self.keystore),
                                              when=STAMP).admitted)

    def test_rotation_revokes_previous_and_new_credential_signs_next_sequence(self):
        first = self.ingest_signed(packet(), when=STAMP)
        self.rotate("sat-a-key-2", seq_from=2, when=STAMP)
        old = store.get_credential(self.db, CREDENTIAL_ID)
        new = store.get_credential(self.db, "sat-a-key-2")
        self.assertEqual(old["status"], "revoked")
        self.assertEqual(new["status"], "active")
        # 旧凭据的延迟包被拒。
        with self.assertRaises(ingest.IngestError) as late:
            self.ingest_signed(packet(), when=STAMP)
        self.assertEqual(late.exception.code, "credential_revoked")
        # 新凭据签的下一序号正常接收。
        second_raw = packet(2, [obs("sim-2")])
        result = ingest.ingest_bytes(self.db, second_raw, self.authority,
                                     sidecar=sign(second_raw, "sat-a-key-2", keystore=self.keystore), when=STAMP)
        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.credential_id, "sat-a-key-2")
        # 历史批次的凭据身份未被抹除。
        self.assertEqual(store.get_batch(self.db, first.batch_id)["credential_id"], CREDENTIAL_ID)

    def test_duplicate_after_rotation_requires_still_admitted_credential(self):
        raw = packet()
        self.ingest_signed(raw, when=STAMP)
        # 凭据仍有效：同一包幂等返回 duplicate。
        again = self.ingest_signed(raw, when=STAMP)
        self.assertEqual(again.status, "duplicate")
        credentials.revoke_credential(self.db, CREDENTIAL_ID, "应急撤销", when=STAMP)
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(raw, when=STAMP)
        self.assertEqual(error.exception.code, "credential_revoked")
        self.assertEqual(store.counts(self.db)["batches"], 1)

    def test_new_credential_same_sequence_conflict_is_quarantined_without_touching_history(self):
        raw = packet()
        first = self.ingest_signed(raw, when=STAMP)
        self.rotate("sat-a-key-2", seq_from=1, when=STAMP)
        conflict = packet(1, [obs("other")])
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, conflict, self.authority,
                                sidecar=sign(conflict, "sat-a-key-2", keystore=self.keystore), when=STAMP)
        self.assertEqual(error.exception.code, "sequence_conflict")
        view = audit.batch_credential_view(self.db, first.batch_id)
        self.assertEqual(view["credential_id"], CREDENTIAL_ID)
        self.assertTrue(view["fingerprint_unchanged"])
        self.assertEqual(view["current_status"], "revoked")

    def test_keystore_file_is_0600_and_secrets_never_reach_db_audit_or_export(self):
        mode = stat.S_IMODE(os.stat(self.root / "keystore.json").st_mode)
        self.assertEqual(mode, 0o600)
        raw = packet()
        accepted = self.ingest_signed(raw, when=STAMP)
        secret_b64 = json.loads((self.root / "keystore.json").read_text())["keys"][CREDENTIAL_ID]["secret_b64"]
        secret_hex = base64.b64decode(secret_b64).hex()
        db_text = "".join(str(row) for row in self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"))
        for table in ("station_credentials", "activity", "batches", "quarantine"):
            rows = self.db.execute(f"SELECT * FROM {table}").fetchall()
            blob = json.dumps([dict(row) for row in rows], ensure_ascii=False, default=str)
            self.assertNotIn(secret_hex, blob)
            self.assertNotIn(secret_b64, blob)
        destination = self.root / "handoffs.jsonl"
        receipt = export.export_handoffs(self.db, "north-watch", destination)
        exported = destination.read_text()
        self.assertNotIn(secret_hex, exported)
        self.assertNotIn(secret_b64, exported)
        # 导出仍携带非秘密凭据身份，供值守人员核对。
        row = json.loads(exported.splitlines()[0])
        self.assertEqual(row["credential_id"], CREDENTIAL_ID)
        self.assertEqual(row["credential_fingerprint"], accepted.key_fingerprint)
        self.assertTrue(export.verify_export(destination, receipt.sha256, expected_rows=1)["ok"])

    def test_audit_views_expose_only_non_secret_identity(self):
        self.ingest_signed(packet(), when=STAMP)
        listed = audit.list_credentials(self.db, "sat-a")
        self.assertEqual({row["credential_id"] for row in listed}, {CREDENTIAL_ID})
        for row in listed:
            self.assertNotIn("secret", json.dumps(row))
        view = audit.batch_credential_view(self.db, 1)
        self.assertTrue(view["fingerprint_unchanged"])
        events = audit.list_activity(self.db)
        for event in events:
            self.assertNotIn("secret", json.dumps(event, ensure_ascii=False))

    def test_lineage_check_flags_missing_credential_evidence(self):
        self.ingest_signed(packet(), when=STAMP)
        self.assertEqual(audit.verify_lineage(self.db), [])
        self.db.execute("DELETE FROM station_credentials WHERE credential_id=?", (CREDENTIAL_ID,))
        issues = audit.verify_lineage(self.db)
        self.assertTrue(any(issue.startswith("credential_lost:") for issue in issues))

    def test_recovery_plan_keeps_blocked_sequences_and_reason_after_revocation(self):
        folder = self.root / "incoming"
        folder.mkdir()
        self.write_packet(1, name=folder / "p1.jsonl")
        self.write_packet(2, [obs("sim-2")], name=folder / "p2.jsonl")
        credentials.revoke_credential(self.db, CREDENTIAL_ID, "应急撤销", when=STAMP)
        plan = recovery.plan_station(self.db, "sat-a", folder, self.authority, when=STAMP)
        self.assertEqual(plan["ready"], [])
        reasons = {(row["source_name"], row["admission_code"], row["blocks_from"]) for row in plan["blocked"]}
        self.assertIn(("p1.jsonl", "credential_revoked", 1), reasons)
        self.assertIn(("p2.jsonl", "credential_revoked", 2), reasons)

    def test_diagnostics_reports_current_admission_without_mutating_state(self):
        path = self.write_packet()
        result = diagnostics.inspect_packet(self.db, path, self.authority, when=STAMP)
        self.assertTrue(result["admission"]["admitted"])
        self.assertEqual(result["admission"]["credential_id"], CREDENTIAL_ID)
        self.assertEqual(store.counts(self.db)["batches"], 0)
        unsigned = self.write_packet(3, name="unsigned.jsonl", signed=False)
        result = diagnostics.inspect_packet(self.db, unsigned, self.authority, when=STAMP)
        self.assertFalse(result["admission"]["admitted"])
        self.assertEqual(result["admission"]["code"], "signature_missing")
        self.assertEqual(store.counts(self.db)["quarantine"], 0)

    def test_sidecar_must_match_station_sequence_and_digest(self):
        raw = packet(1)
        sidecar = sign(raw, keystore=self.keystore)
        sidecar["sequence"] = 2
        self.assertEqual(self.authority.decide(protocol.parse_packet_bytes(raw), sidecar,
                                               when=STAMP).code, "signature_mismatch")
        sidecar = sign(raw, keystore=self.keystore)
        sidecar["station_id"] = "sat-b"
        self.assertEqual(self.authority.decide(protocol.parse_packet_bytes(raw), sidecar,
                                               when=STAMP).code, "signature_mismatch")

    def test_credential_register_rolls_back_db_when_keystore_write_fails(self):
        class BrokenKeyStore(credentials.KeyStore):
            def put(self, credential_id, secret):  # noqa: ANN001
                raise OSError("keystore disk full")

        with self.assertRaises(OSError):
            credentials.register_credential(self.db, BrokenKeyStore(self.root / "broken.json"),
                                            "sat-a", "orphan-key", when=STAMP)
        self.assertIsNone(store.get_credential(self.db, "orphan-key"))

    def test_invalid_sidecar_document_is_denied(self):
        raw = packet()
        decision = self.authority.decide(protocol.parse_packet_bytes(raw), {"bad": "shape"}, when=STAMP)
        self.assertEqual(decision.code, "sidecar_fields")
