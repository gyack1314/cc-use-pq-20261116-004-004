from __future__ import annotations

import hashlib
import json

from orbitbridge import audit, credentials, ingest, intake, protocol, recovery, store
from helpers import CREDENTIAL_ID, DatabaseCase, STAMP, packet, sign


def record(identifier: str) -> dict:
    return {"kind": "observation", "id": identifier, "observed_at": "2026-10-28T12:01:00Z",
            "region": "north", "latitude": 31.2, "longitude": 121.4, "confidence": "0.8",
            "severity": 4, "source": "infrared"}


class RecoveryTests(DatabaseCase):
    def test_plan_orders_sequence_instead_of_filename(self):
        folder = self.root / "incoming"
        folder.mkdir()
        self.write_packet(1, name=folder / "z-first.jsonl")
        self.write_packet(2, [record("sim-2")], name=folder / "a-second.jsonl")
        plan = recovery.plan_station(self.db, "sat-a", folder, self.authority, when=STAMP)
        self.assertEqual([entry["sequence"] for entry in plan["ready"]], [1, 2])
        self.assertEqual(plan["next_expected"], 3)
        self.assertTrue(all(entry["admission"]["admitted"] for entry in plan["ready"]))

    def test_resume_advances_cursor_across_ready_packets(self):
        folder = self.root / "incoming"
        folder.mkdir()
        self.write_packet(1, name=folder / "z-first.jsonl")
        self.write_packet(2, [record("sim-2")], name=folder / "a-second.jsonl")
        outcome = recovery.resume_station(self.db, "sat-a", folder, self.authority, when=STAMP)
        self.assertEqual([row["status"] for row in outcome["results"]], ["accepted", "accepted"])
        self.assertEqual(outcome["cursor_after"], 2)
        repeated = recovery.resume_station(self.db, "sat-a", folder, self.authority, when=STAMP)
        self.assertEqual(repeated["results"], [])
        self.assertEqual(len(repeated["plan"]["duplicates"]), 2)

    def test_gap_is_planned_as_blocked(self):
        folder = self.root / "incoming"
        folder.mkdir()
        self.write_packet(3, name=folder / "three.jsonl")
        plan = recovery.plan_station(self.db, "sat-a", folder, self.authority, when=STAMP)
        self.assertEqual(plan["ready"], [])
        self.assertEqual(plan["blocked"][0]["reason"], "waiting_for_gap")
        self.assertEqual(plan["blocked"][0]["expected"], 1)

    def test_plan_reports_conflicting_same_sequence(self):
        folder = self.root / "incoming"
        folder.mkdir()
        self.write_packet(1, name=folder / "a.jsonl")
        self.write_packet(1, [record("other")], name=folder / "b.jsonl")
        plan = recovery.plan_station(self.db, "sat-a", folder, self.authority, when=STAMP)
        self.assertEqual(len(plan["ready"]), 1)
        self.assertEqual(plan["blocked"][0]["reason"], "sequence_conflict")

    def test_plan_skips_unreadable_packet(self):
        folder = self.root / "incoming"
        folder.mkdir()
        (folder / "bad.jsonl").write_bytes(b"broken")
        plan = recovery.plan_station(self.db, "sat-a", folder, self.authority, when=STAMP)
        self.assertEqual(plan["unreadable"][0]["reason"], "bad_json")
        self.assertEqual(plan["ready"], [])

    def test_revoked_credential_blocks_plan_and_recheck_blocks_resume(self):
        folder = self.root / "incoming"
        folder.mkdir()
        first = self.write_packet(1, name=folder / "a.jsonl")
        plan_before = recovery.plan_station(self.db, "sat-a", folder, self.authority, when=STAMP)
        self.assertEqual([entry["source_name"] for entry in plan_before["ready"]], ["a.jsonl"])
        credentials.revoke_credential(self.db, CREDENTIAL_ID, "应急撤销", when=STAMP)
        plan_after = recovery.plan_station(self.db, "sat-a", folder, self.authority, when=STAMP)
        self.assertEqual(plan_after["ready"], [])
        blocked = plan_after["blocked"][0]
        self.assertEqual(blocked["reason"], "admission_denied")
        self.assertEqual(blocked["admission_code"], "credential_revoked")
        self.assertEqual(blocked["blocks_from"], 1)
        outcome = recovery.resume_station(self.db, "sat-a", folder, self.authority, when=STAMP)
        self.assertEqual(outcome["results"], [])
        self.assertEqual(outcome["plan"]["blocked"][0]["admission_code"], "credential_revoked")
        self.assertEqual(outcome["plan"]["blocked"][0]["blocks_from"], 1)
        self.assertEqual(outcome["cursor_after"], 0)
        self.assertTrue(first.exists())

    def test_quarantine_retry_stays_on_same_packet_identity(self):
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(packet(2), when=STAMP)
        quarantine_id = error.exception.quarantine_id
        path = self.write_packet(2)
        plan = recovery.quarantine_retry_plan(self.db, quarantine_id, path, self.authority, when=STAMP)
        self.assertTrue(plan["same_content"])
        self.assertEqual(plan["sequence"], 2)
        self.assertTrue(plan["admission"]["admitted"])
        self.ingest_signed(packet(1), when=STAMP)
        result = recovery.retry_file(self.db, quarantine_id, path, self.authority, when=STAMP)
        self.assertEqual(result["result"]["status"], "rejected")
        self.assertEqual(result["result"]["code"], "observation_conflict")

    def test_quarantine_retry_rejects_different_content(self):
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(packet(3), when=STAMP)
        changed = self.write_packet(3, [record("other")])
        with self.assertRaises(recovery.RecoveryError) as mismatch:
            recovery.quarantine_retry_plan(self.db, error.exception.quarantine_id, changed,
                                           self.authority, when=STAMP)
        self.assertEqual(mismatch.exception.code, "retry_mismatch")

    def test_quarantine_retry_rechecks_revocation(self):
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(packet(2), when=STAMP)
        path = self.write_packet(2)
        credentials.revoke_credential(self.db, CREDENTIAL_ID, "应急撤销", when=STAMP)
        plan = recovery.quarantine_retry_plan(self.db, error.exception.quarantine_id, path,
                                              self.authority, when=STAMP)
        self.assertFalse(plan["admission"]["admitted"])
        self.assertEqual(plan["admission"]["code"], "credential_revoked")
        with self.assertRaises(recovery.RecoveryError) as blocked:
            recovery.retry_file(self.db, error.exception.quarantine_id, path, self.authority, when=STAMP)
        self.assertEqual(blocked.exception.code, "credential_revoked")

    def test_manifest_preflight_resolves_order_across_filenames(self):
        first = self.write_packet(1, name="z.jsonl")
        second = self.write_packet(2, [record("sim-2")], name="a.jsonl")
        manifest = self._manifest([first, second])
        plan = intake.preflight(self.db, manifest, authority=self.authority, when=STAMP)
        self.assertEqual([entry["sequence"] for entry in plan["entries"]], [1, 2])
        self.assertEqual(plan["ready"], 2)
        self.assertEqual(plan["blocked"], 0)

    def test_manifest_executes_and_replay_is_idempotent(self):
        first = self.write_packet(1)
        second = self.write_packet(2, [record("sim-2")])
        manifest = self._manifest([first, second])
        result = intake.execute_manifest(self.db, manifest, authority=self.authority, when=STAMP)
        self.assertEqual(result["accepted"], 2)
        self.assertEqual(store.counts(self.db)["batches"], 2)
        repeat = intake.execute_manifest(self.db, manifest, authority=self.authority, when=STAMP)
        self.assertEqual(repeat["accepted"], 0)
        self.assertEqual([row["status"] for row in repeat["results"]], ["duplicate", "duplicate"])

    def test_manifest_missing_file_is_reported(self):
        first = self.write_packet()
        manifest = self._manifest([first])
        first.unlink()
        plan = intake.preflight(self.db, manifest, authority=self.authority, when=STAMP)
        self.assertEqual(plan["entries"][0]["status"], "missing")
        self.assertEqual(plan["blocked"], 1)

    def test_manifest_hash_mismatch_is_reported(self):
        first = self.write_packet()
        manifest = self._manifest([first])
        first.write_bytes(first.read_bytes() + b"x")
        plan = intake.preflight(self.db, manifest, authority=self.authority, when=STAMP)
        self.assertEqual(plan["entries"][0]["status"], "checksum_mismatch")

    def test_manifest_entry_without_sidecar_is_admission_denied(self):
        first = self.write_packet(signed=False)
        manifest = self._manifest([first])
        plan = intake.preflight(self.db, manifest, authority=self.authority, when=STAMP)
        self.assertEqual(plan["entries"][0]["status"], "admission_denied")
        self.assertEqual(plan["entries"][0]["admission_code"], "signature_missing")
        self.assertEqual(plan["blocked"], 1)

    def test_manifest_rejects_path_traversal(self):
        raw = {"schema": 1, "name": "bad", "packets": [{"file": "../out.jsonl", "station_id": "sat-a",
              "sequence": 1, "sha256": "a" * 64}]}
        with self.assertRaises(intake.ManifestError) as error:
            intake.parse_manifest(json.dumps(raw).encode())
        self.assertEqual(error.exception.code, "file_name")

    def test_manifest_rejects_duplicate_sequence(self):
        first = self.write_packet()
        manifest = self._manifest([first])
        data = json.loads(manifest.read_text())
        data["packets"].append({**data["packets"][0], "file": "other.jsonl"})
        with self.assertRaises(intake.ManifestError) as error:
            intake.parse_manifest(json.dumps(data).encode())
        self.assertEqual(error.exception.code, "duplicate_sequence")

    def _manifest(self, paths):
        rows = []
        for path in paths:
            parsed = protocol.parse_packet_file(path)
            rows.append({"file": path.name, "station_id": parsed.envelope.station_id,
                         "sequence": parsed.envelope.sequence, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"schema": 1, "name": "synthetic-transfer", "packets": rows}))
        return manifest
