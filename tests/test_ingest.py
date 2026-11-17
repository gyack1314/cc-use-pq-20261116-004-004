from __future__ import annotations

from orbitbridge import audit, catalog, credentials, handoff, ingest, protocol, store
from helpers import CREDENTIAL_ID, DatabaseCase, STAMP, packet, sign


class IngestTests(DatabaseCase):
    def test_ingest_creates_batch_observation_and_handoff_atomically(self):
        result = self.ingest_signed(packet(), when=STAMP)
        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.observation_count, 1)
        self.assertEqual(result.handoff_count, 1)
        self.assertEqual(result.credential_id, CREDENTIAL_ID)
        self.assertEqual(store.counts(self.db)["batches"], 1)
        self.assertEqual(store.counts(self.db)["observations"], 1)
        self.assertEqual(store.counts(self.db)["handoffs"], 1)
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 1)
        batch = audit.batch_detail(self.db, result.batch_id)["batch"]
        self.assertEqual(batch["packet_id"], result.packet_id)
        self.assertEqual(batch["credential_id"], CREDENTIAL_ID)
        self.assertEqual(batch["key_fingerprint"], result.key_fingerprint)

    def test_same_packet_is_idempotent(self):
        first = self.ingest_signed(packet(), when=STAMP)
        second = self.ingest_signed(packet(), when=STAMP)
        self.assertEqual(second.status, "duplicate")
        self.assertEqual(second.batch_id, first.batch_id)
        self.assertEqual(second.handoff_count, first.handoff_count)
        self.assertEqual(second.credential_id, CREDENTIAL_ID)
        self.assertEqual(store.counts(self.db)["batches"], 1)
        self.assertEqual(store.counts(self.db)["quarantine"], 0)

    def test_same_sequence_different_digest_is_isolated(self):
        self.ingest_signed(packet(), when=STAMP)
        changed = packet(records=[{"kind": "observation", "id": "changed",
                                   "observed_at": "2026-10-28T12:01:00Z", "region": "north",
                                   "latitude": 31.2, "longitude": 121.4, "confidence": "0.8",
                                   "severity": 4, "source": "infrared"}])
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(changed, when=STAMP)
        self.assertEqual(error.exception.code, "sequence_conflict")
        self.assertIsNotNone(error.exception.quarantine_id)
        self.assertEqual(store.counts(self.db)["batches"], 1)
        self.assertEqual(store.counts(self.db)["observations"], 1)
        self.assertEqual(store.counts(self.db)["quarantine"], 1)

    def test_gap_does_not_advance_cursor(self):
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(packet(2), when=STAMP)
        self.assertEqual(error.exception.code, "sequence_gap")
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 0)
        self.assertEqual(store.counts(self.db)["batches"], 0)
        self.ingest_signed(packet(1), when=STAMP)
        second = packet(2, [{"kind": "observation", "id": "sim-2",
                             "observed_at": "2026-10-28T12:01:00Z", "region": "north",
                             "latitude": 31.2, "longitude": 121.4, "confidence": "0.8",
                             "severity": 4, "source": "infrared"}])
        self.assertEqual(self.ingest_signed(second, when=STAMP).status, "accepted")
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 2)

    def test_invalid_record_rolls_back_whole_batch(self):
        rows = [
            {"kind": "observation", "id": "good", "observed_at": "2026-10-28T12:01:00Z",
             "region": "north", "latitude": 31.2, "longitude": 121.4, "confidence": "0.8",
             "severity": 4, "source": "infrared"},
            {"kind": "observation", "id": "bad", "observed_at": "2026-10-28T12:01:00Z",
             "region": "north", "latitude": 95, "longitude": 121.4, "confidence": "0.8",
             "severity": 4, "source": "infrared"},
        ]
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(packet(records=rows), when=STAMP)
        self.assertEqual(error.exception.code, "number_range")
        counts = store.counts(self.db)
        self.assertEqual(counts["batches"], 0)
        self.assertEqual(counts["observations"], 0)
        self.assertEqual(counts["handoffs"], 0)
        self.assertEqual(counts["quarantine"], 1)

    def test_invalid_digest_is_quarantined_without_station_identity(self):
        raw = packet().replace(b"sim-1", b"sim-9")
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_bytes(self.db, raw, self.authority, when=STAMP)
        self.assertEqual(error.exception.code, "digest_mismatch")
        record = audit.list_quarantine(self.db)[0]
        self.assertIsNone(record["station_id"])
        self.assertIsNone(record["sequence"])
        self.assertEqual(store.counts(self.db)["batches"], 0)

    def test_repeated_rejection_increments_attempts(self):
        raw = packet(3)
        for _ in range(3):
            with self.assertRaises(ingest.IngestError):
                self.ingest_signed(raw, when=STAMP)
        rows = audit.list_quarantine(self.db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["attempts"], 3)

    def test_inactive_station_is_rejected(self):
        catalog.set_station_active(self.db, "sat-a", False)
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(packet(), when=STAMP)
        self.assertEqual(error.exception.code, "station_inactive")
        self.assertEqual(store.counts(self.db)["batches"], 0)
        catalog.set_station_active(self.db, "sat-a", True)
        self.assertEqual(self.ingest_signed(packet(), when=STAMP).status, "accepted")

    def test_unknown_station_is_rejected(self):
        raw = packet(station="sat-x")
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(raw, when=STAMP)
        # 验真先于站点注册检查：凭据属于 sat-a，与包声明站点不符。
        self.assertEqual(error.exception.code, "credential_station_mismatch")
        self.assertEqual(store.counts(self.db)["batches"], 0)

    def test_observation_identity_must_be_unique_across_batches(self):
        self.ingest_signed(packet(), when=STAMP)
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(packet(2), when=STAMP)
        self.assertEqual(error.exception.code, "observation_conflict")
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 1)
        self.assertEqual(store.counts(self.db)["observations"], 1)

    def test_no_matching_subscription_keeps_observation(self):
        record = {"kind": "observation", "id": "sim-1", "observed_at": "2026-10-28T12:01:00Z",
                  "region": "south", "latitude": 31.2, "longitude": 121.4, "confidence": "0.8",
                  "severity": 4, "source": "infrared"}
        result = self.ingest_signed(packet(records=[record]), when=STAMP)
        self.assertEqual(result.handoff_count, 0)
        self.assertEqual(store.counts(self.db)["observations"], 1)
        self.assertEqual(store.counts(self.db)["handoffs"], 0)

    def test_multiple_subscriptions_receive_same_observation(self):
        catalog.register_subscription(self.db, "north-backup", "north", 2, "0.5", when=STAMP)
        result = self.ingest_signed(packet(), when=STAMP)
        self.assertEqual(result.handoff_count, 2)
        subscriptions = {row["subscription_id"] for row in handoff.list_handoffs(self.db)}
        self.assertEqual(subscriptions, {"north-watch", "north-backup"})

    def test_disabled_subscription_gets_no_new_handoff(self):
        catalog.set_subscription_active(self.db, "north-watch", False)
        result = self.ingest_signed(packet(), when=STAMP)
        self.assertEqual(result.handoff_count, 0)
        self.assertEqual(store.counts(self.db)["observations"], 1)

    def test_confidence_threshold_filters_handoff(self):
        record = {"kind": "observation", "id": "sim-1", "observed_at": "2026-10-28T12:01:00Z",
                  "region": "north", "latitude": 31.2, "longitude": 121.4, "confidence": "0.69",
                  "severity": 4, "source": "infrared"}
        result = self.ingest_signed(packet(records=[record]), when=STAMP)
        self.assertEqual(result.handoff_count, 0)
        self.assertEqual(handoff.list_handoffs(self.db), [])

    def test_severity_threshold_filters_handoff(self):
        record = {"kind": "observation", "id": "sim-1", "observed_at": "2026-10-28T12:01:00Z",
                  "region": "north", "latitude": 31.2, "longitude": 121.4, "confidence": "0.8",
                  "severity": 2, "source": "infrared"}
        result = self.ingest_signed(packet(records=[record]), when=STAMP)
        self.assertEqual(result.handoff_count, 0)
        self.assertEqual(store.counts(self.db)["observations"], 1)

    def test_file_source_name_is_retained(self):
        file = self.write_packet(name="ground-station.jsonl")
        result = ingest.ingest_file(self.db, file, self.authority, when=STAMP)
        self.assertEqual(store.get_batch(self.db, result.batch_id)["source_name"], file.name)

    def test_directory_import_is_ordered_and_isolates_errors(self):
        folder = self.root / "incoming"
        folder.mkdir()
        self.write_packet(1, name=folder / "a.jsonl")
        self.write_packet(3, name=folder / "b.jsonl")
        self.write_packet(2, [{"kind": "observation", "id": "sim-2",
                               "observed_at": "2026-10-28T12:01:00Z", "region": "north",
                               "latitude": 31.2, "longitude": 121.4, "confidence": "0.8",
                               "severity": 4, "source": "infrared"}], name=folder / "c.jsonl")
        results = ingest.ingest_directory(self.db, folder, self.authority, when=STAMP)
        self.assertEqual([item["status"] for item in results], ["accepted", "rejected", "accepted"])
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 2)
        self.assertEqual(store.counts(self.db)["quarantine"], 1)

    def test_stop_on_error_prevents_later_files(self):
        folder = self.root / "incoming"
        folder.mkdir()
        self.write_packet(2, name=folder / "a.jsonl")
        self.write_packet(1, name=folder / "b.jsonl")
        result = ingest.ingest_directory(self.db, folder, self.authority, stop_on_error=True, when=STAMP)
        self.assertEqual(len(result), 1)
        self.assertEqual(store.counts(self.db)["batches"], 0)

    def test_database_reopen_preserves_cursor_and_handoffs(self):
        self.ingest_signed(packet(), when=STAMP)
        self.db.close()
        reopened = store.open_database(self.db_path)
        self.db = reopened
        self.assertEqual(catalog.station(self.db, "sat-a")["committed_sequence"], 1)
        self.assertEqual(len(handoff.list_handoffs(self.db)), 1)
        authority = credentials.AdmissionAuthority(reopened, self.keystore)
        second = packet(2, [{"kind": "observation", "id": "sim-2",
                             "observed_at": "2026-10-28T12:01:00Z", "region": "north",
                             "latitude": 31.2, "longitude": 121.4, "confidence": "0.8",
                             "severity": 4, "source": "infrared"}])
        result = ingest.ingest_bytes(reopened, second, authority, sidecar=sign(second, keystore=self.keystore),
                                     when=STAMP)
        self.assertEqual(result.status, "accepted")

    def test_packet_created_in_future_is_rejected(self):
        raw = packet(created_at="2026-10-28T12:30:00Z")
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(raw, when=STAMP)
        self.assertEqual(error.exception.code, "packet_future")

    def test_packet_created_too_long_ago_is_rejected(self):
        raw = packet(created_at="2026-09-01T12:00:00Z")
        with self.assertRaises(ingest.IngestError) as error:
            self.ingest_signed(raw, when=STAMP)
        self.assertEqual(error.exception.code, "packet_stale")

    def test_source_file_missing_is_quarantined(self):
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_file(self.db, self.root / "missing.jsonl", self.authority, when=STAMP)
        self.assertEqual(error.exception.code, "source_unreadable")
        self.assertEqual(store.counts(self.db)["quarantine"], 1)

    def test_unsigned_packet_is_rejected_before_sequence_checks(self):
        file = self.write_packet(signed=False)
        with self.assertRaises(ingest.IngestError) as error:
            ingest.ingest_file(self.db, file, self.authority, when=STAMP)
        self.assertEqual(error.exception.code, "signature_missing")
        self.assertEqual(store.counts(self.db)["batches"], 0)
        self.assertEqual(store.counts(self.db)["quarantine"], 1)
        row = audit.list_quarantine(self.db)[0]
        self.assertIsNone(row["credential_id"])
