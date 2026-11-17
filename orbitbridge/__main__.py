"""命令行入口：本地批次采集和交接核对。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import (audit, catalog, credentials, diagnostics, export, handoff, ingest, intake, protocol, quality,
               reconcile, recovery, store)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="orbitbridge", description="星地火情事件采集与交接网关")
    root.add_argument("--db", default="orbitbridge.sqlite3", help="SQLite 数据文件")
    root.add_argument("--keystore", default="orbitbridge.keystore.json",
                      help="库外密钥库路径（仅存秘密材料，0600 权限）")
    commands = root.add_subparsers(dest="command", required=True)
    station = commands.add_parser("station-add", help="登记观测站")
    station.add_argument("station_id")
    station.add_argument("label")
    state = commands.add_parser("station-state", help="变更站点状态")
    state.add_argument("station_id")
    state.add_argument("state", choices=("active", "inactive"))
    credential_add = commands.add_parser("credential-add", help="为站点登记验真凭据并生成秘密材料")
    credential_add.add_argument("station_id")
    credential_add.add_argument("credential_id")
    credential_add.add_argument("--seq-from", type=int, default=1)
    credential_add.add_argument("--seq-to", type=int)
    credential_add.add_argument("--valid-from")
    credential_add.add_argument("--valid-until")
    commands.add_parser("keystore-init", help="初始化库外密钥库（已存在则报错，不覆盖）")
    credential_rotate = commands.add_parser("credential-rotate", help="撤销站点现有有效凭据并签发新凭据")
    credential_rotate.add_argument("station_id")
    credential_rotate.add_argument("new_credential_id")
    credential_rotate.add_argument("--reason", required=True)
    credential_rotate.add_argument("--seq-from", type=int)
    credential_rotate.add_argument("--seq-to", type=int)
    credential_rotate.add_argument("--valid-from")
    credential_rotate.add_argument("--valid-until")
    credential_revoke = commands.add_parser("credential-revoke", help="撤销指定凭据（历史批次仍保留其身份）")
    credential_revoke.add_argument("credential_id")
    credential_revoke.add_argument("--reason", required=True)
    commands.add_parser("credential-list", help="列出凭据的非秘密身份与适用范围")
    sign_packet = commands.add_parser("sign-packet", help="用凭据为离线包生成 .sig.json 签名侧车")
    sign_packet.add_argument("credential_id")
    sign_packet.add_argument("packet")
    credential_check = commands.add_parser("credential-check", help="核对单个包在当前时刻的准入决定")
    credential_check.add_argument("packet")
    subscription = commands.add_parser("subscribe", help="登记区域订阅")
    subscription.add_argument("subscription_id")
    subscription.add_argument("region")
    subscription.add_argument("--severity", type=int, default=1)
    subscription.add_argument("--confidence", default="0")
    substate = commands.add_parser("subscription-state", help="变更订阅状态")
    substate.add_argument("subscription_id")
    substate.add_argument("state", choices=("active", "inactive"))
    packet = commands.add_parser("ingest", help="导入单个观测包")
    packet.add_argument("packet")
    directory = commands.add_parser("ingest-dir", help="按文件名导入目录中的 JSONL")
    directory.add_argument("directory")
    directory.add_argument("--stop-on-error", action="store_true")
    queue = commands.add_parser("handoffs", help="查看交接队列")
    queue.add_argument("--subscription")
    queue.add_argument("--status", choices=("pending", "acknowledged"))
    queue.add_argument("--limit", type=int, default=100)
    queue.add_argument("--after", type=int, default=0)
    acknowledgement = commands.add_parser("ack", help="确认交接项")
    acknowledgement.add_argument("handoff_id", type=int)
    acknowledgement.add_argument("operator")
    batch = commands.add_parser("batch", help="查看批次来源")
    batch.add_argument("batch_id", type=int)
    observation = commands.add_parser("observation", help="查看观测来源")
    observation.add_argument("observation_id", type=int)
    quarantine = commands.add_parser("quarantine", help="查看隔离项")
    quarantine.add_argument("--station")
    summary = commands.add_parser("summary", help="计数和完整性核对")
    trace = commands.add_parser("trace", help="查看交接来源与活动")
    trace.add_argument("handoff_id", type=int)
    report = commands.add_parser("region-report", help="查看区域统计")
    report.add_argument("region")
    commands.add_parser("verify", help="检查数据库与来源链")
    station_plan = commands.add_parser("recovery-plan", help="查看站点目录恢复计划")
    station_plan.add_argument("station_id")
    station_plan.add_argument("directory")
    station_resume = commands.add_parser("recovery-resume", help="从已提交游标继续导入")
    station_resume.add_argument("station_id")
    station_resume.add_argument("directory")
    retry = commands.add_parser("quarantine-retry", help="重检已隔离的原始包")
    retry.add_argument("quarantine_id", type=int)
    retry.add_argument("packet")
    commands.add_parser("quality", help="检查跨表业务不变量")
    station_quality = commands.add_parser("station-quality", help="查看站点拒收原因")
    station_quality.add_argument("station_id")
    commands.add_parser("quarantine-quality", help="汇总隔离原因")
    packet_inspect = commands.add_parser("inspect-packet", help="预诊断单个观测包")
    packet_inspect.add_argument("packet")
    directory_inspect = commands.add_parser("inspect-dir", help="预诊断观测包目录")
    directory_inspect.add_argument("directory")
    commands.add_parser("reconcile", help="核对站点与订阅数量")
    batch_report = commands.add_parser("batch-report", help="核对单批次的观测与交接")
    batch_report.add_argument("batch_id", type=int)
    day_report = commands.add_parser("day-report", help="查看接收日期汇总")
    day_report.add_argument("day")
    manifest_check = commands.add_parser("manifest-check", help="预检批次清单")
    manifest_check.add_argument("manifest")
    manifest_check.add_argument("--strict", action="store_true")
    manifest_run = commands.add_parser("manifest-run", help="执行批次清单")
    manifest_run.add_argument("manifest")
    manifest_run.add_argument("--strict", action="store_true")
    handoff_export = commands.add_parser("export-handoffs", help="导出交接清单")
    handoff_export.add_argument("subscription_id")
    handoff_export.add_argument("destination")
    handoff_export.add_argument("--after", type=int, default=0)
    handoff_export.add_argument("--through", type=int)
    handoff_export.add_argument("--status", choices=("pending", "acknowledged"))
    export_check = commands.add_parser("export-check", help="校验导出文件")
    export_check.add_argument("path")
    export_check.add_argument("sha256")
    demo = commands.add_parser("demo", help="运行本地合成数据演示")
    demo.add_argument("--workspace", default="./demo-workspace")
    return root


def _demo(workspace: Path) -> dict[str, Any]:
    workspace.mkdir(parents=True, exist_ok=True)
    database = workspace / "demo.sqlite3"
    if database.exists():
        database.unlink()
    keystore_path = workspace / "demo.keystore.json"
    if keystore_path.exists():
        keystore_path.unlink()
    for stale in workspace.glob("*.sig.json"):
        stale.unlink()
    connection = store.open_database(database)
    try:
        keystore = credentials.KeyStore.create(keystore_path)
        catalog.register_station(connection, "sat-a", "合成观测站 A", when="2026-10-28T12:00:00Z")
        catalog.register_subscription(connection, "forest-watch", "forest-north", 3, "0.70",
                                      when="2026-10-28T12:00:00Z")
        first = credentials.register_credential(connection, keystore, "sat-a", "sat-a-key-1",
                                                seq_from=1, seq_to=1, when="2026-10-28T12:00:00Z")
        authority = credentials.AdmissionAuthority(connection, keystore)
        records = [
            {"kind": "observation", "id": "sim-001", "observed_at": "2026-10-28T12:00:00Z",
             "region": "forest-north", "latitude": 31.20, "longitude": 121.45, "confidence": "0.88",
             "severity": 4, "source": "infrared"},
            {"kind": "observation", "id": "sim-002", "observed_at": "2026-10-28T12:01:00Z",
             "region": "forest-north", "latitude": 31.21, "longitude": 121.46, "confidence": "0.55",
             "severity": 2, "source": "thermal"},
        ]
        packet = protocol.encode_packet("sat-a", 1, "2026-10-28T12:02:00Z", records)
        source = workspace / "synthetic-packet.jsonl"
        source.write_bytes(packet)
        credentials.write_sidecar(
            source, credentials.build_signature(protocol.parse_packet_bytes(packet), "sat-a-key-1",
                                                keystore.secret("sat-a-key-1")))
        accepted = ingest.ingest_file(connection, source, authority, when="2026-10-28T12:03:00Z")
        duplicate = ingest.ingest_file(connection, source, authority, when="2026-10-28T12:03:01Z")
        # 轮换：旧凭据撤销；新凭据覆盖序号 1 起，便于演示同序号冲突的独立处置。
        rotated = credentials.rotate_credential(connection, keystore, "sat-a", "sat-a-key-2",
                                                reason="例行轮换", seq_from=1,
                                                when="2026-10-28T12:05:00Z")
        # 旧凭据签的延迟包：撤销后拒收并隔离，包自称的创建时间不能复活旧凭据。
        late = workspace / "late-packet.jsonl"
        late.write_bytes(packet)
        credentials.write_sidecar(
            late, credentials.build_signature(protocol.parse_packet_bytes(packet), "sat-a-key-1",
                                               keystore.secret("sat-a-key-1")))
        try:
            ingest.ingest_file(connection, late, authority, when="2026-10-28T12:06:00Z")
        except ingest.IngestError as exc:
            late_outcome = exc.as_dict()
        else:  # pragma: no cover - 防御性断言
            raise RuntimeError("已撤销凭据的延迟包必须被拒收")
        # 新凭据签出的同序号异内容冲突包：隔离且历史批次凭据证据不变。
        conflict_records = [{"kind": "observation", "id": "sim-009", "observed_at": "2026-10-28T12:00:00Z",
                             "region": "forest-north", "latitude": 31.20, "longitude": 121.45,
                             "confidence": "0.90", "severity": 4, "source": "optical"}]
        conflict = protocol.encode_packet("sat-a", 1, "2026-10-28T12:02:00Z", conflict_records)
        conflict_path = workspace / "conflict-packet.jsonl"
        conflict_path.write_bytes(conflict)
        credentials.write_sidecar(
            conflict_path, credentials.build_signature(protocol.parse_packet_bytes(conflict), "sat-a-key-2",
                                                        keystore.secret("sat-a-key-2")))
        try:
            ingest.ingest_file(connection, conflict_path, authority, when="2026-10-28T12:07:00Z")
        except ingest.IngestError as exc:
            conflict_outcome = exc.as_dict()
        else:  # pragma: no cover
            raise RuntimeError("同序号异内容包必须被隔离")
        queue = handoff.list_handoffs(connection)
        if len(queue) != 1 or accepted.handoff_count != 1 or duplicate.status != "duplicate":
            raise RuntimeError("合成演示结果与交接预期不符")
        if late_outcome["code"] != "credential_revoked" or conflict_outcome["code"] != "sequence_conflict":
            raise RuntimeError("合成演示凭据处置结果不符")
        ack = handoff.acknowledge(connection, queue[0]["handoff_id"], "值守员甲",
                                  when="2026-10-28T12:08:00Z")
        trace = audit.handoff_trace(connection, queue[0]["handoff_id"])
        issues = audit.verify_lineage(connection)
        if issues or trace["handoff"]["batch_id"] != accepted.batch_id:
            raise RuntimeError(f"合成演示来源链不一致：{issues}")
        batch_view = audit.batch_credential_view(connection, accepted.batch_id)
        if batch_view["credential_id"] != "sat-a-key-1" or not batch_view["fingerprint_unchanged"]:
            raise RuntimeError("历史批次的接收当时验真依据未被保留")
        # 密钥库本身不进入数据库审计计数与导出；活动流只含非秘密身份。
        return {"accepted": accepted.as_dict(), "duplicate": duplicate.as_dict(),
                "rotated_credential": {key: rotated[key] for key in
                                       ("credential_id", "status", "seq_from", "valid_from")},
                "late_rejection": late_outcome, "conflict_rejection": conflict_outcome,
                "handoff": ack, "batch_credential": batch_view,
                "counts": store.counts(connection), "integrity_issues": issues}
    finally:
        connection.close()


def dispatch(args: argparse.Namespace) -> Any:
    if args.command == "demo":
        return _demo(Path(args.workspace))
    connection = store.open_database(args.db)
    try:
        if args.command == "station-add":
            return catalog.register_station(connection, args.station_id, args.label)
        if args.command == "station-state":
            return catalog.set_station_active(connection, args.station_id, args.state == "active")
        if args.command == "keystore-init":
            keystore = credentials.KeyStore.create(args.keystore)
            return {"keystore": str(Path(args.keystore)), "created": True, "mode": "0600"}
        if args.command == "credential-add":
            keystore = credentials.KeyStore.open(args.keystore)
            return credentials.register_credential(
                connection, keystore, args.station_id, args.credential_id,
                seq_from=args.seq_from, seq_to=args.seq_to,
                valid_from=args.valid_from, valid_until=args.valid_until)
        if args.command == "credential-rotate":
            keystore = credentials.KeyStore.open(args.keystore)
            return credentials.rotate_credential(
                connection, keystore, args.station_id, args.new_credential_id, reason=args.reason,
                seq_from=args.seq_from, seq_to=args.seq_to,
                valid_from=args.valid_from, valid_until=args.valid_until)
        if args.command == "credential-revoke":
            return credentials.revoke_credential(connection, args.credential_id, args.reason)
        if args.command == "credential-list":
            return credentials.list_credentials(connection)
        if args.command == "sign-packet":
            keystore = credentials.KeyStore.open(args.keystore)
            packet = protocol.parse_packet_file(args.packet)
            secret = keystore.secret(args.credential_id)
            if secret is None:
                raise credentials.CredentialError("key_material_missing", "密钥库缺少该凭据的秘密材料")
            target = credentials.write_sidecar(
                args.packet, credentials.build_signature(packet, args.credential_id, secret))
            return {"sidecar": str(target), "credential_id": args.credential_id,
                    "source_name": packet.source_name}
        if args.command == "credential-check":
            keystore = credentials.KeyStore.open(args.keystore)
            authority = credentials.AdmissionAuthority(connection, keystore)
            return diagnostics.inspect_packet(connection, args.packet, authority)
        authority = credentials.AdmissionAuthority(connection, credentials.KeyStore.open(args.keystore))
        if args.command == "subscribe":
            return catalog.register_subscription(connection, args.subscription_id, args.region,
                                                 args.severity, args.confidence)
        if args.command == "subscription-state":
            return catalog.set_subscription_active(connection, args.subscription_id, args.state == "active")
        if args.command == "ingest":
            return ingest.ingest_file(connection, args.packet, authority).as_dict()
        if args.command == "ingest-dir":
            return ingest.ingest_directory(connection, args.directory, authority,
                                           stop_on_error=args.stop_on_error)
        if args.command == "handoffs":
            return handoff.list_handoffs(connection, subscription_id=args.subscription, status=args.status,
                                         limit=args.limit, after_id=args.after)
        if args.command == "ack":
            return handoff.acknowledge(connection, args.handoff_id, args.operator)
        if args.command == "batch":
            return audit.batch_detail(connection, args.batch_id)
        if args.command == "observation":
            return audit.observation_detail(connection, args.observation_id)
        if args.command == "quarantine":
            return audit.list_quarantine(connection, station_id=args.station)
        if args.command == "summary":
            return audit.summary(connection)
        if args.command == "trace":
            return audit.handoff_trace(connection, args.handoff_id)
        if args.command == "region-report":
            return audit.region_report(connection, args.region)
        if args.command == "verify":
            issues = audit.verify_lineage(connection)
            return {"ok": not issues, "issues": issues}
        if args.command == "recovery-plan":
            return recovery.plan_station(connection, args.station_id, args.directory, authority)
        if args.command == "recovery-resume":
            return recovery.resume_station(connection, args.station_id, args.directory, authority)
        if args.command == "quarantine-retry":
            return recovery.retry_file(connection, args.quarantine_id, args.packet, authority)
        if args.command == "quality":
            return quality.check_all(connection)
        if args.command == "station-quality":
            return quality.station_quality(connection, args.station_id)
        if args.command == "quarantine-quality":
            return quality.quarantine_quality(connection)
        if args.command == "inspect-packet":
            return diagnostics.inspect_packet(connection, args.packet, authority)
        if args.command == "inspect-dir":
            return diagnostics.inspect_directory(connection, args.directory, authority)
        if args.command == "reconcile":
            return reconcile.full_reconciliation(connection)
        if args.command == "batch-report":
            return reconcile.batch_counts(connection, args.batch_id)
        if args.command == "day-report":
            return reconcile.day_counts(connection, args.day)
        if args.command == "manifest-check":
            return intake.preflight(connection, args.manifest, strict=args.strict, authority=authority)
        if args.command == "manifest-run":
            return intake.execute_manifest(connection, args.manifest, strict=args.strict, authority=authority)
        if args.command == "export-handoffs":
            return export.export_handoffs(connection, args.subscription_id, args.destination,
                                          start_id=args.after, end_id=args.through, status=args.status).as_dict()
        if args.command == "export-check":
            return export.verify_export(args.path, args.sha256)
        raise RuntimeError("未知命令")
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = dispatch(args)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        if args.command in {"verify", "quality", "reconcile"} and not result["ok"]:
            return 2
        return 0
    except (catalog.CatalogError, handoff.HandoffError, ingest.IngestError, audit.AuditError, recovery.RecoveryError,
            intake.ManifestError, export.ExportError, reconcile.ReconcileError,
            credentials.CredentialError) as exc:
        print(json.dumps({"error": getattr(exc, "code", "error"), "message": str(exc),
                          "quarantine_id": getattr(exc, "quarantine_id", None)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
