# 星地火情事件采集与交接网关

本项目供区域应急数据值守人员处理上游已经筛选的候选火情事件。输入为本地 JSONL 观测包；它不处理遥感影像，也不判断真实火情。仓库演示数据均为合成数据。

## 运行

使用 Python 3.11 或更新版本，无第三方依赖。先在项目根目录运行 `python -m orbitbridge demo --workspace /tmp/orbitbridge-demo`，可看到接收、重复导入、交接确认和来源核对结果。演示会重建指定目录中的 `demo.sqlite3`；请仅使用专门的演示目录。

真实本地包的命令顺序为：

```text
python -m orbitbridge --db work.sqlite3 --keystore keys.json keystore-init
python -m orbitbridge --db work.sqlite3 --keystore keys.json station-add sat-a "站点 A"
python -m orbitbridge --db work.sqlite3 --keystore keys.json subscribe north-watch forest-north --severity 3 --confidence 0.7
python -m orbitbridge --db work.sqlite3 --keystore keys.json credential-add sat-a sat-a-key-1 --seq-from 1
python -m orbitbridge --db work.sqlite3 --keystore keys.json sign-packet sat-a-key-1 packet.jsonl
python -m orbitbridge --db work.sqlite3 --keystore keys.json ingest packet.jsonl
python -m orbitbridge --db work.sqlite3 --keystore keys.json handoffs --status pending
python -m orbitbridge --db work.sqlite3 ack 1 "值守员甲"
python -m orbitbridge --db work.sqlite3 trace 1
python -m orbitbridge --db work.sqlite3 verify
```

## 站点验真与凭据轮换

正文摘要只能证明包内容未变，提交者身份由签名侧车证明。每个包必须与同目录的
`<包名>.sig.json` 成对出现；侧车为 schema 1 的 JSON，记录算法（固定 HMAC-SHA256）、
`credential_id`、站点、序号、正文摘要和 HMAC 签名，签名负载把站点、序号、包创建时间
与正文摘要全部绑定。无侧车、侧车与包身份不一致、签名验真失败的包在进入序号或去重
判断之前直接拒收并隔离（`signature_missing`、`signature_mismatch`、`signature_invalid`）。

秘密材料只保存在库外密钥库文件（`--keystore`，默认 `orbitbridge.keystore.json`），文件
强制 0600 权限；数据库只保存非秘密的 `credential_id` 与密钥指纹。活动审计、隔离记录和
交接导出中不会出现秘密材料，值守人员凭凭据标识和指纹即可核对接收与拒收结论。

凭据登记时必须明确适用范围：序号区间 `--seq-from/--seq-to`（截止可空表示开放）和时间
区间 `--valid-from/--valid-until`。所有效力判断以**网关接收时刻**为基准，包自称的
`created_at` 不能让已撤销或已过期的凭据重新获得接入资格；超出序号区间判
`credential_sequence_scope`，未生效/已过期判 `credential_not_yet_valid`/`credential_expired`，
撤销判 `credential_revoked`，均隔离且不推进游标。

`credential-rotate <站点> <新凭据>` 在一个事务内撤销该站点全部有效凭据（保留撤销时间与
原因）并登记新凭据，默认新凭据从当前游标下一个序号起适用。三类同序号情形处置不同：

- 旧凭据签的延迟包在撤销后到达：按 `credential_revoked` 隔离，与普通重放区分；
- 已经提交过的同一包：凭据仍有效时幂等返回 `duplicate`，凭据失效则拒收，不返回历史批次；
- 新凭据签出的同序号异内容包：按 `sequence_conflict` 隔离，历史批次冻结的凭据身份与指纹不变。

凭据只轮换不删除：`batches` 永久保存接收当时的 `credential_id` 与密钥指纹，
`verify`/`quality` 会核对指纹未漂移、凭据证据未丢失（`credential_fingerprint_drift`、
`credential_lost`、`batch_credential_missing`）。`credential-list` 与 `batch` 详情提供
非秘密身份核对视图，`credential-check <包>` 在不改数据库的前提下输出当前准入决定。

`recovery-plan`/`recovery-resume`/`quarantine-retry` 与 `manifest-run` 在执行前都会重新
运行当前准入决定，不能凭旧的“可恢复”计划绕过其间发生的撤销。计划因此失效时，阻塞条目
保留拒收原因（`admission_denied` + 准入码）和被阻塞的后续序号（`blocks_from`）。

包第一行为 `kind=packet`、`schema=1`、`station_id`、正整数 `sequence`、带时区 `created_at`、`record_count`、`digest`。后续每行是 `kind=observation`，包含 `id`、带时区 `observed_at`、`region`、`latitude`、`longitude`、`confidence`、1–5 的 `severity` 和 `source`。`source` 可为 `infrared`、`optical`、`thermal`。摘要是每条记录按键排序、紧凑 UTF-8 JSON 表示后追加换行的 SHA-256。可参考 `orbitbridge.protocol.encode_packet` 生成测试包。

同站点序号须连续。相同包重放返回 `duplicate`，相同序号不同内容或跳号进入隔离记录。所有观测和交接项在一个 SQLite 事务中提交；无匹配订阅的观测仍被保存。订阅规则只影响后续提交的包。`verify` 检查数据库、游标、批次数、交接来源与批次凭据证据。

可用 `inspect-packet` 或 `inspect-dir` 在不改数据库的情况下诊断待收件文件。目录中存在跳号时，先用 `recovery-plan sat-a incoming/` 查看可连续提交的包，再用 `recovery-resume sat-a incoming/` 按站点序号接收。`quarantine-retry <编号> <原文件>` 只允许重检与隔离记录身份一致的包。

清单是 UTF-8 JSON，含 schema、name 和 packets 数组；每个条目含 file、station_id、sequence 和文件 SHA-256。清单与包放在同一目录。`manifest-check <清单>` 预检摘要、包身份和游标，`manifest-run <清单>` 执行可连续提交的条目。执行时再次核对文件摘要。

`quality` 检查跨表不变量，`reconcile` 核对站点和订阅数量。`batch-report <编号>` 与 `day-report YYYY-MM-DD` 分别提供批次及日期统计。`export-handoffs <订阅编号> <新文件路径>` 导出交接来源并返回摘要，`export-check <文件路径> <摘要>` 校验文件。导出不会覆盖已有文件。

测试：`python -m unittest discover -s tests -v`。语法检查：`python -m compileall -q orbitbridge`。
