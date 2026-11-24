# Windows Event Log Analyzer

**English** | [简体中文](README.zh-CN.md)

A small Python CLI that reads Windows **Security event logs** (raw `.evtx` files, or XML
exported with `wevtutil` / Event Viewer), flags the events an incident responder looks at
first, and puts them on a **timeline**:

1. **Brute force**: one source with many `4625` logon failures in a short window, and the
   critical case: a `4624` successful logon from that same source right afterwards.
2. **Password spraying**: one source trying many *different* accounts in a short window.
3. **New accounts**: `4720`.
4. **Group membership changes**: `4732` / `4728` / `4756`. Adding someone to Administrators,
   Domain Admins and the like is critical; Remote Desktop Users is a warning.
5. **Also tracked**: `1102` security log cleared, `4726` account deleted, `4740` account
   locked out, `7045` new service installed, `4624` Remote Desktop logons.

The analysis is standard library only. Reading `.evtx` needs
[python-evtx](https://github.com/williballenthin/python-evtx); reading XML exports needs
nothing. Python 3.8+. Runs on macOS / Linux / Windows; you don't need Windows to analyze
a log copied off a Windows machine.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt                       # python-evtx, only needed for .evtx
```

## Usage

```bash
python3 evtx_analyzer.py Security.evtx
python3 evtx_analyzer.py examples/sample-security.xml          # try it with the sample
python3 evtx_analyzer.py a.evtx b.evtx exported.xml             # several files, merged + de-duplicated
python3 evtx_analyzer.py Security.evtx -t 10 -w 5               # 10 failures within 5 min = brute force
python3 evtx_analyzer.py Security.evtx --since 2026-11-20 --until 2026-11-21T12:00:00
python3 evtx_analyzer.py Security.evtx --no-timeline            # findings only
python3 evtx_analyzer.py Security.evtx --csv timeline.csv       # timeline for Excel
python3 evtx_analyzer.py Security.evtx --json                   # machine-readable
python3 evtx_analyzer.py Security.evtx --utc                    # show times in UTC (default: local)

python3 -m unittest -v                                          # offline tests
```

### Getting the log off a Windows machine

Run in an **administrator** PowerShell / cmd:

```powershell
wevtutil epl Security C:\temp\Security.evtx        # copy of the raw log (.evtx)
wevtutil epl System   C:\temp\System.evtx          # 7045 "service installed" lives here
# or as XML, no python-evtx needed on the analysis side:
wevtutil qe Security /f:xml > C:\temp\Security.xml
```

Event Viewer → Windows Logs → Security → *Save All Events As…* (`.evtx` or `.xml`) works too.
UTF-8 and UTF-16 XML files are both accepted.

## Example

Output for [`examples/sample-security.xml`](examples/sample-security.xml), a made-up attack:
RDP/SMB brute force against `Administrator`, a successful logon, a backdoor account added to
Administrators, a suspicious service, and the log being cleared (the CLI prints in Chinese):

```
读取事件 52 条，其中关注的 52 条（2026-11-20 01:00:00Z 至 2026-11-20 02:32:20Z）
计算机: WS01.corp.local
事件分布: 1102×1  4624×2  4625×44  4720×1  4732×2  4740×1  7045×1

== 发现 ==
❌ [严重] 2026-11-20 02:04:05Z  疑似暴力破解成功：203.0.113.45 多次失败后以 WS01\Administrator 登录成功
      登录类型: 网络；登录前该来源共失败 30 次
❌ [严重] 2026-11-20 02:07:15Z  WS01\svc-backup（S-1-5-21-111-222-333-1005） 被加入本地组 Builtin\Administrators
      特权组 Administrators；操作者: WS01\Administrator
❌ [严重] 2026-11-20 02:17:05Z  安全日志被清空
      操作者: WS01\Administrator（攻击者常用来掩盖痕迹）
⚠️  [警告] 2026-11-20 02:00:00Z  疑似暴力破解：203.0.113.45 在 10 分钟内登录失败 30 次
      2026-11-20 02:00:00Z 至 2026-11-20 02:03:52Z，共 30 次失败；账户: WS01\Administrator×30；原因: 密码错误×30；登录类型: 网络×30
⚠️  [警告] 2026-11-20 02:07:05Z  新建账户 WS01\svc-backup
      操作者: WS01\Administrator；账户 SID: S-1-5-21-111-222-333-1005
⚠️  [警告] 2026-11-20 02:08:05Z  新安装服务 WinUpdateHelper
      程序: C:\Users\Public\upd.exe；运行账户: LocalSystem；启动类型: auto start
⚠️  [警告] 2026-11-20 02:30:00Z  疑似密码喷洒：198.51.100.7 在 10 分钟内尝试了 8 个不同账户
      …

== 时间线 ==
! 2026-11-20 02:00:00Z  4625  来自 203.0.113.45 的登录失败 ×30（WS01\Administrator）
! 2026-11-20 02:04:05Z  4624  登录成功 WS01\Administrator（网络，来源 203.0.113.45）
  2026-11-20 02:07:05Z  4720  新建账户 WS01\svc-backup（操作者 WS01\Administrator）
  2026-11-20 02:07:15Z  4732  WS01\svc-backup（S-1-5-21-111-222-333-1005） 加入组 Builtin\Administrators（操作者 WS01\Administrator）
  2026-11-20 02:08:05Z  7045  安装服务 WinUpdateHelper: C:\Users\Public\upd.exe
  2026-11-20 02:17:05Z  1102  安全日志被清空（操作者 WS01\Administrator）
  …

❌ 严重 3 条，警告 6 条，提示 1 条。
```

`发现` = findings, `时间线` = timeline, `严重 / 警告 / 提示` = critical / warning / info,
`登录失败` = logon failure, `被加入…组` = added to group, `操作者` = done by.
A `!` in the timeline marks events that belong to a brute-force finding.

| Level | Raised for |
|---|---|
| critical | Successful logon right after a brute-force burst from the same IP; added to Administrators / Account, Server, Backup, Print Operators / Domain, Schema, Enterprise Admins (or any group whose name contains "admin" / "管理员"); security log cleared (1102) |
| warning | ≥ 5 failures from one source within 10 min; ≥ 5 different accounts tried from one source within 10 min; new account (4720); added to Remote Desktop Users / Remote Management Users; new service (7045) |
| info | Added to an ordinary group; account deleted (4726); account locked out (4740) |

| Exit code | Meaning |
|---|---|
| `0` | No warnings or critical findings (info is fine) |
| `1` | At least one warning or critical finding (handy for scheduled scans) |
| `2` | Bad arguments, unreadable file, or broken XML |

## How it works

```
.evtx ──python-evtx──► XML per record ─┐
.xml (wevtutil / Event Viewer) ────────┴─► parse <Event>: EventID, time, Computer,
                                            EventData / UserData fields
        ▼
 keep watched IDs whose Provider matches (Security-Auditing, Eventlog, Service Control Manager)
 filter --since/--until, sort by time, drop duplicate (Computer, EventRecordID)
        ▼
 4625 grouped by source (IP, else workstation name)
   ├─ sliding window: max failures in any N minutes   ≥ threshold   → brute force
   ├─ sliding window: max distinct accounts           ≥ spray-users → password spray
   └─ 4624 from same IP, for a tried account, before last failure + window → critical
 4720 / 4732 / 4728 / 4756 / 1102 / 4726 / 4740 / 7045 → one finding each
        ▼
 timeline (consecutive 4625 from one source collapsed into one line) → text / JSON / CSV
```

### Design notes

- **Sliding window, not fixed buckets.** 30 failures from 09:58 to 10:02 would be split by
  10-minute buckets (09:50–10:00, 10:00–10:10). A two-pointer sliding window finds the
  busiest N-minute stretch anywhere in the log in O(n).
- **Source = `IpAddress`, falling back to `WorkstationName`.** Network logons (type 3, 10)
  carry the attacker's IP. Some NTLM failures only carry the client's workstation name,
  which is attacker-controlled but still useful for grouping.
- **Spray vs. brute force.** Spraying tries one or two passwords on many accounts to stay
  under lockout thresholds. If a source is already reported as spraying, it's only also
  reported as brute force when a single account was hit ≥ threshold times, so one attack
  doesn't show up twice.
- **Groups are identified by SID, not name.** Built-in group names are translated
  (`Administrators` is `Administratoren` in German Windows), but `S-1-5-32-544` is always
  Administrators. Domain groups are matched by RID (`-512` Domain Admins, `-519`
  Enterprise Admins…). The name check is only a fallback.
- **Member SIDs are resolved when possible.** In `4732` for local groups, `MemberName` is
  usually `-`. If the same log has the `4720` that created that SID, the account name is
  shown next to it.
- **Provider check.** Event IDs are only unique per provider. An application could log its
  own event 4720; only events from the expected provider are counted.
- **Timeline stays readable.** Real logs have thousands of `4625` and tens of thousands of
  `4624`. Consecutive failures from the same source collapse into one line, and successful
  logons appear only for Remote Desktop or right after a brute-force burst.
- **Offline tests.** Events are built as XML strings in the same shape Windows exports.
  The `.evtx` path is tested with a stand-in for the `Evtx` module, so the tests need
  neither Windows nor python-evtx.

## Limitations

- **Only what was audited is in the log.** `4625` needs "Audit Logon → Failure", and group
  changes need "Audit Security Group Management". Defaults differ between Windows editions
  and Group Policy; check `auditpol /get /category:*`.
- **Not a full detection engine.** No Kerberos (`4768`/`4771` for domain controllers),
  no `4688` process creation, no PowerShell / Sysmon logs, no lateral movement detection.
  For that, use real Sigma rules (see below).
- **python-evtx is slow on big files** (it's pure Python; a full-size Security log can take
  minutes). For a multi-GB log, export a time range with
  `wevtutil qe Security /q:"*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:xml`.
- **A cleared log can't be recovered.** Event 1102 tells you it happened; everything
  before it in that file is gone.
- **NAT / proxies merge sources** (many users behind one IP look like one attacker), and
  an attacker rotating IPs slowly can stay under any threshold.
- Times are taken from `TimeCreated/@SystemTime` (UTC) and shown in your local time zone
  unless you pass `--utc`.

## Real-world equivalents

[Hayabusa](https://github.com/Yamato-Security/hayabusa),
[Chainsaw](https://github.com/WithSecureLabs/chainsaw),
[DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI),
[APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter), and SIEMs like Splunk / Elastic /
Microsoft Sentinel running [Sigma](https://github.com/SigmaHQ/sigma) rules. This project is a
learning-sized version of the same idea.
