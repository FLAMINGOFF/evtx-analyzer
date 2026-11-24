# Windows 事件日志分析器 (Windows Event Log Analyzer)

[English](README.md) | **简体中文**

一个小巧的 Python 命令行工具，读取 Windows **安全日志**（原始 `.evtx` 文件，或者用
`wevtutil` / 事件查看器导出的 XML），找出应急响应时最先要看的那些事件，并排成一条**时间线**：

1. **暴力破解**：同一来源短时间内大量 `4625` 登录失败；最严重的情况是紧接着出现同一来源的
   `4624` 登录成功。
2. **密码喷洒**：同一来源短时间内尝试了很多个*不同*的账户。
3. **新建账户**：`4720`。
4. **组成员变更**：`4732` / `4728` / `4756`。加入 Administrators、Domain Admins 这类特权组为
   严重，加入 Remote Desktop Users 为警告。
5. **附带检查**：`1102` 安全日志被清空、`4726` 账户被删除、`4740` 账户被锁定、
   `7045` 新安装服务、`4624` 远程桌面登录。

分析逻辑只用标准库。读取 `.evtx` 需要
[python-evtx](https://github.com/williballenthin/python-evtx)；读取 XML 导出文件什么都不需要。
Python 3.8+。macOS / Linux / Windows 都能跑，分析从 Windows 机器上拷出来的日志不需要 Windows。

## 安装

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt                       # python-evtx，只有读 .evtx 时才需要
```

## 用法

```bash
python3 evtx_analyzer.py Security.evtx
python3 evtx_analyzer.py examples/sample-security.xml          # 用自带的样例试一下
python3 evtx_analyzer.py a.evtx b.evtx exported.xml             # 多个文件合并分析并去重
python3 evtx_analyzer.py Security.evtx -t 10 -w 5               # 5 分钟内失败 10 次才算暴力破解
python3 evtx_analyzer.py Security.evtx --since 2026-11-20 --until 2026-11-21T12:00:00
python3 evtx_analyzer.py Security.evtx --no-timeline            # 只看发现
python3 evtx_analyzer.py Security.evtx --csv timeline.csv       # 时间线导出给 Excel
python3 evtx_analyzer.py Security.evtx --json                   # 机器可读
python3 evtx_analyzer.py Security.evtx --utc                    # 用 UTC 显示时间（默认本机时区）

python3 -m unittest -v                                          # 离线测试
```

### 从 Windows 机器上导出日志

在**管理员** PowerShell / cmd 里执行：

```powershell
wevtutil epl Security C:\temp\Security.evtx        # 原始日志副本（.evtx）
wevtutil epl System   C:\temp\System.evtx          # 7045「安装服务」在 System 日志里
# 或者导出为 XML，分析端就不需要 python-evtx：
wevtutil qe Security /f:xml > C:\temp\Security.xml
```

也可以用事件查看器 → Windows 日志 → 安全 → *将所有事件另存为…*（`.evtx` 或 `.xml`）。
UTF-8 和 UTF-16 编码的 XML 都能读。

## 示例

分析 [`examples/sample-security.xml`](examples/sample-security.xml) 的输出。这是一段虚构的攻击：
对 `Administrator` 暴力破解、登录成功、建后门账户并加入 Administrators、装可疑服务、清空日志：

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

时间线里的 `!` 表示这条事件属于某个暴力破解发现。

| 等级 | 触发条件 |
|---|---|
| 严重 | 暴力破解之后同一 IP 登录成功；加入 Administrators / Account、Server、Backup、Print Operators / Domain、Schema、Enterprise Admins（或组名含 "admin" / "管理员" 的组）；安全日志被清空（1102） |
| 警告 | 同一来源 10 分钟内失败 ≥ 5 次；同一来源 10 分钟内尝试 ≥ 5 个不同账户；新建账户（4720）；加入 Remote Desktop Users / Remote Management Users；新安装服务（7045） |
| 提示 | 加入普通组；账户被删除（4726）；账户被锁定（4740） |

| 退出码 | 含义 |
|---|---|
| `0` | 没有警告或严重问题（只有提示也算正常） |
| `1` | 至少有一条警告或严重（方便定时任务判断） |
| `2` | 参数错误、文件读不了或 XML 损坏 |

## 工作原理

```
.evtx ──python-evtx──► 每条记录转 XML ─┐
.xml（wevtutil / 事件查看器）──────────┴─► 解析 <Event>：EventID、时间、计算机、
                                            EventData / UserData 字段
        ▼
 只保留关注的事件 ID 且提供程序匹配（Security-Auditing、Eventlog、Service Control Manager）
 按 --since/--until 过滤，按时间排序，按（计算机, EventRecordID）去重
        ▼
 4625 按来源分组（IP，没有就用工作站名）
   ├─ 滑动窗口：任意 N 分钟内的最多失败次数      ≥ 阈值        → 暴力破解
   ├─ 滑动窗口：任意 N 分钟内的最多不同账户数    ≥ spray-users → 密码喷洒
   └─ 同一 IP、被尝试过的账户、在最后一次失败 + 窗口之前的 4624 → 严重
 4720 / 4732 / 4728 / 4756 / 1102 / 4726 / 4740 / 7045 → 每条一个发现
        ▼
 时间线（同一来源连续的 4625 合并成一行）→ 文本 / JSON / CSV
```

### 设计说明

- **用滑动窗口，不用固定时间段。** 09:58 到 10:02 的 30 次失败，按 10 分钟切段
  （09:50–10:00、10:00–10:10）会被劈成两半。双指针滑动窗口能在 O(n) 内找出整份日志里
  最密集的那 N 分钟。
- **来源 = `IpAddress`，没有就用 `WorkstationName`。** 网络登录（类型 3、10）会带攻击者 IP。
  有些 NTLM 失败只带客户端工作站名，这个名字攻击者可以随便改，但用来分组仍然有用。
- **喷洒和暴力破解分开。** 密码喷洒是对很多账户各试一两个密码，躲开锁定策略。如果一个
  来源已经报了喷洒，只有当其中某一个账户也被试了 ≥ 阈值次时才再报暴力破解，免得同一次
  攻击出现两遍。
- **按 SID 识别组，不按组名。** 内置组名会随系统语言变化（德文系统叫 `Administratoren`），
  但 `S-1-5-32-544` 永远是 Administrators。域组按 RID 判断（`-512` Domain Admins、`-519`
  Enterprise Admins…）。组名匹配只是兜底。
- **尽量把成员 SID 翻译成账户名。** 本地组的 `4732` 里 `MemberName` 通常是 `-`。如果同一份
  日志里有创建这个 SID 的 `4720`，就把账户名显示在 SID 旁边。
- **检查提供程序。** 事件 ID 只在同一个提供程序内唯一，别的程序也可能记一条 4720；只有来自
  预期提供程序的事件才计入。
- **时间线保持可读。** 真实日志里有成千上万条 `4625` 和几万条 `4624`。同一来源连续的失败
  合并成一行；登录成功只收录远程桌面登录，以及暴力破解之后那次。
- **离线测试。** 测试里的事件是按 Windows 导出格式手写的 XML 字符串；`.evtx` 读取路径用
  一个假的 `Evtx` 模块替身来测，所以测试既不需要 Windows，也不需要 python-evtx。

## 局限

- **没开审核的事件不会出现在日志里。** `4625` 需要开启「审核登录 → 失败」，组变更需要
  「审核安全组管理」。不同 Windows 版本和组策略默认值不同，可以用 `auditpol /get /category:*` 查看。
- **不是完整的检测引擎。** 不分析 Kerberos（域控上的 `4768`/`4771`）、`4688` 进程创建、
  PowerShell / Sysmon 日志，也不检测横向移动。这些请用真正的 Sigma 规则（见下）。
- **python-evtx 处理大文件很慢**（纯 Python，一份完整的安全日志可能要几分钟）。几个 GB 的日志
  可以先导出一段时间：
  `wevtutil qe Security /q:"*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:xml`。
- **被清空的日志找不回来。** 1102 只能告诉你发生过清空，那份文件里清空前的记录已经没了。
- **NAT / 代理会把来源合并**（很多用户共用一个出口 IP 看起来像一个攻击者），而慢速轮换 IP
  的攻击者可以一直低于阈值。
- 时间取自 `TimeCreated/@SystemTime`（UTC），默认按本机时区显示，加 `--utc` 显示 UTC。

## 业界同类工具

[Hayabusa](https://github.com/Yamato-Security/hayabusa)、
[Chainsaw](https://github.com/WithSecureLabs/chainsaw)、
[DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)、
[APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter)，以及运行
[Sigma](https://github.com/SigmaHQ/sigma) 规则的 Splunk / Elastic / Microsoft Sentinel 等 SIEM。
本项目是同一思路的学习版。
