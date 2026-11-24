#!/usr/bin/env python3
"""
Windows 事件日志分析器 (Windows Event Log Analyzer)

读取 Windows 安全日志（.evtx 原始文件，或 wevtutil / 事件查看器导出的 XML），
找出值得关注的安全事件，并按时间排成一条时间线：

  1. 暴力破解：同一来源短时间内大量 4625 登录失败；
     失败之后紧跟同一来源的 4624 登录成功 → 疑似破解成功；
  2. 密码喷洒：同一来源短时间内尝试了很多个不同账户；
  3. 新建账户：4720；
  4. 加入特权组：4732 / 4728 / 4756（加入 Administrators、Domain Admins 等最严重）；
  5. 附带：1102 安全日志被清空、4726 账户被删除、4740 账户被锁定、
     7045 新安装服务、4624 远程桌面（RDP）登录。

分析逻辑只用标准库；读取 .evtx 文件需要 python-evtx（pip install -r requirements.txt），
读取 XML 导出文件则不需要任何第三方库。Python 3.8+。
"""

import argparse
import csv
import io
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

DEFAULT_THRESHOLD = 5      # 窗口内失败多少次算暴力破解
DEFAULT_WINDOW_MIN = 10    # 滑动窗口（分钟）
DEFAULT_SPRAY_USERS = 5    # 窗口内尝试多少个不同账户算密码喷洒

CRITICAL, WARNING, INFO = "critical", "warning", "info"
LEVEL_LABEL = {CRITICAL: "严重", WARNING: "警告", INFO: "提示"}
LEVEL_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
# 事件 ID → 应有的提供程序。别的程序也可能用同样的数字 ID，提供程序对不上就忽略。
EXPECTED_PROVIDER = {
    4624: SECURITY_PROVIDER, 4625: SECURITY_PROVIDER, 4720: SECURITY_PROVIDER,
    4726: SECURITY_PROVIDER, 4728: SECURITY_PROVIDER, 4732: SECURITY_PROVIDER,
    4740: SECURITY_PROVIDER, 4756: SECURITY_PROVIDER,
    1102: "Microsoft-Windows-Eventlog",
    7045: "Service Control Manager",
}
WATCHED_IDS = set(EXPECTED_PROVIDER)

LOGON_TYPES = {
    "2": "本地交互", "3": "网络", "4": "批处理", "5": "服务", "7": "解锁",
    "8": "网络明文", "9": "新凭据", "10": "远程桌面", "11": "缓存凭据",
}

# 4625 的失败原因码（Status / SubStatus）
FAILURE_STATUS = {
    "0xc000006a": "密码错误",
    "0xc0000064": "用户名不存在",
    "0xc000006d": "用户名或密码错误",
    "0xc0000234": "账户已锁定",
    "0xc0000072": "账户已禁用",
    "0xc000006f": "不在允许的登录时段",
    "0xc0000070": "不允许从此工作站登录",
    "0xc0000071": "密码已过期",
    "0xc0000193": "账户已过期",
    "0xc0000224": "下次登录须修改密码",
    "0xc0000133": "时钟不同步",
    "0xc000015b": "未被授予该登录类型",
    "0xc000005e": "当前没有登录服务器",
    "0xc0000413": "身份验证防火墙拒绝",
}

# 特权组：内置组 SID 是固定的，与系统语言无关；域组按 RID 结尾判断
PRIVILEGED_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
}
REMOTE_ACCESS_SIDS = {
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-580": "Remote Management Users",
}
PRIVILEGED_DOMAIN_RIDS = {"512": "Domain Admins", "518": "Schema Admins",
                          "519": "Enterprise Admins", "520": "Group Policy Creator Owners"}
PRIVILEGED_NAME_RE = re.compile(r"admin|管理员", re.I)

# 不当作“真人账户”的登录名
SYSTEM_ACCOUNTS = {"", "-", "system", "anonymous logon", "local service", "network service",
                   "dwm-1", "dwm-2", "dwm-3", "umfd-0", "umfd-1", "umfd-2", "umfd-3"}


class InputError(Exception):
    """输入文件读不了或格式不对。"""


# ---------------------------------------------------------------- 解析

def parse_time(text):
    """'2026-11-20T03:14:15.1234567Z' → aware datetime（UTC）。Windows 给 7 位小数，截到 6 位。"""
    if not text:
        return None
    t = text.strip().replace(" ", "T")
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$", t)
    if not m:
        return None
    base, frac, tz = m.groups()
    dt = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")
    if frac:
        dt = dt.replace(microsecond=int(frac[:6].ljust(6, "0")))
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        dt = dt - sign * timedelta(hours=hh, minutes=mm)
    return dt.replace(tzinfo=timezone.utc)


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _child(elem, name):
    for c in elem:
        if _local(c.tag) == name:
            return c
    return None


def parse_event_element(ev):
    """把一个 <Event> 元素变成扁平的 dict；不是有效事件时返回 None。"""
    system = _child(ev, "System")
    if system is None:
        return None
    eid_el = _child(system, "EventID")
    try:
        event_id = int((eid_el.text or "").strip())
    except (AttributeError, ValueError):
        return None
    provider_el = _child(system, "Provider")
    time_el = _child(system, "TimeCreated")
    rec_el = _child(system, "EventRecordID")
    data = {}
    event_data = _child(ev, "EventData")
    if event_data is not None:
        for i, d in enumerate(event_data):
            if _local(d.tag) != "Data":
                continue
            data[d.get("Name") or "Data%d" % i] = (d.text or "").strip()
    user_data = _child(ev, "UserData")
    if user_data is not None:  # 例如 1102 的 <UserData><LogFileCleared>...
        for leaf in user_data.iter():
            if len(leaf) == 0 and leaf is not user_data:
                data.setdefault(_local(leaf.tag), (leaf.text or "").strip())
    return {
        "event_id": event_id,
        "provider": provider_el.get("Name", "") if provider_el is not None else "",
        "time": parse_time(time_el.get("SystemTime") if time_el is not None else None),
        "computer": (_child(system, "Computer").text or "").strip()
        if _child(system, "Computer") is not None else "",
        "record_id": (rec_el.text or "").strip() if rec_el is not None else "",
        "data": data,
    }


def decode_bytes(raw):
    """XML 导出文件可能是 UTF-8 或 UTF-16（PowerShell 重定向默认 UTF-16）。"""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    if len(raw) >= 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        return raw.decode("utf-16-le")
    return raw.decode("utf-8-sig", errors="replace")


def parse_xml_text(text):
    """解析 XML 文本，返回事件列表。

    兼容三种导出格式：
      - 事件查看器「将所有事件另存为 XML」：<Events><Event>…</Event></Events>
      - wevtutil qe Security /f:xml：多个 <Event> 直接拼在一起，没有根元素
      - Get-WinEvent | ForEach-Object { $_.ToXml() }：同上
    """
    text = re.sub(r"<\?xml[^>]*\?>", "", text).strip()
    if not text:
        return []
    try:
        root = ET.fromstring("<Root>" + text + "</Root>")
    except ET.ParseError as e:
        raise InputError("XML 解析失败: %s" % e)
    events = []
    for el in root.iter():
        if _local(el.tag) == "Event":
            ev = parse_event_element(el)
            if ev:
                events.append(ev)
    return events


def read_evtx(path):
    """用 python-evtx 读取 .evtx，返回 (事件列表, 解析失败的记录数)。"""
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        raise InputError("读取 .evtx 需要 python-evtx：pip install -r requirements.txt"
                         "（或者先在 Windows 上导出为 XML 再分析）")
    events, bad = [], 0
    try:
        with Evtx(path) as log:
            for record in log.records():
                try:
                    el = ET.fromstring(record.xml())
                except Exception:
                    bad += 1
                    continue
                ev = parse_event_element(el)
                if ev:
                    events.append(ev)
    except InputError:
        raise
    except Exception as e:
        raise InputError("无法读取 %s: %s" % (path, e))
    return events, bad


def load_file(path):
    """按内容判断格式（.evtx 文件头是 'ElfFile\\0'），返回 (事件列表, 坏记录数)。"""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise InputError("无法读取 %s: %s" % (path, e.strerror or e))
    if raw.startswith(b"ElfFile\x00"):
        return read_evtx(path)
    return parse_xml_text(decode_bytes(raw)), 0


def is_relevant(ev):
    if ev["event_id"] not in WATCHED_IDS:
        return False
    want = EXPECTED_PROVIDER[ev["event_id"]]
    return not ev["provider"] or ev["provider"].lower() == want.lower()


# ---------------------------------------------------------------- 小工具

def account(data, user_key="TargetUserName", domain_key="TargetDomainName"):
    user = data.get(user_key, "") or "-"
    domain = data.get(domain_key, "")
    return "%s\\%s" % (domain, user) if domain and domain != "-" else user


def is_real_user(name):
    n = (name or "").strip().lower()
    return n not in SYSTEM_ACCOUNTS and not n.endswith("$")


def failure_source(data):
    """4625 的“来源”：优先远程 IP，其次工作站名，都没有就是本机。"""
    ip = data.get("IpAddress", "")
    if ip and ip not in ("-", "::1", "127.0.0.1"):
        return ip
    ws = data.get("WorkstationName", "")
    if ws and ws != "-":
        return "工作站 " + ws
    return "本机"


def failure_reason(data):
    status = (data.get("Status") or "").lower()
    sub = (data.get("SubStatus") or "").lower()
    code = sub if status == "0xc000006d" and sub and sub != "0x0" else (status or sub)
    return FAILURE_STATUS.get(code, code or "未知")


def group_privilege(data):
    """返回 (等级, 说明)：加入的组有多危险。"""
    sid = (data.get("TargetSid") or "").upper()
    name = data.get("TargetUserName", "")
    if sid in PRIVILEGED_SIDS:
        return CRITICAL, "特权组 " + PRIVILEGED_SIDS[sid]
    rid = sid.rsplit("-", 1)[-1] if sid.startswith("S-1-5-21-") else ""
    if rid in PRIVILEGED_DOMAIN_RIDS:
        return CRITICAL, "特权组 " + PRIVILEGED_DOMAIN_RIDS[rid]
    if PRIVILEGED_NAME_RE.search(name):
        return CRITICAL, "疑似特权组（组名含 admin/管理员）"
    if sid in REMOTE_ACCESS_SIDS:
        return WARNING, "远程访问组 " + REMOTE_ACCESS_SIDS[sid]
    return INFO, "普通组"


def member_label(data, sid_names=None):
    """被加入组的成员。本地组里 MemberName 常常是 '-'，只有 SID；
    如果同一份日志里有这个 SID 的 4720 建号事件，就能把名字对上。"""
    name = data.get("MemberName", "")
    sid = data.get("MemberSid", "") or "-"
    if name and name != "-":
        m = re.match(r"(?i)CN=([^,]+)", name)
        return m.group(1) if m else name
    known = (sid_names or {}).get(sid.upper())
    return "%s（%s）" % (known, sid) if known else sid


def max_window(items, window):
    """items 按时间排好序；返回任意 window 时长内事件最多的那一段（列表）。"""
    best, start = [], 0
    for end in range(len(items)):
        while items[end]["time"] - items[start]["time"] > window:
            start += 1
        if end - start + 1 > len(best):
            best = items[start:end + 1]
    return best


def max_distinct_users_window(items, window):
    """返回任意 window 时长内尝试过的不同账户最多的那一段。"""
    best, best_n, start = [], 0, 0
    counts = Counter()
    for end in range(len(items)):
        counts[items[end]["data"].get("TargetUserName", "").lower()] += 1
        while items[end]["time"] - items[start]["time"] > window:
            u = items[start]["data"].get("TargetUserName", "").lower()
            counts[u] -= 1
            if counts[u] == 0:
                del counts[u]
            start += 1
        if len(counts) > best_n:
            best_n, best = len(counts), items[start:end + 1]
    return best


def _top(counter, n=5):
    parts = ["%s×%d" % (k, v) for k, v in counter.most_common(n)]
    if len(counter) > n:
        parts[-1] += " 等 %d 个" % len(counter)
    return "、".join(parts)


# ---------------------------------------------------------------- 分析

def analyze(events, threshold=DEFAULT_THRESHOLD, window_min=DEFAULT_WINDOW_MIN,
            spray_users=DEFAULT_SPRAY_USERS, since=None, until=None):
    """events: parse_event_element() 的结果列表。返回 {'stats', 'findings', 'timeline'}。"""
    window = timedelta(minutes=window_min)
    evs = [e for e in events if e["time"] is not None and is_relevant(e)]
    if since:
        evs = [e for e in evs if e["time"] >= since]
    if until:
        evs = [e for e in evs if e["time"] <= until]
    # 同一个文件被传两次、或多个导出有重叠时去重
    seen, unique = set(), []
    for e in sorted(evs, key=lambda e: e["time"]):
        key = (e["computer"], e["record_id"], e["event_id"], e["time"]) if e["record_id"] else None
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        unique.append(e)
    evs = unique

    findings, timeline = [], []

    def add(level, title, detail, time, related=None):
        findings.append({"level": level, "title": title, "detail": detail,
                         "time": time, "events": related or []})

    # ---- 1/2. 4625 暴力破解 + 密码喷洒，按来源分组
    failures = defaultdict(list)
    for e in evs:
        if e["event_id"] == 4625:
            failures[failure_source(e["data"])].append(e)
    successes = [e for e in evs if e["event_id"] == 4624 and is_real_user(e["data"].get("TargetUserName"))]
    flagged_sources = set()

    for src, items in sorted(failures.items()):
        burst = max_window(items, window)
        spray = max_distinct_users_window(items, window)
        spray_n = len({x["data"].get("TargetUserName", "").lower() for x in spray})
        users = Counter(account(x["data"]) for x in items)
        reasons = Counter(failure_reason(x["data"]) for x in items)
        ltypes = Counter(LOGON_TYPES.get(x["data"].get("LogonType", ""), x["data"].get("LogonType", "?"))
                         for x in items)
        info = "共 %d 次失败；账户: %s；原因: %s；登录类型: %s" % (
            len(items), _top(users), _top(reasons), _top(ltypes))
        span = {"first": items[0]["time"], "last": items[-1]["time"]}

        sprayed = spray_n >= spray_users
        if sprayed:
            flagged_sources.add(src)
            add(WARNING, "疑似密码喷洒：%s 在 %d 分钟内尝试了 %d 个不同账户" % (src, window_min, spray_n),
                info, spray[0]["time"], [_ref(x) for x in spray])
            findings[-1].update(span)
        # 已经报了喷洒的来源，只有当同一个账户也被反复尝试时才再报暴力破解
        per_user = max(Counter(x["data"].get("TargetUserName", "").lower() for x in burst).values(), default=0)
        if len(burst) >= threshold and (not sprayed or per_user >= threshold):
            flagged_sources.add(src)
            add(WARNING, "疑似暴力破解：%s 在 %d 分钟内登录失败 %d 次" % (src, window_min, len(burst)),
                info, burst[0]["time"], [_ref(x) for x in burst])
            findings[-1].update(span)

        # 失败之后，同一 IP 用被尝试过的账户登录成功了
        if src in flagged_sources and not src.startswith(("工作站 ", "本机")):
            tried = {x["data"].get("TargetUserName", "").lower() for x in items}
            first, last = items[0]["time"], items[-1]["time"]
            for s in successes:
                d = s["data"]
                if (d.get("IpAddress") == src and first <= s["time"] <= last + window
                        and d.get("TargetUserName", "").lower() in tried):
                    add(CRITICAL, "疑似暴力破解成功：%s 多次失败后以 %s 登录成功" % (src, account(d)),
                        "登录类型: %s；登录前该来源共失败 %d 次" % (
                            LOGON_TYPES.get(d.get("LogonType", ""), d.get("LogonType", "?")),
                            sum(1 for x in items if x["time"] <= s["time"])),
                        s["time"], [_ref(s)])
                    s["_after_bruteforce"] = True
                    break

    # ---- 3/4/5. 单条事件
    sid_names = {e["data"].get("TargetSid", "").upper(): account(e["data"])
                 for e in evs if e["event_id"] in (4720, 4726) and e["data"].get("TargetSid")}
    for e in evs:
        d, eid = e["data"], e["event_id"]
        actor = account(d, "SubjectUserName", "SubjectDomainName")
        if eid == 4720:
            add(WARNING, "新建账户 %s" % account(d), "操作者: %s；账户 SID: %s" % (actor, d.get("TargetSid", "-")),
                e["time"], [_ref(e)])
        elif eid in (4732, 4728, 4756):
            level, kind = group_privilege(d)
            scope = {4732: "本地组", 4728: "全局组", 4756: "通用组"}[eid]
            add(level, "%s 被加入%s %s" % (member_label(d, sid_names), scope, account(d)),
                "%s；操作者: %s" % (kind, actor), e["time"], [_ref(e)])
        elif eid == 1102:
            add(CRITICAL, "安全日志被清空", "操作者: %s（攻击者常用来掩盖痕迹）" % actor, e["time"], [_ref(e)])
        elif eid == 4726:
            add(INFO, "账户 %s 被删除" % account(d), "操作者: %s" % actor, e["time"], [_ref(e)])
        elif eid == 4740:
            add(INFO, "账户 %s 被锁定" % d.get("TargetUserName", "-"),
                "锁定来源计算机: %s" % (d.get("TargetDomainName") or "-"), e["time"], [_ref(e)])
        elif eid == 7045:
            add(WARNING, "新安装服务 %s" % d.get("ServiceName", "-"),
                "程序: %s；运行账户: %s；启动类型: %s" % (d.get("ImagePath", "-"), d.get("AccountName", "-"),
                                                     d.get("StartType", "-")), e["time"], [_ref(e)])

    # ---- 时间线
    timeline = build_timeline(evs, flagged_sources, sid_names)

    stats = {
        "events_total": len(events),
        "events_relevant": len(evs),
        "by_id": dict(sorted(Counter(e["event_id"] for e in evs).items())),
        "first": evs[0]["time"] if evs else None,
        "last": evs[-1]["time"] if evs else None,
        "computers": sorted({e["computer"] for e in evs if e["computer"]}),
    }
    findings.sort(key=lambda f: (LEVEL_ORDER[f["level"]], f["time"]))
    return {"stats": stats, "findings": findings, "timeline": timeline}


def _ref(e):
    return {"event_id": e["event_id"], "time": e["time"], "record_id": e["record_id"],
            "computer": e["computer"]}


def describe(e, sid_names=None):
    """时间线上一条事件的一句话描述（4625 由 build_timeline 合并处理）。"""
    d, eid = e["data"], e["event_id"]
    actor = account(d, "SubjectUserName", "SubjectDomainName")
    if eid == 4624:
        lt = LOGON_TYPES.get(d.get("LogonType", ""), d.get("LogonType", "?"))
        return "登录成功 %s（%s，来源 %s）" % (account(d), lt, d.get("IpAddress", "-") or "-")
    if eid == 4720:
        return "新建账户 %s（操作者 %s）" % (account(d), actor)
    if eid in (4732, 4728, 4756):
        return "%s 加入组 %s（操作者 %s）" % (member_label(d, sid_names), account(d), actor)
    if eid == 4726:
        return "删除账户 %s（操作者 %s）" % (account(d), actor)
    if eid == 4740:
        return "账户 %s 被锁定" % d.get("TargetUserName", "-")
    if eid == 1102:
        return "安全日志被清空（操作者 %s）" % actor
    if eid == 7045:
        return "安装服务 %s: %s" % (d.get("ServiceName", "-"), d.get("ImagePath", "-"))
    return "事件 %d" % eid


def build_timeline(evs, flagged_sources=(), sid_names=None):
    """按时间排列的值得关注的事件。

    - 连续的、同一来源的 4625 合并成一行（否则几千条失败会把时间线淹没）；
    - 4624 只收录远程桌面登录，以及暴力破解之后的那次成功登录；
    - 其他关注的事件全部收录。
    """
    out = []
    for e in evs:
        eid, d = e["event_id"], e["data"]
        if eid == 4625:
            src = failure_source(d)
            last = out[-1] if out else None
            if last and last["event_id"] == 4625 and last["source"] == src:
                last["count"] += 1
                last["end"] = e["time"]
                last["users"].add(account(d))
                continue
            out.append({"time": e["time"], "end": e["time"], "event_id": 4625, "source": src,
                        "count": 1, "users": {account(d)}, "flagged": src in flagged_sources})
            continue
        if eid == 4624:
            remote_rdp = d.get("LogonType") == "10"
            if not (remote_rdp or e.get("_after_bruteforce")) or not is_real_user(d.get("TargetUserName")):
                continue
        out.append({"time": e["time"], "event_id": eid, "text": describe(e, sid_names),
                    "flagged": bool(e.get("_after_bruteforce"))})
    for item in out:
        if item["event_id"] == 4625:
            users = sorted(item.pop("users"))
            shown = "、".join(users[:3]) + (" 等 %d 个账户" % len(users) if len(users) > 3 else "")
            item["text"] = "来自 %s 的登录失败 ×%d（%s）" % (item["source"], item["count"], shown)
    return out


# ---------------------------------------------------------------- 输出

def fmt_time(dt, utc=False):
    if dt is None:
        return "-"
    if utc:
        return dt.strftime("%Y-%m-%d %H:%M:%S") + "Z"
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def format_report(result, utc=False, show_timeline=True, timeline_limit=200):
    st, lines = result["stats"], []
    lines.append("读取事件 %d 条，其中关注的 %d 条（%s 至 %s）" % (
        st["events_total"], st["events_relevant"], fmt_time(st["first"], utc), fmt_time(st["last"], utc)))
    if st["computers"]:
        lines.append("计算机: " + "、".join(st["computers"]))
    if st["by_id"]:
        lines.append("事件分布: " + "  ".join("%d×%d" % (k, v) for k, v in st["by_id"].items()))
    lines.append("")

    findings = result["findings"]
    if findings:
        lines.append("== 发现 ==")
        for f in findings:
            icon = {CRITICAL: "❌", WARNING: "⚠️ ", INFO: "ℹ️ "}[f["level"]]
            lines.append("%s [%s] %s  %s" % (icon, LEVEL_LABEL[f["level"]], fmt_time(f["time"], utc), f["title"]))
            detail = f["detail"]
            if "first" in f:
                detail = "%s 至 %s，%s" % (fmt_time(f["first"], utc), fmt_time(f["last"], utc), detail)
            lines.append("      " + detail)
        lines.append("")

    if show_timeline and result["timeline"]:
        tl = result["timeline"]
        lines.append("== 时间线 ==")
        for item in tl[:timeline_limit]:
            mark = "!" if item.get("flagged") else " "
            lines.append("%s %s  %-5d %s" % (mark, fmt_time(item["time"], utc), item["event_id"], item["text"]))
        if len(tl) > timeline_limit:
            lines.append("  …还有 %d 条，用 --timeline-limit 0 显示全部或 --csv 导出" % (len(tl) - timeline_limit))
        lines.append("")

    counts = Counter(f["level"] for f in findings)
    if not findings:
        lines.append("✅ 没有发现可疑事件。")
    else:
        icon = "❌" if counts[CRITICAL] else ("⚠️ " if counts[WARNING] else "ℹ️ ")
        lines.append("%s 严重 %d 条，警告 %d 条，提示 %d 条。" % (
            icon, counts[CRITICAL], counts[WARNING], counts[INFO]))
    return "\n".join(lines)


def _jsonable(obj):
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(type(obj))


def to_json(result):
    out = {"stats": result["stats"], "findings": result["findings"], "timeline": result["timeline"]}
    return json.dumps(out, ensure_ascii=False, indent=2, default=_jsonable)


def to_csv(timeline, utc=False):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "end", "event_id", "count", "flagged", "description"])
    for item in timeline:
        w.writerow([fmt_time(item["time"], utc), fmt_time(item.get("end"), utc) if item.get("end") else "",
                    item["event_id"], item.get("count", 1), "yes" if item.get("flagged") else "", item["text"]])
    return buf.getvalue()


# ---------------------------------------------------------------- 命令行

def parse_cli_time(text):
    """--since / --until：2026-11-20、2026-11-20T08:00:00（本机时区），或带 Z / +08:00。"""
    t = text.strip().replace(" ", "T")
    if re.match(r"^\d{4}-\d{2}-\d{2}$", t):
        t += "T00:00:00"
    if re.search(r"(Z|[+-]\d{2}:?\d{2})$", t):
        dt = parse_time(t)
    else:
        try:
            dt = datetime.strptime(t, "%Y-%m-%dT%H:%M:%S").astimezone().astimezone(timezone.utc)
        except ValueError:
            dt = None
    if dt is None:
        raise argparse.ArgumentTypeError("时间格式应为 2026-11-20、2026-11-20T08:00:00 或 2026-11-20T00:00:00Z")
    return dt


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="分析 Windows 安全日志（.evtx 或 XML 导出），找出暴力破解、新建账户、加入管理员组等事件并生成时间线。")
    parser.add_argument("files", nargs="+", help=".evtx 文件，或 wevtutil / 事件查看器导出的 .xml")
    parser.add_argument("-t", "--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help="窗口内同一来源登录失败多少次算暴力破解（默认 %d）" % DEFAULT_THRESHOLD)
    parser.add_argument("-w", "--window", type=int, default=DEFAULT_WINDOW_MIN,
                        help="滑动窗口分钟数（默认 %d）" % DEFAULT_WINDOW_MIN)
    parser.add_argument("--spray-users", type=int, default=DEFAULT_SPRAY_USERS,
                        help="窗口内同一来源尝试多少个不同账户算密码喷洒（默认 %d）" % DEFAULT_SPRAY_USERS)
    parser.add_argument("--since", type=parse_cli_time, help="只看这个时间之后（本机时区，或带 Z / +08:00）")
    parser.add_argument("--until", type=parse_cli_time, help="只看这个时间之前")
    parser.add_argument("--utc", action="store_true", help="用 UTC 显示时间（默认本机时区）")
    parser.add_argument("--no-timeline", action="store_true", help="不打印时间线，只看发现")
    parser.add_argument("--timeline-limit", type=int, default=200, help="时间线最多打印多少行（0 = 不限，默认 200）")
    parser.add_argument("--csv", metavar="PATH", help="把时间线导出为 CSV（- 表示标准输出）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    if args.threshold < 1 or args.window < 1 or args.spray_users < 2:
        parser.error("--threshold、--window 至少为 1，--spray-users 至少为 2")

    events = []
    for path in args.files:
        try:
            evs, bad = load_file(path)
        except InputError as e:
            print("错误: %s" % e, file=sys.stderr)
            return 2
        if bad:
            print("提示: %s 中有 %d 条记录解析失败，已跳过" % (path, bad), file=sys.stderr)
        events.extend(evs)

    result = analyze(events, threshold=args.threshold, window_min=args.window,
                     spray_users=args.spray_users, since=args.since, until=args.until)

    if args.csv:
        data = to_csv(result["timeline"], args.utc)
        if args.csv == "-":
            sys.stdout.write(data)
        else:
            with open(args.csv, "w", encoding="utf-8-sig", newline="") as f:  # 带 BOM，Excel 打开不乱码
                f.write(data)
    if args.json:
        print(to_json(result))
    elif args.csv != "-":
        limit = args.timeline_limit if args.timeline_limit > 0 else len(result["timeline"])
        print(format_report(result, utc=args.utc, show_timeline=not args.no_timeline, timeline_limit=limit))

    return 1 if any(f["level"] in (CRITICAL, WARNING) for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
