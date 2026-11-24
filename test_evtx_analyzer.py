"""离线测试：不需要 Windows，也不需要 python-evtx。运行: python3 -m unittest -v

事件用手写的 XML 构造（和 Windows 导出的格式一致）；.evtx 读取路径用一个
假的 Evtx 模块替身来测。
"""
import io
import json
import os
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone

import evtx_analyzer as ea

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "examples", "sample-security.xml")
T0 = datetime(2026, 11, 20, 2, 0, 0, tzinfo=timezone.utc)
_rid = [0]


def xml_event(eid, t, data=None, provider=ea.SECURITY_PROVIDER, computer="WS01", record_id=None):
    if record_id is None:
        _rid[0] += 1
        record_id = _rid[0]
    body = "".join('<Data Name="%s">%s</Data>' % (k, v) for k, v in (data or {}).items())
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            '<Provider Name="%s"/><EventID Qualifiers="0">%d</EventID>'
            '<TimeCreated SystemTime="%s"/><EventRecordID>%s</EventRecordID>'
            '<Computer>%s</Computer></System><EventData>%s</EventData></Event>') % (
        provider, eid, t.strftime("%Y-%m-%dT%H:%M:%S.%f0Z"), record_id, computer, body)


def fail(t, user="Administrator", ip="203.0.113.45", **kw):
    d = {"TargetUserName": user, "TargetDomainName": "WS01", "Status": "0xc000006d",
         "SubStatus": "0xc000006a", "LogonType": "3", "IpAddress": ip, "WorkstationName": "-"}
    d.update(kw)
    return xml_event(4625, t, d)


def success(t, user="Administrator", ip="203.0.113.45", logon_type="3"):
    return xml_event(4624, t, {"TargetUserName": user, "TargetDomainName": "WS01",
                               "LogonType": logon_type, "IpAddress": ip})


def events(*xmls):
    return ea.parse_xml_text("".join(xmls))


def titles(result, level=None):
    return [f["title"] for f in result["findings"] if level is None or f["level"] == level]


class TestParsing(unittest.TestCase):
    def test_parse_time_seven_digits(self):
        dt = ea.parse_time("2026-11-20T03:14:15.1234567Z")
        self.assertEqual(dt, datetime(2026, 11, 20, 3, 14, 15, 123456, tzinfo=timezone.utc))

    def test_parse_time_offset(self):
        self.assertEqual(ea.parse_time("2026-11-20T08:00:00+08:00"), datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc))
        self.assertIsNone(ea.parse_time("garbage"))
        self.assertIsNone(ea.parse_time(None))

    def test_event_fields(self):
        [e] = events(fail(T0, ip="1.2.3.4"))
        self.assertEqual(e["event_id"], 4625)
        self.assertEqual(e["computer"], "WS01")
        self.assertEqual(e["data"]["IpAddress"], "1.2.3.4")
        self.assertEqual(e["time"], T0)

    def test_concatenated_events_without_root(self):
        # wevtutil qe /f:xml 的输出：没有根元素
        self.assertEqual(len(events(fail(T0), fail(T0), success(T0))), 3)

    def test_wrapped_events_with_declaration(self):
        text = '<?xml version="1.0" encoding="UTF-8"?>\n<Events>%s%s</Events>' % (fail(T0), fail(T0))
        self.assertEqual(len(ea.parse_xml_text(text)), 2)

    def test_userdata_1102(self):
        xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
               '<Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID>'
               '<TimeCreated SystemTime="2026-11-20T02:00:00.000Z"/></System>'
               '<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
               '<SubjectUserName>mallory</SubjectUserName><SubjectDomainName>WS01</SubjectDomainName>'
               '</LogFileCleared></UserData></Event>')
        [e] = events(xml)
        self.assertEqual(e["data"]["SubjectUserName"], "mallory")
        r = ea.analyze([e])
        self.assertEqual(titles(r, ea.CRITICAL), ["安全日志被清空"])
        self.assertIn("WS01\\mallory", r["findings"][0]["detail"])

    def test_bad_xml(self):
        with self.assertRaises(ea.InputError):
            ea.parse_xml_text("<Event><System>")

    def test_utf16_file(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".xml", delete=False) as f:
            f.write(("<Events>%s</Events>" % fail(T0)).encode("utf-16"))
        try:
            evs, bad = ea.load_file(f.name)
            self.assertEqual((len(evs), bad), (1, 0))
        finally:
            os.unlink(f.name)


class TestBruteForce(unittest.TestCase):
    def test_threshold(self):
        below = events(*[fail(T0 + timedelta(seconds=i)) for i in range(4)])
        self.assertEqual(titles(ea.analyze(below)), [])
        at = events(*[fail(T0 + timedelta(seconds=i)) for i in range(5)])
        self.assertEqual(titles(ea.analyze(at)), ["疑似暴力破解：203.0.113.45 在 10 分钟内登录失败 5 次"])

    def test_window_is_sliding(self):
        # 每 3 分钟一次，任何 10 分钟窗口里最多 4 次 → 不算
        slow = events(*[fail(T0 + timedelta(minutes=3 * i)) for i in range(10)])
        self.assertEqual(titles(ea.analyze(slow)), [])
        # 窗口放宽到 15 分钟 → 6 次
        self.assertEqual(titles(ea.analyze(slow, window_min=15)),
                         ["疑似暴力破解：203.0.113.45 在 15 分钟内登录失败 6 次"])

    def test_sources_counted_separately(self):
        evs = events(*[fail(T0, ip="10.0.0.%d" % i) for i in range(10)])
        self.assertEqual(titles(ea.analyze(evs)), [])

    def test_success_after_failures_is_critical(self):
        evs = events(*[fail(T0 + timedelta(seconds=i)) for i in range(6)],
                     success(T0 + timedelta(minutes=1)))
        r = ea.analyze(evs)
        self.assertEqual(titles(r, ea.CRITICAL),
                         ["疑似暴力破解成功：203.0.113.45 多次失败后以 WS01\\Administrator 登录成功"])
        flagged = [i for i in r["timeline"] if i["event_id"] == 4624]
        self.assertTrue(flagged and flagged[0]["flagged"])

    def test_success_from_other_ip_or_user_is_not_linked(self):
        base = [fail(T0 + timedelta(seconds=i)) for i in range(6)]
        r1 = ea.analyze(events(*base, success(T0 + timedelta(minutes=1), ip="10.9.9.9")))
        r2 = ea.analyze(events(*base, success(T0 + timedelta(minutes=1), user="alice")))
        r3 = ea.analyze(events(*base, success(T0 + timedelta(hours=2))))  # 太晚
        for r in (r1, r2, r3):
            self.assertEqual(titles(r, ea.CRITICAL), [])

    def test_password_spray(self):
        users = ["u%d" % i for i in range(6)]
        r = ea.analyze(events(*[fail(T0 + timedelta(seconds=i), user=u) for i, u in enumerate(users)]))
        # 只报喷洒，不重复报“暴力破解”
        self.assertEqual(titles(r), ["疑似密码喷洒：203.0.113.45 在 10 分钟内尝试了 6 个不同账户"])

    def test_failure_reason_uses_substatus(self):
        self.assertEqual(ea.failure_reason({"Status": "0xC000006D", "SubStatus": "0xC0000064"}), "用户名不存在")
        self.assertEqual(ea.failure_reason({"Status": "0xc0000234", "SubStatus": "0x0"}), "账户已锁定")

    def test_failure_source(self):
        self.assertEqual(ea.failure_source({"IpAddress": "1.2.3.4"}), "1.2.3.4")
        self.assertEqual(ea.failure_source({"IpAddress": "-", "WorkstationName": "KALI"}), "工作站 KALI")
        self.assertEqual(ea.failure_source({"IpAddress": "127.0.0.1"}), "本机")


class TestAccountEvents(unittest.TestCase):
    def test_new_account(self):
        r = ea.analyze(events(xml_event(4720, T0, {"TargetUserName": "backdoor", "TargetDomainName": "WS01",
                                                    "TargetSid": "S-1-5-21-1-2-3-1009",
                                                    "SubjectUserName": "admin", "SubjectDomainName": "WS01"})))
        self.assertEqual(titles(r, ea.WARNING), ["新建账户 WS01\\backdoor"])

    def group_add(self, sid, name, eid=4732, **kw):
        d = {"MemberName": "-", "MemberSid": "S-1-5-21-1-2-3-1009", "TargetUserName": name,
             "TargetDomainName": "Builtin", "TargetSid": sid, "SubjectUserName": "admin"}
        d.update(kw)
        return xml_event(eid, T0 + timedelta(seconds=5), d)

    def test_admin_group_is_critical_by_sid(self):
        # 中文/德文系统组名不一样，但 SID 固定
        r = ea.analyze(events(self.group_add("S-1-5-32-544", "Administratoren")))
        self.assertEqual(r["findings"][0]["level"], ea.CRITICAL)

    def test_domain_admins_by_rid(self):
        r = ea.analyze(events(self.group_add("S-1-5-21-9-9-9-512", "Domain Admins", eid=4728,
                                             MemberName="CN=eve,CN=Users,DC=corp,DC=local")))
        self.assertEqual(titles(r, ea.CRITICAL), ["eve 被加入全局组 Builtin\\Domain Admins"])

    def test_rdp_group_is_warning_and_plain_group_info(self):
        r = ea.analyze(events(self.group_add("S-1-5-32-555", "Remote Desktop Users"),
                              self.group_add("S-1-5-21-1-2-3-2001", "Marketing")))
        levels = sorted(f["level"] for f in r["findings"])
        self.assertEqual(levels, [ea.INFO, ea.WARNING])

    def test_member_sid_resolved_from_4720(self):
        r = ea.analyze(events(xml_event(4720, T0, {"TargetUserName": "backdoor", "TargetDomainName": "WS01",
                                                    "TargetSid": "S-1-5-21-1-2-3-1009"}),
                              self.group_add("S-1-5-32-544", "Administrators")))
        self.assertIn("WS01\\backdoor（S-1-5-21-1-2-3-1009） 被加入本地组 Builtin\\Administrators",
                      titles(r, ea.CRITICAL))

    def test_provider_mismatch_ignored(self):
        r = ea.analyze(events(xml_event(4720, T0, {"TargetUserName": "x"}, provider="SomeApp")))
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["stats"]["events_relevant"], 0)


class TestTimelineAndFilters(unittest.TestCase):
    def test_failures_collapsed(self):
        evs = events(*[fail(T0 + timedelta(seconds=i)) for i in range(20)],
                     fail(T0 + timedelta(seconds=30), ip="9.9.9.9"))
        tl = ea.analyze(evs)["timeline"]
        self.assertEqual([(i["source"], i["count"]) for i in tl], [("203.0.113.45", 20), ("9.9.9.9", 1)])
        self.assertTrue(tl[0]["flagged"])
        self.assertFalse(tl[1]["flagged"])

    def test_ordinary_logons_not_in_timeline(self):
        tl = ea.analyze(events(success(T0, user="alice", logon_type="3"),
                               success(T0, user="WS01$", logon_type="10"),
                               success(T0, user="bob", logon_type="10")))["timeline"]
        self.assertEqual(len(tl), 1)
        self.assertIn("bob", tl[0]["text"])

    def test_since_until(self):
        evs = events(*[fail(T0 + timedelta(hours=h)) for h in range(5)])
        r = ea.analyze(evs, since=T0 + timedelta(hours=1), until=T0 + timedelta(hours=3))
        self.assertEqual(r["stats"]["events_relevant"], 3)

    def test_duplicate_records_removed(self):
        x = xml_event(4720, T0, {"TargetUserName": "dup"}, record_id=77)
        r = ea.analyze(events(x, x))
        self.assertEqual(len(r["findings"]), 1)

    def test_out_of_order_input(self):
        xs = [fail(T0 + timedelta(seconds=i)) for i in range(6)]
        r = ea.analyze(events(*reversed(xs)))
        self.assertEqual(len(titles(r, ea.WARNING)), 1)


class TestSample(unittest.TestCase):
    def test_sample_file(self):
        evs, _ = ea.load_file(SAMPLE)
        r = ea.analyze(evs)
        crit = titles(r, ea.CRITICAL)
        self.assertEqual(len(crit), 3)
        self.assertTrue(any("暴力破解成功" in t for t in crit))
        self.assertTrue(any("Administrators" in t for t in crit))
        self.assertIn("安全日志被清空", crit)
        self.assertTrue(any("密码喷洒" in t for t in titles(r, ea.WARNING)))
        # 时间线按时间排序
        times = [i["time"] for i in r["timeline"]]
        self.assertEqual(times, sorted(times))


class TestEvtxReading(unittest.TestCase):
    """用假的 Evtx.Evtx 模块测试 .evtx 读取路径（真正的解析交给 python-evtx）。"""

    def setUp(self):
        records = [fail(T0), "<not xml", success(T0)]

        class FakeRecord:
            def __init__(self, x):
                self.x = x

            def xml(self):
                return self.x

        class FakeEvtx:
            def __init__(self, path):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def records(self):
                return [FakeRecord(x) for x in records]

        pkg = types.ModuleType("Evtx")
        mod = types.ModuleType("Evtx.Evtx")
        mod.Evtx = FakeEvtx
        pkg.Evtx = mod
        self.saved = {k: sys.modules.get(k) for k in ("Evtx", "Evtx.Evtx")}
        sys.modules["Evtx"], sys.modules["Evtx.Evtx"] = pkg, mod
        fd, self.path = tempfile.mkstemp(suffix=".evtx")
        os.write(fd, b"ElfFile\x00" + b"\x00" * 100)
        os.close(fd)

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
        os.unlink(self.path)

    def test_reads_records_and_counts_bad(self):
        evs, bad = ea.load_file(self.path)
        self.assertEqual([e["event_id"] for e in evs], [4625, 4624])
        self.assertEqual(bad, 1)

    def test_missing_library(self):
        sys.modules["Evtx"] = None  # 让 import 失败
        sys.modules["Evtx.Evtx"] = None
        with self.assertRaises(ea.InputError) as cm:
            ea.load_file(self.path)
        self.assertIn("python-evtx", str(cm.exception))


class TestCLI(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = ea.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_text_report(self):
        code, out, _ = self.run_cli(SAMPLE, "--utc")
        self.assertEqual(code, 1)
        self.assertIn("== 发现 ==", out)
        self.assertIn("== 时间线 ==", out)
        self.assertIn("严重 3 条", out)

    def test_json(self):
        code, out, _ = self.run_cli(SAMPLE, "--json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["stats"]["events_relevant"], 52)
        self.assertTrue(data["findings"][0]["time"].endswith("Z"))

    def test_csv_stdout(self):
        code, out, _ = self.run_cli(SAMPLE, "--csv", "-", "--utc")
        lines = out.strip().splitlines()
        self.assertEqual(lines[0], "time,end,event_id,count,flagged,description")
        self.assertIn("2026-11-20 02:00:00Z,2026-11-20 02:03:52Z,4625,30,yes", out)

    def test_clean_log_exit_zero(self):
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as f:
            f.write(success(T0, user="alice", logon_type="10"))
        try:
            code, out, _ = self.run_cli(f.name)
            self.assertEqual(code, 0)
            self.assertIn("没有发现可疑事件", out)
        finally:
            os.unlink(f.name)

    def test_missing_file(self):
        code, _, err = self.run_cli("/nonexistent/x.evtx")
        self.assertEqual(code, 2)
        self.assertIn("无法读取", err)

    def test_since_parsing(self):
        self.assertEqual(ea.parse_cli_time("2026-11-20T00:00:00Z"), datetime(2026, 11, 20, tzinfo=timezone.utc))
        self.assertIsNotNone(ea.parse_cli_time("2026-11-20"))
        import argparse
        with self.assertRaises(argparse.ArgumentTypeError):
            ea.parse_cli_time("yesterday")


if __name__ == "__main__":
    unittest.main()
