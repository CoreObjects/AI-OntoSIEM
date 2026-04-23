"""生成 BOTSv3-style 合成 Windows 安全日志，构建 Demo 数据集。

运行：
    python scripts/generate_demo_data.py

产出：
    data/events.duckdb   (表 events)

设计原则：
  - 确定性（seed 固定）→ 每次跑结果一致，Demo 可复现
  - schema 与真实 EVTX 同构（字段名、格式、SID 结构）
  - 攻击剧本见 docs/attack_scenarios.md
  - 故意保留 EventID 4698/4702 给演化机制作为锚点
"""
from __future__ import annotations

import json
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import duckdb

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "events.duckdb"

SEED = 20260422
random.seed(SEED)

# =========================================================
# 角色设定（与 docs/attack_scenarios.md 保持一致）
# =========================================================

USERS = [
    {"sid": "S-1-5-21-1000000000-1000000000-1000000000-1001", "domain": "CORP", "username": "alice",       "admin": False, "service": False},
    {"sid": "S-1-5-21-1000000000-1000000000-1000000000-1002", "domain": "CORP", "username": "bob",         "admin": True,  "service": False},
    {"sid": "S-1-5-21-1000000000-1000000000-1000000000-1003", "domain": "CORP", "username": "carol",       "admin": False, "service": False},
    {"sid": "S-1-5-21-1000000000-1000000000-1000000000-1004", "domain": "CORP", "username": "david",       "admin": False, "service": False},
    {"sid": "S-1-5-21-1000000000-1000000000-1000000000-2001", "domain": "CORP", "username": "svc_backup",  "admin": False, "service": True},
    {"sid": "S-1-5-21-1000000000-1000000000-1000000000-2002", "domain": "CORP", "username": "svc_sccm",    "admin": False, "service": True},
]
SYSTEM_SID = "S-1-5-18"

HOSTS = [
    {"name": "DC-01",        "ip": "10.0.1.10", "os": "Windows Server 2019", "dc": True},
    {"name": "FIN-SRV-01",   "ip": "10.0.2.20", "os": "Windows Server 2019", "dc": False},
    {"name": "HR-WS-01",     "ip": "10.0.3.31", "os": "Windows 10",           "dc": False},
    {"name": "IT-WS-02",     "ip": "10.0.3.32", "os": "Windows 10",           "dc": False},
    {"name": "FIN-WS-03",    "ip": "10.0.3.33", "os": "Windows 10",           "dc": False},
    {"name": "ENG-WS-04",    "ip": "10.0.3.34", "os": "Windows 10",           "dc": False},
]
HOST_BY_NAME = {h["name"]: h for h in HOSTS}

USER_BY_NAME = {u["username"]: u for u in USERS}

# 用户主工作站
USER_PRIMARY_HOST = {
    "alice": "HR-WS-01",
    "bob":   "IT-WS-02",
    "carol": "FIN-WS-03",
    "david": "ENG-WS-04",
}


# =========================================================
# Event 数据结构
# =========================================================

@dataclass
class Event:
    event_id: int
    timestamp: datetime
    computer: str
    event_data: Dict[str, Any]
    channel: str = "Security"
    provider: str = "Microsoft-Windows-Security-Auditing"
    record_number: int = 0

    def to_row(self) -> Dict[str, Any]:
        raw = {
            "EventID": self.event_id,
            "TimeCreated": self.timestamp.isoformat(),
            "Computer": self.computer,
            "Channel": self.channel,
            "Provider": self.provider,
            "RecordNumber": self.record_number,
            "EventData": self.event_data,
        }
        return {
            "event_id": self.event_id,
            "channel": self.channel,
            "provider": self.provider,
            "record_number": self.record_number,
            "timestamp": self.timestamp,
            "computer": self.computer,
            "event_data": json.dumps(self.event_data, ensure_ascii=False),
            "raw": json.dumps(raw, ensure_ascii=False),
        }


# =========================================================
# 生成器辅助
# =========================================================

_next_rn = 1000


def _rn() -> int:
    global _next_rn
    _next_rn += 1
    return _next_rn


def _pid() -> int:
    return random.randint(1000, 9999)


def _port(low: int = 49152, high: int = 65535) -> int:
    return random.randint(low, high)


def _logon_id() -> str:
    return f"0x{random.randint(0x10000, 0xFFFFFFFF):X}"


def _ts(day: int, hour: int, minute: int = 0, second: int = 0, base: Optional[datetime] = None) -> datetime:
    """基于 2026-04-15 00:00 UTC 的相对时间。"""
    base = base or datetime(2026, 4, 15, 0, 0, 0, tzinfo=timezone.utc)
    return base + timedelta(days=day - 1, hours=hour, minutes=minute, seconds=second)


# =========================================================
# 事件构造器
# =========================================================

def evt_4624_logon(
    target_user: Dict[str, Any],
    host: Dict[str, Any],
    logon_type: int,
    src_ip: str,
    ts: datetime,
    subject_user: Optional[Dict[str, Any]] = None,
    logon_process: str = "User32",
    auth_package: str = "Negotiate",
) -> Event:
    subject = subject_user or {"sid": SYSTEM_SID, "domain": "", "username": "-"}
    return Event(
        event_id=4624,
        timestamp=ts,
        computer=host["name"],
        event_data={
            "SubjectUserSid":       subject["sid"],
            "SubjectUserName":      subject["username"],
            "SubjectDomainName":    subject["domain"],
            "SubjectLogonId":       _logon_id(),
            "TargetUserSid":        target_user["sid"],
            "TargetUserName":       target_user["username"],
            "TargetDomainName":     target_user["domain"],
            "TargetLogonId":        _logon_id(),
            "LogonType":            str(logon_type),
            "LogonProcessName":     logon_process,
            "AuthenticationPackageName": auth_package,
            "WorkstationName":      host["name"],
            "LogonGuid":            f"{{{random.randint(0, 2**32 - 1):08X}-0000-0000-0000-000000000000}}",
            "TransmittedServices":  "-",
            "LmPackageName":        "-",
            "KeyLength":            "0",
            "ProcessId":            f"0x{_pid():X}",
            "ProcessName":          "C:\\Windows\\System32\\lsass.exe",
            "IpAddress":            src_ip,
            "IpPort":               str(_port()),
        },
        record_number=_rn(),
    )


def evt_4625_failed_logon(
    target_user: Dict[str, Any],
    host: Dict[str, Any],
    logon_type: int,
    src_ip: str,
    ts: datetime,
    failure_reason: str = "0xC000006A",  # bad password
) -> Event:
    return Event(
        event_id=4625,
        timestamp=ts,
        computer=host["name"],
        event_data={
            "SubjectUserSid":   SYSTEM_SID,
            "SubjectUserName":  "-",
            "SubjectDomainName": "-",
            "TargetUserSid":    "S-1-0-0",
            "TargetUserName":   target_user["username"],
            "TargetDomainName": target_user["domain"],
            "Status":           "0xC000006D",
            "SubStatus":        failure_reason,
            "FailureReason":    "%%2313",
            "LogonType":        str(logon_type),
            "WorkstationName":  host["name"],
            "IpAddress":        src_ip,
            "IpPort":           str(_port()),
            "ProcessName":      "C:\\Windows\\System32\\lsass.exe",
        },
        record_number=_rn(),
    )


def evt_4634_logoff(
    target_user: Dict[str, Any],
    host: Dict[str, Any],
    logon_type: int,
    ts: datetime,
) -> Event:
    return Event(
        event_id=4634,
        timestamp=ts,
        computer=host["name"],
        event_data={
            "TargetUserSid":    target_user["sid"],
            "TargetUserName":   target_user["username"],
            "TargetDomainName": target_user["domain"],
            "TargetLogonId":    _logon_id(),
            "LogonType":        str(logon_type),
        },
        record_number=_rn(),
    )


def evt_4688_process_create(
    subject_user: Dict[str, Any],
    host: Dict[str, Any],
    process_name: str,
    command_line: str,
    ts: datetime,
    parent_process_name: str = "C:\\Windows\\System32\\cmd.exe",
    integrity: str = "%%1936",  # Medium
) -> Event:
    return Event(
        event_id=4688,
        timestamp=ts,
        computer=host["name"],
        event_data={
            "SubjectUserSid":       subject_user["sid"],
            "SubjectUserName":      subject_user["username"],
            "SubjectDomainName":    subject_user["domain"],
            "SubjectLogonId":       _logon_id(),
            "NewProcessId":         f"0x{_pid():X}",
            "NewProcessName":       process_name,
            "TokenElevationType":   "%%1936",
            "ProcessId":            f"0x{_pid():X}",
            "CommandLine":          command_line,
            "TargetUserSid":        "S-1-0-0",
            "TargetUserName":       "-",
            "TargetDomainName":     "-",
            "TargetLogonId":        "0x0",
            "ParentProcessName":    parent_process_name,
            "MandatoryLabel":       integrity,
        },
        record_number=_rn(),
    )


def evt_4698_task_created(
    subject_user: Dict[str, Any],
    host: Dict[str, Any],
    task_name: str,
    task_content: str,
    ts: datetime,
) -> Event:
    return Event(
        event_id=4698,
        timestamp=ts,
        computer=host["name"],
        event_data={
            "SubjectUserSid":    subject_user["sid"],
            "SubjectUserName":   subject_user["username"],
            "SubjectDomainName": subject_user["domain"],
            "SubjectLogonId":    _logon_id(),
            "TaskName":          task_name,
            "TaskContent":       task_content,
        },
        record_number=_rn(),
    )


def evt_4702_task_updated(
    subject_user: Dict[str, Any],
    host: Dict[str, Any],
    task_name: str,
    task_content: str,
    ts: datetime,
) -> Event:
    return Event(
        event_id=4702,
        timestamp=ts,
        computer=host["name"],
        event_data={
            "SubjectUserSid":    subject_user["sid"],
            "SubjectUserName":   subject_user["username"],
            "SubjectDomainName": subject_user["domain"],
            "SubjectLogonId":    _logon_id(),
            "TaskName":          task_name,
            "TaskContent":       task_content,
        },
        record_number=_rn(),
    )


def evt_5140_share_access(
    subject_user: Dict[str, Any],
    host: Dict[str, Any],
    share_name: str,
    src_ip: str,
    ts: datetime,
) -> Event:
    return Event(
        event_id=5140,
        timestamp=ts,
        computer=host["name"],
        event_data={
            "SubjectUserSid":    subject_user["sid"],
            "SubjectUserName":   subject_user["username"],
            "SubjectDomainName": subject_user["domain"],
            "SubjectLogonId":    _logon_id(),
            "ObjectType":        "File",
            "IpAddress":         src_ip,
            "IpPort":            str(_port()),
            "ShareName":         share_name,
            "ShareLocalPath":    "\\??\\" + share_name.strip("\\"),
            "AccessMask":        "0x1",
            "AccessList":        "%%1538",
        },
        record_number=_rn(),
    )


def evt_5145_detailed_share(
    subject_user: Dict[str, Any],
    host: Dict[str, Any],
    share_name: str,
    relative_path: str,
    src_ip: str,
    ts: datetime,
    access_mask: str = "0x2",
) -> Event:
    return Event(
        event_id=5145,
        timestamp=ts,
        computer=host["name"],
        event_data={
            "SubjectUserSid":    subject_user["sid"],
            "SubjectUserName":   subject_user["username"],
            "SubjectDomainName": subject_user["domain"],
            "SubjectLogonId":    _logon_id(),
            "IpAddress":         src_ip,
            "IpPort":            str(_port()),
            "ShareName":         share_name,
            "ShareLocalPath":    "\\??\\" + share_name.strip("\\"),
            "RelativeTargetName": relative_path,
            "AccessMask":        access_mask,
            "AccessList":        "%%4417 %%4418",
        },
        record_number=_rn(),
    )


def evt_sysmon_1_process(
    subject_user: Dict[str, Any],
    host: Dict[str, Any],
    image: str,
    command_line: str,
    parent_image: str,
    parent_command_line: str,
    ts: datetime,
    hashes: str = "SHA256=" + "0" * 64,
) -> Event:
    return Event(
        event_id=1,
        timestamp=ts,
        computer=host["name"],
        channel="Microsoft-Windows-Sysmon/Operational",
        provider="Microsoft-Windows-Sysmon",
        event_data={
            "RuleName":      "-",
            "UtcTime":       ts.isoformat(),
            "ProcessGuid":   f"{{{random.randint(0, 2**64 - 1):016X}-0000-0000-0000-000000000000}}",
            "ProcessId":     str(_pid()),
            "Image":         image,
            "FileVersion":   "10.0.19041.1",
            "Description":   "-",
            "Product":       "Microsoft Windows",
            "Company":       "Microsoft Corporation",
            "CommandLine":   command_line,
            "CurrentDirectory": "C:\\",
            "User":          f"{subject_user['domain']}\\{subject_user['username']}",
            "LogonGuid":     f"{{{random.randint(0, 2**32 - 1):08X}-0000-0000-0000-000000000000}}",
            "LogonId":       _logon_id(),
            "TerminalSessionId": "0",
            "IntegrityLevel": "Medium",
            "Hashes":        hashes,
            "ParentProcessId": str(_pid()),
            "ParentImage":   parent_image,
            "ParentCommandLine": parent_command_line,
            "ParentUser":    f"{subject_user['domain']}\\{subject_user['username']}",
        },
        record_number=_rn(),
    )


def evt_sysmon_8_createremotethread(
    subject_user: Dict[str, Any],
    host: Dict[str, Any],
    source_image: str,
    target_image: str,
    ts: datetime,
) -> Event:
    return Event(
        event_id=8,
        timestamp=ts,
        computer=host["name"],
        channel="Microsoft-Windows-Sysmon/Operational",
        provider="Microsoft-Windows-Sysmon",
        event_data={
            "RuleName":       "-",
            "UtcTime":        ts.isoformat(),
            "SourceProcessGuid": f"{{{random.randint(0, 2**64 - 1):016X}}}",
            "SourceProcessId": str(_pid()),
            "SourceImage":    source_image,
            "TargetProcessGuid": f"{{{random.randint(0, 2**64 - 1):016X}}}",
            "TargetProcessId": str(_pid()),
            "TargetImage":    target_image,
            "NewThreadId":    str(random.randint(1000, 9999)),
            "StartAddress":   f"0x{random.randint(0, 2**64 - 1):016X}",
            "StartModule":    "-",
            "StartFunction":  "-",
            "SourceUser":     f"{subject_user['domain']}\\{subject_user['username']}",
            "TargetUser":     f"{subject_user['domain']}\\{subject_user['username']}",
        },
        record_number=_rn(),
    )


def evt_sysmon_10_processaccess(
    subject_user: Dict[str, Any],
    host: Dict[str, Any],
    source_image: str,
    target_image: str,
    granted_access: str,
    ts: datetime,
) -> Event:
    return Event(
        event_id=10,
        timestamp=ts,
        computer=host["name"],
        channel="Microsoft-Windows-Sysmon/Operational",
        provider="Microsoft-Windows-Sysmon",
        event_data={
            "RuleName":         "-",
            "UtcTime":          ts.isoformat(),
            "SourceProcessGuid": f"{{{random.randint(0, 2**64 - 1):016X}}}",
            "SourceProcessId":  str(_pid()),
            "SourceThreadId":   str(random.randint(1000, 9999)),
            "SourceImage":      source_image,
            "TargetProcessGuid": f"{{{random.randint(0, 2**64 - 1):016X}}}",
            "TargetProcessId":  str(_pid()),
            "TargetImage":      target_image,
            "GrantedAccess":    granted_access,
            "CallTrace":        "C:\\Windows\\SYSTEM32\\ntdll.dll+a0a54|UNKNOWN(...)",
            "SourceUser":       f"{subject_user['domain']}\\{subject_user['username']}",
            "TargetUser":       "NT AUTHORITY\\SYSTEM",
        },
        record_number=_rn(),
    )


# =========================================================
# 场景生成
# =========================================================

USER_APPS = [
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
    "C:\\Windows\\System32\\notepad.exe",
    "C:\\Windows\\System32\\mmc.exe",
    "C:\\Program Files\\Microsoft VS Code\\Code.exe",
    "C:\\Program Files\\7-Zip\\7zFM.exe",
    "C:\\Windows\\System32\\SnippingTool.exe",
    "C:\\Program Files\\Microsoft Teams\\current\\Teams.exe",
]

SYSTEM_SERVICES = [
    ("C:\\Windows\\System32\\svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k netsvcs"),
    ("C:\\Windows\\System32\\svchost.exe",     "C:\\Windows\\System32\\svchost.exe -k LocalSystemNetworkRestricted"),
    ("C:\\Windows\\System32\\taskhostw.exe",   "taskhostw.exe"),
    ("C:\\Windows\\System32\\conhost.exe",     "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1"),
    ("C:\\Windows\\System32\\SearchIndexer.exe", "SearchIndexer.exe /Embedding"),
    ("C:\\Windows\\System32\\dllhost.exe",     "C:\\Windows\\System32\\dllhost.exe /Processid:{AppX}"),
]


def gen_normal_daily_activity(events: List[Event], day: int) -> None:
    """每个工作日每个用户在主工作站上产生正常活动。"""
    for username, host_name in USER_PRIMARY_HOST.items():
        user = USER_BY_NAME[username]
        host = HOST_BY_NAME[host_name]
        # 早晨登录
        login_ts = _ts(day, random.randint(8, 9), random.randint(0, 59))
        events.append(evt_4624_logon(user, host, logon_type=2, src_ip="127.0.0.1", ts=login_ts))
        # 用户应用进程启动
        for _ in range(random.randint(18, 28)):
            proc_ts = login_ts + timedelta(minutes=random.randint(1, 480))
            image = random.choice(USER_APPS)
            events.append(evt_sysmon_1_process(
                user, host,
                image=image,
                command_line=f'"{image}"',
                parent_image="C:\\Windows\\explorer.exe",
                parent_command_line="C:\\Windows\\Explorer.EXE",
                ts=proc_ts,
            ))
        # 下班注销
        events.append(evt_4634_logoff(user, host, logon_type=2, ts=login_ts + timedelta(hours=9)))


def gen_background_system_noise(events: List[Event], day: int) -> None:
    """每台主机每天产生一批系统服务/后台进程噪音。"""
    for host in HOSTS:
        actor = USER_BY_NAME["svc_sccm"] if host["dc"] else random.choice(list(USER_BY_NAME.values()))
        for _ in range(random.randint(22, 32)):
            ts = _ts(day, random.randint(0, 23), random.randint(0, 59))
            image, cmd = random.choice(SYSTEM_SERVICES)
            events.append(evt_sysmon_1_process(
                actor, host,
                image=image, command_line=cmd,
                parent_image="C:\\Windows\\System32\\services.exe",
                parent_command_line="C:\\Windows\\system32\\services.exe",
                ts=ts,
            ))


def gen_service_account_noise(events: List[Event], day: int) -> None:
    """svc_sccm 每 4 小时在各工作站做软件盘点。"""
    svc = USER_BY_NAME["svc_sccm"]
    for hour in (0, 4, 8, 12, 16, 20):
        for host in HOSTS:
            if host["dc"]:
                continue
            ts = _ts(day, hour, random.randint(0, 59))
            events.append(evt_4624_logon(svc, host, logon_type=3, src_ip="10.0.1.5", ts=ts))
            events.append(evt_4634_logoff(svc, host, logon_type=3, ts=ts + timedelta(seconds=random.randint(5, 30))))


def gen_failed_logon_noise(events: List[Event], day: int) -> None:
    """每天 3-8 条失败登录（密码错误 / 账户过期等）。"""
    for _ in range(random.randint(3, 8)):
        user = random.choice([USER_BY_NAME[u] for u in ["alice", "bob", "carol", "david"]])
        host = HOST_BY_NAME[USER_PRIMARY_HOST[user["username"]]]
        ts = _ts(day, random.randint(7, 18), random.randint(0, 59))
        events.append(evt_4625_failed_logon(user, host, logon_type=2, src_ip="127.0.0.1", ts=ts))


def gen_dc_activity(events: List[Event], day: int) -> None:
    """DC-01 的日常活动（备份、时间同步等）。"""
    dc = HOST_BY_NAME["DC-01"]
    ts = _ts(day, 3, 15)
    events.append(evt_sysmon_1_process(
        USER_BY_NAME["svc_backup"], dc,
        image="C:\\Windows\\System32\\wbadmin.exe",
        command_line='wbadmin start backup -backupTarget:\\\\BACKUP-01\\dc-bk -include:C:',
        parent_image="C:\\Windows\\System32\\svchost.exe",
        parent_command_line="svchost.exe -k netsvcs",
        ts=ts,
    ))


def gen_attack_chain(events: List[Event]) -> None:
    """攻击剧本（与 docs/attack_scenarios.md §3 对齐）。"""
    alice    = USER_BY_NAME["alice"]
    svc_bk   = USER_BY_NAME["svc_backup"]
    hr_ws    = HOST_BY_NAME["HR-WS-01"]
    fin_srv  = HOST_BY_NAME["FIN-SRV-01"]
    fin_ws   = HOST_BY_NAME["FIN-WS-03"]

    # -------- Day 1 · 04-15 · 钓鱼触发 --------
    t1 = _ts(1, 14, 23)
    # explorer 启动 lnk → powershell
    events.append(evt_sysmon_1_process(
        alice, hr_ws,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line='powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4A...',
        parent_image="C:\\Windows\\explorer.exe",
        parent_command_line="C:\\Windows\\Explorer.EXE",
        ts=t1,
    ))
    events.append(evt_4688_process_create(
        alice, hr_ws,
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line='powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4A...',
        parent_process_name="C:\\Windows\\explorer.exe",
        ts=t1 + timedelta(seconds=1),
    ))

    # -------- Day 2 · 04-16 · LSASS dump --------
    t2 = _ts(2, 3, 45)
    events.append(evt_sysmon_1_process(
        alice, hr_ws,
        image="C:\\Windows\\Temp\\procdump.exe",
        command_line='"C:\\Windows\\Temp\\procdump.exe" -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp',
        parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_command_line="powershell.exe",
        ts=t2,
    ))
    events.append(evt_4688_process_create(
        alice, hr_ws,
        process_name="C:\\Windows\\Temp\\procdump.exe",
        command_line='"procdump.exe" -ma lsass.exe lsass.dmp',
        parent_process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ts=t2 + timedelta(seconds=1),
    ))
    events.append(evt_sysmon_10_processaccess(
        alice, hr_ws,
        source_image="C:\\Windows\\Temp\\procdump.exe",
        target_image="C:\\Windows\\System32\\lsass.exe",
        granted_access="0x1410",  # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
        ts=t2 + timedelta(seconds=3),
    ))

    # -------- Day 3 · 04-17 · 横向到 FIN-SRV-01 --------
    t3 = _ts(3, 10, 12)
    events.append(evt_4624_logon(
        svc_bk, fin_srv,
        logon_type=3, src_ip=hr_ws["ip"],
        ts=t3,
        logon_process="NtLmSsp", auth_package="NTLM",
    ))
    # 远程执行侦察命令
    for i, (img, cmd) in enumerate([
        ("C:\\Windows\\System32\\whoami.exe",  "whoami /groups"),
        ("C:\\Windows\\System32\\net.exe",     "net user /domain"),
        ("C:\\Windows\\System32\\net.exe",     "net group \"Domain Admins\" /domain"),
        ("C:\\Windows\\System32\\net.exe",     "net localgroup Administrators"),
    ]):
        events.append(evt_sysmon_1_process(
            svc_bk, fin_srv,
            image=img, command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line="cmd.exe /c " + cmd,
            ts=t3 + timedelta(minutes=i + 1),
        ))

    # -------- Day 4 · 04-18 · 持续侦察 --------
    t4 = _ts(4, 11, 5)
    events.append(evt_4624_logon(svc_bk, fin_srv, logon_type=3, src_ip=hr_ws["ip"], ts=t4,
                                 logon_process="NtLmSsp", auth_package="NTLM"))
    events.append(evt_sysmon_1_process(
        svc_bk, fin_srv,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line='powershell -c "Get-ADUser -Filter * -Properties * | Select-Object sAMAccountName,lastLogon"',
        parent_image="C:\\Windows\\System32\\svchost.exe",
        parent_command_line="svchost.exe -k netsvcs",
        ts=t4 + timedelta(seconds=30),
    ))

    # -------- Day 5 · 04-19 · 工具传输 --------
    t5 = _ts(5, 2, 30)
    events.append(evt_5140_share_access(
        svc_bk, fin_srv,
        share_name="\\\\FIN-SRV-01\\C$",
        src_ip=hr_ws["ip"], ts=t5,
    ))
    events.append(evt_5145_detailed_share(
        svc_bk, fin_srv,
        share_name="\\\\FIN-SRV-01\\C$",
        relative_path="Windows\\Temp\\tools.zip",
        src_ip=hr_ws["ip"], ts=t5 + timedelta(seconds=2),
        access_mask="0x2",  # write
    ))

    # -------- Day 6 · 04-20 · 持久化 (T1053) · 演化锚点 --------
    t6 = _ts(6, 3, 17)
    # 创建计划任务
    events.append(evt_4624_logon(svc_bk, fin_srv, logon_type=3, src_ip=hr_ws["ip"], ts=t6,
                                 logon_process="NtLmSsp", auth_package="NTLM"))
    events.append(evt_4698_task_created(
        svc_bk, fin_srv,
        task_name="\\Microsoft\\Windows\\MS_Telemetry_Update",
        task_content=(
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<Task><Actions><Exec>'
            '<Command>powershell.exe</Command>'
            '<Arguments>-ep bypass -f C:\\Windows\\Temp\\beacon.ps1</Arguments>'
            '</Exec></Actions>'
            '<Triggers><BootTrigger/><CalendarTrigger><ScheduleByDay/></CalendarTrigger></Triggers></Task>'
        ),
        ts=t6 + timedelta(seconds=5),
    ))
    # 修改现有任务
    events.append(evt_4702_task_updated(
        svc_bk, fin_srv,
        task_name="\\Microsoft\\Windows\\Windows Defender\\Windows Defender Update",
        task_content=(
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<Task><Actions>'
            '<Exec><Command>MpCmdRun.exe</Command><Arguments>-SignatureUpdate</Arguments></Exec>'
            '<Exec><Command>powershell.exe</Command><Arguments>-ep bypass C:\\Windows\\Temp\\beacon.ps1</Arguments></Exec>'
            '</Actions></Task>'
        ),
        ts=t6 + timedelta(seconds=10),
    ))

    # -------- Day 7 · 04-21 · 进程注入 --------
    t7 = _ts(7, 3, 0)
    # 计划任务自动触发 powershell
    events.append(evt_sysmon_1_process(
        svc_bk, fin_srv,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line='powershell.exe -ep bypass -f C:\\Windows\\Temp\\beacon.ps1',
        parent_image="C:\\Windows\\System32\\svchost.exe",
        parent_command_line="svchost.exe -k netsvcs -p -s Schedule",
        ts=t7,
    ))
    # powershell → CreateRemoteThread → explorer.exe
    events.append(evt_sysmon_8_createremotethread(
        svc_bk, fin_srv,
        source_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        target_image="C:\\Windows\\explorer.exe",
        ts=t7 + timedelta(seconds=8),
    ))
    events.append(evt_sysmon_10_processaccess(
        svc_bk, fin_srv,
        source_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        target_image="C:\\Windows\\explorer.exe",
        granted_access="0x1FFFFF",  # PROCESS_ALL_ACCESS
        ts=t7 + timedelta(seconds=9),
    ))


def gen_extra_scheduled_tasks_noise(events: List[Event]) -> None:
    """多个主机上散布 30 条 4698/4702 事件（合法 + 可疑混合），构成演化锚点的 ~40 条异常池。

    其中一部分是合法任务（Windows Update、Defender）、一部分是可疑任务（伪装成系统任务的恶意）。
    本体 v1.0 无 ScheduledTask 节点，全部会进异常池。
    """
    benign_tasks = [
        ("\\Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker",
         '<Task><Actions><Exec><Command>%SystemRoot%\\System32\\MusNotification.exe</Command></Exec></Actions></Task>'),
        ("\\Microsoft\\Windows\\TaskScheduler\\Idle Maintenance",
         '<Task><Actions><Exec><Command>%SystemRoot%\\System32\\MaintenanceService.exe</Command></Exec></Actions></Task>'),
        ("\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
         '<Task><Actions><Exec><Command>%SystemRoot%\\System32\\defrag.exe</Command><Arguments>-c -h -k -g</Arguments></Exec></Actions></Task>'),
        ("\\Microsoft\\Windows\\Chkdsk\\ProactiveScan",
         '<Task><Actions><Exec><Command>%SystemRoot%\\System32\\chkdsk.exe</Command></Exec></Actions></Task>'),
    ]
    suspicious_tasks = [
        ("\\Microsoft\\Windows\\MS_Telemetry_Update",
         '<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-ep bypass C:\\ProgramData\\svc.ps1</Arguments></Exec></Actions></Task>'),
        ("\\MS_Compatibility_Check",
         '<Task><Actions><Exec><Command>C:\\Users\\Public\\comp.exe</Command></Exec></Actions></Task>'),
    ]
    targets = [HOST_BY_NAME["FIN-SRV-01"], HOST_BY_NAME["IT-WS-02"], HOST_BY_NAME["HR-WS-01"],
               HOST_BY_NAME["ENG-WS-04"], HOST_BY_NAME["FIN-WS-03"]]
    admin = USER_BY_NAME["bob"]

    for i in range(28):
        day = random.randint(1, 7)
        hour = random.randint(0, 23)
        ts = _ts(day, hour, random.randint(0, 59))
        host = random.choice(targets)
        # 75% benign，25% 可疑
        if random.random() < 0.75:
            tname, tcontent = random.choice(benign_tasks)
            subj = random.choice([USER_BY_NAME["svc_sccm"], admin])
            ev_cls = evt_4702_task_updated if random.random() < 0.4 else evt_4698_task_created
        else:
            tname, tcontent = random.choice(suspicious_tasks)
            subj = USER_BY_NAME["svc_backup"]
            ev_cls = evt_4698_task_created
        events.append(ev_cls(subj, host, tname, tcontent, ts))


# =========================================================
# 主流程
# =========================================================

def generate_all() -> List[Event]:
    events: List[Event] = []
    # 7 天正常业务
    for day in range(1, 8):
        gen_normal_daily_activity(events, day)
        gen_background_system_noise(events, day)
        gen_service_account_noise(events, day)
        gen_failed_logon_noise(events, day)
        gen_dc_activity(events, day)
    # 攻击剧本
    gen_attack_chain(events)
    # 4698/4702 演化锚点
    gen_extra_scheduled_tasks_noise(events)
    # 按时间排序
    events.sort(key=lambda e: e.timestamp)
    # 重新分配 record_number
    for i, ev in enumerate(events, start=1):
        ev.record_number = i
    return events


def write_to_duckdb(events: List[Event]) -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    con = duckdb.connect(str(DB_PATH))
    con.execute("""
        CREATE TABLE events (
            event_id       INTEGER,
            channel        VARCHAR,
            provider       VARCHAR,
            record_number  BIGINT,
            timestamp      TIMESTAMP,
            computer       VARCHAR,
            event_data     JSON,
            raw            JSON
        )
    """)
    rows = [ev.to_row() for ev in events]
    con.executemany(
        """
        INSERT INTO events (event_id, channel, provider, record_number, timestamp, computer, event_data, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (r["event_id"], r["channel"], r["provider"], r["record_number"],
             r["timestamp"], r["computer"], r["event_data"], r["raw"])
            for r in rows
        ],
    )
    con.execute("CREATE INDEX idx_ts ON events(timestamp)")
    con.execute("CREATE INDEX idx_eid ON events(event_id)")
    con.execute("CREATE INDEX idx_computer ON events(computer)")
    con.close()


def print_summary(events: List[Event]) -> None:
    from collections import Counter
    n = len(events)
    eid = Counter(e.event_id for e in events)
    hosts = Counter(e.computer for e in events)
    print(f"[summary] total events: {n}")
    print(f"[summary] by event_id: {dict(sorted(eid.items()))}")
    print(f"[summary] by computer: {dict(sorted(hosts.items()))}")
    print(f"[summary] time range:  {events[0].timestamp.isoformat()}  ->  {events[-1].timestamp.isoformat()}")
    evo_count = eid.get(4698, 0) + eid.get(4702, 0)
    print(f"[summary] evolution anchors (4698+4702): {evo_count}")
    print(f"[summary] DB path: {DB_PATH}")


def main() -> int:
    events = generate_all()
    write_to_duckdb(events)
    print_summary(events)
    return 0


if __name__ == "__main__":
    sys.exit(main())
