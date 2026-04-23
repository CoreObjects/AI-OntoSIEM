# 攻击剧本与数据设计

> 本文档定义 MVP Demo 所用数据集的完整叙事：有哪些角色、发生了什么、每一步对应哪条 ATT&CK 技术、哪些事件应该被告警、哪些是故意留给演化机制触发的 semantic_gap。

---

## 1. 数据源策略

### 1.1 默认：合成数据（原型阶段采用）
- 脚本生成 ~3000 条 Windows 安全日志（Security channel + Sysmon channel）
- Schema 与 BOTSv3 / Mordor / Windows EVTX 同构
- 保证 Demo 叙事完整且可精准控制（semantic_gap 点位固定）
- 生成命令：`python scripts/generate_demo_data.py`

### 1.2 可选升级：真实 BOTSv3
- 下载：https://github.com/splunk/botsv3
- 大小：~2GB（已索引的 Splunk 格式）
- 升级步骤：
  1. 下载 BOTSv3 数据到 `datasets/botsv3/`
  2. 运行 `scripts/ingest_botsv3.py`（待实现，Phase 1 功能）
  3. 过滤 Windows 事件，抽样 2000-5000 条入 `data/events.duckdb`
- 为什么原型用合成：Demo 需要精确的 semantic_gap 控制，真实数据里 4698/4702 数量不可控

---

## 2. 角色设定

### 2.1 合法用户（CMDB 声明）

| User ID | Display Name | Department | 角色 |
|---------|-------------|-----------|------|
| u1001 | Alice Chen | Finance | HR 会计，日常用户 |
| u1002 | Bob Martinez | IT | 系统管理员 |
| u1003 | Carol Wu | Finance | 财务总监 |
| u1004 | David Kim | Engineering | 后端工程师 |
| u2001 | svc_backup | — | 备份服务账户（非人类） |
| u2002 | svc_sccm | — | SCCM 代理服务账户 |

### 2.2 账户（日志中出现）

| SID | Domain\User | owner User | 性质 |
|-----|-------------|-----------|------|
| S-1-5-21-1-1001 | CORP\alice | u1001 | 普通用户 |
| S-1-5-21-1-1002 | CORP\bob | u1002 | 管理员 |
| S-1-5-21-1-1003 | CORP\carol | u1003 | 普通用户 |
| S-1-5-21-1-1004 | CORP\david | u1004 | 普通用户 |
| S-1-5-21-1-2001 | CORP\svc_backup | u2001 | 服务账户 |
| S-1-5-21-1-2002 | CORP\svc_sccm | u2002 | 服务账户 |
| S-1-5-21-1-9999 | CORP\alice_admin | **孤儿** | **攻击者创建的隐藏账户** |

### 2.3 主机

| Hostname | OS | 角色 | IP |
|----------|-----|------|-----|
| DC-01 | Windows Server 2019 | 域控 | 10.0.1.10 |
| FIN-SRV-01 | Windows Server 2019 | 财务系统 | 10.0.2.20 |
| HR-WS-01 | Windows 10 | Alice 工作站 | 10.0.3.31 |
| IT-WS-02 | Windows 10 | Bob 工作站 | 10.0.3.32 |
| FIN-WS-03 | Windows 10 | Carol 工作站 | 10.0.3.33 |
| ENG-WS-04 | Windows 10 | David 工作站 | 10.0.3.34 |

---

## 3. 攻击剧本（时间线）

**场景时间**：2026-04-15 到 2026-04-21（Demo 前一周）
**叙事**：攻击者从 Alice 的工作站钓鱼得手 → 凭证收集 → 横向到财务服务器 → 建立持久化 → 准备外发数据

### 第 1 天 04-15 · 初始访问（诱饵阶段）
- 02:00-06:00 大量正常日志（登录、注销、进程启动）
- Alice 在 14:23 打开钓鱼邮件附件（`invoice.xls.lnk`），触发 PowerShell
  - 进程：`powershell.exe -nop -w hidden -enc <base64>`
  - **ATT&CK**: T1566.001（钓鱼附件）
  - **事件**：4688 ProcessCreate · Sysmon 1

### 第 2 天 04-16 · 凭证窃取（T1078 / T1003）
- 攻击者在 Alice 主机上 dump LSASS
  - 进程：`procdump.exe -ma lsass.exe lsass.dmp`
  - **事件**：4688 + Sysmon 1 + Sysmon 10 (ProcessAccess to lsass.exe)
- 获得 Alice 的 NTLM hash 和几个登录过该主机的服务账户 hash
- 离线破解得到 `CORP\svc_backup` 的明文密码

### 第 3-4 天 04-17 至 04-18 · 横向移动（T1021 / T1078）
- 用 `svc_backup` 账户从 HR-WS-01 远程登录 FIN-SRV-01（异常：svc_backup 本不该登录财务服务器）
  - **事件**：4624 LogonType=3（网络登录）, TargetUserName=svc_backup, SourceIP=10.0.3.31, ComputerName=FIN-SRV-01
  - **ATT&CK**: T1021.002（SMB/Windows Admin Shares）
  - **预期告警**：高置信（SID 在目标主机首次出现 + 源 IP 是工作站非服务器）
- 在 FIN-SRV-01 上用 `svc_backup` 执行 `whoami /groups` / `net user /domain`
  - **事件**：4688 · 多条 PowerShell ScriptBlock

### 第 5 天 04-19 · 横向工具传输（T1570）
- 从 HR-WS-01 向 FIN-SRV-01 复制工具 `\\FIN-SRV-01\C$\Windows\Temp\tools.zip`
  - **事件**：5140（网络共享对象访问）, 5145（详细文件操作）
  - **ATT&CK**: T1570

### 第 6 天 04-20 · 持久化（T1053）⭐ 演化锚点
- 在 FIN-SRV-01 上创建计划任务 `MS_Telemetry_Update`（伪装成系统任务）
  - **事件**：**4698 (Scheduled Task Created)**
  - 动作：`powershell.exe -ep bypass -f C:\Windows\Temp\beacon.ps1`
  - 触发器：开机 + 每天 03:00
- 修改现有任务 `Windows Defender Update` 添加额外 action
  - **事件**：**4702 (Scheduled Task Updated)**
  - **ATT&CK**: T1053.005
- **⚠️ 关键**：本体 v1.0 **不含** `ScheduledTask` 节点，这些事件**无法建模** → 进入异常池

### 第 7 天 04-21 · 进程注入（T1055）
- 计划任务执行 `beacon.ps1` 向 `explorer.exe` 注入 shellcode
  - **事件**：Sysmon 8 (CreateRemoteThread), Sysmon 10 (ProcessAccess)
  - **ATT&CK**: T1055

### 同期 · 正常业务日志
- 每天 09:00-18:00 各用户在各自工作站的正常登录、应用启动
- 服务账户 svc_sccm 每 4 小时在所有工作站做软件盘点（正常）
- DC-01 每日 03:15 的 AD 备份

---

## 4. 预期告警清单

| ID | 规则名 | 触发事件 | ATT&CK | Demo 预期结果 |
|----|--------|---------|--------|---------------|
| R1 | lsass_memory_dump | Sysmon 10 to lsass | T1003 | ✅ 告警 · AI 研判 malicious |
| R2 | anomalous_service_account_logon | 4624 with svc_backup on non-standard host | T1078 | ✅ 告警 · AI 研判 suspicious |
| R3 | smb_lateral_movement | 4624 LogonType=3 + source workstation | T1021 | ✅ 告警 · AI 研判 malicious |
| R4 | suspicious_powershell | 4688 powershell with encoded command | T1059 | ✅ 告警 |
| R5 | admin_share_access | 5140 to C$/ADMIN$ | T1570 | ✅ 告警 |
| R6 | remote_thread_injection | Sysmon 8 cross-process | T1055 | ✅ 告警 |
| R7 | scheduled_task_creation | **4698 / 4702** | T1053 | ⚠️ **无规则**（本体 v1.0 里没 ScheduledTask） |
| R8 | failed_logon_burst | 多条 4625 同源 IP | T1110 | ✅ 告警（会有 1-2 条误报） |

**Demo 核心矛盾**：
- T1053 的持久化事件 **没有告警产出** → AI 研判时标 `semantic_gap` → 异常池累积 37 条
- 演化机制触发 → LLM 提议新增 `ScheduledTask` 节点
- 人工通过 → Parser 自动生成 → 异常池回收 → **额外识别 2 条完整攻击链**

---

## 5. semantic_gap 点位（演化素材）

### 5.1 主锚点：Scheduled Task 事件
- EventID 4698 / 4702 故意在数据集中保留 ~40 条
- 本体 v1.0 无对应节点 → parser 解析时归类为 `unparseable_event` → 进异常池
- 这是 Demo 演化的**主故事线**

### 5.2 次要锚点：未知字段
- 少量 Sysmon 事件包含 `OriginalFileName` 字段（较新的 Sysmon 版本特性）
- 初始 parser 不认识 → 上报 `unknown_field` 信号
- 这是 Demo 第二幕可选叙事

---

## 6. 数据规模预算

| 类别 | 条数 | 占比 |
|------|------|------|
| 正常业务日志（4624/4634/4688/Sysmon 正常进程） | ~2500 | 83% |
| 攻击相关事件（LSASS / 横移 / 工具传输 / 进程注入） | ~400 | 13% |
| **Scheduled Task (4698/4702) — 演化锚点** | **~40** | **1.3%** |
| 其他噪音（失败登录/正常变更） | ~60 | 2% |
| **合计** | **~3000** | 100% |

---

## 7. 数据文件位置

- `data/events.duckdb` — 主事件库，表 `events`
- 表 schema：
  ```sql
  CREATE TABLE events (
    event_id       INTEGER,        -- Windows Event ID (4624, 4698, ...)
    channel        VARCHAR,        -- Security / Microsoft-Windows-Sysmon/Operational
    provider       VARCHAR,
    record_number  BIGINT,         -- 系统递增 ID
    timestamp      TIMESTAMP,
    computer       VARCHAR,        -- 产生事件的主机
    event_data     JSON,           -- 完整 event_data 字段（JSON）
    raw            JSON            -- 原始日志（保底）
  );
  ```
- 索引：`timestamp`, `event_id`, `computer`

---

## 8. 验证清单（数据生成完后必须过）

- [ ] 总事件数 2000-5000
- [ ] 至少 5 个主机、6 个账户、4 个用户
- [ ] EventID 覆盖：{4624, 4625, 4634, 4688, 4698, 4702, 5140, 5145, Sysmon 1, 8, 10}
- [ ] 4698/4702 数量 30-50 条
- [ ] 时间跨度 5-7 天
- [ ] 每条事件的 SID 格式合法（`S-1-5-21-*`）
- [ ] 合法用户和攻击者事件比例 ~85:15
- [ ] DuckDB 文件可以被 `duckdb.connect()` 读取
