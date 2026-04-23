# 本体 v1.0 说明书

> 本文档是人读版本，机读版本在 `ontology/v1.0.yaml`。
> 两者不一致时以 YAML 为准（代码只读 YAML）。

---

## 1. 设计理念

**本体（Ontology）** 是系统用来描述安全世界的概念集：有哪些实体类型、关系类型、属性。

**为什么用本体而非硬编码 schema？**
- 所有层（数据、检测、图谱、认知、Copilot）共享一份事实源
- 支持版本化演化，**可以加但不能改/删**
- LLM 能读到当前本体版本，研判结果与本体解耦

**为什么叫 v1.0 而不是 v0.1？**
- 需求文档用 v1.0 作为"初始设计"的版本号
- 系统里第一次 Demo 演化到 v1.3（加了 ScheduledTask）

---

## 2. 节点类型（Entities）

| 类型 | 描述 | 来源 | 必填 |
|------|------|------|------|
| **User** | 人类身份主体 | CMDB / IAM | `user_id`, `display_name` |
| **Account** | Windows 账户对象 | 日志 | `sid`, `domain`, `username` |
| **Host** | 终端/服务器 | 日志 + CMDB | `hostname` |
| **Process** | 进程实例 | 日志（4688 / Sysmon 1） | `pid`, `image_name`, `start_time` |
| **NetworkEndpoint** | IP + port 组合 | 日志（Sysmon 3） | `ip` |

**关键设计决策**：
- **User 和 Account 物理分离**，只能通过 `owns` 边连接
- **原型阶段禁止 User↔Account 自动归并**（需求文档 §4.2 "风险控制"）
- SID 是 Account 的规范主键，是实体消歧的黄金键

---

## 3. 关系类型（Edges）

| 关系 | from | to | 时效性 | 说明 |
|------|------|-----|--------|------|
| `owns` | User | Account | 永久 | **只能来自 CMDB/IAM，LLM 不得创建** |
| `authenticated_as` | Host | Account | 90 天 | 成功认证 |
| `logged_into` | Account | Host | 30 天滑窗 | 交互/网络登录 |
| `spawned` | Process | Process | 永久 | 父子进程 |
| `executed_on` | Process | Host | 永久 | 进程运行的主机 |
| `connected_to` | Process | NetworkEndpoint | 7 天 | 网络连接 |

**关系时效性**为什么按关系分档？
- 权限/身份类（`owns`）：永久，变动需要显式声明
- 认证历史（`authenticated_as`）：长期记忆，支持"这账户以前在哪些主机认证过"
- 活跃登录（`logged_into`）：短期滑窗，反映当前状态
- 进程拓扑（`spawned` / `executed_on`）：永久，历史溯源必须
- 网络连接（`connected_to`）：短期，流量层面细节不保留太久

---

## 4. 元字段规约

**每个节点、每条边都强制带 5 个元字段**，由系统自动维护：

| 字段 | 类型 | 说明 |
|------|------|------|
| `first_seen` | ISO 8601 datetime | 第一次观察时间 |
| `last_seen` | ISO 8601 datetime | 最后一次观察时间 |
| `confidence` | float[0..1] | 观察置信度，<0.8 进入观察区（弱匹配） |
| `source` | enum | `log / cmdb / iam / manual / inferred` |
| `ontology_version` | string | 创建/最后更新时所用的本体版本号 |

**为什么每个边都带 `ontology_version`？**
- 本体升级后，历史边回填要能区分"是哪个版本建的"
- 演化回滚时要知道哪些边受影响

---

## 5. 硬边界（不可逾越）

**LLM 在演化提议时必须遵守**（写在 system prompt 里）：

1. **只能新增**，不能修改/删除现有节点、关系或必填属性
2. 新增必须附 **≥3 条支持证据**
3. 新增必须给出**与现有元素的重叠度**分析
4. 单次提议**最多 5 个**新元素
5. `owns` 边**绝不由 LLM 创建**（只能来自 CMDB/IAM 声明）

**为什么？**
- 修改/删除会破坏历史数据的兼容性
- 重叠度 > 0.7 的提议自动丢弃（冗余检测闸一）
- 字符串 + embedding 双重冗余检测（闸二）
- User↔Account 自动归并是 L3 级演化，原型不做

---

## 6. ATT&CK 锚定

原型聚焦 5 个技术点（构成一条完整 Windows 攻击链）：

- **T1078** Valid Accounts（凭证窃取/合法账户滥用）
- **T1021** Remote Services（远程服务/横向移动）
- **T1055** Process Injection（进程注入）
- **T1053** Scheduled Task/Job（计划任务持久化）← **Demo 演化锚点**
- **T1570** Lateral Tool Transfer（横向工具传输）

**Scheduled Task 为什么是 Demo 锚点？**
- 本体 v1.0 **故意不包含** `ScheduledTask` 节点
- 数据集里保留 EventID 4698/4702（任务创建/修改）
- Demo 时这类事件会进异常池，触发演化提议
- 升级到 v1.3 后，新 Parser 自动生成，异常池回收

---

## 7. 演化路径（Demo 中会走一遍）

```
v1.0 (初始)
  │
  │  运行一段时间后：37 条 4698/4702 进异常池
  │  LLM 提议新增 ScheduledTask 节点 + created_task 关系
  │
  ▼
v1.3 (演化后)
  + ScheduledTask
  + created_task (Account → ScheduledTask)
  + runs_on      (ScheduledTask → Host)
```

版本号跳 v1.0 → v1.3 的原因：
- Demo 故事里系统"已经运行了一段时间"，v1.1、v1.2 是之前演化的结果
- 可以在 Demo 前预置 v1.1/v1.2 让历史更真实（或略过直接跳）

---

## 8. API 摘要

```python
from core.ontology_service import get_service

svc = get_service()
onto = svc.get_current()

onto.node_types()            # ['Account','Host','NetworkEndpoint','Process','User']
onto.required_attrs('Account')  # ['sid', 'domain', 'username']
onto.has_edge('owns')        # True
onto.edge_endpoints('owns')  # ('User', 'Account')

svc.list_versions()          # ['v1.0']
svc.get_version('v1.0')      # Ontology 快照

# 订阅变更（变更传播核心机制）
def on_change(old, new):
    print(f"Ontology upgraded: {old.version if old else 'None'} -> {new.version}")

svc.subscribe(on_change)
svc.start_watching()         # 启动文件监听（Streamlit 主进程调用一次即可）
```
