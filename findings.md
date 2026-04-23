# 研究与发现

> 本文件记录从需求文档、外部资料、调研过程中得到的关键信息，供决策参考。

---

## F1. 需求文档核心发现

### F1.1 项目定位是"说服材料"，不是生产系统
> "不是生产系统，也不是技术探索性 POC，而是一个用于对内说服决策层立项的端到端原型"

**含义**：
- 所有技术选型都以"可演示"优先，不追求工程完备
- UI 可以简陋，但 **4 个核心数字必须突出**
- Demo 动线是硬需求（见 §8），开发必须保证这条路径跑通
- 原型允许崩、允许重启，但不允许主演示路径断

### F1.2 差异化卖点是"本体演化横切"
- 其他 AI SIEM 原型把演化当作图谱层的内部事务
- 本项目把演化做成**跨所有层的机制**，与评测层融合为"演化与评测横切层"
- 评测做薄、演化做厚
- **必守**：本体升级 → parser 自动生成 → 回放验证（否则演化就是空转）

### F1.3 场景锚定非常明确
- **聚焦 Windows**：数据源丰富、公开（BOTSv3/Mordor）、决策层易懂
- **一条攻击链**：凭证窃取 → 横向移动 → 持久化
- **ATT&CK 技术**：T1078 / T1021 / T1055 / T1053 / T1570
- **Scheduled Task (4698/4702) 是 Demo 叙事锚点**，必须预留作为演化触发素材

---

## F2. 关键硬约束（不可妥协）

### F2.1 反幻觉：evidence_refs 强制回指
> "evidence_refs 强制字段：所有结论必须回指证据节点 ID，缺失则视为无效输出"
> "绝不能让步"

**实施**：
- LLM structured output schema 把 `evidence_refs` 设为必填
- 引擎侧再做一次校验：空数组也视为无效
- 写入 `data/judgments.duckdb` 前必须通过校验

### F2.2 演化硬边界：只能加，不能改
> "Prompt 硬边界（在 system prompt 写死）：只能新增，不能修改/删除；必须附带 ≥3 条支持样本；必须给出与现有元素的重叠度；单次最多 5 个"
> "硬边界必须写在 prompt 的系统指令里而非用户指令里，防止被绕过"

**实施**：
- System prompt 用 `.txt` 文件固化版本化
- 额外做代码侧校验：提议包含 "modify"/"delete"/"rename" 相关意图直接丢弃
- 重叠度 > 0.7 自动丢弃（闸一）
- 字符串 + embedding 双重冗余检测（闸二）

### F2.3 Parser 配置而非代码
> "parser 引擎是手写的，parser 配置是 LLM 或人写的。区分这一点极其重要"

**含义**：
- 解析逻辑是稳定的 Python 代码（`parsers/windows_parser.py`）
- LLM 生成的是 YAML 映射配置（`parsers/generated/*.yaml`）
- 不允许 LLM 生成可执行代码

### F2.4 User 和 Account 绝不自动归并
> "User 节点只来自 CMDB/IAM 声明；Account 来自日志；owns 关系不自动推断"

**风险原因**：
- User↔Account 自动归并是 L3 级演化，风险太高
- 原型只做 L1（实例增长）+ L2（schema 扩展）

---

## F3. 技术栈决策（已由需求文档锁定）

| 类别 | 选型 | 不选的替代品 | 原因 |
|------|------|-------------|------|
| 数据存储 | **DuckDB** | Postgres / SQLite | 零部署、SQL 友好、单文件、列式快 |
| 图存储 | **NetworkX + pyvis** | Neo4j / TigerGraph | 纯 Python、演示 HTML 友好、无部署 |
| **LLM** | **Qwen-Plus (qwen-plus-2025-07-28)** | Claude / GPT-4 | 用户提供 1M 免费额度，国内低延迟 |
| 本体定义 | **YAML** | JSON / 数据库 | diff 友好、git 可管理、审计友好 |
| 规则引擎 | **pySigma 或自研简化版** | Suricata / Snort | Sigma 是生态标准可移植 |
| UI | **Streamlit** | React / Vue | 一天出界面、改动快、Python 原生 |
| 编排 | **纯 Python 脚本** | LangChain / LlamaIndex | **原型阶段框架是负资产** |
| Prompt 管理 | **.txt / .md 文件** | 专门框架 | git diff 可见、版本化 |
| 部署 | **Docker Compose**（最后一周打包） | k8s / 裸机 | 演示环境一键起 |
| **开发模式** | **Agent 驱动**（AI 写代码） | 人工双人/单人 | 用户决策：2026-04-22 |
| **Python 环境** | **venv** | conda / uv | 用户决策：2026-04-22 |

---

## F4. 组件风险矩阵

| 组件 | 工作量 | 风险等级 | 降级预案 |
|------|--------|---------|---------|
| 1. 数据准备 | 2d | 低 | — |
| 2. 本体注册中心 | 2d | 低 | — |
| 3. 宽容解析器 | 2d | 中 | — |
| 4. Sigma 规则 | 2d | 低 | 减到 4-5 条省 0.5d |
| **5. 知识图谱** | 4d | **高** | 退化为纯 SID 匹配 + 不做弱匹配 |
| **6. 认知推理** | 4d | **高** | 不设简单降级，必须做扎实 |
| 7. 信号中枢 | 2d | 低 | — |
| 8. 提议引擎 | 3d | 中 | — |
| 9. 审核 UI | 2d | 低 | — |
| **10. 变更传播 + Parser 生成 + 回放** | 5d | **高** | 不能砍，这是核心卖点 |
| 11. Copilot UI + 看板 | 3d | 中 | 看板不做趋势图省 1d；静态图代替 pyvis 省 1d |

**关键观察**：组件 5/6/10 是 **12 天**的硬核内容，占 31 天的 39%。Week 2 末必须完成组件 5/6 主体，否则 Week 3 起演化闭环做不下去。

---

## F5. 数据集选型待定

### 候选 1：BOTSv3
- 来源：Splunk Boss of the SOC 红蓝对抗
- 特点：公开、攻击链丰富
- 下载：待调研

### 候选 2：Mordor
- 来源：OTRF (Open Threat Research Forge)
- 特点：按 ATT&CK 技术组织、JSON 格式
- 下载：https://github.com/OTRF/Security-Datasets

**TODO**：下载两个数据集，评估哪个攻击链更贴合 T1078/T1021/T1053/T1055/T1570，且事件 4698/4702 覆盖充分。

---

## F6. 本体 v0 定义（需求文档附录 A）

**5 个节点**：
- `User`（人类身份，来自 CMDB/IAM，必填 user_id / display_name）
- `Account`（Windows 账户，来自日志，必填 sid / domain / username）
- `Host`（终端或服务器，必填 hostname）
- `Process`（进程实例，必填 pid / image_name / start_time）
- `NetworkEndpoint`（IP + port，必填 ip）

**6 个关系**：
- `owns` (User → Account, 永久, **仅来自 CMDB/IAM**)
- `authenticated_as` (Host → Account, 90d)
- `logged_into` (Account → Host, 30d 滑窗)
- `spawned` (Process → Process, 永久)
- `executed_on` (Process → Host, 永久)
- `connected_to` (Process → NetworkEndpoint, 7d)

**每个节点/边强制元字段**：
- `first_seen` / `last_seen` / `confidence` / `source` / `ontology_version`

---

## F7. 信号 Schema（需求文档附录 B）

```json
{
  "signal_id": "uuid",
  "timestamp": "ISO8601",
  "source_layer": "data | detection | graph | reasoning | copilot | evaluation",
  "signal_type": "unparseable_event | unknown_field | rule_schema_mismatch | orphan_entity | unmapped_relation | semantic_gap | manual_annotation | coverage_deficit",
  "priority": "hot | warm | cold",
  "payload": {
    "raw_data": "...",
    "failure_reason": "...",
    "related_entities": [],
    "related_ontology_version": "v1.2"
  },
  "aggregation_key": "...",
  "ontology_version": "v1.2"
}
```

**信号分层表**：
| 来源层 | 信号类型 | 含义 | 冷热 |
|-------|---------|------|------|
| 数据层 | unparseable_event / unknown_field | 解析失败 | 🔥 热 |
| 检测层 | rule_schema_mismatch | 规则字段找不到 | 🌤 温 |
| 图谱层 | orphan_entity / unmapped_relation | 无法建模 | 🌤 温 |
| 认知层 | semantic_gap | LLM 无合适概念 | 🌤 温 |
| Copilot | manual_annotation | 人工标注 | 🌤 温 |
| 评测层 | coverage_deficit | 准确率偏低 | ❄️ 冷 |

---

## F8. Demo 目标数字（需求文档 §8.1 & §8.5）

### 演化前（v1.2）
- 研判准确率：85%
- 反馈采纳率：72%
- 本体覆盖率：92%
- 异常事件池：37 条

### 演化后（v1.3）
- 研判准确率：88% ↑
- 本体覆盖率：96% ↑
- 异常事件池：2 条 ↓
- 新识别攻击链：2 条（计划任务持久化）

**含义**：开发要以这些数字为靶，数据准备 + 故意留空的事件 + 回放验证都要围绕这个目标凑。

---

## F9. 明确不做（需求文档 §7）

**不要做**以下事项，省时间给核心路径：

- UEBA 行为基线
- Agent 自动响应（封禁/隔离）
- 多数据源接入（只 Windows）
- Neo4j / 图数据库
- 完整 OCSF 对齐
- 完整 ATT&CK 覆盖
- 多用户权限系统
- 生产级错误处理与 HA
- User↔Account 自动归并
- 本体的修改/删除/合并（硬禁止）
- 规则 Copilot（LLM 写 Sigma）
- 威胁情报接入（MISP/OpenCTI）

---

## F10. 单人砍功能清单（若无法双人）

累计可省 3 天（31 → 28）：

| 砍点 | 省时 | 位置 |
|------|------|------|
| 看板不做趋势图，只显示 4 个数字 | 1d | 组件 11 |
| matplotlib 静态图代替 pyvis 交互 | 1d | 组件 5 |
| Sigma 规则 6-8 → 4-5 条 | 0.5d | 组件 4 |
| parser review 不做样本预览 | 0.5d | 组件 10 |

**结论**：单人勉强可行但零余量，**强烈建议双人**。

---

## F11. 用户决策记录（2026-04-22）

| # | 问题 | 决策 |
|---|------|------|
| 1 | 人手 | **Agent 驱动**（AI 代理写代码，非人工） |
| 2 | LLM API | **Qwen-Plus 2025-07-28**（DashScope，1M 免费 token，至 2026-07-22） |
| 3 | 数据集 | **BOTSv3**（Splunk Boss of the SOC v3） |
| 4 | Python 环境 | **venv** |
| 5 | Demo 失败案例 | **依赖 LLM 自然出错**（不手工标注） |

---

## F12. Qwen-Plus 接入要点（替代 Claude）

### 基础信息
- **模型 ID**：`qwen-plus-2025-07-28`
- **Provider**：阿里云 DashScope / 百炼
- **免费额度**：1,000,000 tokens（2026-07-22 到期）
- **费用模式**：免费额度用完即停（不自动扣费）

### API 接入方式
Qwen 支持 **OpenAI 兼容模式**，推荐这条路（最低改动）：

```python
from openai import OpenAI
client = OpenAI(
    api_key=os.environ["DASHSCOPE_API_KEY"],
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
)
resp = client.chat.completions.create(
    model="qwen-plus-2025-07-28",
    messages=[...],
    response_format={"type": "json_object"},  # Qwen 支持 JSON 模式
    temperature=0.1,
)
```

**原生 DashScope SDK**（`dashscope`）也可用，但 OpenAI 接口换模型方便。

### Structured Output 能力
- Qwen-Plus 支持 `json_object` 模式输出
- **不支持 Claude 那样的原生 JSON Schema 强约束**，需要在 prompt 里清晰写 schema + 代码侧二次校验
- 反幻觉：`evidence_refs` 的强制回指需要**引擎侧校验**（解析失败/数组为空 → 视为无效输出，重试 ≤2 次后降级）

### Token 预算策略（1M 额度守护）
| 用途 | 预估单次 token | 预估次数 | 小计 |
|------|--------------|---------|------|
| 研判引擎（每告警） | ~3K in / ~1K out | 45 条告警 × 1 轮 | ~180K |
| 本体提议生成 | ~10K in / ~2K out | 3-5 次 | ~60K |
| Parser 自动生成 | ~8K in / ~1.5K out | 2-3 次 | ~28K |
| 开发调试 & 回放 | — | — | ~200K（缓冲） |
| **合计** | | | **~470K** |

**安全余量 >50%**。但**必须在 `llm_client.py` 内置 token 计数 + 预算告警**（>700K 触发告警，>900K 拒绝调用）。

### 需求文档对 LLM 的依赖点（替换 Claude 的地方）
1. **组件 6 认知研判** - `reasoning/llm_client.py` + `judgment_engine.py`
2. **组件 8 提议引擎** - `evolution/proposer.py`
3. **组件 10 Parser 生成** - `evolution/parser_generator.py`

---

## F13. API Key 与密钥管理

### 当前 Key
`sk-7433b92b44e94b44aa37c7e65222a717`（Qwen DashScope，2026-04-22 收到）

### 存储策略
- **不入 git**：写入 `.env`，`.gitignore` 覆盖 `.env`
- **仅模板入 git**：`.env.example` 用占位 `sk-xxxxxxxxxxxxx`
- **代码读取**：统一通过 `os.environ["DASHSCOPE_API_KEY"]`
- **Docker**：`docker-compose.yml` 用 `env_file: .env`

### 安全建议
- 聊天记录中的明文 key 有泄露风险
- **建议在 Demo 前（或首次 push 到 GitHub 前）在百炼控制台重置一次**
- 重置后更新本地 `.env` 即可，无需改代码
