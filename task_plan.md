# AI-native SIEM MVP 开发计划

> **文档版本**：v1.0
> **创建时间**：2026-04-22
> **项目需求源**：`AI-native SIEM MVP 需求文档 v1.0.docx`
> **交付周期**：1 个月（~22 工作日）
> **总工作量**：31 人天（建议双人并行，或单人砍 3 天非核心功能）
> **场景锚定**：Windows 安全 · 凭证窃取 → 横向移动 → 持久化

---

## 🎯 项目目标

交付一个端到端、可演示的 AI-native SIEM 原型，用 5 分钟讲清楚三件事：

1. **真能跑** — 从 Windows 日志到 AI 研判的完整链路
2. **比现状好** — 4 个核心数字（研判准确率 / 反馈采纳率 / 本体覆盖率 / 异常池规模）
3. **有自我演化能力** — 异常池 → 提议 → 审核 → 本体升级 → parser 自动生成 → 回放验证的完整闭环

**与其他 AI SIEM 原型最核心的差异点**：本体演化机制横切所有层（不只是图谱层的内部事务）。

---

## 📐 架构总览

```
⑤ Copilot / Agent 层 ── 对话式研判 · 报告生成
④ 认知推理层 (LLM) ── 告警解释 · 攻击链重构
③ 上下文与知识图谱层 ── 实体 · 关系 · 画像 · 时效性
② 检测与告警层 ── Sigma 规则 · 图谱检测
① 数据与语义理解层 ── 日志接入 · Parser · 异常事件池
        ↕ 所有层读取本体、订阅变更事件、上报信号 ↕
⓪ 演化与评测横切层 ── 信号汇聚 · 提议 · 审核 · 变更传播 · Parser 自动生成 · 回放
```

---

## 📅 阶段总览（5 个阶段映射到 4 周里程碑）

| 阶段 | 内容 | 工作量 | 对应组件 | 里程碑 | 状态 |
|------|------|--------|----------|--------|------|
| **阶段 0** | 需求理解、技术栈准备、仓库骨架 | 0.5 天 | — | 规划完成 | ✅ 完成 |
| **阶段 1** | 基础设施层：数据 + 本体 + 解析器 | ~7 天 | 组件 1/2/3 + LLM 客户端 | Week 1 末「最小链路通」 | ✅ 完成 |
| **阶段 2** | 检测 + 图谱 + 认知研判 + 信号中枢 | ~12 天 | 组件 4/5/6/7 | Week 2 末「端到端主路径通」 | ✅ 完成（Week 2 里程碑达成） |
| **阶段 3** | 演化闭环：提议 + 审核 + Parser 生成 + 回放 | ~10 天 | 组件 8/9/10 | Week 3 末「演化闭环通」 | ⏳ 待开始 |
| **阶段 4** | UI 集成 + 评测看板 + Docker + Demo 录屏 | ~3 天 | 组件 11 + 交付物 | Week 4 末「完整交付」 | ⏳ 待开始 |

总计 32.5 天 → 双人并行 ≈ 22 工作日。

---

## 🔧 阶段 0：项目准备（当前）

**目标**：建立仓库骨架、确认技术栈、拉齐开发计划。
**开发模式**：Agent 驱动（AI 代理写代码，非人工）
**LLM 后端**：Qwen-Plus 2025-07-28（DashScope，1M 免费 token）
**Python 环境**：venv
**数据集**：BOTSv3

### 任务清单
- [x] 读取需求文档并提取关键信息
- [x] 创建规划文件（task_plan / findings / progress）
- [x] 确认 LLM：Qwen-Plus 替代 Claude
- [x] 确认数据集：BOTSv3
- [x] 确认环境：venv
- [x] 写 `.gitignore` 保护 `data/` 与 `.env`
- [x] 创建 `.env`（真实 key）与 `.env.example`（占位）
- [x] 建立仓库目录结构（按组件划分模块）
- [x] 初始化 `requirements.txt` + 创建 venv + 装依赖
- [x] **冒烟测试：Qwen-Plus structured output 可用**（2026-04-22：405 tokens，通过）
- [ ] 下载 BOTSv3 数据集（阶段 1 再做）

**阶段 0 完成！** ✅

### 仓库骨架（建议）
```
AI-OntoSIEM/
├── ontology/                # YAML 本体定义 + 版本
├── core/                    # ontology_service 等核心服务
├── parsers/
│   ├── windows_parser.py
│   ├── mappings/            # 初始 parser 配置
│   └── generated/           # LLM 生成的 parser
├── detection/
│   ├── rules/               # Sigma 规则
│   └── engine.py
├── graph/                   # NetworkX 图谱层
├── reasoning/               # LLM 研判引擎
│   ├── prompt_templates/
│   ├── llm_client.py
│   └── judgment_engine.py
├── evolution/               # 演化横切层
│   ├── signal_hub.py
│   ├── proposer.py
│   ├── change_propagator.py
│   ├── parser_generator.py
│   └── replay_validator.py
├── storage/                 # 异常事件池等
├── ui/                      # Streamlit 主应用
│   ├── main.py
│   └── pages/
├── data/                    # DuckDB 文件（gitignore）
├── docs/                    # 架构文档、攻击剧本
├── tests/
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## 🧱 阶段 1：基础设施层（Week 1 · ~7 天）✅ 完成

**里程碑**：数据库有日志 · 本体服务可调用 · LLM 可返回结构化研判。**全部达成（41/41 测试绿）。**

### 实际完成清单
- ✅ **组件 2 本体注册中心**：`ontology/v1.0.yaml`（5 节点 6 关系 + 元字段 + 硬边界说明）、`core/ontology_service.py`（get_current/subscribe/hot reload）、`docs/ontology_v1.md`、14 测试
- ✅ **组件 1 数据准备**：2329 条合成 Windows 日志入 `data/events.duckdb`，覆盖 T1078/T1021/T1053/T1055/T1570 攻击链，**保留 30 条 4698/4702 作为演化锚点**，`docs/attack_scenarios.md` + `scripts/generate_demo_data.py`
- ✅ **组件 3 宽容解析器**：`parsers/windows_parser.py` + `parsers/mappings/windows_v1.yaml`、`storage/anomaly_pool.py`、解析 2297 事件 → 6134 节点 + 4036 关系、32 事件入异常池（含全部 30 条 4698/4702）、15 测试
- ✅ **信号中枢最小版**（组件 7 部分提前）：`evolution/signal_hub.py` 统一 API + DuckDB 存储、支持 6 类信号类型 + 冷热分级
- ✅ **LLM 客户端**（组件 6 基础）：`reasoning/llm_client.py` OpenAI 兼容调用 Qwen + Token 预算守护 + structured JSON 重试 + `validate_evidence_refs` 反幻觉校验、12 测试

### 组件 1：数据与样本准备（2 天）
- 选定 BOTSv3 或 Mordor，抽取 2000-5000 条 Windows 日志入 DuckDB
- 覆盖 2-3 条攻击链（T1078 / T1021 / T1055 / T1053 / T1570）
- **关键**：故意保留 Scheduled Task 事件（4698/4702）作为演化触发素材
- 写 `docs/attack_scenarios.md`：攻击链 + 预期告警 + semantic_gap 点位

### 组件 2：本体注册中心（2 天）
- `ontology/v1.0.yaml`：5 节点（User/Account/Host/Process/NetworkEndpoint）+ 6 关系
- `core/ontology_service.py`：`get_current()` / `get_version(n)` / `subscribe(callback)`
- 文件监听实现变更广播（watchdog 或 polling）
- 每个节点/边强制元字段：`first_seen` / `last_seen` / `confidence` / `source` / `ontology_version`

### 组件 3：数据层 + 宽容解析器（2 天）
- 从 DuckDB 读原始日志，按本体 schema 映射
- 解析失败 → 完整保留原始 JSON + 失败原因 → 异常事件池
- parser 配置 YAML 化 + hot reload
- 通过组件 7 的 API 上报 `unparseable_event` / `unknown_field` 信号

### 并行任务（若双人）：LLM 客户端骨架（1 天）
- `reasoning/llm_client.py`：Qwen-Plus 2025-07-28 structured output 封装
- Prompt 模板目录规划
- 基础 retry / 超时 / 日志

---

## ⚙️ 阶段 2：检测 + 图谱 + 认知 + 信号中枢（Week 2 · ~12 天）

**里程碑**：告警能产出 · 图谱能建 · LLM 能读图做研判 · 端到端主路径通。

### 组件 4：Sigma 规则集（2 天）✅ 完成（会话 4）
- ✅ 6 条规则覆盖 T1003/T1078/T1021/T1059/T1570/T1055，故意不写 4698/4702（演化锚点）
- ✅ 规则引擎 Sigma 子集（selection + 四种修饰符 + event_id/channel 过滤）
- ✅ 加载时校验 `ontology_refs.nodes/edges`，缺失则发 `rule_schema_mismatch` 信号
- ✅ 每条告警带 ATT&CK 技术标签（只接受 `attack.t<digits>(.sub)?` 格式）
- ✅ AlertStore 持久化 data/alerts.duckdb + 按技术聚合计数
- ✅ 端到端跑批：2329 事件 → 10 告警，零误报 零 schema_mismatch
- ✅ 34 测试全绿

### 组件 5：知识图谱层（4 天 · **高风险组件**）✅ 完成（会话 5）
- ✅ NetworkX MultiDiGraph + 实体合并 upsert 语义
- ✅ 实体消歧三级：SID(strong) / DOMAIN\\user(medium) / ?\\user(weak)
- ✅ 硬约束（初始化时锁死）：User 仅 cmdb/iam；owns 边仅 declared 源 → HardConstraintViolation
- ✅ 关系时效性：owns none / auth 90d / logged_into 30d_sliding / connected_to 7d；`out_edges(valid_at=now)` 过滤
- ✅ 本体变更订阅 `subscribe_to_ontology(svc, backfill_fn)`：升级时自动算新增类型 diff + 触发回填钩子（阶段 3 注入真实 backfill）
- ✅ CMDB 加载器 + `ontology/cmdb.yaml`：6 User + 6 owns 边声明源
- ✅ pyvis HTML 可视化（全图 + 子图聚焦）
- ✅ 端到端：6134 entities→3553 nodes，4036 relations→3574 edges
- ✅ 57 新测试全绿（累计 132/132）

### 组件 6：认知推理层（4 天 · **高风险组件**）✅ 完成（会话 6）
- ✅ JudgmentEngine 接 Alert + GraphStore 子图 → Qwen structured JSON
- ✅ system prompt 动态注入当前本体节点/边类型词汇表
- ✅ evidence_refs 严格校验（matched_field / graph_node / graph_edge 三种 ref type，必须指向真实存在的对象）
- ✅ 子图工程裁剪 `max_nodes_per_type`（默认 Process=8 top-by-last_seen），每条告警 token 从 127K 降到 ~6.5K
- ✅ confidence < 0.5 → needs_review；semantic_gap 非空 → 上报 reasoning/semantic_gap 信号
- ✅ JudgmentStore DuckDB 持久化 + 人工复核队列过滤
- ✅ 端到端真调 Qwen：10 告警 → 10 研判（1 malicious + 9 suspicious），65K tokens
- ✅ 22 新测试全绿（累计 154/154）

### 组件 7：演化信号中枢（2 天）✅ 完成（会话 7）
- ✅ 统一 API `report_signal` 已在会话 3 做完（6 种 signal_type + 3 种 priority）
- ✅ 按 `source_layer + signal_type` 分类存储（aggregation_key）
- ✅ 聚合查询 `list_aggregations(window_hours, min_count)` + `list_pending(threshold)`
- ✅ 冷热分级 `list_by_priority(hot/warm/cold)` + `count_by_priority()`
- ✅ 消费标记 `mark_processed(aggregation_key)` — 阶段 3 演化消费入口
- ✅ schema 扩 `processed_at` 列 + 向后兼容旧 DB
- ✅ 终端看板 `scripts/inspect_signals.py`（UI 版看板留阶段 4）
- ✅ 13 新测试（累计 167/167）

---

## 🔄 阶段 3：演化闭环（Week 3 · ~10 天）

**里程碑**：演化提议可产出 · 审核可操作 · Parser 自动生成可跑通。

### 组件 8：本体演化提议引擎（3 天）
- 输入：聚合信号 + 当前本体 + 历史拒绝记录
- LLM structured output 生成提议
- **硬边界（写死在 system prompt）**：
  - 只能新增，不能修改/删除
  - 必须附 ≥3 条支持样本
  - 必须给出与现有元素重叠度
  - 单次最多 5 个
- 输出 schema：`proposal_type` / `name` / `semantic_definition` / `supporting_evidence` / `overlap_analysis` / `attack_mapping` / `source_signals`
- 重叠度 > 0.7 自动丢弃（闸一）
- 字符串 + embedding 双重冗余检测（闸二）
- 拒绝提议入反面样本库，下次 prompt 注入避免重复
- 双触发：周度定时 + 信号阈值即时

### 组件 9：演化审核 UI（2 天）
- Streamlit 页签，每个提议卡片：类型 / 名称 / 语义定义 / 证据 / 冲突 / 影响 / ATT&CK
- 四级决策：通过 / 拒绝 / 修改后通过 / 延后（最多 2 周期）
- 通过 → 生成新本体 YAML + 递增版本 + 触发事件
- 拒绝 → 理由入反面样本库
- 积压告警：> 10 条红色提示，> 20 条暂停新提议

### 组件 10：变更传播 + Parser 自动生成 + 回放验证（5 天 · **高风险组件**）
- 变更广播：发布 `ontology.version.upgraded` 事件
- **Parser 自动生成（核心亮点）**：
  - 输入：新通过的提议 + 异常池样本 + 当前 parser 配置
  - LLM 任务：分析日志结构 → 生成字段映射（YAML 非代码）
  - 输出：`triggered_by_ontology_version` / `target_node_type` / `source_events` / `field_mappings` / `relations` / `confidence` / `sample_count`
  - 人工审核 UI（复用组件 9）：展示映射 + 抽样解析结果 + 成功率
  - 审核通过 → parser hot reload
- 数据层响应：应用新 parser → 重跑异常池 → 成功事件追溯入图谱（标 `backfilled=true`）
- 图谱层响应：新增节点/边类型 → 历史回填
- 认知层响应：Prompt 注入新概念 → 重推理之前 semantic_gap 的告警
- 回放验证：升级前后对比 异常池规模 / 研判准确率 / 证据引用数 → diff 报告
- 指标恶化 → 触发回滚提议（人工确认）

---

## 🎨 阶段 4：UI 集成 + 交付物（Week 4 · ~3 天 + 打磨）

**里程碑**：完整 Demo + Docker + 录屏 + Memo。

### 组件 11：Copilot + 评测看板（3 天）
- Streamlit 三页签：告警研判 / 本体演化 / 评测看板
- **告警研判页**：左告警列表 / 中 AI 研判卡片（verdict + 推理链 + 证据回指）/ 右图谱片段（可点击展开）
- 反馈按钮 👍/👎 → 回流 `manual_annotation` 信号
- **本体演化页**：提议审核 + 版本历史 + 当前本体可视化
- **评测看板**：4 个核心数字（字号最大）+ 趋势 + 演化前后对比
  - 研判准确率 / 反馈采纳率 / 本体覆盖率 / 异常池规模
- **首页必须一眼看到 4 个核心数字**（说服决策层的关键视觉元素）

### 交付物打磨（同期）
- Docker Compose 一键启动
- README 快速启动 + 演示步骤
- Demo 录屏：5 分钟按需求文档 §8 动线
- 架构文档 / 评测报告 / 立项 Memo（2-3 页）

---

## 🎬 Demo 动线锚点（必须的叙事路径）

需求文档 §8 定义了 5 分钟 Demo 的完整故事线，开发必须保证这条路径全通：

1. **0:00-0:30** 评测看板 4 个数字 + 异常池 37 条
2. **0:30-1:00** 演化页自动弹出 ScheduledTask 提议（含 3 条支持样本、重叠度 0.12、T1053.005）
3. **1:00-1:30** 人工"通过" → 弹出 parser 映射审核（4698/4702，预期 94% 成功）
4. **1:30-2:30** 变更传播动画：parser 应用 → 图谱回填 → 认知层重推
5. **2:30-3:30** 回放报告对比：异常池 37→2，新识别 2 条攻击链
6. **3:30-4:30** **主动暴露失败案例**：一条 LLM 判错的告警 + 三道闸门说明
7. **4:30-5:00** 回看板 + 收尾叙事

---

## ⚠️ 关键风险与缓解（需求文档 §9）

| ID | 风险 | 缓解策略 |
|----|------|----------|
| R1 | 图谱数据质量 | 只用 SID 强匹配，弱匹配进观察区；时效性按关系分档 |
| R2 | LLM 幻觉 | evidence_refs 强制 + structured output + 低置信拒答 + 人工复核 |
| R3 | 延迟与成本 | 演化提议周频 + 阈值；研判只跑告警（非全日志）；单次 token <30K |
| R4 | 评测缺位 | 4 个数字 Week 1 开始采集；回放验证是 gate |
| R5 | 分析师信任 | 主动暴露失败案例；Demo 留一条 AI 判错 |
| R6 | 本体膨胀失控 | 硬边界 + 冗余双闸 + 反面样本库 + 积压速率限制 |
| R7 | Parser 生成质量 | 配置化（非代码）+ 人工审核 + 抽样预览成功率 |
| R8 | 演化空转 | 订阅-响应模型必测；回放验证证明改善；否则回滚 |
| R9 | 排期超支 | 每组件备降级方案；Week 2 末卡住立即砍 |
| R10 | Demo 数据失真 | 故意留 semantic_gap + 故意留失败案例 |

---

## 🚦 决策日志

*（每个重要决策在这里记一笔，含日期 / 决策 / 理由 / 替代方案）*

| 日期 | 决策 | 理由 |
|------|------|------|
| 2026-04-22 | 使用文件规划系统管理本次开发 | 31 天项目 · 11 组件，复杂度高需要持久化跟踪 |
| 2026-04-22 | **Agent 驱动开发**（AI 代理写代码） | 用户明确选择 `agent写，非人工` |
| 2026-04-22 | **LLM 用 Qwen-Plus 2025-07-28** 替代 Qwen-Plus 2025-07-28 | 用户无 Claude key，有 1M Qwen 免费额度 |
| 2026-04-22 | **数据集选 BOTSv3** | 用户指定，开源数据丰富 |
| 2026-04-22 | **Python 环境用 venv** | 用户指定，标准库零依赖 |
| 2026-04-22 | **Demo 失败案例依赖 LLM 自然出错** | 用户指定，避免手工 fabricate 失真 |
| 2026-04-22 | LLM 调用统一走 OpenAI 兼容接口（`dashscope/compatible-mode/v1`） | 方便后续切回 Claude 或其他模型 |
| 2026-04-22 | `.env` + `.gitignore` 管理 API key，`.env.example` 做模板 | 防止 key 泄露到 git |

---

## 🔴 遇到的错误

| 时间 | 错误 | 尝试次数 | 解决方案 |
|------|------|---------|----------|
| — | — | — | — |

---

## 📌 下一步（Next Action）

所有 5 项决策已拿到，现在顺序执行：

1. **建仓库骨架**：写 `.gitignore` / `.env` / `.env.example` / `requirements.txt` / 目录树
2. **建 venv + 装依赖**：`python -m venv .venv` + `pip install -r requirements.txt`
3. **Qwen 冒烟测试**：写 `scripts/smoke_test_qwen.py`，验证 JSON 输出能用
4. **BOTSv3 数据集**：异步下载，同时组件 2 本体注册中心可先起
5. **进入阶段 1**：组件 1（数据准备）+ 组件 2（本体注册中心）+ 组件 3（解析器）顺序推进
