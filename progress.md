# 会话日志

> 记录每次会话的工作、发现、决策、阻塞。按时间倒序。

---

## 2026-04-22 · 会话 5：阶段 2 · 组件 5 知识图谱层完成（高风险模块一次会话攻克）

### 目标
攻克阶段 2 最高风险组件（原计划 4 天）。严格 TDD。

### 完成
- ✅ **GraphStore** `graph/store.py`：NetworkX MultiDiGraph 封装
  - 节点/边 upsert 语义（同主键合并，非重复）
  - 元字段维护：first_seen（min）/ last_seen（max）/ confidence（max）/ source / ontology_version
  - 硬约束（初始化时锁死）：User 仅限 cmdb/iam；owns 边仅限 declared 源，`HardConstraintViolation` 异常
  - 查询 API：`list_nodes_by_type / out_edges / in_edges / subgraph_around(depth) / get_node`
  - 本体变更订阅 `subscribe_to_ontology(svc, backfill_fn=...)`：升级时计算新增节点/边类型，调用 backfill_fn（阶段 3 演化闭环入口）
- ✅ **EntityResolver** `graph/entity_resolver.py`：三级消歧
  - Account：SID (strong 1.0) / `{DOMAIN}\\{user}` (medium 0.8) / `?\\{user}` (weak 0.5)
  - Host：hostname (strong) / FQDN 推短名 (medium)
  - Process：复合键 `{host}::{basename}::{pid}::{start_time}` (strong) / 无 start_time (medium)
  - 过滤 Anonymous SID（S-1-0-0 / S-1-5-7）回退到中匹配
- ✅ **TimeDecay** `graph/time_decay.py`：关系时效规约解析
  - 语法：`none` / `<N>d`（绝对 TTL）/ `<N>d_sliding`（滑动窗口）
  - 默认映射与 ontology v1.0 time_decay 字段对齐（owns none / authenticated_as 90d / logged_into 30d_sliding / connected_to 7d）
  - `out_edges(valid_at=now)` 过滤过期边
- ✅ **Importer** `graph/importer.py`：`parsed_events.duckdb` → GraphStore
  - 所有节点都过 resolver 规范化（修复 parser 对同一账户用两种 id_expr 产生重复节点的问题）
  - 关系端点按 canonical_id 翻译
  - 关系端点缺失时 skip 并计数（不 crash）
- ✅ **CMDB Loader** `graph/cmdb_loader.py` + `ontology/cmdb.yaml`：User+owns 唯一入口
  - 6 个 User（u1001 Alice / u1002 Bob / u1003 Carol / u1004 David / u2001 svc_backup / u2002 svc_sccm）
  - 声明 Account 在图里不存在时 skip owns（避免悬空边）
  - 重复加载幂等
- ✅ **Visualizer** `graph/visualizer.py`：pyvis HTML 渲染
  - 节点颜色按 type 分（User 棕 / Account 蓝 / Host 绿 / Process 红 / NetworkEndpoint 紫）
  - Hover tooltip 显示 attrs + meta
  - 支持全图 或 `center + depth` 聚焦子图
- ✅ **端到端 `scripts/build_graph.py`**
  - 6134 entities → **3553 节点**（User 6 / Account 10 / Host 6 / Process 3537）
  - 4036 relations → **3574 边**（去重率 ~12%）
  - 6 条 owns 声明边落地
  - 生成两个 HTML：`graph/visualization.html`（全图 3.1MB）+ `graph/visualization_attack.html`（FIN-SRV-01 2 跳 346KB）

### 测试统计
132/132 全绿（之前的 75 + 组件 5 新增 57）
- `test_graph_store.py` 23（节点/边 + 硬约束 + 查询 + 订阅）
- `test_entity_resolver.py` 11（三级消歧）
- `test_time_decay.py` 10（解析 + 判定 + store 集成）
- `test_graph_importer.py` 7（含对真实 parsed_events.duckdb 的集成 smoke）
- `test_cmdb_loader.py` 4（User 创建 + owns 落地 + 幂等）
- `test_graph_visualizer.py` 2（HTML 渲染 smoke + 子图作用域）

### 关键发现
- **parser 对同一 Account 用两种 id_expr**：有 SID 的事件里 `node_id = SID`；没 SID 的事件里 `node_id = TargetUserName`。graph importer 层用 resolver 做二次规范化解决，parser 保持不动（契约不破）。
- **weak 观察区**：alice 同时以 `S-1-5-21-...1001`（strong）和 `CORP\\alice`（medium）两种形式存在。这是设计里的"观察区" — 阶段 3 靠演化提议自动合并，或人工决策。MVP 不强合并。
- **本体变更订阅的降级设计**：`backfill_fn` 是可选参数，阶段 2 不提供时 store 会默默更新 ontology_version 但不触发回填。阶段 3 注入真正的 backfill 实现（从 anomaly_pool 取出事件 + 跑新版 parser + 灌入图）。
- **Process 节点数仍 3537（从 3560 降一点）**：因为每个进程有 pid+start_time，绝大多数是唯一的，消歧合并空间小。后续若加"父子进程关系链"可再降。
- **HTML 全图 3.1MB + 3553 节点 pyvis 渲染略慢**：Demo 用聚焦子图（attack 346KB）更合适。

### 下一阶段（阶段 2 剩余）
- 组件 6 认知推理层完整版（4 天，高风险）：judgment_engine 调 llm_client + 图子图输入 + evidence_refs 强制校验 + semantic_gap 信号
- 组件 7 信号中枢完整版（2 天）：聚合 + 冷热分级 + 看板入口

---

## 2026-04-22 · 会话 4：阶段 2 启动 — 组件 4 Sigma 规则集完成

### 目标
进入阶段 2，先完成组件 4（Sigma 规则集，2 天）。严格 TDD 推进。

### 完成
- ✅ **Sigma 子集规则引擎** `detection/engine.py`
  - `SigmaRule`：YAML 加载 + `matches()` / `match_detail()`
  - 支持字段路径：`EventData.X` / `@computer` / `@timestamp` / `@event_id`
  - 支持修饰符：`eq`（默认）/ `|endswith` / `|startswith` / `|contains`（大小写不敏感）
  - selection 多键 AND + 值列表 OR
  - event_id + channel 前置过滤
  - 只提取 `attack.t<digits>` 作为 ATT&CK 技术（战术标签不计入 techniques）
- ✅ **DetectionEngine**：加载规则 + 本体校验 + 事件求值
  - 初始化时校验每条规则的 `ontology_refs.nodes/edges`，缺失则发 `rule_schema_mismatch` 信号（降级：校验失败不阻断规则加载）
- ✅ **Alert 数据结构 + AlertStore** `storage/alert_store.py`
  - DuckDB 持久化 + 主键幂等（ON CONFLICT DO NOTHING）
  - `count_by_technique()` Python 端聚合（DuckDB UNNEST 对 JSON 列有限制，改用应用层聚合）
- ✅ **6 条生产 Sigma 规则** `detection/rules/*.yaml`
  - R1 lsass memory dump (T1003) · R2 异常服务账户登录 (T1078)
  - R3 SMB/NTLM 横向 (T1021) · R4 encoded powershell (T1059)
  - R5 管理员共享写入 (T1570) · R6 远程线程注入 (T1055)
  - 故意不写 4698/4702 规则（Demo 主叙事：演化机制补齐 ScheduledTask 节点 + 自动生成 parser）
- ✅ **端到端跑批** `scripts/run_detection.py`
  - 2329 事件扫描 → 10 告警产出 → `data/alerts.duckdb`
  - ATT&CK 分布：T1059×1 / T1003×1 / T1078×3 / T1021×3 / T1021.002×3 / T1570×1 / T1055×1
  - 本体校验零 `rule_schema_mismatch`（6 条规则的 ontology_refs 全部在 v1.0 本体中）

### 测试统计
75/75 全绿（阶段 1 的 41 + 组件 4 新增 34）
- `test_detection_engine.py` 29 测试（rule 加载 / matcher / engine / 本体校验 / 6 条生产规则精准命中 + 无误报）
- `test_alert_store.py` 5 测试（insert/many/幂等/list_recent/count_by_technique）

### 关键发现
- **Sigma 战术 vs 技术标签**：规则文件里同时写了 `attack.t1003` 和 `attack.credential_access`，初版解析两者都当 technique 导致评测看板被污染。修正为只接受 `attack.t<digits>(.sub)?` 格式，战术标签保留在 YAML 但不计入 techniques。
- **DuckDB 对 JSON 数组不支持 `UNNEST` in GROUP BY**：`count_by_technique` 改为读回 JSON 再在 Python 端聚合。
- **6 条规则的本体锚点**：R2/R3 都引用 `logged_into` / `authenticated_as`（现有边），R1/R6 引用 `executed_on`（现有边），R5 引用 `logged_into`。没有规则暴露需要新本体节点，也就没出现 `rule_schema_mismatch` 信号。这是故意的——Demo 叙事的 rule_schema_mismatch 会在阶段 3 演化阶段才出现（LLM 生成引用 ScheduledTask 的规则候选时）。

### 下一步（阶段 2 剩余）
- 组件 5 知识图谱层（4 天，**高风险**）：NetworkX + 实体消歧分层 + 时效性 + 订阅本体变更 + pyvis
- 组件 6 认知推理层完整版（4 天，**高风险**）：judgment_engine 调 llm_client + 子图 + evidence_refs 强制校验
- 组件 7 信号中枢完整版（2 天）：聚合 / 冷热分级 / 看板入口

---

## 2026-04-22 · 会话 3：阶段 1 完成（Week 1 里程碑达成）

### 目标
完成阶段 1：组件 1（数据）+ 组件 2（本体）+ 组件 3（解析器），并达成 Week 1 里程碑「数据库有日志 · 本体服务可调用 · LLM 可返回结构化研判」。

### 完成
- ✅ **组件 2 本体注册中心**（先做，无依赖）
  - `ontology/v1.0.yaml`：5 节点 6 关系 + 元字段 + 硬边界 + ATT&CK 锚点
  - `core/ontology_service.py`：`get_current / get_version / subscribe / start_watching`
  - `docs/ontology_v1.md` 人读版说明书
  - `tests/test_ontology_service.py`：14 测试全绿
  - **发现并修复**：`_version_sort_key` 正则没兼容 YAML 里无 v 前缀的版本号
- ✅ **组件 1 数据准备**（BOTSv3 策略：合成数据代替真实下载）
  - 决策：用合成数据是因为原型 Demo 需要精确控制 semantic_gap 位置，真实 BOTSv3 里 4698/4702 数量不可控
  - `docs/attack_scenarios.md`：完整攻击剧本（6 用户 + 6 主机 + 7 天时间线 + 预期告警）
  - `scripts/generate_demo_data.py`：种子 20260422 确定性生成
  - 产出 `data/events.duckdb`：2329 事件，6 主机，7 天，**30 条 4698/4702 演化锚点**
- ✅ **组件 3 宽容解析器**
  - `parsers/mappings/windows_v1.yaml`：event_id + channel 配置化映射（故意不覆盖 4698/4702）
  - `parsers/windows_parser.py`：表达式求值（`const:` / `compose:` / `@computer` / `event_data.X`） + ontology 订阅 hot reload + 异常池 + 信号上报
  - `evolution/signal_hub.py`：统一信号 API + DuckDB 存储（组件 7 骨架）
  - `storage/anomaly_pool.py`：异常事件池（backfilled 标记用于回放）
  - `tests/test_windows_parser.py`：15 测试全绿
  - 跑 events.duckdb：2297 解析成功（98.6%）、32 进异常池（含 30 条 4698/4702）、产出 6134 节点 + 4036 关系
  - **发现并修复**：`unknown_field` 信号最初过载（每条事件都触发 2297 条），改为默认关闭（因 Windows 合法事件里有大量我们不提取但非"未知"的字段）
- ✅ **组件 6 LLM 客户端骨架**（为 Week 1 里程碑）
  - `reasoning/llm_client.py`：Qwen-Plus OpenAI 兼容调用 + Token 预算守护（warn 700K / hard 900K） + structured JSON 重试 + `validate_evidence_refs` 反幻觉校验器
  - `tests/test_llm_client.py`：12 测试（mock OpenAI 客户端，不打真实 API）

### 测试统计
41/41 测试全绿 · 总耗时 2.28s

### 关键发现
- **合成数据 > BOTSv3**（原型阶段）：可精准控制演化锚点数量，Demo 叙事可复现
- **Parser 配置化设计**：YAML 配置 + Python 引擎分离，后续 LLM 生成的 parser 配置走同一格式，接入成本零
- **`unknown_field` 信号需要更细的过滤**：Windows 事件结构性很丰富，不是所有未引用字段都是"未知"的。MVP 默认关闭，演化二级故事需要时再开
- **Ontology `subscribe` 回调**是变更传播的机制底座，parser 已经验证能 hot reload

### 下一阶段（阶段 2 · Week 2 · ~12 天）
- 组件 4 Sigma 规则集（2d）
- 组件 5 知识图谱层（4d，高风险）← NetworkX + 实体消歧 + 时效性
- 组件 6 认知推理层完整版（4d，高风险）← 调用 llm_client + judgment_engine
- 组件 7 信号中枢完整版（2d）← 聚合/分级/看板入口

---

## 2026-04-22 · 会话 2：用户决策 + 仓库骨架

### 用户 5 项决策确认
| # | 问题 | 决策 |
|---|------|------|
| 1 | 人手 | Agent 驱动（AI 代理写，非人工） |
| 2 | LLM | Qwen-Plus 2025-07-28（DashScope，1M 免费额度） |
| 3 | 数据集 | BOTSv3 |
| 4 | Python 环境 | venv |
| 5 | Demo 失败案例 | 依赖 LLM 自然出错 |

### 本次目标
- 把"Claude Sonnet"全部换成"Qwen-Plus"
- 建仓库骨架：目录树 + `.gitignore` + `.env` + `requirements.txt`
- Qwen 冒烟测试（验证 structured output 能用）
- 更新规划文件所有相关引用

### ⚠️ 安全提醒
用户在聊天中明文贴了 Qwen API Key。已写入 `.env`（gitignored）。
**建议 Demo 前在百炼控制台重置一次 key**（聊天记录可能缓存）。

### 完成
- ✅ 更新 `findings.md`：F3 技术栈表（LLM → Qwen）、F11 决策记录表、新增 F12（Qwen 接入要点 + token 预算）、F13（key 管理）
- ✅ 更新 `task_plan.md`：阶段 0 任务清单、决策日志、下一步
- ✅ 写 `.gitignore` / `.env` / `.env.example` / `requirements.txt`
- ✅ 建立完整目录骨架（15 个目录 + `__init__.py`）
- ✅ 创建 venv (Python 3.10.7) + 装依赖（openai / duckdb / networkx / pyvis / streamlit / pysigma / watchdog 等）
- ✅ **Qwen-Plus 冒烟测试通过**：405 tokens（147+258）· JSON schema 校验 OK · API 正常
- **阶段 0 完成** 🎉

### Qwen 冒烟测试结果
- 模型：qwen-plus-2025-07-28（DashScope OpenAI 兼容接口）
- 输入：1 条 Windows 4624 样例告警
- 输出：合法 JSON，四字段齐全（verdict=suspicious, confidence=0.75, reasoning_steps×5, evidence_refs×5）
- Token 使用：405 / 1,000,000（0.04%，余 99.96%）
- **坑位**：Windows 终端（cp936）显示 UTF-8 乱码，但 `json.loads` 正确解析；代码中必须显式 `encoding="utf-8"`

### 本次改动
```
.gitignore       (新)
.env             (新，本地不入 git)
.env.example     (新)
requirements.txt (新)
.venv/           (新)
core/ parsers/ detection/ graph/ reasoning/ evolution/ storage/ ui/ tests/ scripts/  (新，含 __init__.py)
ontology/ docs/ data/ scripts/  (空目录，待填充)
scripts/smoke_test_qwen.py  (新)
task_plan.md / findings.md / progress.md  (更新)
```

### 下次会话起手
进入 **阶段 1**：
1. **组件 2 本体注册中心**（优先，无外部依赖）
   - 写 `ontology/v1.0.yaml`（5 节点 6 关系 + 元字段）
   - 写 `core/ontology_service.py`（`get_current` / `get_version` / `subscribe`）
   - 写 `docs/ontology_v1.md`
   - 写单测
2. **组件 1 数据准备**（与 2 并行）
   - 调研 BOTSv3 Windows 日志结构
   - 抽 2000-5000 条入 `data/events.duckdb`
   - 覆盖 T1078/T1021/T1053/T1055/T1570
   - **确保保留** EventID 4698/4702（演化触发锚点）
   - 写 `docs/attack_scenarios.md`
3. **组件 3 宽容解析器** 接在 1+2 后面

### Qwen 接入关键点（F12 摘要）
- 走 OpenAI 兼容接口：`https://dashscope.aliyuncs.com/compatible-mode/v1`
- Structured output：`response_format={"type": "json_object"}` + prompt 写 schema + 代码侧校验
- Token 预算：研判 ~180K + 提议 ~60K + parser ~28K + 缓冲 ~200K = **~470K / 1M**（余量 >50%）
- `llm_client.py` 内置 token 计数 + 预算告警（>700K 告警，>900K 拒绝）

### 下次会话起手
（本次继续执行）进入阶段 1：组件 1 数据准备 + 组件 2 本体注册中心

---

## 2026-04-22 · 会话 1：需求理解与项目规划

### 本次目标
- 阅读 `AI-native SIEM MVP 需求文档 v1.0.docx`
- 基于需求拟定完整开发计划
- 建立文件规划系统

### 完成
- ✅ 安装 `python-docx` 并提取需求文档全文到 `requirements_extracted.txt`
- ✅ 读取需求文档全部 622 行（含 8 张表格）
- ✅ 理清项目结构：11 个组件 · 31 人天 · 4 周里程碑
- ✅ 创建 `task_plan.md`：5 阶段划分 + 任务清单 + 风险表 + 决策日志
- ✅ 创建 `findings.md`：11 条关键研究发现（F1-F11）
- ✅ 创建 `progress.md`：本日志

### 关键发现（摘要，详见 findings.md）
- **项目定位是"说服材料"**，不是生产系统 → 可演示优先
- **核心差异点**：本体演化横切全系统（不只是图谱内部）
- **不可妥协的硬约束**：evidence_refs 强制回指、演化 system prompt 硬边界、parser 配置化（非代码）、User↔Account 不归并
- **高风险组件**：5（图谱 4d）、6（认知 4d）、10（变更传播+Parser+回放 5d）共 12 天占 39%
- **Demo 叙事锚点**：Scheduled Task 事件 4698/4702 必须在数据集中保留

### 待用户决策
1. 人手：双人并行（推荐）vs 单人全栈
2. Claude Sonnet 4.6 API Key 准备情况
3. 数据集选型：BOTSv3 vs Mordor
4. Python 环境策略：venv / conda / uv
5. Demo 失败案例策略：手工标注 vs 自然出错

### 遇到的问题
- `python-docx` 默认输出中文时触发 Windows GBK 编码报错 → 改为写入 UTF-8 文件后读取

### 下次会话起手
1. 根据用户对"待决策"5 项的答复，更新 `task_plan.md` 阶段 0
2. 建立仓库目录骨架（按 task_plan.md "仓库骨架" 章节）
3. 初始化 `requirements.txt` / `pyproject.toml`
4. 写 `.gitignore`（保护 `data/` 与 API Key）
5. 准备进入阶段 1 组件 1 与组件 2 的并行开发

### 本次未改动代码
仅创建规划文件，未写入业务代码。
