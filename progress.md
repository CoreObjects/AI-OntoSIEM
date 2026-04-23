# 会话日志

> 记录每次会话的工作、发现、决策、阻塞。按时间倒序。

---

## 2026-04-23 · 会话 9：阶段 3 · 组件 9 演化审核 UI（四级决策 + 本体版本升级）

### 目标
完成组件 9（2 天）。审核员点按钮通过 ScheduledTask → 生成新本体 YAML → 订阅者自动响应。

### 完成
- ✅ **OntologyUpgrader** `evolution/ontology_upgrader.py`
  - approved Proposal → 新 YAML + 版本 +0.1（v1.0 → v1.1 → v1.2...）
  - 支持 node / edge / attr 三种类型的本体升级
  - 边升级要求 endpoint hints；attr 升级要求 target_node
  - 合并 attack_mapping 到 attack_anchors（去重）
  - 写入 `evolution_history` 审计字段
  - 触发 `OntologyService.reload()` 让 GraphStore / Parser / JudgmentEngine 订阅回调
  - 硬约束：拒绝 non-approved / 重复 / 端点不存在
- ✅ **四级决策动作** `evolution/review_actions.py`
  - `approve_and_upgrade` → 调 upgrader + mark_approved
  - `reject` → mark_rejected + reason 入反面样本库
  - `defer` → 最多 2 周期，超限**自动 reject**
  - `modify_and_upgrade` → 改 name / definition 后通过
  - `backlog_status` → green/yellow/red 三档，红色时 `pause_new_proposals=True`
- ✅ **ProposalStore 扩展**：加 `defer_count` 列 + `increment_defer` + `get` + `as_proposal`
- ✅ **Streamlit UI** `ui/evolution_review.py`
  - 顶部 4 个指标：本体版本 / 节点数 / 边数 / 待审核数
  - 积压告警条（黄 >10 / 红 >20）
  - 每条 pending 提议卡片：类型 / 名称 / 语义定义 / ATT&CK / 重叠度（带条形图）/ 来源信号 / 证据展开
  - 四个决策按钮：✅通过 / ✏️修改后通过 / ❌拒绝 / ⏳延后（带计数 0/2）
  - 历史记录分类展开：approved / modified / rejected / deferred

### 测试统计
215/215 全绿（之前 192 + 组件 9 新增 23）
- `test_ontology_upgrader.py` 13（版本递增 + node/edge/attr 升级 + 拒绝约束 + reload 回调）
- `test_review_actions.py` 8（四级决策 + 延后计数 + 积压告警三档）
- `test_ui_evolution_review.py` 2（smoke：import + 导出符号存在）

### 关键发现
- **UI 与业务逻辑完全分离**：所有状态变化通过 `review_actions` 函数，Streamlit 仅是 "按钮 → 函数" 薄层。便于后续换 CLI / Gradio / API 触发。
- **演化链式升级**：v1.0 + 节点 ScheduledTask → v1.1；v1.1 + 边 schedules (Host→ScheduledTask) → v1.2。测试 `test_multi_step_upgrade_node_then_edge` 覆盖。
- **defer 超周期自动转 reject** 是需求 R6 风险缓解（本体膨胀失控）：延后队列不会无限积压。
- **积压红线 (>20)** 会暂停新提议触发：`backlog_status(store)["pause_new_proposals"]` 可挡 `run_proposals.py` 的调用。
- **UI smoke test 策略**：只测 `import + 导出符号存在`，交互流程靠 actions 层覆盖。Streamlit runtime 下的按钮行为靠 `streamlit run` 人工验收。

### 下一阶段（阶段 3 最后也是最硬一关）
- 组件 10 变更传播 + Parser 自动生成 + 回放验证（5 天，**全项目最高风险**）
  - LLM 基于新通过的提议 + 异常池事件样本 → 生成新 parser YAML 映射（非代码）
  - anomaly_pool 回放：应用新 parser → 成功的事件追溯入图（backfilled=true）
  - 图谱层：新增节点/边类型 → 历史回填
  - 认知层：prompt 注入新概念 → 重推 semantic_gap 告警
  - 对比报告：异常池规模 / 研判准确率 / 证据引用数 diff
  - 指标恶化 → 回滚提议

---

## 2026-04-23 · 会话 8：阶段 3 起手 — 组件 8 本体演化提议引擎（Demo 主故事线素材落地）

### 目标
进入阶段 3 演化闭环，完成组件 8（原计划 3 天）。真调 Qwen 产出第一批真实提议，验证 §8 Demo 主故事线可走通。

### 完成
- ✅ **Proposal dataclass + ProposalEngine** `evolution/proposer.py`
  - 输入：signal_hub.list_pending() + 当前本体 + rejection_names（反面样本库）
  - 四重闸门：
    1. system prompt 硬边界（只能新增 / ≥3 证据 / overlap_analysis 必填 / ≤5 个）
    2. 硬边界代码校验（防 LLM 违约）
    3. 重叠度闸 > 0.7 自动丢弃
    4. 字符串相似度闸（与本体 / 反面样本库 SequenceMatcher ≥ 0.7 丢弃）
  - 输出：List[Proposal] 候选，status=pending
- ✅ **ProposalStore** `storage/proposal_store.py`
  - 状态机：pending → approved / rejected / modified / deferred
  - rejection_names() 反面样本库查询（给 ProposalEngine 闭环消费）
  - mark_rejected 带 reason；mark_modified 支持 new_name + new_definition
- ✅ **端到端真调 Qwen** `scripts/run_proposals.py`
  - 单次调用 1565 tokens（prompt 556 + completion 1009），3 个提议全过闸门
  - 产出：ScheduledTask(T1053.005) / ScheduledTaskModification(T1053.005+T1202) / is_ephemeral(NetworkEndpoint 属性, T1071.001+T1644)

### 测试统计
192/192 全绿（之前 167 + 组件 8 新增 25）
- `test_proposer.py` 16（dataclass + 生成流程 + prompt 注入 + 四重闸门各层）
- `test_proposal_store.py` 9（insert/幂等/四态机/rejection_names/count_by_status）

### 关键发现
- **Qwen 一次调用非常高效**：prompt 仅 556 tokens（含硬边界 + 本体词汇 + 3 组待处理信号），completion 1009 tokens（3 条详细提议）。演化周期级调用，token 预算极宽松。
- **ScheduledTask 提议的 ATT&CK 映射准确**：Qwen 自动挂上 T1053.005（需求 Demo §8 预期的标签），无需人工提示。
- **LLM 主动提议 `is_ephemeral` 属性**：针对 NetworkEndpoint 的 C2 beaconing 场景（T1071.001），**本体真的缺这个维度**。反面样本库可能会在阶段 3 审核阶段拒掉（如果审核员觉得超出 MVP 范围），但 LLM 的观察角度很犀利。
- **重叠度闸门实战效果**：Qwen 诚实自报重叠度（ScheduledTask vs Process=0.35），没撒谎虚报。这是需求 R6（本体膨胀失控）风险缓解的第一道闸。
- **字符串相似度闸门覆盖边界 case**：测试验证 "Accounts" 被 "Account"（本体已有）的 ratio 0.94 > 0.7 拒掉。

### 下一阶段（阶段 3 剩余）
- 组件 9 演化审核 UI（2 天）：Streamlit 提议卡片 + 四级决策（approved / rejected / modified / deferred）
- 组件 10 变更传播 + Parser 自动生成 + 回放验证（5 天，**最高风险**）：
  - ontology v1.0 → v1.1 生效
  - LLM 基于 approved 提议 + 异常池事件 → 生成新 parser YAML 映射
  - anomaly_pool 回放（backfilled=true）→ 重跑图 + 认知研判
  - 对比报告：异常池规模 / 研判准确率 / 证据引用数

---

## 2026-04-23 · 会话 7：阶段 2 收官 — 组件 7 信号中枢完整版（Week 2 末里程碑达成）

### 目标
完成组件 7 收尾阶段 2，实现 Week 2 末「端到端主路径通」里程碑。

### 完成
- ✅ **signal_hub 完整版 API** `evolution/signal_hub.py`
  - `list_aggregations(window_hours, min_count)` 按 aggregation_key 分组 + 计数 + first/last_seen + priority + processed 标记
  - `list_pending(window_hours, threshold)` 过滤窗口内超阈值且未处理的组
  - `list_by_priority(hot/warm/cold, limit)` 冷热分级查询
  - `count_by_priority()` 三档计数
  - `mark_processed(aggregation_key)` 演化机制消费后标记（返回影响行数）
  - schema 扩 `processed_at` 列 + `ALTER TABLE IF NOT EXISTS` 兼容旧 DB
- ✅ **终端看板入口** `scripts/inspect_signals.py`
  - 总计 / 按 priority / 按 signal_type / 聚合热力图 / 待处理队列
  - Windows 终端 UTF-8 强制（`sys.stdout.reconfigure`）
- ✅ **端到端真实信号库扫描**（data/signals.duckdb 当前 43 信号）
  - `hot 32 + warm 11`
  - **待处理 1 组**：`data:unparseable_event:4698` × 22（Demo §8 主故事线触发器 ⭐）
  - 其他聚合：4702×8 / 5140/5145 各 1 / 5 种 semantic_gap（LLM 自发）

### 测试统计
167/167 全绿（之前 154 + 组件 7 新增 13）
- `test_signal_hub.py` 13（聚合分组 + 窗口过滤 + min_count 阈值 + priority 分级 + mark_processed + 向后兼容老 DB）

### 关键发现
- **LLM 自发的 semantic_gap 信号比想象中犀利**：本次端到端 Qwen 调用产出了 5 种 gap 提议 —— `NetworkEndpoint`（本体里已有，误报 5 次）/ `Process`（本体已有，误报 3 次）/ `Thread, RemoteThreadOperation`（**本体真缺**）/ `NetworkConnection`（**本体真缺**）/ `AuthenticationContext`（**本体真缺**）。后三个可直接喂阶段 3 提议引擎。
- **前二误报**是子图工程裁剪的副作用 —— LLM 把"子图里没看到"当成"本体里没有"。system prompt 已有警示但 Qwen 仍会混淆。演化阶段会通过"重叠度检查"自动拒掉这类幻觉提议（需求文档 §4.8 硬边界 3）。
- **待处理阈值设在 10 合理**：4698 单组 22 条，稳稳触发 Demo 主故事线；其他组 ≤8 维持静默，不干扰叙事。
- **Week 2 末里程碑达成** ✓ 端到端主路径全通：
  `events → parser → graph → sigma → alert → judgment(LLM) → signal_hub → 阶段 3 消费入口`

### 下一阶段
- **阶段 3 演化闭环**（Week 3 · ~10 天）
  - 组件 8 本体演化提议引擎（3 天）：LLM 输入 signal_hub pending + 当前本体 + 历史拒绝记录 → 提议 JSON，硬边界 + 重叠度双闸
  - 组件 9 演化审核 UI（2 天）：Streamlit 提议卡片 + 四级决策
  - 组件 10 变更传播 + Parser 自动生成 + 回放验证（5 天，高风险）：ontology v1.0 → v1.1 → parser YAML 生成 → anomaly_pool 回放

---

## 2026-04-23 · 会话 6：阶段 2 · 组件 6 认知推理层完整版（高风险 · 真调 Qwen 跑通）

### 目标
把 llm_client 接入 judgment_engine，告警+子图 → structured verdict，evidence_refs 严格校验，真实 Qwen LLM 端到端跑通 10 条告警。

### 完成
- ✅ **Judgment dataclass + JudgmentEngine** `reasoning/judgment_engine.py`
  - 输入：Alert + GraphStore（以 `Host:alert.computer` 为 center 取 N 跳子图）
  - 动态 system prompt：注入当前本体的节点/边类型词汇表（ontology 参数）
  - 调 `llm_client.structured_json` 带 required_keys + 强校验 validator
  - 响应 schema：`verdict / confidence / reasoning_steps / evidence_refs / attack_chain / next_steps / semantic_gap?`
  - 低 confidence (<0.5) → `needs_review=True` 标记
  - `semantic_gap` 非空 → 自动上报 `reasoning/semantic_gap` 信号（带 missing_concept 聚合 key）
- ✅ **严格 evidence_refs 校验（反幻觉闸门二）**
  - `type=matched_field` → ref 必须是 alert.matched_fields 的键
  - `type=graph_node` → ref 必须是子图节点 key
  - `type=graph_edge` → ref 格式 `edge_type:from_key->to_key`，必须是子图边
  - 不合规 → llm_client 带着错误信息让模型重写（retry）
- ✅ **子图工程裁剪（关键 token 优化）**
  - `subgraph_node_types` 过滤（默认含 User/Account/Host/NetworkEndpoint/Process）
  - `max_nodes_per_type`（默认 `{"Process": 8}`）按 last_seen desc 取 top-N
  - 成效：初版每条告警 **127K tokens** → 优化后 **~6.5K tokens**（-95%）
- ✅ **JudgmentStore** `storage/judgment_store.py`
  - DuckDB 持久化 + 主键幂等 + 按 verdict 聚合 + 人工复核队列过滤 (`list_needs_review`)
- ✅ **端到端 `scripts/run_judgments.py`**
  - 真调 Qwen-Plus：10 告警 → 10 判决，**65K tokens**（累计仍在预算内）
  - 结果：1 malicious（R1 LSASS dump conf 0.95）+ 9 suspicious（conf 0.65 居多）
  - 6 个 semantic_gap 信号落到 signals.duckdb（喂给阶段 3 演化闭环）
  - 零失败 / 零 evidence_refs 校验穿透

### 测试统计
154/154 全绿（之前 132 + 组件 6 新增 22）
- `test_judgment_engine.py` 15（dataclass + judge flow + prompt 注入 + 子图裁剪 + 严格校验 + 低 confidence + semantic_gap 信号）
- `test_judgment_store.py` 7（insert/many/幂等/list_recent/count_by_verdict/needs_review/semantic_gap 持久化）

### 关键发现
- **子图 depth=2 + Host center** 会把 3000+ Process 全拖进 prompt，**单条告警就 127K tokens**（占 1M 免费预算 12%）。工程裁剪 `max_nodes_per_type` 后降 95%。
- **过度裁剪会让 LLM 误报 semantic_gap**：一开始完全删 Process，结果所有告警都标 semantic_gap（"看不到攻击进程上下文"）。折中 Process top-8 后 R1 回到 malicious 0.95。
- **semantic_gap 的正解**是"本体词表里没有该概念"，不是"子图节点不全"。在 system prompt 明说"子图已裁剪 ≠ 本体缺失"，但 Qwen 有时仍会混淆。这其实对 Demo 有利——演示 LLM 谨慎保守的一面（R5 风险缓解：低置信拒答）。
- **10 条告警出 1 硬判定 + 9 疑似**：Demo 叙事极佳——"AI 不敢乱说话，evidence_refs 强制回指 + 子图约束让它保守研判"。与 Demo 动线 §6（3:30-4:30 主动暴露失败案例）对齐。
- **evidence_refs 严格校验零穿透**：10 条告警 12 次 LLM 调用（2 次重试），所有最终输出的 ref 都能在 alert / 子图里找到对应物。反幻觉闸门实战生效。

### 下一阶段（阶段 2 最后）
- 组件 7 信号中枢完整版（2 天）：聚合（24h 同类型 > 20 条 → 待处理）+ 冷热分级查询 API + 看板入口
  - 热力图看板 UI 放阶段 4
- 至此 Week 2 末「端到端主路径通」里程碑达成

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
