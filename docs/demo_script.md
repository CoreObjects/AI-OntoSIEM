# AI-OntoSIEM 5 分钟 Demo 录屏剧本

> **录屏目标**：5 分钟内说清楚三件事 ——
> (1) 真能跑（端到端 Windows 日志 → AI 研判）
> (2) 比现状好（4 个核心数字可量化）
> (3) **有自我演化能力**（异常池 → 提议 → 审核 → 本体升级 → Parser 自动生成 → 回放验证 → 评测对比）
>
> **核心叙事**：演化机制是横切层。当 LLM 遇到本体盲区，整个系统会协同演化 ——
> 不只是图谱内部加几个节点。
>
> **录屏前置**：
> - 已跑过 `generate_demo_data` / `run_parser` / `run_detection` / `run_judgments` / `run_proposals`
> - 当前本体回到 v1.0（删 `ontology/v1.1*.yaml`）+ proposals 全部 pending + 异常池全 open
> - 数据库幂等重置脚本可参考 `scripts/replay_anomaly_pool.py` 里的 `pool.reset_backfilled()`
>
> 时间线精确到秒；解说词用第一人称（"我"）即可，不要念稿感。

---

## 0:00 - 0:30 · 评测看板（说服决策层的开场）

**画面**：浏览器打开 `http://localhost:8501`，停留在默认 tab "📊 评测看板"。

**操作**：仅展示，不点击。

**焦点**：4 个大字号 metric。

**解说**：
> 这是 AI-OntoSIEM 原型的首页。决策层最关心的 4 个数字一眼可见 ——
> 研判准确率 50%、反馈采纳率 0%（还没人点过）、本体覆盖率 99.6%、
> **异常池规模 32**。
>
> 异常池是这个系统的"本体盲区温度计"：32 条事件目前的本体没法建模。
> 看左下角拆分 —— 22 条 4698（Scheduled Task 创建）+ 8 条 4702（修改）+
> 5140 / 5145 各 1 条。这 22 条 4698 就是今天演化故事的起点。

---

## 0:30 - 1:00 · 演化页 · 提议审核

**画面**：点击"📐 本体演化" tab → 默认子 tab "🆕 提议审核"。

**焦点**：3 张 pending 提议卡片，重点看 ScheduledTask 节点提议。

**解说**：
> 系统已经在前一天的批处理（`scripts/run_proposals.py`）里调 Qwen 提了 3 条本体新增建议。
> 重点是这条 ★：**新增 ScheduledTask 节点** ——
>
> - 类型：node
> - 语义定义：Windows 计划任务条目
> - 支持证据：3 条 4698 事件采样（TaskName / TaskContent 等字段）
> - 重叠度分析：与现有 Process 0.35、Account 0.05 —— LLM 自报，没虚高
> - ATT&CK 映射：T1053.005 —— 没人提示，LLM 自动挂上
>
> 三道闸门已自动验过：硬边界（只能新增）+ 重叠度 < 0.7 + 字符串相似度
> 与本体/反面样本库 < 0.7。LLM 提议后，决策权在这位审核员。

**操作**：点击 "✅ 通过" 按钮（在 ScheduledTask 卡片）。
弹窗成功 → 当前本体版本立即从 v1.0 跳 v1.1 → 顶部 banner 实时刷新。

**解说**：
> 通过的瞬间，**整个系统的本体服务广播变更** —— 这是横切层的第一次发力。
> 顶部 banner 已经从 v1.0 变 v1.1。

---

## 1:00 - 1:30 · 候选 Parser · 自动生成 + 抽样回放

**画面**：切到子 tab "🔧 候选 Parser"，点【🤖 生成候选 Parser】按钮（真调 Qwen ~3K，~15 秒），候选当场出现。

**焦点**：候选 parser 卡片，rules 展开 + 🚫 stripped_relations 折叠区。

**解说**：
> 通过 ScheduledTask 节点提议的同时，演化引擎自动调 Qwen 生成了 **候选 parser** ——
> 让数据层学会怎么把 4698 事件解析进图谱。
>
> 看候选内容：1 条规则覆盖 4698，3 个实体（ScheduledTask + Account + Host），
> 字段映射如 `task_name: event_data.TaskName` —— 不是代码，是 YAML，可读、可改、可审。
>
> 注意 🚫 stripped_relations 折叠区 ——
> LLM 想建 2 条关系（authenticated_as / executed_on）但**端点不匹配本体声明**，
> 七道闸门里的 G7 自动剔除并附原因："endpoint mismatch ontology=(Process, Host),
> got=(ScheduledTask, Host)"。LLM 试错全过程审核员看得见。

**操作**：点击 "▶ 跑抽样回放" → 选 5 条样本。

**焦点**：抽样结果展示成功率（应是 100%）+ 解析样例（ScheduledTask 节点真实数据）。

**解说**：
> 抽样回放：拿这候选 parser 试解析 5 条真实 4698 异常池样本，**100% 成功**。
> 这是审核员的"安全网" —— 不是只看 LLM 自报 confidence=0.85，是真跑了一下看结果。

**操作**：点击 "✅ Approve & Apply"。

**解说**：
> 通过后，YAML 写到 `parsers/generated/`，Parser 配置热加载。
> 数据层订阅到本体变更后，已经准备好回放异常池。

---

## 1:30 - 2:30 · 变更传播 + 回放（核心戏剧时刻）

**画面**：切到子 tab "🔁 回放与验证"，点【▶ 回放异常池】按钮（~2 秒，无 LLM）。

**焦点**：按钮下方三个 metric 当场跳出 ——
```
异常池规模 10  (Δ -22)    本轮回填 22    ScheduledTask 节点 17
```

**解说**：
> 这一步是组件 10 的核心。点一下按钮：
>
> - **异常池规模 32 → 10** ★ 主数字达成
>   - 22 条 4698 全部成功回放（100%）
>   - 8 条 4702 留池等下一轮（需要 ScheduledTaskModification 提议）
>   - 5140 / 5145 各 1 条留池（暂无规则）
> - **图谱新增 17 个 ScheduledTask 节点**，全部带 backfilled=true 元字段，可追溯
> - new_entities=31, merged_entities=35，Account / Host 与原 4624 事件合并

**操作**：切回浏览器，点 "🛡️ 告警研判" tab，选一条 HR-WS-01 的告警。

**焦点**：右栏图谱片段，**孤岛 ScheduledTask 节点专区**自动出现。

**解说**：
> 看右栏，告警相关图谱片段。除了原来的 Account / Host / Process，
> **多了一个 "🆕 孤岛 ScheduledTask 节点" 专区** —— 同主机的计划任务节点。
>
> 为什么"孤岛"？因为本轮演化只加了节点，没加边。
> 这正好预告下一站：**v1.2 演化加 schedules 边把节点连入主图**。
> 演化分两步走，每一步都可解释、可审核。

---

## 2:30 - 3:30 · 回放验证 · 演化前后对比

**画面**：仍在 "🔁 回放与验证" 子 tab。点【🔬 回放重判 + 对比】按钮
（真调 LLM ~53K，~4 分钟）——**页面出现实时进度条「重判 N/10」**，边讲架构边等。
跑完再点【🛡 回滚检查】。

**焦点**：进度条跑完后的 diff metric 区 + 回滚提议框。

```
=== ValidatorReport ===   ← 示例；verdict 部分每次跑都可能不同（LLM 非确定性）
  pool size : 32 → 10  (Δ -22)        ★ 确定性
  rejudged  : 10
    upgraded / downgraded / unchanged  ← 随机：本轮 0/0/10，别的轮可能出现降级
  semantic_gap : cleared 0 / persisted 6   ★ 确定性（4702/5140/5145 还没建模）
  evidence_refs avg : 8.60 → 7.60

=== ⚠️ RollbackProposal · WARNING ===     ★ 每次都触发
  rationale: semantic_gap 全部持续未清（persisted=6, cleared=0）
```

**解说**：
> 脚本拿 v1.0 的 10 条老判决和 v1.1 升级图谱后的新判决做 diff。**确定性的两条**：
>
> - 异常池规模 32→10 —— 演化的显性收益。
> - semantic_gap 还剩 6 条持续未清（4702 计划任务修改、5140/5145 共享访问还没建模）。
>   `check_rollback.py` 据此**自动产出一条回滚提议（WARNING）**：演化只解决了一部分，
>   系统自己知道还没干完，并把"是否回滚"这个决定交还给审核员。
>
> verdict 这部分**每次跑不一样**（LLM 非确定性）。这本身就是诚实材料 ——
> 见下一段怎么讲。

---

## 3:30 - 4:30 · 演化的真实成本（按当场结果二选一讲）

**画面**：切回浏览器 🛡️ 告警研判 tab，逐条看重判结果。

**焦点**：找一条高危告警（如 r1-lsass-memory-dump / r6-remote-thread-injection）看 verdict。

**解说（看当场 verdict 结果走分支）**：
>
> **分支 A —— 如果某条高危被降级了**（例如 LSASS malicious→suspicious）：
> > 看这条，真值是 malicious，演化后 LLM 却保守化了。为什么？右栏图谱多了
> > ScheduledTask 节点，LLM"看到这台主机有合法计划任务"反而不敢妄判。
> > **这是演化的真实代价（R5 分析师信任风险）—— 视野变宽，偶尔过度保守。**
>
> **分支 B —— 如果 verdict 全部不变**（像我验证那次）：
> > 这轮演化没改变任何判决（10 条全 unchanged，高危依旧 malicious）。
> > **这恰恰说明加节点是"安全的增量"** —— 没引入误降，但也没立刻提升准确率；
> > 真正的盲区（6 条 semantic_gap）还在，所以系统自己提了回滚预警。
>
> 无论哪个分支，结论一致：**演化不是"自动变好"，而是"可观测、可量化、可回滚"。**
> Demo 不装"AI 永远更好"，装"每一步代价和盲区都摆在台面上"。

**操作**：选一条你不认同的研判，反馈框写说明（如"这条应判 malicious"或
"这次演化没解决核心 gap"），点 👎。

**解说**：
> 我作为审核员把判断写回系统。这条 manual_annotation 信号立即落 signal_hub。

---

## 4:30 - 5:00 · 反馈闭环 + 收尾

**画面**：切回 "📊 评测看板" tab。

**焦点**：**反馈采纳率 metric 从 0.0% 当场跳起来**（1 / 判决数）—— 现场跳数字。

**解说**：
> 看顶部反馈采纳率：刚才还是 0.0%，现在跳起来了。**反馈机制不是装饰** ——
> 每一次按钮点击，看板立即统计，反馈数据将驱动下一轮演化（修改提议优先级 / 拒提议入反面样本库）。
>
> 总结一下今天演示了什么：
>
> 1. **真能跑**：从 Windows 日志（events.duckdb）→ Sigma 告警 → AI 研判 → 知识图谱
>    → 异常池 → 本体演化 → Parser 自动生成 → 回放 → 重判 → 回滚检查，端到端通。
>
> 2. **比现状好、且代价透明**：异常池 32→10 是确定性的显性收益；而 6 条 semantic_gap
>    持续未清触发了**自动回滚预警**——系统自己量化"还没干完"。verdict 准确率每轮
>    随 LLM 浮动（有时高危被过度保守降级），**把这个不确定性如实摆出来**才是卖点。
>
> 3. **有自我演化能力**：演化机制横切五层，每一层订阅本体变更并响应升级。
>    硬边界 + 反幻觉闸门 + 反面样本库 + 演化前后 diff + 回滚提议 —— 演化不是黑箱。
>
> v1.2 演化（加 schedules 边连接 ScheduledTask 节点 + 第二轮 approve
> ScheduledTaskModification 把 4702 也清理）将进一步把异常池压到 2 条。

**画面定格**：评测看板 4 个 metric。

**录屏结束**。

---

## 后台真实数字附录（用来对答时候核对）

> 标 ★ 的是确定性结果，每次跑都一样；其余随 LLM 浮动。
> 数字来自 2026-05-20 一次完整 P6→P11 验证跑。

| 指标 | v1.0 | v1.1 | 说明 |
|---|---|---|---|
| 异常池规模 ★ | 32 | 10 | 22 条 4698 全回填；4702×8 / 5140×1 / 5145×1 留池 |
| ScheduledTask 节点数 ★ | 0 | 17 | 灌入图谱，带 backfilled=true |
| semantic_gap persisted ★ | — | 6 | 触发回滚提议 WARNING |
| 候选 parser stripped 关系 ★ | — | 2 | authenticated_as（幻觉字段）+ executed_on（端点不匹配）|
| 本体覆盖率 | 99.6% | 99.6% | |
| 研判准确率 | ~50% | **随 LLM 浮动** | 验证那轮 10 条 verdict 全 unchanged（LSASS 仍 malicious）；别轮可能出现高危被误降 |
| 反馈采纳率 | 0.0% | 0% → 跳起 | 点 👎 后 = 1/判决数 |
| 总 LLM token | — | ~56K | 候选 parser ~2.7K + 重判 ~53K |

| 通过的提议 | proposal_id | 触发的本体版本 |
|---|---|---|
| ScheduledTask (node) | bae04eee | v1.1 |

| 候选 Parser（每次重跑 candidate_id 都不同） | 状态 |
|---|---|
| 4698_scheduled_task_create（target=ScheduledTask）| applied |

> 回滚提议**每次都触发**（semantic_gap 未清），但触发原因可能不同：本轮是
> "gap 持续未清"；若某轮出现 verdict 净降级，则会额外/改以"verdict 降级"触发。

---

## 录屏前 checklist（避免现场翻车）

- [ ] `.env` 有 DASHSCOPE_API_KEY 且额度够（看 `scripts/smoke_test_qwen.py` 跑一下）
- [ ] `data/events.duckdb` 存在（不存在跑 `generate_demo_data.py`）
- [ ] `data/parsed_events.duckdb` 存在（不存在跑 `run_parser.py`）
- [ ] `data/alerts.duckdb` 存在（不存在跑 `run_detection.py`）
- [ ] `data/judgments.duckdb` 存在（v1.0 时代的，不存在跑 `run_judgments.py`）
- [ ] `data/proposals.duckdb` 有 3 条 pending 提议（不存在跑 `run_proposals.py`）
- [ ] `ontology/` 只有 v1.0.yaml（删 v1.1+）
- [ ] `parsers/generated/` 清空
- [ ] `data/candidate_parsers.duckdb` 删除（让 store 重新建）
- [ ] `data/judgments_after_replay.duckdb` 删除
- [ ] `pool.reset_backfilled()` 一下让异常池回到 32 全 open
- [ ] 浏览器打开 streamlit + 终端两个窗口准备好
