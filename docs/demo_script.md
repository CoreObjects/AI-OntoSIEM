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

**画面**：切到子 tab "🔧 候选 Parser"。**预先在录屏前**跑 `python scripts/generate_parser.py`，让候选已经在 store 里 pending。

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

**画面**：切回浏览器之前的终端（或 split view 终端）。

**操作**：执行 `python scripts/replay_anomaly_pool.py`。

**焦点**：终端输出 ——
```
[pool] 重置 backfilled 标志（32 条全部翻 open）
[replay] 异常池 32 → 10; 灌图 +31 new entities
ScheduledTask: 17 个新节点
```

**解说**：
> 这一步是组件 10 的核心。看终端：
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

**画面**：终端。

**操作**：执行 `python scripts/run_replay_validator.py`（约 70K tokens，~30 秒）。

**焦点**：终端输出 ValidatorReport，重点 verdict_changes。

```
=== ValidatorReport ===
  pool size : 32 → 10  (Δ -22)
  rejudged  : 9
    upgraded   : 0
    downgraded : 1
    unchanged  : 8
  semantic_gap : cleared 1 / persisted 5
  evidence_refs avg : 8.60 → 6.78

  详细变更:
    ↓↓ 29a5c7e0  malicious(0.95) → suspicious(0.65)
        + new ref: Host:HR-WS-01
```

**解说**：
> 跑完了。脚本拿 v1.0 时代的 10 条老判决和 v1.1 升级图谱后的 9 条新判决做 diff：
>
> - 异常池规模 32→10 已得
> - **8 条 verdict 不变，1 条降级（downgraded）** —— 注意这里 ★
> - semantic_gap 清掉 1 条（r5-admin-share），还有 5 条持续等下一轮演化
> - evidence_refs 平均从 8.60 略降到 6.78，新引用了图节点 Host:HR-WS-01

---

## 3:30 - 4:30 · 主动暴露失败案例（Demo 灵魂段）

**画面**：切回浏览器告警研判 tab，选**第二条告警 r1-lsass-memory-dump**（HR-WS-01）。

**焦点**：中栏 verdict 卡片 —— suspicious(0.65)，但 ATT&CK 是 T1003 LSASS dump。

**解说**：
> 这条告警是**今天 demo 的灵魂材料**。
>
> 真值表里，r1 LSASS 内存导出标的是 malicious。v1.0 时代 LLM 也判了 malicious(0.95)。
>
> 但是 ——
>
> 演化升级到 v1.1 后，LLM 重判变成 suspicious(0.65)。**降级了 30 个百分点。**
>
> 为什么？看右栏图谱片段：HR-WS-01 上多出了 ScheduledTask 节点。
> LLM 看到"这台主机有合法的计划任务运行"，就把"LSASS dump"也保守化了 ——
> "我看到更多上下文，反而不敢妄判"。
>
> 这是 R5 风险（分析师信任）的真实案例：
> **演化让 LLM 的视野变宽，但偶尔会过度保守。**
>
> Demo 不需要装"AI 永远更好"，需要装"AI 真实可解释，错误可观测可纠正"。

**操作**：在反馈面板写 "LSASS dump 应判 malicious，演化让 AI 过度保守了"，点 👎。

**解说**：
> 我作为审核员告诉系统："这个降级是错的"。
> 这条 manual_annotation 信号立即写到 signal_hub。

---

## 4:30 - 5:00 · 反馈闭环 + 收尾

**画面**：切回 "📊 评测看板" tab。

**焦点**：**反馈采纳率 metric 从 0.0% 跳到 11.1% (1/9)** —— 现场跳数字。

**解说**：
> 看顶部反馈采纳率：刚才还是 0.0%，现在是 11.1%。**反馈机制不是装饰** ——
> 每一次按钮点击，看板立即统计，反馈数据将驱动下一轮演化（修改提议优先级 / 拒提议入反面样本库）。
>
> 总结一下今天演示了什么：
>
> 1. **真能跑**：从 Windows 日志（events.duckdb）→ Sigma 告警 → AI 研判 → 知识图谱
>    → 异常池 → 本体演化 → Parser 自动生成 → 回放 → 评测，端到端通。
>
> 2. **比现状好**：4 个数字可量化 —— 异常池 32→10 是显性收益，准确率 50%→44%
>    是隐性代价，**两数字并列出现就是为了让决策层看到真实代价**。
>
> 3. **有自我演化能力**：演化机制横切五层，每一层订阅本体变更并响应升级。
>    硬边界 + 反幻觉闸门 + 反面样本库 + 演化前后 diff —— 演化不是黑箱。
>
> v1.2 演化（加 schedules 边连接 ScheduledTask 节点 + 第二轮 approve
> ScheduledTaskModification 把 4702 也清理）将进一步把异常池压到 2 条。

**画面定格**：评测看板 4 个 metric。

**录屏结束**。

---

## 后台真实数字附录（用来对答时候核对）

| 指标 | v1.0 | v1.1 |
|---|---|---|
| 研判准确率 | 50.0% (5/10) | 44.4% (4/9) |
| 反馈采纳率 | 0.0% | 0.0% → 11.1%（演示后） |
| 本体覆盖率 | 99.6% | 99.6% |
| 异常池规模 | 32 | 10 |
| ScheduledTask 节点数 | 0 | 17 |
| 总 LLM token 消耗 | ~2K（提议）+ ~2.7K（候选 parser）+ ~71K（重判）= ~76K |

| 通过的提议 | proposal_id | 触发的本体版本 |
|---|---|---|
| ScheduledTask (node) | bae04eee | v1.1 |

| 候选 Parser | candidate_id | 状态 |
|---|---|---|
| 4698_scheduled_task_create | 1581021d (示例) | applied |

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
