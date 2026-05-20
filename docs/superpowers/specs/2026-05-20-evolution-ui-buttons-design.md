# 设计：演化管线 UI 按钮化（去掉演示时的终端命令）

日期：2026-05-20
状态：已实现（343 测试全绿 + 完整管线端到端重跑验证）

## 问题

现场演化直播需要在终端敲 `generate_parser.py` / `replay_anomaly_pool.py` /
`run_replay_validator.py` / `check_rollback.py`。给领导演示时切终端敲命令显得半成品。
要把这四步做成 UI 按钮，演示全程零终端。

## 决策（已与用户确认）

- **4 个独立按钮**，对应审核员真实工作流（不做一键大按钮、不自动链式）。
- 重判 ~4 分钟：**实时进度条 +「重判 N/10」边讲边等**（真·实时，不预热不缩范围）。

## 架构

新增服务层 `evolution/pipeline_ops.py`，把四个脚本的编排逻辑收成 4 个函数。
**CLI 脚本与 UI 按钮都调它**（脚本退化成瘦壳，逻辑不重复，CI/无头仍可用）：

| 函数 | 职责 | 关键点 |
|---|---|---|
| `generate_candidates()` | 对 approved 提议生成候选 parser | 可注入 generator（测试免 LLM）|
| `replay_pool()` | 重建图 + 回放异常池 + 落 HTML | 返回 `ReplayResult`（含 graph、32→10）|
| `rejudge_and_compare(progress_cb=)` | 回放 + 重判 + diff | progress_cb 每条回调一次喂进度条 |
| `latest_rollback_assessment()` | 读最新报告 → assess_for_rollback | 返回 `RollbackProposal` 或 None |

`rejudge_alerts(engine, alerts)` 加可选 `progress_cb`（向后兼容）作为进度钩子。

所有函数关键依赖（store/pool/graph/engine/llm/db 路径）可注入，默认走真实对象，
便于 TDD 用 tmp + 假对象隔离测试。打开的 store 由函数 try/finally 关闭（不持锁）。

## UI 落位（全在 📐 本体演化 tab）

| 按钮 | 位置 | demo 时点 |
|---|---|---|
| 🤖 生成候选 Parser | 🔧 候选 Parser sub-tab（无候选时显示）| 1:00 |
| ▶ 回放异常池 | 新增 🔁 回放与验证 sub-tab | 2:30 |
| 🔬 回放重判 + 对比 | 🔁 回放与验证（st.progress 实时）| 3:30 |
| 🛡 回滚检查 | 🔁 回放与验证 | 3:40 |

- 长任务：`st.progress` + `st.empty`，progress_cb 每判完一条刷新进度条与该行 verdict。
- 报告存 `st.session_state` 跨 rerun 保留。
- 回放/重判后 `_cached_graph.clear()`，告警研判页孤岛节点随之出现。
- 重判按钮调 `pipeline_ops` 用临时 `SignalHub`（不持久锁 signals.duckdb）。

## 测试（TDD）

- `rejudge_alerts` progress_cb 每 alert 调一次。
- `rejudge_and_compare`：注入假 engine + graph + alerts + old_judgments → progress_cb
  被调 N 次、返回 ValidatorReport（rejudged_count 正确）。
- `latest_rollback_assessment`：tmp reports 目录 + 构造 validator json → 返回 proposal。
- `generate_candidates`：tmp stores + 假 generator → 插入 + skip 逻辑。
- `replay_pool`：注入空 tmp pool + GraphStore → 返回 ReplayResult 形状正确、写 html。
- UI helper：按钮动作后 store 不持锁（沿用 _external_open_ok 探针）。

## 非目标（YAGNI）

- 不做一键大按钮、不自动链式触发。
- 不改 LLM 行为（重判仍非确定性，文案已如实说明）。
- 不删脚本（保留给 CI / 无头）。
