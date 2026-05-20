# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目定位

AI-native SIEM MVP 原型，1 个月交付周期。核心差异点：**本体演化机制横切全系统**（不仅是图谱内部事务）—— 数据层解析、检测规则、图谱建模、LLM 研判、信号汇聚都通过 `OntologyService` 订阅本体变更并响应升级。这决定了几乎所有模块的设计形态。

需求规格、攻击剧本、本体 v1.0 说明分别在 `task_plan.md`、`docs/attack_scenarios.md`、`docs/ontology_v1.md`。

## 常用命令

**环境**：Windows venv，Python 3.10.7。所有 Python 命令走 `.venv/Scripts/python.exe`（不是裸 `python`）。

```bash
# 测试（全量 / 单文件 / 单测）
.venv/Scripts/python.exe -m pytest
.venv/Scripts/python.exe -m pytest tests/test_graph_store.py -v
.venv/Scripts/python.exe -m pytest tests/test_X.py::test_fn --tb=short

# 端到端数据管线（按顺序跑；每步产出下一步的输入）
python scripts/generate_demo_data.py   # → data/events.duckdb
python scripts/run_parser.py           # → parsed_events / anomaly_pool / signals
python scripts/run_detection.py        # → alerts.duckdb
python scripts/build_graph.py          # → graph/visualization*.html
python scripts/run_judgments.py        # → judgments.duckdb（真调 Qwen，每条 ~6.5K tokens）
python scripts/inspect_signals.py      # 终端热力图
python scripts/run_proposals.py        # → proposals.duckdb（真调 Qwen）

# Streamlit 审核 UI
streamlit run ui/evolution_review.py
```

单个脚本跑前请确认前置 `data/*.duckdb` 存在；脚本自带"前置文件缺失 → 报错退出"检查。

## 架构：五层 + 一横切

```
⑤ Copilot / Agent          ui/             (Streamlit 页面，尽量薄，绑定到 evolution/review_actions)
④ 认知推理                 reasoning/      (LLM 客户端 + judgment_engine)
③ 知识图谱                 graph/          (NetworkX + 实体消歧 + 时效性 + pyvis)
② 检测告警                 detection/      (Sigma 子集引擎 + rules/*.yaml)
① 数据/语义                parsers/        (宽容解析器 + mappings/*.yaml)
⓪ 演化横切                 evolution/      (signal_hub / proposer / ontology_upgrader / review_actions)

本体服务                   core/ontology_service.py   (所有层订阅变更，版本升级触发回调)
持久化                     storage/*.py               (DuckDB：anomaly_pool / alert_store / judgment_store / proposal_store)
```

**数据流**：event.duckdb → parser → (parsed_events + anomaly_pool + signals) → sigma → alerts → judgment_engine (+ graph subgraph + LLM) → judgments + 更多 signals → proposer → proposals → 审核 UI → ontology_upgrade → 订阅者自动响应（组件 10 将闭合最后一环：Parser 自动生成 + 异常池回放）。

## 关键契约（违反会破坏整套叙事）

**本体硬边界**（ontology/v1.0.yaml + evolution/proposer.py）
- User 节点只能来自 CMDB/IAM（`graph.store.HardConstraintViolation`）
- owns 边只能 declared 源，禁止 LLM 或日志推断
- 演化只能新增、必须 ≥3 条支持证据、overlap_analysis 必填、单次 ≤5 个
- 重叠度 >0.7 自动丢弃；SequenceMatcher 与本体/反面样本库相似 ≥0.7 也丢弃

**反幻觉闸门**（reasoning/judgment_engine.py + reasoning/llm_client.py）
- `evidence_refs` 强制非空（llm_client 的 validator）
- `evidence_refs` 严格校验：`matched_field` ref ∈ alert.matched_fields 键；`graph_node` / `graph_edge` ref 必须在子图中实际存在
- 不合规 → LLM 带错误消息重写（max_retries=2）

**实体消歧分层**（graph/entity_resolver.py）
- Account：SID (strong 1.0) / `DOMAIN\user` (medium 0.8) / `?\user` (weak 0.5)
- Host：hostname (strong) / FQDN 推短名 (medium)
- Process：`host::basename::pid::start_time` (strong) / 无 start_time (medium)
- Anonymous SID（S-1-0-0, S-1-5-7）一律回退中匹配

**Token 预算**（reasoning/llm_client.py）
- Qwen 1M 免费额度；硬上限 900K；warn 700K
- judgment_engine 对 subgraph 做 `max_nodes_per_type` 裁剪（默认 Process=8 by last_seen），否则 Host 中心 2 跳子图轻松 127K tokens/条

**Sigma 规则与 Demo 叙事**
- 6 条规则覆盖 T1003/T1078/T1021/T1059/T1570/T1055
- **故意不写 4698/4702 规则**（ScheduledTask），这是演化主故事线的触发器：解析器遇到无法映射的 4698 → 进 anomaly_pool → 信号聚合 → 阶段 3 LLM 提议 ScheduledTask 节点

## 开发流程

**TDD 铁律**（由 `superpowers:test-driven-development` skill 约束）：
新功能/修 bug 都走 Red→Green→Refactor。绝不写"事后测试"。除配置文件外无例外。

**规划文件约定**（不要用 TodoWrite；memory 里的 `feedback_planning_files` 固定偏好）
- `task_plan.md` — 五阶段主计划 + 组件清单 + 风险表 + 决策日志
- `progress.md` — 会话日志，按时间倒序。每次会话结束追加一条，含完成清单、关键发现、下一步
- `findings.md` — 研究发现（F1..FN 编号）

## Git 规范

- Commit message 用中文（与历史提交一致），简短标题 + 详细 body；模式 `阶段 X 组件 N：<模块简述>`
- **不添加 `Co-Authored-By`、`Generated with Claude` 等 attribution footer**
- 分支命名：待约定（当前工作都在 `main`，如需分支请与用户确认规范）

## Windows 特有坑

- Python 命令必须 `.venv/Scripts/python.exe`，不是 `python`
- 终端默认 cp936（GBK），直接打印 UTF-8 中文会乱码；含中文输出的脚本前加：
  ```python
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
  ```
- 终端不认 emoji（✅/⏳ 等），脚本用 `[DONE]` / `[TODO]` 等 ASCII 替代
- `git add` 会提示 LF→CRLF 转换 warning，不影响
