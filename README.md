# AI-OntoSIEM

> **AI-native SIEM MVP 原型** —— 1 个月交付。
> 核心差异点：**本体演化机制横切全系统**，不只是图谱内部事务。
>
> 当 LLM 看到日志里出现"本体里没建模的概念"（例如 ScheduledTask），系统会自动产出
> 提议 → 人工审核 → 本体升级 → Parser 自动生成 → 异常池回放 → 图谱回填 → 认知层重推 → 评测对比。
> 每一层都订阅本体变更并响应升级。

---

## 一句话演示

```
异常池 32 → 10                ← 本体 v1.1 加 ScheduledTask 节点 + 回放 4698 事件（确定性）
semantic_gap 6 条持续未清     ← 触发自动回滚提议 WARNING（系统自知"还没干完"，确定性）
研判准确率                    ← 随 LLM 浮动；某些轮高危会被过度保守降级（演化的代价，如实呈现）
反馈采纳率 0% → 跳起          ← 审核员点 👎 触发 manual_annotation 信号回流
```

**Demo 不装"AI 永远更好"，装"演化机制可观测、代价透明、可回滚"。**
LLM 重判是非确定性的——把这个不确定性如实摆出来，本身就是这套框架的诚实卖点。

---

## 五层 + 一横切架构

```
⑤ Copilot / Agent 层      ui/                        Streamlit 三页签
④ 认知推理层 (LLM)        reasoning/                 LLM 客户端 + judgment_engine
③ 上下文知识图谱          graph/                     NetworkX + 实体消歧 + 时效性
② 检测告警层              detection/                 Sigma 子集 + rules/*.yaml
① 数据语义理解层          parsers/                   Windows parser + mappings/*.yaml
                              ↕ 全部订阅本体变更 ↕
⓪ 演化与评测横切层        evolution/                 提议 / 审核 / Parser 生成 / 回放 / 指标

本体服务                  core/ontology_service.py   全系统订阅入口
持久化                    storage/*.py               DuckDB（events / parsed / alerts /
                                                     anomaly_pool / signals / judgments
                                                     / proposals / candidate_parsers）
```

---

## 快速启动

### 选项 A：Docker Compose（推荐演示）

```bash
# 1. 配 Qwen API Key
cp .env.example .env
# 编辑 .env 填 DASHSCOPE_API_KEY

# 2. 启动
docker compose up --build -d

# 3. 首次运行需要生成 demo 数据（在容器内）
docker exec ai-ontosiem-demo python scripts/generate_demo_data.py
docker exec ai-ontosiem-demo python scripts/run_parser.py
docker exec ai-ontosiem-demo python scripts/run_detection.py
docker exec ai-ontosiem-demo python scripts/run_judgments.py

# 4. 浏览器打开 http://localhost:8501
```

### 选项 B：本地 venv

```bash
# 1. 环境（Python 3.10+）
python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. 配 API Key
cp .env.example .env               # 编辑填入 DASHSCOPE_API_KEY

# 3. 跑数据管线（首次）
python scripts/generate_demo_data.py        # → data/events.duckdb（2329 条合成日志）
python scripts/run_parser.py                # → parsed_events / anomaly_pool / signals
python scripts/run_detection.py             # → alerts.duckdb（10 条 Sigma 告警）
python scripts/run_judgments.py             # → judgments.duckdb（真调 Qwen，约 65K tokens）

# 4. 启 Streamlit
streamlit run ui/main.py
# 默认开 http://localhost:8501
```

---

## 演示脚本（5 分钟）

完整剧本见 [docs/demo_script.md](docs/demo_script.md)。**全程点 UI 按钮，零终端**。简版动线：

1. **0:00** 首页评测看板，4 个核心数字 + 异常池 32 条 → 引出 "演化机制"
2. **0:30** 演化页提议审核，点【✅ 通过】ScheduledTask 提议 → 本体 v1.1
3. **1:00** 候选 Parser 页点【🤖 生成候选 Parser】→ 候选出现（含 2 条被闸门 strip 的关系）→ 抽样回放 → 【Approve & Apply】
4. **2:30** 回放与验证页点【▶ 回放异常池】→ 异常池 32→10，灌入 17 个 ScheduledTask 节点
5. **3:30** 点【🔬 回放重判 + 对比】（实时进度条）→ diff；再点【🛡 回滚检查】→ **自动回滚提议 WARNING**
6. **4:30** 按当场 verdict 结果讲演化代价（高危被误降则讲 R5 风险；全不变则讲"安全增量"）+ 告警研判页点 👎 → 反馈采纳率 0% → 飞起
7. **5:00** 收尾：演化 ≠ 自动变好，演化 = **可观测、代价透明、可回滚**

---

## 4 个核心数字（首页一眼可见）

| 指标 | 含义 | 当前值（v1.1） |
|---|---|---|
| 研判准确率 | LLM verdict vs 人工 ground truth | ~50%，随 LLM 浮动¹ |
| 反馈采纳率 | manual_annotation 信号 / 判决数 | 0%（演示前）/ ↑ 演示后 |
| 本体覆盖率 | 成功 parse / (parse + 异常池) | 99.6% |
| 异常池规模 | 当前未解决的"本体盲区"事件数 | 10（v1.0 时代是 32）★ 确定性 |

¹ 重判是 LLM 非确定性的：某些轮 LLM 看到新增的 ScheduledTask 节点会把高危告警（如 LSASS dump）过度保守地从 malicious 降到 suspicious，准确率因此下降；另一些轮 verdict 全不变。**不保证每次复现**——Demo 如实呈现这个不确定性，并靠确定性的 semantic_gap 回滚提议兜底叙事。

---

## 流水线脚本对照

| 顺序 | 脚本 | 输入 | 输出 |
|---|---|---|---|
| 1 | `scripts/generate_demo_data.py` | (合成种子) | `data/events.duckdb` (2329 条) |
| 2 | `scripts/run_parser.py` | events.duckdb | parsed_events / anomaly_pool / signals |
| 3 | `scripts/run_detection.py` | events.duckdb | alerts.duckdb (10 条 Sigma 告警) |
| 4 | `scripts/run_judgments.py` | alerts + 图谱 | judgments.duckdb (真调 Qwen) |
| 5 | `scripts/run_proposals.py` | signals + 本体 | proposals.duckdb (LLM 提议) |
| 6 | `streamlit run ui/main.py`（演化 tab → approve ScheduledTask） | proposals | `ontology/v1.1.yaml` |
| 7 | `scripts/generate_parser.py` | approved 提议 + 异常池样本 | candidate_parsers.duckdb |
| 8 | （演化 tab → approve candidate） | candidate | `parsers/generated/<id>.yaml` |
| 9 | `scripts/replay_anomaly_pool.py` | 异常池 + 新 parser | 灌图 + replay_reports |
| 10 | `scripts/run_replay_validator.py` | 老 judgments + 升级图 | judgments_after_replay.duckdb + diff 报告 |

---

## 测试

```bash
.venv/Scripts/python.exe -m pytest                          # 全量（333 测试）
.venv/Scripts/python.exe -m pytest tests/test_X.py -v       # 单文件
.venv/Scripts/python.exe -m pytest tests/test_X.py::test_fn # 单测
```

**项目状态**：333/333 全绿。

---

## 关键契约（违反会破坏 demo 叙事）

- **本体硬边界**：User 节点只能来自 CMDB/IAM；owns 边只能 declared 源；演化只能新增、必须 ≥3 条证据、overlap_analysis 必填。
- **反幻觉闸门**：evidence_refs 严格校验（matched_field / graph_node / graph_edge ref 必须在真实子图中存在），不合规 LLM 重写。
- **实体消歧分层**：SID (strong) / `DOMAIN\user` (medium) / `?\user` (weak)；Anonymous SID 一律降级。
- **Token 预算**：Qwen 1M 免费额度；硬上限 900K；`judgment_engine` 对子图做 `max_nodes_per_type=8` 裁剪（Process），单条告警从 127K → 6.5K tokens。

详细参见 [CLAUDE.md](CLAUDE.md)。

---

## 当前限制 / 未来工作

- **回滚是"提议"而非"自动执行"**：`check_rollback.py` 会在指标恶化（verdict 净降级 / semantic_gap 持续未清）时自动产出 RollbackProposal，但**从不自动回滚**——撤销 v1.1 仍需人工删 yaml + 重启（R8 缓解：避免演化空转又避免误自动回滚）。
- **第二轮演化**：4702 / 5140 / 5145 仍在异常池（6 条 semantic_gap）；下一轮 approve ScheduledTaskModification 提议可清理 4702。
- **生产化**：当前是单租户 demo，多租户隔离 / RBAC / 审计日志 / 多 LLM 后端切换属于 Phase 5 工作。

---

## 文档目录

- [CLAUDE.md](CLAUDE.md) —— Claude Code 协作指南（项目规范 / 命令清单 / 关键契约）
- [task_plan.md](task_plan.md) —— 五阶段开发计划 + 风险表 + 决策日志
- [progress.md](progress.md) —— 会话日志（按时间倒序）
- [docs/ontology_v1.md](docs/ontology_v1.md) —— 本体 v1.0 人读版说明书
- [docs/attack_scenarios.md](docs/attack_scenarios.md) —— 攻击剧本 + 预期告警
- [docs/demo_script.md](docs/demo_script.md) —— 5 分钟 Demo 录屏剧本
- [docs/memo.md](docs/memo.md) —— 立项 Memo（决策层友好版）

---

## License

原型项目，未发布 license。如需商用请联系作者。
