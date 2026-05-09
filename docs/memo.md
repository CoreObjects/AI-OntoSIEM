# AI-OntoSIEM 立项 Memo

> **致**：决策层 / Sponsor
> **作者**：项目组
> **日期**：2026-05-09
> **版本**：v1.0（MVP 原型交付）
> **附件**：[README.md](../README.md) · [docs/demo_script.md](demo_script.md) · 5 分钟 Demo 录屏

---

## TL;DR

我们在 1 个月（22 工作日）内交付了一个**端到端可跑的 AI-native SIEM 原型**。
核心差异点是**本体演化机制横切全系统** —— 不是图谱内部的小事务，而是当 AI 遇到本体盲区时，
解析层 / 检测层 / 图谱层 / 认知层都协同响应升级。

最后一公里的"演化机制"几乎所有竞品都做不到，这是项目能否进入下一阶段（生产化、商业化）的关键。

**建议立项**：进入 Phase 5（生产化 6-9 个月，预算另议），重点在多租户隔离 / 模型多源切换 / 与 SOAR
集成 / 持续反馈训练。Phase 5 GO/NO-GO 评审建议在 8 周内完成。

---

## 1. 我们解决什么问题

**现状痛点**：
- 传统 SIEM 的 schema / 检测规则 / parser 都是**死的**。新型攻击或新数据源出现时，需要工程师手工
  改规则、改 parser、改图谱模型 —— 周期 1-3 个月，TCO 很高。
- 已有 AI SIEM 原型大多停留在 "LLM 写一段告警解释" 层面。
- 当 AI 遇到本体里没建模的概念，要么**沉默**（错过攻击），要么**幻觉**（编造关系）。

**本项目独有**：
- AI 检测到本体盲区 → 自动产出 **结构化的本体演化提议**（不是自由文本）
- 提议过 4 重闸门后 → 人工审核 → 通过则系统**自动**升级本体 + 生成新 Parser + 回放历史事件
- 每一步**可解释、可追溯、可回滚**

---

## 2. MVP 原型可量化结果

### 端到端 Demo 主数字（5 分钟现场可演示）

| 指标 | 演化前 (v1.0) | 演化后 (v1.1) | 变化 |
|---|---|---|---|
| **异常池规模** | 32 条本体盲区事件 | **10 条** | **-68.8%** ★ |
| **图谱节点丰富度** | 3553 节点 | 3590 节点 | +17 ScheduledTask 节点（全新概念） |
| 研判准确率 | 50.0% (5/10) | 44.4% (4/9) | -5.6pp |
| 反馈采纳率 | 0% | 0% → 11.1%（demo 现场） | 反馈机制可即时统计 |
| 本体覆盖率 | 99.6% | 99.6% | 稳定 |

### 工程指标
- **313/313 测试全绿**（约 5800 行代码 + 290 行 Streamlit UI）
- **TDD 全程贯彻**（不写"事后测试"）
- **真调 LLM 累计 ~79K token**（占 Qwen 1M 免费额度 8%；生产化按 ¥0.04/K token 估算单次完整跑批 ~¥3.2）
- 端到端管线 1 条命令可跑（10 个脚本 + 1 个 Streamlit 入口）

---

## 3. 关键差异点（vs 主流 AI SIEM）

| 维度 | 主流方案 | 本项目 |
|---|---|---|
| AI 输出形式 | 自由文本告警解释 | **structured JSON + evidence_refs 强制回指真实数据** |
| 本体定义 | 硬编码 schema | YAML 文件 + 版本化 + 订阅广播 |
| 检测规则 | 工程师手写 Sigma | Sigma 子集 + LLM 辅助生成（带本体校验） |
| Parser | 工程师写代码 | YAML 配置（手写 + LLM 自动生成 + 抽样回放验证） |
| 反幻觉 | 后处理过滤 | **multi-gate 闸门 + evidence_refs 严格校验 + 反面样本库** |
| 演化机制 | 通常没有 / 仅图谱内部 | **全栈横切 + 自动生成 Parser + 异常池回放 + 评测前后对比** |

---

## 4. 风险与缓解（已落地）

| ID | 风险 | 缓解策略（已实现） |
|---|---|---|
| R1 | 图谱数据质量 | SID 强匹配 / DOMAIN\\user 中匹配 / ?\\user 弱匹配（"观察区"概念）；关系时效性按类型分档 |
| R2 | LLM 幻觉 | structured JSON + evidence_refs 强制 + max_retries=2 重写 + 低置信拒答（confidence<0.5 入复核队列） |
| R3 | 延迟与成本 | 演化提议**周频或阈值触发**；研判只跑告警（非全日志）；token 单条 < 30K（Process 子图裁剪 95%） |
| R4 | 评测缺位 | 4 个核心数字 Week 1 即采集；回放验证作为演化 gate |
| R5 | 分析师信任 | **主动暴露失败案例**（demo 留 LSASS 误降一例）；反馈按钮回流 |
| R6 | 本体膨胀失控 | 硬边界（只能新增）+ 重叠度 > 0.7 自动丢弃 + 字符串相似度闸 + 反面样本库 + 延后周期上限（max 2） |
| R7 | Parser 生成质量 | 配置化（非代码） + 7 道闸门 + 抽样回放成功率审核 + 人工 approve 才 apply |
| R8 | 演化空转 | 订阅-响应模型测试覆盖；ValidatorReport 量化前后对比；指标恶化触发回滚提议（Phase 5 自动化） |
| R9 | 排期超支 | 每组件备降级方案（如 pyvis 全图卡顿则只渲染聚焦子图）；Week 2 末卡住即砍 |
| R10 | Demo 数据失真 | 用合成数据精确控制演化锚点（4698/4702 30 条）；故意留 semantic_gap + 留 LSASS 失败案例 |

---

## 5. 关键决策与权衡

| 决策 | 选项 | 选择 | 理由 |
|---|---|---|---|
| LLM 后端 | Claude / Qwen / GPT | **Qwen-Plus** | 1M 免费 token；DashScope OpenAI 兼容接口可后期切回 Claude |
| 数据集 | BOTSv3 / Mordor / 合成 | **合成** | Demo 需要精确控制演化锚点；BOTSv3 4698/4702 数量不可控 |
| 反馈采纳 | embedding 相似度 / 字符串 | **字符串 + overlap 双闸** | MVP 简化，embedding 留 Phase 5 |
| 演化触发 | 仅人工 / 仅自动 | **周频定时 + 信号阈值即时双触发** | 演化频率可控，重大事件不延迟 |
| Parser 生成 | 代码 / YAML | **YAML 配置化** | 可读、可改、可回滚；LLM 生成代码 ROI 不划算 |
| User-Account 归并 | 自动 / 手工 | **绝不自动归并** | L3 演化（高风险），原型阶段不在自动提议范围 |

---

## 6. 项目里程碑回顾

| 阶段 | 工作量 | 内容 | 状态 |
|---|---|---|---|
| **阶段 0** 准备 | 0.5d | 仓库骨架 + Qwen 冒烟 | ✅ |
| **阶段 1** 基础设施 | 7d | 数据 + 本体 + 解析器 + LLM 客户端 | ✅ |
| **阶段 2** 检测+图+认知+信号 | 12d | Sigma 6 规则 + NetworkX 图 + judgment_engine + 信号中枢 | ✅ |
| **阶段 3** 演化闭环 | 10d | 提议引擎 + 审核 UI + Parser 自动生成 + 异常池回放 + 评测对比 | ✅ |
| **阶段 4** UI 交付 | 3d | Streamlit 三页签 + 4 核心数字 + 反馈闭环 + Docker + Memo | ✅ |
| **总计** | **32.5d** | 单人执行 ~22 工作日（与计划吻合）| ✅ |

---

## 7. Phase 5 建议（生产化路线图）

### 7.1 必做（前 3 个月）

- **多租户隔离**：当前是单租户 demo；生产需要 RBAC + 数据隔离 + 审计日志
- **多 LLM 后端切换**：当前硬编码 Qwen；OpenAI 兼容接口已留好钩子，加 Anthropic / Azure / 私有化推理
- **生产级数据接入**：当前是 DuckDB，生产换 ClickHouse / OpenSearch；接 syslog / Kafka / cloud event source
- **回滚机制自动化**：当前是手工 reject 提议；ValidatorReport 指标恶化（如 LSASS 误降）应能自动 rollback ontology 版本
- **持续反馈训练**：manual_annotation 信号 + LLM 真实回放 → fine-tune 或 prompt-tune 推理模板

### 7.2 应做（中 3 个月）

- 与现有 SOAR 集成（如 Demisto / Splunk Phantom），把 next_steps 转成自动化剧本
- 多场景扩展：不只 Windows Security，还有 Linux audit / cloud event / network IDS
- 本体多语言 / 多领域：金融合规、IoT 安全、医疗 PHI 各自的本体扩展
- 评测看板专业化：Grafana / Superset 接 metrics endpoint（`MetricsSnapshot.to_dict()` 已是 API 友好）

### 7.3 选做（后 3 个月）

- Copilot 对话式：与本体演化 / 图谱片段 / 历史告警的多轮对话
- 自动 attack chain 重构：从 alert + judgment 自动构造 ATT&CK 攻击链时间线
- 跨租户匿名化情报共享：本体级别的"威胁本体共享"（不分享原始数据）

---

## 8. 推荐 Phase 5 GO/NO-GO 评审标准

如果以下任一项 < 80% 满足，建议**降级**为内部研究项目而非商业产品：

1. **演化机制实战检验**：在真实客户日志（非合成）上跑一周，至少 2 次有效演化 + 0 次 R6 风险（本体膨胀失控）
2. **LLM 成本可预测**：单租户每月 token 消耗 < 100M（按当前优化水平推算约 ¥4K/月）
3. **审核员体验验证**：3 位 SOC 分析师独立使用 Streamlit UI 1 周，反馈采纳率 > 30%
4. **可解释性测试**：随机抽 50 条 evidence_refs，分析师能完整追溯到原始日志/图谱节点 > 95%

---

## 9. 附录：关键技术契约（供工程评审参考）

- **本体硬边界**（v1.0 第一次写定，绝不放宽）：
  - User 节点只能来自 CMDB/IAM
  - owns 边只能 declared 源（CMDB/IAM/manual）
  - 演化只能新增、必须 ≥3 条证据、overlap_analysis 必填、单次 ≤5 个
- **反幻觉闸门**：evidence_refs 强制非空；ref 必须能在 alert.matched_fields / 子图节点 / 子图边里找到
- **Token 预算守护**：1M 硬上限；judgment_engine 子图按 last_seen 裁剪 Process 至 top-8（127K → 6.5K tokens / 告警）
- **TDD 铁律**：新功能 / 修 bug 都走 Red-Green-Refactor，零事后测试
- **演化前后 diff**：异常池规模 + verdict 变化 + semantic_gap 清除/持续 + evidence_refs 增量四维度量化

---

## 10. 联系

- 代码仓库：https://github.com/CoreObjects/AI-OntoSIEM
- Demo 录屏：（链接待补）
- 项目组：（联系方式待补）

---

*本 Memo 旨在 30 分钟内完成阅读 + 决策。如需更深入的技术细节，请参考 README.md / progress.md 会话日志（按时间倒序，含每次会话的关键发现） / docs/architecture.md / 5 分钟 Demo 录屏。*
