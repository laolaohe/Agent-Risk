# AgentRisk 开发会话记录 — 2026-06-29

## 会话成果

### 1. 代码规范确立
- **规则中文友好**：检测规则、报告输出全部使用中文
- **关键步骤注释**：所有函数、核心算法、CLI 输出步骤均添加中文注释说明意图
- 详见 memory: `code-conventions.md`

### 2. Skill Analyzer v2 — 正则 → LLM 重构

**原方案（v1 正则）：**
```
Skill 文本 → 正则规则引擎 → 6 条硬编码规则匹配 → Findings → 报告
```
问题：只能做关键词匹配，无法理解语义，漏报误报严重

**新方案（v2 LLM）：**
```
Skill 文本 → DeepSeek v4 Pro API → 结构化 Findings → CVSS 评分 → Rich 终端报告
```
一条直线，端到端 LLM 语义分析。

### 3. 改动文件清单

| 文件 | 动作 | 说明 |
|------|------|------|
| `agentrisk/analyzers/llm.py` | **新增** | LLM 分析器核心：System Prompt + DeepSeek API + Function Calling 结构化输出 |
| `agentrisk/models/config.py` | **修改** | Finding 加 confidence 字段，SkillReport 加 overall_assessment |
| `agentrisk/analyzers/skill.py` | **修改** | RuleEngine 替换为 analyze_with_llm() |
| `agentrisk/cli/main.py` | **修改** | 报告显示置信度和整体评语 |
| `requirements.txt` | **修改** | 新增 openai>=1.0.0 依赖 |

**保留但不再调用**：`rules/engine.py` 和 `rules/skill_rules.yaml`，留作后续可能的规则回退方案。

### 4. 测试验证

| 样本 | 结果 | 评分 |
|------|------|------|
| `skill_malicious_shell.md` | 5 条发现（2 CRITICAL + 3 HIGH） | 100/100 |
| `skill_benign_readonly.md` | 0 条发现，正确识别为安全 | 0/100 |

LLM 准确识别了：
- 任意 Shell 命令执行
- 无人工审批机制
- 无限制网络访问 + 数据外泄通道
- 全局作用域违规
- 多重高危配置组合形成系统性安全崩溃

对良性样本零误报，正确判断其遵循了最小权限原则。

### 5. 技术决策

| 决策 | 结论 |
|------|------|
| 正则规则引擎 | **废弃**，LLM 直接分析 |
| RAG 知识库 | **V2 再加**，当前无历史数据 |
| LLM 提供商 | DeepSeek v4 Pro（兼容 OpenAI SDK） |
| API Key 变量 | 同时支持 DEEPSEEK_API_KEY 和 OPENAI_API_KEY |
| 输出语言 | 全中文（System Prompt + 报告 + 发现） |
| Python 版本 | 3.11（已解决 Windows Store 桩程序问题） |

### 6. 文档更新

- **蓝图** `bule print.txt`：更新为实际 LLM 架构，标注 V1 完成状态
- **README** `drafts/V1-README.md`：完整架构图 + 使用说明 + 技术栈
- **会话记录** `drafts/2026-06-29-session-summary.md`：本文档

### 下一步

- [ ] Prompt Analyzer（Prompt 层安全分析）
- [ ] MCP Analyzer（MCP 配置安全分析）
- [ ] demo.yaml 演示配置
- [ ] 三个 Analyzer 统一入口 `agentrisk scan`

## 已解决的环境问题

**Windows Store Python 桩程序冲突**：PATH 中 WindowsApps\python.exe 排在 Python 3.11 前面导致 `python` 命令弹 Store。已通过关闭 Windows 应用执行别名解决。
