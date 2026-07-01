# AgentRisk 开发会话记录 — 2026-07-01

## 会话成果

### 1. 清理正则规则引擎
- **删除** `agentrisk/rules/` 整个目录（engine.py + skill_rules.yaml + __init__.py）
- 代码层面无任何引用，全盘 LLM 路线
- 文档同步清理：bule print.txt、drafts/V1-README.md

### 2. 样本全部中文化
- 5 个 Skill 样本全部改写为中文
- 安全特征原样保留（恶意继续恶意，良性继续良性）

### 3. Skill Analyzer v3 — 5 维 → 11 维 LLM 重构

**原方案（v2 5 维）：**
```
Skill 文本 → DeepSeek v4 Pro → 5 条安全检查清单 → Findings → 报告
```
问题：方法论是"安全检查清单"而非"威胁建模"，权限组合、能力漂移、用户输入路径等全盲

**新方案（v3 11 维）：**
```
Skill 文本 → deepseek-chat → 三层 11 维威胁建模 → 结构化 Findings + 能力清单 → CVSS 评分 → Rich 报告
```

### 4. 11 维分析框架

**第一层：能力测绘**
- ① 能力枚举：列出全部能力
- ② 权限分析：权限宽度 + 副作用等级
- ③ 高危能力标记：shell/exec/http/fs_write/db/payment/ssh/browser/email
- ⑨ 外部依赖：第三方API/SaaS/MCP/内部系统

**第二层：风险识别**
- ④ 权限组合：read+http=exfil, shell+fs=RCE, browser+email=phishing
- ⑤ 用户输入路径：user input → skill → dangerous operation
- ⑧ 能力一致性：描述 vs 权限 vs 实际（隐藏能力/参数劫持/夸大限制/作用域虚标）

**第三层：Skill 特有风险**
- 🅐 注入指令：描述中的指令性语言
- 🅑 审批机制：none/implicit/explicit/human_in_loop
- 🅒 元数据矛盾：权限字段与描述文本冲突
- 🅓 凭证硬编码：API Key/Token/密码/私钥
- 🅔 作用域穿透：路径遍历/命令注入/通配符滥用/环境变量注入

### 5. 改动文件清单

| 文件 | 动作 | 说明 |
|------|------|------|
| `agentrisk/models/config.py` | **重写** | 风险类别 8→14 种，Finding 新增 12 个扩展字段，新增 PermissionBreadth 枚举 |
| `agentrisk/analyzers/llm.py` | **重写** | System Prompt 从 500 字扩展到三层 11 维框架，FINDINGS_FUNCTION 新增 capability_inventory + 扩展字段 |
| `agentrisk/analyzers/skill.py` | **修改** | 处理新增 capability_inventory |
| `agentrisk/cli/main.py` | **修改** | 渲染能力清单、权限宽度、高危标记、组合风险、漂移检测、注入类型、审批级别、矛盾字段、凭证类型、穿透方式 |
| `agentrisk/rules/` | **删除** | 正则规则引擎全部删除 |

### 6. 模型切换

| 决策 | 原因 |
|------|------|
| deepseek-v4-pro → deepseek-chat | v4-pro 推理模型的 thinking tokens 吃掉大量 output budget，导致 Function Calling JSON 频繁截断。chat 模型专注 tool use，JSON 输出完整稳定。 |

### 7. JSON 容错机制

新增 `_safe_json_parse()` 函数，支持：
- 直接解析
- 补全缺失的 `}]}]}` 后缀
- 截断到最后一个完整 finding 对象

### 8. 测试验证（deepseek-chat）

| 样本 | 结果 | 评分 |
|------|------|------|
| `skill_malicious_combo.md` | 10 条发现（6 CRITICAL + 3 HIGH + 1 MEDIUM） | 100/100 |

**重构前（v2 5 维）**：5 条发现（2C+2H+1M）
**重构后（v3 11 维）**：10 条发现（6C+3H+1M）

新增发现：
- ⑤ 用户输入路径（CRITICAL）
- ④ 权限组合爆炸（CRITICAL）
- ⑧ 能力漂移——声称 DevOps 工具 vs 实际全权控制（HIGH）
- 🅒 元数据矛盾——温和标签 vs 激进权限（MEDIUM）
- 🅔 作用域穿透（HIGH）

### 9. 文档更新

- **蓝图** `bule print.txt`：更新架构、维度、进度、实测结果
- **V1 README** `drafts/V1-README.md`：更新架构图、维度描述
- **会话记录** `drafts/2026-07-01-session-summary.md`：本文档
- **记忆** MEMORY.md + project-current-state.md：全量同步

### 下一步

- [ ] Prompt Analyzer（Prompt 层安全分析）
- [ ] MCP Analyzer（MCP 配置安全分析）
- [ ] demo.yaml 演示配置
- [ ] 三个 Analyzer 统一入口 `agentrisk scan`
