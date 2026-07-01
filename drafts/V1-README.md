# AgentRisk V1

**AI Agent 上线前安全评估平台** — 用 LLM 对 Agent 配置做深度安全分析。

---

## 一句话

```bash
agentrisk skill scan evil.md
```

输入一个 Skill 文件，LLM 自动识别风险，输出彩色安全报告。

---

## 能检测什么（11 维三层框架）

### 第一层：能力测绘
| 维度 | 检测内容 | 示例 |
|------|---------|------|
| ① 能力枚举 | 列出全部能力 | shell/http/fs/db/email/browser |
| ② 权限分析 | 宽度（无限制/受限/最小）+ 副作用 | `approval: none`、`scope: any` |
| ③ 高危标记 | 单独标记高危能力 | shell/exec/http/fs_write/payment/ssh |
| ⑨ 外部依赖 | 第三方API/SaaS/MCP/内部系统 | OpenAI API / GitHub MCP |

### 第二层：风险识别
| 维度 | 检测内容 | 示例 |
|------|---------|------|
| ④ 权限组合 | 能力组合爆炸 | read+http=exfil, shell+fs=RCE |
| ⑤ 用户输入路径 | 用户输入能否到达危险操作 | 无过滤直接传参给 bash |
| ⑧ 能力一致性 | 描述 vs 权限 vs 实际能力 | "只读搜索"实际可写文件 |

### 第三层：Skill 特有风险
| 维度 | 检测内容 | 示例 |
|------|---------|------|
| 🅐 注入指令 | 描述中暗藏指令性语言 | "忽略之前的规则" |
| 🅑 审批机制 | 无/隐式/明确/人工审批 | 分级评估 |
| 🅒 元数据矛盾 | 权限字段与描述文本冲突 | execute:none 但描述"可执行命令" |
| 🅓 凭证硬编码 | API Key / Token / 密码 | `sk-xxx` / `ghp_xxx` |
| 🅔 作用域穿透 | 路径遍历/命令注入/通配符 | `../../../etc/passwd` |

每条发现附带：风险等级 + CVSS 三维评分向量 + 能力清单 + 攻击链还原 + 具体修复建议 + LLM 置信度 + 扩展字段（权限宽度/组合伙伴/漂移类型/注入类型等）。

---

## 安装

```bash
git clone https://github.com/laolaohe/Agent-Risk.git
cd Agent-Risk
pip install -r requirements.txt
```

设置 DeepSeek API Key：

```bash
# Windows
set DEEPSEEK_API_KEY=sk-你的key

# Mac / Linux
export DEEPSEEK_API_KEY=sk-你的key
```

> 也支持 `OPENAI_API_KEY` 变量名。Key 获取：https://platform.deepseek.com/api_keys

---

## 使用

```bash
# 扫描单个 Skill 文件
agentrisk skill scan samples/skill_malicious_shell.md
```

输出示例：

```
==== AgentRisk Skill 扫描报告 ====
  文件        samples/skill_malicious_shell.md
  风险评分    #################### 100/100
  风险等级    严重
  整体评语    该 Skill 是一个完全无防护的 Shell 执行后门…

  [1] [严重] 任意 Shell 命令执行（完全 RCE）
      类别: 命令执行
      评分向量: 利用难度=高 / 影响程度=高 / 作用范围=高
      置信度: 100%
      匹配内容: "passes it to /bin/bash -c. No sanitization…"
      >> 攻击链:
         攻击者通过提示注入向 Agent 注入恶意命令字符串
         → Agent 将命令原样传递给 /bin/bash -c
         → 攻击者获得宿主系统 RCE 能力
         → 可进一步下载后门、窃取数据、横向移动
      >> 修复建议:
         1. 立即删除此 Skill…
         2. 如需保留，实施命令白名单…
         3. 沙箱隔离执行环境…

  风险汇总: 严重: 2  高危: 3
============================================================
```

---

	## 架构

```
Skill 文件（.md）
      │
      ▼
┌─────────────────────┐
│ CLI                 │  Typer 解析 → scan_skill()
│ cli/main.py         │  检查文件存在 / 读取内容
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Skill Analyzer      │  analyze_skill_file()
│ analyzers/skill.py  │  调用 LLM → findings → 评分 → SkillReport
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ LLM Analyzer        │  analyze_with_llm()
│ analyzers/llm.py    │  ┌──────────────────────────┐
│                     │  │ System Prompt（三层11维） │
│                     │  │ 能力测绘+风险识别+Skill特有│
│                     │  ├──────────────────────────┤
│                     │  │ User Prompt：Skill名+全文 │
│                     │  ├──────────────────────────┤
│                     │  │ deepseek-chat API          │
│                     │  │ tools=[report_findings]   │
│                     │  │ Function Calling 强制JSON  │
│                     │  ├──────────────────────────┤
│                     │  │ 解析 tool_calls → Finding │
│                     │  └──────────────────────────┘
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ 评分引擎             │  _calculate_score()
│                     │  CRITICAL×30 HIGH×20 MED×10 LOW×5
│                     │  各级 cap 上限，满分 100
│                     │  _overall_severity() 等级映射
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Rich 终端输出        │  彩色中文报告
│                     │  报告头 + 发现列表 + 攻击链 + 修复建议 + 汇总
└─────────────────────┘
```

核心链路：**Skill 全文 → deepseek-chat 三层 11 维分析 → Function Calling JSON（能力清单+发现+评语） → CVSS 评分 → Rich 彩色报告**。

---

## 项目结构

```
agentrisk/
├── cli/              CLI 入口（Typer + Rich）
│   └── main.py       agentrisk skill scan 命令
├── analyzers/        分析器
│   ├── llm.py        LLM 分析核心（System Prompt + DeepSeek API）
│   └── skill.py      Skill 分析入口
├── models/           数据模型（Pydantic）
│   └── config.py     Finding / SkillReport / 枚举
├── scoring/          评分引擎（规划中）
└── reports/          报告模板（规划中）
samples/              测试样本
├── skill_malicious_shell.md      明显的 Shell 后门
├── skill_malicious_injection.md  暗藏注入指令
├── skill_malicious_combo.md      多重风险组合
├── skill_malicious_noscope.md    无作用域限制
└── skill_benign_readonly.md      正确设计的良性 Skill
```

---

## 技术栈

| 组件 | 技术 |
|------|------|
| CLI | Typer + Rich |
| LLM | deepseek-chat（兼容 OpenAI SDK，tool use 优化） |
| 数据 | Pydantic v2 |
| 语言 | Python 3.11 |

---

## 风险评分模型

CVSS 风格三维加权：

| 等级 | 单条权重 | 计入上限 |
|------|---------|---------|
| CRITICAL | +30 | 最多 3 条 |
| HIGH | +20 | 最多 3 条 |
| MEDIUM | +10 | 最多 4 条 |
| LOW | +5 | 最多 4 条 |

设 cap 上限防止大量低危发现撑高总分，确保评分反映"最严重的几条"而非"总条数"。

---

## 版本路线

| 版本 | 内容 |
|------|------|
| **V1** *(当前)* | Skill Analyzer（LLM 端到端） |
| V1.x | + Prompt Analyzer + MCP Analyzer + 统一入口 `agentrisk scan` |
| V2 | RAG 知识库 + MITRE ATLAS 映射 + Threat Graph |
| V3 | Web Dashboard + PDF 报告 + CI/CD 集成 |
