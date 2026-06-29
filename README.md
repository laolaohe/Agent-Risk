# AgentRisk

**Wiz for Agent — Agent 上线前安全评估平台**

对 Agent 的配置进行自动化安全分析，输出风险评分和安全建议。

---

## V1 能做啥

```bash
agentrisk scan demo.yaml
```

输入一个 Agent 配置（YAML），自动分析三个层面：

| 分析层 | 检测项 |
|--------|--------|
| **Prompt** | Instruction Override、Privilege Escalation、敏感资产暴露 |
| **Skill** | Shell 执行、文件系统写入、高危 Skill |
| **MCP** | 外部 MCP、权限过大、供应链风险 |

输出终端彩色风险报告，包含 Risk Score + CVSS 评分向量 + 修复建议。

---

## 快速开始

```bash
# 安装
pip install -r requirements.txt

# 扫描内置 Demo
agentrisk scan demo.yaml
```

## 输出示例

```
╔══════════════════════════════════╗
║   AgentRisk Scan Report         ║
╠══════════════════════════════════╣
║ Agent: data-classifier          ║
║ Risk Score: 82 (CRITICAL)       ║
╠══════════════════════════════════╣
║ [CRIT] System Prompt: DB access ║
║        Vector: E:H/I:H/S:M      ║
║        → Restrict SQL to read-only
║ [HIGH]  Shell Skill             ║
║        Vector: E:H/I:H/S:L      ║
║        → Add human-in-the-loop  ║
║ [HIGH]  External MCP (GitHub)   ║
║        Vector: E:M/I:H/S:M      ║
║        → Scope to read-only     ║
║ [MED]   Unscoped MCP (Jira)     ║
║        Vector: E:L/I:M/S:L      ║
║        → Limit project scope    ║
╚══════════════════════════════════╝
```

---

## 版本路线

| 版本 | 内容 |
|------|------|
| **V1** *(当前)* | CLI + Prompt / Skill / MCP 三个 Analyzer + 风险评分 |
| V2 | Workflow + Memory Analyzer + Threat Graph + MITRE ATLAS |
| V3 | Web Dashboard + PDF 报告 + CI/CD 集成 |

---

## 技术栈

Python · Typer · Rich · PyYAML · Pydantic · Jinja2
