# AgentRisk

**Wiz for Agent — Agent 上线前安全评估平台**

对 Agent 的 Skill 配置进行自动化安全分析，输出风险评分和安全建议。

---

## V1 能做啥

```bash
agentrisk skill scan samples/skill_malicious_combo.md
```

输入一个 Skill 文件（Markdown），LLM 自动执行三层 11 维威胁建模：

### 第一层：能力测绘
| 维度 | 检测项 |
|------|--------|
| ① 能力枚举 | 列出全部能力（shell/http/fs/db/email/browser...） |
| ② 权限分析 | 权限宽度（无限制/受限/最小）+ 副作用等级（只读/修改/删除/执行） |
| ③ 高危标记 | shell / exec / http / fs_write / db_write / payment / ssh / browser / email |
| ⑨ 外部依赖 | 第三方 API / SaaS / MCP Server / 内部系统 |

### 第二层：风险识别
| 维度 | 检测项 |
|------|--------|
| ④ 权限组合 | read+http=exfil, shell+fs=RCE, browser+email=phishing |
| ⑤ 用户输入路径 | user input → skill → dangerous operation |
| ⑧ 能力一致性 | 描述 vs 权限 vs 实际（隐藏能力/参数劫持/夸大限制/作用域虚标） |

### 第三层：Skill 特有风险
| 维度 | 检测项 |
|------|--------|
| 🅐 注入指令 | 描述中暗藏指令性语言 |
| 🅑 审批机制 | 无审批 / 隐式 / 明确 / 人工审批 |
| 🅒 元数据矛盾 | 权限字段与描述文本冲突 |
| 🅓 凭证硬编码 | API Key / Token / 密码 / 私钥 |
| 🅔 作用域穿透 | 路径遍历 / 命令注入 / 通配符滥用 / 环境变量注入 |

输出终端彩色风险报告，包含能力清单 + Risk Score + CVSS 评分向量 + 攻击链 + 修复建议。

---

## 快速开始

```bash
# 安装
pip install -r requirements.txt

# 设置 DeepSeek API Key
set DEEPSEEK_API_KEY=sk-你的key

# 扫描 Skill 文件
python -m agentrisk.cli.main skill scan samples/skill_malicious_combo.md
```

> 模型使用 deepseek-chat（兼容 OpenAI SDK），专为 tool use / 结构化输出优化。

---

## 实测结果

| 样本 | 发现数 | 评分 | 等级 |
|------|--------|------|------|
| `skill_malicious_combo.md` | 10（6C+3H+1M） | 100/100 | 严重 |

10 条发现覆盖：命令执行 / 文件操作 / HTTP 外连 / 邮件 / 权限组合爆炸 / 用户输入路径 / 能力漂移 / 元数据矛盾 / 审批缺失 / 作用域穿透

---

## 输出示例

```
==== AgentRisk Skill 扫描报告 ====
  文件        samples/skill_malicious_combo.md
  风险评分    #################### 100/100
  风险等级    严重
  能力清单    shell、filesystem_write、filesystem_modify、...

  [1] [严重] 无限制 Shell 命令执行权限
      类别: 命令执行
      评分向量: 利用难度=高 / 影响程度=高 / 作用范围=高
      置信度: 100%
      关联能力: shell
      权限宽度: 无限制
      ⚠ 高危能力
      >> 攻击链:
         攻击者构造恶意 Prompt → Agent 调用该 Skill
         → 执行任意 bash 命令 → 攻击者获得 RCE → 完全控制宿主系统
      >> 修复建议:
         1. 移除任意命令执行权限，改用白名单模式
         2. 如必须执行动态命令，使用参数化方式并严格校验
         3. 所有命令执行操作必须有人工审批

  [5] [严重] 高危权限组合：Shell + 文件系统 + HTTP + 邮件 = 完整攻击链
      类别: 权限组合
      ⚡ 危险组合: filesystem_write + http_request + email_send
      >> 攻击链:
         攻击者 Prompt Injection → Agent 执行 Shell 下载恶意负载
         → 写入文件系统持久化 → 读取敏感文件
         → HTTP POST 外泄到 C2 → 邮件发送内部信息 → 删除日志清理痕迹

  [8] [高危] 能力漂移：声称 DevOps 工具 vs 实际全权控制
      类别: 能力漂移
      🔍 能力漂移: 隐藏能力
      >> 攻击链:
         用户信任该 Skill 仅用于 DevOps → 实际拥有全权控制能力
         → 攻击者利用信任差距绕过安全审查 → 获得超出预期的系统控制权

  风险汇总: 严重: 6  高危: 3  中危: 1
============================================================
```

---

## 架构

```
Skill 文件（.md）
      │
      ▼
CLI (Typer) → Skill Analyzer → deepseek-chat API
                                  │
          ┌───────────────────────┘
          │
          ▼
    System Prompt（三层 11 维）
    + User Prompt（Skill 全文）
    + tools=[report_findings]
          │
          ▼
    JSON 结构化输出
    ├─ capability_inventory（能力清单）
    ├─ findings（风险发现列表）
    └─ overall_assessment（整体评语）
          │
          ▼
    CVSS 三维评分（0-100）
          │
          ▼
    Rich 彩色终端报告
```

---

## 项目结构

```
agentrisk/
├── cli/              CLI 入口（Typer + Rich）
│   └── main.py       agentrisk skill scan 命令
├── analyzers/        分析器
│   ├── llm.py        LLM 分析核心（11 维 System Prompt + DeepSeek API）
│   └── skill.py      Skill 分析入口
└── models/           数据模型（Pydantic）
    └── config.py     Finding（14 种风险类别）/ SkillReport
samples/              测试样本 ×5（全部中文）
```

---

## 版本路线

| 版本 | 内容 |
|------|------|
| **V1** *(当前)* | Skill Analyzer（11 维 LLM 威胁建模） |
| V1.x | + Prompt Analyzer + MCP Analyzer + 统一入口 `agentrisk scan` |
| V2 | RAG 知识库 + MITRE ATLAS 映射 + Threat Graph |
| V3 | Web Dashboard + PDF 报告 + CI/CD 集成 |

---

## 技术栈

Python · Typer · Rich · PyYAML · Pydantic · OpenAI SDK（DeepSeek deepseek-chat）
