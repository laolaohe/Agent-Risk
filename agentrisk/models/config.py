"""AgentRisk 数据模型 —— Pydantic 定义所有核心数据结构。

包含：
  - 风险评分三维度（可利用性 / 影响 / 范围）
  - 风险类别枚举（14 种，覆盖 11 维分析框架）
  - Finding 单条发现 & SkillReport 扫描报告
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── 风险严重程度 ──
class RiskSeverity(str, Enum):
    """风险等级，映射到终端颜色输出。"""
    CRITICAL = "CRITICAL"  # 严重
    HIGH = "HIGH"          # 高危
    MEDIUM = "MEDIUM"      # 中危
    LOW = "LOW"            # 低危


# ── CVSS 风格三维评分因子 ──
class Exploitability(str, Enum):
    """可利用性 —— 攻击者利用该风险的难易程度。"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Impact(str, Enum):
    """影响程度 —— 风险被利用后造成的损害大小。"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Scope(str, Enum):
    """作用范围 —— 风险影响的边界（单文件 / 单 Skill / 跨系统）。"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ── 风险类别（对应 11 维分析框架） ──
class RiskCategory(str, Enum):
    """风险类别，每种对应一种攻击模式或设计缺陷。

    第一层：能力测绘
    ────────────────
    """
    COMMAND_EXECUTION = "command_execution"          # ① 命令执行能力
    DATA_EXFILTRATION = "data_exfiltration"          # ② 数据外泄通道
    PRIVILEGE_ESCALATION = "privilege_escalation"    # ② 权限提升
    EXCESSIVE_PERMISSION = "excessive_permission"    # ② 权限过度宽泛
    DANGEROUS_CAPABILITY = "dangerous_capability"    # ③ 高危能力（shell/http/db等）
    EXTERNAL_DEPENDENCY = "external_dependency"      # ⑨ 外部依赖风险

    # 第二层：风险识别
    # ────────────────
    PRIVILEGE_COMBINATION = "privilege_combination"  # ④ 权限组合爆炸
    USER_INPUT_PATH = "user_input_path"              # ⑤ 用户输入可达危险操作
    CAPABILITY_DRIFT = "capability_drift"            # ⑧ 能力一致性（描述 vs 实际）

    # 第三层：Skill 特有风险
    # ────────────────
    PROMPT_INJECTION = "prompt_injection"            # 🅐 注入指令（Skill 描述含指令性语言）
    MISSING_APPROVAL = "missing_approval"            # 🅑 审批机制缺失
    METADATA_CONTRADICTION = "metadata_contradiction"  # 🅒 元数据与描述矛盾
    HARDCODED_CREDENTIAL = "hardcoded_credential"    # 🅓 凭证硬编码
    SCOPE_ESCAPE = "scope_escape"                    # 🅔 作用域穿透风险

    # 保留兼容
    SUPPLY_CHAIN = "supply_chain"                    # 供应链风险（含恶意 Skill）
    SCOPE_VIOLATION = "scope_violation"              # 作用域违规
    DANGEROUS_COMBO = "dangerous_combo"              # 高危组合（已升级为 privilege_combination）


# ── 权限宽度枚举 ──
class PermissionBreadth(str, Enum):
    """权限宽度 —— 某项能力的限制程度。"""
    UNRESTRICTED = "unrestricted"    # 无限制（任意命令/任意路径/任意域名）
    SCOPED = "scoped"               # 有限制但范围较宽
    MINIMAL = "minimal"             # 严格限制，最小权限


# ── 核心数据结构 ──
class Finding(BaseModel):
    """单条风险发现，包含完整攻击链和修复建议。

    对应 11 维分析框架中各项检测维度的输出载体。
    """
    severity: RiskSeverity              # 风险等级
    category: RiskCategory              # 风险类别
    rule_id: str = "LLM"                # 触发来源（LLM 发现）
    title: str                          # 发现标题（中文）
    description: str                    # 详细描述（中文）

    # CVSS 风格三维评分
    exploitability: Exploitability      # 可利用性评分
    impact: Impact                      # 影响程度评分
    scope: Scope                        # 作用范围评分

    attack_chain: str                   # 攻击链描述
    remediation: str                    # 修复建议
    matched_context: str = ""           # 匹配到的文本片段
    confidence: float = 1.0             # LLM 置信度 0.0~1.0

    # ── 11 维框架扩展字段（可选） ──
    capability: Optional[str] = None         # ① 该发现关联的具体能力名称
    permission_breadth: Optional[str] = None # ② 权限宽度（unrestricted/scoped/minimal）
    is_dangerous: Optional[bool] = None      # ③ 是否为高危能力
    combination_partners: Optional[list[str]] = None  # ④ 组合的能力列表
    user_input_reachable: Optional[bool] = None  # ⑤ 用户输入是否可达
    drift_type: Optional[str] = None         # ⑧ 漂移类型（hidden/hijack/exaggerate）
    external_target: Optional[str] = None    # ⑨ 外部依赖目标
    injection_type: Optional[str] = None     # 🅐 注入类型（instruction/override/chain）
    approval_level: Optional[str] = None     # 🅑 审批级别（none/implicit/explicit/human_in_loop）
    metadata_field: Optional[str] = None     # 🅒 矛盾的元数据字段名
    credential_type: Optional[str] = None    # 🅓 凭证类型（api_key/token/password）
    scope_bypass_method: Optional[str] = None  # 🅔 作用域穿透方式（path_traversal/command_injection/..）


class SkillReport(BaseModel):
    """Skill 扫描完整报告，汇总所有发现和评分。"""
    skill_file: str                     # 被扫描的文件路径
    overall_score: int                  # 综合风险评分 0-100
    severity: RiskSeverity              # 综合风险等级
    findings: list[Finding]             # 所有发现列表

    # ① 能力清单（新增）
    capability_inventory: list[str] = []   # LLM 枚举的全部能力

    # 统计计数
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0

    overall_assessment: str = ""        # LLM 整体安全评估评语
