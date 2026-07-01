"""Skill Analyzer —— 对 Skill 文件执行端到端 LLM 安全分析。

工作流程：
  1. 读取 Skill 文件内容
  2. 调用 DeepSeek LLM 进行深度语义分析
  3. 按 CVSS 风格三维模型计算综合风险评分
  4. 汇总各等级发现数量，返回 SkillReport
"""

from pathlib import Path

from agentrisk.analyzers.llm import analyze_with_llm
from agentrisk.models.config import Finding, RiskSeverity, SkillReport


def analyze_skill_file(file_path: str | Path) -> SkillReport:
    """读取 Skill 文件并调用 LLM 执行深度安全分析。

    Args:
        file_path: Skill 文件路径（.md）

    Returns:
        SkillReport，包含所有发现、综合评分、风险等级和整体评语

    Raises:
        FileNotFoundError: 文件不存在时抛出
        ValueError: DEEPSEEK_API_KEY 未设置
        RuntimeError: LLM API 调用失败
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Skill file not found: {file_path}")

    # 读取 Skill 全文，文件名（去掉扩展名）作为 Skill 标识
    skill_text = path.read_text(encoding="utf-8")
    skill_name = path.stem

    # 调用 DeepSeek LLM 进行端到端分析
    result = analyze_with_llm(skill_text, skill_name)
    findings: list[Finding] = result["findings"]
    overall_assessment: str = result.get("overall_assessment", "")
    capability_inventory: list[str] = result.get("capability_inventory", [])

    # 基于发现列表计算综合评分和风险等级
    score = _calculate_score(findings)
    severity = _overall_severity(score)

    # 按严重程度统计发现数量
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity.value] += 1

    return SkillReport(
        skill_file=str(path),
        overall_score=score,
        severity=severity,
        findings=findings,
        capability_inventory=capability_inventory,
        total_critical=counts["CRITICAL"],
        total_high=counts["HIGH"],
        total_medium=counts["MEDIUM"],
        total_low=counts["LOW"],
        overall_assessment=overall_assessment,
    )


def _calculate_score(findings: list[Finding]) -> int:
    """基于发现列表计算综合风险评分（0-100），CVSS 风格加权模型。

    评分模型设计：
      CRITICAL = +30（最多计 3 条 → 上限 90）
      HIGH     = +20（最多计 3 条 → 上限 60）
      MEDIUM   = +10（最多计 4 条 → 上限 40）
      LOW      = +5 （最多计 4 条 → 上限 20）

    设 cap 是为了防止大量低危发现撑高总分，确保评分反映的是
    "最严重的几条发现"而非"发现的总条数"。
    """
    # 权重：每条发现对总分的贡献
    weights = {
        RiskSeverity.CRITICAL: 30,
        RiskSeverity.HIGH: 20,
        RiskSeverity.MEDIUM: 10,
        RiskSeverity.LOW: 5,
    }
    # 上限：每个等级最多计入的发现条数
    caps = {
        RiskSeverity.CRITICAL: 3,
        RiskSeverity.HIGH: 3,
        RiskSeverity.MEDIUM: 4,
        RiskSeverity.LOW: 4,
    }

    # 按等级分桶统计
    bucket: dict[RiskSeverity, int] = {}
    for f in findings:
        bucket[f.severity] = bucket.get(f.severity, 0) + 1

    # 加权求和，并应用每个等级的条数上限
    score = 0
    for sev, count in bucket.items():
        capped = min(count, caps.get(sev, 99))
        score += capped * weights.get(sev, 0)

    return min(score, 100)


def _overall_severity(score: int) -> RiskSeverity:
    """将 0-100 的综合评分映射到风险等级。

    阈值设计：
      80-100 → CRITICAL（严重）
      50-79  → HIGH（高危）
      20-49  → MEDIUM（中危）
      0-19   → LOW（低危）
    """
    if score >= 80:
        return RiskSeverity.CRITICAL
    if score >= 50:
        return RiskSeverity.HIGH
    if score >= 20:
        return RiskSeverity.MEDIUM
    return RiskSeverity.LOW
