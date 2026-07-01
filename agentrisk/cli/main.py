"""AgentRisk CLI —— Typer 命令行入口。

子命令结构：
  agentrisk skill scan <file>    扫描 Skill 文件中的安全风险
  （后续）agentrisk mcp scan <config>   扫描 MCP 配置
  （后续）agentrisk scan <config>       全量扫描（Skill + MCP + Prompt）
"""

import sys
import io
from pathlib import Path

# ── Windows 终端强制 UTF-8 编码（解决中文显示乱码） ──
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import typer
from rich.console import Console
from rich.table import Table

from agentrisk.analyzers.skill import analyze_skill_file

# ── Typer 应用实例 ──
app = typer.Typer(name="agentrisk", help="Agent 安全评估平台")
console = Console()

# ── 风险等级 → Rich 颜色映射 ──
SEVERITY_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "dim",
}

# ── 风险等级中文标签 ──
SEVERITY_LABELS = {
    "CRITICAL": "严重",
    "HIGH": "高危",
    "MEDIUM": "中危",
    "LOW": "低危",
}

# ── 风险类别中文标签 ──
CATEGORY_LABELS = {
    # 第一层：能力测绘
    "command_execution": "命令执行",
    "data_exfiltration": "数据外泄",
    "privilege_escalation": "权限提升",
    "excessive_permission": "权限过度",
    "dangerous_capability": "高危能力",
    "external_dependency": "外部依赖",
    # 第二层：风险识别
    "privilege_combination": "权限组合",
    "user_input_path": "用户输入路径",
    "capability_drift": "能力漂移",
    # 第三层：Skill 特有
    "prompt_injection": "注入指令",
    "missing_approval": "缺少审批",
    "metadata_contradiction": "元数据矛盾",
    "hardcoded_credential": "凭证硬编码",
    "scope_escape": "作用域穿透",
    # 保留兼容
    "supply_chain": "供应链风险",
    "scope_violation": "作用域违规",
    "dangerous_combo": "高危组合",
}

# ── 漂移类型中文标签 ──
DRIFT_LABELS = {
    "hidden": "隐藏能力",
    "hijack": "参数劫持",
    "exaggerate": "夸大限制",
    "scope": "作用域虚标",
}

# ── 凭证类型中文标签 ──
CREDENTIAL_LABELS = {
    "api_key": "API Key",
    "token": "访问令牌",
    "password": "密码",
    "private_key": "私钥",
}

# ── 穿透方式中文标签 ──
SCOPE_BYPASS_LABELS = {
    "path_traversal": "路径遍历",
    "command_injection": "命令注入",
    "wildcard_abuse": "通配符滥用",
    "env_injection": "环境变量注入",
}

# ── 审批级别中文标签 ──
APPROVAL_LABELS = {
    "none": "无审批",
    "implicit": "隐式审批",
    "explicit": "明确审批",
    "human_in_loop": "人工审批",
}


# ── 子命令组：agentrisk skill ... ──
skill_app = typer.Typer()
app.add_typer(skill_app, name="skill", help="Skill 层分析")


@skill_app.command("scan")
def scan_skill(
    file: str = typer.Argument(..., help="skill.md 文件路径"),
):
    """扫描 skill.md 文件中的安全风险。"""
    path = Path(file)

    # 文件存在性检查
    if not path.exists():
        console.print(f"[red]错误:[/] 文件不存在: {file}")
        raise typer.Exit(code=1)

    # 调用 Skill Analyzer 执行扫描
    report = analyze_skill_file(path)

    # ═══════════════════════════════════════════════
    # 报告头：文件信息 + 综合评分 + 风险等级
    # ═══════════════════════════════════════════════
    console.print()
    console.print("[bold]==== AgentRisk Skill 扫描报告 ====[/]")

    meta_table = Table(show_header=False, box=None, padding=(0, 2))
    meta_table.add_column("k", style="dim")
    meta_table.add_column("v")
    meta_table.add_row("文件", str(report.skill_file))
    meta_table.add_row("风险评分", _score_bar(report.overall_score))
    meta_table.add_row("风险等级", _severity_label(report.severity))
    if report.overall_assessment:
        meta_table.add_row("整体评语", report.overall_assessment)
    if report.capability_inventory:
        caps_formatted = "、".join(report.capability_inventory)
        meta_table.add_row("能力清单", f"[dim]{caps_formatted}[/]")
    console.print(meta_table)
    console.print()

    # ═══════════════════════════════════════════════
    # 发现列表：逐条展示风险详情
    # ═══════════════════════════════════════════════
    if not report.findings:
        console.print("[green]未检测到安全风险。[/]")
    else:
        for i, f in enumerate(report.findings, 1):
            sev_label = SEVERITY_LABELS.get(f.severity.value, f.severity.value)
            cat_label = CATEGORY_LABELS.get(f.category.value, f.category.value)

            # 标题行：序号 + 风险等级 + 标题 + 规则 ID
            console.print(
                f"  [{i}] [{SEVERITY_COLORS[f.severity.value]}][{sev_label}][/] "
                f"[bold]{f.title}[/] ({f.rule_id})"
            )
            console.print(f"      类别: {cat_label}")
            # CVSS 风格三维评分向量
            console.print(
                f"      评分向量: 利用难度={_label(f.exploitability.value)} / "
                f"影响程度={_label(f.impact.value)} / "
                f"作用范围={_label(f.scope.value)}"
            )
            console.print(f'      置信度: {f.confidence:.0%}')
            console.print(f'      匹配内容: "{f.matched_context}"')

            # ── 11 维扩展信息（有则展示） ──
            if f.capability:
                console.print(f"      关联能力: [cyan]{f.capability}[/]")
            if f.permission_breadth:
                breadth_map = {"unrestricted": "[red]无限制[/]", "scoped": "[yellow]受限[/]", "minimal": "[green]最小权限[/]"}
                console.print(f"      权限宽度: {breadth_map.get(f.permission_breadth, f.permission_breadth)}")
            if f.is_dangerous:
                console.print(f"      [bright_red]⚠ 高危能力[/]")
            if f.combination_partners:
                partners = " + ".join(f.combination_partners)
                console.print(f"      [yellow]⚡ 危险组合: {partners}[/]")
            if f.user_input_reachable:
                console.print(f"      [yellow]🔗 用户输入可达此操作[/]")
            if f.drift_type:
                drift_label = DRIFT_LABELS.get(f.drift_type, f.drift_type)
                console.print(f"      [magenta]🔍 能力漂移: {drift_label}[/]")
            if f.external_target:
                console.print(f"      外部依赖: [cyan]{f.external_target}[/]")
            if f.injection_type:
                inj_map = {"instruction": "指令注入", "override": "规则覆盖", "chain": "链式注入"}
                console.print(f"      [bright_red]💉 注入类型: {inj_map.get(f.injection_type, f.injection_type)}[/]")
            if f.approval_level:
                console.print(f"      审批级别: {APPROVAL_LABELS.get(f.approval_level, f.approval_level)}")
            if f.metadata_field:
                console.print(f"      [yellow]⚠ 矛盾字段: {f.metadata_field}[/]")
            if f.credential_type:
                cred_label = CREDENTIAL_LABELS.get(f.credential_type, f.credential_type)
                console.print(f"      [bright_red]🔑 泄露凭证类型: {cred_label}[/]")
            if f.scope_bypass_method:
                bypass_label = SCOPE_BYPASS_LABELS.get(f.scope_bypass_method, f.scope_bypass_method)
                console.print(f"      [yellow]⚠ 作用域穿透: {bypass_label}[/]")

            # 攻击链（黄色）
            console.print(f"      [bold yellow]>> 攻击链:[/]")
            for line in f.attack_chain.strip().split("\n"):
                console.print(f"         {line.strip()}", style="dim")

            # 修复建议（绿色）
            console.print(f"      [bold green]>> 修复建议:[/]")
            for line in f.remediation.strip().split("\n"):
                console.print(f"         [green]{line.strip()}[/]")
            console.print()

    # ═══════════════════════════════════════════════
    # 汇总行：各等级发现计数
    # ═══════════════════════════════════════════════
    parts = []
    if report.total_critical:
        parts.append(f"[bright_red]严重: {report.total_critical}[/]")
    if report.total_high:
        parts.append(f"[red]高危: {report.total_high}[/]")
    if report.total_medium:
        parts.append(f"[yellow]中危: {report.total_medium}[/]")
    if report.total_low:
        parts.append(f"[dim]低危: {report.total_low}[/]")

    console.print(f"  风险汇总: {'  '.join(parts)}")
    console.print("=" * 60)


# ── 终端渲染辅助函数 ──

def _score_bar(score: int) -> str:
    """渲染风险评分条：用 # 和 - 组成 20 格进度条。

    颜色分段：
      0-19  绿色（低危）
      20-49 黄色（中危）
      50-79 红色（高危）
      80-100 亮红（严重）
    """
    if score < 20:
        color = "green"
    elif score < 50:
        color = "yellow"
    elif score < 80:
        color = "red"
    else:
        color = "bright_red"
    # 每 5 分一格，满分 100 对应 20 格
    bar_len = score // 5
    bar_filled = "#" * bar_len
    bar_empty = "-" * (20 - bar_len)
    return f"[{color}]{bar_filled}{bar_empty}[/] [{color}]{score}/100[/]"


def _severity_label(sev) -> str:
    """渲染带颜色的风险等级中文标签。"""
    color = SEVERITY_COLORS.get(sev.value, "white")
    label = SEVERITY_LABELS.get(sev.value, sev.value)
    return f"[bold {color}]{label}[/]"


def _label(val: str) -> str:
    """将评分维度值转为中文简写（HIGH → 高 / MEDIUM → 中 / LOW → 低）。"""
    mapping = {"HIGH": "高", "MEDIUM": "中", "LOW": "低"}
    return mapping.get(val, val)


# ── 入口 ──
if __name__ == "__main__":
    app()
