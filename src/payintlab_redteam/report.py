from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def build_report(scan_result: dict[str, Any]) -> dict[str, Any]:
    findings = list(scan_result.get("findings", []))
    triggered = [item for item in findings if item.get("triggered")]
    by_severity: dict[str, int] = {}
    for item in triggered:
        severity = str(item.get("severity", "Unknown"))
        by_severity[severity] = by_severity.get(severity, 0) + 1
    hardened_blocked = sum(
        1 for item in findings if item.get("triggered") and item.get("hardened_blocked")
    )
    return {
        "tool": "payintlab-redteam",
        "version": "0.1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": scan_result.get("target"),
        "mode": scan_result.get("mode"),
        "health": scan_result.get("health", {}),
        "summary": {
            "total": len(findings),
            "triggered": len(triggered),
            "hardened_blocked": hardened_blocked,
            "by_severity": by_severity,
        },
        "findings": findings,
    }


def to_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# PayIntLab Red Team Report",
        "",
        f"- Target: `{report.get('target')}`",
        f"- Mode: `{report.get('mode')}`",
        f"- Generated: {report.get('generated_at')}",
        f"- Total checks: {summary['total']}",
        f"- Triggered: {summary['triggered']}",
        f"- Blocked after hardening: {summary.get('hardened_blocked', 0)}",
        f"- By severity: {summary.get('by_severity', {})}",
        "",
        "## Findings",
        "",
    ]
    for item in report.get("findings", []):
        status = "TRIGGERED" if item.get("triggered") else "NOT TRIGGERED"
        lines.extend(
            [
                f"### {item['id']} - {item['name']}",
                "",
                f"- Category: {item['category']}",
                f"- Severity: {item['severity']}",
                f"- Status: {status}",
                "",
                "**Prompt**",
                "",
                f"```text\n{item['prompt']}\n```",
                "",
                "**Response**",
                "",
                f"```text\n{item['response']}\n```",
                "",
                "**Evidence**",
                "",
                *[f"- {value}" for value in item.get("evidence", [])],
                "",
                "**Recommendation**",
                "",
                f"{item.get('recommendation', '')}",
                "",
                "---",
                "",
            ]
        )
    return "\n".join(lines)


def save_report(report: dict[str, Any], output_dir: str | Path) -> tuple[Path, Path]:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    json_path = path / "report.json"
    markdown_path = path / "report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    markdown_path.write_text(to_markdown(report), encoding="utf-8")
    return json_path, markdown_path
