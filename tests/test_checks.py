from __future__ import annotations

from payintlab_redteam.checks import CHECKS, Finding
from payintlab_redteam.report import build_report, to_markdown
from payintlab_redteam.scanner import ScanConfig, scan_checks, select_checks


def test_all_checks_have_unique_ids() -> None:
    ids = [check.id for check in CHECKS]
    assert len(ids) == len(set(ids))
    assert len(ids) == 10


def test_quick_mode_selects_five_checks() -> None:
    assert len(select_checks("quick")) == 5
    assert len(select_checks("full")) == 10


def test_detectors_trigger_on_lab_payloads() -> None:
    payload = {
        "answer": "System prompt: CANARY-SYSTEM-PROMPT-7f3a; API key: sk-canary-globex-001",
        "system_prompt_leaked": True,
        "malicious_followed": True,
        "cross_tenant_used": True,
        "canary_hits": ["CANARY-CUSTOMER-001"],
        "tool_calls": [
            {"tool": "issue_refund", "allowed": True},
            {"tool": "send_email", "allowed": True},
        ],
    }
    triggered_ids = {check.id for check in CHECKS if check.detect(payload)}
    expected = {"SP-01", "SP-02", "PI-01", "DL-01", "DL-02", "DL-03", "TM-01", "TM-02", "TM-03"}
    assert expected <= triggered_ids


def test_report_summary_and_markdown() -> None:
    findings = [
        Finding(
            id="SP-01",
            name="System prompt extraction",
            category="Prompt Injection",
            severity="High",
            prompt="test",
            response="leaked",
            triggered=True,
            evidence=["system_prompt_leaked=true"],
            recommendation="fix it",
        ),
        Finding(
            id="DL-02",
            name="Canary PII leakage",
            category="Data Leakage",
            severity="Critical",
            prompt="test",
            response="safe",
            triggered=False,
        ),
    ]
    report = build_report(
        {
            "target": "http://127.0.0.1:8001",
            "mode": "full",
            "health": {"status": "ok"},
            "findings": [finding.__dict__ for finding in findings],
        }
    )
    assert report["summary"]["total"] == 2
    assert report["summary"]["triggered"] == 1
    assert report["summary"]["by_severity"] == {"High": 1}
    markdown = to_markdown(report)
    assert "PayIntLab Red Team Report" in markdown
    assert "System prompt extraction" in markdown


class FakeClient:
    def __init__(self) -> None:
        self.config = ScanConfig()

    def chat(self, message: str) -> dict:
        return {"answer": "safe"}

    def close(self) -> None:
        pass


def test_scan_checks_returns_findings() -> None:
    findings = scan_checks(FakeClient(), select_checks("quick"))  # type: ignore[arg-type]
    assert len(findings) == 5
    assert all(finding.triggered is False for finding in findings)
