from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from .checks import CHECKS, Check, Finding

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEMO_HOSTS = {"vulnerable-rag-lab.onrender.com"}
QUICK_CHECK_IDS = {"SP-01", "SP-02", "PI-01", "DL-01", "DL-02"}


@dataclass(frozen=True)
class ScanConfig:
    target: str = "http://127.0.0.1:8001"
    tenant_id: str = "tenant-a"
    token: str | None = None
    authorized: bool = False
    rate_limit: float = 0.5
    timeout: float = 30.0


class TargetClient:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.params = {"token": config.token} if config.token else {}
        self.client = httpx.Client(
            base_url=config.target.rstrip("/"),
            timeout=config.timeout,
            headers={"User-Agent": "payintlab-redteam/0.1"},
        )

    def close(self) -> None:
        self.client.close()

    @property
    def hostname(self) -> str:
        return urlparse(self.config.target).hostname or ""

    def is_local(self) -> bool:
        return self.hostname in LOCAL_HOSTS

    def assert_authorized(self) -> None:
        if self.is_local() or self.hostname in DEMO_HOSTS:
            return
        if not self.config.authorized:
            raise PermissionError(
                "Refusing to scan a non-local target without --authorized. "
                "Only test systems you own or have explicit written permission to test."
            )

    def health(self) -> dict[str, Any]:
        response = self.client.get("/health", params=self.params)
        response.raise_for_status()
        return response.json()

    def chat(self, message: str) -> dict[str, Any]:
        response = self.client.post(
            "/api/chat",
            params=self.params,
            json={
                "tenant_id": self.config.tenant_id,
                "user_id": "payintlab-redteam",
                "message": message,
            },
        )
        response.raise_for_status()
        return response.json()

    def lab_attack_run(self) -> dict[str, Any]:
        response = self.client.post(
            "/api/attacks/run",
            params=self.params,
            json={"mode": "compare"},
        )
        response.raise_for_status()
        return response.json()


def select_checks(mode: str) -> list[Check]:
    if mode == "quick":
        return [check for check in CHECKS if check.id in QUICK_CHECK_IDS]
    return list(CHECKS)


def _evidence(payload: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    if payload.get("canary_hits"):
        evidence.append(f"canary_hits={payload['canary_hits']}")
    if payload.get("tool_calls"):
        evidence.append(f"tool_calls={payload['tool_calls']}")
    for key in ("system_prompt_leaked", "malicious_followed", "cross_tenant_used"):
        if payload.get(key):
            evidence.append(f"{key}=true")
    return evidence


def scan_checks(client: TargetClient, checks: list[Check]) -> list[Finding]:
    findings: list[Finding] = []
    for check in checks:
        response_payload = client.chat(check.prompt)
        response_text = str(response_payload.get("answer", ""))
        findings.append(
            Finding(
                id=check.id,
                name=check.name,
                category=check.category,
                severity=check.severity,
                prompt=check.prompt,
                response=response_text,
                triggered=check.detect(response_payload),
                evidence=_evidence(response_payload),
                recommendation=check.recommendation,
            )
        )
        time.sleep(client.config.rate_limit)
    return findings


def scan_lab_report(client: TargetClient) -> list[Finding]:
    report = client.lab_attack_run()
    findings: list[Finding] = []
    for item in report.get("findings", []):
        findings.append(
            Finding(
                id=str(item.get("id", "UNKNOWN")),
                name=str(item.get("name", "Unknown")),
                category=str(item.get("category", "Unknown")),
                severity=str(item.get("severity", "Medium")),
                prompt=str(item.get("input", "")),
                response=str(item.get("answer", "")),
                triggered=bool(item.get("triggered")),
                evidence=[str(value) for value in item.get("evidence", [])],
                recommendation=str(item.get("recommendation", "")),
                hardened_blocked=not bool(item.get("hardened_triggered")),
            )
        )
    return findings


def run_scan(config: ScanConfig, mode: str = "lab") -> dict[str, Any]:
    client = TargetClient(config)
    try:
        client.assert_authorized()
        health = client.health()
        if mode == "lab":
            findings = scan_lab_report(client)
        else:
            findings = scan_checks(client, select_checks(mode))
        return {
            "target": config.target,
            "mode": mode,
            "health": health,
            "findings": [asdict(finding) for finding in findings],
        }
    finally:
        client.close()
