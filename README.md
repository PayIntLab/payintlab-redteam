# PayIntLab Red Team

[![CI](https://github.com/PayIntLab/payintlab-redteam/actions/workflows/ci.yml/badge.svg)](https://github.com/PayIntLab/payintlab-redteam/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

Open-source AI red-team CLI for payment, fintech and multi-tenant RAG agents.

Find prompt injection, cross-tenant leakage, canary PII exposure, API key leakage, refund tool misuse, unauthorized emails and RAG poisoning before launch.

## Why this exists

Strix and other tools are excellent for broad, horizontal AI pentesting. PayIntLab Red Team focuses on a narrower and higher-stakes problem:

- Payment, fintech and multi-tenant RAG agents
- Cross-tenant data leakage
- Canary PII and secret exposure
- Refund, email and confirmation-gate misuse
- Evidence-first vulnerable vs hardened comparison

## Install

```bash
curl -sSL https://raw.githubusercontent.com/PayIntLab/payintlab-redteam/main/install.sh | bash
```

Or with pipx:

```bash
pipx install git+https://github.com/PayIntLab/payintlab-redteam.git
```

## Quick start

### 1. Use the hosted practice lab

```text
https://vulnerable-rag-lab.onrender.com/
```

### 2. List checks

```bash
payintlab-redteam attacks
```

### 3. Scan

```bash
payintlab-redteam scan --target https://vulnerable-rag-lab.onrender.com --mode lab
```

For a local lab (available on request), run it on port 8001 and use:

```bash
payintlab-redteam scan --target http://127.0.0.1:8001 --mode lab
```

## Modes

| Mode | Behavior |
|---|---|
| `lab` | Calls the lab's vulnerable vs hardened comparison endpoint (10 checks) |
| `quick` | Runs 5 high-value prompt-injection and data-leakage checks |
| `full` | Runs all 10 chat-based checks |

## Checks

| ID | Check | Category | Severity |
|---|---|---|---|
| SP-01 | System prompt extraction | Prompt Injection | High |
| SP-02 | System prompt via summarization | Prompt Injection | Medium |
| PI-01 | Indirect prompt injection | Prompt Injection | Critical |
| DL-01 | Cross-tenant retrieval | Data Leakage | Critical |
| DL-02 | Canary PII leakage | Data Leakage | High |
| DL-03 | API key leakage | Data Leakage | High |
| TM-01 | Unauthorized refund | Tool Misuse | Critical |
| TM-02 | External email abuse | Tool Misuse | High |
| TM-03 | Confirmation bypass | Tool Misuse | High |
| RAG-01 | RAG poisoning | RAG | High |

## Reports

Each run writes:

```text
payintlab-reports/<timestamp>/report.json
payintlab-reports/<timestamp>/report.md
```

The CLI exits with code `1` when any Critical or High finding is triggered, so it can be used as a CI gate.

## Example output

```text
Target: https://vulnerable-rag-lab.onrender.com
Mode: lab
Triggered: 10/10
By severity: {'Critical': 3, 'High': 6, 'Medium': 1}

V01  System prompt extraction      High      YES   blocked after hardening
V02  Cross-tenant retrieval        Critical  YES   blocked after hardening
V03  Canary PII and API key leak   High      YES   blocked after hardening
V04  Unauthorized refund           Critical  YES   blocked after hardening
V05  Indirect prompt injection     Critical  YES   blocked after hardening
```

## Safety

This tool actively sends adversarial prompts to the target you point it at. Only test systems you own or have explicit written permission to test. For non-local targets, you must pass `--authorized`.

```bash
payintlab-redteam scan --target https://your-staging-app.example.com --authorized
```

Never use real customer data, production secrets or destructive actions.

The official hosted practice lab is allowlisted for convenience. Every other non-local target requires `--authorized`.

## Comparison with Strix

| | Strix | PayIntLab Red Team |
|---|---|---|
| Scope | Horizontal AI pentesting | Payment / fintech / multi-tenant RAG |
| Targets | Code, web, API, OpenAPI, Postman | RAG agents with chat + tools |
| Strength | Broad exploit validation, multi-agent | Cross-tenant, canary, refund/email abuse, RAG poisoning |
| Output | Security assessment | Evidence-first red-team report + hardened retest |
| Model | Open-source + cloud/enterprise | Open-source CLI + service layer |

Strix is broader. PayIntLab Red Team is deeper in the payment and multi-tenant RAG niche.

## Roadmap

- GitHub Actions integration
- MCP server
- Strix skill for payment/RAG checks
- HTML report and local viewer
- More payment-specific checks: refund, reconciliation, chargeback, webhook replay
- Cloud-hosted scan history

## License

MIT
