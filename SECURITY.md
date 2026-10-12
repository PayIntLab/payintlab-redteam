# Security and Authorized Use

PayIntLab Red Team actively sends adversarial prompts to the target you select.

## Allowed use

- Systems you own
- Staging or test environments where you have explicit written permission
- The official hosted practice lab: <https://vulnerable-rag-lab.onrender.com/>

## Prohibited use

- Scanning third-party systems without written authorization
- Testing production systems without explicit permission
- Using real customer data, PII, credentials, or production secrets
- Destructive, denial-of-service, or high-volume testing
- Using the tool to cause financial, operational, or reputational harm

## Guardrails

- Non-local targets require `--authorized`
- The CLI uses a low default rate limit
- The built-in checks are focused on prompt injection, data leakage, and tool misuse
- Reports are written locally; the CLI does not upload target data

## Responsible disclosure

If you find a vulnerability in PayIntLab Red Team itself, open a GitHub security advisory or contact the maintainers. If you want to test a real system, obtain written authorization first and define scope, time window, rate limit, and rules of engagement.
