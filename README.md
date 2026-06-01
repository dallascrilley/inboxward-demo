# Inboxward

> **200 sending domains. 47 are in trouble. You don't know which.**

Inboxward is a client-side email deliverability cockpit that audits SPF, DKIM, DMARC, blacklist status, and inbox placement across all sending domains. It generates auto-prioritized remediation playbooks with zero backend.

**Live demo:** [demos.dallascrilley.com/inboxward](https://demos.dallascrilley.com/inboxward)

## What it proves

- **Deliverability infrastructure fluency** — understands SPF flattening, DKIM rotation, DMARC alignment, and blacklist delisting workflows.
- **Risk scoring** — composite 0-100 score weighted by actual business impact of each failure mode.
- **Remediation prioritization** — auto-generated fixes ranked by severity, not just listed.
- **Zero-backend architecture** — all validation logic, scoring, and playbook generation runs in vanilla TypeScript.

## Run locally

```bash
pnpm install
pnpm dev
```

Open `http://localhost:4321`. The demo loads 12 synthetic domains from `public/data/domains.json`.

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for design decisions, scoring formula, and tradeoffs.

## Honest limits

- **No live DNS lookups** — records are synthetic.
- **No real blacklist queries** — Spamhaus, Barracuda, SURBL status is fabricated.
- **No inbox placement API** — test results are synthetic.
- **Single-tenant** — no multi-org view.

## License

MIT
