# Inboxward

[![CI](https://github.com/dallascrilley/inboxward-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/dallascrilley/inboxward-demo/actions/workflows/ci.yml)

> **200 sending domains. 47 are in trouble. You don't know which.**

Inboxward is an email-deliverability cockpit that audits SPF, DKIM, and DMARC across sending domains, scores deliverability risk, and generates prioritized remediation. It is a **hybrid proof**: a real backend performs live DNS inspection of any domain you type, and a synthetic fleet stands in for the signals that require paid external feeds.

**Live demo:** [dallascrilley.com/demos/inboxward](https://dallascrilley.com/demos/inboxward) — type any domain (try `openai.com`) and the cockpit inspects it live.

## Real vs. synthetic — the honest boundary

This is the line a reviewer should be able to see at a glance:

| Signal | Source |
|---|---|
| SPF record + lookup-count risk | **Live** — DNS-over-HTTPS query at request time |
| DMARC policy / alignment / `pct` | **Live** — DNS-over-HTTPS query at request time |
| DKIM presence (common selectors) | **Live** — probes 12 known ESP selectors via TXT/CNAME |
| Blacklist status (Spamhaus, etc.) | Synthetic — requires paid/rate-limited feeds |
| Inbox placement / seedlist tests | Synthetic — requires a seedlist provider |

The synthetic fleet (`public/data/domains.json`) demonstrates the scoring and remediation UI at scale; the live path proves the inspection logic is real.

## The backend

[`functions/inboxward/inspect.js`](functions/inboxward/inspect.js) is a **Cloudflare Pages Function** — `GET /inboxward/inspect?domain=example.com`. It:

- normalizes/validates the domain, then resolves `TXT`, `_dmarc` `TXT`, and `<selector>._domainkey` records via `dns.google` (DNS-over-HTTPS) — no API keys, no stored state;
- parses SPF (counting the DNS-querying mechanisms against the [SPF-10 lookup limit](https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4)), DMARC (`p`, `pct`, `adkim`/`aspf` alignment), and DKIM (TXT or CNAME-delegated);
- returns a normalized verdict in the same shape as a synthetic domain, so the UI treats live and synthetic identically.

```bash
curl "https://dallascrilley.com/demos/inboxward/inspect?domain=openai.com"
```

The parsing helpers are pure functions, exported and unit-tested in [`tests/inspect.test.js`](tests/inspect.test.js).

## Run locally

```bash
pnpm install
pnpm test                                    # unit tests for the DNS-parsing logic
pnpm dev                                     # static UI only — http://localhost:4321 (synthetic fleet)
pnpm build && npx wrangler pages dev dist    # UI + live backend — http://localhost:8788
```

The live inspection endpoint exists only under `wrangler pages dev` (port **8788**); `pnpm dev` (port 4321) serves the synthetic UI alone.

## What it proves

- **Deliverability infrastructure fluency** — SPF flattening, DKIM rotation, DMARC alignment, blacklist delisting.
- **Real protocol work** — live DoH resolution and correct SPF/DMARC/DKIM record parsing, not a mock.
- **Risk scoring** — composite 0–100 score weighted by business impact of each failure mode.
- **Honest system boundaries** — the live/synthetic split is explicit in the UI, the API response (`source`, `lookup_metadata`), and this README.

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the data model, scoring formula, backend design, and tradeoffs.

## License

MIT
