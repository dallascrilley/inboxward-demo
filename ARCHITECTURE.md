# Inboxward Architecture

## Stack

- **Astro 5** — static site generator
- **TypeScript** — vanilla TS, no framework
- **Cloudflare Pages Function** — one serverless endpoint for live DNS inspection
- **No API keys, no environment variables, no stored state** — the backend is a stateless DNS-over-HTTPS proxy

## Live backend

`functions/inboxward/inspect.js` handles `GET /inboxward/inspect?domain=…` and performs real deliverability inspection at request time:

1. **Normalize + validate** the domain (strip scheme/path/trailing dot; reject non-hosts).
2. **Resolve in parallel** via `dns.google` DNS-over-HTTPS: root `TXT` (for SPF), `_dmarc.<domain>` `TXT`, and `<selector>._domainkey.<domain>` across 12 common ESP selectors (DKIM has no discovery mechanism, so deliverability tools probe a known set).
3. **Parse** SPF (count DNS-querying mechanisms against the SPF-10 lookup limit), DMARC (`p`/`pct`/`adkim`/`aspf`), and DKIM (TXT or CNAME-delegated).
4. **Return** a verdict in the same shape as a synthetic domain (`source: "live"`, plus `lookup_metadata` recording the provider, raw records, and the live/synthetic boundary), so the UI renders live and synthetic domains identically.

Pure parsing helpers (`normalizeDomain`, `parseDmarc`, `countSpfMechanisms`, …) are exported and unit-tested in `tests/inspect.test.js`; the network-bound resolver is kept thin and out of the test surface.

**Boundary:** SPF/DMARC/DKIM are live; blacklist status and inbox placement remain synthetic because they require paid or rate-limited external feeds (Spamhaus, seedlist providers). The synthetic fleet exercises scoring/remediation at scale; the live path proves the inspection is real.

## Data model

```typescript
interface Domain {
  id: string;
  name: string;
  registrar: string;
  created_date: string;
  spf_record: string;
  spf_status: 'pass' | 'warn' | 'fail';
  spf_mechanism_count: number;
  dkim_selector: string;
  dkim_key_age_days: number;
  dkim_status: 'pass' | 'warn' | 'fail';
  dmarc_policy: 'none' | 'quarantine' | 'reject';
  dmarc_alignment: 'relaxed' | 'strict';
  dmarc_pct: number;
  blacklist_statuses: { list: string; status: 'listed' | 'clear'; reason?: string }[];
  warmup_days: number;
  warmup_health: number;
  last_inbox_test: { provider: string; placement: number; date: string };
}
```

## Risk scoring formula

Base score: 100

| Condition | Penalty |
|---|---|
| SPF fail | −30 |
| SPF warn (>4 mechanisms) | −10 |
| DKIM fail | −25 |
| DKIM warn (key >90 days) | −8 |
| DMARC policy = none | −15 |
| DMARC quarantine with pct < 100 | −5 |
| Each blacklist listing | −20 |
| Inbox placement < 50% | −15 |
| Inbox placement < 80% | −5 |
| Domain < 30 days old | −10 |

Score clamped to [0, 100].

### Why this weighting

SPF and DKIM failures are the most severe because they break authentication entirely — emails will fail DMARC and likely be rejected or quarantined. Blacklist listings are equally severe but domain-specific. DMARC "none" is a policy gap, not a technical failure, so it carries less weight. Inbox placement below 50% is a symptom, not a root cause, so it's weighted lower than the infrastructure failures that cause it.

## Remediation generation

Remediations are generated deterministically from domain state:

1. **Missing SPF/DKIM** → critical, immediate action required
2. **SPF lookup limit** → warning, flatten before growth
3. **DKIM rotation due** → warning, scheduled maintenance
4. **DMARC none** → warning, policy hardening
5. **Blacklist** → critical, delisting + root cause
6. **Poor placement** → critical, pause campaigns
7. **Warm-up in progress** → info, monitor only

## File map

| File | Responsibility |
|---|---|
| `src/pages/index.astro` | Shell: nav, banner, sidebar + detail layout |
| `src/components/app.ts` | Bootstrap, domain list rendering, detail panel, remediation cards |
| `src/components/store.ts` | Data loading singleton |
| `src/components/types.ts` | Shared interfaces |
| `src/styles/inboxward.css` | Dark cockpit theme, risk color system, responsive grid |

## What is live vs. cut for scope

**Live:** SPF, DMARC, and DKIM are resolved against real DNS (see [Live backend](#live-backend)).

Cut for scope:
- **Real blacklist APIs** — static data (needs paid/rate-limited feeds)
- **Inbox placement** — synthetic (needs a seedlist provider)
- **Historical trending** — single snapshot
- **Multi-org view** — single tenant
- **Auto-fix execution** — suggestions only, no API calls

## How to extend to production

The live DNS path already covers authentication-record inspection. A production version would add:
1. Real blacklist API integration (Spamhaus, Barracuda, SURBL, MXToolbox)
2. Inbox placement testing (seedlist providers like GlockApps or Mail-Tester)
3. Historical trending and drift detection
4. Webhook alerts when a domain's score drops below threshold
5. Integration with registrars and DNS providers for auto-remediation

## Performance

- Render: <10ms for 12 domains
- Bundle: ~7 KB gzipped
