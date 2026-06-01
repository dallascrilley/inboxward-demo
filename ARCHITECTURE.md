# Inboxward Architecture

## Stack

- **Astro 5** — static site generator
- **TypeScript** — vanilla TS, no framework
- **No backend, no API keys, no environment variables**

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

## What was cut for scope

- **Live DNS resolution** — synthetic records only
- **Real blacklist APIs** — static data
- **Historical trending** — single snapshot
- **Multi-org view** — single tenant
- **Auto-fix execution** — suggestions only, no API calls

## How to extend to production

A production version would need:
1. Live DNS lookups (via DNS-over-HTTPS or internal resolver)
2. Real blacklist API integration (Spamhaus, Barracuda, SURBL, MXToolbox)
3. Inbox placement testing (Seedlist providers like GlockApps or Mail-Tester)
4. Historical trending and drift detection
5. Webhook alerts when a domain's score drops below threshold
6. Integration with registrars and DNS providers for auto-remediation

## Performance

- Render: <10ms for 12 domains
- Bundle: ~7 KB gzipped
