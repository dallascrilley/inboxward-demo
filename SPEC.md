# Inboxward SPEC

## Slug
`inboxward`

## Hook
"200 sending domains. 47 are in trouble. You don't know which."

## Lane
L1 primary (GTM / RevOps)

## What it proves
Email deliverability infrastructure management — SPF, DKIM, DMARC, domain warming, blacklist monitoring. The kind of work a GTM Engineer actually owns but never gets credit for.

## Demo surface

### Main view: Deliverability cockpit
Three-column layout:
- **Left:** Domain list with risk score per domain
- **Center:** Selected domain detail — DNS records, policy status, rotation age
- **Right:** Remediation playbook + auto-fix suggestions

### Domain list columns
- Domain name
- Overall risk score (0-100, green/yellow/red)
- SPF status
- DKIM status + key age
- DMARC policy
- Blacklist status
- Warm-up health

### Detail panel
For selected domain:
- SPF record validation (pass/fail/partial)
- DKIM selector + key age (days since rotation)
- DMARC policy (none/quarantine/reject) + alignment
- Blacklist checks (Spamhaus, Barracuda, SURBL)
- Warm-up progress (if < 30 days old)
- Last inbox placement test result

### Remediation playbook
Auto-generated fixes:
- "DKIM key > 90 days old → rotate via CNAME change"
- "DMARC policy is 'none' → upgrade to 'quarantine'"
- "SPF includes 8 mechanisms → flatten to avoid DNS lookup limit"
- "Domain on Spamhaus DBL → submit delisting request"

## Data
Synthetic data for 12 domains:
- 4 healthy (green, all checks pass)
- 4 warning (yellow, 1-2 issues)
- 4 critical (red, blacklist or no SPF/DKIM)

Each domain has:
- name, registrar, created_date
- spf_record, spf_status, spf_mechanism_count
- dkim_selector, dkim_key_age_days, dkim_status
- dmarc_policy, dmarc_alignment, dmarc_pct
- blacklist_statuses[]
- warmup_days, warmup_health
- last_inbox_test { provider, placement, date }

## Buildability
4 — moderate. Mostly data visualization and conditional logic. No complex algorithms.

## Acceptance criteria
- [ ] All 12 domains render with correct risk scores
- [ ] Detail panel populates on domain click
- [ ] Remediation suggestions are contextual and actionable
- [ ] Risk scoring formula is documented
- [ ] One-pager explains the deliverability concepts
- [ ] Synthetic banner visible
- [ ] Noindex meta tag present
- [ ] Builds clean, no console errors
