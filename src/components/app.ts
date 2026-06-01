import { loadDomains } from './store.js';
import type { Domain, Remediation } from './types.js';

function el(id: string): HTMLElement | null {
  return document.getElementById(id);
}

function computeRiskScore(d: Domain): number {
  let score = 100;
  if (d.spf_status === 'fail') score -= 30;
  else if (d.spf_status === 'warn') score -= 10;
  if (d.dkim_status === 'fail') score -= 25;
  else if (d.dkim_status === 'warn') score -= 8;
  if (d.dmarc_policy === 'none') score -= 15;
  else if (d.dmarc_policy === 'quarantine' && d.dmarc_pct < 100) score -= 5;
  score -= d.blacklist_statuses.length * 20;
  if (d.warmup_days < 30) score -= 10;
  if (d.last_inbox_test.placement < 50) score -= 15;
  else if (d.last_inbox_test.placement < 80) score -= 5;
  return Math.max(0, Math.min(100, score));
}

function riskClass(score: number): string {
  if (score >= 80) return 'healthy';
  if (score >= 60) return 'warning';
  return 'critical';
}

function generateRemediations(d: Domain): Remediation[] {
  const r: Remediation[] = [];
  if (d.spf_status === 'fail') {
    r.push({ severity: 'critical', title: 'Missing SPF record', description: 'No SPF record found. Emails will fail authentication.', action: 'Add an SPF record: v=spf1 include:_spf.google.com ~all' });
  } else if (d.spf_mechanism_count > 4) {
    r.push({ severity: 'warning', title: 'SPF lookup limit', description: `SPF includes ${d.spf_mechanism_count} mechanisms. DNS lookup limit is 10.`, action: 'Flatten SPF record or remove unused includes.' });
  }
  if (d.dkim_status === 'fail') {
    r.push({ severity: 'critical', title: 'Missing DKIM', description: 'No DKIM selector configured. Reputation cannot be isolated per domain.', action: 'Configure DKIM selector and publish DNS TXT record.' });
  } else if (d.dkim_key_age_days > 90) {
    r.push({ severity: 'warning', title: 'DKIM key rotation due', description: `DKIM key is ${d.dkim_key_age_days} days old. Best practice: rotate every 90 days.`, action: 'Generate new DKIM key and update DNS TXT record.' });
  }
  if (d.dmarc_policy === 'none') {
    r.push({ severity: 'warning', title: 'DMARC policy is none', description: 'DMARC is in monitoring mode only. No enforcement.', action: 'Upgrade to p=quarantine with pct=25, then ramp to p=reject.' });
  }
  for (const bl of d.blacklist_statuses) {
    r.push({ severity: 'critical', title: `Listed on ${bl.list}`, description: bl.reason || 'Domain or IP is blacklisted.', action: 'Submit delisting request and identify root cause.' });
  }
  if (d.warmup_days < 30) {
    r.push({ severity: 'info', title: 'Domain warming in progress', description: `Domain is ${d.warmup_days} days old. Warm-up protocol active.`, action: 'Continue gradual volume increase; monitor placement daily.' });
  }
  if (d.last_inbox_test.placement < 50) {
    r.push({ severity: 'critical', title: 'Poor inbox placement', description: `Only ${d.last_inbox_test.placement}% reaching inbox on ${d.last_inbox_test.provider}.`, action: 'Pause campaigns; investigate content and reputation.' });
  }
  return r;
}

function renderDomainList(domains: Domain[]): void {
  const container = el('iw-domain-list');
  if (!container) return;

  domains.sort((a, b) => computeRiskScore(a) - computeRiskScore(b));

  container.innerHTML = domains.map(d => {
    const score = computeRiskScore(d);
    const rc = riskClass(score);
    return `
      <div class="iw-domain" data-id="${d.id}">
        <div class="iw-domain-header">
          <span class="iw-domain-name">${d.name}</span>
          <span class="iw-risk ${rc}">${score}</span>
        </div>
        <div class="iw-domain-meta">
          <span class="iw-badge ${d.spf_status}">SPF ${d.spf_status}</span>
          <span class="iw-badge ${d.dkim_status}">DKIM ${d.dkim_status}</span>
          <span class="iw-badge ${d.dmarc_policy === 'none' ? 'fail' : d.dmarc_policy === 'quarantine' ? 'warn' : 'pass'}">DMARC ${d.dmarc_policy}</span>
          ${d.blacklist_statuses.length ? `<span class="iw-badge critical">BL ${d.blacklist_statuses.length}</span>` : ''}
        </div>
      </div>
    `;
  }).join('');

  container.querySelectorAll('.iw-domain').forEach(domainEl => {
    domainEl.addEventListener('click', () => {
      const id = domainEl.getAttribute('data-id');
      const domain = domains.find(d => d.id === id);
      if (domain) showDomainDetail(domain);
    });
  });

  // Update summary stats
  const statsEl = el('iw-stats');
  if (statsEl) {
    const healthy = domains.filter(d => computeRiskScore(d) >= 80).length;
    const warning = domains.filter(d => { const s = computeRiskScore(d); return s >= 60 && s < 80; }).length;
    const critical = domains.filter(d => computeRiskScore(d) < 60).length;
    statsEl.innerHTML = `
      <span class="iw-stat healthy">${healthy} healthy</span>
      <span class="iw-stat warning">${warning} warning</span>
      <span class="iw-stat critical">${critical} critical</span>
    `;
  }
}

function showDomainDetail(d: Domain): void {
  const panel = el('iw-detail-panel');
  if (!panel) return;

  const score = computeRiskScore(d);
  const rc = riskClass(score);
  const remediations = generateRemediations(d);

  panel.innerHTML = `
    <div class="iw-detail-header">
      <div>
        <div class="iw-detail-name">${d.name}</div>
        <div class="iw-detail-registrar">${d.registrar} · Created ${d.created_date}</div>
      </div>
      <span class="iw-risk-large ${rc}">${score}</span>
    </div>

    <div class="iw-checks">
      <div class="iw-check">
        <div class="iw-check-label">SPF</div>
        <div class="iw-check-value ${d.spf_status}">${d.spf_status === 'pass' ? 'Valid' : d.spf_status === 'warn' ? 'Warning' : 'Missing'}</div>
        <div class="iw-check-detail">${d.spf_record || 'No record'}</div>
        ${d.spf_mechanism_count > 4 ? `<div class="iw-check-alert">${d.spf_mechanism_count} mechanisms — flatten recommended</div>` : ''}
      </div>
      <div class="iw-check">
        <div class="iw-check-label">DKIM</div>
        <div class="iw-check-value ${d.dkim_status}">${d.dkim_status === 'pass' ? 'Valid' : d.dkim_status === 'warn' ? 'Rotate soon' : 'Missing'}</div>
        <div class="iw-check-detail">${d.dkim_selector ? `Selector: ${d.dkim_selector} · ${d.dkim_key_age_days} days old` : 'No selector configured'}</div>
      </div>
      <div class="iw-check">
        <div class="iw-check-label">DMARC</div>
        <div class="iw-check-value ${d.dmarc_policy === 'none' ? 'fail' : d.dmarc_policy === 'quarantine' ? 'warn' : 'pass'}">${d.dmarc_policy === 'none' ? 'Monitoring only' : d.dmarc_policy === 'quarantine' ? 'Quarantine' : 'Reject'}</div>
        <div class="iw-check-detail">Alignment: ${d.dmarc_alignment} · pct=${d.dmarc_pct}</div>
      </div>
      <div class="iw-check">
        <div class="iw-check-label">Blacklist</div>
        <div class="iw-check-value ${d.blacklist_statuses.length ? 'fail' : 'pass'}">${d.blacklist_statuses.length ? `${d.blacklist_statuses.length} listed` : 'Clear'}</div>
        ${d.blacklist_statuses.map(bl => `<div class="iw-check-alert">${bl.list}: ${bl.reason}</div>`).join('')}
      </div>
      <div class="iw-check">
        <div class="iw-check-label">Inbox Placement</div>
        <div class="iw-check-value ${d.last_inbox_test.placement >= 80 ? 'pass' : d.last_inbox_test.placement >= 50 ? 'warn' : 'fail'}">${d.last_inbox_test.placement}% (${d.last_inbox_test.provider})</div>
        <div class="iw-check-detail">Tested ${d.last_inbox_test.date}</div>
      </div>
      <div class="iw-check">
        <div class="iw-check-label">Warm-up</div>
        <div class="iw-check-value ${d.warmup_days >= 30 ? 'pass' : 'warn'}">${d.warmup_days} days</div>
        <div class="iw-check-detail">Health score: ${d.warmup_health}/100</div>
      </div>
    </div>

    ${remediations.length ? `
      <div class="iw-remediations">
        <div class="iw-rem-heading">Remediation Playbook</div>
        ${remediations.map(rem => `
          <div class="iw-rem-card ${rem.severity}">
            <div class="iw-rem-title">${rem.title}</div>
            <div class="iw-rem-desc">${rem.description}</div>
            <div class="iw-rem-action">→ ${rem.action}</div>
          </div>
        `).join('')}
      </div>
    ` : ''}
  `;
}

async function init(): Promise<void> {
  const domains = await loadDomains();
  renderDomainList(domains);

  // Select first domain by default
  if (domains.length) showDomainDetail(domains[0]);
}

init().catch(console.error);
