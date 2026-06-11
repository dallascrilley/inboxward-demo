import { inspectLiveDomain, loadDomains } from './store.js';
import type { Domain, LiveDomainInspection, Remediation } from './types.js';

function el<T extends HTMLElement = HTMLElement>(id: string): T | null {
  return document.getElementById(id) as T | null;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function formatMaybe(value: string | number | null | undefined, fallback = 'Unavailable'): string {
  if (value === null || value === undefined || value === '') return fallback;
  return String(value);
}

function computeRiskScore(d: Domain): number {
  let score = 100;
  if (d.spf_status === 'fail') score -= 30;
  else if (d.spf_status === 'warn') score -= 10;

  if (d.dkim_status === 'fail') score -= 25;
  else if (d.dkim_status === 'warn') score -= 8;

  if (d.dmarc_policy === 'none') score -= 15;
  else if (d.dmarc_policy === 'quarantine' && (d.dmarc_pct ?? 100) < 100) score -= 5;

  score -= d.blacklist_statuses.length * 20;

  if ((d.warmup_days ?? 999) < 30) score -= 10;

  const placement = d.last_inbox_test?.placement;
  if (placement !== undefined && placement !== null) {
    if (placement < 50) score -= 15;
    else if (placement < 80) score -= 5;
  }

  return Math.max(0, Math.min(100, score));
}

function riskClass(score: number): 'healthy' | 'warning' | 'critical' {
  if (score >= 80) return 'healthy';
  if (score >= 60) return 'warning';
  return 'critical';
}

function generateRemediations(d: Domain): Remediation[] {
  const remediations: Remediation[] = [];

  if (d.spf_status === 'fail') {
    remediations.push({
      severity: 'critical',
      title: 'Missing SPF record',
      description: 'No SPF record found. Receivers cannot verify which senders are authorized.',
      action: 'Publish an SPF record for the root domain and limit senders to the platforms you actually use.',
    });
  } else if ((d.spf_mechanism_count ?? 0) > 4) {
    remediations.push({
      severity: 'warning',
      title: 'SPF lookup budget getting tight',
      description: `SPF includes ${d.spf_mechanism_count} lookup-causing mechanisms. The hard limit is 10.`,
      action: 'Flatten SPF or remove unused includes before new senders push the record over the limit.',
    });
  }

  if (d.dkim_status === 'fail') {
    remediations.push({
      severity: 'critical',
      title: 'DKIM not detected',
      description: 'No DKIM selector was found in the standard probe set, so mailbox providers cannot verify signed mail.',
      action: 'Publish a DKIM key for the active ESP selector and verify signing is enabled in the sender platform.',
    });
  } else if ((d.dkim_key_age_days ?? 0) > 90) {
    remediations.push({
      severity: 'warning',
      title: 'DKIM key rotation due',
      description: `Current DKIM key age is ${d.dkim_key_age_days} days. Long-lived keys increase blast radius if a sender is compromised.`,
      action: 'Generate a new key pair, stage the new selector, then rotate traffic over after propagation.',
    });
  } else if (d.source === 'live' && d.dkim_status === 'warn') {
    remediations.push({
      severity: 'warning',
      title: 'DKIM selector not found in standard probes',
      description: 'The live lookup checked common selectors only. Your domain may still be signed under a nonstandard selector.',
      action: 'Confirm the active selector in the ESP and add it to the verification workflow before treating this as an outage.',
    });
  }

  if (d.dmarc_policy === 'none') {
    remediations.push({
      severity: 'warning',
      title: 'DMARC still in monitor-only mode',
      description: 'Mailbox providers receive reports, but fraudulent mail is not yet quarantined or rejected.',
      action: 'Move to p=quarantine first, validate alignment, then ramp to p=reject when false positives are cleared.',
    });
  } else if (d.dmarc_policy === 'quarantine' && (d.dmarc_pct ?? 100) < 100) {
    remediations.push({
      severity: 'info',
      title: 'DMARC enforcement is partial',
      description: `Only ${(d.dmarc_pct ?? 0)}% of failing mail is quarantined right now.`,
      action: 'Increase pct toward 100 once aggregate reports show legitimate mail is aligned.',
    });
  }

  for (const blacklist of d.blacklist_statuses) {
    remediations.push({
      severity: 'critical',
      title: `Listed on ${blacklist.list}`,
      description: blacklist.reason || 'A blacklist listing will materially hurt inbox placement until remediated.',
      action: 'Stop the causing traffic, identify the offending campaign or sender, then file for delisting with evidence of the fix.',
    });
  }

  if ((d.warmup_days ?? 999) < 30) {
    remediations.push({
      severity: 'info',
      title: 'Domain warm-up still in progress',
      description: `This sender is only ${d.warmup_days ?? 0} days into warm-up, so reputation is still immature.`,
      action: 'Keep daily volume ramps gradual and avoid list-quality experiments until the sender stabilizes.',
    });
  }

  const placement = d.last_inbox_test?.placement;
  if (placement !== undefined && placement !== null && placement < 50) {
    remediations.push({
      severity: 'critical',
      title: 'Poor inbox placement',
      description: `Latest seed test reached the inbox only ${placement}% of the time on ${d.last_inbox_test?.provider}.`,
      action: 'Pause broad sends, isolate the sender, then inspect auth, content, and complaint spikes before resuming.',
    });
  }

  if (d.source === 'live') {
    remediations.push({
      severity: 'info',
      title: 'Live mode is DNS-only',
      description: 'This inspection verifies public DNS records in real time, but does not include blacklist feeds or inbox placement telemetry.',
      action: 'Pair this surface with seed testing and blacklist monitoring before using it as the only production control panel.',
    });
  }

  return remediations;
}

function renderStats(domains: Domain[]): void {
  const statsEl = el('iw-stats');
  if (!statsEl) return;

  const healthy = domains.filter((domain) => computeRiskScore(domain) >= 80).length;
  const warning = domains.filter((domain) => {
    const score = computeRiskScore(domain);
    return score >= 60 && score < 80;
  }).length;
  const critical = domains.filter((domain) => computeRiskScore(domain) < 60).length;

  statsEl.innerHTML = `
    <span class="iw-stat healthy">${healthy} healthy</span>
    <span class="iw-stat warning">${warning} warning</span>
    <span class="iw-stat critical">${critical} critical</span>
  `;
}

// Fleet cockpit — every instrument computed from the loaded domains, not hardcoded.
// Only instruments backed by real data are shown; reputation/volume telemetry was
// removed because the dataset carries no time-series or send-volume to compute them.
function renderCockpit(domains: Domain[]): void {
  const n = domains.length;
  if (!n) return;
  const pct = (count: number): number => Math.round((count / n) * 100);
  const band = (v: number): 'pass' | 'warn' | 'fail' => (v >= 80 ? 'pass' : v >= 50 ? 'warn' : 'fail');

  const fleetCount = el('iw-fleet-count');
  if (fleetCount) fleetCount.textContent = `${n} domain${n === 1 ? '' : 's'}`;

  // Deliverability index = mean health score across the fleet.
  const mean = Math.round(domains.reduce((sum, d) => sum + computeRiskScore(d), 0) / n);
  const gaugeCls = band(mean);
  const gaugeWord = mean >= 80 ? 'healthy' : mean >= 60 ? 'warning' : 'critical';
  const gaugeNum = el('iw-gauge-num');
  if (gaugeNum) gaugeNum.textContent = String(mean);
  const gaugeFill = el('iw-gauge-fill');
  if (gaugeFill) {
    gaugeFill.classList.remove('pass', 'warn', 'fail');
    gaugeFill.classList.add(gaugeCls);
    gaugeFill.style.setProperty('--iw-gauge-pct', String(mean));
  }
  el('iw-gauge-svg')?.setAttribute('aria-label', `Fleet deliverability index ${mean} of 100, ${gaugeWord}`);

  // Auth coverage = share of the fleet passing each check.
  const authList = el('iw-auth-list');
  if (authList) {
    const row = (key: string, value: number): string => {
      const c = band(value);
      return `<li class="iw-auth-row"><span class="iw-auth-key">${key}</span>` +
        `<span class="iw-meter" aria-hidden="true"><span class="iw-meter-fill ${c}" style="--iw-meter:${value}"></span></span>` +
        `<span class="iw-auth-val ${c}">${value}%</span></li>`;
    };
    const spf = pct(domains.filter((d) => d.spf_status === 'pass').length);
    const dkim = pct(domains.filter((d) => d.dkim_status === 'pass').length);
    const dmarc = pct(domains.filter((d) => d.dmarc_policy === 'quarantine' || d.dmarc_policy === 'reject').length);
    authList.innerHTML = row('SPF', spf) + row('DKIM', dkim) + row('DMARC', dmarc);
  }

  // Priority queue = real outstanding issues across the fleet.
  const todo = el('iw-todo');
  if (todo) {
    const blacklisted = domains.filter((d) => d.blacklist_statuses.length > 0).length;
    const dkimOld = domains.filter((d) => (d.dkim_key_age_days ?? 0) > 90).length;
    const monitorOnly = domains.filter((d) => d.dmarc_policy === 'none').length;
    const spfTight = domains.filter((d) => (d.spf_mechanism_count ?? 0) > 4).length;
    const item = (cls: string, label: string): string =>
      `<li class="iw-todo-item ${cls}"><span class="iw-todo-dot" aria-hidden="true"></span>${label}</li>`;
    const items: string[] = [];
    if (blacklisted) items.push(item('critical', `${blacklisted} domain${blacklisted === 1 ? '' : 's'} on a blocklist`));
    if (dkimOld) items.push(item('warn', `${dkimOld} DKIM key${dkimOld === 1 ? '' : 's'} &gt;90 days`));
    if (monitorOnly) items.push(item('warn', `DMARC monitor-only ×${monitorOnly}`));
    if (spfTight) items.push(item('warn', `${spfTight} SPF record${spfTight === 1 ? '' : 's'} near lookup limit`));
    if (!items.length) items.push(item('healthy', 'No outstanding auth issues'));
    todo.innerHTML = items.join('');
  }
}

function renderDomainList(domains: Domain[]): void {
  const container = el('iw-domain-list');
  if (!container) return;

  const ordered = [...domains].sort((a, b) => computeRiskScore(a) - computeRiskScore(b));

  container.innerHTML = ordered.map((domain) => {
    const score = computeRiskScore(domain);
    const rc = riskClass(score);
    const sourceBadge = domain.source === 'live'
      ? '<span class="iw-badge live">LIVE DNS</span>'
      : '<span class="iw-badge synthetic">SYNTH</span>';

    return `
      <button class="iw-domain" data-id="${escapeHtml(domain.id)}" type="button">
        <div class="iw-domain-header">
          <span class="iw-domain-name">${escapeHtml(domain.name)}</span>
          <span class="iw-risk ${rc}">${score}</span>
        </div>
        <div class="iw-domain-meta">
          ${sourceBadge}
          <span class="iw-badge ${domain.spf_status}">SPF ${escapeHtml(domain.spf_status)}</span>
          <span class="iw-badge ${domain.dkim_status}">DKIM ${escapeHtml(domain.dkim_status)}</span>
          <span class="iw-badge ${domain.dmarc_policy === 'none' ? 'fail' : domain.dmarc_policy === 'quarantine' ? 'warn' : 'pass'}">DMARC ${escapeHtml(domain.dmarc_policy)}</span>
          ${domain.blacklist_statuses.length ? `<span class="iw-badge critical">BL ${domain.blacklist_statuses.length}</span>` : ''}
        </div>
      </button>
    `;
  }).join('');

  container.querySelectorAll<HTMLElement>('.iw-domain').forEach((domainEl) => {
    domainEl.addEventListener('click', () => {
      const id = domainEl.getAttribute('data-id');
      const domain = ordered.find((candidate) => candidate.id === id);
      if (domain) showDomainDetail(domain);
    });
  });

  renderStats(domains);
  renderCockpit(domains);
}

function liveLookupNotes(domain: LiveDomainInspection): string {
  const rootRecords = domain.lookup_metadata.root_txt_records.length
    ? domain.lookup_metadata.root_txt_records.map((record) => `<li><code>${escapeHtml(record)}</code></li>`).join('')
    : '<li>No root TXT records returned.</li>';

  return `
    <div class="iw-live-notes">
      <div class="iw-live-notes-heading">Live lookup notes</div>
      <p class="iw-live-note-body"><strong>${escapeHtml(domain.lookup_metadata.note)}</strong> Checked ${escapeHtml(domain.lookup_metadata.checked_at)} via ${escapeHtml(domain.lookup_metadata.dns_provider)}.</p>
      <div class="iw-live-grid">
        <div>
          <div class="iw-live-label">DMARC record</div>
          <div class="iw-live-value"><code>${escapeHtml(formatMaybe(domain.lookup_metadata.dmarc_record))}</code></div>
        </div>
        <div>
          <div class="iw-live-label">DKIM probe</div>
          <div class="iw-live-value"><code>${escapeHtml(formatMaybe(domain.lookup_metadata.dkim_probe_host))}</code></div>
        </div>
      </div>
      <div class="iw-live-label">Root TXT records</div>
      <ul class="iw-live-records">${rootRecords}</ul>
    </div>
  `;
}

function showDomainDetail(domain: Domain, scroll = true): void {
  const panel = el('iw-detail-panel');
  if (!panel) return;

  const score = computeRiskScore(domain);
  const rc = riskClass(score);
  const remediations = generateRemediations(domain);
  const liveDomain = domain.source === 'live' ? (domain as LiveDomainInspection) : null;

  const blacklistContent = domain.blacklist_statuses.length
    ? domain.blacklist_statuses.map((entry) => `<div class="iw-check-alert">${escapeHtml(entry.list)}: ${escapeHtml(entry.reason || 'listed')}</div>`).join('')
    : liveDomain
      ? '<div class="iw-check-detail">Live mode is DNS-only — blacklist feeds are demonstrated on the synthetic fleet.</div>'
      : '<div class="iw-check-detail">No blacklist data attached.</div>';

  panel.innerHTML = `
    <div class="iw-detail-header">
      <div>
        <div class="iw-detail-name">${escapeHtml(domain.name)}</div>
        <div class="iw-detail-registrar">
          ${escapeHtml(domain.source === 'live' ? 'Live DNS inspection' : formatMaybe(domain.registrar, 'Synthetic dataset'))}
          · Created ${escapeHtml(formatMaybe(domain.created_date, 'unknown'))}
        </div>
      </div>
      <div class="iw-detail-score">
        <span class="iw-source-pill ${domain.source === 'live' ? 'live' : 'synthetic'}">${domain.source === 'live' ? 'LIVE DNS' : 'SYNTHETIC'}</span>
        <span class="iw-risk-large ${rc}">${score}</span>
      </div>
    </div>

    <div class="iw-checks">
      <div class="iw-check">
        <div class="iw-check-label">SPF</div>
        <div class="iw-check-value ${domain.spf_status}">${domain.spf_status === 'pass' ? 'Valid' : domain.spf_status === 'warn' ? 'Warning' : 'Missing'}</div>
        <div class="iw-check-detail">${escapeHtml(formatMaybe(domain.spf_record, 'No SPF record found'))}</div>
        ${(domain.spf_mechanism_count ?? 0) > 0 ? `<div class="iw-check-detail">Lookup-causing mechanisms: ${domain.spf_mechanism_count}</div>` : ''}
        ${(domain.spf_mechanism_count ?? 0) > 4 ? `<div class="iw-check-alert">${domain.spf_mechanism_count} mechanisms — flatten recommended before adding more senders.</div>` : ''}
      </div>

      <div class="iw-check">
        <div class="iw-check-label">DKIM</div>
        <div class="iw-check-value ${domain.dkim_status}">${domain.dkim_status === 'pass' ? 'Detected' : domain.dkim_status === 'warn' ? 'Needs verification' : 'Missing'}</div>
        <div class="iw-check-detail">${escapeHtml(domain.dkim_selector ? `Selector: ${domain.dkim_selector}` : 'No selector detected')}</div>
        <div class="iw-check-detail">${escapeHtml(domain.dkim_key_age_days !== null ? `${domain.dkim_key_age_days} days old` : liveDomain?.dkim_record ? liveDomain.dkim_record : 'No key age data')}</div>
      </div>

      <div class="iw-check">
        <div class="iw-check-label">DMARC</div>
        <div class="iw-check-value ${domain.dmarc_policy === 'none' ? 'fail' : domain.dmarc_policy === 'quarantine' ? 'warn' : 'pass'}">${domain.dmarc_policy === 'none' ? 'Monitoring only' : domain.dmarc_policy === 'quarantine' ? 'Quarantine' : 'Reject'}</div>
        <div class="iw-check-detail">Alignment: ${escapeHtml(domain.dmarc_alignment)}</div>
        <div class="iw-check-detail">pct=${escapeHtml(formatMaybe(domain.dmarc_pct, 'unknown'))}</div>
      </div>

      <div class="iw-check">
        <div class="iw-check-label">Blacklist</div>
        <div class="iw-check-value ${domain.blacklist_statuses.length ? 'fail' : liveDomain ? 'warn' : 'pass'}">${domain.blacklist_statuses.length ? `${domain.blacklist_statuses.length} listed` : liveDomain ? 'Not checked — live mode' : 'No flags attached'}</div>
        ${blacklistContent}
      </div>

      <div class="iw-check">
        <div class="iw-check-label">Inbox Placement</div>
        <div class="iw-check-value ${domain.last_inbox_test ? (domain.last_inbox_test.placement >= 80 ? 'pass' : domain.last_inbox_test.placement >= 50 ? 'warn' : 'fail') : 'warn'}">${domain.last_inbox_test ? `${domain.last_inbox_test.placement}% (${escapeHtml(domain.last_inbox_test.provider)})` : liveDomain ? 'Not tested — live mode' : 'No seed test loaded'}</div>
        <div class="iw-check-detail">${escapeHtml(domain.last_inbox_test ? `Tested ${domain.last_inbox_test.date}` : liveDomain ? 'Live mode is DNS-only — placement signals are demonstrated on the synthetic fleet.' : 'No seed test attached.')}</div>
      </div>

      <div class="iw-check">
        <div class="iw-check-label">Warm-up</div>
        <div class="iw-check-value ${(domain.warmup_days ?? 999) >= 30 ? 'pass' : 'warn'}">${escapeHtml(domain.warmup_days !== null ? `${domain.warmup_days} days` : 'Unknown')}</div>
        <div class="iw-check-detail">${escapeHtml(domain.warmup_health !== null ? `Health score: ${domain.warmup_health}/100` : 'No warm-up telemetry attached.')}</div>
      </div>
    </div>

    ${liveDomain ? liveLookupNotes(liveDomain) : ''}

    ${remediations.length ? `
      <div class="iw-remediations">
        <div class="iw-rem-heading">Remediation Playbook</div>
        ${remediations.map((remediation) => `
          <div class="iw-rem-card ${remediation.severity}">
            <div class="iw-rem-title">${escapeHtml(remediation.title)}</div>
            <div class="iw-rem-desc">${escapeHtml(remediation.description)}</div>
            <div class="iw-rem-action">→ ${escapeHtml(remediation.action)}</div>
          </div>
        `).join('')}
      </div>
    ` : ''}
  `;

  // Mobile-first layout stacks list above detail — bring the detail into view
  // on user-initiated selections (the initial render must not move the page;
  // desktop keeps the panel sticky alongside the list).
  if (scroll && window.matchMedia('(max-width: 979px)').matches) {
    panel.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }
}

async function handleLiveLookup(domains: Domain[]): Promise<void> {
  const form = el<HTMLFormElement>('iw-live-form');
  const input = el<HTMLInputElement>('iw-live-domain');
  const status = el('iw-live-status');
  const button = el<HTMLButtonElement>('iw-live-submit');
  if (!form || !input || !status || !button) return;

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const query = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    // Hostname shape only — saves a doomed server round-trip and keeps the
    // error message local and immediate.
    const looksLikeDomain = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(query);
    if (!query || !looksLikeDomain) {
      status.textContent = 'Enter a domain like example.com.';
      status.dataset.state = 'error';
      return;
    }

    button.disabled = true;
    status.textContent = 'Running live DNS lookup…';
    status.dataset.state = 'loading';

    try {
      const inspection = await inspectLiveDomain(query);
      const nextDomains = domains.filter((domain) => domain.id !== inspection.id && domain.name !== inspection.name);
      nextDomains.unshift(inspection);
      domains.splice(0, domains.length, ...nextDomains);
      renderDomainList(domains);
      showDomainDetail(inspection);
      status.textContent = `Live inspection loaded for ${inspection.name}.`;
      status.dataset.state = 'ok';
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : 'Live lookup failed.';
      status.dataset.state = 'error';
    } finally {
      button.disabled = false;
    }
  });
}

async function init(): Promise<void> {
  const domains = await loadDomains();
  renderDomainList(domains);
  if (domains.length > 0) showDomainDetail(domains[0], false);
  await handleLiveLookup(domains);
}

init().catch(console.error);
