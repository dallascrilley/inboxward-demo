import type { Domain, LiveDomainInspection } from './types.js';

let _domains: Domain[] | null = null;

export async function loadDomains(): Promise<Domain[]> {
  if (_domains) return _domains;
  // Standalone repo serves the synthetic fleet from public/data/ (no /inboxward base path).
  const res = await fetch('/data/domains.json');
  const domains: Domain[] = await res.json();
  for (const domain of domains) {
    domain.name = domain.name.trim();
    domain.source = 'synthetic';
  }
  _domains = domains;
  return domains;
}

export async function inspectLiveDomain(domain: string): Promise<LiveDomainInspection> {
  const res = await fetch(`/inboxward/inspect?domain=${encodeURIComponent(domain)}`);
  if (!res.ok) {
    const payload = await res.json().catch(() => null);
    const message = payload && typeof payload.error === 'string' ? payload.error : `Live lookup failed (${res.status})`;
    throw new Error(message);
  }
  return res.json();
}

export function getDomains(): Domain[] | null {
  return _domains;
}
