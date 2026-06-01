import type { Domain } from './types.js';

let _domains: Domain[] | null = null;

export async function loadDomains(): Promise<Domain[]> {
  if (_domains) return _domains;
  const res = await fetch('/inboxward/data/domains.json');
  _domains = await res.json();
  return _domains!;
}

export function getDomains(): Domain[] | null {
  return _domains;
}
