export interface BlacklistEntry {
  list: string;
  status: 'listed' | 'clear';
  reason?: string;
}

export interface InboxTest {
  provider: string;
  placement: number;
  date: string;
}

export interface BaseDomain {
  id: string;
  name: string;
  source?: 'synthetic' | 'live';
  registrar: string | null;
  created_date: string | null;
  spf_record: string | null;
  spf_status: 'pass' | 'warn' | 'fail';
  spf_mechanism_count: number | null;
  dkim_selector: string | null;
  dkim_key_age_days: number | null;
  dkim_status: 'pass' | 'warn' | 'fail';
  dmarc_policy: 'none' | 'quarantine' | 'reject';
  dmarc_alignment: 'relaxed' | 'strict' | 'unknown';
  dmarc_pct: number | null;
  blacklist_statuses: BlacklistEntry[];
  warmup_days: number | null;
  warmup_health: number | null;
  last_inbox_test: InboxTest | null;
}

export interface Domain extends BaseDomain {}

export interface LiveLookupMetadata {
  checked_at: string;
  backend: string;
  dns_provider: string;
  note: string;
  root_txt_records: string[];
  dmarc_record: string | null;
  dkim_probe_host: string | null;
  dkim_probe_via: 'txt' | 'cname' | null;
}

export interface LiveDomainInspection extends BaseDomain {
  source: 'live';
  dkim_record: string | null;
  lookup_metadata: LiveLookupMetadata;
}

export interface Remediation {
  severity: 'critical' | 'warning' | 'info';
  title: string;
  description: string;
  action: string;
}
