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

export interface Domain {
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
  blacklist_statuses: BlacklistEntry[];
  warmup_days: number;
  warmup_health: number;
  last_inbox_test: InboxTest;
}

export interface Remediation {
  severity: 'critical' | 'warning' | 'info';
  title: string;
  description: string;
  action: string;
}
