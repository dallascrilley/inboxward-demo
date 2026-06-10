// Cloudflare Pages Function: GET /inboxward/inspect?domain=example.com
//
// Performs LIVE deliverability inspection against public DNS — SPF, DMARC, and
// common-selector DKIM — using DNS-over-HTTPS (dns.google). No API keys, no
// stored state. Pure parsing/scoring helpers are exported for unit tests; only
// `onRequestGet` is routed by Cloudflare Pages.

const GOOGLE_DNS_ENDPOINT = 'https://dns.google/resolve';

// Selectors covering the common ESPs (Google, SendGrid, Mailgun, SES, Mandrill…).
// DKIM has no discovery mechanism, so deliverability tools probe a known set.
const COMMON_DKIM_SELECTORS = [
  'google',
  'selector1',
  'selector2',
  'sg',
  's1',
  's2',
  'k1',
  'default',
  'mail',
  'mg',
  'mandrill',
  'amazonses',
];

function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...init.headers,
    },
    ...init,
  });
}

// TXT records arrive as one or more quoted chunks; join them into the raw value.
export function stripTxtQuotes(value) {
  if (!value) return '';
  const matches = [...value.matchAll(/"([^"]*)"/g)].map((match) => match[1]);
  return matches.length > 0 ? matches.join('') : value;
}

export function normalizeDomain(input) {
  if (!input) return '';
  let value = input.trim().toLowerCase();
  value = value.replace(/^https?:\/\//, '');
  const slashIndex = value.indexOf('/');
  if (slashIndex >= 0) value = value.slice(0, slashIndex);
  if (value.endsWith('.')) value = value.slice(0, -1);
  return value;
}

export function isValidDomain(domain) {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(domain);
}

export function parseTxtAnswers(payload) {
  return (payload?.Answer || [])
    .map((answer) => stripTxtQuotes(answer.data))
    .filter(Boolean);
}

export function parseCnameAnswers(payload) {
  return (payload?.Answer || [])
    .map((answer) => (answer.data || '').replace(/\.$/, ''))
    .filter(Boolean);
}

// SPF allows at most 10 DNS-querying mechanisms; counting them flags records
// at risk of `permerror` from the lookup limit.
export function countSpfMechanisms(record) {
  return record
    .split(/\s+/)
    .filter((token) => /^(include:|a$|a:|mx$|mx:|ptr$|ptr:|exists:|redirect=)/i.test(token)).length;
}

export function parseDmarc(record) {
  const fields = Object.create(null);
  for (const segment of record.split(';')) {
    const [rawKey, ...rawValue] = segment.split('=');
    if (!rawKey || rawValue.length === 0) continue;
    fields[rawKey.trim().toLowerCase()] = rawValue.join('=').trim();
  }

  const policy = fields.p === 'reject' || fields.p === 'quarantine' ? fields.p : 'none';
  const pct = Number.parseInt(fields.pct || '100', 10);
  const dkimAlignment = fields.adkim === 's' ? 'strict' : 'relaxed';
  const spfAlignment = fields.aspf === 's' ? 'strict' : 'relaxed';

  return {
    policy,
    pct: Number.isFinite(pct) ? pct : 100,
    alignment: dkimAlignment === 'strict' || spfAlignment === 'strict' ? 'strict' : 'relaxed',
    raw: record,
  };
}

async function resolveDns(name, type) {
  const url = `${GOOGLE_DNS_ENDPOINT}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const response = await fetch(url, {
    headers: { accept: 'application/dns-json, application/json' },
  });
  if (!response.ok) {
    throw new Error(`DNS lookup failed for ${name} ${type}: HTTP ${response.status}`);
  }
  return response.json();
}

async function probeDkim(domain) {
  const probes = await Promise.all(
    COMMON_DKIM_SELECTORS.map(async (selector) => {
      const host = `${selector}._domainkey.${domain}`;
      const [txtPayload, cnamePayload] = await Promise.all([
        resolveDns(host, 'TXT').catch(() => null),
        resolveDns(host, 'CNAME').catch(() => null),
      ]);
      const txtRecords = parseTxtAnswers(txtPayload).filter((record) => /v=dkim1/i.test(record));
      if (txtRecords.length > 0) {
        return { selector, record: txtRecords[0], host, via: 'txt' };
      }
      const cnameRecords = parseCnameAnswers(cnamePayload);
      if (cnameRecords.length > 0) {
        return { selector, record: cnameRecords[0], host, via: 'cname' };
      }
      return null;
    })
  );

  return probes.find(Boolean) || null;
}

export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  const domain = normalizeDomain(url.searchParams.get('domain') || '');

  if (!domain) {
    return json({ error: 'Missing ?domain=example.com query parameter.' }, { status: 400 });
  }
  if (!isValidDomain(domain)) {
    return json({ error: 'Invalid domain. Use a bare host like example.com.' }, { status: 400 });
  }

  try {
    const [rootTxt, dmarcTxt, dkim] = await Promise.all([
      resolveDns(domain, 'TXT'),
      resolveDns(`_dmarc.${domain}`, 'TXT').catch(() => null),
      probeDkim(domain),
    ]);

    // DoH Status 3 = NXDOMAIN: the name does not exist at all, so report
    // "domain not found" instead of scoring a fake all-fail domain.
    if (rootTxt?.Status === 3) {
      return json(
        {
          error: `Domain not found: ${domain} does not exist in public DNS (NXDOMAIN).`,
          code: 'nxdomain',
        },
        { status: 404 }
      );
    }

    const txtRecords = parseTxtAnswers(rootTxt);
    const spfRecord = txtRecords.find((record) => /^v=spf1\s/i.test(record)) || null;
    const spfMechanismCount = spfRecord ? countSpfMechanisms(spfRecord) : null;
    const dmarcRecord = parseTxtAnswers(dmarcTxt).find((record) => /^v=dmarc1/i.test(record)) || null;
    const dmarc = dmarcRecord ? parseDmarc(dmarcRecord) : null;

    return json({
      id: `live:${domain}`,
      name: domain,
      source: 'live',
      registrar: null,
      created_date: null,
      spf_record: spfRecord,
      spf_status: !spfRecord ? 'fail' : spfMechanismCount > 4 ? 'warn' : 'pass',
      spf_mechanism_count: spfMechanismCount,
      dkim_selector: dkim?.selector || null,
      dkim_record: dkim?.record || null,
      dkim_key_age_days: null,
      dkim_status: dkim ? 'pass' : 'warn',
      dmarc_policy: dmarc?.policy || 'none',
      dmarc_alignment: dmarc?.alignment || 'unknown',
      dmarc_pct: dmarc?.pct ?? null,
      blacklist_statuses: [],
      warmup_days: null,
      warmup_health: null,
      last_inbox_test: null,
      lookup_metadata: {
        checked_at: new Date().toISOString(),
        backend: 'cloudflare-pages-function',
        dns_provider: 'dns.google',
        note: 'Live DNS only. Blacklist checks and inbox placement remain out of scope without paid external feeds.',
        root_txt_records: txtRecords,
        dmarc_record: dmarcRecord,
        dkim_probe_host: dkim?.host || null,
        dkim_probe_via: dkim?.via || null,
      },
    });
  } catch (error) {
    return json(
      {
        error: error instanceof Error ? error.message : 'Live DNS lookup failed.',
      },
      { status: 502 }
    );
  }
}
