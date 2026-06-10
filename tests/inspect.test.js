// Unit tests for the live-inspection backend's pure parsing/scoring logic.
// Run with `pnpm test` (node --test). No network: the network-bound resolver
// (resolveDns/probeDkim) is intentionally not exported or exercised here —
// these tests pin the DNS-record parsing that turns raw answers into verdicts.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  normalizeDomain,
  isValidDomain,
  stripTxtQuotes,
  parseTxtAnswers,
  parseCnameAnswers,
  countSpfMechanisms,
  parseDmarc,
  onRequestGet,
} from '../functions/inboxward/inspect.js';

// The NXDOMAIN path is exercised end-to-end through onRequestGet with a mocked
// global fetch standing in for dns.google — still no real network.
function withMockedDoh(t, payload) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify(payload), {
      headers: { 'content-type': 'application/json' },
    });
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
}

test('normalizeDomain strips scheme, path, trailing dot, and case', () => {
  assert.equal(normalizeDomain('  HTTPS://Example.com/path?q=1 '), 'example.com');
  assert.equal(normalizeDomain('mail.example.com.'), 'mail.example.com');
  assert.equal(normalizeDomain(''), '');
});

test('isValidDomain accepts hosts and rejects junk', () => {
  assert.ok(isValidDomain('openai.com'));
  assert.ok(isValidDomain('mail.sub.example.co.uk'));
  assert.ok(!isValidDomain('not a domain'));
  assert.ok(!isValidDomain('localhost'));
  assert.ok(!isValidDomain('-bad.com'));
});

test('stripTxtQuotes joins multi-chunk TXT values', () => {
  assert.equal(stripTxtQuotes('"v=spf1 " "include:_spf.google.com ~all"'), 'v=spf1 include:_spf.google.com ~all');
  assert.equal(stripTxtQuotes('unquoted value'), 'unquoted value');
  assert.equal(stripTxtQuotes(''), '');
});

test('parseTxtAnswers / parseCnameAnswers normalize DoH payloads', () => {
  assert.deepEqual(
    parseTxtAnswers({ Answer: [{ data: '"v=spf1 -all"' }, { data: '' }] }),
    ['v=spf1 -all']
  );
  assert.deepEqual(parseTxtAnswers(null), []);
  assert.deepEqual(
    parseCnameAnswers({ Answer: [{ data: 'sg.example.com.' }] }),
    ['sg.example.com']
  );
});

test('countSpfMechanisms counts only DNS-querying mechanisms', () => {
  // 3 includes + a + mx = 5 lookups; ip4/all do not count toward the SPF-10 limit.
  const record = 'v=spf1 include:a.com include:b.com include:c.com a mx ip4:1.2.3.4 -all';
  assert.equal(countSpfMechanisms(record), 5);
  assert.equal(countSpfMechanisms('v=spf1 -all'), 0);
});

test('parseDmarc reads policy, pct, and alignment', () => {
  const strict = parseDmarc('v=DMARC1; p=reject; pct=100; adkim=s; aspf=s');
  assert.equal(strict.policy, 'reject');
  assert.equal(strict.pct, 100);
  assert.equal(strict.alignment, 'strict');

  const relaxed = parseDmarc('v=DMARC1; p=quarantine; pct=50');
  assert.equal(relaxed.policy, 'quarantine');
  assert.equal(relaxed.pct, 50);
  assert.equal(relaxed.alignment, 'relaxed');

  // Unknown/absent policy falls back to "none" rather than trusting the input.
  assert.equal(parseDmarc('v=DMARC1; p=bogus').policy, 'none');
});

test('onRequestGet returns 404 domain-not-found on NXDOMAIN (DoH Status 3)', async (t) => {
  withMockedDoh(t, { Status: 3 });

  const response = await onRequestGet({
    request: { url: 'https://demo.test/inboxward/inspect?domain=no-such-domain-9f3k2q.com' },
  });

  assert.equal(response.status, 404);
  const payload = await response.json();
  assert.equal(payload.code, 'nxdomain');
  assert.match(payload.error, /does not exist/i);
  // A nonexistent domain must not get a fake all-fail scorecard.
  assert.equal(payload.spf_status, undefined);
});

test('onRequestGet still returns a 200 live inspection when the domain resolves', async (t) => {
  withMockedDoh(t, { Status: 0, Answer: [{ data: '"v=spf1 -all"' }] });

  const response = await onRequestGet({
    request: { url: 'https://demo.test/inboxward/inspect?domain=example.com' },
  });

  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.source, 'live');
  assert.equal(payload.spf_record, 'v=spf1 -all');
  assert.equal(payload.spf_status, 'pass');
});
