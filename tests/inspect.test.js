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
} from '../functions/inboxward/inspect.js';

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
