'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeRules, rulesToAnalysis, extractIndicators } = require('../src/rules');
const { SAMPLES } = require('../src/samples');

test('every scam sample is flagged and every genuine sample is safe', () => {
  for (const s of SAMPLES) {
    const r = analyzeRules(s.text);
    if (s.expected === 'SCAM') {
      assert.notEqual(r.verdict, 'LIKELY_SAFE', `${s.id} should be flagged (score ${r.score})`);
      assert.ok(r.score >= 30, `${s.id} score ${r.score}`);
    } else {
      assert.equal(r.verdict, 'LIKELY_SAFE', `${s.id} should be safe (score ${r.score})`);
    }
  }
});

test('digital arrest sample is classified as DIGITAL_ARREST with high score', () => {
  const r = analyzeRules(SAMPLES.find((s) => s.id === 'digital-arrest').text);
  assert.equal(r.verdict, 'SCAM');
  assert.equal(r.category, 'DIGITAL_ARREST');
  assert.ok(r.score >= 90);
  assert.ok(r.tactics.includes('ISOLATION_SECRECY'));
  assert.ok(r.tactics.includes('PAYMENT_DEMAND'));
});

test('indicator extraction finds links, UPI IDs, amounts and accounts', () => {
  const ind = extractIndicators('Pay Rs 4,85,000 to A/c No: 50100234567812 or ramesh.k21@okpay, visit http://kyc-update-bank.xyz/verify, call +91 98765 43210');
  assert.ok(ind.urls.some((u) => u.includes('kyc-update-bank.xyz')));
  assert.ok(ind.upi_ids.includes('ramesh.k21@okpay'));
  assert.ok(ind.amounts.some((a) => a.includes('4,85,000')));
  assert.ok(ind.bank_accounts.length === 1);
  assert.ok(ind.phone_numbers.length === 1);
});

test('rulesToAnalysis produces the same shape as the Gemini result', () => {
  const a = rulesToAnalysis(analyzeRules(SAMPLES[0].text));
  for (const k of ['verdict', 'risk_score', 'confidence', 'scam_category', 'impersonated_entity', 'summary', 'red_flags', 'recommended_actions', 'do_not']) {
    assert.ok(k in a, `missing ${k}`);
  }
  assert.ok(a.red_flags.length > 0);
});
