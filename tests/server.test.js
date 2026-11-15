'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

// Force offline mode so tests never call the real API.
process.env.GEMINI_API_KEY = '';
const { server } = require('../server');

let base;
test.before(() => new Promise((resolve) => {
  server.listen(0, () => { base = `http://127.0.0.1:${server.address().port}`; resolve(); });
}));
test.after(() => new Promise((resolve) => server.close(resolve)));

test('serves the dashboard with security headers', async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Satark/);
  assert.ok(res.headers.get('content-security-policy'));
});

test('health endpoint reports configuration', async () => {
  const h = await (await fetch(`${base}/api/health`)).json();
  assert.equal(h.status, 'ok');
  assert.equal(h.geminiConfigured, false);
});

test('analyze falls back to the rule engine when Gemini is not configured', async () => {
  const res = await fetch(`${base}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: 'You are under digital arrest. Do not disconnect the video call. Transfer money to RBI verification account.', language: 'en' }),
  });
  assert.equal(res.status, 200);
  const d = await res.json();
  assert.equal(d.engine, 'rules');
  assert.equal(d.analysis.verdict, 'SCAM');
  assert.ok(d.notice);
  assert.equal(d.helplines[0].value, '1930');
});

test('analyze rejects empty input and bad image types', async () => {
  const post = (body) => fetch(`${base}/api/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await post({})).status, 400);
  assert.equal((await post({ image: { mimeType: 'application/pdf', data: 'AAAA' } })).status, 400);
});

test('static path traversal is blocked', async () => {
  const res = await fetch(`${base}/..%2fserver.js`);
  assert.ok([403, 404].includes(res.status));
});
