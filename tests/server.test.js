'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');

// Force offline mode so tests never call the real API.
process.env.XAI_API_KEY = '';
const { server, handler } = require('../server');
const vercelFn = require('../api/index');

let base;
test.before(() => new Promise((resolve) => {
  server.listen(0, () => { base = `http://127.0.0.1:${server.address().port}`; resolve(); });
}));
test.after(() => new Promise((resolve) => server.close(resolve)));

const post = (body) => fetch(`${base}/api/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

test('serves the dashboard with security headers', async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Satark/);
  assert.ok(res.headers.get('content-security-policy'));
});

test('health endpoint reports configuration', async () => {
  const h = await (await fetch(`${base}/api/health`)).json();
  assert.equal(h.status, 'ok');
  assert.equal(h.aiProvider, 'xAI Grok');
  assert.equal(h.aiConfigured, false);
  assert.equal(h.platform, 'local');
});

test('analyze falls back to the rule engine when Grok is not configured', async () => {
  const res = await post({ text: 'You are under digital arrest. Do not disconnect the video call. Transfer money to RBI verification account.', language: 'en' });
  assert.equal(res.status, 200);
  const d = await res.json();
  assert.equal(d.engine, 'rules');
  assert.equal(d.analysis.verdict, 'SCAM');
  assert.ok(d.notice);
  assert.equal(d.helplines[0].value, '1930');
});

test('analyze rejects empty input and unsupported image types', async () => {
  assert.equal((await post({})).status, 400);
  assert.equal((await post({ image: { mimeType: 'application/pdf', data: 'AAAA' } })).status, 400);
  assert.equal((await post({ image: { mimeType: 'image/webp', data: 'AAAA' } })).status, 400);
});

test('static path traversal is blocked', async () => {
  const res = await fetch(`${base}/..%2fserver.js`);
  assert.ok([403, 404].includes(res.status));
});

test('Vercel function exports the same handler', () => {
  assert.equal(vercelFn, handler);
});

test('handler accepts a body already parsed by Vercel', async () => {
  const req = Object.assign(Readable.from([]), {
    method: 'POST', url: '/api/analyze', headers: { 'x-forwarded-for': '10.0.0.9' }, socket: {},
    body: { text: 'Your parcel has drugs. Customs officer will arrest you. Press 9 now and pay the fine.' },
  });
  const res = await new Promise((resolve) => {
    const out = {
      headersSent: false,
      writeHead(status, headers) { this.statusCode = status; this.headers = headers; },
      end(body) { this.body = body; resolve(this); },
    };
    handler(req, out);
  });
  assert.equal(res.statusCode, 200);
  assert.equal(JSON.parse(res.body).engine, 'rules');
});
