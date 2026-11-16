'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeWithGrok, normalizeAnalysis, buildRequest, extractJson, GrokError, DEFAULT_MODEL } = require('../src/grok');

const grokReply = (obj) => ({
  choices: [{ index: 0, message: { role: 'assistant', content: JSON.stringify(obj) }, finish_reason: 'stop' }],
});
const okFetch = (obj, calls = []) => async (url, init) => {
  calls.push({ url, init });
  return { ok: true, status: 200, json: async () => grokReply(obj) };
};

const SAMPLE = {
  verdict: 'SCAM', risk_score: 96, confidence: 'HIGH', scam_category: 'DIGITAL_ARREST',
  impersonated_entity: 'Mumbai Police', summary: 'Classic digital arrest.',
  red_flags: [{ evidence: 'You are now under digital arrest', explanation: 'Not a real procedure', tactic: 'FEAR_THREAT' }],
  recommended_actions: ['Hang up', 'Call 1930'], do_not: ['Do not pay'],
};

test('request uses structured JSON output, system prompt and a bearer token', async () => {
  const calls = [];
  const out = await analyzeWithGrok({ text: 'test message here', language: 'hi' }, { apiKey: 'k', model: DEFAULT_MODEL, fetch: okFetch(SAMPLE, calls) });
  assert.equal(out.analysis.verdict, 'SCAM');
  assert.equal(out.model, DEFAULT_MODEL);
  assert.equal(calls[0].url, 'https://api.x.ai/v1/chat/completions');
  const body = JSON.parse(calls[0].init.body);
  assert.equal(body.model, DEFAULT_MODEL);
  assert.equal(body.response_format.type, 'json_schema');
  assert.equal(body.response_format.json_schema.strict, true);
  assert.ok(body.response_format.json_schema.schema.properties.red_flags);
  assert.equal(body.messages[0].role, 'system');
  assert.ok(body.messages[0].content.includes('Digital arrest'));
  assert.ok(body.messages[1].content[0].text.includes('Hindi'));
  assert.equal(calls[0].init.headers.Authorization, 'Bearer k');
});

test('image is sent as a base64 data URL (vision)', () => {
  const req = buildRequest({ text: '', image: { mimeType: 'image/jpeg', data: 'AAAA' }, language: 'en' });
  assert.deepEqual(req.messages[1].content[1], { type: 'image_url', image_url: { url: 'data:image/jpeg;base64,AAAA', detail: 'high' } });
});

test('falls back to the next model when one is unavailable', async () => {
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push(JSON.parse(init.body).model);
    if (seen.length === 1) return { ok: false, status: 404, json: async () => ({ error: 'model not found' }) };
    return { ok: true, status: 200, json: async () => grokReply(SAMPLE) };
  };
  const out = await analyzeWithGrok({ text: 'hello there friend' }, { apiKey: 'k', model: 'grok-x', fetch: fetchImpl });
  assert.deepEqual(seen, ['grok-x', DEFAULT_MODEL]);
  assert.equal(out.model, DEFAULT_MODEL);
});

test('invalid API key fails fast without trying other models', async () => {
  let n = 0;
  const fetchImpl = async () => { n += 1; return { ok: false, status: 401, json: async () => ({ error: 'Incorrect API key provided' }) }; };
  await assert.rejects(analyzeWithGrok({ text: 'hello there friend' }, { apiKey: 'bad', fetch: fetchImpl }), GrokError);
  assert.equal(n, 1);
});

test('rate-limit (429) errors are not retried', async () => {
  let n = 0;
  const fetchImpl = async () => { n += 1; return { ok: false, status: 429, json: async () => ({ error: 'rate limited' }) }; };
  await assert.rejects(analyzeWithGrok({ text: 'hello there friend' }, { apiKey: 'k', fetch: fetchImpl }), /429/);
  assert.equal(n, 2); // one try per model, no second pass
});

test('extractJson handles fenced output and reports empty replies', () => {
  const fenced = { choices: [{ message: { content: '```json\n{"verdict":"SCAM"}\n```' } }] };
  assert.equal(extractJson(fenced).verdict, 'SCAM');
  assert.throws(() => extractJson({ choices: [{ message: { content: '' }, finish_reason: 'length' }] }), /no text/);
});

test('normalizeAnalysis clamps score, fixes verdict and drops bad enums', () => {
  const a = normalizeAnalysis({ ...SAMPLE, risk_score: 140, verdict: 'LIKELY_SAFE', confidence: 'X', red_flags: [{ evidence: 'x', explanation: 'y', tactic: 'NOPE' }] });
  assert.equal(a.risk_score, 100);
  assert.equal(a.verdict, 'SCAM');
  assert.equal(a.confidence, 'MEDIUM');
  assert.equal(a.red_flags[0].tactic, 'OTHER');
});

test('missing API key raises a clear error', async () => {
  const saved = process.env.XAI_API_KEY;
  delete process.env.XAI_API_KEY;
  await assert.rejects(analyzeWithGrok({ text: 'hello there friend' }), /XAI_API_KEY/);
  if (saved) process.env.XAI_API_KEY = saved;
});
