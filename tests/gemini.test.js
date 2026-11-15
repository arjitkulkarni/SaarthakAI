'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeWithGemini, normalizeAnalysis, buildRequest, GeminiError, DEFAULT_MODEL } = require('../src/gemini');

const geminiReply = (obj) => ({
  candidates: [{ content: { parts: [{ text: JSON.stringify(obj) }] }, finishReason: 'STOP' }],
});
const okFetch = (obj, calls = []) => async (url, init) => {
  calls.push({ url, init });
  return { ok: true, status: 200, json: async () => geminiReply(obj) };
};

const SAMPLE = {
  verdict: 'SCAM', risk_score: 96, confidence: 'HIGH', scam_category: 'DIGITAL_ARREST',
  impersonated_entity: 'Mumbai Police', summary: 'Classic digital arrest.',
  red_flags: [{ evidence: 'You are now under digital arrest', explanation: 'Not a real procedure', tactic: 'FEAR_THREAT' }],
  recommended_actions: ['Hang up', 'Call 1930'], do_not: ['Do not pay'],
};

test('request uses structured JSON output, system instruction and the API key header', async () => {
  const calls = [];
  const out = await analyzeWithGemini({ text: 'test message here', language: 'hi' }, { apiKey: 'k', model: DEFAULT_MODEL, fetch: okFetch(SAMPLE, calls) });
  assert.equal(out.analysis.verdict, 'SCAM');
  assert.equal(out.model, DEFAULT_MODEL);
  const body = JSON.parse(calls[0].init.body);
  assert.equal(body.generationConfig.responseMimeType, 'application/json');
  assert.ok(body.generationConfig.responseSchema.properties.red_flags);
  assert.ok(body.systemInstruction.parts[0].text.includes('Digital arrest'));
  assert.ok(body.contents[0].parts[0].text.includes('Hindi'));
  assert.equal(calls[0].init.headers['x-goog-api-key'], 'k');
});

test('image is sent as inline data (multimodal)', () => {
  const req = buildRequest({ text: '', image: { mimeType: 'image/jpeg', data: 'AAAA' }, language: 'en' });
  assert.deepEqual(req.contents[0].parts[1], { inline_data: { mime_type: 'image/jpeg', data: 'AAAA' } });
});

test('falls back to the next model when one is unavailable', async () => {
  const seen = [];
  const fetchImpl = async (url) => {
    seen.push(url);
    if (seen.length === 1) return { ok: false, status: 404, json: async () => ({ error: { message: 'not found' } }) };
    return { ok: true, status: 200, json: async () => geminiReply(SAMPLE) };
  };
  const out = await analyzeWithGemini({ text: 'hello there friend' }, { apiKey: 'k', model: 'gemini-x', fetch: fetchImpl });
  assert.equal(seen.length, 2);
  assert.equal(out.model, DEFAULT_MODEL);
});

test('invalid API key fails fast without trying other models', async () => {
  let n = 0;
  const fetchImpl = async () => { n += 1; return { ok: false, status: 400, json: async () => ({ error: { message: 'API key not valid' } }) }; };
  await assert.rejects(analyzeWithGemini({ text: 'hello there friend' }, { apiKey: 'bad', fetch: fetchImpl }), GeminiError);
  assert.equal(n, 1);
});

test('normalizeAnalysis clamps score, fixes verdict and drops bad enums', () => {
  const a = normalizeAnalysis({ ...SAMPLE, risk_score: 140, verdict: 'LIKELY_SAFE', confidence: 'X', red_flags: [{ evidence: 'x', explanation: 'y', tactic: 'NOPE' }] });
  assert.equal(a.risk_score, 100);
  assert.equal(a.verdict, 'SCAM');
  assert.equal(a.confidence, 'MEDIUM');
  assert.equal(a.red_flags[0].tactic, 'OTHER');
});

test('missing API key raises a clear error', async () => {
  const saved = process.env.GEMINI_API_KEY;
  delete process.env.GEMINI_API_KEY;
  await assert.rejects(analyzeWithGemini({ text: 'hello there friend' }), /GEMINI_API_KEY/);
  if (saved) process.env.GEMINI_API_KEY = saved;
});
