'use strict';

/**
 * Satark AI - AI-Based Digital Arrest & Cyber Fraud Scam Detection System
 * HTTP server designed for Google Cloud Run (stateless, listens on $PORT).
 *
 *   GET  /                -> web dashboard (public/)
 *   GET  /api/health      -> health + configuration status
 *   GET  /api/samples     -> demo scam / genuine messages
 *   GET  /api/stats       -> live counters for this instance
 *   POST /api/analyze     -> { text?, image?: {mimeType, data(base64)}, language? }
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

loadDotEnv(path.join(__dirname, '.env'));

const { analyzeRules, rulesToAnalysis } = require('./src/rules');
const { analyzeWithGemini, DEFAULT_MODEL } = require('./src/gemini');
const { SAMPLES } = require('./src/samples');
const { HELPLINES, LANGUAGES } = require('./src/constants');

const PORT = Number(process.env.PORT) || 8080;
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY_BYTES = 7 * 1024 * 1024; // ~5 MB image after base64
const MAX_TEXT_CHARS = 8000;
const ALLOWED_IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/webp', 'image/heic', 'image/heif'];
const RATE_LIMIT = { windowMs: 60_000, max: Number(process.env.RATE_LIMIT_PER_MIN) || 20 };

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
};

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; '),
};

const stats = { startedAt: new Date().toISOString(), total: 0, scam: 0, suspicious: 0, safe: 0, gemini: 0, fallback: 0, categories: {} };
const hits = new Map();

/* ------------------------------------------------------------------ helpers */

function loadDotEnv(file) {
  try {
    for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  } catch { /* no .env file - fine on Cloud Run */ }
}

function log(severity, message, extra = {}) {
  // Structured JSON logs are parsed automatically by Google Cloud Logging.
  console.log(JSON.stringify({ severity, message, ...extra }));
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': MIME['.json'], 'Cache-Control': 'no-store' });
  res.end(body);
}

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  return (typeof fwd === 'string' && fwd.split(',')[0].trim()) || req.socket.remoteAddress || 'unknown';
}

function rateLimited(ip) {
  const now = Date.now();
  const entry = hits.get(ip);
  if (!entry || now - entry.start > RATE_LIMIT.windowMs) {
    hits.set(ip, { start: now, count: 1 });
    if (hits.size > 5000) for (const [k, v] of hits) if (now - v.start > RATE_LIMIT.windowMs) hits.delete(k);
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT.max;
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('Request too large (max ~5 MB image)'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        reject(Object.assign(new Error('Invalid JSON body'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function validateInput(body) {
  const text = typeof body.text === 'string' ? body.text.trim() : '';
  const language = Object.prototype.hasOwnProperty.call(LANGUAGES, body.language) ? body.language : 'en';
  let image = null;
  if (body.image && typeof body.image === 'object') {
    const mimeType = String(body.image.mimeType || '').toLowerCase();
    const data = String(body.image.data || '').replace(/^data:[^,]+,/, '');
    if (!ALLOWED_IMAGE_TYPES.includes(mimeType)) throw Object.assign(new Error('Unsupported image type. Use PNG, JPG or WEBP.'), { status: 400 });
    if (!/^[A-Za-z0-9+/=\s]+$/.test(data)) throw Object.assign(new Error('Image data must be base64'), { status: 400 });
    image = { mimeType, data };
  }
  if (!text && !image) throw Object.assign(new Error('Paste a message or upload a screenshot to analyse.'), { status: 400 });
  if (text.length > MAX_TEXT_CHARS) throw Object.assign(new Error(`Message is too long (max ${MAX_TEXT_CHARS} characters).`), { status: 400 });
  if (text && !image && text.length < 8) throw Object.assign(new Error('Message is too short to analyse.'), { status: 400 });
  return { text, image, language };
}

function record(analysis, engine) {
  stats.total += 1;
  if (analysis.verdict === 'SCAM') stats.scam += 1;
  else if (analysis.verdict === 'SUSPICIOUS') stats.suspicious += 1;
  else stats.safe += 1;
  stats[engine === 'gemini' ? 'gemini' : 'fallback'] += 1;
  if (analysis.scam_category !== 'NOT_A_SCAM') {
    stats.categories[analysis.scam_category] = (stats.categories[analysis.scam_category] || 0) + 1;
  }
}

/* ----------------------------------------------------------------- handlers */

async function handleAnalyze(req, res) {
  const requestId = crypto.randomUUID();
  if (rateLimited(clientIp(req))) {
    return sendJson(res, 429, { error: 'Too many requests. Please wait a minute and try again.' });
  }
  let input;
  try {
    input = validateInput(await readJsonBody(req));
  } catch (err) {
    return sendJson(res, err.status || 400, { error: err.message });
  }

  // Layer 1: rule engine (always runs, instant, offline).
  const rules = analyzeRules(input.text);

  // Layer 2: Gemini (primary AI analysis). Falls back to rules if unavailable.
  let analysis;
  let engine = 'gemini';
  let model = null;
  let latencyMs = 0;
  let notice = null;
  try {
    const out = await analyzeWithGemini(input);
    analysis = out.analysis;
    model = out.model;
    latencyMs = out.latencyMs;
  } catch (err) {
    log('WARNING', 'Gemini unavailable, using rule engine', { requestId, error: err.message });
    if (input.image && !input.text) {
      return sendJson(res, 503, {
        error: 'Screenshot analysis needs the Gemini API, which is not reachable right now. Paste the message text instead, or try again shortly.',
      });
    }
    analysis = rulesToAnalysis(rules);
    engine = 'rules';
    notice = process.env.GEMINI_API_KEY
      ? 'Gemini AI was unreachable, so this result comes from the offline rule engine.'
      : 'Gemini API key not configured - showing the offline rule-engine result.';
  }

  record(analysis, engine);
  log('INFO', 'analysis complete', {
    requestId, engine, model, latencyMs, verdict: analysis.verdict, score: analysis.risk_score,
    category: analysis.scam_category, hasImage: Boolean(input.image), textChars: input.text.length,
  });

  return sendJson(res, 200, {
    requestId,
    engine,
    model,
    latencyMs,
    notice,
    language: input.language,
    analysis,
    rule_check: {
      score: rules.score,
      verdict: rules.verdict,
      category: rules.category,
      signals: rules.signals.map(({ id, tactic, explanation }) => ({ id, tactic, explanation })),
    },
    indicators: rules.indicators,
    helplines: HELPLINES,
    analyzedAt: new Date().toISOString(),
  });
}

function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === '/' || rel === '') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(403, SECURITY_HEADERS);
    return res.end('Forbidden');
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Not found');
    }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600',
    });
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}

