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

