'use strict';

/**
 * Layer 2 - Google Gemini API (Google AI Studio) client.
 *
 * Uses the Gemini REST endpoint directly through Node's built-in fetch, so the
 * service has zero third-party dependencies. Gemini receives the message text
 * and/or a screenshot (multimodal) and must answer in a fixed JSON schema
 * (structured output), which the server then validates.
 */

const { CATEGORIES, TACTICS, VERDICTS, CONFIDENCE, LANGUAGES, verdictFromScore } = require('./constants');

const API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';
const DEFAULT_MODEL = 'gemini-3.8-flash';
// Tried in order when a model is unavailable (404) or overloaded (429/5xx).
const FALLBACK_MODELS = ['gemini-3.8-flash', 'gemini-3.5-flash', 'gemini-flash-latest', 'gemini-3.1-flash-lite'];
const TIMEOUT_MS = 20000;        // per model attempt (real answers take ~2-5 s; a hung model must not eat the budget)
const TOTAL_BUDGET_MS = 50000;   // whole fallback chain; stays under Cloud Run's 60 s request timeout

