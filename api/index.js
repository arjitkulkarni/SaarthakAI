'use strict';

/**
 * Vercel serverless function. Every /api/* request is rewritten here
 * (see vercel.json) and handled by the same handler used for local runs.
 * Static files in public/ are served directly by Vercel's edge network.
 */
module.exports = require('../server').handler;
