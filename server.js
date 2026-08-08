const express = require('express');
const path = require('path');
const https = require('https');
const http = require('http');
const app = express();
const PORT = process.env.PORT || 3000;
const KEEPALIVE_URL = process.env.KEEPALIVE_URL || '';

const validation = require('./validation');

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Security headers
app.use(function(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// CORS
app.use(function(req, res, next) {
  const allowed = [
    'https://portalsegurancaglobal.com.br',
    'https://www.portalsegurancaglobal.com.br',
    'https://portal-seguranca-global.pages.dev'
  ];
  const origin = req.headers.origin;
  if (!origin || allowed.indexOf(origin) !== -1 || process.env.NODE_ENV !== 'production') {
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Static files
app.use(express.static(path.join(__dirname), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
  etag: true
}));

// Health check
app.get('/api/health', function(req, res) {
  res.json({ status: 'ok', ts: Date.now(), version: '2.0.0' });
});

// Search validation (server-side, second layer)
app.post('/api/search', function(req, res) {
  const result = validation.validateSearch(req.body);
  if (!result.valid) return res.status(400).json({ error: result.error });
  res.json({ valid: true, query: result.sanitized });
});

// SPA fallback
app.get('*', function(req, res) {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Keep-alive ping
if (KEEPALIVE_URL) {
  function ping() {
    const mod = KEEPALIVE_URL.startsWith('https') ? https : http;
    mod.get(KEEPALIVE_URL + '/api/health', function(r) {
      console.log('[KEEPALIVE] ping ->', r.statusCode);
    }).on('error', function(e) {
      console.warn('[KEEPALIVE] error:', e.message);
    });
  }
  setTimeout(function() { ping(); setInterval(ping, 10 * 60 * 1000); }, 30000);
}

app.listen(PORT, function() {
  console.log('PSG v2.0 running on port', PORT);
});
