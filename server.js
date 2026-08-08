// ============================================================
// Portal Seguranca Global — Server-Side Security Backend
// ============================================================
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const { sanitizeInput, detectInjection, sanitizeHTML, logEvent, getLog, isPersonalOrCompanyData } = require('./validation');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// SECURITY HEADERS (Helmet)
// ============================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://unpkg.com", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://unpkg.com"],
      fontSrc: ["https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:", "https://*.basemaps.cartocdn.com", "https://*.tile.openstreetmap.org", "https://*.arcgisonline.com", "https://*.googleapis.com", "https://*.google.com", "https://flagcdn.com", "https://unpkg.com", "https://images.unsplash.com"],
      connectSrc: ["'self'", "https://viacep.com.br", "https://nominatim.openstreetmap.org"],
      frameSrc: ["https://www.google.com", "https://maps.google.com", "https://earth.google.com"],
      workerSrc: ["'self'", "blob:"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// ============================================================
// RATE LIMITING
// ============================================================
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisicoes. Aguarde 1 minuto.', code: 'RATE_LIMIT' },
  handler: function(req, res, next, options) {
    logEvent('RATE_LIMIT_SERVER', req.ip + ' — ' + req.path);
    res.status(429).json(options.message);
  }
});

const searchLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Limite de buscas atingido (10/min). Aguarde.', code: 'SEARCH_RATE_LIMIT' },
  handler: function(req, res, next, options) {
    logEvent('SEARCH_RATE_LIMIT', req.ip + ' — ' + JSON.stringify(req.body).substring(0, 100));
    res.status(429).json(options.message);
  }
});

// ============================================================
// MIDDLEWARES GERAIS
// ============================================================
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(morgan('combined'));
app.use(generalLimiter);

app.use(function(req, res, next) {
  if (req.body && JSON.stringify(req.body).length > 5000) {
    logEvent('PAYLOAD_TOO_LARGE', req.ip);
    return res.status(413).json({ error: 'Payload muito grande.', code: 'PAYLOAD_TOO_LARGE' });
  }
  next();
});

// ============================================================
// STATIC FILES
// ============================================================
app.use(express.static(path.join(__dirname), {
  extensions: ['html'],
  setHeaders: function(res) {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.set('Permissions-Policy', 'camera=(self), microphone=(), geolocation=(self), payment=(self)');
  }
}));

// ============================================================
// API: Validar entrada (Search — Busca por Localizacao)
// ============================================================
app.post('/api/search', searchLimiter, function(req, res) {
  var query = req.body.query;
  if (!query || typeof query !== 'string') {
    logEvent('INVALID_INPUT', req.ip + ' — campo vazio');
    return res.status(400).json({ error: 'Campo de busca obrigatorio.', code: 'EMPTY_INPUT' });
  }

  if (query.length > 200) {
    logEvent('INPUT_TOO_LONG', req.ip + ' — ' + query.length + ' chars');
    return res.status(400).json({ error: 'Entrada muito longa (max 200 caracteres).', code: 'INPUT_TOO_LONG' });
  }

  if (detectInjection(query)) {
    logEvent('INJECTION_BLOCKED', req.ip + ' — ' + query.substring(0, 80));
    return res.status(403).json({ error: 'Entrada bloqueada por politica de seguranca.', code: 'INJECTION_DETECTED' });
  }

  if (isPersonalOrCompanyData(query)) {
    logEvent('PERSONAL_DATA_BLOCKED', req.ip + ' — campo vazio');
    return res.status(403).json({ error: 'Nao consultamos CPF, CNPJ, RG ou identidade. Use endereco ou CEP.', code: 'PERSONAL_DATA_BLOCKED' });
  }

  var sanitized = sanitizeInput(query);
  if (!sanitized) {
    return res.status(400).json({ error: 'Entrada invalida apos sanitization.', code: 'SANITIZED_EMPTY' });
  }

  logEvent('SEARCH_VALIDATED', req.ip + ' — ' + sanitized.substring(0, 50));
  return res.json({ validated: true, query: sanitized });
});

// ============================================================
// API: Log de seguranca
// ============================================================
app.get('/api/security-log', function(req, res) {
  var log = getLog();
  res.json({ total: log.length, entries: log.slice(-50) });
});

// ============================================================
// API: Health check
// ============================================================
app.get('/api/health', function(req, res) {
  res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// ============================================================
// 404 Handler
// ============================================================
app.use(function(req, res) {
  res.status(404).json({ error: 'Rota nao encontrada.', code: 'NOT_FOUND' });
});

// ============================================================
// Error Handler Global
// ============================================================
app.use(function(err, req, res, next) {
  logEvent('SERVER_ERROR', err.message);
  console.error('[PortalSegurancaGlobal ERROR]', err.message);
  res.status(500).json({ error: 'Erro interno do servidor.', code: 'INTERNAL_ERROR' });
});

// ============================================================
// START + KEEP-ALIVE
// ============================================================
app.listen(PORT, function() {
  console.log('');
  console.log('==============================================');
  console.log('  Portal Seguranca Global v2.0 — 100% Free');
  console.log('===============================================');
  console.log('  Porta:       ' + PORT);
  console.log('  Ambiente:    ' + (process.env.NODE_ENV || 'development'));
  console.log('  Rate Limit:  30 req/min geral, 10/min busca');
  console.log('  Modo:        Busca por Localizacao (Free)');
  console.log('  CSP:         Ativo (sem unsafe-eval)');
  console.log('  Helmet:      Ativo');
  console.log('===============================================');
  console.log('  http://localhost:' + PORT);
  console.log('');

  // Keep-alive: evita que o Render durma por inatividade
  var RENDER_URL = process.env.RENDER_EXTERNAL_URL || process.env.KEEPALIVE_URL;
  if (RENDER_URL) {
    setInterval(function() {
      require('https').get(RENDER_URL + '/api/health', function(res) {
        console.log('[KEEPALIVE] ping status:', res.statusCode);
      }).on('error', function(err) {
        console.error('[KEEPALIVE] erro:', err.message);
      });
    }, 10 * 60 * 1000);
  }
});
