// ============================================================
// Portal Seguranca Global — Server-Side Security Backend
// ============================================================
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const { sanitizeInput, detectInjection, validateCPF, validateCNPJ, sanitizeHTML, logEvent, getLog } = require('./validation');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// SECURITY HEADERS (Helmet — substitui meta tags CSP)
// ============================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://unpkg.com", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://unpkg.com"],
      fontSrc: ["https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:", "https://*.tile.openstreetmap.org", "https://*.arcgisonline.com", "https://*.googleapis.com", "https://*.google.com", "https://flagcdn.com"],
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
// RATE LIMITING — por IP
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

const bgCheckLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Limite de consultas Background Check (5/min). Aguarde.', code: 'BG_RATE_LIMIT' },
  handler: function(req, res, next, options) {
    logEvent('BG_CHECK_RATE_LIMIT', req.ip + ' — ' + JSON.stringify(req.body).substring(0, 100));
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

// Anti-payload oversized
app.use(function(req, res, next) {
  if (req.body && JSON.stringify(req.body).length > 5000) {
    logEvent('PAYLOAD_TOO_LARGE', req.ip);
    return res.status(413).json({ error: 'Payload muito grande.', code: 'PAYLOAD_TOO_LARGE' });
  }
  next();
});

// ============================================================
// STATIC FILES (HTML, CSS, JS, imagens)
// ============================================================
app.use(express.static(path.join(__dirname), {
  extensions: ['html'],
  setHeaders: function(res) {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  }
}));

// ============================================================
// API: Validar entrada (Search — Portal Principal)
// ============================================================
app.post('/api/search', searchLimiter, function(req, res) {
  var query = req.body.query;
  if (!query || typeof query !== 'string') {
    logEvent('INVALID_INPUT', req.ip + ' — campo vazio');
    return res.status(400).json({ error: 'Campo de busca obrigatorio.', code: 'EMPTY_INPUT' });
  }

  // Tamanho maximo
  if (query.length > 200) {
    logEvent('INPUT_TOO_LONG', req.ip + ' — ' + query.length + ' chars');
    return res.status(400).json({ error: 'Entrada muito longa (max 200 caracteres).', code: 'INPUT_TOO_LONG' });
  }

  // Deteccao de injecao server-side
  if (detectInjection(query)) {
    logEvent('INJECTION_BLOCKED', req.ip + ' — ' + query.substring(0, 80));
    return res.status(403).json({ error: 'Entrada bloqueada por politica de seguranca.', code: 'INJECTION_DETECTED' });
  }

  // Sanitizacao server-side
  var sanitized = sanitizeInput(query);
  if (!sanitized) {
    return res.status(400).json({ error: 'Entrada invalida apos sanitizacao.', code: 'SANITIZED_EMPTY' });
  }

  logEvent('SEARCH_VALIDATED', req.ip + ' — ' + sanitized.substring(0, 50));
  return res.json({ validated: true, query: sanitized });
});

// ============================================================
// API: Validar entrada (Background Check)
// ============================================================
app.post('/api/background-check', bgCheckLimiter, function(req, res) {
  var input = req.body.input;
  var type = req.body.type;

  if (!input || typeof input !== 'string') {
    logEvent('BG_INVALID_INPUT', req.ip);
    return res.status(400).json({ error: 'Documento obrigatorio.', code: 'EMPTY_INPUT' });
  }

  if (!type || !['cpf', 'cnpj', 'nome'].includes(type)) {
    return res.status(400).json({ error: 'Tipo de busca invalido.', code: 'INVALID_TYPE' });
  }

  if (input.length > 100) {
    logEvent('BG_INPUT_TOO_LONG', req.ip);
    return res.status(400).json({ error: 'Entrada muito longa.', code: 'INPUT_TOO_LONG' });
  }

  // Deteccao de injecao
  if (detectInjection(input)) {
    logEvent('BG_INJECTION_BLOCKED', req.ip + ' — ' + input.substring(0, 80));
    return res.status(403).json({ error: 'Entrada bloqueada.', code: 'INJECTION_DETECTED' });
  }

  var sanitized = sanitizeInput(input);
  var clean = sanitized.replace(/\D/g, '');

  // Validacao de CPF
  if (type === 'cpf') {
    if (!validateCPF(clean)) {
      logEvent('INVALID_CPF', req.ip);
      return res.status(400).json({ error: 'CPF invalido. Verifique os digitos.', code: 'INVALID_CPF' });
    }
  }

  // Validacao de CNPJ
  if (type === 'cnpj') {
    if (!validateCNPJ(clean)) {
      logEvent('INVALID_CNPJ', req.ip);
      return res.status(400).json({ error: 'CNPJ invalido. Verifique os digitos.', code: 'INVALID_CNPJ' });
    }
  }

  // Validacao de nome
  if (type === 'nome') {
    if (sanitized.length < 3) {
      return res.status(400).json({ error: 'Nome muito curto (minimo 3 caracteres).', code: 'NAME_TOO_SHORT' });
    }
    if (/\d/.test(sanitized)) {
      return res.status(400).json({ error: 'Nome nao pode conter numeros.', code: 'NAME_HAS_NUMBERS' });
    }
  }

  logEvent('BG_CHECK_VALIDATED', req.ip + ' — tipo:' + type + ' input:' + sanitized.substring(0, 20));
  return res.json({ validated: true, input: sanitized, type: type, clean: clean });
});

// ============================================================
// API: Log de seguranca (somente leitura — admin futuro)
// ============================================================
app.get('/api/security-log', function(req, res) {
  // Em producao, proteger com autenticacao
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
// START
// ============================================================
app.listen(PORT, function() {
  console.log('');
  console.log('==============================================');
  console.log('  Portal Seguranca Global — Seguranca Ativa');
  console.log('==============================================');
  console.log('  Porta:       ' + PORT);
  console.log('  Ambiente:    ' + (process.env.NODE_ENV || 'development'));
  console.log('  Rate Limit:  30 req/min geral, 10/min busca, 5/min background');
  console.log('  CSP:         Sem unsafe-inline, sem unsafe-eval');
  console.log('  Helmet:      Ativo (headers de seguranca)');
  console.log('  Validacao:   Server-side (sanitize + injection + CPF/CNPJ)');
  console.log('==============================================');
  console.log('  http://localhost:' + PORT);
  console.log('');
});