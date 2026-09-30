// ============================================================
// Portal Seguranca Global — Server-Side Security Backend
// ============================================================
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const zlib = require('zlib');
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
      scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://unpkg.com"],
      fontSrc: ["https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:", "https://*.basemaps.cartocdn.com", "https://*.tile.openstreetmap.org", "https://*.arcgisonline.com", "https://*.googleapis.com", "https://*.google.com", "https://flagcdn.com", "https://unpkg.com", "https://images.unsplash.com", "https://commons.wikimedia.org", "https://upload.wikimedia.org", "https://thumb.wikimedia.org", "https://api.qrserver.com"],
      connectSrc: ["'self'", "https://viacep.com.br", "https://nominatim.openstreetmap.org", "https://ntfy.sh", "https://api.allorigins.win", "https://api.rss2json.com", "https://pt.wikipedia.org", "https://overpass-api.de", "https://overpass.kumi.systems", "https://router.project-osrm.org", "https://routing.openstreetmap.de", "https://marine-api.open-meteo.com", "https://api.open-meteo.com"],
      frameSrc: ["https://www.google.com", "https://maps.google.com", "https://earth.google.com"],
      workerSrc: ["'self'", "blob:"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'", "https://formsubmit.co"]
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

// ============================================================
// COMPRESSAO GZIP (zlib nativo — reduz ~75% de HTML/JS/CSS/JSON)
// ============================================================
var GZIP_TYPES = ['text/html', 'text/css', 'text/plain', 'text/javascript', 'application/javascript', 'application/json', 'image/svg+xml'];
var GZIP_MIN = 1024; // so comprime acima de 1 KB

app.use(function(req, res, next) {
  if (req.method !== 'GET') return next();
  var accept = String(req.headers['accept-encoding'] || '');
  if (accept.indexOf('gzip') === -1) return next();

  var origWrite = res.write.bind(res);
  var origEnd = res.end.bind(res);
  var chunks = [];
  var gzipping = false;

  res.write = function(chunk, enc) {
    if (gzipping) return true; // durante gzip, bufferiza via end
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, enc || 'utf8'));
    return true;
  };

  res.end = function(chunk, enc) {
    if (chunk) {
      if (Buffer.isBuffer(chunk)) chunks.push(chunk);
      else if (typeof chunk === 'string') chunks.push(Buffer.from(chunk, enc || 'utf8'));
    }
    var body = Buffer.concat(chunks);
    var ctype = String(res.getHeader('Content-Type') || '').split(';')[0].trim();

    var podeGzip = GZIP_TYPES.indexOf(ctype) !== -1 && body.length >= GZIP_MIN;
    if (podeGzip) {
      zlib.gzip(body, { level: 6 }, function(err, out) {
        if (err || !out || out.length >= body.length) {
          // gzip nao compensou: envia original
          res.setHeader('Content-Length', String(body.length));
          origEnd(body);
          return;
        }
        gzipping = true;
        res.setHeader('Content-Encoding', 'gzip');
        res.setHeader('Content-Length', String(out.length));
        res.removeHeader('ETag');
        origEnd(out);
      });
    } else {
      res.setHeader('Content-Length', String(body.length));
      origEnd(body);
    }
  };

  next();
});

// ============================================================
// STATIC FILES (com cache de navegador)
// ============================================================
var ONE_DAY = 86400;
var ONE_WEEK = 604800;

app.use(express.static(path.join(__dirname), {
  extensions: ['html'],
  setHeaders: function(res, filePath) {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.set('Permissions-Policy', 'camera=(self), microphone=(), geolocation=(self), payment=(self)');
    // Service Worker: nunca cachear (precisa atualizar sempre)
    if (filePath.endsWith(path.join('sw.js'))) {
      res.set('Cache-Control', 'public, max-age=0, must-revalidate');
      return;
    }
    // HTML: revalida rapido (atualizacoes do portal fluem)
    if (/\.html$/i.test(filePath)) {
      res.set('Cache-Control', 'public, max-age=300');
      return;
    }
    // Assets versionados ou imutaveis: 7 dias no navegador
    if (/\.(js|css|png|jpg|jpeg|gif|svg|ico|json|woff2?)$/i.test(filePath)) {
      res.set('Cache-Control', 'public, max-age=' + ONE_WEEK);
    }
  }
}));

// ============================================================
// RATE LIMIT — SOMENTE NA API (arquivos estaticos nao contam)
// ============================================================
app.use('/api', generalLimiter);

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
    logEvent('PERSONAL_DATA_BLOCKED', req.ip + ' — ' + query.substring(0, 50));
    return res.status(403).json({ error: 'Nao consultamos CPF, CNPJ, RG ou identidade. Use endereco ou CEP.', code: 'PERSONAL_DATA_BLOCKED' });
  }

  var sanitized = sanitizeInput(query);
  if (!sanitized) {
    return res.status(400).json({ error: 'Entrada invalida apos sanitizacao.', code: 'SANITIZED_EMPTY' });
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
  console.log('==============================================');
  console.log('  Porta:       ' + PORT);
  console.log('  Ambiente:    ' + (process.env.NODE_ENV || 'development'));
  console.log('  Rate Limit:  30 req/min geral, 10/min busca');
  console.log('  Modo:        Busca por Localizacao (Free)');
  console.log('  CSP:         Ativo (sem unsafe-eval)');
  console.log('  Helmet:      Ativo');
  console.log('==============================================');
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
