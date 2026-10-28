// ============================================================
// Portal Seguranca Global — Registro de Protocolos de Relatorios
// Verificacao publica em /verificar/PSG-AAAA-XXXXXXXX.
// Persiste no Postgres existente (DATABASE_URL); JSON so em desenvolvimento.
// ============================================================
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const DATABASE_URL = process.env.DATABASE_URL || '';
const ARQ = path.join(__dirname, 'psg-relatorios.json');
const PROTO_RE = /^PSG-\d{4}-[A-F0-9]{12}$/;
const COOKIE_NAME = 'psg_sessao';
let pool = null;
let dbReady = null;

function getPool() {
  if (!pool) {
    const pg = require('pg');
    const needsSsl = /sslmode=require/i.test(DATABASE_URL) || !/\.onrender\.com/i.test(DATABASE_URL);
    const cfg = { connectionString: DATABASE_URL, max: 4 };
    if (needsSsl) cfg.ssl = { rejectUnauthorized: false };
    pool = new pg.Pool(cfg);
    dbReady = pool.query(`
      CREATE TABLE IF NOT EXISTS psg_report_verifications (
        protocolo TEXT PRIMARY KEY,
        emissao TIMESTAMPTZ NOT NULL,
        endereco TEXT NOT NULL,
        cidade TEXT,
        estado TEXT,
        pais TEXT,
        criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS psg_report_verifications_created ON psg_report_verifications (criado_em DESC);
    `).catch(function (e) {
      console.error('[RELATORIOS] erro ao preparar Postgres:', e.message);
      throw e;
    });
  }
  return dbReady;
}

function loadLocal() {
  try { return JSON.parse(fs.readFileSync(ARQ, 'utf8')); }
  catch (e) { return {}; }
}
function saveLocal(db) {
  fs.writeFileSync(ARQ + '.tmp', JSON.stringify(db));
  fs.renameSync(ARQ + '.tmp', ARQ);
}
function getCookie(req, name) {
  const raw = String(req.headers.cookie || '');
  const parts = raw.split(';');
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i].trim();
    const eq = p.indexOf('=');
    if (eq > 0 && p.slice(0, eq) === name) return decodeURIComponent(p.slice(eq + 1));
  }
  return '';
}
async function validSession(req) {
  const token = getCookie(req, COOKIE_NAME);
  if (!token || token.length > 128) return false;
  if (DATABASE_URL) {
    await getPool();
    const r = await pool.query('SELECT 1 FROM psg_sessions WHERE token = $1 AND expira_em > now()', [token]);
    return r.rowCount > 0;
  }
  const db = loadLocal();
  const sessions = db.sessions || [];
  return sessions.some(function (s) {
    return s.token === token && new Date(s.expira_em) > new Date();
  });
}
function clean(v, max) { return String(v || '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max); }
function createProtocol() { return 'PSG-' + new Date().getFullYear() + '-' + crypto.randomBytes(6).toString('hex').toUpperCase(); }

module.exports = function (app) {
  // Emite protocolo exclusivamente no servidor e vinculado a sessao ativa.
  app.post('/api/relatorios', async function (req, res) {
    try {
      if (!await validSession(req)) return res.status(401).json({ error: 'Entre na sua conta para registrar o relatorio.' });
      const b = req.body || {};
      const endereco = clean(b.endereco, 400);
      const reg = {
        emissao: new Date().toISOString(),
        endereco: endereco,
        cidade: clean(b.cidade, 120),
        estado: clean(b.estado, 120),
        pais: clean(b.pais, 80)
      };
      let protocolo = createProtocol();
      if (DATABASE_URL) {
        await getPool();
        await pool.query(
          'INSERT INTO psg_report_verifications (protocolo, emissao, endereco, cidade, estado, pais) VALUES ($1,$2,$3,$4,$5,$6)',
          [protocolo, reg.emissao, reg.endereco, reg.cidade, reg.estado, reg.pais]
        );
      } else {
        if (process.env.NODE_ENV === 'production') {
          return res.status(503).json({ error: 'Verificacao temporariamente indisponivel: banco persistente nao configurado.' });
        }
        const db = loadLocal();
        db[protocolo] = reg;
        saveLocal(db);
      }
      return res.json({ ok: true, protocolo: protocolo, url: '/verificar/' + protocolo });
    } catch (e) {
      console.error('[RELATORIOS] erro ao registrar:', e.message);
      return res.status(503).json({ error: 'Nao foi possivel registrar o protocolo agora.' });
    }
  });

  // Consulta publica de autenticidade; nao requer login.
  app.get('/api/relatorios/:protocolo', async function (req, res) {
    try {
      const proto = String(req.params.protocolo || '').trim().toUpperCase();
      if (!PROTO_RE.test(proto)) return res.json({ valido: false, protocolo: proto });
      if (!DATABASE_URL && process.env.NODE_ENV === 'production') {
        return res.status(503).json({ error: 'Verificacao indisponivel: banco persistente nao configurado.' });
      }
      let reg = null;
      if (DATABASE_URL) {
        await getPool();
        const r = await pool.query(
          'SELECT emissao, endereco, cidade, estado, pais FROM psg_report_verifications WHERE protocolo = $1', [proto]
        );
        if (r.rows[0]) reg = r.rows[0];
      } else if (process.env.NODE_ENV !== 'production') {
        reg = loadLocal()[proto] || null;
      }
      if (!reg) return res.json({ valido: false, protocolo: proto });
      return res.json({
        valido: true,
        protocolo: proto,
        emissao: new Date(reg.emissao).toISOString(),
        endereco: reg.endereco,
        cidade: reg.cidade,
        estado: reg.estado,
        pais: reg.pais
      });
    } catch (e) {
      console.error('[RELATORIOS] erro ao consultar:', e.message);
      return res.status(503).json({ error: 'Consulta de protocolo temporariamente indisponivel.' });
    }
  });

  app.get('/verificar/:protocolo', function (req, res) {
    res.sendFile(path.join(__dirname, 'verificar.html'));
  });
  console.log('[RELATORIOS] rotas montadas; armazenamento: ' + (DATABASE_URL ? 'Postgres' : 'local dev')); 
};
