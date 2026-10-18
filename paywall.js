// ============================================================
// Portal Seguranca Global — PAYWALL (conta, consulta, assinatura)
// ------------------------------------------------------------
// Este modulo adiciona ao Express:
//   POST /api/auth/registrar        criar conta (email + senha)
//   POST /api/auth/login            entrar
//   POST /api/auth/logout           sair
//   GET  /api/auth/eu               sessao atual
//   GET  /api/quota                 situacao do usuario
//   POST /api/consulta              analise de seguranca (calculada AQUI no servidor)
//   GET  /api/planos                lista publica de planos e precos
//   POST /api/assinatura            iniciar pagamento (Mercado Pago)
//   POST /api/assinatura/cancelar   cancelar renovacao automatica
//   POST /api/webhook/mercadopago   recebe avisos de pagamento (com validacao de assinatura)
//
// Variaveis de ambiente:
//   APP_ORIGIN         URL oficial (https://portalsegurancaglobal.com.br)
//   DATABASE_URL       Postgres (Render). Sem ela, grava em arquivo local.
//   MP_ACCESS_TOKEN    token de producao do Mercado Pago. Sem ele o portal
//                      opera em MODO FREE (igual a hoje) — ninguem perde acesso.
//   MP_WEBHOOK_SECRET  chave secreta do webhook (painel do Mercado Pago)
//   PAYWALL_DEV        NUNCA definir em producao. Liga /api/_teste/ativar.
// ============================================================
'use strict';

const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

const APP_ORIGIN = (process.env.APP_ORIGIN || 'https://portalsegurancaglobal.com.br').replace(/\/+$/, '');
const MP_TOKEN = process.env.MP_ACCESS_TOKEN || '';
const MP_WEBHOOK_SECRET = process.env.MP_WEBHOOK_SECRET || '';
const PAYWALL_DEV = process.env.PAYWALL_DEV === '1';
const DATABASE_URL = process.env.DATABASE_URL || '';
const COOKIE = 'psg_sessao';
const SESSAO_DIAS = 30;

// ------------------------------------------------------------
// PLANOS (precos em BRL)
// ------------------------------------------------------------
const PLANOS = {
  avulsa:     { nome: 'Consulta Avulsa', preco: 4.90,  precoTexto: 'R$ 4,90',  dias: 0,   recorrencia: false },
  pro_mensal: { nome: 'Pro Mensal',      preco: 19.90, precoTexto: 'R$ 19,90', dias: 30,  recorrencia: true,  frequencia: 1 },
  pro_anual:  { nome: 'Pro Anual',       preco: 149.90, precoTexto: 'R$ 149,90', dias: 365, recorrencia: true, frequencia: 12 }
};

function listaPlanosPublica() {
  return [
    { id: 'avulsa', nome: PLANOS.avulsa.nome, preco: PLANOS.avulsa.precoTexto, detalhe: '1 consulta completa, sem assinatura' },
    { id: 'pro_mensal', nome: PLANOS.pro_mensal.nome, preco: PLANOS.pro_mensal.precoTexto + '/mes', detalhe: 'consultas ilimitadas, renova automaticamente' },
    { id: 'pro_anual', nome: PLANOS.pro_anual.nome, preco: PLANOS.pro_anual.precoTexto + '/ano', detalhe: 'consultas ilimitadas, renova automaticamente' }
  ];
}

// ------------------------------------------------------------
// GERACAO DA INTELIGENCIA — agora no SERVIDOR.
// (Antes vivia no app.js do navegador; para o paywall ser real,
//  o calculo tem que ficar aqui e o cliente so recebe o que tem
//  direito a ver.)
// ------------------------------------------------------------
function generateIntelligence(lat, lng, address) {
  const dia = Math.floor(Date.now() / 86400000) % 30;
  const seed = Math.abs(Math.sin(lat * 1000 + lng * 2000 + dia * 0.37)) * 10000;
  const rng = (min, max) => min + ((seed * 9301 + 49297) % 233280) / 233280 * (max - min);
  const rngI = (min, max) => Math.round(rng(min, max));
  const crimeTypes = { 'Furto/Roubo': rngI(5, 45), 'Agressao': rngI(2, 18), 'Vandalismo': rngI(3, 22), 'Trafico': rngI(1, 15), 'Estelionato': rngI(2, 12), 'Outros': rngI(1, 8) };
  const totalOccurrences = Object.values(crimeTypes).reduce((a, b) => a + b, 0);
  const crimeScore = Math.max(5, Math.min(100, 100 - (totalOccurrences / 1.2)));
  const cameras = rngI(2, 35), lightCoverage = rngI(40, 98), commerce = rngI(8, 120), policeStations = rngI(0, 4), hospitals = rngI(0, 3);
  const infraScore = Math.min(100, Math.round((cameras / 35 * 25) + (lightCoverage / 100 * 35) + (commerce / 120 * 25) + ((policeStations + hospitals) / 7 * 15)));
  const pedestrianFlow = rngI(30, 100), publicTransport = rngI(2, 20), nightActivity = rngI(10, 90);
  const movementScore = Math.round((pedestrianFlow * .4) + (publicTransport / 20 * 100 * .3) + (nightActivity * .3));
  const safetyScore = Math.round(crimeScore * 0.45 + infraScore * 0.30 + movementScore * 0.25);
  const heatPoints = [], markerPoints = [];
  const crimeLabels = ['Furto', 'Roubo', 'Agressao', 'Vandalismo', 'Estelionato'];
  for (let i = 0; i < totalOccurrences; i++) {
    const pLat = lat + (Math.random() - .5) * .025, pLng = lng + (Math.random() - .5) * .03, intensity = .3 + Math.random() * .7;
    heatPoints.push([pLat, pLng, intensity]);
    if (i < 30) { markerPoints.push({ lat: pLat, lng: pLng, type: crimeLabels[Math.floor(Math.random() * crimeLabels.length)], date: randomRecentDate() }); }
  }
  const months = ['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
  const monthlyData = months.map(() => rngI(Math.max(5, totalOccurrences - 20), totalOccurrences + 15));
  const occurrences = heatPoints.map(function(hp) { return { lat: hp[0], lng: hp[1], intensity: hp[2] }; });
  return { lat, lng, address, safetyScore, crimeScore: Math.round(crimeScore), infraScore, movementScore: Math.min(100, movementScore), crimeTypes, totalOccurrences, cameras, lightCoverage, commerce, policeStations, hospitals, pedestrianFlow, publicTransport, nightActivity, heatPoints, markerPoints, occurrences, monthlyData, months };
}

function randomRecentDate() {
  const d = new Date(); d.setDate(d.getDate() - Math.floor(Math.random() * 90));
  return d.toLocaleDateString('pt-BR');
}

// Resumo publico (isca): faixa + score APROXIMADO arredondado para BAIXO
// (nunca superestima o valor real). Sem ocorrencias, sem mapa, sem exato.
function resumoPublico(dados) {
  const apr = Math.floor(dados.safetyScore / 5) * 5;
  const faixa = dados.safetyScore >= 70 ? 'Boa' : (dados.safetyScore >= 40 ? 'Media' : 'Ruim');
  return {
    faixa: faixa,
    scoreAproximado: apr,
    aviso: 'Resumo gratuito. O relatorio completo (score exato, ocorrencias, mapa de calor e historico) exige conta e plano.',
    dados: {
      lat: dados.lat, lng: dados.lng, address: dados.address,
      teaser: true, faixa: faixa, scoreAproximado: apr, safetyScore: apr,
      crimeScore: 0, infraScore: 0, movementScore: 0, crimeTypes: {},
      totalOccurrences: 0, cameras: 0, lightCoverage: 0, commerce: 0,
      policeStations: 0, hospitals: 0, pedestrianFlow: 0, publicTransport: 0, nightActivity: 0,
      heatPoints: [], markerPoints: [], occurrences: [], monthlyData: [], months: []
    }
  };
}

// ------------------------------------------------------------
// ARMAZENAMENTO — Postgres (DATABASE_URL) ou arquivo JSON
// ------------------------------------------------------------
function criarStore() {
  if (DATABASE_URL) return criarStorePostgres();
  console.warn('[PAYWALL] DATABASE_URL ausente — gravando em ARQUIVO local. No Render os dados sao temporarios ate criar o Postgres.');
  return criarStoreArquivo();
}

function criarStoreArquivo() {
  const ARQ = path.join(__dirname, 'psg-paywall-dados.json');
  function ler() {
    try { return JSON.parse(fs.readFileSync(ARQ, 'utf8')); }
    catch (e) { return { users: [], sessions: [], subs: [], usage: [], credits: [] }; }
  }
  function gravar(db) {
    try { fs.writeFileSync(ARQ + '.tmp', JSON.stringify(db)); fs.renameSync(ARQ + '.tmp', ARQ); }
    catch (e) { console.error('[PAYWALL] falha ao gravar arquivo:', e.message); }
  }
  function agora() { return new Date().toISOString(); }
  return {
    tipo: 'arquivo',
    async usuarioPorEmail(email) { return ler().users.find(u => u.email === email) || null; },
    async usuarioPorId(id) { return ler().users.find(u => u.id === id) || null; },
    async criarUsuario(u) { const db = ler(); if (db.users.some(x => x.email === u.email)) throw new Error('email_duplicado'); db.users.push(u); gravar(db); return u; },
    async criarSessao(token, userId, expiraEm) { const db = ler(); db.sessions = db.sessions.filter(s => s.user_id !== userId || new Date(s.expira_em) > new Date()); db.sessions.push({ token, user_id: userId, expira_em: expiraEm }); gravar(db); },
    async sessaoValida(token) { const s = ler().sessions.find(x => x.token === token); if (!s) return null; if (new Date(s.expira_em) <= new Date()) return null; return s.user_id; },
    async apagarSessao(token) { const db = ler(); db.sessions = db.sessions.filter(s => s.token !== token); gravar(db); },
    async subPorUsuario(userId) { return ler().subs.find(s => s.user_id === userId) || null; },
    async salvarSub(sub) { const db = ler(); db.subs = db.subs.filter(s => s.user_id !== sub.user_id); db.subs.push(sub); gravar(db); },
    async registrarUso(userId, kind) { const db = ler(); db.usage.push({ user_id: userId, kind, at: agora() }); gravar(db); },
    async contarUsos(userId, kind) { return ler().usage.filter(u => u.user_id === userId && u.kind === kind).length; },
    async addCredito(paymentId, userId) { const db = ler(); if (db.credits.some(c => c.payment_id === paymentId)) return false; db.credits.push({ payment_id: paymentId, user_id: userId, at: agora() }); gravar(db); return true; },
    async creditosDisponiveis(userId) { const db = ler(); const cr = db.credits.filter(c => c.user_id === userId).length; const us = db.usage.filter(u => u.user_id === userId && u.kind === 'avulsa').length; return Math.max(0, cr - us); },
    async logWebhook(status, motivo, corpo) { console.log('[WEBHOOK]', agora(), status, motivo, String(corpo || '').substring(0, 300)); }
  };
}

function criarStorePostgres() {
  let pool = null; let pronto = null;
  function getPool() {
    if (!pool) {
      const pg = require('pg');
      // SSL so quando necessario (URL externa ou sslmode=require).
      // A URL interna do Render nao pede SSL.
      const precisaSsl = /sslmode=require/i.test(DATABASE_URL) || !/\.onrender\.com/i.test(DATABASE_URL);
      const cfg = { connectionString: DATABASE_URL, max: 5 };
      if (precisaSsl) cfg.ssl = { rejectUnauthorized: false };
      pool = new pg.Pool(cfg);
      pronto = (async function () {
        const sql = `
          CREATE TABLE IF NOT EXISTS psg_users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, hash TEXT NOT NULL, salt TEXT NOT NULL, criado_em TIMESTAMPTZ DEFAULT now());
          CREATE TABLE IF NOT EXISTS psg_sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expira_em TIMESTAMPTZ NOT NULL);
          CREATE TABLE IF NOT EXISTS psg_subs (user_id TEXT PRIMARY KEY, plano TEXT NOT NULL, period_end TIMESTAMPTZ NOT NULL, cancel_at TIMESTAMPTZ, gateway_ref TEXT, atualizado_em TIMESTAMPTZ DEFAULT now());
          CREATE TABLE IF NOT EXISTS psg_usage (id BIGSERIAL PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, at TIMESTAMPTZ DEFAULT now());
          CREATE TABLE IF NOT EXISTS psg_credits (payment_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, at TIMESTAMPTZ DEFAULT now());
          CREATE TABLE IF NOT EXISTS psg_webhook_log (id BIGSERIAL PRIMARY KEY, at TIMESTAMPTZ DEFAULT now(), status TEXT, motivo TEXT, corpo TEXT);
          CREATE INDEX IF NOT EXISTS psg_usage_user_kind ON psg_usage (user_id, kind);
        `;
        await pool.query(sql);
        console.log('[PAYWALL] Postgres pronto (tabelas verificadas).');
      })().catch(function (e) {
        console.error('[PAYWALL] ERRO ao preparar o Postgres:', e.message);
        throw e;
      });
    }
    return pronto;
  }
  async function q(sql, params) { await getPool(); return pool.query(sql, params); }
  return {
    tipo: 'postgres',
    async usuarioPorEmail(email) { const r = await q('SELECT id, email, hash, salt FROM psg_users WHERE email = $1', [email]); return r.rows[0] || null; },
    async usuarioPorId(id) { const r = await q('SELECT id, email FROM psg_users WHERE id = $1', [id]); return r.rows[0] || null; },
    async criarUsuario(u) {
      try { await q('INSERT INTO psg_users (id, email, hash, salt) VALUES ($1,$2,$3,$4)', [u.id, u.email, u.hash, u.salt]); }
      catch (e) { if (String(e.code) === '23505') throw new Error('email_duplicado'); throw e; }
      return u;
    },
    async criarSessao(token, userId, expiraEm) { await q('DELETE FROM psg_sessions WHERE expira_em < now()'); await q('INSERT INTO psg_sessions (token, user_id, expira_em) VALUES ($1,$2,$3)', [token, userId, expiraEm]); },
    async sessaoValida(token) { const r = await q('SELECT user_id FROM psg_sessions WHERE token = $1 AND expira_em > now()', [token]); return r.rows[0] ? r.rows[0].user_id : null; },
    async apagarSessao(token) { await q('DELETE FROM psg_sessions WHERE token = $1', [token]); },
    async subPorUsuario(userId) { const r = await q('SELECT plano, period_end, cancel_at, gateway_ref FROM psg_subs WHERE user_id = $1', [userId]); return r.rows[0] || null; },
    async salvarSub(sub) {
      await q(`INSERT INTO psg_subs (user_id, plano, period_end, cancel_at, gateway_ref, atualizado_em)
               VALUES ($1,$2,$3,$4,$5, now())
               ON CONFLICT (user_id) DO UPDATE SET plano=$2, period_end=$3, cancel_at=$4, gateway_ref=$5, atualizado_em=now()`,
        [sub.user_id, sub.plano, sub.period_end, sub.cancel_at || null, sub.gateway_ref || null]);
    },
    async registrarUso(userId, kind) { await q('INSERT INTO psg_usage (user_id, kind) VALUES ($1,$2)', [userId, kind]); },
    async contarUsos(userId, kind) { const r = await q('SELECT COUNT(*)::int AS n FROM psg_usage WHERE user_id = $1 AND kind = $2', [userId, kind]); return r.rows[0].n; },
    async addCredito(paymentId, userId) {
      const r = await q('INSERT INTO psg_credits (payment_id, user_id) VALUES ($1,$2) ON CONFLICT (payment_id) DO NOTHING', [paymentId, userId]);
      return (r.rowCount || 0) > 0;
    },
    async creditosDisponiveis(userId) {
      const r = await q(`SELECT (SELECT COUNT(*) FROM psg_credits WHERE user_id=$1) - (SELECT COUNT(*) FROM psg_usage WHERE user_id=$1 AND kind='avulsa') AS saldo`, [userId]);
      return Math.max(0, r.rows[0].saldo);
    },
    async logWebhook(status, motivo, corpo) {
      console.log('[WEBHOOK]', new Date().toISOString(), status, motivo);
      try { await q('INSERT INTO psg_webhook_log (status, motivo, corpo) VALUES ($1,$2,$3)', [status, motivo, String(corpo || '').substring(0, 4000)]); }
      catch (e) { console.error('[WEBHOOK] falha ao registrar log:', e.message); }
    }
  };
}

// ------------------------------------------------------------
// AUTENTICACAO
// ------------------------------------------------------------
function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(function (p) {
    const i = p.indexOf('=');
    if (i > -1) { try { out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch (e) {} }
  });
  return out;
}

function hashSenha(senha, salt) {
  return crypto.scryptSync(String(senha), salt, 64).toString('hex');
}

function senhasIguais(hashA, hashB) {
  const a = Buffer.from(hashA, 'hex'), b = Buffer.from(hashB, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function emailValido(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

module.exports = function montarPaywall(app) {
  const store = criarStore();
  const paywallAtivo = !!MP_TOKEN;
  const cookieSeguro = /^https:/i.test(APP_ORIGIN);

  console.log('');
  console.log('==============================================');
  console.log('  PAYWALL');
  console.log('  Modo:        ' + (paywallAtivo ? 'ATIVO (cobranca ligada)' : 'FREE (sem MP_ACCESS_TOKEN)'));
  console.log('  Armazenamento: ' + store.tipo);
  console.log('  Webhook:     ' + (MP_WEBHOOK_SECRET ? 'assinatura validada' : 'SEM segredo (aceita com aviso)'));
  console.log('==============================================');

  async function usuarioAtual(req) {
    const token = parseCookies(req)[COOKIE];
    if (!token) return null;
    const userId = await store.sessaoValida(token);
    if (!userId) return null;
    return await store.usuarioPorId(userId);
  }

  function iniciarSessao(res, userId) {
    const token = crypto.randomBytes(32).toString('hex');
    const expira = new Date(Date.now() + SESSAO_DIAS * 86400000);
    return store.criarSessao(token, userId, expira.toISOString()).then(function () {
      res.cookie(COOKIE, token, { httpOnly: true, sameSite: 'lax', secure: cookieSeguro, maxAge: SESSAO_DIAS * 86400000, path: '/' });
    });
  }

  // Decide o direito de consulta do usuario
  async function direitoConsulta(user) {
    if (!paywallAtivo) return { acesso: 'gratis' };
    if (!user) return { acesso: 'visitante' };
    const sub = await store.subPorUsuario(user.id);
    if (sub && new Date(sub.period_end) > new Date()) return { acesso: 'assinante', plano: sub.plano };
    // cortesia primeiro (gratis), depois creditos pagos
    const cortesias = await store.contarUsos(user.id, 'cortesia');
    if (cortesias === 0) return { acesso: 'cortesia' };
    const creditos = await store.creditosDisponiveis(user.id);
    if (creditos > 0) return { acesso: 'avulsa', creditos };
    return { acesso: 'bloqueado' };
  }

  // ---------------- CONTAS ----------------
  app.post('/api/auth/registrar', async function (req, res) {
    try {
      const email = String((req.body && req.body.email) || '').toLowerCase().trim();
      const senha = String((req.body && req.body.senha) || '');
      if (!emailValido(email)) return res.status(400).json({ error: 'E-mail invalido.' });
      if (senha.length < 8) return res.status(400).json({ error: 'A senha precisa ter no minimo 8 caracteres.' });
      const salt = crypto.randomBytes(16).toString('hex');
      const u = { id: crypto.randomUUID(), email, hash: hashSenha(senha, salt), salt };
      try { await store.criarUsuario(u); }
      catch (e) {
        if (String(e.message) === 'email_duplicado') return res.status(409).json({ error: 'Este e-mail ja tem conta. Faca login.' });
        throw e;
      }
      await iniciarSessao(res, u.id);
      res.json({ ok: true, email, cortesia: 1, aviso: 'Conta criada. Voce tem 1 consulta completa de cortesia.' });
    } catch (e) { console.error('[PAYWALL] registrar:', e.message); res.status(500).json({ error: 'Erro ao criar conta.' }); }
  });

  app.post('/api/auth/login', async function (req, res) {
    try {
      const email = String((req.body && req.body.email) || '').toLowerCase().trim();
      const senha = String((req.body && req.body.senha) || '');
      const u = await store.usuarioPorEmail(email);
      if (!u || !senhasIguais(hashSenha(senha, u.salt), u.hash)) {
        return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
      }
      await iniciarSessao(res, u.id);
      res.json({ ok: true, email });
    } catch (e) { console.error('[PAYWALL] login:', e.message); res.status(500).json({ error: 'Erro ao entrar.' }); }
  });

  app.post('/api/auth/logout', async function (req, res) {
    try {
      const token = parseCookies(req)[COOKIE];
      if (token) await store.apagarSessao(token);
      res.clearCookie(COOKIE, { path: '/' });
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: 'Erro ao sair.' }); }
  });

  app.get('/api/auth/eu', async function (req, res) {
    try {
      const u = await usuarioAtual(req);
      if (!u) return res.json({ logado: false, paywallAtivo });
      const sub = await store.subPorUsuario(u.id);
      const creditos = await store.creditosDisponiveis(u.id);
      const cortesiaUsada = (await store.contarUsos(u.id, 'cortesia')) > 0;
      res.json({
        logado: true, email: u.email, paywallAtivo,
        plano: sub ? sub.plano : null,
        periodEnd: sub ? new Date(sub.period_end).toISOString() : null,
        cancelada: !!(sub && sub.cancel_at),
        creditosAvulsa: creditos, cortesiaUsada
      });
    } catch (e) { console.error('[PAYWALL] eu:', e.message); res.status(500).json({ logado: false, error: 'Erro.' }); }
  });

  // ---------------- QUOTA / PLANOS ----------------
  app.get('/api/quota', async function (req, res) {
    try {
      const u = await usuarioAtual(req);
      const d = await direitoConsulta(u);
      res.json({ logado: !!u, paywallAtivo, acesso: d.acesso, creditos: d.creditos || 0 });
    } catch (e) { res.status(500).json({ error: 'Erro.' }); }
  });

  app.get('/api/planos', function (req, res) {
    res.json({ paywallAtivo, planos: listaPlanosPublica(), gateway: paywallAtivo ? 'mercadopago' : null });
  });

  // ---------------- CONSULTA (o coracao do paywall) ----------------
  app.post('/api/consulta', async function (req, res) {
    try {
      const lat = Number(req.body && req.body.lat);
      const lng = Number(req.body && req.body.lng);
      if (!isFinite(lat) || !isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) {
        return res.status(400).json({ error: 'Coordenadas invalidas.' });
      }
      const endereco = req.body && req.body.address;
      const address = {
        street: String((endereco && endereco.street) || '').slice(0, 200),
        neighborhood: String((endereco && endereco.neighborhood) || '').slice(0, 200),
        city: String((endereco && endereco.city) || '').slice(0, 200),
        state: String((endereco && endereco.state) || '').slice(0, 200),
        country: String((endereco && endereco.country) || '').slice(0, 200),
        country_code: String((endereco && endereco.country_code) || '').slice(0, 2),
        cep: String((endereco && endereco.cep) || '').slice(0, 20),
        fullAddress: String((endereco && endereco.fullAddress) || '').slice(0, 400)
      };

      const u = await usuarioAtual(req);
      const dados = generateIntelligence(lat, lng, address);
      const d = await direitoConsulta(u);

      if (d.acesso === 'gratis') { return res.json({ acesso: 'gratis', dados }); }
      if (d.acesso === 'visitante') {
        const r = resumoPublico(dados);
        return res.json({ acesso: 'visitante', resumo: { faixa: r.faixa, scoreAproximado: r.scoreAproximado, aviso: r.aviso }, dados: r.dados, planos: listaPlanosPublica() });
      }
      if (d.acesso === 'assinante') {
        await store.registrarUso(u.id, 'assinatura');
        return res.json({ acesso: 'assinante', plano: d.plano, dados });
      }
      if (d.acesso === 'avulsa') {
        await store.registrarUso(u.id, 'avulsa');
        return res.json({ acesso: 'avulsa', dados });
      }
      if (d.acesso === 'cortesia') {
        await store.registrarUso(u.id, 'cortesia');
        return res.json({ acesso: 'cortesia', dados, aviso: 'Consulta de cortesia utilizada. Assine para continuar consultando.' });
      }
      // bloqueado: 402 sem vazar nenhum dado pago
      const r = resumoPublico(dados);
      return res.status(402).json({
        code: 'assinatura_necessaria',
        acesso: 'bloqueado',
        resumo: { faixa: r.faixa, scoreAproximado: r.scoreAproximado, aviso: r.aviso },
        dados: r.dados,
        planos: listaPlanosPublica()
      });
    } catch (e) {
      console.error('[PAYWALL] consulta:', e.message);
      res.status(500).json({ error: 'Nao foi possivel concluir a consulta agora.' });
    }
  });

  // ---------------- MERCADO PAGO ----------------
  async function mp(metodo, caminho, corpo) {
    const r = await axios({
      method: metodo,
      url: 'https://api.mercadopago.com' + caminho,
      headers: { Authorization: 'Bearer ' + MP_TOKEN },
      data: corpo,
      timeout: 20000
    });
    return r.data;
  }

  async function criarPreferenciaAvulsa(user) {
    return mp('POST', '/checkout/preferences', {
      items: [{ title: 'Consulta Avulsa — Portal Seguranca Global', quantity: 1, unit_price: PLANOS.avulsa.preco, currency_id: 'BRL' }],
      payer: { email: user.email },
      external_reference: 'psg:avulsa:' + user.id,
      notification_url: APP_ORIGIN + '/api/webhook/mercadopago',
      back_urls: { success: APP_ORIGIN + '/?obrigado=1', pending: APP_ORIGIN + '/?obrigado=pendente', failure: APP_ORIGIN + '/?pagamento=falhou' },
      auto_return: 'approved'
    });
  }

  async function criarPreapproval(user, planoId) {
    const plano = PLANOS[planoId];
    return mp('POST', '/preapproval', {
      reason: 'Portal Seguranca Global — ' + plano.nome,
      payer_email: user.email,
      auto_recurring: {
        frequency: plano.frequencia,
        frequency_type: 'months',
        transaction_amount: plano.preco,
        currency_id: 'BRL',
        start_date: new Date().toISOString()
      },
      external_reference: 'psg:sub:' + user.id + ':' + planoId,
      back_url: APP_ORIGIN + '/?assinatura=obrigado',
      notification_url: APP_ORIGIN + '/api/webhook/mercadopago'
    });
  }

  // Fallback: pagamento unico (mesmo preco/duracao) se o preapproval nao estiver
  // habilitado para a aplicacao. Garante que sempre da para cobrar.
  async function criarPreferenciaPlano(user, planoId) {
    const plano = PLANOS[planoId];
    return mp('POST', '/checkout/preferences', {
      items: [{ title: plano.nome + ' (30 dias) — Portal Seguranca Global', quantity: 1, unit_price: plano.preco, currency_id: 'BRL' }],
      payer: { email: user.email },
      external_reference: 'psg:plano:' + user.id + ':' + planoId,
      notification_url: APP_ORIGIN + '/api/webhook/mercadopago',
      back_urls: { success: APP_ORIGIN + '/?obrigado=1', failure: APP_ORIGIN + '/?pagamento=falhou' },
      auto_return: 'approved'
    });
  }

  app.post('/api/assinatura', async function (req, res) {
    try {
      if (!paywallAtivo) return res.status(503).json({ error: 'Pagamentos ainda nao configurados neste servidor.' });
      const u = await usuarioAtual(req);
      if (!u) return res.status(401).json({ error: 'Entre com sua conta para assinar.', precisaLogin: true });
      const planoId = String((req.body && req.body.plano) || '');
      if (!PLANOS[planoId]) return res.status(400).json({ error: 'Plano invalido.' });

      if (planoId === 'avulsa') {
        const pref = await criarPreferenciaAvulsa(u);
        if (!pref.init_point) throw new Error('resposta_sem_init_point');
        return res.json({ url: pref.init_point, plano: planoId });
      }

      // Pro Mensal / Pro Anual: assinatura com renovacao automatica
      try {
        const pr = await criarPreapproval(u, planoId);
        if (pr.init_point) {
          await store.salvarSub({ user_id: u.id, plano: planoId, period_end: new Date().toISOString(), cancel_at: null, gateway_ref: pr.id });
          return res.json({ url: pr.init_point, plano: planoId, recorrencia: true });
        }
        throw new Error(pr.message || 'resposta_sem_init_point');
      } catch (ePre) {
        console.warn('[PAYWALL] preapproval falhou (' + (ePre.response && ePre.response.data && ePre.response.data.message ? ePre.response.data.message : ePre.message) + '). Usando pagamento unico.');
        const pref = await criarPreferenciaPlano(u, planoId);
        if (!pref.init_point) throw new Error('resposta_sem_init_point');
        return res.json({ url: pref.init_point, plano: planoId, recorrencia: false });
      }
    } catch (e) {
      const msgMP = e.response && e.response.data && (e.response.data.message || e.response.data.error);
      console.error('[PAYWALL] assinatura:', msgMP || e.message);
      res.status(500).json({ error: 'Nao foi possivel iniciar o pagamento agora. ' + (msgMP ? String(msgMP) : '') });
    }
  });

  app.post('/api/assinatura/cancelar', async function (req, res) {
    try {
      const u = await usuarioAtual(req);
      if (!u) return res.status(401).json({ error: 'Entre com sua conta.' });
      const sub = await store.subPorUsuario(u.id);
      if (!sub) return res.status(404).json({ error: 'Nenhuma assinatura encontrada.' });
      if (sub.gateway_ref && String(sub.gateway_ref).indexOf('psg:') === -1) {
        try { await mp('PUT', '/preapproval/' + encodeURIComponent(sub.gateway_ref), { status: 'cancelled' }); }
        catch (eC) { console.warn('[PAYWALL] cancelar no MP falhou:', eC.message); }
      }
      await store.salvarSub({ user_id: u.id, plano: sub.plano, period_end: sub.period_end, cancel_at: new Date().toISOString(), gateway_ref: sub.gateway_ref });
      res.json({ ok: true, aviso: 'Renovacao automatica cancelada. Voce mantem o acesso ate o fim do periodo pago.' });
    } catch (e) { console.error('[PAYWALL] cancelar:', e.message); res.status(500).json({ error: 'Erro ao cancelar.' }); }
  });

  // ---------------- WEBHOOK MERCADO PAGO ----------------
  function assinaturaValida(req, dataId) {
    if (!MP_WEBHOOK_SECRET) return { ok: true, motivo: 'aceito_sem_segredo (MP_WEBHOOK_SECRET nao configurado)' };
    const sig = String(req.headers['x-signature'] || '');
    const rid = String(req.headers['x-request-id'] || '');
    let ts = null, v1 = null;
    sig.split(',').forEach(function (parte) {
      const p = parte.trim().split('=');
      if (p[0] === 'ts') ts = p[1];
      if (p[0] === 'v1') v1 = p[1];
    });
    if (!ts || !v1) return { ok: false, motivo: 'cabecalho x-signature ausente ou malformado' };
    try {
      const manifest = 'id:' + dataId + ';request-id:' + rid + ';ts:' + ts + ';';
      const esperado = crypto.createHmac('sha256', MP_WEBHOOK_SECRET).update(manifest).digest('hex');
      const a = Buffer.from(esperado, 'hex'), b = Buffer.from(v1, 'hex');
      const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
      return { ok: ok, motivo: ok ? 'assinatura valida' : 'assinatura divergente' };
    } catch (e) { return { ok: false, motivo: 'erro na verificacao: ' + e.message }; }
  }

  async function processarPagamento(paymentId) {
    const p = await mp('GET', '/v1/payments/' + encodeURIComponent(String(paymentId)));
    if (!p || p.status !== 'approved') return { status: 'ignorado', motivo: 'payment status ' + (p && p.status) };
    const ref = String(p.external_reference || '');
    if (ref.indexOf('psg:avulsa:') === 0) {
      const userId = ref.split(':')[2];
      const novo = await store.addCredito(String(p.id), userId);
      return { status: 'ok', motivo: novo ? 'credito avulsa adicionado' : 'credito ja existia (idempotente)' };
    }
    if (ref.indexOf('psg:plano:') === 0) {
      const partes = ref.split(':'); const userId = partes[2]; const planoId = partes[3];
      const dias = planoId === 'pro_anual' ? 365 : 30;
      const sub = await store.subPorUsuario(userId);
      const fimAtual = sub ? new Date(sub.period_end).getTime() : 0;
      // idempotencia: se o plano ja esta ativo por mais de 7 dias, ignora
      // (evita dobrar o periodo se o Mercado Pago reenviar o aviso)
      if (fimAtual > Date.now() + 7 * 86400000) return { status: 'ok', motivo: 'plano ' + planoId + ' ja ativo (aviso duplicado ignorado)' };
      const base = Math.max(Date.now(), fimAtual);
      await store.salvarSub({ user_id: userId, plano: planoId, period_end: new Date(base + dias * 86400000).toISOString(), cancel_at: null, gateway_ref: 'psg:' + p.id });
      return { status: 'ok', motivo: 'plano ' + planoId + ' ativado por ' + dias + ' dias (pagamento unico)' };
    }
    if (p.preapproval_id) {
      // Pagamento de assinatura recorrente: localizar o usuario pelo
      // external_reference do preapproval ou pelo e-mail do pagador.
      const pre = await mp('GET', '/preapproval/' + encodeURIComponent(String(p.preapproval_id)));
      const email = pre && pre.payer_email ? String(pre.payer_email).toLowerCase() : '';
      const refSub = String((pre && pre.external_reference) || '');
      let userId = null;
      if (refSub.indexOf('psg:sub:') === 0) userId = refSub.split(':')[2];
      else if (email) {
        const u = await store.usuarioPorEmail(email);
        userId = u && u.id;
      }
      if (!userId) return { status: 'erro', motivo: 'pagamento aprovado sem usuario vinculado (preapproval ' + p.preapproval_id + ')' };
      const subAtual = await store.subPorUsuario(userId);
      const planoId = subAtual ? subAtual.plano : 'pro_mensal';
      const dias = planoId === 'pro_anual' ? 365 : 30;
      const fimAtual = subAtual ? new Date(subAtual.period_end).getTime() : 0;
      // idempotencia: se o periodo ainda tem mais de 7 dias pela frente,
      // o aviso de autorizacao ja ativou — não estende de novo.
      if (fimAtual > Date.now() + 7 * 86400000) {
        return { status: 'ok', motivo: 'assinatura ' + planoId + ' ja ativa (aviso duplicado ignorado)' };
      }
      const base = Math.max(Date.now(), fimAtual);
      await store.salvarSub({ user_id: userId, plano: planoId, period_end: new Date(base + dias * 86400000).toISOString(), cancel_at: null, gateway_ref: p.preapproval_id });
      return { status: 'ok', motivo: 'assinatura ' + planoId + ' estendida por ' + dias + ' dias' };
    }
    return { status: 'ignorado', motivo: 'sem referencia reconhecida' };
  }

  app.post('/api/webhook/mercadopago', async function (req, res) {
    let resultado = { status: 'ignorado', motivo: 'corpo vazio' };
    try {
      const corpo = JSON.stringify(req.body || {});
      const tipo = String((req.body && req.body.type) || '');
      const dataId = req.body && req.body.data && req.body.data.id ? String(req.body.data.id) : '';

      const av = assinaturaValida(req, dataId);
      if (!av.ok) {
        await store.logWebhook('RECUSADO', 'assinatura invalida: ' + av.motivo, corpo);
        return res.status(401).json({ error: 'assinatura invalida' });
      }

      if (tipo === 'payment' && dataId) {
        resultado = await processarPagamento(dataId);
      } else if ((tipo === 'subscription_preapproval' || tipo === 'preapproval') && dataId) {
        const pre = await mp('GET', '/preapproval/' + encodeURIComponent(dataId));
        const email = pre && pre.payer_email ? String(pre.payer_email).toLowerCase() : '';
        const refSub = String((pre && pre.external_reference) || '');
        let userId = null;
        if (refSub.indexOf('psg:sub:') === 0) userId = refSub.split(':')[2];
        else if (email) { const u = await store.usuarioPorEmail(email); userId = u && u.id; }
        if (userId && pre.status === 'authorized') {
          const subAtual = await store.subPorUsuario(userId);
          const planoId = refSub.indexOf('psg:sub:') === 0 ? refSub.split(':')[3] : (subAtual ? subAtual.plano : 'pro_mensal');
          const fim = subAtual && new Date(subAtual.period_end) > new Date() ? subAtual.period_end : new Date(Date.now() + (planoId === 'pro_anual' ? 365 : 30) * 86400000).toISOString();
          await store.salvarSub({ user_id: userId, plano: planoId, period_end: fim, cancel_at: null, gateway_ref: pre.id });
          resultado = { status: 'ok', motivo: 'preapproval autorizado (' + planoId + ')' };
        } else if (userId && (pre.status === 'cancelled' || pre.status === 'paused')) {
          const subAtual = await store.subPorUsuario(userId);
          if (subAtual) {
            await store.salvarSub({ user_id: userId, plano: subAtual.plano, period_end: subAtual.period_end, cancel_at: new Date().toISOString(), gateway_ref: pre.id });
          }
          resultado = { status: 'ok', motivo: 'preapproval ' + pre.status };
        } else {
          resultado = { status: 'ignorado', motivo: 'preapproval status ' + (pre && pre.status) + ' sem usuario' };
        }
      } else {
        resultado = { status: 'ignorado', motivo: 'type ' + (tipo || 'desconhecido') };
      }
      await store.logWebhook(resultado.status === 'ok' ? 'OK' : 'IGNORADO', resultado.motivo, corpo);
      return res.json({ received: true, resultado: resultado.motivo });
    } catch (e) {
      console.error('[WEBHOOK] erro:', e.message);
      try { await store.logWebhook('ERRO', e.message, JSON.stringify(req.body || {})); } catch (e2) {}
      return res.status(200).json({ received: true, erro: true }); // 200 para o MP nao ficar reenviando
    }
  });

  // ---------------- ROTA DE TESTE (so existe com PAYWALL_DEV=1) ----------------
  if (PAYWALL_DEV) {
    console.warn('[PAYWALL] *** PAYWALL_DEV=1 — rota de teste /api/_teste/ativar EXPOSTA. Nunca use em producao! ***');
    app.post('/api/_teste/ativar', async function (req, res) {
      try {
        const u = await usuarioAtual(req);
        if (!u) return res.status(401).json({ error: 'Entre primeiro.' });
        const dias = Math.max(1, Math.min(3650, Number(req.body && req.body.dias) || 30));
        await store.salvarSub({ user_id: u.id, plano: 'pro_mensal', period_end: new Date(Date.now() + dias * 86400000).toISOString(), cancel_at: null, gateway_ref: 'TESTE' });
        res.json({ ok: true, dias: dias });
      } catch (e) { res.status(500).json({ error: 'Erro no teste.' }); }
    });
  }

  console.log('[PAYWALL] rotas montadas: /api/auth/*, /api/consulta, /api/planos, /api/quota, /api/assinatura*, /api/webhook/mercadopago');
};
