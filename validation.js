// ============================================================
// SafeHaven — Validacao Server-Side
// Replica TODAS as protecoes do client-side no servidor
// FOCO: seguranca de enderecos/locais. NAO consultamos CPF/CNPJ.
// ============================================================
'use strict';

var _serverLog = [];

// ============================================================
// SANITIZE INPUT — remove caracteres perigosos
// ============================================================
function sanitizeInput(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>"'`;\\(){}[\]]/g, '').trim();
}

// ============================================================
// SANITIZE HTML — escapa entidades HTML
// ============================================================
function sanitizeHTML(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

// ============================================================
// DETECT INJECTION — 15+ padroes de ataque
// ============================================================
function detectInjection(str) {
  if (typeof str !== 'string') return false;
  var patterns = [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /eval\s*\(/i,
    /document\.(cookie|write|location)/i,
    /window\.(location|open)/i,
    /\.\.\//g,
    /%3C/i,
    /%3E/i,
    /%00/i,
    /union\s+select/i,
    /drop\s+table/i,
    /insert\s+into/i,
    /delete\s+from/i,
    /update\s+.*set/i,
    /src\s*=\s*['"]/i,
    /href\s*=\s*["']javascript/i,
    /\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
    /;\s*--/,
    /\/\*.*\*\//,
    /xp_cmdshell/i,
    /exec\s*\(/i,
    /UNION\s+ALL\s+SELECT/i,
    /select\s+.+\s+from/i,
    /alter\s+table/i,
    /create\s+table/i,
    /truncate\s+table/i
  ];

  for (var i = 0; i < patterns.length; i++) {
    if (patterns[i].test(str)) {
      logEvent('INJECTION_PATTERN_' + i, str.substring(0, 80));
      return true;
    }
  }
  return false;
}

// ============================================================
// BLOQUEIO DE CONSULTA PESSOAL/EMPRESARIAL
// Nao processamos CPF, CNPJ, RG ou identidade.
// ============================================================
function isPersonalOrCompanyData(str) {
  if (typeof str !== 'string') return false;
  var s = str.replace(/\D/g, '');
  // CPF (11 digitos) ou CNPJ (14 digitos)
  if (/^\d{11}$/.test(s) || /^\d{14}$/.test(s)) {
    logEvent('PERSONAL_DATA_BLOCKED', str.substring(0, 20));
    return true;
  }
  // RG/identidade: padroes comuns
  var rgPatterns = [/\brg\b/i, /\bidentidade\b/i, /\bregistro geral\b/i, /\bcnpj\b/i, /\bcpf\b/i];
  for (var j = 0; j < rgPatterns.length; j++) {
    if (rgPatterns[j].test(str)) {
      logEvent('PERSONAL_DATA_BLOCED', str.substring(0, 50));
      return true;
    }
  }
  return false;
}

// ============================================================
// LOG DE EVENTOS (server-side)
// ============================================================
function logEvent(type, detail) {
  var entry = {
    ts: Date.now(),
    date: new Date().toISOString(),
    type: type,
    detail: typeof detail === 'string' ? detail.substring(0, 200) : ''
  };
  _serverLog.push(entry);
  if (_serverLog.length > 2000) _serverLog.shift();
  console.log('[SH_SEC] ' + type + ': ' + entry.detail);
}

function getLog() {
  return _serverLog.slice();
}

// ============================================================
// EXPORTS
// ============================================================
module.exports = {
  sanitizeInput: sanitizeInput,
  sanitizeHTML: sanitizeHTML,
  detectInjection: detectInjection,
  isPersonalOrCompanyData: isPersonalOrCompanyData,
  logEvent: logEvent,
  getLog: getLog
};
