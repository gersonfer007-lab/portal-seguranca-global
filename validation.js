// ============================================================
// SafeHaven — Validacao Server-Side
// Replica TODAS as protecoes do client-side no servidor
// ============================================================
'use strict';

var _serverLog = [];

// ============================================================
// SANITIZE INPUT — remove caracteres perigosos
// ============================================================
function sanitizeInput(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>\"'`;\\(){}[\]]/g, '').trim();
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
// VALIDATE CPF (algoritmo completo com digitos verificadores)
// ============================================================
function validateCPF(cpf) {
  if (typeof cpf !== 'string') return false;
  cpf = cpf.replace(/\D/g, '');
  if (cpf.length !== 11) return false;

  // Rejeita sequencias repetidas
  if (/^(\d)\1{10}$/.test(cpf)) return false;

  // Digito verificador 1
  var sum = 0;
  for (var i = 0; i < 9; i++) {
    sum += parseInt(cpf.charAt(i)) * (10 - i);
  }
  var remainder = (sum * 10) % 11;
  if (remainder === 10) remainder = 0;
  if (remainder !== parseInt(cpf.charAt(9))) return false;

  // Digito verificador 2
  sum = 0;
  for (var j = 0; j < 10; j++) {
    sum += parseInt(cpf.charAt(j)) * (11 - j);
  }
  remainder = (sum * 10) % 11;
  if (remainder === 10) remainder = 0;
  if (remainder !== parseInt(cpf.charAt(10))) return false;

  return true;
}

// ============================================================
// VALIDATE CNPJ (algoritmo completo)
// ============================================================
function validateCNPJ(cnpj) {
  if (typeof cnpj !== 'string') return false;
  cnpj = cnpj.replace(/\D/g, '');
  if (cnpj.length !== 14) return false;

  // Rejeita sequencias repetidas
  if (/^(\d)\1{13}$/.test(cnpj)) return false;

  // Digito verificador 1
  var weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  var sum = 0;
  for (var i = 0; i < 12; i++) {
    sum += parseInt(cnpj.charAt(i)) * weights1[i];
  }
  var remainder = sum % 11;
  var digit1 = remainder < 2 ? 0 : 11 - remainder;
  if (parseInt(cnpj.charAt(12)) !== digit1) return false;

  // Digito verificador 2
  var weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  sum = 0;
  for (var j = 0; j < 13; j++) {
    sum += parseInt(cnpj.charAt(j)) * weights2[j];
  }
  remainder = sum % 11;
  var digit2 = remainder < 2 ? 0 : 11 - remainder;
  if (parseInt(cnpj.charAt(13)) !== digit2) return false;

  return true;
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
  validateCPF: validateCPF,
  validateCNPJ: validateCNPJ,
  logEvent: logEvent,
  getLog: getLog
};
