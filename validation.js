'use strict';

const BLOCKED_PATTERNS = [
  /\d{3}\.?\d{3}\.?\d{3}-?\d{2}/,
  /\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}/,
  /cpf/i,
  /cnpj/i,
  /rg\b/i,
  /cnh\b/i,
  /facial/i,
  /biometr/i
];

const INJECTION_PATTERNS = [
  /<script/i, /javascript:/i, /on\w+\s*=/i, /eval\s*\(/i,
  /document\.(cookie|write|location)/i, /union\s+select/i,
  /drop\s+table/i, /insert\s+into/i, /delete\s+from/i
];

function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>"'`;\\(){}[\]]/g, '').trim().substring(0, 500);
}

function validateSearch(body) {
  if (!body || typeof body !== 'object') return { valid: false, error: 'Requisicao invalida.' };
  const raw = body.query;
  if (!raw || typeof raw !== 'string') return { valid: false, error: 'Campo de busca obrigatorio.' };
  if (raw.length > 500) return { valid: false, error: 'Busca muito longa.' };
  for (const p of INJECTION_PATTERNS) {
    if (p.test(raw)) return { valid: false, error: 'Entrada invalida detectada.' };
  }
  for (const p of BLOCKED_PATTERNS) {
    if (p.test(raw)) return { valid: false, error: 'Este portal e exclusivo para buscas de enderecos e locais. Nao e permitido buscar dados pessoais (CPF, CNPJ, RG etc).' };
  }
  return { valid: true, sanitized: sanitize(raw) };
}

module.exports = { validateSearch, sanitize };
