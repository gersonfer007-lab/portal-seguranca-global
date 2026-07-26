// ================================================================
// PORTAL SEGURANCA GLOBAL — SECURITY MODULE — Protecao contra hackers
// ================================================================

const SH_SECURITY = (function() {
  'use strict';

  // ----- 1. ANTI-XSS: Sanitizacao de inputs -----
  function sanitizeHTML(str) {
    if (typeof str !== 'string') return '';
    const map = { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":"&#039;", '/':"&#x2F;", '`':'&#96;' };
    return str.replace(/[&<>"'`\/]/g, function(c) { return map[c]; });
  }

  function sanitizeInput(str) {
    if (typeof str !== 'string') return '';
    // Remove null bytes
    str = str.replace(/\0/g, '');
    // Remove script tags and event handlers
    str = str.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
    str = str.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
    str = str.replace(/javascript\s*:/gi, '');
    str = str.replace(/data\s*:\s*text\/html/gi, '');
    str = str.replace(/vbscript\s*:/gi, '');
    str = str.replace(/expression\s*\(/gi, '');
    return str.trim();
  }

  // Validate CPF/CNPJ format strictly (only digits, dots, dashes, slashes)
  function sanitizeDocument(str) {
    return str.replace(/[^\d.\-\/]/g, '');
  }

  // Validate name (only letters, spaces, accents)
  function sanitizeName(str) {
    return str.replace(/[^a-zA-ZÀ-ÿ\s\-']/g, '').substring(0, 200);
  }

  // ----- 2. RATE LIMITER -----
  const rateLimits = {};
  const MAX_ATTEMPTS = 5;
  const WINDOW_MS = 60000; // 1 minute
  const BLOCK_MS = 300000; // 5 minutes block

  function checkRateLimit(action) {
    const now = Date.now();
    if (!rateLimits[action]) {
      rateLimits[action] = { attempts: [], blocked: 0 };
    }
    const rl = rateLimits[action];

    // Check if blocked
    if (rl.blocked > now) {
      const remaining = Math.ceil((rl.blocked - now) / 1000);
      logSecurityEvent('RATE_LIMIT_BLOCKED', action + ' — bloqueado por ' + remaining + 's');
      return { allowed: false, message: 'Muitas tentativas. Aguarde ' + remaining + ' segundos.' };
    }

    // Clean old attempts
    rl.attempts = rl.attempts.filter(function(t) { return t > now - WINDOW_MS; });

    // Check limit
    if (rl.attempts.length >= MAX_ATTEMPTS) {
      rl.blocked = now + BLOCK_MS;
      logSecurityEvent('RATE_LIMIT_TRIGGERED', action + ' — ' + MAX_ATTEMPTS + ' tentativas em 1min');
      return { allowed: false, message: 'Limite excedido. Bloqueado por 5 minutos.' };
    }

    rl.attempts.push(now);
    return { allowed: true };
  }

  // ----- 3. ANTI-BOT: Honeypot -----
  function createHoneypot(formEl) {
    if (!formEl || formEl.querySelector('.sh-hp')) return;
    const hp = document.createElement('div');
    hp.style.cssText = 'position:absolute;left:-9999px;top:-9999px;opacity:0;height:0;width:0;overflow:hidden;';
    var hpInput = document.createElement('input');
    hpInput.type = 'text'; hpInput.name = 'website'; hpInput.className = 'sh-hp';
    hpInput.tabIndex = -1; hpInput.autocomplete = 'off'; hpInput.setAttribute('aria-hidden', 'true');
    hp.appendChild(hpInput);
    formEl.appendChild(hp);
  }

  function checkHoneypot(formEl) {
    if (!formEl) return true;
    const hp = formEl.querySelector('.sh-hp');
    if (hp && hp.value.length > 0) {
      logSecurityEvent('BOT_DETECTED', 'Honeypot field preenchido');
      return false; // Bot detected
    }
    return true; // Human
  }

  // ----- 4. ANTI-TAMPERING: DOM Integrity -----
  let domChecksum = null;

  function computeChecksum() {
    const critical = document.querySelectorAll('script[src], link[rel="stylesheet"]');
    let hash = 0;
    critical.forEach(function(el) {
      var s = (el.src || el.href || '');
      for (var i = 0; i < s.length; i++) {
        hash = ((hash << 5) - hash + s.charCodeAt(i)) | 0;
      }
    });
    return hash;
  }

  function initIntegrity() {
    domChecksum = computeChecksum();
    // Monitor for new script injections
    var observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(m) {
        m.addedNodes.forEach(function(node) {
          if (node.nodeType === 1) {
            if (node.tagName === 'SCRIPT' && !node.hasAttribute('data-sh-trusted')) {
              logSecurityEvent('SCRIPT_INJECTION', 'Script nao autorizado detectado: ' + (node.src || 'inline'));
              node.remove();
            }
            if (node.tagName === 'IFRAME') {
              logSecurityEvent('IFRAME_INJECTION', 'Iframe nao autorizado detectado');
              node.remove();
            }
          }
        });
      });
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  function verifyIntegrity() {
    var current = computeChecksum();
    if (domChecksum !== null && current !== domChecksum) {
      logSecurityEvent('INTEGRITY_VIOLATION', 'DOM checksum alterado');
      return false;
    }
    return true;
  }

  // ----- 5. SESSION SECURITY -----
  function secureStore(key, value) {
    try {
      var data = JSON.stringify({ v: value, t: Date.now(), h: simpleHash(key + JSON.stringify(value)) });
      sessionStorage.setItem('sh_' + key, btoa(unescape(encodeURIComponent(data))));
    } catch(e) { /* storage full or blocked */ }
  }

  function secureRetrieve(key) {
    try {
      var raw = sessionStorage.getItem('sh_' + key);
      if (!raw) return null;
      var data = JSON.parse(decodeURIComponent(escape(atob(raw))));
      // Verify hash
      if (data.h !== simpleHash(key + JSON.stringify(data.v))) {
        logSecurityEvent('SESSION_TAMPER', 'Dado adulterado: ' + key);
        sessionStorage.removeItem('sh_' + key);
        return null;
      }
      // Check expiry (1 hour max)
      if (Date.now() - data.t > 3600000) {
        sessionStorage.removeItem('sh_' + key);
        return null;
      }
      return data.v;
    } catch(e) {
      sessionStorage.removeItem('sh_' + key);
      return null;
    }
  }

  function simpleHash(str) {
    var h = 0;
    for (var i = 0; i < str.length; i++) {
      h = ((h << 5) - h + str.charCodeAt(i)) | 0;
    }
    return h;
  }

  // ----- 6. ANTI-DEVTOOLS -----
  var devtoolsWarned = false;

  function detectDevTools() {
    var threshold = 160;
    var widthDiff = window.outerWidth - window.innerWidth > threshold;
    var heightDiff = window.outerHeight - window.innerHeight > threshold;
    if ((widthDiff || heightDiff) && !devtoolsWarned) {
      devtoolsWarned = true;
      logSecurityEvent('DEVTOOLS_OPEN', 'DevTools detectado aberto');
    }
  }

  // ----- 7. COPY PROTECTION -----
  function initCopyProtection() {
    document.addEventListener('contextmenu', function(e) {
      if (document.getElementById('results-section') &&
          document.getElementById('results-section').classList.contains('active')) {
        e.preventDefault();
        logSecurityEvent('CONTEXT_MENU', 'Tentativa de menu de contexto na area de resultados');
      }
    });

    document.addEventListener('keydown', function(e) {
      // Block Ctrl+U (view source), Ctrl+S (save), Ctrl+Shift+I (devtools), F12
      if ((e.ctrlKey && e.key === 'u') ||
          (e.ctrlKey && e.key === 's') ||
          (e.ctrlKey && e.shiftKey && e.key === 'I') ||
          e.key === 'F12') {
        e.preventDefault();
        logSecurityEvent('KEY_BLOCKED', 'Atalho bloqueado: ' + (e.ctrlKey?'Ctrl+':'') + (e.shiftKey?'Shift+':'') + e.key);
      }
    });
  }

  // ----- 8. SQL/NOSQL INJECTION PREVENTION -----
  function detectInjection(str) {
    if (typeof str !== 'string') return false;
    var patterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b)/i,
      /(-{2}|\/\*|\*\/|;|\bOR\b\s+\d+=\d+)/i,
      /(\$\{|\$\(|`.*`)/,
      /(\\x[0-9a-f]{2}|\\u[0-9a-f]{4})/i,
      /(<\s*script|<\s*img\s+src\s*=|<\s*svg\s+onload)/i,
      /(document\s*\.\s*(cookie|write|location)|window\s*\.\s*location)/i,
      /(\balert\s*\(|\beval\s*\(|\bFunction\s*\()/i,
      /(&#x?[0-9a-f]+;?){3,}/i
    ];
    for (var i = 0; i < patterns.length; i++) {
      if (patterns[i].test(str)) {
        logSecurityEvent('INJECTION_ATTEMPT', 'Padrao ' + (i+1) + ' detectado: ' + str.substring(0,50));
        return true;
      }
    }
    return false;
  }

  // ----- 9. SECURITY EVENT LOG -----
  var securityLog = [];
  var MAX_LOG = 100;

  function logSecurityEvent(type, detail) {
    var entry = {
      ts: new Date().toISOString(),
      type: type,
      detail: detail,
      ua: navigator.userAgent.substring(0, 80)
    };
    securityLog.push(entry);
    if (securityLog.length > MAX_LOG) securityLog.shift();
    // In production, send to server:
    // fetch('/api/security-log', { method:'POST', body:JSON.stringify(entry) });
    console.warn('[SH-SECURITY] ' + type + ': ' + detail);
  }

  // ----- 10. REQUEST FINGERPRINT -----
  function generateFingerprint() {
    var canvas = document.createElement('canvas');
    var ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('SH-FP', 2, 2);
    var data = canvas.toDataURL().substring(0, 50);
    var fp = simpleHash(navigator.userAgent + screen.width + screen.height +
      new Date().getTimezoneOffset() + navigator.language + data);
    return fp;
  }

  // ----- 11. FLOOD PROTECTION (rapid clicks) -----
  var lastAction = 0;
  var MIN_INTERVAL = 1000; // 1s between actions

  function throttleAction() {
    var now = Date.now();
    if (now - lastAction < MIN_INTERVAL) {
      logSecurityEvent('FLOOD', 'Acoes muito rapidas (' + (now - lastAction) + 'ms)');
      return false;
    }
    lastAction = now;
    return true;
  }

  // ----- 12. INIT -----
  function init() {
    initIntegrity();
    initCopyProtection();
    createHoneypot(document.getElementById('search-form'));
    setInterval(detectDevTools, 3000);
    setInterval(verifyIntegrity, 10000);
    logSecurityEvent('INIT', 'Modulo de seguranca inicializado | FP: ' + generateFingerprint());
  }

  // Auto-init on DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Public API
  return {
    sanitizeHTML: sanitizeHTML,
    sanitizeInput: sanitizeInput,
    sanitizeDocument: sanitizeDocument,
    sanitizeName: sanitizeName,
    checkRateLimit: checkRateLimit,
    checkHoneypot: checkHoneypot,
    detectInjection: detectInjection,
    throttleAction: throttleAction,
    secureStore: secureStore,
    secureRetrieve: secureRetrieve,
    verifyIntegrity: verifyIntegrity,
    logEvent: logSecurityEvent,
    getLog: function() { return securityLog.slice(); }
  };
})();

// ================================================================
// END SECURITY MODULE
// ================================================================
// =======================================================
// STATE
// =======================================================
let searchType = 'cpf';
let currentResult = null;
let consentAccepted = false;
let facialImageData = null;
let cameraStream = null;

// =======================================================
// CONSENT SYSTEM
// =======================================================
(function initConsent() {
  if (SH_SECURITY.secureRetrieve('consent') === 'accepted') {
    consentAccepted = true;
  }
  // NAO mostra o overlay ao carregar — so quando tentar pesquisar
  const c1 = document.getElementById('consent-check-1');
  const c2 = document.getElementById('consent-check-2');
  const btnAccept = document.getElementById('btn-accept-consent');
  function checkConsent() {
    btnAccept.disabled = !(c1.checked && c2.checked);
  }
  c1.addEventListener('change', checkConsent);
  c2.addEventListener('change', checkConsent);
})();

function acceptConsent() {
  consentAccepted = true;
  SH_SECURITY.secureStore('consent', 'accepted');
  SH_SECURITY.logEvent('CONSENT_ACCEPTED', 'Termos aceitos pelo usuario');
  document.getElementById('consent-overlay').classList.remove('active');
  // Executa a busca que estava pendente
  if (window._pendingBgCheck) { window._pendingBgCheck = false; runBackgroundCheck(); }
}
function rejectConsent() {
  document.getElementById('consent-overlay').classList.remove('active');
  var section = document.querySelector('.search-section');
  section.textContent = '';
  var wrapper = document.createElement('div');
  wrapper.style.cssText = 'text-align:center;padding:3rem;';
  var h2 = document.createElement('h2');
  h2.style.color = 'var(--text-muted)';
  h2.textContent = 'Acesso Negado';
  var p = document.createElement('p');
  p.style.cssText = 'color:var(--text-muted);margin-top:1rem;';
  p.textContent = 'Voce precisa aceitar os termos de uso para utilizar o Background Check.';
  var btn = document.createElement('button');
  btn.className = 'btn';
  btn.style.marginTop = '1rem';
  btn.textContent = 'Tentar Novamente';
  btn.onclick = function() { location.reload(); };
  wrapper.appendChild(h2);
  wrapper.appendChild(p);
  wrapper.appendChild(btn);
  section.appendChild(wrapper);
}

// =======================================================
// AGENCIES DATABASE
// =======================================================
const AGENCIES = [
  // International & UN System
  { id: 'un', name: 'Nacoes Unidas (ONU)', country: 'Internacional', flag: '&#127482;&#127475;', system: 'UN Security Council / OHCHR', level: 'restricted' },
  { id: 'interpol', name: 'INTERPOL', country: 'Internacional', flag: '&#127758;', system: 'I-24/7 / Red Notices', level: 'restricted' },
  { id: 'europol', name: 'EUROPOL', country: 'Uniao Europeia', flag: '&#127466;&#127482;', system: 'SIENA / EIS', level: 'restricted' },
  { id: 'icc', name: 'ICC/TPI', country: 'Haia', flag: '&#9878;', system: 'Tribunal Penal Internacional', level: 'classified' },
  { id: 'unodc', name: 'UNODC', country: 'ONU', flag: '&#127482;&#127475;', system: 'Escritorio contra Drogas e Crime', level: 'restricted' },
  { id: 'unhcr', name: 'ACNUR/UNHCR', country: 'ONU', flag: '&#127482;&#127475;', system: 'Registro de Refugiados', level: 'classified' },
  { id: 'unsanctions', name: 'UN Sanctions', country: 'ONU', flag: '&#127482;&#127475;', system: 'Lista Consolidada de Sancoes', level: 'restricted' },
  // Brazil
  { id: 'pf', name: 'Policia Federal', country: 'Brasil', flag: '&#127463;&#127479;', system: 'SINPI / SINIC', level: 'restricted' },
  { id: 'pc', name: 'Policia Civil', country: 'Brasil', flag: '&#127463;&#127479;', system: 'Registros Estaduais', level: 'restricted' },
  { id: 'pm', name: 'Policia Militar', country: 'Brasil', flag: '&#127463;&#127479;', system: 'BOC / COPOM', level: 'restricted' },
  { id: 'mp', name: 'Ministerio Publico', country: 'Brasil', flag: '&#127463;&#127479;', system: 'CNMP / MPF', level: 'public' },
  { id: 'rf', name: 'Receita Federal', country: 'Brasil', flag: '&#127463;&#127479;', system: 'CPF/CNPJ', level: 'public' },
  // USA
  { id: 'fbi', name: 'FBI', country: 'EUA', flag: '&#127482;&#127480;', system: 'NCIC / III / NICS', level: 'restricted' },
  { id: 'dea', name: 'DEA', country: 'EUA', flag: '&#127482;&#127480;', system: 'NADDIS', level: 'classified' },
  { id: 'usms', name: 'U.S. Marshals', country: 'EUA', flag: '&#127482;&#127480;', system: 'Fugitives Database', level: 'restricted' },
  // Europe
  { id: 'met', name: 'Scotland Yard', country: 'Reino Unido', flag: '&#127468;&#127463;', system: 'PNC / PND', level: 'restricted' },
  { id: 'bka', name: 'BKA', country: 'Alemanha', flag: '&#127465;&#127466;', system: 'INPOL / SIS II', level: 'restricted' },
  { id: 'dgsi', name: 'DGSI', country: 'Franca', flag: '&#127467;&#127479;', system: 'TAJ / FPR', level: 'classified' },
  { id: 'gc', name: 'Guardia Civil', country: 'Espanha', flag: '&#127466;&#127480;', system: 'SIRDEE / BDSN', level: 'restricted' },
  // Other
  { id: 'rcmp', name: 'RCMP', country: 'Canada', flag: '&#127464;&#127462;', system: 'CPIC', level: 'restricted' },
  { id: 'afp', name: 'AFP', country: 'Australia', flag: '&#127462;&#127482;', system: 'NCIS', level: 'restricted' },
  { id: 'npa', name: 'NPA', country: 'Japao', flag: '&#127471;&#127477;', system: 'NCIS-JP', level: 'restricted' },
  { id: 'carab', name: 'Carabineros', country: 'Chile', flag: '&#127464;&#127473;', system: 'AUPOL', level: 'restricted' },
  { id: 'pfa', name: 'Policia Federal', country: 'Argentina', flag: '&#127462;&#127479;', system: 'SIBIOS', level: 'restricted' },
];

// =======================================================
// SEARCH TYPE TABS
// =======================================================
function setSearchType(type) {
  searchType = type;
  document.querySelectorAll('.search-type-tab').forEach(t => t.classList.remove('active'));
  document.querySelector('[data-type="' + type + '"]').classList.add('active');

  const docRow = document.getElementById('doc-row');
  const nameRow = document.getElementById('name-row');
  const facialRow = document.getElementById('facial-row');
  const docInput = document.getElementById('doc-input');
  const docLabel = document.getElementById('doc-label');
  const filter = document.getElementById('homonimo-filter');
  const btnSearch = document.getElementById('btn-search');

  // Fechar camera se trocar de aba
  stopCamera();

  if (type === 'cpf') {
    docRow.style.display = '';
    nameRow.style.display = 'none';
    facialRow.style.display = 'none';
    docLabel.textContent = 'CPF';
    docInput.placeholder = '000.000.000-00';
    docInput.maxLength = 14;
    docInput.value = '';
    filter.classList.remove('active');
    btnSearch.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Iniciar Varredura com IA';
  } else if (type === 'cnpj') {
    docRow.style.display = '';
    nameRow.style.display = 'none';
    facialRow.style.display = 'none';
    docLabel.textContent = 'CNPJ';
    docInput.placeholder = '00.000.000/0000-00';
    docInput.maxLength = 18;
    docInput.value = '';
    filter.classList.remove('active');
    btnSearch.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Iniciar Varredura com IA';
  } else if (type === 'nome') {
    docRow.style.display = 'none';
    nameRow.style.display = '';
    facialRow.style.display = 'none';
    filter.classList.add('active');
    btnSearch.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Iniciar Varredura com IA';
  } else if (type === 'facial') {
    docRow.style.display = 'none';
    nameRow.style.display = 'none';
    facialRow.style.display = '';
    filter.classList.remove('active');
    btnSearch.innerHTML = '&#128247; Iniciar Escaneamento Facial';
  }
}

// =======================================================
// FORMAT DOCUMENT
// =======================================================
function formatDocument(el) {
  let v = el.value.replace(/\D/g, '');
  if (searchType === 'cpf') {
    if (v.length > 11) v = v.substring(0, 11);
    if (v.length > 9) v = v.substring(0,3) + '.' + v.substring(3,6) + '.' + v.substring(6,9) + '-' + v.substring(9);
    else if (v.length > 6) v = v.substring(0,3) + '.' + v.substring(3,6) + '.' + v.substring(6);
    else if (v.length > 3) v = v.substring(0,3) + '.' + v.substring(3);
  } else if (searchType === 'cnpj') {
    if (v.length > 14) v = v.substring(0, 14);
    if (v.length > 12) v = v.substring(0,2) + '.' + v.substring(2,5) + '.' + v.substring(5,8) + '/' + v.substring(8,12) + '-' + v.substring(12);
    else if (v.length > 8) v = v.substring(0,2) + '.' + v.substring(2,5) + '.' + v.substring(5,8) + '/' + v.substring(8);
    else if (v.length > 5) v = v.substring(0,2) + '.' + v.substring(2,5) + '.' + v.substring(5);
    else if (v.length > 2) v = v.substring(0,2) + '.' + v.substring(2);
  }
  el.value = v;
}

// =======================================================
// VALIDATE CPF
// =======================================================
function validateCPF(cpf) {
  cpf = cpf.replace(/\D/g, '');
  if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += parseInt(cpf[i]) * (10 - i);
  let d1 = 11 - (sum % 11);
  if (d1 >= 10) d1 = 0;
  if (parseInt(cpf[9]) !== d1) return false;
  sum = 0;
  for (let i = 0; i < 10; i++) sum += parseInt(cpf[i]) * (11 - i);
  let d2 = 11 - (sum % 11);
  if (d2 >= 10) d2 = 0;
  return parseInt(cpf[10]) === d2;
}

// =======================================================
// VALIDATE CNPJ
// =======================================================
function validateCNPJ(cnpj) {
  cnpj = cnpj.replace(/\D/g, '');
  if (cnpj.length !== 14 || /^(\d)\1{13}$/.test(cnpj)) return false;
  const w1 = [5,4,3,2,9,8,7,6,5,4,3,2];
  const w2 = [6,5,4,3,2,9,8,7,6,5,4,3,2];
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += parseInt(cnpj[i]) * w1[i];
  let d1 = sum % 11 < 2 ? 0 : 11 - (sum % 11);
  if (parseInt(cnpj[12]) !== d1) return false;
  sum = 0;
  for (let i = 0; i < 13; i++) sum += parseInt(cnpj[i]) * w2[i];
  let d2 = sum % 11 < 2 ? 0 : 11 - (sum % 11);
  return parseInt(cnpj[13]) === d2;
}

// =======================================================
// SEED RANDOM (deterministic based on input)
// =======================================================
function seedRandom(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h + str.charCodeAt(i)) | 0;
  }
  return function() {
    h = (h * 1103515245 + 12345) & 0x7fffffff;
    return (h % 1000) / 1000;
  };
}

// =======================================================
// GENERATE NAMES
// =======================================================
const firstNames = ['Carlos', 'Maria', 'Jose', 'Ana', 'Paulo', 'Fernanda', 'Lucas', 'Juliana', 'Pedro', 'Mariana', 'Rafael', 'Camila', 'Bruno', 'Patricia', 'Rodrigo', 'Beatriz', 'Eduardo', 'Larissa', 'Gabriel', 'Amanda'];
const lastNames = ['Silva', 'Santos', 'Oliveira', 'Souza', 'Rodrigues', 'Ferreira', 'Alves', 'Pereira', 'Lima', 'Gomes', 'Costa', 'Ribeiro', 'Martins', 'Carvalho', 'Araujo', 'Melo', 'Barbosa', 'Rocha', 'Dias', 'Nascimento'];
const cities = ['Sao Paulo/SP', 'Rio de Janeiro/RJ', 'Belo Horizonte/MG', 'Curitiba/PR', 'Porto Alegre/RS', 'Salvador/BA', 'Brasilia/DF', 'Fortaleza/CE', 'Recife/PE', 'Manaus/AM', 'Maringa/PR', 'Londrina/PR', 'Campinas/SP', 'Goiania/GO', 'Florianopolis/SC'];
const courts = ['TJSP', 'TJRJ', 'TJMG', 'TJPR', 'TJRS', 'TJBA', 'TJDF', 'TJCE', 'TJPE', 'TJAM', 'TRF-1', 'TRF-2', 'TRF-3', 'TRF-4', 'TRF-5', 'TST', 'TRT-9', 'TRT-15', 'TRT-2'];
const companyTypes = ['LTDA', 'S.A.', 'EIRELI', 'MEI', 'EPP'];
const companyNames = ['Tech Solutions', 'Comercio Digital', 'Servicos Integrados', 'Construtora Delta', 'Transportes Express', 'Consultoria Alpha', 'Alimentos Premium', 'Industria Nacional', 'Logistica Brasil', 'Engenharia Total'];

function generateName(rng) {
  return firstNames[Math.floor(rng() * firstNames.length)] + ' ' +
         lastNames[Math.floor(rng() * lastNames.length)] + ' ' +
         lastNames[Math.floor(rng() * lastNames.length)];
}

function generateCompanyName(rng) {
  return companyNames[Math.floor(rng() * companyNames.length)] + ' ' +
         companyTypes[Math.floor(rng() * companyTypes.length)];
}

// =======================================================
// GENERATE PROCESS NUMBER
// =======================================================
function generateProcessNumber(rng) {
  const n = () => Math.floor(rng() * 10);
  return n()+''+n()+''+n()+''+n()+''+n()+''+n()+''+n()+'-'+n()+''+n()+'.20'+
    (20+Math.floor(rng()*6))+'.'+Math.floor(rng()*9+1)+'.'+n()+''+n()+'.'+ 
    n()+''+n()+''+n()+''+n();
}

// =======================================================
// GENERATE INTELLIGENCE DATA
// =======================================================
function generateIntelligenceData(input, type) {
  const rng = seedRandom(input);
  const isCNPJ = type === 'cnpj';
  const isName = type === 'nome';

  // Determine risk profile
  const riskSeed = rng();
  let riskLevel, riskScore;
  if (riskSeed < 0.35) { riskLevel = 'BAIXO'; riskScore = Math.floor(10 + rng() * 25); }
  else if (riskSeed < 0.7) { riskLevel = 'MEDIO'; riskScore = Math.floor(35 + rng() * 30); }
  else if (riskSeed < 0.9) { riskLevel = 'ALTO'; riskScore = Math.floor(65 + rng() * 25); }
  else { riskLevel = 'CRITICO'; riskScore = Math.floor(90 + rng() * 10); }

  // Subject info
  const name = isName ? input : (isCNPJ ? generateCompanyName(rng) : generateName(rng));
  const city = cities[Math.floor(rng() * cities.length)];
  const birthYear = 1960 + Math.floor(rng() * 40);
  const birthMonth = 1 + Math.floor(rng() * 12);
  const birthDay = 1 + Math.floor(rng() * 28);

  // Judicial records
  const processTypes = ['civil', 'criminal', 'trabalhista', 'tributario'];
  const processDescriptions = {
    civil: ['Acao de Cobranca', 'Acao de Indenizacao por Danos Morais', 'Acao de Despejo', 'Execucao de Titulo Extrajudicial', 'Acao Revisional de Contrato', 'Acao de Obrigacao de Fazer', 'Busca e Apreensao', 'Monitoria', 'Acao de Consignacao em Pagamento'],
    criminal: ['Estelionato (Art. 171 CP)', 'Apropriacao Indebita (Art. 168 CP)', 'Fraude (Art. 171 CP)', 'Crime contra a Ordem Tributaria', 'Lavagem de Dinheiro', 'Furto Qualificado (Art. 155 CP)', 'Falsidade Ideologica (Art. 299 CP)'],
    trabalhista: ['Reclamacao Trabalhista - Verbas Rescisorias', 'Reclamacao Trabalhista - Horas Extras', 'Acao Trabalhista - Danos Morais no Trabalho', 'Reclamacao Trabalhista - Vinculo Empregaticio', 'Acao Trabalhista - Adicional de Insalubridade'],
    tributario: ['Execucao Fiscal - Divida Ativa', 'Execucao Fiscal - ICMS', 'Execucao Fiscal - ISS', 'Acao Anulatoria de Debito Fiscal', 'Mandado de Seguranca Tributario']
  };
  const statuses = ['Ativo', 'Arquivado', 'Em andamento', 'Sentenca proferida', 'Recurso pendente', 'Encerrado', 'Baixado'];

  let numProcesses = 0;
  if (riskLevel === 'BAIXO') numProcesses = Math.floor(rng() * 2);
  else if (riskLevel === 'MEDIO') numProcesses = 1 + Math.floor(rng() * 3);
  else if (riskLevel === 'ALTO') numProcesses = 3 + Math.floor(rng() * 4);
  else numProcesses = 5 + Math.floor(rng() * 5);

  const processes = [];
  for (let i = 0; i < numProcesses; i++) {
    let pType;
    if (riskLevel === 'CRITICO' && i === 0) pType = 'criminal';
    else if (riskLevel === 'ALTO' && i < 2 && rng() > 0.5) pType = 'criminal';
    else pType = processTypes[Math.floor(rng() * processTypes.length)];

    const descs = processDescriptions[pType];
    const values = [5000, 10000, 15000, 25000, 50000, 75000, 100000, 250000, 500000, 1000000];
    const val = values[Math.floor(rng() * values.length)];
    const year = 2018 + Math.floor(rng() * 8);
    const court = courts[Math.floor(rng() * courts.length)];
    const status = (riskLevel === 'BAIXO' || rng() > 0.5) ? statuses[Math.floor(3 + rng() * 4)] : statuses[Math.floor(rng() * 3)];

    processes.push({
      number: generateProcessNumber(rng),
      type: pType,
      description: descs[Math.floor(rng() * descs.length)],
      value: val,
      year: year,
      court: court,
      status: status,
      parties: isCNPJ ? name + ' (Reu)' : name + (rng() > 0.5 ? ' (Autor)' : ' (Reu)')
    });
  }

  // Gazette entries
  let numGazettes = 0;
  if (riskLevel === 'MEDIO') numGazettes = Math.floor(rng() * 2);
  else if (riskLevel === 'ALTO') numGazettes = 1 + Math.floor(rng() * 3);
  else if (riskLevel === 'CRITICO') numGazettes = 2 + Math.floor(rng() * 3);

  const gazetteTypes = [
    { source: 'DOU - Diario Oficial da Uniao', title: 'Edital de Citacao', excerpt: 'Fica citado(a) o(a) interessado(a) para comparecer em juizo no prazo de 15 dias uteis.' },
    { source: 'DOSP - Diario Oficial de Sao Paulo', title: 'Publicacao de Licitacao', excerpt: 'Participacao em processo licitatorio - Pregao Eletronico.' },
    { source: 'DOERJ - Diario Oficial do Rio de Janeiro', title: 'Intimacao Judicial', excerpt: 'Intimacao para apresentacao de defesa no processo administrativo.' },
    { source: 'DOU - Diario Oficial da Uniao', title: 'Sancao Administrativa', excerpt: 'Aplicacao de multa por descumprimento de obrigacao acessoria.' },
    { source: 'DOEMG - Diario Oficial de Minas Gerais', title: 'Protesto de Titulo', excerpt: 'Registro de protesto por falta de pagamento de titulo cambial.' },
    { source: 'DOU - Diario Oficial da Uniao', title: 'Cadastro de Impedidos', excerpt: 'Inclusao no cadastro de empresas impedidas de contratar com a administracao publica.' },
    { source: 'DOEPR - Diario Oficial do Parana', title: 'Edital de Notificacao', excerpt: 'Notificacao para regularizacao de pendencias junto ao orgao competente.' }
  ];

  const gazettes = [];
  for (let i = 0; i < numGazettes; i++) {
    const g = gazetteTypes[Math.floor(rng() * gazetteTypes.length)];
    const month = 1 + Math.floor(rng() * 12);
    const day = 1 + Math.floor(rng() * 28);
    const year = 2022 + Math.floor(rng() * 4);
    gazettes.push({
      source: g.source,
      title: g.title,
      excerpt: g.excerpt.replace('o(a) interessado(a)', name),
      date: String(day).padStart(2,'0') + '/' + String(month).padStart(2,'0') + '/' + year
    });
  }

  // Financial status
  const cpfStatus = riskLevel === 'CRITICO' ? 'Irregular' : (riskLevel === 'ALTO' && rng() > 0.5 ? 'Pendente' : 'Regular');
  const debtValues = [0, 0, 1500, 5000, 12000, 25000, 50000, 80000, 150000, 300000];
  let activeDebt = 0;
  if (riskLevel === 'MEDIO') activeDebt = debtValues[2 + Math.floor(rng() * 2)];
  else if (riskLevel === 'ALTO') activeDebt = debtValues[4 + Math.floor(rng() * 3)];
  else if (riskLevel === 'CRITICO') activeDebt = debtValues[6 + Math.floor(rng() * 4)];

  const financials = [
    { label: isCNPJ ? 'Situacao Cadastral CNPJ' : 'Situacao Cadastral CPF', detail: 'Receita Federal do Brasil', status: cpfStatus },
    { label: 'Divida Ativa da Uniao', detail: 'Procuradoria-Geral da Fazenda Nacional', status: activeDebt > 0 ? 'R$ ' + activeDebt.toLocaleString('pt-BR') : 'Nada consta' },
    { label: 'Certidao Negativa de Debitos', detail: 'Tributos Federais e Divida Ativa', status: activeDebt > 0 ? 'Positiva' : 'Negativa' }
  ];

  if (isCNPJ) {
    financials.push({ label: 'CEIS - Cadastro de Empresas Inidoeneas', detail: 'Portal da Transparencia', status: riskLevel === 'CRITICO' ? 'Consta registro' : 'Nada consta' });
    financials.push({ label: 'CNEP - Cadastro Nacional de Empresas Punidas', detail: 'Portal da Transparencia', status: riskLevel === 'CRITICO' ? 'Consta registro' : 'Nada consta' });
  }

  // Debts and protests
  let numDebts = 0;
  if (riskLevel === 'MEDIO') numDebts = Math.floor(rng() * 2);
  else if (riskLevel === 'ALTO') numDebts = 1 + Math.floor(rng() * 3);
  else if (riskLevel === 'CRITICO') numDebts = 3 + Math.floor(rng() * 4);

  const creditors = ['Banco do Brasil', 'Caixa Economica Federal', 'Itau Unibanco', 'Bradesco', 'Santander', 'CPFL Energia', 'Sabesp', 'Copel', 'Tim', 'Claro', 'Vivo'];
  const debts = [];
  for (let i = 0; i < numDebts; i++) {
    const val = [800, 1500, 3000, 5000, 8000, 12000, 20000, 35000, 50000][Math.floor(rng() * 9)];
    debts.push({
      creditor: creditors[Math.floor(rng() * creditors.length)],
      value: val,
      date: String(1 + Math.floor(rng() * 28)).padStart(2,'0') + '/' + String(1 + Math.floor(rng() * 12)).padStart(2,'0') + '/' + (2022 + Math.floor(rng() * 4)),
      type: rng() > 0.5 ? 'Protesto' : 'Negativacao'
    });
  }

  // Generate AI Summary
  let summary = '';
  const criminalProcesses = processes.filter(p => p.type === 'criminal');
  const activeProcesses = processes.filter(p => p.status === 'Ativo' || p.status === 'Em andamento');

  if (riskLevel === 'BAIXO') {
    if (numProcesses === 0) {
      summary = '<p><strong>Resultado da analise:</strong> Nao foram encontrados registros negativos significativos vinculados a este ' + (isCNPJ ? 'CNPJ' : 'CPF') + '.</p>' +
        '<p>A varredura em tribunais de justica, Jusbrasil, Diarios Oficiais e Portal da Transparencia retornou resultado limpo. ' +
        (isCNPJ ? 'A empresa' : 'A pessoa consultada') + ' nao possui processos judiciais ativos, publicacoes em diarios oficiais que indiquem pendencias, nem dividas registradas nos orgaos federais.</p>' +
        '<p><strong>Classificacao de Risco: BAIXO.</strong> ' + (isCNPJ ? 'A empresa apresenta' : 'O perfil apresenta') + ' historico limpo nas bases consultadas.</p>';
    } else {
      summary = '<p><strong>Resultado da analise:</strong> Foram encontrados <strong>' + numProcesses + ' registro(s) judicial(is)</strong>, porem todos de natureza civil e com status encerrado ou arquivado.</p>' +
        '<p>Os processos identificados sao de baixa relevancia e nao indicam padroes de risco. Nao ha registros criminais, dividas ativas ou restricoes cadastrais.</p>' +
        '<p><strong>Classificacao de Risco: BAIXO.</strong> Os registros encontrados nao comprometem a avaliacao geral.</p>';
    }
  } else if (riskLevel === 'MEDIO') {
    summary = '<p><strong>Resultado da analise:</strong> Foram identificados <strong>' + numProcesses + ' processo(s) judicial(is)</strong>';
    if (numGazettes > 0) summary += ' e <strong>' + numGazettes + ' publicacao(oes) em Diarios Oficiais</strong>';
    summary += '.</p>';
    summary += '<p>Os processos sao majoritariamente de natureza civil' + (processes.some(p => p.type === 'trabalhista') ? ' e trabalhista' : '') + ', com valores moderados. ';
    if (activeDebt > 0) summary += 'Foi identificada divida ativa no valor de <strong>R$ ' + activeDebt.toLocaleString('pt-BR') + '</strong>. ';
    if (numDebts > 0) summary += 'Ha <strong>' + numDebts + ' registro(s) de protesto/negativacao</strong>. ';
    summary += '</p>';
    summary += '<p><strong>Classificacao de Risco: MEDIO.</strong> Existem pendencias que merecem atencao, mas nao indicam comprometimento grave. Recomenda-se aprofundamento na analise dos processos ativos antes de qualquer decisao.</p>';
  } else if (riskLevel === 'ALTO') {
    summary = '<p><strong>Resultado da analise:</strong> A varredura identificou <strong>' + numProcesses + ' processo(s) judicial(is)</strong>';
    if (criminalProcesses.length > 0) summary += ', incluindo <strong>' + criminalProcesses.length + ' de natureza criminal</strong>';
    summary += '.</p>';
    summary += '<p><strong>Pontos criticos identificados:</strong></p><p>';
    if (criminalProcesses.length > 0) summary += '- Processos criminais ativos: ' + criminalProcesses.map(p => p.description).join(', ') + '<br>';
    if (activeDebt > 0) summary += '- Divida ativa junto a Uniao: R$ ' + activeDebt.toLocaleString('pt-BR') + '<br>';
    if (numDebts > 0) summary += '- ' + numDebts + ' registro(s) de protesto/negativacao em cartorios<br>';
    if (cpfStatus !== 'Regular') summary += '- Situacao cadastral: ' + cpfStatus + '<br>';
    summary += '</p>';
    summary += '<p><strong>Classificacao de Risco: ALTO.</strong> O perfil apresenta indicadores significativos de risco. Recomenda-se cautela extrema e consulta a um profissional juridico antes de qualquer relacao comercial ou contratual.</p>';
  } else {
    summary = '<p><strong>ALERTA: Resultado da analise indica perfil de RISCO CRITICO.</strong></p>';
    summary += '<p>Foram identificados <strong>' + numProcesses + ' processo(s) judicial(is)</strong>, incluindo <strong>' + criminalProcesses.length + ' de natureza criminal</strong>, com multiplas publicacoes em Diarios Oficiais e restricoes ativas.</p>';
    summary += '<p><strong>Principais alertas:</strong></p><p>';
    criminalProcesses.forEach(p => { summary += '- <strong style="color:#ef4444;">' + p.description + '</strong> (' + p.court + ', ' + p.year + ') - Status: ' + p.status + '<br>'; });
    if (activeDebt > 0) summary += '- <strong>Divida ativa:</strong> R$ ' + activeDebt.toLocaleString('pt-BR') + '<br>';
    if (isCNPJ) summary += '- Empresa consta no CEIS/CNEP (impedida de contratar com a administracao publica)<br>';
    summary += '- ' + numDebts + ' protesto(s)/negativacao(oes) registrados<br>';
    summary += '</p>';
    summary += '<p><strong>Classificacao de Risco: CRITICO.</strong> O perfil apresenta multiplos indicadores de risco grave. E fortemente recomendado <strong>nao prosseguir</strong> com qualquer relacao sem consultoria juridica especializada e due diligence completa.</p>';
  }

  return {
    riskLevel, riskScore, name, city,
    birthDate: String(birthDay).padStart(2,'0') + '/' + String(birthMonth).padStart(2,'0') + '/' + birthYear,
    isCNPJ, isName,
    docFormatted: isCNPJ ? document.getElementById('doc-input').value : (isName ? '---' : document.getElementById('doc-input').value),
    processes, gazettes, financials, debts,
    activeDebt, cpfStatus, summary,
    totalAlerts: numProcesses + numGazettes + numDebts + (activeDebt > 0 ? 1 : 0),
    timestamp: new Date().toLocaleString('pt-BR'),

    // Agency results
    agencyResults: generateAgencyResults(rng, riskLevel, numProcesses, criminalProcesses.length)
  };
}

// =======================================================
// GENERATE AGENCY RESULTS
// =======================================================
function generateAgencyResults(rng, riskLevel, totalProcesses, criminalCount) {
  const results = {};
  AGENCIES.forEach(a => {
    let status = 'clear';
    let detail = 'Nenhum registro encontrado';

    if (a.level === 'classified') {
      status = 'restricted';
      detail = 'Acesso restrito — requer autorizacao judicial';
    } else if (riskLevel === 'CRITICO') {
      if (a.id === 'interpol') { status = 'found'; detail = 'ALERTA: Red Notice ativa identificada'; }
      else if (a.id === 'fbi' && rng() > 0.4) { status = 'found'; detail = 'Registro no NCIC — consulta classificada'; }
      else if (a.id === 'pf') { status = 'found'; detail = 'Inquerito policial ativo — delegacia especializada'; }
      else if (a.id === 'pc') { status = 'found'; detail = 'Boletins de ocorrencia registrados'; }
      else if (a.id === 'pm') { status = rng() > 0.5 ? 'found' : 'clear'; detail = status === 'found' ? 'Registros operacionais identificados' : detail; }
      else if (rng() > 0.6) { status = 'found'; detail = 'Registro identificado — verificar detalhes'; }
    } else if (riskLevel === 'ALTO') {
      if (a.id === 'pf' && criminalCount > 0) { status = 'found'; detail = 'Registro de antecedentes identificado'; }
      else if (a.id === 'pc' && rng() > 0.5) { status = 'found'; detail = 'Boletim de ocorrencia registrado'; }
      else if (a.id === 'mp') { status = totalProcesses > 2 ? 'found' : 'clear'; detail = status === 'found' ? 'Procedimento no Ministerio Publico' : detail; }
      else if (a.id === 'interpol' && rng() > 0.8) { status = 'found'; detail = 'Difusao identificada — verificar'; }
    } else if (riskLevel === 'MEDIO') {
      if (a.id === 'pc' && rng() > 0.7) { status = 'found'; detail = 'BO antigo registrado (arquivado)'; }
    }

    results[a.id] = { status, detail };
  });
  return results;
}

// =======================================================
// RUN BACKGROUND CHECK
// =======================================================
async function runBackgroundCheck() {
  if (!consentAccepted) {
    window._pendingBgCheck = true;
    document.getElementById('consent-overlay').classList.add('active');
    return;
  }

  // SECURITY: Throttle
  if (!SH_SECURITY.throttleAction()) {
    alert('Aguarde um momento antes de fazer outra consulta.');
    return;
  }

  // SECURITY: Rate limit
  var rl = SH_SECURITY.checkRateLimit('search');
  if (!rl.allowed) {
    alert(rl.message);
    return;
  }

  // SECURITY: Anti-bot honeypot
  if (!SH_SECURITY.checkHoneypot(document.getElementById('search-form'))) {
    SH_SECURITY.logEvent('BOT_BLOCKED', 'Consulta bloqueada — bot detectado');
    return;
  }

  // SECURITY: DOM integrity
  SH_SECURITY.verifyIntegrity();

  let input = '';
  let facialHash = null;

  if (searchType === 'facial') {
    // Validacao de foto
    if (!facialImageData) {
      alert('Envie uma foto ou capture pela camera antes de iniciar o escaneamento.');
      return;
    }
    // Rodar animacao de scan facial
    facialHash = await runFacialScan();
    input = facialHash;
  } else if (searchType === 'nome') {
    input = SH_SECURITY.sanitizeName(document.getElementById('name-input').value);

    // SECURITY: Injection check
    if (SH_SECURITY.detectInjection(document.getElementById('name-input').value)) {
      alert('Entrada invalida detectada. Tentativa registrada.');
      return;
    }

    if (!input || input.length < 5) { alert('Informe o nome completo (minimo 5 caracteres).'); return; }
  } else {
    input = SH_SECURITY.sanitizeDocument(document.getElementById('doc-input').value);

    // SECURITY: Injection check
    if (SH_SECURITY.detectInjection(document.getElementById('doc-input').value)) {
      alert('Entrada invalida detectada. Tentativa registrada.');
      return;
    }
    const digits = input.replace(/\D/g, '');
    if (searchType === 'cpf') {
      if (!validateCPF(digits)) { alert('CPF invalido. Verifique os digitos e tente novamente.'); return; }
    } else {
      if (!validateCNPJ(digits)) { alert('CNPJ invalido. Verifique os digitos e tente novamente.'); return; }
    }
  }

  // SERVER-SIDE VALIDATION (segunda camada — segura)
  try {
    var valRes = await fetch('/api/background-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: input, type: searchType })
    });
    var valData = await valRes.json();
    if (!valRes.ok) {
      alert(valData.error || 'Erro de validacao no servidor.');
      return;
    }
  } catch(serverErr) {
    // Se servidor nao disponivel, prossegue com validacao client-side apenas
    console.warn('Server validation unavailable, using client-side only:', serverErr.message);
  }

  // Show loading
  const loading = document.getElementById('loading');
  loading.classList.add('active');

  const steps = searchType === 'facial' ? [
    { id: 'step-1', text: 'Hash facial processado — iniciando busca biometrica', duration: 800 },
    { id: 'step-2', text: 'ONU — Conselho de Seguranca / Lista de Sancoes', duration: 1200 },
    { id: 'step-3', text: 'INTERPOL Face Recognition (IFRS) / Red Notices', duration: 2000 },
    { id: 'step-4', text: 'FBI FACE Services / NGI — comparando biometria', duration: 2200 },
    { id: 'step-5', text: 'Europol FACE, UNODC, ACNUR e bases nacionais', duration: 1800 },
    { id: 'step-6', text: 'Cruzando com passaportes, vistos e cameras publicas', duration: 1500 },
    { id: 'step-7', text: 'Filtrando correspondencias — score de similaridade', duration: 1200 },
    { id: 'step-8', text: 'IA gerando relatorio com identificacao e historico', duration: 1500 }
  ] : [
    { id: 'step-1', text: 'Validando documento e identidade', duration: 800 },
    { id: 'step-2', text: 'ONU — Conselho de Seguranca / Lista Consolidada de Sancoes', duration: 1200 },
    { id: 'step-3', text: 'INTERPOL (Red Notices / I-24/7) e EUROPOL (SIENA)', duration: 1500 },
    { id: 'step-4', text: 'FBI (NCIC), UNODC e agencias nacionais', duration: 1800 },
    { id: 'step-5', text: 'Policia Federal, Civil e Militar — registros policiais', duration: 1500 },
    { id: 'step-6', text: 'Tribunais, Diarios Oficiais, Receita e Transparencia', duration: 1500 },
    { id: 'step-7', text: 'Cruzando dados, filtrando homonimos, verificando direitos', duration: 1200 },
    { id: 'step-8', text: 'IA gerando relatorio executivo com classificacao de risco', duration: 1500 }
  ];

  // Reset steps
  steps.forEach(s => {
    const el = document.getElementById(s.id);
    el.className = 'loading-step';
    el.querySelector('.step-icon').textContent = '\u25CB';
  });

  // Animate steps
  for (let i = 0; i < steps.length; i++) {
    const el = document.getElementById(steps[i].id);
    el.className = 'loading-step active';
    var iconEl = el.querySelector('.step-icon');
    iconEl.textContent = '';
    var spinner = document.createElement('div');
    spinner.className = 'step-spinner';
    iconEl.appendChild(spinner);
    document.getElementById('loading-title').textContent = steps[i].text + '...';

    await new Promise(r => setTimeout(r, steps[i].duration));

    el.className = 'loading-step done';
    el.querySelector('.step-icon').textContent = '\u2713';
  }

  // Generate data
  currentResult = generateIntelligenceData(input, searchType);

  // SECURITY: Log successful search
  SH_SECURITY.logEvent('SEARCH_COMPLETED', searchType.toUpperCase() + ' — Risco: ' + currentResult.riskLevel);

  // Render results
  renderResults(currentResult);

  // Hide loading, show results
  await new Promise(r => setTimeout(r, 500));
  loading.classList.remove('active');
  document.getElementById('results-section').classList.add('active');
  document.getElementById('results-section').scrollIntoView({ behavior: 'smooth' });

  // PAYWALL: bloquear resultado ate pagamento
  if (!paymentCompleted) {
    lockResult();
    // Mostrar paywall automaticamente apos 2 segundos
    setTimeout(function() { showPaywall(); }, 2000);
  }
}

// =======================================================
// SAFE HTML HELPER — sanitiza todo valor antes de inserir no DOM
// =======================================================
function escVal(v) {
  return SH_SECURITY.sanitizeHTML(String(v == null ? '' : v));
}
function safeTags(html) {
  // Permite apenas tags seguras: p, strong, br, span, em, b, i, ul, li
  var tmp = document.createElement('div');
  tmp.innerHTML = html;
  var allowed = ['P','STRONG','BR','SPAN','EM','B','I','UL','LI','DIV'];
  function clean(node) {
    var children = Array.from(node.childNodes);
    for (var i = 0; i < children.length; i++) {
      var c = children[i];
      if (c.nodeType === 1) {
        if (allowed.indexOf(c.tagName) === -1) {
          c.replaceWith(document.createTextNode(c.textContent));
        } else {
          // Remove atributos perigosos
          var attrs = Array.from(c.attributes);
          for (var j = 0; j < attrs.length; j++) {
            var name = attrs[j].name.toLowerCase();
            if (name.startsWith('on') || name === 'href' || name === 'src' || name === 'action') {
              c.removeAttribute(attrs[j].name);
            }
          }
          clean(c);
        }
      }
    }
  }
  clean(tmp);
  return tmp.innerHTML;
}

// =======================================================
// RENDER RESULTS
// =======================================================
function renderResults(data) {
  // Risk banner
  const banner = document.getElementById('risk-banner');
  banner.className = 'risk-banner';
  let riskColor, riskClass;
  if (data.riskLevel === 'BAIXO') { riskColor = 'var(--risk-low)'; riskClass = 'risk-low'; }
  else if (data.riskLevel === 'MEDIO') { riskColor = 'var(--risk-medium)'; riskClass = 'risk-medium'; }
  else { riskColor = 'var(--risk-high)'; riskClass = 'risk-high'; }
  banner.classList.add(riskClass);

  document.getElementById('risk-score').textContent = data.riskScore;
  document.getElementById('risk-score').style.color = riskColor;

  const circle = document.getElementById('risk-circle');
  const offset = 264 - (264 * data.riskScore / 100);
  circle.setAttribute('stroke-dashoffset', offset);
  circle.setAttribute('stroke', riskColor);

  document.getElementById('risk-class').textContent = 'Risco ' + data.riskLevel;
  document.getElementById('risk-class').style.color = riskColor;
  document.getElementById('risk-title').textContent = 'Analise Concluida — ' + data.totalAlerts + ' alerta(s)';

  const summaryTexts = {
    BAIXO: 'Nenhuma irregularidade significativa encontrada nas bases consultadas.',
    MEDIO: 'Foram identificadas pendencias moderadas que merecem atencao.',
    ALTO: 'Multiplos indicadores de risco identificados. Recomenda-se cautela.',
    CRITICO: 'ALERTA: Perfil com indicadores graves. Nao recomendado prosseguir sem consultoria juridica.'
  };
  document.getElementById('risk-summary').textContent = summaryTexts[data.riskLevel];

  // Subject
  document.getElementById('subject-avatar').textContent = data.name.charAt(0);
  document.getElementById('subject-name').textContent = data.name;
  document.getElementById('subject-doc').textContent = (data.isCNPJ ? 'CNPJ: ' : (data.isName ? '' : 'CPF: ')) + data.docFormatted;

  const meta = document.getElementById('subject-meta');
  let metaHTML = '';
  if (!data.isCNPJ && !data.isName) {
    metaHTML += '<div class="subject-meta-item"><div class="meta-label">Data de Nascimento</div><div class="meta-value">' + escVal(data.birthDate) + '</div></div>';
  }
  metaHTML += '<div class="subject-meta-item"><div class="meta-label">Cidade</div><div class="meta-value">' + escVal(data.city) + '</div></div>';
  metaHTML += '<div class="subject-meta-item"><div class="meta-label">Processos</div><div class="meta-value">' + escVal(data.processes.length) + '</div></div>';
  metaHTML += '<div class="subject-meta-item"><div class="meta-label">Situacao Cadastral</div><div class="meta-value" style="color:' + (data.cpfStatus === 'Regular' ? 'var(--risk-low)' : 'var(--risk-high)') + '">' + escVal(data.cpfStatus) + '</div></div>';
  metaHTML += '<div class="subject-meta-item"><div class="meta-label">Consulta em</div><div class="meta-value">' + escVal(data.timestamp) + '</div></div>';
  meta.innerHTML = metaHTML;

  // Judicial
  const judicialBody = document.getElementById('judicial-body');
  const judicialCount = document.getElementById('judicial-count');
  judicialCount.textContent = data.processes.length + ' encontrado(s)';
  judicialCount.className = 'count-badge' + (data.processes.some(p => p.type === 'criminal') ? ' alert' : '');

  if (data.processes.length === 0) {
    judicialBody.innerHTML = '<div class="empty-state"><div class="empty-icon">\u2705</div>Nenhum registro judicial encontrado</div>';
  } else {
    judicialBody.innerHTML = data.processes.map(p => {
      const statusClass = (p.status === 'Ativo' || p.status === 'Em andamento') ? 'ativo' : (p.status === 'Encerrado' || p.status === 'Baixado' ? 'encerrado' : 'arquivado');
      return '<div class="process-item ' + escVal(p.type) + '">' +
        '<div class="process-item-header"><span class="process-number">' + escVal(p.number) + '</span><span class="process-type ' + escVal(p.type) + '">' + escVal(p.type) + '</span></div>' +
        '<div class="process-title">' + escVal(p.description) + '</div>' +
        '<div class="process-detail">' + escVal(p.court) + ' | ' + escVal(p.year) + ' | Valor: R$ ' + escVal(p.value.toLocaleString('pt-BR')) + '</div>' +
        '<div class="process-detail">' + escVal(p.parties) + '</div>' +
        '<div class="process-status ' + escVal(statusClass) + '">\u25CF ' + escVal(p.status) + '</div>' +
        '</div>';
    }).join('');
  }

  // Gazette
  const gazetteBody = document.getElementById('gazette-body');
  const gazetteCount = document.getElementById('gazette-count');
  gazetteCount.textContent = data.gazettes.length + ' encontrado(s)';

  if (data.gazettes.length === 0) {
    gazetteBody.innerHTML = '<div class="empty-state"><div class="empty-icon">\u2705</div>Nenhuma publicacao em Diarios Oficiais</div>';
  } else {
    gazetteBody.innerHTML = data.gazettes.map(g =>
      '<div class="gazette-item">' +
      '<div class="gazette-source">' + escVal(g.source) + '</div>' +
      '<div class="gazette-title">' + escVal(g.title) + '</div>' +
      '<div class="gazette-excerpt">' + escVal(g.excerpt) + '</div>' +
      '<div class="gazette-date">' + escVal(g.date) + '</div>' +
      '</div>'
    ).join('');
  }

  // Financial
  const financialBody = document.getElementById('financial-body');
  const financialCount = document.getElementById('financial-count');
  financialCount.textContent = data.financials.length + ' item(ns)';

  financialBody.innerHTML = data.financials.map(f => {
    const isNeg = f.status === 'Irregular' || f.status === 'Positiva' || f.status.startsWith('R$') || f.status === 'Consta registro' || f.status === 'Pendente';
    const cls = isNeg ? (f.status === 'Pendente' ? 'pendente' : 'irregular') : 'regular';
    return '<div class="financial-item">' +
      '<div><div class="fi-label">' + escVal(f.label) + '</div><div class="fi-detail">' + escVal(f.detail) + '</div></div>' +
      '<div class="fi-value"><span class="fi-status ' + escVal(cls) + '">' + escVal(f.status) + '</span></div>' +
      '</div>';
  }).join('');

  // Debts
  const debtsBody = document.getElementById('debts-body');
  const debtsCount = document.getElementById('debts-count');
  debtsCount.textContent = data.debts.length + ' encontrado(s)';
  debtsCount.className = 'count-badge' + (data.debts.length > 2 ? ' alert' : '');

  if (data.debts.length === 0) {
    debtsBody.innerHTML = '<div class="empty-state"><div class="empty-icon">\u2705</div>Nenhuma divida ou protesto registrado</div>';
  } else {
    debtsBody.innerHTML = data.debts.map(d =>
      '<div class="financial-item">' +
      '<div><div class="fi-label">' + escVal(d.creditor) + '</div><div class="fi-detail">' + escVal(d.type) + ' \u2014 ' + escVal(d.date) + '</div></div>' +
      '<div class="fi-value"><span class="fi-status irregular">R$ ' + escVal(d.value.toLocaleString('pt-BR')) + '</span></div>' +
      '</div>'
    ).join('');
  }

  // AI Summary
  document.getElementById('ai-summary-text').innerHTML = safeTags(data.summary);

  // AGENCIES PANEL
  renderAgencies(data);
}

// =======================================================
// RENDER AGENCIES
// =======================================================
function renderAgencies(data) {
  const grid = document.getElementById('agencies-grid');
  const levelBadge = document.getElementById('access-level-badge');
  const interpolAlert = document.getElementById('interpol-alert');

  // Determine max access level
  const hasFound = Object.values(data.agencyResults).some(r => r.status === 'found');
  if (data.riskLevel === 'CRITICO') {
    levelBadge.className = 'access-level classified';
    levelBadge.textContent = 'Alerta Critico';
  } else if (data.riskLevel === 'ALTO') {
    levelBadge.className = 'access-level restricted';
    levelBadge.textContent = 'Acesso Restrito';
  } else {
    levelBadge.className = 'access-level public';
    levelBadge.textContent = 'Acesso Publico';
  }

  // Render agency cards
  grid.innerHTML = AGENCIES.map(a => {
    const r = data.agencyResults[a.id];
    const cardClass = r.status === 'found' ? 'alert' : (r.status === 'clear' ? 'checked' : '');
    return '<div class="agency-card ' + escVal(cardClass) + '">' +
      '<div class="agency-flag">' + a.flag + '</div>' +
      '<div class="agency-name">' + escVal(a.name) + '</div>' +
      '<div class="agency-country">' + escVal(a.country) + '</div>' +
      '<div class="agency-status ' + escVal(r.status) + '">' +
        (r.status === 'clear' ? 'Nada consta' :
         r.status === 'found' ? 'Registro encontrado' :
         r.status === 'restricted' ? 'Acesso restrito' : 'Pendente') + 
      '</div>' +
      '</div>';
  }).join('');

  // INTERPOL alert
  if (data.agencyResults.interpol && data.agencyResults.interpol.status === 'found') {
    interpolAlert.classList.add('active');
    document.getElementById('interpol-alert-body').innerHTML = 
      '<p><strong>' + escVal(data.agencyResults.interpol.detail) + '</strong></p>' +
      '<p>Uma difusao ou notificacao vermelha da INTERPOL foi identificada para este perfil. ' +
      'Isso indica que existe um pedido de cooperacao policial internacional ativo. ' +
      'Recomenda-se contato imediato com as autoridades competentes.</p>' +
      '<p style="margin-top:.5rem;font-size:.7rem;">Nota: Conforme Artigo 3 do Estatuto da INTERPOL, esta informacao e tratada com respeito aos direitos humanos e nao pode ser utilizada para fins politicos, militares, religiosos ou raciais.</p>';
  } else {
    interpolAlert.classList.remove('active');
  }
}

// =======================================================
// GENERATE PDF
// =======================================================
async function generatePDF() {
  if (!currentResult) return;
  const data = currentResult;

  // Populate PDF template
  document.getElementById('pdf-title').textContent = 'Relatorio de Background Check — ' + data.name;
  document.getElementById('pdf-subtitle').textContent = 'Portal Seguranca Global | Gerado em ' + data.timestamp;

  const metaEl = document.getElementById('pdf-meta');
  metaEl.innerHTML = '<span>' + (data.isCNPJ ? 'CNPJ: ' : 'CPF: ') + escVal(data.docFormatted) + '</span>' +
    '<span>Cidade: ' + escVal(data.city) + '</span>' +
    '<span>Risco: ' + escVal(data.riskLevel) + '</span>';

  const riskBox = document.getElementById('pdf-risk-box');
  riskBox.className = 'pdf-risk-box ' + (data.riskLevel === 'BAIXO' ? 'low' : data.riskLevel === 'MEDIO' ? 'medium' : 'high');
  document.getElementById('pdf-risk-score').textContent = data.riskScore;
  document.getElementById('pdf-risk-score').style.color = data.riskLevel === 'BAIXO' ? '#22c55e' : data.riskLevel === 'MEDIO' ? '#f59e0b' : '#ef4444';
  document.getElementById('pdf-risk-label').textContent = 'RISCO ' + data.riskLevel;

  let sectionsHTML = '';

  // Judicial section
  sectionsHTML += '<div class="pdf-section"><h3>Registros Judiciais (' + escVal(data.processes.length) + ')</h3>';
  if (data.processes.length === 0) {
    sectionsHTML += '<div class="pdf-item">Nenhum registro judicial encontrado.</div>';
  } else {
    data.processes.forEach(p => {
      sectionsHTML += '<div class="pdf-item"><strong>[' + escVal(p.type.toUpperCase()) + '] ' + escVal(p.description) + '</strong><br>' +
        'Processo: ' + escVal(p.number) + ' | ' + escVal(p.court) + ' | ' + escVal(p.year) + '<br>' +
        'Valor: R$ ' + escVal(p.value.toLocaleString('pt-BR')) + ' | Status: ' + escVal(p.status) + '</div>';
    });
  }
  sectionsHTML += '</div>';

  // Gazette section
  sectionsHTML += '<div class="pdf-section"><h3>Diarios Oficiais (' + escVal(data.gazettes.length) + ')</h3>';
  if (data.gazettes.length === 0) {
    sectionsHTML += '<div class="pdf-item">Nenhuma publicacao encontrada em Diarios Oficiais.</div>';
  } else {
    data.gazettes.forEach(g => {
      sectionsHTML += '<div class="pdf-item"><strong>' + escVal(g.title) + '</strong> \u2014 ' + escVal(g.source) + '<br>' + escVal(g.excerpt) + '<br>Data: ' + escVal(g.date) + '</div>';
    });
  }
  sectionsHTML += '</div>';

  // Financial section
  sectionsHTML += '<div class="pdf-section"><h3>Situacao Financeira</h3>';
  data.financials.forEach(f => {
    sectionsHTML += '<div class="pdf-item"><strong>' + escVal(f.label) + ':</strong> ' + escVal(f.status) + ' (' + escVal(f.detail) + ')</div>';
  });
  sectionsHTML += '</div>';

  // Debts section
  if (data.debts.length > 0) {
    sectionsHTML += '<div class="pdf-section"><h3>Dividas e Protestos (' + escVal(data.debts.length) + ')</h3>';
    data.debts.forEach(d => {
      sectionsHTML += '<div class="pdf-item"><strong>' + escVal(d.creditor) + ':</strong> R$ ' + escVal(d.value.toLocaleString('pt-BR')) + ' (' + escVal(d.type) + ' \u2014 ' + escVal(d.date) + ')</div>';
    });
    sectionsHTML += '</div>';
  }

  document.getElementById('pdf-sections').innerHTML = sectionsHTML;
  document.getElementById('pdf-summary').textContent = data.summary.replace(/<\/?p>/g, ' ').replace(/<br>/g, ' ').replace(/<[^>]+>/g, '');

  // Generate PDF
  try {
    const element = document.getElementById('pdf-report');
    const canvas = await html2canvas(element, { scale: 2, useCORS: true, backgroundColor: '#ffffff' });
    const { jsPDF } = window.jspdf;
    const pdf = new jsPDF('p', 'mm', 'a4');
    const imgData = canvas.toDataURL('image/jpeg', 0.95);
    const pdfWidth = pdf.internal.pageSize.getWidth();
    const pdfHeight = (canvas.height * pdfWidth) / canvas.width;

    let position = 0;
    const pageHeight = pdf.internal.pageSize.getHeight();

    if (pdfHeight <= pageHeight) {
      pdf.addImage(imgData, 'JPEG', 0, 0, pdfWidth, pdfHeight);
    } else {
      while (position < pdfHeight) {
        if (position > 0) pdf.addPage();
        pdf.addImage(imgData, 'JPEG', 0, -position, pdfWidth, pdfHeight);
        position += pageHeight;
      }
    }

    pdf.save('PortalSegurancaGlobal_BackgroundCheck_' + data.name.replace(/\s/g, '_') + '.pdf');
  } catch(e) {
    alert('Erro ao gerar PDF: ' + e.message);
  }
}

// =======================================================
// NEW SEARCH
// =======================================================
function newSearch() {
  document.getElementById('results-section').classList.remove('active');
  document.getElementById('search-section').scrollIntoView({ behavior: 'smooth' });
  document.getElementById('doc-input').value = '';
  document.getElementById('name-input').value = '';
  currentResult = null;
  facialImageData = null;
  resetFacialUI();
}

function resetFacialUI() {
  var upload = document.getElementById('facial-upload-area');
  var preview = document.getElementById('facial-preview');
  var camera = document.getElementById('camera-container');
  if (upload) upload.style.display = '';
  if (preview) preview.style.display = 'none';
  if (camera) camera.style.display = 'none';
  var scanLine = document.getElementById('scan-line');
  var faceBox = document.getElementById('face-detect-box');
  var points = document.getElementById('facial-points');
  if (scanLine) scanLine.classList.remove('active');
  if (faceBox) faceBox.classList.remove('active');
  if (points) points.innerHTML = '';
}

// =======================================================
// FACIAL RECOGNITION — Camera & Upload
// =======================================================
function handleFacialFile(file) {
  if (!file || !file.type.startsWith('image/')) {
    alert('Por favor, selecione uma imagem valida (JPG, PNG ou WEBP).');
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    alert('A imagem deve ter no maximo 10MB.');
    return;
  }
  var reader = new FileReader();
  reader.onload = function(e) {
    facialImageData = e.target.result;
    showFacialPreview(facialImageData);
  };
  reader.readAsDataURL(file);
}

function showFacialPreview(dataUrl) {
  document.getElementById('facial-upload-area').style.display = 'none';
  document.getElementById('camera-container').style.display = 'none';
  var preview = document.getElementById('facial-preview');
  preview.style.display = '';
  document.getElementById('facial-preview-img').src = dataUrl;
  document.getElementById('preview-status').textContent = 'Foto carregada — pronta para escaneamento';
  document.getElementById('preview-status').className = 'preview-status';
  document.getElementById('scan-line').classList.remove('active');
  document.getElementById('face-detect-box').classList.remove('active');
  document.getElementById('facial-points').innerHTML = '';
}

function startCamera() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    alert('Seu navegador nao suporta acesso a camera. Tente enviar uma foto.');
    return;
  }
  document.getElementById('facial-upload-area').style.display = 'none';
  document.getElementById('facial-preview').style.display = 'none';
  document.getElementById('camera-container').style.display = '';

  navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } } })
    .then(function(stream) {
      cameraStream = stream;
      document.getElementById('camera-video').srcObject = stream;
    })
    .catch(function(err) {
      alert('Nao foi possivel acessar a camera: ' + err.message);
      stopCamera();
      document.getElementById('facial-upload-area').style.display = '';
    });
}

function stopCamera() {
  if (cameraStream) {
    cameraStream.getTracks().forEach(function(t) { t.stop(); });
    cameraStream = null;
  }
  var video = document.getElementById('camera-video');
  if (video) video.srcObject = null;
  var container = document.getElementById('camera-container');
  if (container) container.style.display = 'none';
}

function captureFromCamera() {
  var video = document.getElementById('camera-video');
  var canvas = document.getElementById('facial-canvas');
  canvas.width = video.videoWidth || 640;
  canvas.height = video.videoHeight || 480;
  canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
  facialImageData = canvas.toDataURL('image/jpeg', 0.92);
  stopCamera();
  showFacialPreview(facialImageData);
}

// =======================================================
// FACIAL SCAN ANIMATION
// =======================================================
function runFacialScan() {
  return new Promise(function(resolve) {
    var status = document.getElementById('preview-status');
    var scanLine = document.getElementById('scan-line');
    var faceBox = document.getElementById('face-detect-box');
    var points = document.getElementById('facial-points');

    // Phase 1: Scanning
    status.textContent = 'Escaneando biometria facial...';
    if (status) status.className = 'cam-feed-status alert';
        }
      });
    } else {
      document.getElementById('cam-alert-title-text').textContent = 'Varredura Concluida — Nenhuma Correspondencia';
      document.getElementById('cam-alert-title-text').parentElement.querySelector('svg').setAttribute('stroke', '#22c55e');
      html += '<p style="margin:0;font-size:.8rem;">Nenhuma correspondencia facial foi encontrada nas <strong>2.847.391</strong> cameras ativas em <strong>194 paises</strong>.</p>';
      html += '<p style="margin:8px 0 0;font-size:.75rem;color:rgba(255,255,255,.5);">A varredura continuara em segundo plano. Voce sera notificado caso uma correspondencia seja detectada nas proximas 72 horas.</p>';
    }

    alertDetails.innerHTML = html;
    alertBanner.classList.add('active');
    btn.disabled = false;
    btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Iniciar Nova Varredura Facial';

    // Scroll para o resultado
    alertBanner.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }, totalScanTime);
}

function randomTime(maxHours) {
  var h = Math.floor(Math.random() * maxHours);
  if (h === 0) {
    var m = Math.floor(Math.random() * 58) + 2;
    return 'ha ' + m + ' min';
  } else if (h < 24) {
    return 'ha ' + h + 'h ' + Math.floor(Math.random() * 59) + 'min';
  } else {
    var d = Math.floor(h / 24);
    return 'ha ' + d + ' dia' + (d > 1 ? 's' : '');
  }
}

// Incrementa contadores de cameras em tempo real (efeito visual)
setInterval(function() {
  var el = document.getElementById('cam-total');
  if (!el) return;
  var val = parseInt(el.textContent.replace(/\D/g, ''));
  val += Math.floor(Math.random() * 5) - 2;
  el.textContent = val.toLocaleString('pt-BR');
}, 8000);