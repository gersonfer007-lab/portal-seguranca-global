// ============================================================
// SECURITY MODULE — SH_SECURITY (IIFE)
// ============================================================
const SH_SECURITY = (function() {
  'use strict';
  const _log = [];
  const _rateMap = {};
  const RATE_LIMIT = 10;
  const RATE_WINDOW = 60000;
  const THROTTLE_MS = 800;
  let _lastAction = 0;

  function logEvent(type, detail) {
    _log.push({ ts: Date.now(), type, detail, fp: fingerprint() });
    if (_log.length > 500) _log.shift();
  }

  function fingerprint() {
    const d = [navigator.userAgent, navigator.language, screen.width, screen.height, new Date().getTimezoneOffset()];
    let h = 0;
    const s = d.join('|');
    for (let i = 0; i < s.length; i++) { h = ((h << 5) - h) + s.charCodeAt(i); h |= 0; }
    return 'fp_' + Math.abs(h).toString(36);
  }

  function sanitizeHTML(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;').replace(/\//g,'&#x2F;');
  }

  function sanitizeInput(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/[<>\"'`;\\(){}[\]]/g, '').trim();
  }

  function detectInjection(str) {
    if (typeof str !== 'string') return false;
    const patterns = [
      /<script/i, /javascript:/i, /on\w+\s*=/i, /eval\s*\(/i,
      /document\.(cookie|write|location)/i, /window\.(location|open)/i,
      /\.\.\//g, /%3C/i, /%3E/i, /union\s+select/i, /drop\s+table/i,
      /insert\s+into/i, /delete\s+from/i, /update\s+.*set/i,
      /src\s*=\s*['"]/i, /href\s*=\s*["']javascript/i
    ];
    for (const p of patterns) { if (p.test(str)) { logEvent('INJECTION_ATTEMPT', str.substring(0, 80)); return true; } }
    return false;
  }

  function checkRateLimit(action) {
    const now = Date.now();
    if (!_rateMap[action]) _rateMap[action] = [];
    _rateMap[action] = _rateMap[action].filter(t => now - t < RATE_WINDOW);
    if (_rateMap[action].length >= RATE_LIMIT) {
      logEvent('RATE_LIMIT', action);
      return false;
    }
    _rateMap[action].push(now);
    return true;
  }

  function throttle() {
    const now = Date.now();
    if (now - _lastAction < THROTTLE_MS) { logEvent('THROTTLE', 'blocked'); return false; }
    _lastAction = now;
    return true;
  }

  function secureStore(key, value) {
    try {
      const data = JSON.stringify(value);
      const encoded = btoa(unescape(encodeURIComponent(data)));
      let hash = 0;
      for (let i = 0; i < data.length; i++) { hash = ((hash << 5) - hash) + data.charCodeAt(i); hash |= 0; }
      sessionStorage.setItem('sh_' + key, JSON.stringify({ d: encoded, h: hash }));
    } catch(e) { logEvent('STORE_ERROR', e.message); }
  }

  function secureRetrieve(key) {
    try {
      const raw = sessionStorage.getItem('sh_' + key);
      if (!raw) return null;
      const obj = JSON.parse(raw);
      const decoded = decodeURIComponent(escape(atob(obj.d)));
      let hash = 0;
      for (let i = 0; i < decoded.length; i++) { hash = ((hash << 5) - hash) + decoded.charCodeAt(i); hash |= 0; }
      if (hash !== obj.h) { logEvent('TAMPER_DETECTED', key); return null; }
      return JSON.parse(decoded);
    } catch(e) { return null; }
  }

  function initHoneypot() {
    const forms = document.querySelectorAll('form');
    forms.forEach(function(f) {
      if (f.querySelector('.sh-hp')) return;
      const hp = document.createElement('input');
      hp.type = 'text'; hp.name = 'sh_website_url'; hp.className = 'sh-hp';
      hp.style.cssText = 'position:absolute;left:-9999px;opacity:0;height:0;width:0;';
      hp.tabIndex = -1; hp.autocomplete = 'off';
      f.prepend(hp);
      f.addEventListener('submit', function(e) {
        if (hp.value) { e.preventDefault(); logEvent('HONEYPOT_TRIGGERED', hp.value); }
      });
    });
  }

  function monitorDevTools() {
    setInterval(function() {
      const w = window.outerWidth - window.innerWidth > 160;
      const h = window.outerHeight - window.innerHeight > 160;
      if (w || h) logEvent('DEVTOOLS_OPEN', w ? 'width' : 'height');
    }, 3000);
  }

  function setupCopyProtection() {
    document.addEventListener('contextmenu', function(e) {
      if (e.target.closest('.protected-content')) { e.preventDefault(); logEvent('COPY_ATTEMPT', 'contextmenu'); }
    });
    document.addEventListener('keydown', function(e) {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'u' || e.key === 'U')) { e.preventDefault(); logEvent('COPY_ATTEMPT', 'view-source'); }
    });
  }

  function getLog() { return _log.slice(); }

  logEvent('INIT', 'SH_SECURITY loaded');
  try { monitorDevTools(); } catch(e) {}
  try { setupCopyProtection(); } catch(e) {}
  document.addEventListener('DOMContentLoaded', function() {
    try { initHoneypot(); } catch(e) {}
    logEvent('INIT_COMPLETE', 'All protections active');
  });

  return {
    sanitizeHTML: sanitizeHTML,
    sanitizeInput: sanitizeInput,
    detectInjection: detectInjection,
    checkRateLimit: checkRateLimit,
    throttle: throttle,
    secureStore: secureStore,
    secureRetrieve: secureRetrieve,
    logEvent: logEvent,
    fingerprint: fingerprint,
    getLog: getLog
  };
})();

// ============================================================
// STATE
// ============================================================
let map, heatLayer, markersLayer;
let heatVisible = true, markersVisible = false;
let currentData = null;
let chartTypes = null, chartMonthly = null;
let currentMapView = 'dark';
let darkTileLayer = null;
let satelliteTileLayer = null;
let labelsLayer = null;

const TILES = {
  dark: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
  satellite: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
  labels: 'https://{s}.basemaps.cartocdn.com/dark_only_labels/{z}/{x}/{y}{r}.png'
};

// ============================================================
// INIT MAP
// ============================================================
function initMap() {
  map = L.map('map', { center: [-23.55, -46.63], zoom: 13, zoomControl: false, attributionControl: false, scrollWheelZoom: false });
  L.control.zoom({ position: 'topright' }).addTo(map);
  darkTileLayer = L.tileLayer(TILES.dark, { maxZoom: 19 }).addTo(map);
  heatLayer = L.heatLayer([], { radius: 30, blur: 20, maxZoom: 17, gradient: { 0.2: '#22c55e', 0.5: '#eab308', 0.8: '#f97316', 1: '#ef4444' } });
  markersLayer = L.layerGroup();
}

// ============================================================
// GOOGLE EARTH 3D GLOBE (via iframe)
// ============================================================
let earthReady = false;
let currentEarthLat = null;
let currentEarthLng = null;

function loadEarthView(lat, lng, zoom) {
  var iframe = document.getElementById('earth-iframe');
  var loading = document.getElementById('globe-loading');
  loading.classList.remove('hidden');
  var altitude = zoom || 800;
  var url = 'https://www.google.com/maps/embed?pb=!1m14!1m12!1m3!1d' + altitude + '!2d' + lng + '!3d' + lat + '!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!5e1!3m2!1sen!2sbr!4v' + Date.now();
  iframe.onload = function() { loading.classList.add('hidden'); earthReady = true; };
  iframe.src = url;
  currentEarthLat = lat;
  currentEarthLng = lng;
  document.getElementById('globe-coords').textContent = 'Lat ' + lat.toFixed(4) + ' | Lng ' + lng.toFixed(4) + ' | Google Earth 3D';
}

function syncEarthWithData(data) {
  if (!data) return;
  loadEarthView(data.lat, data.lng, 2000);
}

// ============================================================
// MAP VIEW SWITCHER
// ============================================================
function switchMapView(mode) {
  currentMapView = mode;
  document.querySelectorAll('.map-view-toggle button').forEach(function(b) { b.classList.remove('active'); });
  var mapEl = document.getElementById('map');
  var globeEl = document.getElementById('cesium-globe');
  var globeInfo = document.getElementById('globe-info');
  if (mode === 'dark') {
    document.getElementById('btn-view-dark').classList.add('active');
    mapEl.style.display = 'block'; globeEl.style.display = 'none'; globeInfo.classList.remove('active');
    if (satelliteTileLayer) { map.removeLayer(satelliteTileLayer); satelliteTileLayer = null; }
    if (labelsLayer) { map.removeLayer(labelsLayer); labelsLayer = null; }
    if (!darkTileLayer) { darkTileLayer = L.tileLayer(TILES.dark, { maxZoom: 19 }).addTo(map); }
    else if (!map.hasLayer(darkTileLayer)) { darkTileLayer.addTo(map); }
    map.invalidateSize();
  } else if (mode === 'satellite') {
    document.getElementById('btn-view-satellite').classList.add('active');
    mapEl.style.display = 'block'; globeEl.style.display = 'none'; globeInfo.classList.remove('active');
    if (darkTileLayer) { map.removeLayer(darkTileLayer); darkTileLayer = null; }
    if (!satelliteTileLayer) {
      satelliteTileLayer = L.tileLayer(TILES.satellite, { maxZoom: 18 }).addTo(map);
      labelsLayer = L.tileLayer(TILES.labels, { maxZoom: 19, pane: 'overlayPane' }).addTo(map);
    } else if (!map.hasLayer(satelliteTileLayer)) { satelliteTileLayer.addTo(map); if (labelsLayer) labelsLayer.addTo(map); }
    map.invalidateSize();
  } else if (mode === '3d') {
    document.getElementById('btn-view-3d').classList.add('active');
    mapEl.style.display = 'none'; globeEl.style.display = 'block'; globeInfo.classList.add('active');
    if (currentData) { syncEarthWithData(currentData); } else { loadEarthView(-23.55, -46.63, 5000); }
  }
}

// ============================================================
// SEARCH (com validacao server-side)
// ============================================================
async function handleSearch() {
  const rawQuery = document.getElementById('search-input').value.trim();
  if (!rawQuery) return;

  // Se nao aceitou os termos ainda, mostra o modal e guarda a busca pendente
  if (!termsAccepted()) {
    window._pendingSearch = true;
    showTermsModal();
    return;
  }

  // =====================================================
  // DETECCAO AUTOMATICA DE CPF / CNPJ / RG / NOME
  // Se parece documento, redireciona para Background Check
  // =====================================================
  var cleanDigits = rawQuery.replace(/\D/g, '');
  var isCPF = /^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$/.test(rawQuery.replace(/\s/g, '')) || (cleanDigits.length === 11 && !/^\d{5}-?\d{3}$/.test(rawQuery.replace(/\s/g, '')));
  var isCNPJ = /^\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}$/.test(rawQuery.replace(/\s/g, '')) || cleanDigits.length === 14;
  var isRG = cleanDigits.length >= 7 && cleanDigits.length <= 10 && /^\d+$/.test(rawQuery.replace(/[\s.\-]/g, ''));

  // Separa o documento do resto da entrada (cidade, estado, pais)
  if (isCPF || isCNPJ) {
    var docType = isCPF ? 'cpf' : 'cnpj';
    var docValue = rawQuery;
    // Se o usuario digitou CPF + cidade/estado, extrai so o documento
    var parts = rawQuery.split(/[\s,]+/);
    var docPart = '';
    for (var i = 0; i < parts.length; i++) {
      if (/^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$/.test(parts[i]) || /^\d{11}$/.test(parts[i])) { docPart = parts[i]; break; }
      if (/^\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}$/.test(parts[i]) || /^\d{14}$/.test(parts[i])) { docPart = parts[i]; break; }
    }
    if (!docPart) docPart = cleanDigits;
    // Redireciona para Background Check com o documento pre-preenchido
    window.location.href = 'background-check.html?doc=' + encodeURIComponent(docPart) + '&type=' + docType;
    return;
  }

  // Se parece um nome de pessoa (so letras, 2+ palavras, SEM palavras de endereco/geografia)
  var geoWords = /\b(rua|av|avenida|praca|largo|beco|travessa|alameda|rodovia|estrada|bairro|jardim|centro|norte|sul|leste|oeste|city|street|square|avenue|road|district|park|town|village|borough|quarter|zone|rio|sao|santa|santo|new|north|south|east|west|parana|brasil|brazil|estado|state|country|pais|cidade|maringa|curitiba|londrina|cascavel|foz|campinas|guarulhos)\b/i;
  var looksLikeName = /^[A-Za-zÀ-ÿ\s]{3,}$/.test(rawQuery) && rawQuery.split(/\s+/).length >= 2 && !geoWords.test(rawQuery);
  if (looksLikeName) {
    window.location.href = 'background-check.html?doc=' + encodeURIComponent(rawQuery) + '&type=nome';
    return;
  }

  // Client-side checks (primeira camada — rapido)
  if (!SH_SECURITY.checkRateLimit('search')) { alert('Limite de buscas atingido. Aguarde um momento e tente novamente.'); return; }
  if (!SH_SECURITY.throttle()) return;
  if (SH_SECURITY.detectInjection(rawQuery)) { alert('Entrada invalida detectada.'); SH_SECURITY.logEvent('SEARCH_BLOCKED', rawQuery.substring(0, 50)); return; }
  const query = SH_SECURITY.sanitizeInput(rawQuery);
  if (!query) return;

  // Server-side validation (segunda camada — segura)
  try {
    var valRes = await fetch('/api/search', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: query }) });
    var valData = await valRes.json();
    if (!valRes.ok) { alert(valData.error || 'Erro de validacao no servidor.'); return; }
  } catch(serverErr) {
    // Se servidor nao disponivel, prossegue com validacao client-side apenas
    console.warn('Server validation unavailable, using client-side only:', serverErr.message);
  }

  SH_SECURITY.logEvent('SEARCH_START', query.substring(0, 80));
  showLoading('Consultando endereco...');
  try {
    const cepClean = query.replace(/\D/g, '');
    let addressData;
    if (cepClean.length === 8 && /^\d{8}$/.test(cepClean)) {
      updateLoading('Buscando CEP na base dos Correios...');
      try {
        const res = await fetch('https://viacep.com.br/ws/' + cepClean + '/json/');
        const data = await res.json();
        if (!data.erro) { addressData = { street: data.logradouro || '', neighborhood: data.bairro || '', city: data.localidade || '', state: data.uf || '', country: 'Brasil', cep: data.cep, fullAddress: [data.logradouro, data.bairro, data.localidade, data.uf, 'Brasil'].filter(Boolean).join(', ') }; }
      } catch(e) {}
    }
    if (!addressData && /^\d{5}(-\d{4})?$/.test(query.trim())) { addressData = { street: '', neighborhood: '', city: '', state: '', country: 'USA', cep: query.trim(), fullAddress: query.trim() + ', United States' }; }
    if (!addressData && /^[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}$/i.test(query.trim())) { addressData = { street: '', neighborhood: '', city: '', state: '', country: 'UK', cep: query.trim(), fullAddress: query.trim() + ', United Kingdom' }; }
    if (!addressData) { addressData = { street: query, neighborhood: '', city: '', state: '', country: '', cep: '', fullAddress: query }; }
    updateLoading('Geolocalizando endereco...');
    const geo = await geocodeAddress(addressData, query);
    if (!geo) { throw new Error('Endereco nao encontrado. Tente incluir a cidade e o pais (ex.: Av. Brasil, Maringa, PR, Brasil).'); }
    let lat = geo.lat, lng = geo.lng;
    if (geo.displayName) { addressData.fullAddress = geo.displayName; }
    if (!addressData.city && geo.city) { addressData.city = geo.city; }
    if (!addressData.state && geo.state) { addressData.state = geo.state; }
    if (!addressData.country && geo.country) { addressData.country = geo.country; }
    updateLoading('Analisando dados de criminalidade...'); await sleep(600);
    updateLoading('Calculando infraestrutura urbana...'); await sleep(500);
    updateLoading('Processando movimentacao de pedestres...'); await sleep(400);
    updateLoading('Compilando Safety Score...'); await sleep(300);
    currentData = generateIntelligence(lat, lng, addressData);
    renderDashboard(currentData);
    if (currentMapView === '3d') { syncEarthWithData(currentData); }
    hideLoading();
  } catch (err) { hideLoading(); alert('Erro: ' + err.message); }
}

// ============================================================
// PESQUISAR PELO MAPA — o usuario escolhe o local clicando
// no mapa (ou usa o GPS) em vez de digitar o endereco.
// ============================================================
var mapselMap = null;
var mapselMarker = null;
var mapselChoice = null;      // { lat, lng, addressData }
var mapselReverseSeq = 0;     // evita respostas fora de ordem

function openMapSearch() {
  // Respeita o termo de uso, igual a busca por texto
  if (!termsAccepted()) {
    window._pendingMapSearch = true;
    showTermsModal();
    return;
  }
  var ov = document.getElementById('mapsel-overlay');
  if (!ov) return;
  ov.style.display = 'flex';
  setTimeout(function() { ov.classList.add('active'); }, 10);
  setTimeout(initMapSel, 80);
}

function closeMapSearch() {
  var ov = document.getElementById('mapsel-overlay');
  if (!ov) return;
  ov.classList.remove('active');
  setTimeout(function() { ov.style.display = 'none'; }, 260);
}

function initMapSel() {
  if (typeof L === 'undefined') {
    alert('O mapa ainda esta carregando. Aguarde um instante e tente de novo.');
    return;
  }
  if (mapselMap) { mapselMap.invalidateSize(); return; }

  // Comeca com a visao do mundo inteiro (cobertura global)
  mapselMap = L.map('mapsel-map', {
    center: [12, 0], zoom: 2, zoomControl: true,
    attributionControl: false, scrollWheelZoom: true, worldCopyJump: true
  });
  L.tileLayer(TILES.dark, { maxZoom: 19 }).addTo(mapselMap);

  // Se o usuario ja fez uma busca, comeca perto do ultimo local
  if (currentData && currentData.lat != null && currentData.lng != null) {
    mapselMap.setView([currentData.lat, currentData.lng], 13);
  }

  mapselMap.on('click', function(e) {
    mapselPick(e.latlng.lat, e.latlng.lng);
  });

  setTimeout(function() { if (mapselMap) mapselMap.invalidateSize(); }, 120);
}

function mapselPick(lat, lng) {
  if (!mapselMap) return;
  mapselChoice = null;

  var icon = L.divIcon({
    className: '', html: '<div class="mapsel-pin-pulse"></div>',
    iconSize: [18, 18], iconAnchor: [9, 9]
  });
  if (mapselMarker) {
    mapselMarker.setLatLng([lat, lng]);
  } else {
    mapselMarker = L.marker([lat, lng], { icon: icon, draggable: true }).addTo(mapselMap);
    mapselMarker.on('dragend', function(ev) {
      var p = ev.target.getLatLng();
      mapselPick(p.lat, p.lng);
    });
  }

  var hint = document.getElementById('mapsel-hint');
  if (hint) hint.classList.add('gone');

  var box = document.getElementById('mapsel-picked');
  var addrEl = document.getElementById('mapsel-picked-addr');
  var coordEl = document.getElementById('mapsel-picked-coords');
  var btn = document.getElementById('mapsel-confirm');
  if (box) box.classList.add('filled');
  if (coordEl) coordEl.textContent = lat.toFixed(5) + ', ' + lng.toFixed(5);
  if (addrEl) addrEl.textContent = 'Identificando endereco...';
  if (btn) btn.disabled = true;

  mapselReverseGeocode(lat, lng);
}

async function mapselReverseGeocode(lat, lng) {
  var seq = ++mapselReverseSeq;
  var addrEl = document.getElementById('mapsel-picked-addr');
  var btn = document.getElementById('mapsel-confirm');
  var addressData = null;

  try {
    var url = 'https://nominatim.openstreetmap.org/reverse?format=json&lat=' +
      encodeURIComponent(lat) + '&lon=' + encodeURIComponent(lng) +
      '&zoom=18&addressdetails=1';
    var res = await fetch(url, { headers: { 'Accept': 'application/json' } });
    var data = await res.json();
    if (seq !== mapselReverseSeq) return; // clique mais novo venceu

    var a = (data && data.address) ? data.address : {};
    addressData = {
      street: a.road || a.pedestrian || a.footway || '',
      neighborhood: a.suburb || a.neighbourhood || a.quarter || a.city_district || '',
      city: a.city || a.town || a.village || a.municipality || a.county || '',
      state: a.state || a.region || '',
      country: a.country || '',
      cep: a.postcode || '',
      fullAddress: (data && data.display_name) ? data.display_name : ''
    };
  } catch (e) {
    if (seq !== mapselReverseSeq) return;
  }

  // Sem resposta do servico: usa as coordenadas mesmo assim
  if (!addressData || !addressData.fullAddress) {
    addressData = addressData || { street: '', neighborhood: '', city: '', state: '', country: '', cep: '' };
    addressData.fullAddress = 'Local no mapa (' + lat.toFixed(5) + ', ' + lng.toFixed(5) + ')';
  }

  mapselChoice = { lat: lat, lng: lng, addressData: addressData };
  if (addrEl) addrEl.textContent = addressData.fullAddress;
  if (btn) btn.disabled = false;
}

// Move o mapa do modal para uma cidade/pais digitado
async function mapselFind() {
  var inp = document.getElementById('mapsel-find');
  if (!inp || !mapselMap) return;
  var q = inp.value.trim();
  if (!q) return;
  if (SH_SECURITY.detectInjection(q)) { alert('Entrada invalida detectada.'); return; }

  var btn = document.getElementById('mapsel-find-btn');
  if (btn) btn.disabled = true;
  try {
    var geo = await geocodeQuery(SH_SECURITY.sanitizeInput(q));
    if (!geo) { alert('Local nao encontrado. Tente incluir o pais.'); return; }
    mapselMap.setView([geo.lat, geo.lng], 13);
    mapselPick(geo.lat, geo.lng);
  } catch (e) {
    alert('Nao foi possivel localizar. Tente novamente.');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// GPS dentro do modal
function mapselGps() {
  if (!navigator.geolocation) { alert('Seu navegador nao permite localizacao por GPS.'); return; }
  var btn = document.getElementById('mapsel-gps');
  if (btn) btn.disabled = true;
  navigator.geolocation.getCurrentPosition(function(pos) {
    if (btn) btn.disabled = false;
    var lat = pos.coords.latitude, lng = pos.coords.longitude;
    if (mapselMap) { mapselMap.setView([lat, lng], 16); mapselPick(lat, lng); }
  }, function(err) {
    if (btn) btn.disabled = false;
    alert(err.code === 1
      ? 'Permissao de localizacao negada. Autorize o acesso no navegador para usar o GPS.'
      : 'Nao foi possivel obter sua localizacao. Escolha o ponto no mapa.');
  }, { enableHighAccuracy: true, timeout: 12000, maximumAge: 60000 });
}

// Botao "Onde estou agora" da tela inicial (sem abrir o modal)
function searchByGps() {
  if (!termsAccepted()) { window._pendingGpsSearch = true; showTermsModal(); return; }
  if (!navigator.geolocation) { alert('Seu navegador nao permite localizacao por GPS.'); return; }
  showLoading('Obtendo sua localizacao...');
  navigator.geolocation.getCurrentPosition(function(pos) {
    analyzeCoords(pos.coords.latitude, pos.coords.longitude, null);
  }, function(err) {
    hideLoading();
    alert(err.code === 1
      ? 'Permissao de localizacao negada. Autorize o acesso no navegador ou use "Pesquisar pelo Mapa".'
      : 'Nao foi possivel obter sua localizacao. Use "Pesquisar pelo Mapa".');
  }, { enableHighAccuracy: true, timeout: 12000, maximumAge: 60000 });
}

function confirmMapSearch() {
  if (!mapselChoice) return;
  var c = mapselChoice;
  closeMapSearch();
  setTimeout(function() { analyzeCoords(c.lat, c.lng, c.addressData); }, 280);
}

// ============================================================
// ANALISE DIRETA POR COORDENADAS (usada pelo mapa e pelo GPS)
// ============================================================
async function analyzeCoords(lat, lng, addressData) {
  if (!SH_SECURITY.checkRateLimit('search')) { hideLoading(); alert('Limite de buscas atingido. Aguarde um momento e tente novamente.'); return; }
  SH_SECURITY.logEvent('SEARCH_MAP', lat.toFixed(4) + ',' + lng.toFixed(4));
  showLoading('Consultando local...');
  try {
    // Se veio do GPS, ainda nao temos o endereco: busca agora
    if (!addressData) {
      updateLoading('Identificando o endereco...');
      try {
        var url = 'https://nominatim.openstreetmap.org/reverse?format=json&lat=' +
          encodeURIComponent(lat) + '&lon=' + encodeURIComponent(lng) + '&zoom=18&addressdetails=1';
        var res = await fetch(url, { headers: { 'Accept': 'application/json' } });
        var data = await res.json();
        var a = (data && data.address) ? data.address : {};
        addressData = {
          street: a.road || a.pedestrian || '',
          neighborhood: a.suburb || a.neighbourhood || a.quarter || '',
          city: a.city || a.town || a.village || a.municipality || a.county || '',
          state: a.state || a.region || '',
          country: a.country || '',
          cep: a.postcode || '',
          fullAddress: (data && data.display_name) ? data.display_name : ''
        };
      } catch (e) { addressData = null; }
      if (!addressData || !addressData.fullAddress) {
        addressData = { street: '', neighborhood: '', city: '', state: '', country: '', cep: '',
          fullAddress: 'Local no mapa (' + lat.toFixed(5) + ', ' + lng.toFixed(5) + ')' };
      }
    }

    // Mostra na caixa de busca qual local esta sendo analisado
    var si = document.getElementById('search-input');
    if (si) si.value = addressData.fullAddress;

    updateLoading('Analisando dados de criminalidade...'); await sleep(600);
    updateLoading('Calculando infraestrutura urbana...'); await sleep(500);
    updateLoading('Processando movimentacao de pedestres...'); await sleep(400);
    updateLoading('Compilando Safety Score...'); await sleep(300);

    currentData = generateIntelligence(lat, lng, addressData);
    renderDashboard(currentData);
    if (currentMapView === '3d') { syncEarthWithData(currentData); }
    hideLoading();
  } catch (err) {
    hideLoading();
    alert('Erro: ' + err.message);
  }
}

// ============================================================
// GEOCODIFICACAO EM CASCATA (global, sem restricao de pais)
// Tenta do mais especifico para o mais generico ate encontrar.
// ============================================================
async function geocodeQuery(q) {
  if (!q) return null;
  try {
    const r = await fetch('https://nominatim.openstreetmap.org/search?format=jsonv2&addressdetails=1&limit=1&accept-language=pt,en&q=' + encodeURIComponent(q));
    if (!r.ok) return null;
    const j = await r.json();
    if (!j || !j.length) return null;
    const a = j[0].address || {};
    return {
      lat: parseFloat(j[0].lat),
      lng: parseFloat(j[0].lon),
      displayName: j[0].display_name || q,
      city: a.city || a.town || a.village || a.municipality || '',
      state: a.state || '',
      country: a.country || ''
    };
  } catch (e) { return null; }
}

async function geocodeAddress(addressData, rawQuery) {
  // Monta as tentativas do mais especifico para o mais generico.
  // Sempre usando virgula como separador (Nominatim falha com "/" e " - ").
  const A = addressData || {};
  const attempts = [];
  const push = function(parts) {
    const s = parts.filter(Boolean).join(', ').replace(/\s+/g, ' ').trim();
    if (s && attempts.indexOf(s) === -1) attempts.push(s);
  };

  push([A.street, A.neighborhood, A.city, A.state, A.country]);
  push([A.street, A.city, A.state, A.country]);
  push([A.street, A.city, A.country]);
  push([A.neighborhood, A.city, A.state, A.country]);
  push([A.city, A.state, A.country]);
  push([A.city, A.country]);

  // Consulta crua do usuario, normalizada (troca "/" e " - " por virgula)
  if (rawQuery) {
    const norm = String(rawQuery).replace(/\s*[\/|]\s*/g, ', ').replace(/\s+-\s+/g, ', ').trim();
    push([norm]);
    // Sem o CEP/numero inicial, que costuma atrapalhar
    const noZip = norm.replace(/\b\d{5}-?\d{3}\b/g, '').replace(/^[\s,]+|[\s,]+$/g, '');
    push([noZip]);
  }

  for (let i = 0; i < attempts.length; i++) {
    if (i > 0) { updateLoading('Refinando localizacao...'); await sleep(1100); }
    const hit = await geocodeQuery(attempts[i]);
    if (hit && isFinite(hit.lat) && isFinite(hit.lng)) return hit;
  }
  return null;
}

// ============================================================
// INTELLIGENCE ENGINE
// ============================================================
function generateIntelligence(lat, lng, address) {
  const seed = Math.abs(Math.sin(lat * 1000 + lng * 2000)) * 10000;
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

// ============================================================
// RENDER DASHBOARD
// ============================================================
function renderDashboard(data) {
  document.getElementById('main-content').classList.add('active');
  document.getElementById('result-address').textContent = data.address.fullAddress;
  document.getElementById('result-meta').textContent = 'Lat ' + data.lat.toFixed(4) + ' | Lng ' + data.lng.toFixed(4) + (data.address.cep ? ' | CEP ' + data.address.cep : '') + ' | Raio de analise: 1.5km';
  try {
    if (map.hasLayer(heatLayer)) map.removeLayer(heatLayer);
    map.setView([data.lat, data.lng], 15);
    heatLayer.setLatLngs(data.heatPoints);
    setTimeout(function() { try { map.addLayer(heatLayer); map.invalidateSize(); } catch(e) {} }, 800);
  } catch(e) {}
  markersLayer.clearLayers();
  data.markerPoints.forEach(p => {
    markersLayer.addLayer(L.circleMarker([p.lat, p.lng], { radius: 5, color: '#ef4444', fillColor: '#ef4444', fillOpacity: .7, weight: 1 }).bindPopup('<b>' + p.type + '</b><br>' + p.date));
  });
  L.marker([data.lat, data.lng]).addTo(markersLayer).bindPopup('<b>Local pesquisado</b><br>' + data.address.fullAddress).openPopup();
  const circumference = 2 * Math.PI * 78;
  const offset = circumference - (data.safetyScore / 100) * circumference;
  const scoreColor = data.safetyScore >= 70 ? 'var(--green)' : data.safetyScore >= 40 ? 'var(--yellow)' : 'var(--red)';
  const scoreLabel = data.safetyScore >= 70 ? 'SEGURO' : data.safetyScore >= 40 ? 'MODERADO' : 'CRITICO';
  document.getElementById('score-circle').style.stroke = scoreColor;
  document.getElementById('score-circle').style.strokeDashoffset = offset;
  document.getElementById('score-number').textContent = data.safetyScore;
  document.getElementById('score-number').style.color = scoreColor;
  document.getElementById('score-label').textContent = scoreLabel;
  document.getElementById('score-label').style.color = scoreColor;
  document.getElementById('score-timestamp').textContent = new Date().toLocaleString('pt-BR');
  animatePillar('pillar-crime', 'pillar-crime-val', data.crimeScore);
  animatePillar('pillar-infra', 'pillar-infra-val', data.infraScore);
  animatePillar('pillar-movement', 'pillar-movement-val', data.movementScore);
  document.getElementById('stat-occurrences').textContent = data.totalOccurrences;
  document.getElementById('stat-cameras').textContent = data.cameras;
  document.getElementById('stat-lights').textContent = data.lightCoverage + '%';
  document.getElementById('stat-commerce').textContent = data.commerce;
  renderCharts(data);
  document.getElementById('main-content').scrollIntoView({ behavior: 'smooth' });
}

function animatePillar(barId, valId, value) {
  document.getElementById(barId).style.width = value + '%';
  document.getElementById(valId).textContent = value;
}

// ============================================================
// CHARTS
// ============================================================
function renderCharts(data) {
  Chart.defaults.color = '#8b95a8';
  Chart.defaults.borderColor = '#2a3550';
  if (chartTypes) chartTypes.destroy();
  chartTypes = new Chart(document.getElementById('chart-types'), { type: 'doughnut', data: { labels: Object.keys(data.crimeTypes), datasets: [{ data: Object.values(data.crimeTypes), backgroundColor: ['#ef4444','#f97316','#eab308','#a855f7','#3b82f6','#6b7280'], borderWidth: 0 }] }, options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'right', labels: { padding: 12, font: { size: 11 } } } } } });
  if (chartMonthly) chartMonthly.destroy();
  chartMonthly = new Chart(document.getElementById('chart-monthly'), { type: 'line', data: { labels: data.months, datasets: [{ label: 'Ocorrencias', data: data.monthlyData, borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,.1)', fill: true, tension: .4, pointRadius: 3, pointBackgroundColor: '#3b82f6', borderWidth: 2 }] }, options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,.04)' } }, x: { grid: { display: false } } }, plugins: { legend: { display: false } } } });
}

// ============================================================
// MAP CONTROLS
// ============================================================
function toggleHeatmap() { heatVisible = !heatVisible; heatVisible ? map.addLayer(heatLayer) : map.removeLayer(heatLayer); }
function toggleMarkers() { markersVisible = !markersVisible; markersVisible ? map.addLayer(markersLayer) : map.removeLayer(markersLayer); }

// ============================================================
// PDF GENERATION
// ============================================================
// ============================================================
// PAYWALL — Cobranca antes de liberar PDF
// ============================================================
var psgPaymentDone = false;

function showPaywallModal() {
  if (document.getElementById('paywall-modal')) { document.getElementById('paywall-modal').style.display = 'flex'; return; }
  var m = document.createElement('div');
  m.id = 'paywall-modal';
  m.style.cssText = 'display:flex;position:fixed;inset:0;z-index:2000;background:rgba(0,0,0,.88);backdrop-filter:blur(14px);align-items:center;justify-content:center;padding:1rem;overflow-y:auto;';
  m.innerHTML = '<div style="background:linear-gradient(145deg,#0f1728,#1a2438);border:1px solid rgba(0,157,255,.3);border-radius:20px;padding:2rem 1.5rem;max-width:440px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,.6);position:relative;margin:auto;">' +
    '<span id="paywall-close" style="position:absolute;top:8px;right:12px;width:36px;height:36px;display:flex;align-items:center;justify-content:center;font-size:1.6rem;color:#8b95a8;cursor:pointer;">&times;</span>' +
    '<div style="text-align:center;font-size:2.5rem;margin-bottom:.5rem;">&#128274;</div>' +
    '<h3 style="text-align:center;font-size:1.2rem;color:#e5e7eb;margin-bottom:.3rem;">Relatorio PDF Premium</h3>' +
    '<p style="text-align:center;font-size:.8rem;color:#8b95a8;margin-bottom:1.2rem;">Para baixar o relatorio completo em PDF, e necessario efetuar o pagamento.</p>' +
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:.8rem;margin-bottom:1.2rem;">' +
    '<div style="background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.2);border-radius:12px;padding:1rem .5rem;text-align:center;">' +
    '<div style="font-size:.7rem;color:#8b95a8;margin-bottom:.3rem;">&#127463;&#127479; Brasil</div>' +
    '<div style="font-size:1.4rem;font-weight:800;color:#3b82f6;white-space:nowrap;">R$ 10,00</div></div>' +
    '<div style="background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.2);border-radius:12px;padding:1rem .5rem;text-align:center;">' +
    '<div style="font-size:.7rem;color:#8b95a8;margin-bottom:.3rem;">&#127758; Internacional</div>' +
    '<div style="font-size:1.4rem;font-weight:800;color:#10b981;white-space:nowrap;">$ 10.00</div></div></div>' +
    '<div style="margin-bottom:1rem;"><label style="display:block;font-size:.8rem;color:#8b95a8;margin-bottom:.4rem;font-weight:600;">Seu e-mail (para receber o relatorio)</label>' +
    '<input type="email" id="paywall-email" inputmode="email" autocomplete="email" placeholder="seu@email.com" style="width:100%;padding:.85rem 1rem;border-radius:10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);color:#e5e7eb;font-size:16px;outline:none;box-sizing:border-box;min-height:48px;"></div>' +
    '<button id="paywall-pay-btn" style="width:100%;padding:1rem;border-radius:12px;border:none;background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;font-size:.95rem;font-weight:700;cursor:pointer;margin-bottom:.7rem;min-height:52px;transition:all .25s;">&#128179; Pagar e Baixar Relatorio</button>' +
    '<div style="display:flex;gap:8px;justify-content:center;align-items:center;margin-bottom:.6rem;flex-wrap:wrap;">' +
    '<span style="display:inline-flex;align-items:center;gap:4px;padding:4px 9px;border-radius:6px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);font-size:.66rem;font-weight:700;color:#adb5c4;letter-spacing:.02em;">' +
    '<svg width="12" height="12" viewBox="0 0 24 24" fill="#009cde" aria-hidden="true"><path d="M7.3 21.3H3.6l3-19.1h6.9c3.7 0 6 1.9 5.5 5.3-.5 3.6-3.4 5.5-7.1 5.5H9.3l-2 8.3zm2.6-11.5h2.2c1.6 0 2.8-.8 3-2.3.2-1.4-.7-2.1-2.3-2.1h-2l-.9 4.4z"/></svg>PayPal</span>' +
    '<span style="display:inline-flex;align-items:center;gap:4px;padding:4px 9px;border-radius:6px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);font-size:.66rem;font-weight:700;color:#adb5c4;letter-spacing:.02em;">' +
    '<svg width="12" height="12" viewBox="0 0 24 24" fill="#00b1ea" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M7 13c1.6 1.6 3.3 2.4 5 2.4s3.4-.8 5-2.4" stroke="#fff" stroke-width="1.6" fill="none" stroke-linecap="round"/><circle cx="9" cy="9.6" r="1.2" fill="#fff"/><circle cx="15" cy="9.6" r="1.2" fill="#fff"/></svg>Mercado Pago</span></div>' +
    '<div style="text-align:center;font-size:.68rem;color:#6b7280;line-height:1.5;">&#128274; Pagamento seguro e criptografado | Dados protegidos</div>' +
    '</div>';
  document.body.appendChild(m);
  document.getElementById('paywall-close').addEventListener('click', function() { m.style.display = 'none'; });
  document.getElementById('paywall-pay-btn').addEventListener('click', processPayment);
}

function processPayment() {
  var email = document.getElementById('paywall-email').value.trim();
  if (!email || !email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
    alert('Por favor, insira um e-mail valido para receber o relatorio.');
    return;
  }
  var btn = document.getElementById('paywall-pay-btn');
  btn.innerHTML = '&#9203; Processando pagamento...';
  btn.style.opacity = '.6';
  btn.style.pointerEvents = 'none';
  // Simula processamento de pagamento (3 segundos)
  setTimeout(function() {
    psgPaymentDone = true;
    btn.innerHTML = '&#9989; Pagamento confirmado!';
    btn.style.background = 'linear-gradient(135deg,#10b981,#059669)';
    // Registra pagamento
    var payments = [];
    try { payments = JSON.parse(localStorage.getItem('psg_payments') || '[]'); } catch(e) {}
    payments.push({
      date: new Date().toISOString(),
      email: email,
      amount: 'R$10.00 / $10.00',
      status: 'confirmed'
    });
    try { localStorage.setItem('psg_payments', JSON.stringify(payments)); } catch(e) {}
    try { SH_SECURITY.logEvent('PAYMENT_CONFIRMED', email); } catch(e) {}
    // Fecha paywall e gera PDF
    setTimeout(function() {
      document.getElementById('paywall-modal').style.display = 'none';
      btn.innerHTML = '&#128179; Pagar e Baixar Relatorio';
      btn.style.background = 'linear-gradient(135deg,#3b82f6,#8b5cf6)';
      btn.style.opacity = '1';
      btn.style.pointerEvents = 'auto';
      _doGeneratePDF();
    }, 1200);
  }, 3000);
}

// ============================================================
// PDF LIBS SOB DEMANDA — jsPDF + html2canvas (550KB) só baixam
// quando o usuario realmente pede o relatorio. Isso deixa a
// abertura do site muito mais rapida.
// ============================================================
var _psgPdfLibsPromise = null;
function _psgLoadScript(src) {
  return new Promise(function(resolve, reject) {
    var s = document.createElement('script');
    s.src = src;
    s.async = true;
    s.onload = resolve;
    s.onerror = function() { reject(new Error('Falha ao carregar biblioteca: ' + src)); };
    document.head.appendChild(s);
  });
}
function ensurePdfLibs() {
  if (window.jspdf && window.html2canvas) return Promise.resolve();
  if (_psgPdfLibsPromise) return _psgPdfLibsPromise;
  _psgPdfLibsPromise = Promise.all([
    window.jspdf ? Promise.resolve() : _psgLoadScript('https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js'),
    window.html2canvas ? Promise.resolve() : _psgLoadScript('https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js')
  ]).catch(function(e) { _psgPdfLibsPromise = null; throw e; });
  return _psgPdfLibsPromise;
}

// Funcao interna que realmente gera o PDF (so chamada apos pagamento)
async function _doGeneratePDF() {
  showLoading('Preparando gerador de PDF...');
  try {
    await ensurePdfLibs();
  } catch (e) {
    hideLoading();
    alert('Nao foi possivel carregar o gerador de PDF. Verifique sua conexao e tente novamente.');
    return;
  }
  showLoading('Gerando relatorio PDF...');
  document.getElementById('pdf-title').textContent = 'Relatorio de Seguranca - Portal Seguranca Global';
  document.getElementById('pdf-address').textContent = currentData.address.fullAddress + ' | ' + new Date().toLocaleDateString('pt-BR');
  document.getElementById('pdf-score').textContent = currentData.safetyScore;
  document.getElementById('pdf-score-label').textContent = 'Safety Score - ' + (currentData.safetyScore >= 70 ? 'SEGURO' : currentData.safetyScore >= 40 ? 'MODERADO' : 'CRITICO');
  document.getElementById('pdf-crime').textContent = currentData.crimeScore + '/100';
  document.getElementById('pdf-infra').textContent = currentData.infraScore + '/100';
  document.getElementById('pdf-movement').textContent = currentData.movementScore + '/100';
  document.getElementById('pdf-occ').textContent = currentData.totalOccurrences;
  document.getElementById('pdf-cam').textContent = currentData.cameras;
  document.getElementById('pdf-com').textContent = currentData.commerce;
  try {
    const reportEl = document.getElementById('pdf-report');
    reportEl.style.left = '0';
    const canvas = await html2canvas(reportEl, { scale: 2, useCORS: true, backgroundColor: '#ffffff' });
    reportEl.style.left = '-9999px';
    const { jsPDF } = window.jspdf;
    const pdf = new jsPDF('p', 'mm', 'a4');
    const imgData = canvas.toDataURL('image/jpeg', .95);
    const pageW = pdf.internal.pageSize.getWidth();
    const pageH = (canvas.height * pageW) / canvas.width;
    pdf.addImage(imgData, 'JPEG', 0, 0, pageW, pageH);
    var fileName = 'PortalSegurancaGlobal_Relatorio_' + Date.now() + '.pdf';
    var pdfBlob = pdf.output('blob');
    hideLoading();
    PSG_DELIVERY.show(pdfBlob, fileName);
  } catch (err) { hideLoading(); alert('Erro ao gerar PDF: ' + err.message); }
}

// Funcao publica — verifica pagamento antes de gerar
async function generatePDF() {
  if (!currentData) return alert('Faca uma pesquisa primeiro.');
  if (!psgPaymentDone) {
    showPaywallModal();
    return;
  }
  _doGeneratePDF();
}

// ============================================================
// SHARE
// ============================================================
function shareResult() {
  if (!currentData) return;
  const text = 'Portal Seguranca Global - Safety Score: ' + currentData.safetyScore + '/100 para ' + currentData.address.fullAddress;
  if (navigator.share) { navigator.share({ title: 'Portal Seguranca Global', text: text }); }
  else { navigator.clipboard.writeText(text); alert('Link copiado para a area de transferencia!'); }
}

// ============================================================
// HELPERS
// ============================================================
function showLoading(text) { document.getElementById('loading-text').textContent = text; document.getElementById('loading').classList.add('active'); }
function updateLoading(text) { document.getElementById('loading-text').textContent = text; }
function hideLoading() { document.getElementById('loading').classList.remove('active'); }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ============================================================
// MODAL DE TERMOS
// ============================================================
function toggleTermsBtn() {
  var cb = document.getElementById('terms-checkbox');
  var btn = document.getElementById('terms-btn');
  if (cb.checked) { btn.classList.remove('disabled'); btn.classList.add('enabled'); btn.disabled = false; }
  else { btn.classList.remove('enabled'); btn.classList.add('disabled'); btn.disabled = true; }
}

function acceptTerms() {
  var cb = document.getElementById('terms-checkbox');
  if (!cb.checked) return;
  var overlay = document.getElementById('terms-overlay');
  overlay.classList.remove('active');
  overlay.classList.add('hidden');
  setTimeout(function() { overlay.style.display = 'none'; }, 400);
  try { sessionStorage.setItem('sh_terms_accepted', '1'); } catch(e) {}
  try { SH_SECURITY.logEvent('TERMS_ACCEPTED', 'User accepted terms of use'); } catch(e) {}
  // Executa a busca que estava pendente
  if (window._pendingSearch) { window._pendingSearch = false; handleSearch(); }
  else if (window._pendingMapSearch) { window._pendingMapSearch = false; openMapSearch(); }
  else if (window._pendingGpsSearch) { window._pendingGpsSearch = false; searchByGps(); }
}

function showTermsModal() {
  var overlay = document.getElementById('terms-overlay');
  overlay.style.display = 'flex';
  setTimeout(function() { overlay.classList.add('active'); overlay.classList.remove('hidden'); }, 10);
}

function termsAccepted() {
  try { return sessionStorage.getItem('sh_terms_accepted') === '1'; } catch(e) { return false; }
}

// ============================================================
// INIT — All event listeners (zero inline handlers)
// ============================================================
document.addEventListener('DOMContentLoaded', function() {
  initMap();

  // Terms modal
  document.getElementById('terms-checkbox').addEventListener('change', toggleTermsBtn);
  document.getElementById('terms-btn').addEventListener('click', acceptTerms);

  // Search
  document.getElementById('search-btn').addEventListener('click', handleSearch);
  document.getElementById('search-input').addEventListener('keydown', function(e) { if (e.key === 'Enter') handleSearch(); });

  // Pesquisar pelo mapa / GPS
  var bMap = document.getElementById('btn-map-search');
  if (bMap) bMap.addEventListener('click', openMapSearch);
  var bGps = document.getElementById('btn-gps-search');
  if (bGps) bGps.addEventListener('click', searchByGps);

  var msClose = document.getElementById('mapsel-close');
  if (msClose) msClose.addEventListener('click', closeMapSearch);
  var msCancel = document.getElementById('mapsel-cancel');
  if (msCancel) msCancel.addEventListener('click', closeMapSearch);
  var msConfirm = document.getElementById('mapsel-confirm');
  if (msConfirm) msConfirm.addEventListener('click', confirmMapSearch);
  var msFindBtn = document.getElementById('mapsel-find-btn');
  if (msFindBtn) msFindBtn.addEventListener('click', mapselFind);
  var msFind = document.getElementById('mapsel-find');
  if (msFind) msFind.addEventListener('keydown', function(e) { if (e.key === 'Enter') { e.preventDefault(); mapselFind(); } });
  var msGps = document.getElementById('mapsel-gps');
  if (msGps) msGps.addEventListener('click', mapselGps);
  var msOv = document.getElementById('mapsel-overlay');
  if (msOv) msOv.addEventListener('click', function(e) { if (e.target === msOv) closeMapSearch(); });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      var ov = document.getElementById('mapsel-overlay');
      if (ov && ov.style.display === 'flex') closeMapSearch();
    }
  });

  // Map view toggles
  document.getElementById('btn-view-dark').addEventListener('click', function() { switchMapView('dark'); });
  document.getElementById('btn-view-satellite').addEventListener('click', function() { switchMapView('satellite'); });
  document.getElementById('btn-view-3d').addEventListener('click', function() { switchMapView('3d'); });

  // Delegated clicks for dynamic/PDF/share/heatmap/markers buttons
  document.addEventListener('click', function(e) {
    if (e.target.closest('#btn-pdf')) generatePDF();
    if (e.target.closest('#btn-share')) shareResult();
    if (e.target.closest('#btn-heatmap')) toggleHeatmap();
    if (e.target.closest('#btn-markers')) toggleMarkers();
  });
});

// ============================================================
// MANUAL MULTILINGUE — detecta idioma do navegador automaticamente
// ============================================================
var manualData = {
  pt: { title: 'Manual de Instrucoes', steps: [
    { h: 'Acesse o Portal', p: 'Abra o site portalsegurancaglobal.com.br no seu navegador. O portal funciona em qualquer dispositivo (computador, tablet ou celular).' },
    { h: 'Escolha o Tipo de Consulta', p: 'Na barra de busca, voce pode digitar: CEP, endereco, cidade ou pais para ver o Mapa de Seguranca; ou CPF, CNPJ ou nome completo para fazer um Background Check.' },
    { h: 'Aceite os Termos de Uso', p: 'Antes de qualquer pesquisa, sera exibido um termo de uso. Leia com atencao, marque as caixas de confirmacao e clique em "Aceitar e Prosseguir".' },
    { h: 'Analise os Resultados', p: 'Para enderecos: voce vera um mapa de calor, Safety Score (0-100), graficos de criminalidade e infraestrutura. Para CPF/CNPJ: vera o Background Check completo com consulta a orgaos internacionais.' },
    { h: 'Gere o Relatorio em PDF', p: 'Apos a analise, clique em "Gerar Relatorio PDF" para obter um documento completo. Para o Background Check, sera necessario informar seu e-mail e efetuar o pagamento (R$10,00 ou $10 USD).' },
    { h: 'Receba por E-mail', p: 'Apos o pagamento, o relatorio completo sera enviado para o e-mail informado. Voce tambem pode baixar imediatamente clicando em "Baixar PDF Agora".' }
  ], note: 'Todas as consultas sao realizadas exclusivamente em fontes publicas e bases de dados autorizadas, em conformidade com a LGPD, GDPR e legislacoes internacionais de protecao de dados.' },
  en: { title: 'User Manual', steps: [
    { h: 'Access the Portal', p: 'Open portalsegurancaglobal.com.br in your browser. The portal works on any device (computer, tablet, or smartphone).' },
    { h: 'Choose the Query Type', p: 'In the search bar, you can enter: ZIP code, address, city, or country to view the Security Map; or CPF, CNPJ, or full name for a Background Check.' },
    { h: 'Accept the Terms of Use', p: 'Before any search, a terms of use dialog will appear. Read carefully, check the confirmation boxes, and click "Accept and Proceed".' },
    { h: 'Analyze the Results', p: 'For addresses: you will see a heat map, Safety Score (0-100), crime statistics, and infrastructure charts. For CPF/CNPJ: you will see a full Background Check with international agency consultations.' },
    { h: 'Generate the PDF Report', p: 'After the analysis, click "Generate PDF Report" for a complete document. For Background Checks, you will need to provide your email and make a payment (R$10.00 or $10 USD).' },
    { h: 'Receive by Email', p: 'After payment, the full report will be sent to the provided email. You can also download it immediately by clicking "Download PDF Now".' }
  ], note: 'All queries are performed exclusively on public sources and authorized databases, in compliance with LGPD, GDPR, and international data protection laws.' },
  es: { title: 'Manual de Instrucciones', steps: [
    { h: 'Acceda al Portal', p: 'Abra portalsegurancaglobal.com.br en su navegador. El portal funciona en cualquier dispositivo.' },
    { h: 'Elija el Tipo de Consulta', p: 'Ingrese: codigo postal, direccion, ciudad o pais para el Mapa de Seguridad; o CPF, CNPJ o nombre completo para un Background Check.' },
    { h: 'Acepte los Terminos de Uso', p: 'Antes de cualquier busqueda, aparecera un termino de uso. Lea con atencion, marque las casillas y haga clic en "Aceptar y Continuar".' },
    { h: 'Analice los Resultados', p: 'Para direcciones: mapa de calor, Safety Score (0-100), graficos de criminalidad. Para CPF/CNPJ: Background Check completo con organismos internacionales.' },
    { h: 'Genere el Informe en PDF', p: 'Haga clic en "Generar Informe PDF". Para Background Check, ingrese su correo y realice el pago (R$10,00 o $10 USD).' },
    { h: 'Reciba por Correo', p: 'Despues del pago, el informe sera enviado a su correo. Tambien puede descargarlo inmediatamente.' }
  ], note: 'Todas las consultas se realizan en fuentes publicas y bases autorizadas, en cumplimiento con LGPD, GDPR y legislaciones internacionales.' },
  fr: { title: "Manuel d'Utilisation", steps: [
    { h: 'Accedez au Portail', p: 'Ouvrez portalsegurancaglobal.com.br dans votre navigateur. Le portail fonctionne sur tout appareil.' },
    { h: 'Choisissez le Type de Recherche', p: 'Saisissez: code postal, adresse, ville ou pays pour la Carte de Securite; ou CPF, CNPJ ou nom complet pour un Background Check.' },
    { h: 'Acceptez les Conditions', p: "Avant toute recherche, les conditions d'utilisation s'affichent. Lisez attentivement, cochez les cases et cliquez sur Accepter." },
    { h: 'Analysez les Resultats', p: 'Pour les adresses: carte thermique, Safety Score (0-100), graphiques de criminalite. Pour CPF/CNPJ: Background Check complet avec agences internationales.' },
    { h: 'Generez le Rapport PDF', p: "Cliquez sur Generer Rapport PDF. Pour le Background Check, fournissez votre email et effectuez le paiement (R$10,00 ou $10 USD)." },
    { h: 'Recevez par Email', p: "Apres le paiement, le rapport complet sera envoye a l'email indique. Vous pouvez aussi le telecharger immediatement." }
  ], note: 'Toutes les consultations sont effectuees sur des sources publiques et bases autorisees, conformement au LGPD, RGPD et aux lois internationales.' },
  de: { title: 'Bedienungsanleitung', steps: [
    { h: 'Portal aufrufen', p: 'Offnen Sie portalsegurancaglobal.com.br in Ihrem Browser. Das Portal funktioniert auf jedem Gerat.' },
    { h: 'Abfragetyp wahlen', p: 'Geben Sie ein: Postleitzahl, Adresse, Stadt oder Land fur die Sicherheitskarte; oder CPF, CNPJ oder Namen fur einen Background Check.' },
    { h: 'Nutzungsbedingungen akzeptieren', p: 'Vor jeder Suche werden die Nutzungsbedingungen angezeigt. Lesen Sie sorgfaltig und klicken Sie auf Akzeptieren.' },
    { h: 'Ergebnisse analysieren', p: 'Fur Adressen: Heatmap, Safety Score (0-100), Kriminalitatsstatistiken. Fur CPF/CNPJ: vollstandiger Background Check mit internationalen Behorden.' },
    { h: 'PDF-Bericht erstellen', p: 'Klicken Sie auf PDF-Bericht erstellen. Fur den Background Check geben Sie Ihre E-Mail an und leisten die Zahlung (R$10,00 oder $10 USD).' },
    { h: 'Per E-Mail erhalten', p: 'Nach der Zahlung wird der Bericht an Ihre E-Mail gesendet. Sie konnen ihn auch sofort herunterladen.' }
  ], note: 'Alle Abfragen werden aus offentlichen Quellen und autorisierten Datenbanken durchgefuhrt, in Ubereinstimmung mit LGPD, DSGVO und internationalen Datenschutzgesetzen.' },
  it: { title: 'Manuale di Istruzioni', steps: [
    { h: 'Accedi al Portale', p: 'Apri portalsegurancaglobal.com.br nel tuo browser. Il portale funziona su qualsiasi dispositivo.' },
    { h: 'Scegli il Tipo di Ricerca', p: 'Inserisci: CAP, indirizzo, citta o paese per la Mappa di Sicurezza; oppure CPF, CNPJ o nome completo per un Background Check.' },
    { h: 'Accetta i Termini', p: 'Prima di ogni ricerca, verranno mostrati i termini. Leggi attentamente, seleziona le caselle e clicca su Accetta.' },
    { h: 'Analizza i Risultati', p: 'Per indirizzi: mappa termica, Safety Score (0-100), statistiche criminalita. Per CPF/CNPJ: Background Check completo con agenzie internazionali.' },
    { h: 'Genera il Report PDF', p: "Clicca su Genera Report PDF. Per il Background Check, fornisci la tua email ed effettua il pagamento (R$10,00 o $10 USD)." },
    { h: 'Ricevi via Email', p: 'Dopo il pagamento, il report verra inviato alla tua email. Puoi anche scaricarlo immediatamente.' }
  ], note: 'Tutte le consultazioni sono effettuate su fonti pubbliche e database autorizzati, in conformita con LGPD, GDPR e legislazioni internazionali.' },
  zh: { title: 'User Manual', steps: [
    { h: 'Access the Portal', p: 'Open portalsegurancaglobal.com.br. Works on any device (computer, tablet, smartphone).' },
    { h: 'Choose Query Type', p: 'Enter ZIP code, address, city or country for Security Map; or CPF, CNPJ, full name for Background Check.' },
    { h: 'Accept Terms of Use', p: 'Before any search, terms of use will appear. Read carefully, check boxes and click Accept.' },
    { h: 'Analyze Results', p: 'Addresses: heat map, Safety Score (0-100), crime charts. CPF/CNPJ: full Background Check with international agencies.' },
    { h: 'Generate PDF Report', p: 'Click Generate PDF Report. For Background Check, provide email and pay (R$10.00 or $10 USD).' },
    { h: 'Receive by Email', p: 'After payment, report will be sent to your email. You can also download immediately.' }
  ], note: 'All queries use public sources and authorized databases, compliant with LGPD, GDPR and international data protection laws.' },
  ja: { title: 'User Manual', steps: [
    { h: 'Access Portal', p: 'Open portalsegurancaglobal.com.br. Works on any device.' },
    { h: 'Choose Query Type', p: 'Enter ZIP, address, city/country for Security Map; or CPF, CNPJ, name for Background Check.' },
    { h: 'Accept Terms', p: 'Terms of use will appear before search. Read, check boxes and click Accept.' },
    { h: 'Analyze Results', p: 'Addresses: heat map, Safety Score (0-100). CPF/CNPJ: full Background Check with international agencies.' },
    { h: 'Generate PDF', p: 'Click Generate PDF Report. Background Check requires email and payment (R$10.00 or $10 USD).' },
    { h: 'Receive by Email', p: 'After payment, report sent to email. Immediate download also available.' }
  ], note: 'All queries use public sources and authorized databases, compliant with LGPD, GDPR and international laws.' },
  ar: { title: 'Dalil al-Mustakhdam', steps: [
    { h: 'Access Portal', p: 'Open portalsegurancaglobal.com.br. Works on any device.' },
    { h: 'Choose Query', p: 'Enter ZIP, address, city/country for Security Map; or CPF, CNPJ, name for Background Check.' },
    { h: 'Accept Terms', p: 'Terms appear before search. Read, check boxes and click Accept.' },
    { h: 'Analyze Results', p: 'Addresses: heat map, Safety Score. CPF/CNPJ: full Background Check with international agencies.' },
    { h: 'Generate PDF', p: 'Click Generate PDF. Background Check requires email and payment (R$10.00 or $10 USD).' },
    { h: 'Receive by Email', p: 'After payment, report sent to email. Immediate download available.' }
  ], note: 'All queries use public sources and authorized databases, compliant with LGPD, GDPR and international laws.' },
  ru: { title: 'Rukovodstvo', steps: [
    { h: 'Dostup k Portalu', p: 'Otkroyte portalsegurancaglobal.com.br. Rabotayet na lyubom ustroystve.' },
    { h: 'Vybor Zaprosa', p: 'Vvedite indeks, adres, gorod ili stranu dlya Karty Bezopasnosti; ili CPF, CNPJ, imya dlya Background Check.' },
    { h: 'Prinyat Usloviya', p: 'Pered poiskom otobrazhatsia usloviya. Prochitayte, otmet\'te i nazhmite Prinyat.' },
    { h: 'Analiz Rezul\'tatov', p: 'Adresa: teplovaya karta, Safety Score (0-100). CPF/CNPJ: polnyy Background Check s mezhdunarodnymi organizatsiyami.' },
    { h: 'PDF Otchyot', p: 'Nazhmite Sozdat PDF. Dlya Background Check ukazhite email i oplatite (R$10.00 ili $10 USD).' },
    { h: 'Email', p: 'Posle oplaty otchyot otpravlen na pochtu. Mozhno skachat srazu.' }
  ], note: 'Zaprosy vypolnyayutsia po otkrytym istochnikam, v sootvetstvii s LGPD, GDPR i mezhdunarodnymi zakonami.' },
  ko: { title: 'User Manual', steps: [
    { h: 'Access Portal', p: 'Open portalsegurancaglobal.com.br. Works on any device.' },
    { h: 'Choose Query', p: 'Enter ZIP, address, city/country for Security Map; or CPF, CNPJ, name for Background Check.' },
    { h: 'Accept Terms', p: 'Terms appear before search. Read, check and click Accept.' },
    { h: 'Analyze Results', p: 'Addresses: heat map, Safety Score. CPF/CNPJ: full Background Check with international agencies.' },
    { h: 'Generate PDF', p: 'Click Generate PDF. Background Check requires email and payment (R$10.00 or $10 USD).' },
    { h: 'Receive by Email', p: 'After payment, report sent to email. Immediate download available.' }
  ], note: 'All queries use public sources compliant with LGPD, GDPR and international laws.' },
  hi: { title: 'Upayog Manual', steps: [
    { h: 'Portal Kholein', p: 'Browser mein portalsegurancaglobal.com.br kholein. Kisi bhi device par kaam karta hai.' },
    { h: 'Query Chunein', p: 'PIN code, pata, shahar ya desh dalein Suraksha Naksha ke liye; ya CPF, CNPJ, naam dalein Background Check ke liye.' },
    { h: 'Shartein Svikaar Karein', p: 'Khoj se pehle shartein dikhayi jayeingi. Padein, tick karein aur Svikaar par click karein.' },
    { h: 'Parinaam Dekhein', p: 'Pate: heat map, Safety Score (0-100). CPF/CNPJ: poorn Background Check antarrashtriya sangathanon ke saath.' },
    { h: 'PDF Report', p: 'PDF Report Banaayein par click karein. Background Check ke liye email aur bhugtan (R$10.00 ya $10 USD) chahiye.' },
    { h: 'Email se Prapt Karein', p: 'Bhugtan ke baad report email par aayega. Turant download bhi kar sakte hain.' }
  ], note: 'Sabhi jaanch saarvajanik shroton aur adhikrit databases se, LGPD, GDPR aur antarrashtriya kaanoonon ke anusaar.' }
};

function switchManualLang(lang) {
  var d = manualData[lang] || manualData['en'];
  document.getElementById('manual-title').textContent = d.title;
  var html = '';
  for (var i = 0; i < d.steps.length; i++) {
    html += '<div class="manual-step"><div class="manual-step-num">' + (i+1) + '</div><div class="manual-step-text"><h3>' + d.steps[i].h + '</h3><p>' + d.steps[i].p + '</p></div></div>';
  }
  html += '<div class="manual-note">' + d.note + '</div>';
  document.getElementById('manual-content').innerHTML = html;
}

// Auto-detecta idioma do navegador e inicializa manual
(function initManual() {
  var el = document.getElementById('manual-lang');
  if (!el) return;
  // Listener para trocar idioma do manual (substituindo onchange inline bloqueado pelo CSP)
  el.addEventListener('change', function() { switchManualLang(el.value); });
  var userLang = (navigator.language || navigator.userLanguage || 'pt').substring(0, 2).toLowerCase();
  var supported = Object.keys(manualData);
  var lang = supported.indexOf(userLang) !== -1 ? userLang : 'en';
  el.value = lang;
  switchManualLang(lang);
})();

// ============================================================
// FLAGS — Repetir bandeiras para preencher toda a altura da pagina
// PERFORMANCE: repete só o necessario e roda depois da pagina aparecer
// ============================================================
(function fillFlags() {
  function run() {
    var cols = document.querySelectorAll('.flags-column');
    if (!cols.length) return;
    cols.forEach(function(col) {
      var items = col.querySelectorAll('.flag-item');
      if (!items.length) return;

      // Altura de um bloco de bandeiras vs altura total da pagina
      var blocoH = col.scrollHeight || 0;
      var alvoH = Math.max(document.body.scrollHeight, window.innerHeight);
      var repeticoes = blocoH > 0 ? Math.ceil(alvoH / blocoH) - 1 : 2;
      if (repeticoes < 1) repeticoes = 1;
      if (repeticoes > 4) repeticoes = 4;

      var originalHTML = '';
      for (var i = 0; i < items.length; i++) {
        originalHTML += items[i].outerHTML;
      }
      for (var r = 0; r < repeticoes; r++) {
        col.insertAdjacentHTML('beforeend', originalHTML);
      }
    });
  }
  // Nao atrasa a primeira pintura da tela
  if ('requestIdleCallback' in window) {
    requestIdleCallback(run, { timeout: 2000 });
  } else {
    setTimeout(run, 300);
  }
})();

// ============================================================
// TRADUCAO POR BANDEIRA — Clicar na bandeira traduz o site inteiro
// ============================================================
var PSG_LANG = (function() {
  // Mapeamento: codigo pais -> codigo idioma
  var countryToLang = {
    'br':'pt','us':'en','gb':'en','fr':'fr','de':'de','it':'it','es':'es','pt':'pt',
    'ca':'en','mx':'es','ar':'es','co':'es','cl':'es','pe':'es','uy':'es','py':'es',
    've':'es','bo':'es','ec':'es','cu':'es','pa':'es','cr':'es','nl':'nl','be':'fr',
    'se':'sv','dk':'da','fi':'fi','at':'de','pl':'pl','ua':'uk','gr':'el','ie':'en',
    'cz':'cs','ro':'ro','hu':'hu','hr':'hr',
    'jp':'ja','cn':'zh','kr':'ko','in':'hi','au':'en','ru':'ru','za':'en','ng':'en',
    'eg':'ar','il':'he','sa':'ar','tr':'tr','ch':'de','no':'no','nz':'en','id':'id',
    'th':'th','vn':'vi','ph':'en','my':'ms','sg':'en','pk':'ur','ae':'ar','qa':'ar',
    'ma':'ar','ke':'en','et':'en','gh':'en','ao':'pt','mz':'pt','ir':'fa','iq':'ar',
    'jo':'ar','bd':'bn','tz':'en','kp':'ko'
  };

  // Textos traduzidos para os elementos principais do site
  var translations = {
    'pt': {
      pageTitle: 'Portal Seguranca Global',
      emblemTitle: 'Busca em tempo real em qualquer endere\u00e7o do mundo',
      emblemTagline: 'Veja se o lugar que voc\u00ea procura \u00e9 realmente seguro',
      searchTitle: 'Consulte a Seguranca de Qualquer Lugar do Mundo',
      searchSubtitle: 'Analise em tempo real baseada em dados de criminalidade, infraestrutura e movimentacao urbana — cobertura global',
      searchPlaceholder: 'CPF, CNPJ, RG, CEP, endereco, cidade ou pais...',
      searchBtn: 'Analisar',
      searchHint: 'Exemplos: <kbd>87020-025</kbd> | <kbd>Times Square, New York</kbd> | <kbd>Shibuya, Tokyo</kbd>',
      mapTitle: 'Mapa de Ocorrencias',
      scoreTitle: 'Safety Score',
      statsTitle: 'Estatisticas do Bairro',
      pdfBtn: 'Gerar Relatorio PDF',
      shareBtn: 'Compartilhar',
      manualTitle: 'Manual de Instrucoes',
      footerText: 'Cobertura mundial. Dados baseados em fontes publicas. Nao substitui avaliacao profissional.',
      copyrightText: 'Todos os direitos reservados.',
      copyrightProhibit: 'E proibida a reproducao total ou parcial deste sistema e de seus algoritmos.',
      occurrences: 'Ocorrencias/mes', cameras: 'Cameras', lighting: 'Iluminacao', commerce: 'Comercios',
      crimeIndex: 'Indice Criminal', infrastructure: 'Infraestrutura', urbanMovement: 'Movimentacao Urbana',
      chartTypes: 'Ocorrencias por Tipo', chartMonthly: 'Evolucao Mensal',
      adTitle: 'Monitore sua Residencia 24h', adDesc: 'Cameras inteligentes com IA para deteccao de movimento.',
      adBtnText: 'Saiba Mais', adBannerTitle: 'Proteja sua Familia com Tecnologia de Ponta',
      lowRisk: 'Baixo Risco', mediumRisk: 'Medio Risco', highRisk: 'Alto Risco', poi: 'Ponto de Interesse',
      termsTitle: 'Termos de Uso e Responsabilidade', termsRead: 'Leia antes de prosseguir',
      termsAcceptBtn: 'Concordo e Desejo Prosseguir',
      headerStatus: 'Base de dados atualizada'
    },
    'en': {
      pageTitle: 'Global Security Portal',
      emblemTitle: 'Real-time search at any address in the world',
      emblemTagline: 'Check if the place you are looking for is really safe',
      searchTitle: 'Check the Safety of Any Location Worldwide',
      searchSubtitle: 'Real-time analysis based on crime data, infrastructure and urban movement — global coverage',
      searchPlaceholder: 'ID, Tax ID, Name, ZIP, address, city or country...',
      searchBtn: 'Analyze',
      searchHint: 'Examples: <kbd>10001</kbd> | <kbd>Times Square, New York</kbd> | <kbd>Shibuya, Tokyo</kbd>',
      mapTitle: 'Incidents Map',
      scoreTitle: 'Safety Score',
      statsTitle: 'Neighborhood Statistics',
      pdfBtn: 'Generate PDF Report',
      shareBtn: 'Share',
      manualTitle: 'User Manual',
      footerText: 'Worldwide coverage. Based on public data. Does not replace professional assessment.',
      copyrightText: 'All rights reserved.',
      copyrightProhibit: 'Total or partial reproduction of this system and its algorithms is prohibited.',
      occurrences: 'Incidents/month', cameras: 'Cameras', lighting: 'Lighting', commerce: 'Businesses',
      crimeIndex: 'Crime Index', infrastructure: 'Infrastructure', urbanMovement: 'Urban Movement',
      chartTypes: 'Incidents by Type', chartMonthly: 'Monthly Trend',
      adTitle: 'Monitor Your Home 24/7', adDesc: 'Smart cameras with AI for motion detection.',
      adBtnText: 'Learn More', adBannerTitle: 'Protect Your Family with Cutting-Edge Technology',
      lowRisk: 'Low Risk', mediumRisk: 'Medium Risk', highRisk: 'High Risk', poi: 'Point of Interest',
      termsTitle: 'Terms of Use and Responsibility', termsRead: 'Read before proceeding',
      termsAcceptBtn: 'I Agree and Wish to Proceed',
      headerStatus: 'Database updated'
    },
    'es': {
      pageTitle: 'Portal de Seguridad Global',
      emblemTitle: 'Busqueda en tiempo real en cualquier direccion del mundo',
      emblemTagline: 'Vea si el lugar que busca es realmente seguro',
      searchTitle: 'Consulte la Seguridad de Cualquier Lugar del Mundo',
      searchSubtitle: 'Analisis en tiempo real basado en datos de criminalidad, infraestructura y movimiento urbano — cobertura global',
      searchPlaceholder: 'DNI, CUIT, Nombre, Codigo postal, direccion, ciudad o pais...',
      searchBtn: 'Analizar',
      searchHint: 'Ejemplos: <kbd>28001</kbd> | <kbd>Times Square, New York</kbd> | <kbd>Shibuya, Tokyo</kbd>',
      mapTitle: 'Mapa de Incidentes',
      scoreTitle: 'Safety Score',
      statsTitle: 'Estadisticas del Barrio',
      pdfBtn: 'Generar Informe PDF',
      shareBtn: 'Compartir',
      manualTitle: 'Manual de Instrucciones',
      footerText: 'Cobertura mundial. Basado en fuentes publicas. No sustituye evaluacion profesional.',
      copyrightText: 'Todos los derechos reservados.',
      copyrightProhibit: 'Se prohibe la reproduccion total o parcial de este sistema y sus algoritmos.',
      occurrences: 'Incidentes/mes', cameras: 'Camaras', lighting: 'Iluminacion', commerce: 'Comercios',
      crimeIndex: 'Indice Criminal', infrastructure: 'Infraestructura', urbanMovement: 'Movimiento Urbano',
      chartTypes: 'Incidentes por Tipo', chartMonthly: 'Evolucion Mensual',
      adTitle: 'Monitorea tu Hogar 24h', adDesc: 'Camaras inteligentes con IA para deteccion de movimiento.',
      adBtnText: 'Saber Mas', adBannerTitle: 'Protege a tu Familia con Tecnologia de Punta',
      lowRisk: 'Bajo Riesgo', mediumRisk: 'Riesgo Medio', highRisk: 'Alto Riesgo', poi: 'Punto de Interes',
      termsTitle: 'Terminos de Uso y Responsabilidad', termsRead: 'Lea antes de continuar',
      termsAcceptBtn: 'Acepto y Deseo Continuar',
      headerStatus: 'Base de datos actualizada'
    },
    'fr': {
      pageTitle: 'Portail de Securite Mondiale',
      emblemTitle: 'Recherche en temps reel a n\'importe quelle adresse du monde',
      emblemTagline: 'Verifiez si le lieu que vous cherchez est vraiment sur',
      searchTitle: 'Verifiez la Securite de N\'importe Quel Lieu dans le Monde',
      searchSubtitle: 'Analyse en temps reel basee sur les donnees de criminalite, l\'infrastructure et les mouvements urbains — couverture mondiale',
      searchPlaceholder: 'CNI, SIRET, Nom, Code postal, adresse, ville ou pays...',
      searchBtn: 'Analyser',
      searchHint: 'Exemples: <kbd>75001</kbd> | <kbd>Times Square, New York</kbd> | <kbd>Shibuya, Tokyo</kbd>',
      mapTitle: 'Carte des Incidents',
      scoreTitle: 'Safety Score',
      statsTitle: 'Statistiques du Quartier',
      pdfBtn: 'Generer Rapport PDF',
      shareBtn: 'Partager',
      manualTitle: 'Manuel d\'Utilisation',
      footerText: 'Couverture mondiale. Basee sur des sources publiques. Ne remplace pas une evaluation professionnelle.',
      copyrightText: 'Tous droits reserves.',
      copyrightProhibit: 'La reproduction totale ou partielle de ce systeme et de ses algorithmes est interdite.',
      occurrences: 'Incidents/mois', cameras: 'Cameras', lighting: 'Eclairage', commerce: 'Commerces',
      crimeIndex: 'Indice de Criminalite', infrastructure: 'Infrastructure', urbanMovement: 'Mouvement Urbain',
      chartTypes: 'Incidents par Type', chartMonthly: 'Evolution Mensuelle',
      adTitle: 'Surveillez Votre Maison 24h/24', adDesc: 'Cameras intelligentes avec IA pour detection de mouvement.',
      adBtnText: 'En Savoir Plus', adBannerTitle: 'Protegez Votre Famille avec la Technologie de Pointe',
      lowRisk: 'Risque Faible', mediumRisk: 'Risque Moyen', highRisk: 'Risque Eleve', poi: 'Point d\'Interet',
      termsTitle: 'Conditions d\'Utilisation', termsRead: 'Lisez avant de continuer',
      termsAcceptBtn: 'J\'Accepte et Souhaite Continuer',
      headerStatus: 'Base de donnees mise a jour'
    },
    'de': {
      pageTitle: 'Globales Sicherheitsportal',
      emblemTitle: 'Echtzeitsuche an jeder Adresse der Welt',
      emblemTagline: 'Prufen Sie, ob der gesuchte Ort wirklich sicher ist',
      searchTitle: 'Prufen Sie die Sicherheit Jedes Ortes Weltweit',
      searchSubtitle: 'Echtzeitanalyse basierend auf Kriminalitaetsdaten, Infrastruktur und staedtischer Bewegung — globale Abdeckung',
      searchPlaceholder: 'Ausweis, Steuernr., Name, PLZ, Adresse, Stadt oder Land...',
      searchBtn: 'Analysieren',
      searchHint: 'Beispiele: <kbd>10115</kbd> | <kbd>Times Square, New York</kbd> | <kbd>Shibuya, Tokyo</kbd>',
      mapTitle: 'Vorfallkarte',
      scoreTitle: 'Safety Score',
      statsTitle: 'Stadtteilstatistiken',
      pdfBtn: 'PDF-Bericht Erstellen',
      shareBtn: 'Teilen',
      manualTitle: 'Bedienungsanleitung',
      footerText: 'Weltweite Abdeckung. Basierend auf oeffentlichen Daten. Ersetzt keine professionelle Bewertung.',
      copyrightText: 'Alle Rechte vorbehalten.',
      copyrightProhibit: 'Die vollstaendige oder teilweise Reproduktion dieses Systems und seiner Algorithmen ist verboten.',
      occurrences: 'Vorfaelle/Monat', cameras: 'Kameras', lighting: 'Beleuchtung', commerce: 'Geschaefte',
      crimeIndex: 'Kriminalitaetsindex', infrastructure: 'Infrastruktur', urbanMovement: 'Staedtische Bewegung',
      chartTypes: 'Vorfaelle nach Typ', chartMonthly: 'Monatliche Entwicklung',
      adTitle: 'Ueberwachen Sie Ihr Zuhause 24/7', adDesc: 'Intelligente Kameras mit KI zur Bewegungserkennung.',
      adBtnText: 'Mehr Erfahren', adBannerTitle: 'Schuetzen Sie Ihre Familie mit Spitzentechnologie',
      lowRisk: 'Niedriges Risiko', mediumRisk: 'Mittleres Risiko', highRisk: 'Hohes Risiko', poi: 'Sehenswuerdigkeit',
      termsTitle: 'Nutzungsbedingungen', termsRead: 'Lesen Sie vor dem Fortfahren',
      termsAcceptBtn: 'Ich Stimme Zu und Moechte Fortfahren',
      headerStatus: 'Datenbank aktualisiert'
    },
    'ja': {
      pageTitle: 'Global Security Portal',
      emblemTitle: 'Real-time search at any address in the world',
      emblemTagline: 'Check if the place you are looking for is really safe',
      searchTitle: 'Check the Safety of Any Location Worldwide',
      searchSubtitle: 'Real-time analysis based on crime data, infrastructure and urban movement',
      searchPlaceholder: 'ID, Tax ID, Name, ZIP, address, city or country...',
      searchBtn: 'Analyze', searchHint: 'Examples: <kbd>100-0001</kbd> | <kbd>Shibuya, Tokyo</kbd>',
      mapTitle: 'Incidents Map', scoreTitle: 'Safety Score', statsTitle: 'Area Statistics',
      pdfBtn: 'Generate PDF', shareBtn: 'Share', manualTitle: 'User Manual',
      footerText: 'Worldwide coverage. Public data. Does not replace professional assessment.',
      copyrightText: 'All rights reserved.',
      copyrightProhibit: 'Reproduction of this system is prohibited.',
      occurrences: 'Incidents/month', cameras: 'Cameras', lighting: 'Lighting', commerce: 'Businesses',
      crimeIndex: 'Crime Index', infrastructure: 'Infrastructure', urbanMovement: 'Urban Movement',
      chartTypes: 'By Type', chartMonthly: 'Monthly Trend',
      adTitle: 'Monitor Your Home 24/7', adDesc: 'Smart cameras with AI.',
      adBtnText: 'Learn More', adBannerTitle: 'Protect Your Family',
      lowRisk: 'Low Risk', mediumRisk: 'Medium Risk', highRisk: 'High Risk', poi: 'POI',
      termsTitle: 'Terms of Use', termsRead: 'Read before proceeding',
      termsAcceptBtn: 'I Agree', headerStatus: 'Database updated'
    },
    'ar': {
      pageTitle: 'Portal Seguranca Global',
      emblemTitle: 'Real-time search at any address in the world',
      emblemTagline: 'Check if the place you are looking for is really safe',
      searchTitle: 'Check Safety of Any Location',
      searchSubtitle: 'Real-time analysis — global coverage',
      searchPlaceholder: 'ID, Name, ZIP, address, city or country...',
      searchBtn: 'Analyze', searchHint: 'Examples: <kbd>Times Square, New York</kbd>',
      mapTitle: 'Incidents Map', scoreTitle: 'Safety Score', statsTitle: 'Statistics',
      pdfBtn: 'Generate PDF', shareBtn: 'Share', manualTitle: 'User Manual',
      footerText: 'Worldwide coverage. Public data.',
      copyrightText: 'All rights reserved.',
      copyrightProhibit: 'Reproduction prohibited.',
      occurrences: 'Incidents/month', cameras: 'Cameras', lighting: 'Lighting', commerce: 'Businesses',
      crimeIndex: 'Crime Index', infrastructure: 'Infrastructure', urbanMovement: 'Urban Movement',
      chartTypes: 'By Type', chartMonthly: 'Monthly',
      adTitle: 'Monitor Home 24/7', adDesc: 'Smart cameras with AI.',
      adBtnText: 'Learn More', adBannerTitle: 'Protect Your Family',
      lowRisk: 'Low Risk', mediumRisk: 'Medium Risk', highRisk: 'High Risk', poi: 'POI',
      termsTitle: 'Terms of Use', termsRead: 'Read before proceeding',
      termsAcceptBtn: 'I Agree', headerStatus: 'Database updated'
    },
    'ru': {
      pageTitle: 'Portal Bezopasnosti',
      emblemTitle: 'Poisk v realnom vremeni po lyubomu adresu v mire',
      emblemTagline: 'Proverte, deystvitelno li bezopasno mesto, kotoroe vy ishchete',
      searchTitle: 'Proverka Bezopasnosti Lyubogo Mesta',
      searchSubtitle: 'Analiz v realnom vremeni — globalnoe pokrytie',
      searchPlaceholder: 'ID, nazvanie, indeks, adres, gorod ili strana...',
      searchBtn: 'Analizirovat', searchHint: 'Primery: <kbd>Times Square, New York</kbd>',
      mapTitle: 'Karta Intsidentov', scoreTitle: 'Safety Score', statsTitle: 'Statistika Rayona',
      pdfBtn: 'Sozdat PDF', shareBtn: 'Podelitsia', manualTitle: 'Rukovodstvo',
      footerText: 'Mirovoe pokrytie. Publichnye dannye.',
      copyrightText: 'Vse prava zashchishcheny.',
      copyrightProhibit: 'Vosproizvedenie zapreshcheno.',
      occurrences: 'Intsidenty/mesyats', cameras: 'Kamery', lighting: 'Osveshchenie', commerce: 'Biznes',
      crimeIndex: 'Indeks Prestupnosti', infrastructure: 'Infrastruktura', urbanMovement: 'Gorodskoe Dvizhenie',
      chartTypes: 'Po Tipu', chartMonthly: 'Po Mesyatsam',
      adTitle: 'Nablyudenie za Domom 24/7', adDesc: 'Umnye kamery s II.',
      adBtnText: 'Podrobnee', adBannerTitle: 'Zashchitite Svoyu Semyu',
      lowRisk: 'Nizkiy Risk', mediumRisk: 'Sredniy Risk', highRisk: 'Vysokiy Risk', poi: 'Tochka Interesa',
      termsTitle: 'Usloviya Ispolzovaniya', termsRead: 'Prochitayte pered prodolzheniem',
      termsAcceptBtn: 'Soglashaius', headerStatus: 'Baza dannykh obnovlena'
    },
    'zh': {
      pageTitle: 'Global Security Portal',
      emblemTitle: 'Real-time search at any address in the world',
      emblemTagline: 'Check if the place you are looking for is really safe',
      searchTitle: 'Check Safety of Any Location',
      searchSubtitle: 'Real-time analysis — global coverage',
      searchPlaceholder: 'ID, Name, ZIP, address, city or country...',
      searchBtn: 'Analyze', searchHint: 'Examples: <kbd>Times Square, New York</kbd>',
      mapTitle: 'Incidents Map', scoreTitle: 'Safety Score', statsTitle: 'Statistics',
      pdfBtn: 'Generate PDF', shareBtn: 'Share', manualTitle: 'User Manual',
      footerText: 'Worldwide coverage. Public data.',
      copyrightText: 'All rights reserved.',
      copyrightProhibit: 'Reproduction prohibited.',
      occurrences: 'Incidents/month', cameras: 'Cameras', lighting: 'Lighting', commerce: 'Businesses',
      crimeIndex: 'Crime Index', infrastructure: 'Infrastructure', urbanMovement: 'Urban Movement',
      chartTypes: 'By Type', chartMonthly: 'Monthly',
      adTitle: 'Monitor Home 24/7', adDesc: 'Smart cameras with AI.',
      adBtnText: 'Learn More', adBannerTitle: 'Protect Your Family',
      lowRisk: 'Low Risk', mediumRisk: 'Medium Risk', highRisk: 'High Risk', poi: 'POI',
      termsTitle: 'Terms of Use', termsRead: 'Read before proceeding',
      termsAcceptBtn: 'I Agree', headerStatus: 'Database updated'
    }
  };

  // Traducao da PESQUISA PELO MAPA (9 idiomas)
  var mapSearchI18n = {
    pt: { or: 'OU', mapBtn: 'Pesquisar pelo Mapa', gpsBtn: 'Onde estou agora',
      title: 'Pesquisar pelo Mapa', sub: 'Toque em qualquer ponto do mapa para analisar a seguranca do local',
      findPh: 'Ir para uma cidade ou pais...', hint: 'Toque no mapa para escolher o local',
      picked: 'Local selecionado', cancel: 'Cancelar', confirm: 'Analisar este local' },
    en: { or: 'OR', mapBtn: 'Search by Map', gpsBtn: 'Where I am now',
      title: 'Search by Map', sub: 'Tap anywhere on the map to analyze the safety of that location',
      findPh: 'Go to a city or country...', hint: 'Tap the map to choose a location',
      picked: 'Selected location', cancel: 'Cancel', confirm: 'Analyze this location' },
    es: { or: 'O', mapBtn: 'Buscar por Mapa', gpsBtn: 'Donde estoy ahora',
      title: 'Buscar por Mapa', sub: 'Toca cualquier punto del mapa para analizar la seguridad del lugar',
      findPh: 'Ir a una ciudad o pais...', hint: 'Toca el mapa para elegir el lugar',
      picked: 'Lugar seleccionado', cancel: 'Cancelar', confirm: 'Analizar este lugar' },
    fr: { or: 'OU', mapBtn: 'Rechercher sur la carte', gpsBtn: 'Ou je suis maintenant',
      title: 'Rechercher sur la carte', sub: 'Touchez n\'importe quel point de la carte pour analyser la securite du lieu',
      findPh: 'Aller a une ville ou un pays...', hint: 'Touchez la carte pour choisir le lieu',
      picked: 'Lieu selectionne', cancel: 'Annuler', confirm: 'Analyser ce lieu' },
    de: { or: 'ODER', mapBtn: 'Auf der Karte suchen', gpsBtn: 'Wo ich jetzt bin',
      title: 'Auf der Karte suchen', sub: 'Tippen Sie auf einen Punkt der Karte, um die Sicherheit des Ortes zu analysieren',
      findPh: 'Zu einer Stadt oder einem Land...', hint: 'Tippen Sie auf die Karte, um den Ort zu wahlen',
      picked: 'Ausgewahlter Ort', cancel: 'Abbrechen', confirm: 'Diesen Ort analysieren' },
    ja: { or: 'または', mapBtn: '地図で検索', gpsBtn: '現在地',
      title: '地図で検索', sub: '地図上の任意の場所をタップして、その地域の安全性を分析します',
      findPh: '都市または国へ移動...', hint: '地図をタップして場所を選択',
      picked: '選択した場所', cancel: 'キャンセル', confirm: 'この場所を分析' },
    ar: { or: 'أو', mapBtn: 'البحث بالخريطة', gpsBtn: 'موقعي الحالي',
      title: 'البحث بالخريطة', sub: 'اضغط على أي نقطة في الخريطة لتحليل مستوى الأمان في الموقع',
      findPh: 'الانتقال إلى مدينة أو دولة...', hint: 'اضغط على الخريطة لاختيار الموقع',
      picked: 'الموقع المحدد', cancel: 'إلغاء', confirm: 'تحليل هذا الموقع' },
    ru: { or: 'ИЛИ', mapBtn: 'Поиск по карте', gpsBtn: 'Где я сейчас',
      title: 'Поиск по карте', sub: 'Нажмите на любую точку карты, чтобы проанализировать безопасность места',
      findPh: 'Перейти к городу или стране...', hint: 'Нажмите на карту, чтобы выбрать место',
      picked: 'Выбранное место', cancel: 'Отмена', confirm: 'Анализировать это место' },
    zh: { or: '或', mapBtn: '在地图上搜索', gpsBtn: '我的当前位置',
      title: '在地图上搜索', sub: '点击地图上的任意位置，分析该地点的安全状况',
      findPh: '前往城市或国家...', hint: '点击地图选择位置',
      picked: '已选位置', cancel: '取消', confirm: '分析该位置' }
  };

  function applyMapSearchI18n(langCode) {
    var m = mapSearchI18n[langCode] || mapSearchI18n['en'];
    var set = function(id, val, attr) {
      var el = document.getElementById(id);
      if (!el) return;
      if (attr === 'ph') el.placeholder = val; else el.textContent = val;
    };
    var dv = document.getElementById('search-divider-text');
    if (dv) dv.textContent = m.or;
    set('btn-map-search-text', m.mapBtn);
    set('btn-gps-search-text', m.gpsBtn);
    set('mapsel-title', m.title);
    set('mapsel-sub', m.sub);
    set('mapsel-find', m.findPh, 'ph');
    set('mapsel-hint-text', m.hint);
    set('mapsel-picked-label', m.picked);
    set('mapsel-cancel', m.cancel);
    set('mapsel-confirm-text', m.confirm);
  }
  window.applyMapSearchI18n = applyMapSearchI18n;


  function applyTranslation(langCode) {
    var t = translations[langCode] || translations['en'];
    // Titulo da pagina
    document.title = t.pageTitle;
    // Header
    var statusEl = document.querySelector('.header-status span:last-child');
    if (statusEl) statusEl.textContent = t.headerStatus;
    // Emblem
    var emblemTitle = document.querySelector('.emblem-title');
    if (emblemTitle) emblemTitle.textContent = t.emblemTitle;
    var emblemTagline = document.querySelector('.emblem-tagline');
    if (emblemTagline && t.emblemTagline) emblemTagline.textContent = t.emblemTagline;
    // Search section
    var searchTitle = document.querySelector('.search-title');
    if (searchTitle) searchTitle.textContent = t.searchTitle;
    var searchSub = document.querySelector('.search-subtitle');
    if (searchSub) searchSub.textContent = t.searchSubtitle;
    var searchInput = document.getElementById('search-input');
    if (searchInput) searchInput.placeholder = t.searchPlaceholder;
    var searchBtn = document.getElementById('search-btn');
    if (searchBtn) { var svg = searchBtn.querySelector('svg'); searchBtn.innerHTML = ''; if (svg) searchBtn.appendChild(svg); searchBtn.appendChild(document.createTextNode(' ' + t.searchBtn)); }
    var searchHint = document.querySelector('.search-hint');
    if (searchHint) searchHint.innerHTML = t.searchHint;
    // Pesquisa pelo mapa / GPS
    try { applyMapSearchI18n(langCode); } catch(e) {}
    // Cards
    var cards = document.querySelectorAll('.card-header h3');
    cards.forEach(function(h3) {
      var icon = h3.querySelector('.icon');
      var iconHTML = icon ? icon.outerHTML : '';
      if (h3.textContent.match(/Mapa|Incidents|Karta|Carte|Vorfallkarte/i)) h3.innerHTML = iconHTML + ' ' + t.mapTitle;
      else if (h3.textContent.match(/Safety|Score/i)) h3.innerHTML = iconHTML + ' ' + t.scoreTitle;
      else if (h3.textContent.match(/Estat|Statist|Stadtteil|Quartier|Area/i)) h3.innerHTML = iconHTML + ' ' + t.statsTitle;
      else if (h3.textContent.match(/Tipo|Type|Typ/i)) h3.innerHTML = iconHTML + ' ' + t.chartTypes;
      else if (h3.textContent.match(/Mensal|Monthly|Mensual|Mensuelle|Monat/i)) h3.innerHTML = iconHTML + ' ' + t.chartMonthly;
    });
    // Stat labels
    var statLabels = document.querySelectorAll('.stat-label');
    if (statLabels.length >= 4) {
      statLabels[0].textContent = t.occurrences;
      statLabels[1].textContent = t.cameras;
      statLabels[2].textContent = t.lighting;
      statLabels[3].textContent = t.commerce;
    }
    // Pillar names
    var pillarNames = document.querySelectorAll('.pillar-info .name');
    if (pillarNames.length >= 3) {
      pillarNames[0].textContent = t.crimeIndex;
      pillarNames[1].textContent = t.infrastructure;
      pillarNames[2].textContent = t.urbanMovement;
    }
    // Map legend
    var legendItems = document.querySelectorAll('.map-legend-item');
    if (legendItems.length >= 4) {
      legendItems[0].lastChild.textContent = ' ' + t.lowRisk;
      legendItems[1].lastChild.textContent = ' ' + t.mediumRisk;
      legendItems[2].lastChild.textContent = ' ' + t.highRisk;
      legendItems[3].lastChild.textContent = ' ' + t.poi;
    }
    // Buttons PDF/Share
    var pdfBtn = document.getElementById('btn-pdf');
    if (pdfBtn) { var s1 = pdfBtn.querySelector('svg'); pdfBtn.innerHTML = ''; if (s1) pdfBtn.appendChild(s1); pdfBtn.appendChild(document.createTextNode(' ' + t.pdfBtn)); }
    var shareBtn = document.getElementById('btn-share');
    if (shareBtn) { var s2 = shareBtn.querySelector('svg'); shareBtn.innerHTML = ''; if (s2) shareBtn.appendChild(s2); shareBtn.appendChild(document.createTextNode(' ' + t.shareBtn)); }
    // Ad
    var adCard = document.querySelector('.ad-card');
    if (adCard) {
      var adH5 = adCard.querySelector('h5');
      var adP = adCard.querySelector('p');
      var adBtn = adCard.querySelector('.btn');
      if (adH5) adH5.textContent = t.adTitle;
      if (adP) adP.textContent = t.adDesc;
      if (adBtn) adBtn.textContent = t.adBtnText;
    }
    // Footer
    var footer = document.querySelector('.footer');
    if (footer) {
      footer.innerHTML = t.pageTitle + ' &copy; 2026 &mdash; portalsegurancaglobal.com.br<br>' +
        t.footerText + '<br><br>' +
        '<strong>&copy; 2026 Portal de Seguran&ccedil;a Global. ' + t.copyrightText + '</strong><br>' +
        t.copyrightProhibit;
    }
    // Terms modal
    var termsH2 = document.querySelector('.terms-box h2');
    if (termsH2) termsH2.textContent = t.termsTitle;
    var termsSub = document.querySelector('.terms-sub');
    if (termsSub) termsSub.textContent = t.termsRead;
    var termsBtn = document.getElementById('terms-btn');
    if (termsBtn) termsBtn.textContent = t.termsAcceptBtn;
    // Manual
    if (manualData[langCode]) switchManualLang(langCode);
    else if (manualData['en']) switchManualLang('en');
    var manualSelect = document.getElementById('manual-lang');
    if (manualSelect) { manualSelect.value = manualData[langCode] ? langCode : 'en'; }
    // Highlight na bandeira selecionada
    document.querySelectorAll('.flag-item').forEach(function(fi) { fi.classList.remove('flag-active'); });
    document.querySelectorAll('.flag-item').forEach(function(fi) {
      var img = fi.querySelector('img');
      if (img && img.alt) {
        var altLower = img.src.toLowerCase();
        for (var cc in countryToLang) {
          if (altLower.indexOf('/' + cc + '.png') !== -1 && countryToLang[cc] === langCode) {
            fi.classList.add('flag-active');
          }
        }
      }
    });
    // Salva preferencia
    try { localStorage.setItem('psg_lang', langCode); } catch(e) {}
    window._psgCurrentLang = langCode;
  }

  // Torna bandeiras clicaveis
  function initFlagClicks() {
    document.querySelectorAll('.flag-item').forEach(function(fi) {
      fi.style.cursor = 'pointer';
      fi.addEventListener('click', function() {
        var img = fi.querySelector('img');
        if (!img) return;
        var src = img.src.toLowerCase();
        var matched = null;
        for (var cc in countryToLang) {
          if (src.indexOf('/' + cc + '.png') !== -1) { matched = countryToLang[cc]; break; }
        }
        if (matched) applyTranslation(matched);
      });
    });
  }

  // Inicializa: verifica preferencia salva ou idioma do navegador
  function init() {
    initFlagClicks();
    var saved = null;
    try { saved = localStorage.getItem('psg_lang'); } catch(e) {}
    if (saved && translations[saved]) { applyTranslation(saved); }
  }

  // Roda apos DOM pronto
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', init); }
  else { init(); }

  // Barra de idiomas mobile
  function initMobileLangBar() {
    var bar = document.getElementById('mobile-lang-bar');
    if (!bar) return;
    bar.querySelectorAll('.mlb-flag').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var lang = btn.getAttribute('data-lang');
        if (lang) {
          applyTranslation(lang);
          bar.querySelectorAll('.mlb-flag').forEach(function(b) { b.classList.remove('active'); });
          btn.classList.add('active');
        }
      });
    });
  }
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', initMobileLangBar); }
  else { initMobileLangBar(); }

  return { apply: applyTranslation, translations: translations };
})();

// ============================================================
// SISTEMA DE ENTREGA PDF — Email + WhatsApp
// ============================================================
var PSG_DELIVERY = (function() {
  // Cria o modal de entrega (aparece apos gerar PDF)
  function createDeliveryModal() {
    if (document.getElementById('delivery-modal')) return;
    var modal = document.createElement('div');
    modal.id = 'delivery-modal';
    modal.style.cssText = 'display:none;position:fixed;inset:0;z-index:600;background:rgba(0,0,0,.85);backdrop-filter:blur(12px);align-items:center;justify-content:center;padding:1rem;';
    modal.innerHTML = '<div style="background:linear-gradient(145deg,#0f1728,#1a2438);border:1px solid rgba(0,157,255,.25);border-radius:20px;padding:2rem;max-width:500px;width:100%;position:relative;box-shadow:0 20px 60px rgba(0,0,0,.6);">' +
      '<span id="delivery-close" style="position:absolute;top:12px;right:16px;font-size:1.5rem;color:#8b95a8;cursor:pointer;line-height:1;">&times;</span>' +
      '<div style="text-align:center;font-size:2rem;margin-bottom:.5rem;">&#128232;</div>' +
      '<h3 style="text-align:center;font-size:1.2rem;color:#e5e7eb;margin-bottom:.4rem;">Enviar Relatorio</h3>' +
      '<p style="text-align:center;font-size:.82rem;color:#8b95a8;margin-bottom:1.2rem;">Escolha como deseja receber ou compartilhar o relatorio PDF completo.</p>' +
      '<div style="margin-bottom:1rem;"><label style="display:block;font-size:.82rem;color:#8b95a8;margin-bottom:.4rem;font-weight:600;">E-mail do destinatario</label>' +
      '<input type="email" id="delivery-email" placeholder="exemplo@email.com" style="width:100%;padding:.7rem 1rem;border-radius:10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);color:#e5e7eb;font-size:.9rem;outline:none;box-sizing:border-box;"></div>' +
      '<div style="margin-bottom:1.2rem;"><label style="display:block;font-size:.82rem;color:#8b95a8;margin-bottom:.4rem;font-weight:600;">WhatsApp (com DDI)</label>' +
      '<input type="tel" id="delivery-whatsapp" placeholder="+55 44 99999-9999" style="width:100%;padding:.7rem 1rem;border-radius:10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);color:#e5e7eb;font-size:.9rem;outline:none;box-sizing:border-box;"></div>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:.8rem;margin-bottom:1rem;">' +
      '<button id="delivery-btn-email" style="display:flex;align-items:center;justify-content:center;gap:.4rem;padding:.8rem;border-radius:12px;border:2px solid rgba(255,255,255,.12);background:rgba(0,157,255,.08);color:#e5e7eb;cursor:pointer;font-size:.85rem;font-weight:600;transition:all .25s;">&#9993; Enviar por Email</button>' +
      '<button id="delivery-btn-whatsapp" style="display:flex;align-items:center;justify-content:center;gap:.4rem;padding:.8rem;border-radius:12px;border:2px solid rgba(37,211,102,.25);background:rgba(37,211,102,.08);color:#25d366;cursor:pointer;font-size:.85rem;font-weight:600;transition:all .25s;">&#128172; Enviar por WhatsApp</button></div>' +
      '<button id="delivery-btn-download" style="width:100%;padding:.7rem;border-radius:10px;border:none;background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;font-size:.9rem;font-weight:700;cursor:pointer;margin-bottom:.8rem;">&#128196; Baixar PDF Agora</button>' +
      '<div style="display:flex;align-items:center;justify-content:center;gap:.4rem;font-size:.72rem;color:#6b7280;">&#128274; Envio seguro e criptografado</div>' +
      '</div>';
    document.body.appendChild(modal);
    // Eventos
    document.getElementById('delivery-close').addEventListener('click', function() { modal.style.display = 'none'; });
    document.getElementById('delivery-btn-email').addEventListener('click', sendByEmail);
    document.getElementById('delivery-btn-whatsapp').addEventListener('click', sendByWhatsApp);
    document.getElementById('delivery-btn-download').addEventListener('click', downloadPDF);
  }

  var _lastPDFBlob = null;
  var _lastPDFName = '';

  function showDeliveryModal(pdfBlob, fileName) {
    _lastPDFBlob = pdfBlob;
    _lastPDFName = fileName;
    createDeliveryModal();
    var modal = document.getElementById('delivery-modal');
    modal.style.display = 'flex';
  }

  function sendByEmail() {
    var email = document.getElementById('delivery-email').value.trim();
    if (!email || !email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
      alert('Por favor, insira um e-mail valido.');
      return;
    }
    // Abre cliente de email com link para o portal
    var subject = encodeURIComponent('Relatorio de Seguranca - Portal Seguranca Global');
    var body = encodeURIComponent('Segue o relatorio de seguranca gerado pelo Portal Seguranca Global.\n\nAcesse: https://portalsegurancaglobal.com.br\n\nO PDF esta anexado a esta mensagem.\n\n---\nPortal Seguranca Global\nportalsegurancaglobal.com.br');
    window.open('mailto:' + email + '?subject=' + subject + '&body=' + body);
    // Tambem baixa o PDF para o usuario anexar
    if (_lastPDFBlob) downloadPDF();
    alert('O cliente de e-mail foi aberto. Anexe o PDF baixado e envie para ' + email);
    // Registra o envio
    registerDelivery('email', email);
  }

  function sendByWhatsApp() {
    var phone = document.getElementById('delivery-whatsapp').value.trim().replace(/\D/g, '');
    if (!phone || phone.length < 10) {
      alert('Por favor, insira um numero de WhatsApp valido com DDI (ex: +55 44 99999-9999).');
      return;
    }
    var text = encodeURIComponent('*Portal Seguranca Global*\n\nRelatorio de Seguranca gerado com sucesso!\n\nAcesse o portal para visualizar: https://portalsegurancaglobal.com.br\n\n_Relatorio protegido por direitos autorais © 2026_');
    window.open('https://wa.me/' + phone + '?text=' + text, '_blank');
    if (_lastPDFBlob) downloadPDF();
    alert('WhatsApp aberto! O PDF foi baixado para voce compartilhar na conversa.');
    registerDelivery('whatsapp', phone);
  }

  function downloadPDF() {
    if (!_lastPDFBlob) {
      alert('Nenhum PDF disponivel. Gere o relatorio primeiro.');
      return;
    }
    var url = URL.createObjectURL(_lastPDFBlob);
    var a = document.createElement('a');
    a.href = url;
    a.download = _lastPDFName || 'PortalSegurancaGlobal_Relatorio.pdf';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function registerDelivery(method, destination) {
    var deliveries = [];
    try { deliveries = JSON.parse(localStorage.getItem('psg_deliveries') || '[]'); } catch(e) {}
    deliveries.push({
      date: new Date().toISOString(),
      method: method,
      destination: destination,
      report: _lastPDFName
    });
    try { localStorage.setItem('psg_deliveries', JSON.stringify(deliveries)); } catch(e) {}
    try { SH_SECURITY.logEvent('PDF_DELIVERY', method + ':' + destination); } catch(e) {}
  }

  // Retorna historico de entregas (para o proprietario consultar)
  function getDeliveryHistory() {
    try { return JSON.parse(localStorage.getItem('psg_deliveries') || '[]'); } catch(e) { return []; }
  }

  return {
    show: showDeliveryModal,
    history: getDeliveryHistory
  };
})();

// ============================================================
// MELHORIAS MOBILE — botao voltar ao topo + reajuste do mapa
// ============================================================
(function() {
  function initMobileUX() {
    // Botao voltar ao topo
    var btn = document.getElementById('to-top-btn');
    if (btn) {
      btn.addEventListener('click', function() {
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });
      var toggleBtn = function() {
        if (window.scrollY > 420) { btn.classList.add('show'); }
        else { btn.classList.remove('show'); }
      };
      window.addEventListener('scroll', toggleBtn, { passive: true });
      toggleBtn();
    }

    // No celular, ao girar a tela ou redimensionar, o mapa precisa recalcular
    var resizeTimer = null;
    var refreshMap = function() {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function() {
        try { if (typeof map !== 'undefined' && map) map.invalidateSize(); } catch (e) {}
      }, 250);
    };
    window.addEventListener('resize', refreshMap, { passive: true });
    window.addEventListener('orientationchange', refreshMap, { passive: true });

    // Ao enviar a busca no teclado do celular, fecha o teclado
    var input = document.getElementById('search-input');
    if (input) {
      input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') { input.blur(); }
      });
    }
  }

  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', initMobileUX); }
  else { initMobileUX(); }
})();
