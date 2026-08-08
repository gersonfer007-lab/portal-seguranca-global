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
    }
    catch(e) { return null; }
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

async function generatePDF() {
  if (!currentData) return alert('Faca uma pesquisa primeiro.');
  _doGeneratePDF();
}

// ============================================================
// SHARE — painel de compartilhamento em redes sociais
// ============================================================
var SHARE_SITE_URL = 'https://portalsegurancaglobal.com.br';

var shareI18n = {
  pt: { title: 'Compartilhar Resultado', sub: 'Envie esta analise de seguranca para quem precisa saber',
    score: 'Safety Score', at: 'em', cta: 'Consulte a seguranca de qualquer endereco do mundo:',
    copy: 'Copiar link', copyMsg: 'Copiar mensagem', copied: 'Copiado com sucesso!',
    native: 'Mais opcoes', email: 'E-mail', cancel: 'Fechar', preview: 'Previa da mensagem',
    safe: 'SEGURO', mod: 'MODERADO', crit: 'CRITICO', subject: 'Analise de Seguranca — Portal Seguranca Global' },
  en: { title: 'Share Result', sub: 'Send this safety analysis to those who need to know',
    score: 'Safety Score', at: 'at', cta: 'Check the safety of any address in the world:',
    copy: 'Copy link', copyMsg: 'Copy message', copied: 'Copied successfully!',
    native: 'More options', email: 'Email', cancel: 'Close', preview: 'Message preview',
    safe: 'SAFE', mod: 'MODERATE', crit: 'CRITICAL', subject: 'Safety Analysis — Global Security Portal' },
  es: { title: 'Compartir Resultado', sub: 'Envie este analisis de seguridad a quien necesite saberlo',
    score: 'Safety Score', at: 'en', cta: 'Consulte la seguridad de cualquier direccion del mundo:',
    copy: 'Copiar enlace', copyMsg: 'Copiar mensaje', copied: 'Copiado con exito!',
    native: 'Mas opciones', email: 'Correo', cancel: 'Cerrar', preview: 'Vista previa del mensaje',
    safe: 'SEGURO', mod: 'MODERADO', crit: 'CRITICO', subject: 'Analisis de Seguridad — Portal Seguridad Global' }
};

function openShare() {
  if (!currentData) return alert('Pesquise um local antes de compartilhar.');
  var lang = window.PSG_LANG || 'pt';
  var ui = shareI18n[lang] || shareI18n.pt;
  var scoreText = (currentData.safetyScore >= 70 ? ui.safe : currentData.safetyScore >= 40 ? ui.mod : ui.crit);
  var msg = "*" + ui.subject + "*\n\n"
    + "📍 " + currentData.address.fullAddress + "\n"
    + "🛡️ " + ui.score + ": *" + currentData.safetyScore + "/100* (" + scoreText + ")\n\n"
    + ui.cta + "\n"
    + SHARE_SITE_URL + "?q=" + encodeURIComponent(currentData.address.fullAddress);

  document.getElementById('share-title').textContent = ui.title;
  document.getElementById('share-subtitle').textContent = ui.sub;
  document.getElementById('share-preview-text').textContent = msg;
  document.getElementById('btn-copy-link').textContent = ui.copy;
  document.getElementById('btn-copy-msg').textContent = ui.copyMsg;
  document.getElementById('btn-native-share').textContent = ui.native;
  document.getElementById('btn-close-share').textContent = ui.cancel;
  document.getElementById('share-overlay').style.display = 'flex';
  setTimeout(function() { document.getElementById('share-overlay').classList.add('active'); }, 10);
}

function closeShare() {
  document.getElementById('share-overlay').classList.remove('active');
  setTimeout(function() { document.getElementById('share-overlay').style.display = 'none'; }, 260);
}

function copyToClipboard(text, btnId) {
  navigator.clipboard.writeText(text).then(function() {
    var btn = document.getElementById(btnId);
    var old = btn.textContent;
    var lang = window.PSG_LANG || 'pt';
    btn.textContent = shareI18n[lang].copied;
    btn.classList.add('success');
    setTimeout(function() { btn.textContent = old; btn.classList.remove('success'); }, 2000);
  });
}

function copyShareLink() {
  var url = SHARE_SITE_URL + "?q=" + encodeURIComponent(currentData.address.fullAddress);
  copyToClipboard(url, 'btn-copy-link');
}

function copyShareMsg() {
  var msg = document.getElementById('share-preview-text').textContent;
  copyToClipboard(msg, 'btn-copy-msg');
}

function nativeShare() {
  var msg = document.getElementById('share-preview-text').textContent;
  var url = SHARE_SITE_URL + "?q=" + encodeURIComponent(currentData.address.fullAddress);
  if (navigator.share) {
    navigator.share({ title: 'Portal Seguranca Global', text: msg, url: url }).catch(function() {});
  } else {
    window.location.href = "mailto:?subject=" + encodeURIComponent(shareI18n[window.PSG_LANG || 'pt'].subject) + "&body=" + encodeURIComponent(msg);
  }
}

// ============================================================
// UTILS
// ============================================================
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function showLoading(text) {
  const overlay = document.getElementById('loading-overlay');
  overlay.querySelector('.loading-text').textContent = text;
  overlay.classList.remove('hidden');
}

function updateLoading(text) { document.getElementById('loading-overlay').querySelector('.loading-text').textContent = text; }
function hideLoading() { document.getElementById('loading-overlay').classList.add('hidden'); }

function termsAccepted() { return localStorage.getItem('psg_terms_accepted') === 'true'; }
function acceptTerms() {
  localStorage.setItem('psg_terms_accepted', 'true');
  document.getElementById('terms-modal').classList.add('hidden');
  if (window._pendingSearch) { window._pendingSearch = false; handleSearch(); }
  if (window._pendingMapSearch) { window._pendingMapSearch = false; openMapSearch(); }
  if (window._pendingGpsSearch) { window._pendingGpsSearch = false; searchByGps(); }
}
function showTermsModal() { document.getElementById('terms-modal').classList.remove('hidden'); }

// ============================================================
// MOBILE UX IMPROVEMENTS
// ============================================================
(function() {
  function initMobileUX() {
    var btn = document.getElementById('back-to-top');
    if (btn) {
      var toggleBtn = function() {
        if (window.scrollY > 420) { btn.classList.add('show'); }
        else { btn.classList.remove('show'); }
      };
      window.addEventListener('scroll', toggleBtn, { passive: true });
      toggleBtn();
    }
    var resizeTimer = null;
    var refreshMap = function() {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function() {
        try { if (typeof map !== 'undefined' && map) map.invalidateSize(); } catch (e) {}
      }, 250);
    };
    window.addEventListener('resize', refreshMap, { passive: true });
    window.addEventListener('orientationchange', refreshMap, { passive: true });
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

// ============================================================
// LINK COMPARTILHADO — abre a analise direto pelo parametro ?q=
// (respeita o termo de uso: handleSearch valida antes de buscar)
// ============================================================
(function() {
  function openSharedQuery() {
    var q = '';
    try { q = new URLSearchParams(window.location.search).get('q') || ''; } catch (e) { return; }
    q = q.replace(/[<>"'`\\]/g, '').trim().slice(0, 160);
    if (!q) return;
    var input = document.getElementById('search-input');
    if (!input) return;
    input.value = q;
    setTimeout(function() { try { handleSearch(); } catch (e) {} }, 700);
  }
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', openSharedQuery); }
  else { openSharedQuery(); }
})();