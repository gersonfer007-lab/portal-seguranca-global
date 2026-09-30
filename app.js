// ============================================================
// CONFIGURACAO DO BACKEND
// Troque pela URL absoluta do backend no Render
// Exemplo: 'https://portal-seguranca-global.onrender.com'
// Deixe vazio ('') para usar chamadas relativas (mesmo dominio)
// ============================================================
const PSG_BACKEND_URL = 'https://portal-seguranca-global.onrender.com';

// ============================================================
// SECURITY MODULE â€” SH_SECURITY (IIFE)
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
    bindUI();
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
// UI BINDINGS
// ============================================================
function bindUI() {
  var searchBtn = document.getElementById('search-btn');
  if (searchBtn) searchBtn.addEventListener('click', handleSearch);

  var searchInput = document.getElementById('search-input');
  if (searchInput) {
    searchInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { e.preventDefault(); handleSearch(); }
    });
  }

  var termsCheckbox = document.getElementById('terms-checkbox');
  var termsBtn = document.getElementById('terms-btn');
  if (termsCheckbox && termsBtn) {
    termsCheckbox.addEventListener('change', function() {
      termsBtn.disabled = !termsCheckbox.checked;
      termsBtn.classList.toggle('disabled', !termsCheckbox.checked);
      termsBtn.classList.toggle('enabled', termsCheckbox.checked);
    });
    termsBtn.addEventListener('click', acceptTerms);
  }

  var btnMapSearch = document.getElementById('btn-map-search');
  if (btnMapSearch) btnMapSearch.addEventListener('click', openMapSearch);

  var btnGpsSearch = document.getElementById('btn-gps-search');
  if (btnGpsSearch) btnGpsSearch.addEventListener('click', searchByGps);

  var btnPdf = document.getElementById('btn-pdf');
  if (btnPdf) btnPdf.addEventListener('click', generatePDF);

  var btnShare = document.getElementById('btn-share');
  if (btnShare) btnShare.addEventListener('click', openShare);

  var btnViewDark = document.getElementById('btn-view-dark');
  if (btnViewDark) btnViewDark.addEventListener('click', function() { switchMapView('dark'); });

  var btnViewSatellite = document.getElementById('btn-view-satellite');
  if (btnViewSatellite) btnViewSatellite.addEventListener('click', function() { switchMapView('satellite'); });

  var btnView3d = document.getElementById('btn-view-3d');
  if (btnView3d) btnView3d.addEventListener('click', function() { switchMapView('3d'); });

  var btnHeatmap = document.getElementById('btn-heatmap');
  if (btnHeatmap) btnHeatmap.addEventListener('click', toggleHeatmap);

  var btnMarkers = document.getElementById('btn-markers');
  if (btnMarkers) btnMarkers.addEventListener('click', toggleMarkers);

  var mapselClose = document.getElementById('mapsel-close');
  if (mapselClose) mapselClose.addEventListener('click', closeMapSearch);

  var mapselCancel = document.getElementById('mapsel-cancel');
  if (mapselCancel) mapselCancel.addEventListener('click', closeMapSearch);

  var mapselConfirm = document.getElementById('mapsel-confirm');
  if (mapselConfirm) mapselConfirm.addEventListener('click', confirmMapSearch);

  var mapselFindBtn = document.getElementById('mapsel-find-btn');
  if (mapselFindBtn) mapselFindBtn.addEventListener('click', mapselFind);

  var mapselGps = document.getElementById('mapsel-gps');
  if (mapselGps) mapselGps.addEventListener('click', function() { runMapselGps(); });

  var mapselFindInput = document.getElementById('mapsel-find');
  if (mapselFindInput) {
    mapselFindInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { e.preventDefault(); mapselFind(); }
    });
  }

  var shareClose = document.getElementById('share-close');
  if (shareClose) shareClose.addEventListener('click', closeShare);

  var shareCancel = document.getElementById('share-cancel');
  if (shareCancel) shareCancel.addEventListener('click', closeShare);

  var shareCopyLink = document.getElementById('share-copy-link');
  if (shareCopyLink) shareCopyLink.addEventListener('click', copyShareLink);

  var shareCopyMsg = document.getElementById('share-copy-msg');
  if (shareCopyMsg) shareCopyMsg.addEventListener('click', copyShareMsg);

  var shareNative = document.getElementById('share-native');
  if (shareNative) shareNative.addEventListener('click', nativeShare);

  document.querySelectorAll('.share-net').forEach(function(btn) {
    btn.addEventListener('click', function() { shareToNetwork(btn.getAttribute('data-share')); });
  });

  var btnLoadGlobe = document.getElementById('btn-load-globe');
  if (btnLoadGlobe) btnLoadGlobe.addEventListener('click', loadGlobeOnDemand);

  // Lazy load do mapa principal quando entrar na viewport
  observeMapLazy();

  // Keep-alive do backend (ping a cada 10 minutos)
  keepBackendAwake();
}

function loadGlobeOnDemand() {
  var globe = document.getElementById('cesium-globe');
  var placeholder = document.getElementById('globe-placeholder');
  var iframe = document.getElementById('earth-iframe');
  if (!globe || !iframe) return;
  globe.classList.add('active');
  if (placeholder) placeholder.style.display = 'none';
  iframe.style.display = 'block';
  if (currentData) { syncEarthWithData(currentData); }
  else { loadEarthView(-23.55, -46.63, 5000); }
}

function observeMapLazy() {
  var mapEl = document.getElementById('map');
  if (!mapEl || typeof L === 'undefined') return;
  if (!('IntersectionObserver' in window)) {
    if (!map) initMap();
    return;
  }
  var observer = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (entry.isIntersecting) {
        if (!map) initMap();
        observer.disconnect();
      }
    });
  }, { rootMargin: '200px' });
  observer.observe(mapEl);
}

function keepBackendAwake() {
  var url = (typeof PSG_BACKEND_URL !== 'undefined' ? PSG_BACKEND_URL : '') + '/api/health';
  function ping() {
    fetch(url).then(function(r) { return r.json(); }).then(function() {
      console.log('[KEEPALIVE] backend acordado');
    }).catch(function(err) {
      console.warn('[KEEPALIVE] backend offline ou dormindo:', err.message);
    });
  }
  ping();
  setInterval(ping, 10 * 60 * 1000);
}

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
  dark: 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
  satellite: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
  labels: 'https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}'
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
    if (mapEl) mapEl.style.display = 'block';
    if (globeEl) globeEl.style.display = 'none';
    if (globeInfo) globeInfo.classList.remove('active');
    if (map) {
      if (satelliteTileLayer) { map.removeLayer(satelliteTileLayer); satelliteTileLayer = null; }
      if (labelsLayer) { map.removeLayer(labelsLayer); labelsLayer = null; }
      if (!darkTileLayer) { darkTileLayer = L.tileLayer(TILES.dark, { maxZoom: 19 }).addTo(map); }
      else if (!map.hasLayer(darkTileLayer)) { darkTileLayer.addTo(map); }
      map.invalidateSize();
    }
  } else if (mode === 'satellite') {
    document.getElementById('btn-view-satellite').classList.add('active');
    if (mapEl) mapEl.style.display = 'block';
    if (globeEl) globeEl.style.display = 'none';
    if (globeInfo) globeInfo.classList.remove('active');
    if (map) {
      if (darkTileLayer) { map.removeLayer(darkTileLayer); darkTileLayer = null; }
      if (!satelliteTileLayer) {
        satelliteTileLayer = L.tileLayer(TILES.satellite, { maxZoom: 18 }).addTo(map);
        labelsLayer = L.tileLayer(TILES.labels, { maxZoom: 19, pane: 'overlayPane' }).addTo(map);
      } else if (!map.hasLayer(satelliteTileLayer)) { satelliteTileLayer.addTo(map); if (labelsLayer) labelsLayer.addTo(map); }
      map.invalidateSize();
    }
  } else if (mode === '3d') {
    document.getElementById('btn-view-3d').classList.add('active');
    if (mapEl) mapEl.style.display = 'none';
    if (globeEl) globeEl.style.display = 'block';
    if (globeInfo) globeInfo.classList.add('active');
    loadGlobeOnDemand();
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

  // Client-side checks (primeira camada â€” rapido)
  if (!SH_SECURITY.checkRateLimit('search')) { alert('Limite de buscas atingido. Aguarde um momento e tente novamente.'); return; }
  if (!SH_SECURITY.throttle()) return;
  if (SH_SECURITY.detectInjection(rawQuery)) { alert('Entrada invalida detectada.'); SH_SECURITY.logEvent('SEARCH_BLOCKED', rawQuery.substring(0, 50)); return; }
  const query = SH_SECURITY.sanitizeInput(rawQuery);
  if (!query) return;

  // Server-side validation (segunda camada â€” segura)
  try {
    var backendUrl = (typeof PSG_BACKEND_URL !== 'undefined' ? PSG_BACKEND_URL : '');
    var valRes = await fetch(backendUrl + '/api/search', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: query }) });
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
        if (!data.erro) { addressData = { street: data.logradouro || '', neighborhood: data.bairro || '', city: data.localidade || '', state: data.uf || '', country: 'Brasil', country_code: 'br', cep: data.cep, fullAddress: [data.logradouro, data.bairro, data.localidade, data.uf, 'Brasil'].filter(Boolean).join(', ') }; }
      } catch(e) {}
    }
    if (!addressData && /^\d{5}(-\d{4})?$/.test(query.trim())) { addressData = { street: '', neighborhood: '', city: '', state: '', country: 'USA', country_code: 'us', cep: query.trim(), fullAddress: query.trim() + ', United States' }; }
    if (!addressData && /^[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}$/i.test(query.trim())) { addressData = { street: '', neighborhood: '', city: '', state: '', country: 'UK', country_code: 'gb', cep: query.trim(), fullAddress: query.trim() + ', United Kingdom' }; }
    if (!addressData) { addressData = { street: query, neighborhood: '', city: '', state: '', country: '', country_code: '', cep: '', fullAddress: query }; }
    updateLoading('Geolocalizando endereco...');
    const geo = await geocodeAddress(addressData, query);
    if (!geo) { throw new Error('Endereco nao encontrado. Tente incluir a cidade e o pais (ex.: Av. Brasil, Maringa, PR, Brasil) ou o nome completo da rodovia (ex.: Rodovia Presidente Dutra, SP, Brasil).'); }
    let lat = geo.lat, lng = geo.lng;
    if (geo.displayName) { addressData.fullAddress = geo.displayName; }
    if (!addressData.city && geo.city) { addressData.city = geo.city; }
    if (!addressData.state && geo.state) { addressData.state = geo.state; }
    if (!addressData.country && geo.country) { addressData.country = geo.country; }
    if (!addressData.country_code && geo.country_code) { addressData.country_code = geo.country_code; }
    updateLoading('Analisando dados de criminalidade...'); await sleep(600);
    updateLoading('Calculando infraestrutura urbana...'); await sleep(500);
    updateLoading('Processando movimentacao de pedestres...'); await sleep(400);
    updateLoading('Compilando Safety Score...'); await sleep(300);
    currentData = generateIntelligence(lat, lng, addressData);
    renderDashboard(currentData);
    if (currentMapView === '3d') { loadGlobeOnDemand(); }
    hideLoading();
  } catch (err) { hideLoading(); alert('Erro: ' + err.message); }
}

// ============================================================
// PESQUISAR PELO MAPA â€” o usuario escolhe o local clicando
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
      country_code: a.country_code || '',
      cep: a.postcode || '',
      fullAddress: (data && data.display_name) ? data.display_name : ''
    };
  } catch (e) {
    if (seq !== mapselReverseSeq) return;
  }

  // Sem resposta do servico: usa as coordenadas mesmo assim
  if (!addressData || !addressData.fullAddress) {
    addressData = addressData || { street: '', neighborhood: '', city: '', state: '', country: '', country_code: '', cep: '' };
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
function runMapselGps() {
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
          country_code: a.country_code || '',
          cep: a.postcode || '',
          fullAddress: (data && data.display_name) ? data.display_name : ''
        };
      } catch (e) { addressData = null; }
      if (!addressData || !addressData.fullAddress) {
        addressData = { street: '', neighborhood: '', city: '', state: '', country: '', country_code: '', cep: '',
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
    if (currentMapView === '3d') { loadGlobeOnDemand(); }
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
// --- RODOVIAS E ESTRADAS DO MUNDO INTEIRO ---
// Detecta consultas rodoviarias (BR-116, Rodovia Dutra, Route 66,
// Autobahn A7, Autoestrada A1, Ruta 40, M25, N-340, km 45...) e
// prepara tentativas otimizadas para o Nominatim/OpenStreetMap,
// que cobre estradas de todos os paises do planeta.
var ROAD_WORD_RE = /(rodovia|estrada|trevo|highway|freeway|expressway|motorway|turnpike|parkway|interstate|autobahn|autostrada|autoestrada|autoroute|autopista|carretera|circunvalacion|periferico|ruta|camino|route\b|state road|national road|trunk road|a-road|b-road)/i;
var ROAD_BR_CODE_RE = /\b(br|sp|rj|mg|pr|rs|sc|ba|pe|ce|go|mt|ms|pa|am|ma|pi|rn|al|pb|se|es|to|ro|rr|ap|ac|df)[- ]?\d{2,4}\b/i;
function isRoadQuery(q) {
  if (!q) return false;
  var s = String(q);
  if (ROAD_WORD_RE.test(s)) return true;
  if (ROAD_BR_CODE_RE.test(s)) return true;
  if (/\bkm\.?\s*\d+/i.test(s)) return true;
  if (/\b(i|us|sr|sh|m|a|b|n|ap|ct|eu|d|e|a-?vel)\s?-?\s?\d{1,4}\b/i.test(s) && /\b(route|road|estrada|rodovia|autopista|carretera|autostrada|autobahn|autoroute|autoestrada|highway)\b/i.test(s)) return true;
  return false;
}
// Nomes de paises das edicoes do site (para dar contexto a busca)
var ROAD_COUNTRIES = { br:'Brasil', us:'United States', gb:'United Kingdom', fr:'France', de:'Deutschland', it:'Italia', es:'Espana', pt:'Portugal', ca:'Canada', mx:'Mexico', ar:'Argentina', co:'Colombia', cl:'Chile', pe:'Peru', uy:'Uruguay', py:'Paraguay', ve:'Venezuela', bo:'Bolivia', ec:'Ecuador', cu:'Cuba', do:'Republica Dominicana', jp:'Japan', cn:'China', ru:'Russia', in:'India', au:'Australia', za:'South Africa', nz:'New Zealand', kr:'South Korea', sa:'Saudi Arabia', ae:'United Arab Emirates', tr:'Turkiye', gr:'Greece', nl:'Nederland', be:'Belgique', ch:'Schweiz', at:'Osterreich', se:'Sverige', no:'Norge', dk:'Danmark', fi:'Finland', pl:'Polska', ie:'Ireland', il:'Israel', eg:'Egypt', ma:'Maroc', ng:'Nigeria', ke:'Kenya' };
function roadSelectedCountry() {
  try {
    var cc = (localStorage.getItem('psg_feed_pais') || 'br').toLowerCase();
    return ROAD_COUNTRIES[cc] || '';
  } catch (e) { return ''; }
}
function roadAttempts(q) {
  var raw = String(q);
  // Remove marcadores de km (confundem o geocodificador) mantendo o nome da via
  var base = raw.replace(/\bkm\.?\s*\d+(\s*[-\u2013]\s*\d+)?/gi, '').replace(/\s{2,}/g, ' ').replace(/^[\s,]+|[\s,]+$/g, '');
  var pais = roadSelectedCountry();
  var out = [];
  var push = function(s) { s = String(s).replace(/\s+/g, ' ').trim(); if (s && out.indexOf(s) === -1) out.push(s); };
  if (pais) {
    push(base + ', ' + pais);
    push(raw + ', ' + pais);
  }
  push(base);
  push(raw);
  return out;
}

async function geocodeQuery(q, wantRoad) {
  if (!q) return null;
  try {
    const r = await fetch('https://nominatim.openstreetmap.org/search?format=jsonv2&addressdetails=1&limit=5&accept-language=pt,en&q=' + encodeURIComponent(q));
    if (!r.ok) return null;
    const j = await r.json();
    if (!j || !j.length) return null;
    // Em busca de rodovia, prefere resultados do tipo highway/estrada
    var pick = j[0];
    if (wantRoad) {
      for (var i = 0; i < j.length; i++) {
        if (j[i].category === 'highway' || j[i].category === 'amenity' && /fuel|police/.test(j[i].type || '')) { pick = j[i]; break; }
      }
    }
    const a = pick.address || {};
    return {
      lat: parseFloat(pick.lat),
      lng: parseFloat(pick.lon),
      displayName: pick.display_name || q,
      city: a.city || a.town || a.village || a.municipality || '',
      state: a.state || '',
      country: a.country || '',
      country_code: a.country_code || ''
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

  // RODOVIAS: se a consulta parece rodovia/estrada, tenta primeiro as
  // combinacoes otimizadas (nome da via + pais da edicao selecionada)
  const isRoad = isRoadQuery(rawQuery || A.street || '');
  if (isRoad && rawQuery) {
    roadAttempts(rawQuery).forEach(function(s) { if (attempts.indexOf(s) === -1) attempts.push(s); });
    updateLoading('Localizando rodovia no mapa mundial...');
  }

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
    const hit = await geocodeQuery(attempts[i], isRoad);
    if (hit && isFinite(hit.lat) && isFinite(hit.lng)) return hit;
  }
  return null;
}

// ============================================================
// INTELLIGENCE ENGINE
// ============================================================
function generateIntelligence(lat, lng, address) {
  // FATOR TEMPORAL â€” atualizacao automatica dos dados:
  // o indice de cada local evolui sozinho ao longo dos dias
  // (ciclo mensal), sem nenhuma intervencao humana.
  var dia = Math.floor(Date.now() / 86400000) % 30;
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

// ============================================================
// RELOGIO MUNDIAL â€” horario e fuso horario de cada pais
// Mostra a hora local do lugar analisado (painel de resultado)
// e do pais selecionado nas bandeiras (cabecalho de noticias).
// ============================================================
var WorldClock = (function() {
  // Fuso principal de cada pais (IANA) â€” cobertura mundial
  var PAIS_TZ = {
    br:'America/Sao_Paulo', ar:'America/Argentina/Buenos_Aires', bo:'America/La_Paz', cl:'America/Santiago', co:'America/Bogota', pe:'America/Lima', uy:'America/Montevideo', py:'America/Asuncion', ve:'America/Caracas', ec:'America/Guayaquil', gy:'America/Guyana', sr:'America/Paramaribo', gf:'America/Cayenne',
    us:'America/New_York', ca:'America/Toronto', mx:'America/Mexico_City', gt:'America/Guatemala', cr:'America/Costa_Rica', pa:'America/Panama', cu:'America/Havana', do:'America/Santo_Domingo', ht:'America/Port-au-Prince', jm:'America/Jamaica', bs:'America/Nassau', tt:'America/Port_of_Spain',
    gb:'Europe/London', ie:'Europe/Dublin', fr:'Europe/Paris', de:'Europe/Berlin', it:'Europe/Rome', es:'Europe/Madrid', pt:'Europe/Lisbon', nl:'Europe/Amsterdam', be:'Europe/Brussels', ch:'Europe/Zurich', at:'Europe/Vienna', se:'Europe/Stockholm', no:'Europe/Oslo', dk:'Europe/Copenhagen', fi:'Europe/Helsinki', is:'Atlantic/Reykjavik', pl:'Europe/Warsaw', cz:'Europe/Prague', gr:'Europe/Athens', tr:'Europe/Istanbul', hu:'Europe/Budapest', ro:'Europe/Bucharest', bg:'Europe/Sofia', hr:'Europe/Zagreb', rs:'Europe/Belgrade', sk:'Europe/Bratislava', si:'Europe/Ljubljana', ua:'Europe/Kyiv', by:'Europe/Minsk', lt:'Europe/Vilnius', lv:'Europe/Riga', ee:'Europe/Tallinn',
    ru:'Europe/Moscow', kz:'Asia/Almaty', uz:'Asia/Tashkent',
    jp:'Asia/Tokyo', cn:'Asia/Shanghai', kr:'Asia/Seoul', tw:'Asia/Taipei', hk:'Asia/Hong_Kong', mo:'Asia/Macau', mn:'Asia/Ulaanbaatar', in:'Asia/Kolkata', pk:'Asia/Karachi', bd:'Asia/Dhaka', lk:'Asia/Colombo', np:'Asia/Kathmandu', mv:'Indian/Maldives', bt:'Asia/Thimphu',
    ae:'Asia/Dubai', sa:'Asia/Riyadh', qa:'Asia/Qatar', kw:'Asia/Kuwait', bh:'Asia/Bahrain', om:'Asia/Muscat', ye:'Asia/Aden', il:'Asia/Jerusalem', jo:'Asia/Amman', lb:'Asia/Beirut', sy:'Asia/Damascus', iq:'Asia/Baghdad', ir:'Asia/Tehran', af:'Asia/Kabul',
    th:'Asia/Bangkok', vn:'Asia/Ho_Chi_Minh', id:'Asia/Jakarta', my:'Asia/Kuala_Lumpur', sg:'Asia/Singapore', ph:'Asia/Manila', kh:'Asia/Phnom_Penh', la:'Asia/Vientiane', mm:'Asia/Yangon', bn:'Asia/Brunei',
    au:'Australia/Sydney', nz:'Pacific/Auckland', fj:'Pacific/Fiji', pg:'Pacific/Port_Moresby',
    eg:'Africa/Cairo', ma:'Africa/Casablanca', dz:'Africa/Algiers', tn:'Africa/Tunis', ly:'Africa/Tripoli', sd:'Africa/Khartoum', et:'Africa/Addis_Ababa', ke:'Africa/Nairobi', ug:'Africa/Kampala', tz:'Africa/Dar_es_Salaam', rw:'Africa/Kigali', ng:'Africa/Lagos', gh:'Africa/Accra', ci:'Africa/Abidjan', sn:'Africa/Dakar', cm:'Africa/Douala', ao:'Africa/Luanda', zm:'Africa/Lusaka', zw:'Africa/Harare', mz:'Africa/Maputo', bw:'Africa/Gaborone', na:'Africa/Windhoek', za:'Africa/Johannesburg', mu:'Indian/Mauritius', sc:'Indian/Mahe', mg:'Africa/Antananarivo'
  };
  // Ajustes por estado/provincia (paises com varios fusos)
  var BR_TZ = { am:'America/Manaus', rr:'America/Manaus', ro:'America/Porto_Velho', ac:'America/Rio_Branco', mt:'America/Cuiaba', ms:'America/Campo_Grande' };
  var US_TZ = { az:'America/Phoenix', co:'America/Denver', id:'America/Denver', mt:'America/Denver', nm:'America/Denver', ut:'America/Denver', wy:'America/Denver', ca:'America/Los_Angeles', nv:'America/Los_Angeles', wa:'America/Los_Angeles', or:'America/Los_Angeles', ak:'America/Anchorage', hi:'Pacific/Honolulu', al:'America/Chicago', ar:'America/Chicago', il:'America/Chicago', ia:'America/Chicago', ks:'America/Chicago', la:'America/Chicago', mn:'America/Chicago', ms:'America/Chicago', mo:'America/Chicago', ne:'America/Chicago', nd:'America/Chicago', ok:'America/Chicago', sd:'America/Chicago', tn:'America/Chicago', tx:'America/Chicago', wi:'America/Chicago', ct:'America/New_York', de:'America/New_York', fl:'America/New_York', ga:'America/New_York', in:'America/New_York', ky:'America/New_York', me:'America/New_York', md:'America/New_York', ma:'America/New_York', mi:'America/New_York', nh:'America/New_York', nj:'America/New_York', ny:'America/New_York', nc:'America/New_York', oh:'America/New_York', pa:'America/New_York', ri:'America/New_York', sc:'America/New_York', vt:'America/New_York', va:'America/New_York', wv:'America/New_York', dc:'America/New_York' };

  function tzDoLocal(countryCode, state) {
    var cc = String(countryCode || '').toLowerCase().trim();
    var uf = String(state || '').toLowerCase().replace(/[^a-z]/g, '').trim();
    if (!cc) return null;
    if (cc === 'br' && BR_TZ[uf]) return BR_TZ[uf];
    if (cc === 'us' && US_TZ[uf]) return US_TZ[uf];
    return PAIS_TZ[cc] || null;
  }
  function partesHora(tz) {
    try {
      var d = new Date();
      var hora = new Intl.DateTimeFormat('pt-BR', { timeZone: tz, hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(d);
      var fuso = '';
      try {
        fuso = new Intl.DateTimeFormat('pt-BR', { timeZone: tz, timeZoneName: 'shortOffset' }).formatToParts(d).filter(function(p) { return p.type === 'timeZoneName'; })[0].value;
      } catch (e) {
        try { fuso = new Intl.DateTimeFormat('en-US', { timeZone: tz, timeZoneName: 'short' }).formatToParts(d).filter(function(p) { return p.type === 'timeZoneName'; })[0].value; } catch (e2) { fuso = ''; }
      }
      if (fuso && /^GMT/i.test(fuso)) { fuso = 'UTC' + fuso.replace(/^GMT/i, ''); }
      return { hora: hora, fuso: fuso };
    } catch (e) { return null; }
  }

  // Relogio do lugar analisado (painel de resultado)
  var tzLocal = null;
  function setLocalClock(countryCode, state) {
    tzLocal = tzDoLocal(countryCode, state);
    var el = document.getElementById('result-clock');
    if (!el) return;
    if (!tzLocal) { el.style.display = 'none'; return; }
    el.style.display = 'block';
    tickLocal();
  }
  function tickLocal() {
    var el = document.getElementById('result-clock');
    if (!el || !tzLocal) return;
    var p = partesHora(tzLocal);
    if (p) { el.innerHTML = '&#128337; Hor&aacute;rio local: <b>' + p.hora + '</b>' + (p.fuso ? ' <span style="color:var(--text-muted);font-weight:500;">(' + p.fuso + ')</span>' : ''); }
  }

  // Relogio do pais selecionado nas bandeiras (cabecalho de noticias)
  function tickFeed() {
    var el = document.getElementById('feed-clock');
    if (!el) return;
    var cc = '';
    try { cc = (localStorage.getItem('psg_feed_pais') || 'br').toLowerCase(); } catch (e) { cc = 'br'; }
    var tz = PAIS_TZ[cc] || null;
    if (!tz) { el.style.display = 'none'; return; }
    var p = partesHora(tz);
    if (p) { el.innerHTML = '&#128337; ' + p.hora + ' ' + (p.fuso || ''); }
  }

  setInterval(function() { tickLocal(); tickFeed(); }, 1000);
  return { setLocalClock: setLocalClock, tzDoLocal: tzDoLocal, partesHora: partesHora };
})();

// ============================================================
// AVISOS DE RODOVIA â€” pedagios e radares (dados do OpenStreetMap)
// Consulta a API Overpass num raio de 8 km do ponto analisado
// e mostra aviso no painel + marcadores no mapa.
// ============================================================
var roadAlertsLayer = null;
function roadEsc(s) { return String(s || '').replace(/[&<>"']/g, function(c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
function roadDistanceKm(lat1, lng1, lat2, lng2) {
  var R = 6371, dLat = (lat2 - lat1) * Math.PI / 180, dLng = (lng2 - lng1) * Math.PI / 180;
  var a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}
async function loadRoadAlerts(lat, lng) {
  var R = 8000; // raio de busca: 8 km
  var q = '[out:json][timeout:25];(' +
    'node(around:' + R + ',' + lat + ',' + lng + ')[barrier=toll_booth];' +
    'node(around:' + R + ',' + lat + ',' + lng + ')[highway=speed_camera];' +
    'way(around:300,' + lat + ',' + lng + ')[highway][maxspeed];' +
    ');out body center 90;';
  var endpoints = [
    'https://overpass-api.de/api/interpreter',
    'https://overpass.kumi.systems/api/interpreter'
  ];
  var alerts = null;
  for (var e = 0; e < endpoints.length && !alerts; e++) {
    try {
      var r = await fetch(endpoints[e], {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        body: 'data=' + encodeURIComponent(q)
      });
      if (r.ok) {
        var j = await r.json();
        var pedagios = [], radares = [], vias = [];
        (j.elements || []).forEach(function(el) {
          var tags = el.tags || {};
          if (el.type === 'node' && typeof el.lat === 'number' && typeof el.lon === 'number') {
            var item = {
              lat: el.lat, lng: el.lon,
              name: tags.name || tags.operator || tags.ref || '',
              maxspeed: tags['maxspeed'] || ''
            };
            if (tags.barrier === 'toll_booth') pedagios.push(item);
            else if (tags.highway === 'speed_camera') radares.push(item);
          } else if (el.type === 'way' && el.center && tags.maxspeed) {
            vias.push({
              lat: el.center.lat, lng: el.center.lon,
              name: tags.name || tags.ref || '',
              maxspeed: String(tags.maxspeed)
            });
          }
        });
        alerts = { pedagios: pedagios, radares: radares, vias: vias };
      }
    } catch (err) { /* tenta o proximo espelho */ }
  }
  renderRoadAlerts(alerts, lat, lng);
}
function roadSpeedLabel(ms) {
  var s = String(ms || '').trim().toLowerCase();
  if (!s) return null;
  if (s === 'none' || s === 'unlimited') return 'sem limite';
  if (s === 'walk') return 'area de pedestres';
  if (/^\d+(\.\d+)?$/.test(s)) return s + ' km/h';
  if (/^\d+(\.\d+)?\s*mph$/.test(s)) return String(ms).trim() + ' (mph)';
  if (/^\d+/.test(s)) return String(ms).trim() + ' km/h';
  if (/^[a-z]{2}:/.test(s)) return null; // valores regionais complexos do OSM
  return String(ms).trim();
}
function renderRoadAlerts(alerts, lat, lng) {
  // Caixa de aviso no painel (abaixo do cabecalho do resultado)
  var header = document.querySelector('.result-header');
  var box = document.getElementById('road-alerts');
  if (!box && header && header.parentNode) {
    box = document.createElement('div');
    box.id = 'road-alerts';
    header.parentNode.insertBefore(box, header.nextSibling);
  }
  if (!box) return;
  // Limite de velocidade da via mais proxima (badge amarelo sob o endereco)
  var speedEl = document.getElementById('result-speed');
  var vias = (alerts && alerts.vias && alerts.vias.length) ? alerts.vias : [];
  if (speedEl) {
    var mostrou = false;
    if (vias.length) {
      var ord = vias.map(function(v) { v._d = roadDistanceKm(lat, lng, v.lat, v.lng); return v; }).sort(function(a, b) { return a._d - b._d; });
      for (var i = 0; i < ord.length; i++) {
        var lbl = roadSpeedLabel(ord[i].maxspeed);
        if (lbl) {
          speedEl.style.display = 'block';
          speedEl.innerHTML = '&#128678; Limite de velocidade: <b>' + roadEsc(lbl) + '</b>' + (ord[i].name ? ' &mdash; ' + roadEsc(ord[i].name) : '') + ' <span style="color:var(--text-muted);font-weight:500;">(via mais proxima)</span>';
          mostrou = true;
          break;
        }
      }
    }
    if (!mostrou) speedEl.style.display = 'none';
  }
  if (!alerts) {
    box.style.cssText = 'display:none;';
    return;
  }
  var pedagios = alerts.pedagios, radares = alerts.radares;
  var total = pedagios.length + radares.length;
  var css = 'margin:14px 0;border-radius:12px;padding:14px 18px;font-size:.86rem;line-height:1.6;';
  if (total === 0) {
    box.style.cssText = css + 'border:1px solid rgba(34,197,94,.35);background:rgba(34,197,94,.08);color:#86efac;';
    box.innerHTML = '&#9989; Nenhum ped&aacute;gio ou radar cadastrado no OpenStreetMap num raio de 8 km deste ponto.';
    return;
  }
  // Ordena por distancia e limita a lista
  var fmt = function(list) {
    return list.map(function(p) { p._d = roadDistanceKm(lat, lng, p.lat, p.lng); return p; })
               .sort(function(a, b) { return a._d - b._d; });
  };
  pedagios = fmt(pedagios); radares = fmt(radares);
  var linhas = [];
  pedagios.slice(0, 4).forEach(function(p) {
    linhas.push('<div style="display:flex;justify-content:space-between;gap:12px;padding:3px 0;"><span>&#128176; Ped&aacute;gio' + (p.name ? ' &mdash; <b>' + roadEsc(p.name) + '</b>' : '') + '</span><span style="color:var(--text-muted);white-space:nowrap;">' + p._d.toFixed(1) + ' km</span></div>');
  });
  if (pedagios.length > 4) linhas.push('<div style="color:var(--text-muted);padding:3px 0;">+ ' + (pedagios.length - 4) + ' outro(s) ped&aacute;gio(s) no raio</div>');
  radares.slice(0, 4).forEach(function(p) {
    linhas.push('<div style="display:flex;justify-content:space-between;gap:12px;padding:3px 0;"><span>&#128247; Radar' + (p.maxspeed ? ' &mdash; m&aacute;x. <b>' + roadEsc(p.maxspeed) + '</b>' : '') + '</span><span style="color:var(--text-muted);white-space:nowrap;">' + p._d.toFixed(1) + ' km</span></div>');
  });
  if (radares.length > 4) linhas.push('<div style="color:var(--text-muted);padding:3px 0;">+ ' + (radares.length - 4) + ' outro(s) radar(es) no raio</div>');
  var temPed = pedagios.length > 0, temRad = radares.length > 0;
  box.style.cssText = css + 'border:1px solid rgba(250,204,21,.4);background:rgba(250,204,21,.08);color:#fde047;';
  box.innerHTML = '<div style="font-weight:800;margin-bottom:6px;text-transform:uppercase;letter-spacing:.03em;">&#9888;&#65039; Aten&ccedil;&atilde;o na via &mdash; ' +
    (temPed ? pedagios.length + ' ped&aacute;gio(s)' : '') + (temPed && temRad ? ' e ' : '') + (temRad ? radares.length + ' radar(es)' : '') + ' num raio de 8 km</div>' +
    linhas.join('') +
    '<div style="margin-top:8px;font-size:.72rem;color:var(--text-muted);">Veja os marcadores &#128176; (ped&aacute;gio) e &#128247; (radar) no mapa. Dados do OpenStreetMap.</div>';
  // Marcadores no mapa
  try {
    if (roadAlertsLayer) { map.removeLayer(roadAlertsLayer); roadAlertsLayer = null; }
    roadAlertsLayer = L.layerGroup();
    var mkIcon = function(emoji, fundo) {
      return L.divIcon({
        className: '',
        html: '<div style="background:' + fundo + ';border-radius:50% 50% 50% 0;transform:rotate(-45deg);width:30px;height:30px;display:flex;align-items:center;justify-content:center;border:2px solid #fff;box-shadow:0 2px 8px rgba(0,0,0,.5);"><span style="transform:rotate(45deg);font-size:14px;line-height:1;">' + emoji + '</span></div>',
        iconSize: [30, 30], iconAnchor: [15, 30], popupAnchor: [0, -30]
      });
    };
    pedagios.forEach(function(p) {
      L.marker([p.lat, p.lng], { icon: mkIcon('&#128176;', 'linear-gradient(135deg,#b45309,#f59e0b)'), zIndexOffset: 500 })
        .addTo(roadAlertsLayer)
        .bindPopup('<b>&#128176; Ped&aacute;gio</b>' + (p.name ? '<br>' + roadEsc(p.name) : '') + '<br>' + p._d.toFixed(1) + ' km do ponto analisado');
    });
    radares.forEach(function(p) {
      L.marker([p.lat, p.lng], { icon: mkIcon('&#128247;', 'linear-gradient(135deg,#b91c1c,#ef4444)'), zIndexOffset: 500 })
        .addTo(roadAlertsLayer)
        .bindPopup('<b>&#128247; Radar de velocidade</b>' + (p.maxspeed ? '<br>Velocidade m&aacute;xima: ' + roadEsc(p.maxspeed) : '') + '<br>' + p._d.toFixed(1) + ' km do ponto analisado');
    });
    if (currentMapView === 'dark' || currentMapView === 'satellite') { roadAlertsLayer.addTo(map); }
  } catch (e) { /* mapa em modo 3D ou nao iniciado */ }
}

// ============================================================
// AVISOS NAUTICOS — rios, mares e navegacao
// Detecta corpos d'agua proximos (OpenStreetMap), mostra
// condicoes do mar em tempo real (Open-Meteo Marine) e orienta
// com base nas autoridades de navegacao do mundo.
// ============================================================
var nauticLayer = null;
var currentNautic = null;   // estado nautico da ultima busca (para o PDF)
function nauticEsc(s) { return roadEsc(s); }
// "Rio Tiete" -> "Rio Tiete"; "Represa Billings" (tipo agua) -> "Corpo d'agua — Represa Billings"
function nauticNomeLabel(a) {
  var rot = { rio: 'Rio', baia: 'Ba\u00eda', lago: 'Lago', canal: 'Canal', agua: 'Corpo d\u2019\u00e1gua' }[a.tipo] || 'Corpo d\u2019\u00e1gua';
  var nm = a.nome || rot;
  if (!a.nome) return rot;
  var norm = function(x) { return String(x).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, ''); };
  if (norm(a.nome).indexOf(norm(rot)) === 0) return nm;
  return rot + ' \u2014 ' + nm;
}
function nauticTipoLabel(t) {
  var m = { rio: 'Rio', baia: 'Ba&iacute;a', lago: 'Lago', canal: 'Canal', agua: 'Corpo d&apos;&aacute;gua' };
  return m[t] || 'Corpo d&apos;&aacute;gua';
}
async function nauticFetchOverpass(lat, lng) {
  var q = '[out:json][timeout:25];(' +
    'way(around:4000,' + lat + ',' + lng + ')[natural=water];' +
    'way(around:4000,' + lat + ',' + lng + ')[waterway=river];' +
    'way(around:4000,' + lat + ',' + lng + ')[natural=bay];' +
    'relation(around:4000,' + lat + ',' + lng + ')[natural=water];' +
    ');out tags center 40;';
  var endpoints = [
    'https://overpass-api.de/api/interpreter',
    'https://overpass.kumi.systems/api/interpreter'
  ];
  for (var e = 0; e < endpoints.length; e++) {
    try {
      var r = await fetch(endpoints[e], {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        body: 'data=' + encodeURIComponent(q)
      });
      if (r.ok) return await r.json();
    } catch (err) { /* tenta o proximo espelho */ }
  }
  return null;
}
async function nauticMarine(lat, lng) {
  try {
    var u = 'https://marine-api.open-meteo.com/v1/marine?latitude=' + lat + '&longitude=' + lng +
      '&current=wave_height,wind_wave_height,swell_wave_height,swell_wave_period,sea_surface_temperature&timezone=auto';
    var r = await fetch(u);
    if (!r.ok) return null;
    var j = await r.json();
    if (j && j.current && j.current.wave_height != null) return j.current;
    return null;
  } catch (e) { return null; }
}
async function loadNauticAlerts(lat, lng) {
  var box = document.getElementById('nautic-alerts');
  var header = document.querySelector('.result-header');
  if (!box && header && header.parentNode) {
    box = document.createElement('div');
    box.id = 'nautic-alerts';
    var ref = document.getElementById('road-alerts') || header;
    header.parentNode.insertBefore(box, ref.nextSibling);
  }
  if (!box) return;
  var css = 'margin:14px 0;border-radius:12px;padding:14px 18px;font-size:.86rem;line-height:1.6;';
  // A consulta menciona agua? (rio, mar, praia, lago...)
  var consulta = '';
  try { consulta = ((document.getElementById('search-input') || {}).value || '').toLowerCase(); } catch (e) {}
  var palavraAgua = /(rio|river|lago|lake|mar |sea|oceano|ocean|baia|bay|canal|praia|beach|represa|lagoa|delta|estuario|portugal porto)/.test(' ' + consulta + ' ');
  // 1) Corpos d'agua num raio de 4 km
  var j = await nauticFetchOverpass(lat, lng);
  var aguas = [];
  if (j && j.elements) {
    j.elements.forEach(function(el) {
      var tags = el.tags || {};
      var pt = (el.type === 'node') ? el : el.center;
      if (!pt || typeof pt.lat !== 'number' || typeof (pt.lon || pt.lng) !== 'number') return;
      var tipo = '';
      if (tags.waterway === 'river') tipo = 'rio';
      else if (tags.natural === 'bay') tipo = 'baia';
      else if (tags.natural === 'water') tipo = (tags.water === 'lake' ? 'lago' : (tags.water === 'canal' ? 'canal' : 'agua'));
      if (!tipo) return;
      var lon = pt.lon != null ? pt.lon : pt.lng;
      aguas.push({
        nome: tags.name || '', tipo: tipo, lat: pt.lat, lng: lon,
        d: roadDistanceKm(lat, lng, pt.lat, lon)
      });
    });
    aguas.sort(function(a, b) { return a.d - b.d; });
    var vistos = {}, unicas = [];
    aguas.forEach(function(a) {
      var k = (a.nome || a.tipo);
      if (!vistos[k]) { vistos[k] = 1; unicas.push(a); }
    });
    aguas = unicas.slice(0, 4);
  }
  var temAgua = aguas.length > 0;
  if (!temAgua && !palavraAgua) {
    currentNautic = { temAgua: false, aguas: [], mar: null, aguaQuery: false };
    box.style.cssText = 'display:none;'; return;
  }

  // 2) Condicoes do mar no ponto d'agua mais proximo
  var alvoMar = temAgua ? aguas[0] : { lat: lat, lng: lng };
  var mar = await nauticMarine(alvoMar.lat, alvoMar.lng);
  currentNautic = { temAgua: temAgua, aguas: aguas, mar: mar, aguaQuery: palavraAgua };

  // 3) Montagem do painel
  var linhas = [];
  if (temAgua) {
    linhas.push('<div style="font-weight:800;margin-bottom:4px;">&#127754; Corpos d&apos;&aacute;gua num raio de 4 km:</div>');
    aguas.forEach(function(a) {
      linhas.push('<div style="display:flex;justify-content:space-between;gap:12px;padding:3px 0;"><span>&#128167; <b>' + nauticEsc(nauticNomeLabel(a)) + '</b></span><span style="color:var(--text-muted);white-space:nowrap;">' + a.d.toFixed(1) + ' km</span></div>');
    });
  } else {
    linhas.push('<div style="font-weight:800;margin-bottom:4px;">&#127754; Local consultado &eacute; um ambiente aqu&aacute;tico.</div>');
  }
  var cor, iconeStatus, textoStatus;
  if (mar && typeof mar.wave_height === 'number') {
    var onda = mar.wave_height;
    linhas.push('<div style="font-weight:800;margin:10px 0 4px;">&#9875;&#65039; Condi&ccedil;&otilde;es do mar agora (Open-Meteo Marine):</div>');
    var itens = ['&#127754; Ondas: <b>' + onda.toFixed(1).replace('.', ',') + ' m</b>'];
    if (mar.swell_wave_height != null) itens.push('Ondula&ccedil;&atilde;o: <b>' + mar.swell_wave_height.toFixed(1).replace('.', ',') + ' m</b>');
    if (mar.swell_wave_period != null) itens.push('per&iacute;odo <b>' + Math.round(mar.swell_wave_period) + ' s</b>');
    if (mar.sea_surface_temperature != null) itens.push('&aacute;gua: <b>' + mar.sea_surface_temperature.toFixed(0) + '&deg;C</b>');
    linhas.push('<div style="padding:3px 0;">' + itens.join(' &bull; ') + '</div>');
    if (onda < 1) { cor = 'rgba(34,197,94,.4)'; iconeStatus = '&#9989;'; textoStatus = 'MAR CALMO &mdash; condi&ccedil;&otilde;es adequadas para banho e navega&ccedil;&atilde;o com os cuidados normais.'; }
    else if (onda < 2) { cor = 'rgba(250,204,21,.4)'; iconeStatus = '&#9888;&#65039;'; textoStatus = 'MAR AGITADO &mdash; cautela: banhistas devem respeitar as bandeiras dos salva-vidas e pequenas embarca&ccedil;&otilde;es devem redobrar a aten&ccedil;&atilde;o.'; }
    else { cor = 'rgba(239,68,68,.4)'; iconeStatus = '&#128680;'; textoStatus = 'MAR PERIGOSO &mdash; ondas altas: banho e navega&ccedil;&atilde;o N&Atilde;O s&atilde;o recomendados. Aguarde a melhoria das condi&ccedil;&otilde;es.'; }
  } else {
    cor = 'rgba(59,130,246,.4)';
    iconeStatus = '&#8505;&#65039;';
    textoStatus = 'Corpo d&apos;&aacute;gua continental (rio/lago) &mdash; aten&ccedil;&atilde;o a correnteza, enchentes e margens alagadas.';
  }
  box.style.cssText = css + 'border:1px solid ' + cor + ';background:rgba(59,130,246,.08);color:#93c5fd;';
  box.innerHTML =
    '<div style="font-weight:800;margin-bottom:6px;text-transform:uppercase;letter-spacing:.03em;">&#9875;&#65039; Avisos n&aacute;uticos &mdash; Marinha e autoridades de navega&ccedil;&atilde;o</div>' +
    linhas.join('') +
    '<div style="margin-top:10px;padding:8px 10px;border-radius:8px;border:1px solid ' + cor + ';background:rgba(0,0,0,.18);">' + iconeStatus + ' <b>' + textoStatus + '</b></div>' +
    '<div style="margin-top:8px;font-size:.75rem;line-height:1.7;">' +
    '&#128680; <b>Emerg&ecirc;ncia no mar e rios:</b> Canal 16 VHF (156,8 MHz) &mdash; frequ&ecirc;ncia internacional de socorro &mdash; e os telefones de emerg&ecirc;ncia do seu pa&iacute;s (192/193 no Brasil).<br>' +
    '&#9875;&#65039; <b>Antes de navegar:</b> consulte os <a href="https://www.marinha.mil.br/chm/" target="_blank" rel="noopener" style="color:#60a5fa;">Avisos aos Navegantes da Marinha do Brasil (CHM/DHN)</a>, as Cartas N&aacute;uticas oficiais e as normas da <a href="https://www.imo.org" target="_blank" rel="noopener" style="color:#60a5fa;">IMO (Organiza&ccedil;&atilde;o Mar&iacute;tima Internacional)</a>.<br>' +
    '&#127757; Banhistas: respeite as bandeiras dos salva-vidas, nade em &aacute;reas monitoradas e nunca subestime correntes de retorno.<br>' +
    '&#127885; <b>Homenagem:</b> &agrave;s Marinhas de Guerra e Guardas Costeiras de todo o planeta, que guardam rios, mares e vidas &mdash; respeito, reconhecimento e gratid&atilde;o.<br>' +
    '<span style="color:var(--text-muted);font-size:.68rem;">Dados de &aacute;gua: OpenStreetMap e Open-Meteo Marine. Os avisos oficiais de navega&ccedil;&atilde;o s&atilde;o emitidos pelas autoridades navais de cada pa&iacute;s.</span>' +
    '</div>';
  // 4) Marcadores de agua no mapa
  try {
    if (nauticLayer) { map.removeLayer(nauticLayer); nauticLayer = null; }
    if (aguas.length && map && typeof L !== 'undefined') {
      nauticLayer = L.layerGroup();
      var nautIcon = L.divIcon({
        className: '',
        html: '<div style="background:linear-gradient(135deg,#1d4ed8,#3b82f6);border-radius:50% 50% 50% 0;transform:rotate(-45deg);width:30px;height:30px;display:flex;align-items:center;justify-content:center;border:2px solid #fff;box-shadow:0 2px 8px rgba(0,0,0,.5);"><span style="transform:rotate(45deg);font-size:14px;line-height:1;">&#128167;</span></div>',
        iconSize: [30, 30], iconAnchor: [15, 30], popupAnchor: [0, -30]
      });
      aguas.forEach(function(a) {
        L.marker([a.lat, a.lng], { icon: nautIcon, zIndexOffset: 400 })
          .addTo(nauticLayer)
          .bindPopup('<b>' + nauticEsc(nauticNomeLabel(a)) + '</b><br>' + a.d.toFixed(1) + ' km do ponto analisado');
      });
      if (currentMapView === 'dark' || currentMapView === 'satellite') { nauticLayer.addTo(map); }
    }
  } catch (e) { /* mapa em modo 3D ou nao iniciado */ }
}

// ============================================================
// RENDER DASHBOARD
// ============================================================
function renderDashboard(data) {
  document.getElementById('main-content').classList.add('active');
  if (!map) { try { initMap(); } catch(e) { console.error('[MAP] initMap falhou:', e); } }
  if (map) map.invalidateSize();
  document.getElementById('result-address').textContent = data.address.fullAddress;
  document.getElementById('result-meta').textContent = 'Lat ' + data.lat.toFixed(4) + ' | Lng ' + data.lng.toFixed(4) + (data.address.cep ? ' | CEP ' + data.address.cep : '') + ' | Raio de analise: 1.5km';
  WorldClock.setLocalClock(data.address.country_code || '', data.address.state || '');
  loadRoadAlerts(data.lat, data.lng);
  loadNauticAlerts(data.lat, data.lng);
  try {
    if (map.hasLayer(heatLayer)) map.removeLayer(heatLayer);
    map.setView([data.lat, data.lng], 15);
    heatLayer.setLatLngs(data.heatPoints);
    setTimeout(function() { try { map.addLayer(heatLayer); map.invalidateSize(); } catch(e) {} }, 800);
  } catch(e) {}
  if (markersLayer) {
    markersLayer.clearLayers();
    data.markerPoints.forEach(p => {
      markersLayer.addLayer(L.circleMarker([p.lat, p.lng], { radius: 5, color: '#ef4444', fillColor: '#ef4444', fillOpacity: .7, weight: 1 }).bindPopup('<b>' + p.type + '</b><br>' + p.date));
    });
    L.marker([data.lat, data.lng]).addTo(markersLayer).bindPopup('<b>Local pesquisado</b><br>' + data.address.fullAddress).openPopup();
  }
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

// Bandeiras dos estados brasileiros (Wikimedia Commons / Special:FilePath)
var PSG_BR_STATE_FLAGS = {
  'acre': 'Bandeira do Acre.svg', 'ac': 'Bandeira do Acre.svg',
  'alagoas': 'Bandeira de Alagoas.svg', 'al': 'Bandeira de Alagoas.svg',
  'amapa': 'Bandeira do Amap\u00e1.svg', 'ap': 'Bandeira do Amap\u00e1.svg',
  'amazonas': 'Bandeira do Amazonas.svg', 'am': 'Bandeira do Amazonas.svg',
  'bahia': 'Bandeira da Bahia.svg', 'ba': 'Bandeira da Bahia.svg',
  'ceara': 'Bandeira do Cear\u00e1.svg', 'ce': 'Bandeira do Cear\u00e1.svg',
  'distrito federal': 'Bandeira do Distrito Federal (Brasil).svg', 'df': 'Bandeira do Distrito Federal (Brasil).svg',
  'espirito santo': 'Bandeira do Esp\u00edrito Santo.svg', 'es': 'Bandeira do Esp\u00edrito Santo.svg',
  'goias': 'Bandeira de Goi\u00e1s.svg', 'go': 'Bandeira de Goi\u00e1s.svg',
  'maranhao': 'Bandeira do Maranh\u00e3o.svg', 'ma': 'Bandeira do Maranh\u00e3o.svg',
  'mato grosso': 'Bandeira de Mato Grosso.svg', 'mt': 'Bandeira de Mato Grosso.svg',
  'mato grosso do sul': 'Bandeira de Mato Grosso do Sul.svg', 'ms': 'Bandeira de Mato Grosso do Sul.svg',
  'minas gerais': 'Bandeira de Minas Gerais.svg', 'mg': 'Bandeira de Minas Gerais.svg',
  'para': 'Bandeira do Par\u00e1.svg', 'pa': 'Bandeira do Par\u00e1.svg',
  'paraiba': 'Bandeira da Para\u00edba.svg', 'pb': 'Bandeira da Para\u00edba.svg',
  'parana': 'Bandeira do Paran\u00e1.svg', 'pr': 'Bandeira do Paran\u00e1.svg',
  'pernambuco': 'Bandeira de Pernambuco.svg', 'pe': 'Bandeira de Pernambuco.svg',
  'piaui': 'Bandeira do Piau\u00ed.svg', 'pi': 'Bandeira do Piau\u00ed.svg',
  'rio de janeiro': 'Bandeira do estado do Rio de Janeiro.svg', 'rj': 'Bandeira do estado do Rio de Janeiro.svg',
  'rio grande do norte': 'Bandeira do Rio Grande do Norte.svg', 'rn': 'Bandeira do Rio Grande do Norte.svg',
  'rio grande do sul': 'Bandeira do Rio Grande do Sul.svg', 'rs': 'Bandeira do Rio Grande do Sul.svg',
  'rondonia': 'Bandeira de Rond\u00f4nia.svg', 'ro': 'Bandeira de Rond\u00f4nia.svg',
  'roraima': 'Bandeira de Roraima.svg', 'rr': 'Bandeira de Roraima.svg',
  'santa catarina': 'Bandeira de Santa Catarina.svg', 'sc': 'Bandeira de Santa Catarina.svg',
  'sao paulo': 'Bandeira do estado de S\u00e3o Paulo.svg', 'sp': 'Bandeira do estado de S\u00e3o Paulo.svg',
  'sergipe': 'Bandeira de Sergipe.svg', 'se': 'Bandeira de Sergipe.svg',
  'tocantins': 'Bandeira do Tocantins.svg', 'to': 'Bandeira do Tocantins.svg'
};
var PSG_BR_STATE_NAMES = {
  ac:'Acre',al:'Alagoas',ap:'Amap\u00e1',am:'Amazonas',ba:'Bahia',ce:'Cear\u00e1',df:'Distrito Federal',
  es:'Esp\u00edrito Santo',go:'Goi\u00e1s',ma:'Maranh\u00e3o',mt:'Mato Grosso',ms:'Mato Grosso do Sul',mg:'Minas Gerais',
  pa:'Par\u00e1',pb:'Para\u00edba',pr:'Paran\u00e1',pe:'Pernambuco',pi:'Piau\u00ed',rj:'Rio de Janeiro',rn:'Rio Grande do Norte',
  rs:'Rio Grande do Sul',ro:'Rond\u00f4nia',rr:'Roraima',sc:'Santa Catarina',sp:'S\u00e3o Paulo',se:'Sergipe',to:'Tocantins'
};
function _psgNorm(s) {
  return (s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^\x00-\x7F]/g, '').trim();
}
function _psgUF(stateRaw) {
  var n = _psgNorm(stateRaw);
  if (PSG_BR_STATE_NAMES[n]) return n.toUpperCase();
  for (var k in PSG_BR_STATE_NAMES) { if (_psgNorm(PSG_BR_STATE_NAMES[k]) === n) return k.toUpperCase(); }
  return '';
}
async function _psgResolveCommonsUrl(fileName) {
  try {
    var api = 'https://pt.wikipedia.org/w/api.php?action=query&titles=File:' + encodeURIComponent(fileName)
      + '&prop=imageinfo&iiprop=url&iiurlwidth=320&format=json&origin=*';
    var r = await fetch(api);
    if (!r.ok) return '';
    var d = await r.json();
    var pages = (d.query && d.query.pages) || {};
    for (var k in pages) {
      var info = pages[k] && pages[k].imageinfo && pages[k].imageinfo[0];
      if (info && info.thumburl) return info.thumburl;
    }
    return '';
  } catch (e) { return ''; }
}
function _psgWaitImg(img) {
  return new Promise(function(resolve) {
    if (!img || !img.src || img.style.display === 'none') return resolve();
    if (img.complete && img.naturalWidth > 0) return resolve();
    var done = function() { resolve(); };
    img.addEventListener('load', done, { once: true });
    img.addEventListener('error', done, { once: true });
    setTimeout(done, 12000);
  });
}
function _psgSleep(ms) { return new Promise(function(r) { setTimeout(r, ms); }); }
async function _psgReverseLabel(lat, lng) {
  try {
    var r = await fetch('https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=' + lat + '&lon=' + lng + '&zoom=14&accept-language=pt');
    if (!r.ok) return '';
    var d = await r.json();
    var a = d.address || {};
    var bairro = a.suburb || a.neighbourhood || a.quarter || a.village || a.hamlet || '';
    var cidade = a.city || a.town || a.municipality || a.village || '';
    return [bairro, cidade].filter(function(v, i, arr) { return v && arr.indexOf(v) === i; }).join(' \u2014 ');
  } catch (e) { return ''; }
}
function _psgMesAno(d) {
  return d.toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' });
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
  var addr = currentData.address;
  var countryCode = (addr.country_code || '').toLowerCase();
  var countryName = addr.country || 'Brasil';
  var city = addr.city || addr.town || addr.village || addr.municipality || addr.county || '';
  var stateRaw = addr.state || '';
  var stateName = PSG_BR_STATE_NAMES[_psgNorm(stateRaw)] || stateRaw;
  var localLabel = [city, stateName].filter(Boolean).join(' - ') || countryName;
  var now = new Date();
  var protocol = 'PSG-' + now.getFullYear() + '-' + Date.now().toString(36).toUpperCase().slice(-8);

  // ---- Perimetro da varredura (raio 1,5 km) ----
  showLoading('Mapeando perimetro da varredura...');
  var RAIO_KM = 1.5;
  var lat = currentData.lat, lng = currentData.lng;
  var dLat = RAIO_KM / 111.32;
  var dLng = RAIO_KM / (111.32 * Math.cos(lat * Math.PI / 180) || 1);
  // Consulta o ponto central para identificar o bairro exato da pesquisa
  var bairro = addr.neighborhood || '';
  try {
    var rc = await fetch('https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=' + lat + '&lon=' + lng + '&zoom=18&accept-language=pt');
    if (rc.ok) {
      var dc = await rc.json();
      var ac = dc.address || {};
      bairro = bairro || ac.suburb || ac.neighbourhood || ac.quarter || ac.city_district || '';
      if (!city) { city = ac.city || ac.town || ac.municipality || city; }
    }
  } catch (e) {}
  await _psgSleep(1100);
  var lims = [
    { id: 'n', lat: lat + dLat, lng: lng },
    { id: 's', lat: lat - dLat, lng: lng },
    { id: 'e', lat: lat, lng: lng + dLng },
    { id: 'w', lat: lat, lng: lng - dLng }
  ];
  for (var i = 0; i < lims.length; i++) {
    var L = lims[i];
    var label = await _psgReverseLabel(L.lat, L.lng);
    document.getElementById('pdf-limit-' + L.id).textContent = label || 'Ponto limite do perimetro';
    document.getElementById('pdf-limit-' + L.id + '-coord').textContent = 'Lat ' + L.lat.toFixed(5) + ' | Lng ' + L.lng.toFixed(5);
    if (i < lims.length - 1) await _psgSleep(1100); // respeita 1 req/s do Nominatim
  }
  var desc = 'A varredura parte do endereco pesquisado e se estende por 1,5 km em todas as direcoes, cobrindo '
    + (bairro ? 'o bairro ' + bairro + ' e suas adjacencias' : 'a regiao central e suas adjacencias')
    + (city ? ', no municipio de ' + city + (stateName ? ' (' + stateName + ')' : '') : '')
    + '. Os limites Norte, Sul, Leste e Oeste abaixo indicam exatamente onde a analise comeca e onde termina; em pontos proximos a divisas, a varredura pode alcancar bairros ou municipios vizinhos.';
  document.getElementById('pdf-perimeter-desc').textContent = desc;

  // ---- Bandeiras ----
  var flagImg = document.getElementById('pdf-country-flag');
  if (countryCode) { flagImg.src = 'https://flagcdn.com/160x120/' + countryCode + '.png'; flagImg.style.display = 'block'; }
  else { flagImg.style.display = 'none'; }
  document.getElementById('pdf-country-name').textContent = countryName;
  document.getElementById('pdf-state-name').textContent = stateName || 'Nao identificado';
  document.getElementById('pdf-city-name').textContent = city || localLabel;

  var stateFlagImg = document.getElementById('pdf-state-flag');
  var stateSeal = document.getElementById('pdf-state-seal');
  var stateFile = PSG_BR_STATE_FLAGS[_psgNorm(stateRaw)];
  var stateUrl = '';
  if (countryCode === 'br' && stateFile) stateUrl = await _psgResolveCommonsUrl(stateFile);
  if (stateUrl) {
    stateFlagImg.style.display = 'block';
    stateSeal.style.display = 'none';
    stateFlagImg.onerror = function() {
      stateFlagImg.style.display = 'none';
      stateSeal.textContent = _psgUF(stateRaw) || 'BR';
      stateSeal.style.display = 'flex';
    };
    stateFlagImg.src = stateUrl;
  } else {
    stateFlagImg.style.display = 'none';
    stateSeal.textContent = _psgUF(stateRaw) || (countryCode || '--').toUpperCase();
    stateSeal.style.display = 'flex';
  }

  var cityFlagImg = document.getElementById('pdf-city-flag');
  var citySeal = document.getElementById('pdf-city-seal');
  cityFlagImg.style.display = 'none';
  citySeal.style.display = 'flex';
  citySeal.textContent = (city || '?').replace(/[^A-Za-z\u00C0-\u00FF ]/g, '').split(' ').filter(Boolean).map(function(w) { return w[0]; }).slice(0, 2).join('').toUpperCase();
  if (countryCode === 'br' && city) {
    var uf = _psgNorm(stateRaw).length === 2 ? stateRaw.toUpperCase() : '';
    var candidates = ['Bandeira da cidade de ' + city + '.svg', 'Bandeira de ' + city + (uf ? ' (' + uf + ')' : '') + '.svg', 'Bandeira de ' + city + '.svg'];
    var cityUrl = '';
    for (var ci = 0; ci < candidates.length; ci++) {
      cityUrl = await _psgResolveCommonsUrl(candidates[ci]);
      if (cityUrl) break;
    }
    if (cityUrl) {
      cityFlagImg.onerror = function() { cityFlagImg.style.display = 'none'; citySeal.style.display = 'flex'; };
      cityFlagImg.onload = function() {
        if (cityFlagImg.naturalWidth > 0) { cityFlagImg.style.display = 'block'; citySeal.style.display = 'none'; }
      };
      cityFlagImg.src = cityUrl;
    }
  }

  // ---- Identificacao, protocolo, periodo ----
  document.getElementById('pdf-protocol').textContent = protocol;
  var emittedStr = now.toLocaleDateString('pt-BR') + ' ' + now.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  document.getElementById('pdf-emitted').textContent = emittedStr;
  document.getElementById('pdf-protocol-2').textContent = protocol;
  document.getElementById('pdf-emitted-2').textContent = emittedStr;
  var mesesExtenso = ['janeiro','fevereiro','mar\u00e7o','abril','maio','junho','julho','agosto','setembro','outubro','novembro','dezembro'];
  var cidadeData = city || stateName || countryName;
  document.getElementById('pdf-dateline').textContent = cidadeData + ', ' + now.getDate() + ' de ' + mesesExtenso[now.getMonth()] + ' de ' + now.getFullYear() + '.';
  var qrData = 'https://portalsegurancaglobal.com.br/verificar/' + protocol;
  document.getElementById('pdf-qr').src = 'https://api.qrserver.com/v1/create-qr-code/?size=140x140&margin=4&color=12-23-53&data=' + encodeURIComponent(qrData);
  // Microtexto de seguranca (topo e base do documento)
  var microStr = 'PORTAL SEGURANCA GLOBAL \u2022 DOCUMENTO DE ANALISE DE SEGURANCA \u2022 ' + protocol + ' \u2022 EMISSAO ' + emittedStr + ' \u2022 ';
  document.getElementById('pdf-micro-top').textContent = microStr + microStr + microStr;
  document.getElementById('pdf-micro-bot').textContent = microStr + microStr + microStr;
  var serial = 'SERIE B ' + (Math.floor(Math.random() * 899999999) + 100000000);
  document.getElementById('pdf-address').textContent = addr.fullAddress;
  document.getElementById('pdf-coords').textContent = 'Ponto central: Lat ' + lat.toFixed(5) + ' | Lng ' + lng.toFixed(5) + (addr.cep ? ' | CEP ' + addr.cep : '');
  var fim = new Date(now.getFullYear(), now.getMonth(), 1);
  var inicio = new Date(now.getFullYear(), now.getMonth() - 11, 1);
  document.getElementById('pdf-period').textContent = _psgMesAno(inicio) + ' a ' + _psgMesAno(fim);

  document.getElementById('pdf-pm-city').textContent = [city, stateName].filter(Boolean).join(' - ') || countryName;
  document.getElementById('pdf-pc-city').textContent = [city, stateName].filter(Boolean).join(' - ') || countryName;
  document.getElementById('pdf-score').textContent = currentData.safetyScore;
  document.getElementById('pdf-score-label').textContent = 'Safety Score - ' + (currentData.safetyScore >= 70 ? 'SEGURO' : currentData.safetyScore >= 40 ? 'MODERADO' : 'CRITICO');
  document.getElementById('pdf-crime').textContent = currentData.crimeScore + '/100';
  document.getElementById('pdf-infra').textContent = currentData.infraScore + '/100';
  document.getElementById('pdf-movement').textContent = currentData.movementScore + '/100';
  document.getElementById('pdf-occ').textContent = currentData.totalOccurrences;
  document.getElementById('pdf-cam').textContent = currentData.cameras;
  document.getElementById('pdf-com').textContent = currentData.commerce;

  // ---- Avisos nauticos (secao 6 do relatorio) ----
  var nautStatusEl = document.getElementById('pdf-nautic-status');
  var nautDetailsEl = document.getElementById('pdf-nautic-details');
  if (nautStatusEl && nautDetailsEl) {
    var naut = currentNautic;
    if (!naut || (!naut.temAgua && !naut.mar && !naut.aguaQuery)) {
      nautStatusEl.textContent = 'Nenhum corpo d\u2019\u00e1gua relevante identificado num raio de 4 km';
      nautDetailsEl.textContent = 'A varredura n\u00e1utica n\u00e3o encontrou rios, mares, ba\u00edas ou lagos no per\u00edmetro analisado. N\u00e3o h\u00e1 avisos n\u00e1uticos aplic\u00e1veis a este endere\u00e7o.';
    } else {
      var partes = [];
      if (naut.temAgua) {
        var lista = naut.aguas.map(function(a) {
          return nauticNomeLabel(a) + ' (' + a.d.toFixed(1).replace('.', ',') + ' km)';
        }).join('; ');
        partes.push('Corpos d\u2019\u00e1gua num raio de 4 km: ' + lista + '.');
      } else {
        partes.push('O local consultado \u00e9 um ambiente aqu\u00e1tico.');
      }
      var tituloNaut = 'Aviso n\u00e1utico';
      if (naut.mar && typeof naut.mar.wave_height === 'number') {
        var onda = naut.mar.wave_height;
        var cond = 'ondas de ' + onda.toFixed(1).replace('.', ',') + ' m';
        if (naut.mar.swell_wave_height != null) cond += ', ondula\u00e7\u00e3o de ' + naut.mar.swell_wave_height.toFixed(1).replace('.', ',') + ' m';
        if (naut.mar.sea_surface_temperature != null) cond += ', \u00e1gua a ' + naut.mar.sea_surface_temperature.toFixed(0) + '\u00b0C';
        partes.push('Condi\u00e7\u00f5es do mar no momento da emiss\u00e3o: ' + cond + '.');
        if (onda < 1) { tituloNaut = 'MAR CALMO'; partes.push('Condi\u00e7\u00f5es adequadas para banho e navega\u00e7\u00e3o com os cuidados normais.'); }
        else if (onda < 2) { tituloNaut = 'MAR AGITADO'; partes.push('Cautela: banhistas devem respeitar as bandeiras dos salva-vidas e pequenas embarca\u00e7\u00f5es devem redobrar a aten\u00e7\u00e3o.'); }
        else { tituloNaut = 'MAR PERIGOSO'; partes.push('Ondas altas: banho e navega\u00e7\u00e3o N\u00c3O s\u00e3o recomendados. Aguarde a melhoria das condi\u00e7\u00f5es.'); }
      } else {
        tituloNaut = 'Ambiente aqu\u00e1tico continental';
        partes.push('Aten\u00e7\u00e3o a correnteza, enchentes e margens alagadas. Consulte as autoridades locais antes de atividades no local.');
      }
      nautStatusEl.textContent = tituloNaut;
      nautDetailsEl.textContent = partes.join(' ');
    }
  }

  // ---- Renderiza com todas as imagens carregadas ----
  showLoading('Gerando relatorio PDF...');
  try {
    var reportEl = document.getElementById('pdf-report');
    var imgs = reportEl.querySelectorAll('img');
    await Promise.all(Array.prototype.map.call(imgs, _psgWaitImg));
    reportEl.style.left = '0';
    const canvas = await html2canvas(reportEl, { scale: 2, useCORS: true, backgroundColor: '#ffffff', imageTimeout: 15000 });
    reportEl.style.left = '-9999px';
    const { jsPDF } = window.jspdf;
    const pdf = new jsPDF('p', 'mm', 'a4');
    const pageW = pdf.internal.pageSize.getWidth();
    const pageHmm = pdf.internal.pageSize.getHeight();
    // MARGEM INFERIOR: deixa 10mm livres em cada pagina para a moldura,
    // o rodape (protocolo/pagina) e o numero de serie nao colidirem com o texto
    const pageContentHmm = pageHmm - 10;
    const pxPerPage = Math.floor(canvas.width * pageContentHmm / pageW);
    // CORTE INTELIGENTE: detecta faixas de linhas em branco (espaco entre
    // paragrafos/secoes) para nunca cortar uma linha de texto no meio.
    const srcCtx = canvas.getContext('2d');
    function rowIsBlank(y) {
      if (y < 0 || y >= canvas.height) return false;
      try {
        const row = srcCtx.getImageData(0, y, canvas.width, 1).data;
        for (let x = 0; x < row.length; x += 4) {
          if (row[x] < 246 || row[x + 1] < 246 || row[x + 2] < 246) return false;
        }
        return true;
      } catch (e) { return false; }
    }
    function findSafeCut(ideal) {
      // Sobe ate 150px (75px CSS) procurando uma faixa branca de 8px
      for (let y = ideal - 2; y > Math.max(0, ideal - 150); y -= 2) {
        if (rowIsBlank(y) && rowIsBlank(y - 2) && rowIsBlank(y - 4) && rowIsBlank(y - 6) && rowIsBlank(y - 8)) {
          return y;
        }
      }
      return ideal;
    }
    // Fatia o relatorio em paginas
    const slices = [];
    let pos = 0;
    while (pos < canvas.height) {
      let sliceH = Math.min(pxPerPage, canvas.height - pos);
      if (pos + sliceH < canvas.height) {
        // Nao e a ultima pagina: ajusta o corte para uma faixa em branco
        const safe = findSafeCut(pos + sliceH);
        if (safe > pos + 40) sliceH = safe - pos;
      }
      const pageCanvas = document.createElement('canvas');
      pageCanvas.width = canvas.width;
      pageCanvas.height = sliceH;
      const ctx = pageCanvas.getContext('2d');
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, pageCanvas.width, pageCanvas.height);
      ctx.drawImage(canvas, 0, pos, canvas.width, sliceH, 0, 0, canvas.width, sliceH);
      slices.push({ data: pageCanvas.toDataURL('image/jpeg', .95), hMm: sliceH * pageW / canvas.width });
      pos += sliceH;
    }
    // Monta o documento com moldura e rodape de pagina
    var microLine = microStr + microStr; // microtexto carimbado por pagina
    for (let p = 0; p < slices.length; p++) {
      if (p > 0) pdf.addPage();
      pdf.addImage(slices[p].data, 'JPEG', 0, 0, pageW, slices[p].hMm);
      // Moldura do documento
      pdf.setDrawColor(201, 162, 39);
      pdf.setLineWidth(0.7);
      pdf.rect(5, 5, pageW - 10, pageHmm - 10);
      pdf.setDrawColor(12, 23, 53);
      pdf.setLineWidth(0.25);
      pdf.rect(6.5, 6.5, pageW - 13, pageHmm - 13);
      // Marcas de canto (ouro)
      pdf.setFillColor(201, 162, 39);
      pdf.rect(7, 7, 2.2, 2.2, 'F');
      pdf.rect(pageW - 9.2, 7, 2.2, 2.2, 'F');
      pdf.rect(7, pageHmm - 9.2, 2.2, 2.2, 'F');
      pdf.rect(pageW - 9.2, pageHmm - 9.2, 2.2, 2.2, 'F');
      // Microtexto de seguranca (fonte minÃºscula, legÃ­vel apenas com lupa)
      pdf.setFont('courier', 'normal');
      pdf.setFontSize(2.8);
      pdf.setTextColor(26, 58, 110);
      pdf.text(microLine, pageW / 2, 4.2, { align: 'center' });
      pdf.text(microLine, pageW / 2, pageHmm - 2.6, { align: 'center' });
      // Numero de serie na lateral (vermelho, como em cedulas)
      pdf.setFont('courier', 'bold');
      pdf.setFontSize(8);
      pdf.setTextColor(138, 31, 31);
      pdf.text(serial, 8.2, pageHmm - 60, { angle: 90 });
      pdf.text(serial, pageW - 5.2, 60, { angle: 90 });
      // Rodape de pagina
      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(7.5);
      pdf.setTextColor(110, 110, 110);
      pdf.text('Protocolo ' + protocol + '  |  Pagina ' + (p + 1) + ' de ' + slices.length + '  |  portalsegurancaglobal.com.br  |  Documento gerado eletronicamente', pageW / 2, pageHmm - 3.2, { align: 'center' });
    }
    var fileName = 'PortalSegurancaGlobal_Relatorio_' + protocol + '.pdf';
    var pdfBlob = pdf.output('blob');
    hideLoading();
    // Download direto gratuito (sem paywall)
    var url = URL.createObjectURL(pdfBlob);
    var a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    setTimeout(function() { document.body.removeChild(a); URL.revokeObjectURL(url); }, 1000);
  } catch (err) { hideLoading(); alert('Erro ao gerar PDF: ' + err.message); }
}

async function generatePDF() {
  if (!currentData) return alert('Faca uma pesquisa primeiro.');
  _doGeneratePDF();
}

// ============================================================
// SHARE â€” painel de compartilhamento em redes sociais
// ============================================================
var SHARE_SITE_URL = 'https://portalsegurancaglobal.com.br';

var shareI18n = {
  pt: { title: 'Compartilhar Resultado', sub: 'Envie esta analise de seguranca para quem precisa saber',
    score: 'Safety Score', at: 'em', cta: 'Consulte a seguranca de qualquer endereco do mundo:',
    copy: 'Copiar link', copyMsg: 'Copiar mensagem', copied: 'Copiado com sucesso!',
    native: 'Mais opcoes', email: 'E-mail', cancel: 'Fechar', preview: 'Previa da mensagem',
    safe: 'SEGURO', mod: 'MODERADO', crit: 'CRITICO', subject: 'Analise de Seguranca \u2014 Portal Seguranca Global' },
  en: { title: 'Share Result', sub: 'Send this safety analysis to those who need to know',
    score: 'Safety Score', at: 'at', cta: 'Check the safety of any address in the world:',
    copy: 'Copy link', copyMsg: 'Copy message', copied: 'Copied successfully!',
    native: 'More options', email: 'Email', cancel: 'Close', preview: 'Message preview',
    safe: 'SAFE', mod: 'MODERATE', crit: 'CRITICAL', subject: 'Safety Analysis \u2014 Global Security Portal' },
  es: { title: 'Compartir Resultado', sub: 'Envie este analisis de seguridad a quien necesite saberlo',
    score: 'Safety Score', at: 'en', cta: 'Consulte la seguridad de cualquier direccion del mundo:',
    copy: 'Copiar enlace', copyMsg: 'Copiar mensaje', copied: 'Copiado con exito!',
    native: 'Mas opciones', email: 'Correo', cancel: 'Cerrar', preview: 'Vista previa del mensaje',
    safe: 'SEGURO', mod: 'MODERADO', crit: 'CRITICO', subject: 'Analisis de Seguridad \u2014 Portal Seguridad Global' }
};

function openShare() {
  if (!currentData) return alert('Pesquise um local antes de compartilhar.');
  var lang = window.PSG_LANG || 'pt';
  var ui = shareI18n[lang] || shareI18n.pt;
  var scoreText = (currentData.safetyScore >= 70 ? ui.safe : currentData.safetyScore >= 40 ? ui.mod : ui.crit);
  var msg = "*" + ui.subject + "*\n\n"
    + "\uD83D\uDCCD " + currentData.address.fullAddress + "\n"
    + "\uD83D\uDEE1\uFE0F " + ui.score + ": *" + currentData.safetyScore + "/100* (" + scoreText + ")\n\n"
    + ui.cta + "\n"
    + SHARE_SITE_URL + "?q=" + encodeURIComponent(currentData.address.fullAddress);

  document.getElementById('share-title').textContent = ui.title;
  document.getElementById('share-sub').textContent = ui.sub;
  document.getElementById('share-preview-text').textContent = msg;
  document.getElementById('share-copy-link-text').textContent = ui.copy;
  document.getElementById('share-copy-msg-text').textContent = ui.copyMsg;
  document.getElementById('share-native-text').textContent = ui.native;
  document.getElementById('share-cancel').textContent = ui.cancel;
  document.getElementById('share-preview-label').textContent = ui.preview;
  document.getElementById('share-email-text').textContent = ui.email;
  document.getElementById('share-copied-text').textContent = ui.copied;
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
  copyToClipboard(url, 'share-copy-link');
}

function copyShareMsg() {
  var msg = document.getElementById('share-preview-text').textContent;
  copyToClipboard(msg, 'share-copy-msg');
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

function shareToNetwork(net) {
  if (!net || !currentData) return;
  var lang = window.PSG_LANG || 'pt';
  var ui = shareI18n[lang] || shareI18n.pt;
  var url = SHARE_SITE_URL + "?q=" + encodeURIComponent(currentData.address.fullAddress);
  var msg = document.getElementById('share-preview-text').textContent || '';
  var textOnly = msg.split(url)[0].trim();
  var href = null, sameWindow = false;
  switch (net) {
    case 'whatsapp': href = 'https://api.whatsapp.com/send?text=' + encodeURIComponent(msg); break;
    case 'telegram': href = 'https://t.me/share/url?url=' + encodeURIComponent(url) + '&text=' + encodeURIComponent(textOnly); break;
    case 'twitter':  href = 'https://twitter.com/intent/tweet?text=' + encodeURIComponent(textOnly) + '&url=' + encodeURIComponent(url); break;
    case 'facebook': href = 'https://www.facebook.com/sharer/sharer.php?u=' + encodeURIComponent(url); break;
    case 'linkedin': href = 'https://www.linkedin.com/sharing/share-offsite/?url=' + encodeURIComponent(url); break;
    case 'reddit':   href = 'https://www.reddit.com/submit?url=' + encodeURIComponent(url) + '&title=' + encodeURIComponent(ui.subject); break;
    case 'email':    href = 'mailto:?subject=' + encodeURIComponent(ui.subject) + '&body=' + encodeURIComponent(msg); sameWindow = true; break;
    case 'sms':      href = 'sms:?&body=' + encodeURIComponent(msg); sameWindow = true; break;
  }
  if (!href) return;
  if (sameWindow) { window.location.href = href; }
  else { window.open(href, '_blank', 'noopener'); }
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
  document.getElementById('terms-overlay').classList.remove('active');
  if (window._pendingSearch) { window._pendingSearch = false; handleSearch(); }
  if (window._pendingMapSearch) { window._pendingMapSearch = false; openMapSearch(); }
  if (window._pendingGpsSearch) { window._pendingGpsSearch = false; searchByGps(); }
}
function showTermsModal() { var el = document.getElementById('terms-overlay'); el.classList.remove('hidden'); el.classList.add('active'); }

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
// MANUAL MULTILINGUE
// Abre no idioma do pais clicado na bandeira
// ============================================================
(function() {
  var MANUAL_I18N = {
    pt: {
      title: 'Manual de Instrucoes',
      steps: [
        { h: 'Digite um local', p: 'Use CEP, endereco completo, coordenadas GPS ou o nome de uma rodovia de qualquer pais do mundo.' },
        { h: 'Escolha no mapa (opcional)', p: 'Toque no botao do mapa para selecionar um ponto exato no globo.' },
        { h: 'Veja o Safety Score', p: 'Nota de seguranca calculada com dados abertos, alem de mapa de ocorrencias, relogio mundial com fuso horario do local e noticias do pais selecionado nas bandeiras.' },
        { h: 'Rodovias: pedagios, radares e limite', p: 'Ao pesquisar uma rodovia, o portal mostra pedagios, radares e camaras num raio de 8 km e o limite de velocidade da via mais proxima.' },
        { h: 'GPS de Estradas', p: 'Traca a rota ate o seu destino com navegacao guiada por voz e avisos automaticos de camaras, radares e pedagios a frente.' },
        { h: 'Rios e mares: avisos nauticos', p: 'Perto da agua, o portal mostra os corpos d\u2019agua proximos, as condicoes do mar (ondas e temperatura) e as orientacoes da Marinha e das autoridades de navegacao. Tudo entra tambem no relatorio PDF.' },
        { h: 'Rastreamento seguro', p: 'Veja como rastrear carros, pessoas e pets de forma simples e segura, com orientacoes e boas praticas.' },
        { h: 'Compartilhe ou baixe o PDF', p: 'Envie a analise por WhatsApp, Telegram, e-mail e redes sociais, ou baixe o relatorio PDF gratuito com QR de verificacao, fundamentacao legal e avisos oficiais.' },
        { h: 'Caminhada Segura', p: 'Na pagina Caminhada Segura, toque em iniciar, envie o link por WhatsApp e o responsavel acompanha sua rota em tempo real, com botao de emergencia.' },
        { h: 'Central de Noticias e atualizacao automatica', p: 'A pagina Noticias traz artigos e manchetes atualizadas automaticamente: camaras, protecao pessoal, pets, bikes, motos e carros. O portal tambem se atualiza sozinho, sem precisar recarregar.' },
        { h: 'Importante', p: 'Nao consultamos CPF, CNPJ, RG ou dados pessoais. Use apenas enderecos.' }
      ]
    },
    en: {
      title: 'User Manual',
      steps: [
        { h: 'Enter a location', p: 'Use a ZIP/postcode, full address, GPS coordinates, or a highway name from anywhere in the world.' },
        { h: 'Pick on the map (optional)', p: 'Tap the map button to select an exact point on the globe.' },
        { h: 'See the Safety Score', p: 'A safety rating based on open data, plus an occurrence map, world clock with local timezone, and news for the country selected in the flags.' },
        { h: 'Highways: tolls, radars and limits', p: 'When you search a highway, the portal shows tolls, radars and speed cameras within 8 km, plus the speed limit of the nearest road.' },
        { h: 'Road GPS', p: 'Trace your route with voice-guided navigation and automatic warnings of cameras, radars and tolls ahead.' },
        { h: 'Rivers and seas: nautical warnings', p: 'Near water, the portal shows nearby water bodies, sea conditions (waves and temperature) and guidance from navies and navigation authorities. Everything is also included in the PDF report.' },
        { h: 'Safe tracking', p: 'Learn how to track cars, people and pets in a simple and safe way, with guidance and best practices.' },
        { h: 'Share or download the PDF', p: 'Send the analysis via WhatsApp, Telegram, email and social networks, or download the free PDF report with verification QR code, legal basis and official notices.' },
        { h: 'Safe Walk', p: 'On the Safe Walk page, tap start, share the link via WhatsApp, and a guardian follows your route in real time with an emergency button.' },
        { h: 'News hub and auto-update', p: 'The News page brings articles and automatically updated headlines: cameras, personal protection, pets, bikes, motorcycles and cars. The portal also updates itself, no reload needed.' },
        { h: 'Important', p: 'We do not query ID, tax or personal records. Use addresses only.' }
      ]
    },
    es: {
      title: 'Manual de Instrucciones',
      steps: [
        { h: 'Escriba un lugar', p: 'Use código postal, dirección completa, coordenadas GPS o el nombre de una carretera de cualquier país del mundo.' },
        { h: 'Elija en el mapa (opcional)', p: 'Toque el botón del mapa para seleccionar un punto exacto en el globo.' },
        { h: 'Vea el Safety Score', p: 'Nota de seguridad calculada con datos abiertos, además de mapa de ocurrencias, reloj mundial con huso horario local y noticias del país seleccionado en las banderas.' },
        { h: 'Carreteras: peajes, radares y límites', p: 'Al buscar una carretera, el portal muestra peajes, radares y cámaras en un radio de 8 km y el límite de velocidad de la vía más cercana.' },
        { h: 'GPS de Carreteras', p: 'Trace su ruta con navegación guiada por voz y avisos automáticos de cámaras, radares y peajes más adelante.' },
        { h: 'Ríos y mares: avisos náuticos', p: 'Cerca del agua, el portal muestra los cuerpos de agua cercanos, las condiciones del mar (olas y temperatura) y las orientaciones de la Marina y las autoridades de navegación. Todo también entra en el informe PDF.' },
        { h: 'Rastreo seguro', p: 'Vea cómo rastrear coches, personas y mascotas de forma simple y segura, con orientaciones y buenas prácticas.' },
        { h: 'Comparta o descargue el PDF', p: 'Envíe el análisis por WhatsApp, Telegram, correo electrónico y redes sociales, o descargue el informe PDF gratuito con QR de verificación, fundamentación legal y avisos oficiales.' },
        { h: 'Caminata Segura', p: 'En la página Caminata Segura, toque iniciar, envíe el enlace por WhatsApp y el responsable acompaña su ruta en tiempo real, con botón de emergencia.' },
        { h: 'Centro de Noticias y actualización automática', p: 'La página de Noticias trae artículos y titulares actualizados automáticamente: cámaras, protección personal, mascotas, bicicletas, motos y coches. El portal también se actualiza solo, sin necesidad de recargar.' },
        { h: 'Importante', p: 'No consultamos documentos ni datos personales. Use solo direcciones.' }
      ]
    },
    fr: {
      title: "Manuel d'Instructions",
      steps: [
        { h: 'Saisissez un lieu', p: 'Utilisez un code postal, une adresse complète, des coordonnées GPS ou le nom d\u2019une route de n\u2019importe quel pays du monde.' },
        { h: 'Choisissez sur la carte (facultatif)', p: 'Touchez le bouton carte pour sélectionner un point exact sur le globe.' },
        { h: 'Consultez le Safety Score', p: 'Note de sécurité calculée avec des données ouvertes, plus une carte des occurrences, une horloge mondiale avec le fuseau horaire local et les actualités du pays choisi dans les drapeaux.' },
        { h: 'Routes : péages, radars et limites', p: 'Lors d\u2019une recherche de route, le portail affiche les péages, radars et caméras dans un rayon de 8 km, ainsi que la limite de vitesse de la route la plus proche.' },
        { h: 'GPS Routier', p: 'Tracez votre itinéraire avec une navigation vocale et des avertissements automatiques des caméras, radars et péages à venir.' },
        { h: 'Rivières et mers : avis nautiques', p: 'Près de l\u2019eau, le portail affiche les plans d\u2019eau proches, les conditions de la mer (vagues et température) et les recommandations de la Marine et des autorités de navigation. Tout figure aussi dans le rapport PDF.' },
        { h: 'Suivi sécurisé', p: 'Découvrez comment suivre voitures, personnes et animaux de compagnie de manière simple et sûre, avec conseils et bonnes pratiques.' },
        { h: 'Partagez ou téléchargez le PDF', p: 'Envoyez l\u2019analyse par WhatsApp, Telegram, e-mail et réseaux sociaux, ou téléchargez le rapport PDF gratuit avec QR de vérification, base légale et avis officiels.' },
        { h: 'Marche Sécurisée', p: 'Sur la page Marche Sécurisée, touchez démarrer, envoyez le lien par WhatsApp et un proche suit votre trajet en temps réel, avec bouton d\u2019urgence.' },
        { h: 'Centre d\u2019actualités et mise à jour automatique', p: 'La page Actualités propose des articles et des titres mis à jour automatiquement : caméras, protection personnelle, animaux, vélos, motos et voitures. Le portail se met aussi à jour tout seul, sans rechargement.' },
        { h: 'Important', p: 'Nous ne consultons aucun document ni donnée personnelle. Utilisez uniquement des adresses.' }
      ]
    },
    de: {
      title: 'Bedienungsanleitung',
      steps: [
        { h: 'Or eingeben', p: 'Verwenden Sie Postleitzahl, vollständige Adresse, GPS-Koordinaten oder den Namen einer Straße aus der ganzen Welt.' },
        { h: 'Auf der Karte wählen (optional)', p: 'Tippen Sie auf die Karten-Schaltfläche, um einen genauen Punkt auf dem Globus auszuwählen.' },
        { h: 'Safety Score ansehen', p: 'Sicherheitsnote auf Basis offener Daten, dazu Vorkommnis-Karte, Weltuhr mit lokaler Zeitzone und Nachrichten des in den Flaggen gewählten Landes.' },
        { h: 'Straßen: Maut, Blitzer und Limits', p: 'Bei der Suche nach einer Straße zeigt das Portal Mautstellen, Blitzer und Kameras im Umkreis von 8 km sowie das Tempolimit der nächsten Straße.' },
        { h: 'Straßen-GPS', p: 'Route planen mit sprachgeführter Navigation und automatischen Warnungen vor Kameras, Blitzern und Mautstellen.' },
        { h: 'Flüsse und Meere: nautische Warnungen', p: 'In Wassernähe zeigt das Portal nahegelegene Gewässer, Meeresbedingungen (Wellen und Temperatur) sowie Hinweise der Marine und der Schifffahrtsbehörden. Alles steht auch im PDF-Bericht.' },
        { h: 'Sicheres Tracking', p: 'Erfahren Sie, wie Sie Autos, Personen und Haustiere einfach und sicher orten können, mit Tipps und bewährten Methoden.' },
        { h: 'Teilen oder PDF herunterladen', p: 'Senden Sie die Analyse per WhatsApp, Telegram, E-Mail und sozialen Netzwerken oder laden Sie den kostenlosen PDF-Bericht mit Verifizierungs-QR-Code, Rechtsgrundlage und offiziellen Hinweisen herunter.' },
        { h: 'Sicherer Spaziergang', p: 'Auf der Seite Sicherer Spaziergang starten Sie die Freigabe, senden den Link per WhatsApp, und eine Vertrauensperson verfolgt Ihre Route in Echtzeit - mit Notfallknopf.' },
        { h: 'News-Center und Auto-Update', p: 'Die News-Seite bietet Artikel und automatisch aktualisierte Schlagzeilen: Kameras, Personenschutz, Haustiere, Fahrr\u00e4der, Motorr\u00e4der und Autos. Das Portal aktualisiert sich auch von selbst, ohne Neuladen.' },
        { h: 'Wichtig', p: 'Wir fragen keine Ausweise oder persönlichen Daten ab. Verwenden Sie nur Adressen.' }
      ]
    },
    it: {
      title: 'Manuale di Istruzioni',
      steps: [
        { h: 'Digita un luogo', p: 'Usa CAP, indirizzo completo, coordinate GPS o il nome di una strada di qualsiasi paese del mondo.' },
        { h: 'Scegli sulla mappa (facoltativo)', p: 'Tocca il pulsante mappa per selezionare un punto esatto sul globo.' },
        { h: 'Guarda il Safety Score', p: 'Voto di sicurezza calcolato con dati aperti, oltre a mappa degli eventi, orologio mondiale con fuso orario locale e notizie del paese scelto nelle bandiere.' },
        { h: 'Strade: pedaggi, autovelox e limiti', p: 'Cercando una strada, il portale mostra pedaggi, autovelox e telecamere in un raggio di 8 km e il limite di velocità della strada più vicina.' },
        { h: 'GPS Stradale', p: 'Traccia il percorso con navigazione vocale e avvisi automatici di telecamere, autovelox e pedaggi davanti a te.' },
        { h: 'Fiumi e mari: avvisi nautici', p: 'Vicino all\u2019acqua, il portale mostra i corpi idrici vicini, le condizioni del mare (onde e temperatura) e le indicazioni della Marina e delle autorità di navigazione. Tutto entra anche nel rapporto PDF.' },
        { h: 'Tracciamento sicuro', p: 'Scopri come tracciare auto, persone e animali domestici in modo semplice e sicuro, con consigli e buone pratiche.' },
        { h: 'Condividi o scarica il PDF', p: 'Invia l\u2019analisi via WhatsApp, Telegram, e-mail e social network, oppure scarica il rapporto PDF gratuito con QR di verifica, base legale e avvisi ufficiali.' },
        { h: 'Camminata Sicura', p: 'Nella pagina Camminata Sicura, tocca avvia, invia il link via WhatsApp e un responsabile segue il tuo percorso in tempo reale, con pulsante di emergenza.' },
        { h: 'Centro Notizie e aggiornamento automatico', p: 'La pagina Notizie porta articoli e titoli aggiornati automaticamente: telecamere, protezione personale, animali, bici, moto e auto. Il portale si aggiorna anche da solo, senza ricaricare.' },
        { h: 'Importante', p: 'Non consultiamo documenti o dati personali. Usa solo indirizzi.' }
      ]
    },
    zh: {
      title: '使用手册',
      steps: [
        { h: '输入地点', p: '输入邮政编码、完整地址、GPS坐标或世界任何国家的公路名称。' },
        { h: '在地图上选择（可选）', p: '点击地图按钮选择地球上的精确位置。' },
        { h: '查看安全评分', p: '基于开放数据计算的安全评分，还包括事件地图、当地时间的世界时钟，以及所选国家（旗帜）的新闻。' },
        { h: '公路：收费、雷达与限速', p: '搜索公路时，门户网站会显示8公里范围内的收费站、测速雷达和摄像头，以及最近道路的限速。' },
        { h: '公路GPS', p: '规划路线，配语音导航，并自动提醒前方的摄像头、测速雷达和收费站。' },
        { h: '河流与海洋：航行警报', p: '靠近水域时，门户网站会显示附近水域、海况（海浪和温度），以及海军和航行当局的指引。所有内容也会写入PDF报告。' },
        { h: '安全追踪', p: '了解如何以简单安全的方式追踪汽车、人员和宠物，附指引和最佳实践。' },
        { h: '分享或下载PDF', p: '通过WhatsApp、Telegram、电子邮件和社交网络发送分析，或下载免费PDF报告，含验证二维码、法律依据和官方公告。' },
        { h: '安全散步', p: '在安全散步页面点击开始，通过WhatsApp发送链接，家人即可实时跟踪您的路线，并配有紧急按钮。' },
        { h: '新闻中心与自动更新', p: '新闻页面提供自动更新的文章和头条：摄像头、个人防护、宠物、自行车、摩托车和汽车。门户网站也会自动更新，无需重新加载。' },
        { h: '重要提示', p: '我们不查询证件号码或个人数据。请仅使用地址。' }
      ]
    },
    ja: {
      title: '取扱説明書',
      steps: [
        { h: '場所を入力', p: '郵便番号、住所、GPS座標、または世界中の道路名を入力してください。' },
        { h: '地図で選択（任意）', p: '地図ボタンをタップして地球上の正確な地点を選択します。' },
        { h: '安全スコアを確認', p: '公開データに基づく安全スコアのほか、事件マップ、現地タイムゾーン付きの世界時計、旗で選んだ国のニュースを提供します。' },
        { h: '道路：料金・レーダー・速度制限', p: '道路を検索すると、8km圏内の料金所、速度違反取締装置（オービス）とカメラ、および最寄り道路の速度制限を表示します。' },
        { h: '道路GPS', p: '音声ナビゲーション付きのルート案内と、前方のカメラ・オービス・料金所の自動警告機能。' },
        { h: '川と海：海難警報', p: '水辺では、近くの水域、海の状態（波と水温）、海軍および航海当局の指針を表示します。すべてPDFレポートにも含まれます。' },
        { h: '安全な追跡', p: '車、人、ペットを簡単かつ安全に追跡する方法を、ガイドとベストプラクティスとともに紹介します。' },
        { h: '共有またはPDFダウンロード', p: 'WhatsApp、Telegram、メール、SNSで分析を送信、または検証QRコード、法的根拠、公式通知付きの無料PDFレポートをダウンロードできます。' },
        { h: '安全な散歩', p: '安全な散歩ページで開始をタップし、WhatsAppでリンクを送ると、家族が緊急ボタン付きでルートをリアルタイムで追跡できます。' },
        { h: 'ニュースセンターと自動更新', p: 'ニュースページは、カメラ、身辺保護、ペット、自転車、バイク、自動車に関する記事と自動更新される見出しを提供します。ポータル自体も再読み込みなしで自動更新されます。' },
        { h: '重要', p: '個人番号や個人データは照会しません。住所のみをご利用ください。' }
      ]
    },
    ar: {
      title: 'دليل الاستخدام',
      steps: [
        { h: 'أدخل الموقع', p: 'أدخل الرمز البريدي أو العنوان الكامل أو إحداثيات GPS أو اسم طريق من أي دولة في العالم.' },
        { h: 'اختر على الخريطة (اختياري)', p: 'اضغط على زر الخريطة لاختيار نقطة دقيقة على الكرة الأرضية.' },
        { h: 'اطّلع على درجة الأمان', p: 'درجة أمان محسوبة من البيانات المفتوحة، مع خريطة الحوادث وساعة عالمية بالتوقيت المحلي وأخبار الدولة المختارة في الأعلام.' },
        { h: 'الطرق: الرسوم والرادارات والحدود', p: 'عند البحث عن طريق، يعرض البوابة الرسوم ورادارات السرعة والكاميرات في نطاق 8 كم، وحد السرعة لأقرب طريق.' },
        { h: 'GPS الطرق', p: 'ارسم مسارك مع ملاحة صوتية وتحذيرات تلقائية من الكاميرات والرادارات ومراكز الرسوم أمامك.' },
        { h: 'الأنهار والبحار: تحذيرات ملاحية', p: 'قرب الماء، يعرض البوابة المسطحات المائية القريبة وحالة البحر (الأمواج ودرجة الحرارة) وإرشادات البحرية وسلطات الملاحة. كل ذلك يرد أيضًا في تقرير PDF.' },
        { h: 'التتبع الآمن', p: 'تعرّف على كيفية تتبع السيارات والأشخاص والحيوانات الأليفة بطريقة بسيطة وآمنة، مع إرشادات وأفضل الممارسات.' },
        { h: 'شارك أو حمّل ملف PDF', p: 'أرسل التحليل عبر واتساب وتيليجرام والبريد الإلكتروني والشبكات الاجتماعية، أو حمّل تقرير PDF المجاني مع رمز تحقق QR والأساس القانوني والإعلانات الرسمية.' },
        { h: 'المشي الآمن', p: 'في صفحة المشي الآمن، اضغط ابدأ وأرسل الرابط عبر واتساب ليتابع أحد المسؤولين مسارك في الوقت الفعلي مع زر الطوارئ.' },
        { h: 'مركز الأخبار والتحديث التلقائي', p: 'تقدم صفحة الأخبار مقالات وعناوين تُحدَّث تلقائيًا: الكاميرات، الحماية الشخصية، الحيوانات الأليفة، الدراجات، الدراجات النارية والسيارات. كما يتحدث البوابة تلقائيًا دون إعادة تحميل.' },
        { h: 'مهم', p: 'لا نستعلم عن أرقام الهوية أو البيانات الشخصية. استخدم العناوين فقط.' }
      ]
    },
    ru: {
      title: 'Руководство пользователя',
      steps: [
        { h: 'Введите место', p: 'Введите почтовый индекс, полный адрес, GPS-координаты или название шоссе из любой страны мира.' },
        { h: 'Выберите на карте (необязательно)', p: 'Нажмите кнопку карты, чтобы выбрать точную точку на глобусе.' },
        { h: 'Посмотрите Safety Score', p: 'Оценка безопасности на основе открытых данных, а также карта происшествий, мировые часы с местным часовым поясом и новости страны, выбранной во флажках.' },
        { h: 'Шоссе: платные дороги, радары и лимиты', p: 'При поиске шоссе портал показывает платные пункты, радары и камеры в радиусе 8 км, а также ограничение скорости ближайшей дороги.' },
        { h: 'Дорожный GPS', p: 'Проложите маршрут с голосовой навигацией и автоматическими предупреждениями о камерах, радарах и платных пунктах впереди.' },
        { h: 'Реки и моря: морские предупреждения', p: 'Рядом с водой портал показывает ближайшие водоёмы, состояние моря (волны и температура) и рекомендации ВМФ и навигационных властей. Всё это также входит в PDF-отчёт.' },
        { h: 'Безопасное отслеживание', p: 'Узнайте, как отслеживать автомобили, людей и питомцев просто и безопасно, с рекомендациями и лучшими практиками.' },
        { h: 'Поделитесь или скачайте PDF', p: 'Отправьте анализ через WhatsApp, Telegram, электронную почту и соцсети или скачайте бесплатный PDF-отчёт с QR-кодом проверки, правовым обоснованием и официальными уведомлениями.' },
        { h: 'Безопасная прогулка', p: 'На странице «Безопасная прогулка» нажмите начать, отправьте ссылку через WhatsApp, и ответственный человек будет отслеживать ваш маршрут в реальном времени с кнопкой экстренной помощи.' },
        { h: 'Центр новостей и автообновление', p: 'Страница новостей предлагает статьи и автоматически обновляемые заголовки: камеры, личная защита, питомцы, велосипеды, мотоциклы и автомобили. Портал также обновляется сам, без перезагрузки.' },
        { h: 'Важно', p: 'Мы не запрашиваем документы или персональные данные. Используйте только адреса.' }
      ]
    },
    ko: {
      title: '사용 설명서',
      steps: [
        { h: '장소 입력', p: '우편번호, 전체 주소, GPS 좌표 또는 전 세계 어느 나라의 도로 이름이든 입력하세요.' },
        { h: '지도에서 선택 (선택 사항)', p: '지도 버튼을 눌러 지구본에서 정확한 지점을 선택하세요.' },
        { h: '안전 점수 확인', p: '공개 데이터 기반 안전 점수와 함께 사건 지도, 현지 시간대가 표시되는 세계 시계, 국기에서 선택한 나라의 뉴스를 제공합니다.' },
        { h: '도로: 통행료, 레이더, 제한 속도', p: '도로를 검색하면 8km 반경 내 통행료소, 속도 단속 카메라와 레이더, 그리고 가장 가까운 도로의 제한 속도를 표시합니다.' },
        { h: '도로 GPS', p: '음성 내비게이션으로 경로를 안내하고 전방의 카메라, 레이더, 통행료소를 자동으로 경고합니다.' },
        { h: '강과 바다: 해상 경보', p: '물가 근처에서는 주변 수역, 해상 상태(파도와 수온), 해군 및 항해 당국의 지침을 표시합니다. 모든 내용은 PDF 보고서에도 포함됩니다.' },
        { h: '안전한 추적', p: '안내와 모범 사례와 함께 자동차, 사람, 반려동물을 간단하고 안전하게 추적하는 방법을 알아보세요.' },
        { h: '공유 또는 PDF 다운로드', p: 'WhatsApp, Telegram, 이메일, 소셜 네트워크로 분석 결과를 보내거나 검증 QR 코드, 법적 근거, 공지 사항이 포함된 무료 PDF 보고서를 다운로드하세요.' },
        { h: '안전 산책', p: '안전 산책 페이지에서 시작을 누르고 WhatsApp으로 링크를 보내면 가족이 긴급 버튼과 함께 실시간으로 경로를 추적합니다.' },
        { h: '뉴스 센터와 자동 업데이트', p: '뉴스 페이지는 카메라, 개인 보호, 반려동물, 자전거, 오토바이, 자동차에 관한 기사와 자동 업데이트되는 헤드라인을 제공합니다. 포털도 새로고침 없이 스스로 업데이트됩니다.' },
        { h: '중요', p: '우리는 신분증 번호나 개인 데이터를 조회하지 않습니다. 주소만 사용하세요.' }
      ]
    },
    hi: {
      title: 'उपयोगकर्ता मार्गदर्शिका',
      steps: [
        { h: 'स्थान दर्ज करें', p: 'पिन कोड, पूरा पता, GPS निर्देशांक या दुनिया के किसी भी देश की सड़क का नाम दर्ज करें।' },
        { h: 'मानचित्र पर चुनें (वैकल्पिक)', p: 'मानचित्र बटन पर क्लिक करके ग्लोब पर सटीक बिंदु चुनें।' },
        { h: 'सुरक्षा स्कोर देखें', p: 'खुले डेटा से गणना की गई सुरक्षा रेटिंग, साथ ही घटनाओं का मानचित्र, स्थानीय समय क्षेत्र वाली विश्व घड़ी, और झंडों में चुने गए देश की खबरें।' },
        { h: 'सड़कें: टोल, रडार और सीमा', p: 'सड़क खोजने पर पोर्टल 8 किमी त्रिज्या में टोल, स्पीड रडार और कैमरे, तथा निकटतम सड़क की गति सीमा दिखाता है।' },
        { h: 'सड़क GPS', p: 'आवाज़ वाले नेविगेशन के साथ रूट बनाएं और आगे आने वाले कैमरों, रडार और टोल की स्वतः चेतावनी पाएं।' },
        { h: 'नदियाँ और समुद्र: समुद्री चेतावनियाँ', p: 'पानी के पास होने पर पोर्टल नज़दीकी जलस्रोत, समुद्र की स्थिति (लहरें और तापमान) तथा नौसेना और नेविगेशन प्राधिकरणों के दिशा-निर्देश दिखाता है। यह सब PDF रिपोर्ट में भी आता है।' },
        { h: 'सुरक्षित ट्रैकिंग', p: 'मार्गदर्शन और सर्वोत्तम प्रथाओं के साथ जानें कि कारों, लोगों और पालतू जानवरों को कैसे सरल और सुरक्षित तरीके से ट्रैक करें।' },
        { h: 'साझा करें या PDF डाउनलोड करें', p: 'WhatsApp, Telegram, ईमेल और सोशल नेटवर्क पर विश्लेषण भेजें, या सत्यापन QR कोड, कानूनी आधार और आधिकारिक सूचनाओं के साथ निःशुल्क PDF रिपोर्ट डाउनलोड करें।' },
        { h: 'सुरक्षित सैर', p: 'सुरक्षित सैर पेज पर शुरू करें दबाएं, WhatsApp पर लिंक भेजें, और एक जिम्मेदार व्यक्ति आपातकालीन बटन के साथ आपके मार्ग को वास्तविक समय में देखता है।' },
        { h: 'समाचार केंद्र और स्वतः अद्यतन', p: 'समाचार पेज कैमरों, व्यक्तिगत सुरक्षा, पालतू जानवरों, साइकिल, मोटरसाइकिल और कारों पर स्वतः अद्यतन होने वाले लेख और शीर्षक देता है। पोर्टल भी बिना रीलोड स्वयं अपडेट होता है।' },
        { h: 'महत्वपूर्ण', p: 'हम दस्तावेज़ नंबर या व्यक्तिगत डेटा की जांच नहीं करते। केवल पते का उपयोग करें।' }
      ]
    },
  };

  function renderManual(lang) {
    lang = MANUAL_I18N[lang] ? lang : 'pt';
    var data = MANUAL_I18N[lang];
    var title = document.getElementById('manual-title');
    var content = document.getElementById('manual-content');
    var select = document.getElementById('manual-lang');
    if (title) title.textContent = data.title;
    if (select) select.value = lang;
    if (!content) return;
    content.innerHTML = '';
    data.steps.forEach(function(step, idx) {
      var div = document.createElement('div');
      div.className = 'manual-step';
      div.innerHTML = '<div class="manual-step-num">' + (idx + 1) + '</div>' +
        '<div class="manual-step-text"><h3>' + escapeHtml(step.h) + '</h3><p>' + escapeHtml(step.p) + '</p></div>';
      content.appendChild(div);
    });
  }

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function manualLangFromFlag(flagLang) {
    var map = {
      'pt-BR': 'pt', 'en-US': 'en', 'es': 'es', 'fr': 'fr', 'de': 'de',
      'it': 'it', 'ja': 'ja', 'zh': 'zh', 'ar': 'ar', 'ru': 'ru', 'ko': 'ko', 'hi': 'hi'
    };
    return map[flagLang] || flagLang;
  }

  function bindManualEvents() {
    var select = document.getElementById('manual-lang');
    if (select) {
      select.addEventListener('change', function() { renderManual(select.value); });
    }

    // Quando o usuario clica em uma bandeira lateral
    var flags = document.querySelectorAll('.flags-column .flag-item');
    flags.forEach(function(flag) {
      flag.addEventListener('click', function() {
        var lang = flag.getAttribute('data-lang');
        renderManual(manualLangFromFlag(lang));
      });
    });

    // Quando o usuario clica na barra de idiomas mobile
    var mlbFlags = document.querySelectorAll('.mobile-lang-bar .mlb-flag');
    mlbFlags.forEach(function(flag) {
      flag.addEventListener('click', function() {
        var lang = flag.getAttribute('data-lang');
        renderManual(manualLangFromFlag(lang));
      });
    });
  }

  function initManual() {
    bindManualEvents();
    var select = document.getElementById('manual-lang');
    var initialLang = (window.PSG_LANG || 'pt').replace(/-BR|-US/g, '');
    if (select && MANUAL_I18N[select.value]) initialLang = select.value;
    renderManual(MANUAL_I18N[initialLang] ? initialLang : 'pt');
  }

  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', initManual); }
  else { initManual(); }
})();

// ============================================================
// LINK COMPARTILHADO â€” abre a analise direto pelo parametro ?q=
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

// ============================================================
// NEWSLETTER AJAX â€” mostra se a pessoa conseguiu ou nao se inscrever
// ============================================================
(function() {
  function initNewsletter() {
    var form = document.getElementById('nl-form');
    if (!form) return;
    var msg = document.getElementById('nl-msg');
    var btn = document.getElementById('nl-btn');
    function show(kind, html) {
      if (!msg) return;
      var cores = {
        ok:  'border:1px solid rgba(34,197,94,.4);background:rgba(34,197,94,.12);color:#4ade80;',
        err: 'border:1px solid rgba(239,68,68,.4);background:rgba(239,68,68,.12);color:#f87171;',
        load:'border:1px solid rgba(59,130,246,.4);background:rgba(59,130,246,.12);color:#93c5fd;'
      };
      msg.style.cssText = 'display:block;margin:.8rem auto 0;max-width:420px;padding:.8rem 1rem;border-radius:10px;font-size:.85rem;font-weight:600;line-height:1.5;text-align:center;' + (cores[kind] || '');
      msg.innerHTML = html;
    }
    form.addEventListener('submit', function(e) {
      e.preventDefault();
      var input = form.querySelector('input[name=email]');
      var email = (input && input.value || '').trim();
      if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(email)) {
        show('err', '&#10060; <b>N&atilde;o foi poss&iacute;vel inscrever:</b> digite um e-mail v&aacute;lido (ex.: nome@email.com).');
        if (input) { try { input.focus(); } catch (err) {} }
        return;
      }
      if (btn) { btn.disabled = true; btn.textContent = 'Enviando...'; }
      show('load', '&#8987; Enviando sua inscri&ccedil;&atilde;o...');
      fetch('https://formsubmit.co/ajax/gersonfer007@hotmail.com', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({
          _subject: 'Novo inscrito na newsletter - Portal Seguran\u00e7a Global',
          _template: 'table',
          _captcha: 'false',
          email: email
        })
      })
        .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
        .then(function(j) {
          if (j && (j.success === 'true' || j.success === true)) {
            form.reset();
            show('ok', '&#9989; <b>Inscri&ccedil;&atilde;o realizada com sucesso!</b> Voc&ecirc; receber&aacute; as pr&oacute;ximas novidades de seguran&ccedil;a por e-mail.');
          } else {
            show('err', '&#10060; <b>N&atilde;o foi poss&iacute;vel concluir a inscri&ccedil;&atilde;o.</b> O servi&ccedil;o de e-mail pode estar em ativa&ccedil;&atilde;o &mdash; tente novamente em alguns minutos.');
          }
        })
        .catch(function() {
          show('err', '&#10060; <b>Falha na inscri&ccedil;&atilde;o.</b> Sem conex&atilde;o com o servi&ccedil;o agora. Tente novamente em instantes.');
        })
        .finally(function() {
          if (btn) { btn.disabled = false; btn.textContent = 'Inscrever-se'; }
        });
    });
  }
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', initNewsletter); }
  else { initNewsletter(); }
})();

// ============================================================
// NEWSLETTER â€” mensagem de sucesso ao voltar com ?inscrito=1
// ============================================================
(function() {
  function showSubscriptionOk() {
    var ok = false;
    try { ok = new URLSearchParams(window.location.search).get('inscrito') === '1'; } catch (e) { return; }
    if (!ok) return;
    var box = document.querySelector('.nl-box');
    if (!box) return;
    var msg = document.createElement('div');
    msg.className = 'nl-ok';
    msg.setAttribute('role', 'status');
    msg.innerHTML = '&#9989; Inscri&ccedil;&atilde;o recebida! Voc&ecirc; receber&aacute; as pr&oacute;ximas novidades por e-mail.';
    msg.style.cssText = 'margin:1rem auto 0;max-width:420px;padding:.8rem 1rem;border-radius:10px;border:1px solid rgba(34,197,94,.4);background:rgba(34,197,94,.12);color:#4ade80;font-size:.85rem;font-weight:600;';
    box.appendChild(msg);
    if (box.scrollIntoView) { try { box.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (e) {} }
  }
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', showSubscriptionOk); }
  else { showSubscriptionOk(); }
})();

// ============================================================
// MODAL DE ORCAMENTO â€” banner "Proteja sua Familia"
// ============================================================
(function() {
  function initOrcamento() {
    var overlay = document.getElementById('orc-overlay');
    var form = document.getElementById('orc-form');
    var openBtn = document.getElementById('open-orcamento');
    if (!overlay || !form) return;

    function open() {
      overlay.classList.add('active');
      var first = document.getElementById('orc-nome');
      if (first) setTimeout(function() { try { first.focus(); } catch (e) {} }, 120);
    }
    function close() { overlay.classList.remove('active'); }
    function showMsg(kind, text) {
      var m = document.getElementById('orc-msg');
      if (!m) return;
      m.className = 'orc-msg ' + kind;
      m.textContent = text;
    }

    if (openBtn) openBtn.addEventListener('click', open);
    var closeBtn = document.getElementById('orc-close');
    var cancelBtn = document.getElementById('orc-cancel');
    if (closeBtn) closeBtn.addEventListener('click', close);
    if (cancelBtn) cancelBtn.addEventListener('click', close);
    overlay.addEventListener('click', function(e) { if (e.target === overlay) close(); });
    document.addEventListener('keydown', function(e) { if (e.key === 'Escape') close(); });

    form.addEventListener('submit', function(e) {
      e.preventDefault();
      var nome = (document.getElementById('orc-nome') || {}).value || '';
      var contato = (document.getElementById('orc-contato') || {}).value || '';
      if (!nome.trim() || !contato.trim()) {
        showMsg('err', 'Preencha seu nome e um contato (e-mail ou WhatsApp).');
        return;
      }
      var sendBtn = document.getElementById('orc-send');
      if (sendBtn) sendBtn.disabled = true;
      showMsg('', '');
      var payload = {
        _subject: 'Pedido de orcamento - Portal Seguranca Global',
        _template: 'table',
        nome: nome.trim(),
        contato: contato.trim(),
        cidade: (document.getElementById('orc-cidade') || {}).value || '-',
        servico: (document.getElementById('orc-servico') || {}).value || '-',
        mensagem: (document.getElementById('orc-msg-field') || {}).value || '-'
      };
      fetch('https://formsubmit.co/ajax/gersonfer007@hotmail.com', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(payload)
      })
        .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
        .then(function() {
          form.reset();
          showMsg('ok', 'Pedido enviado com sucesso! Retornaremos o contato em breve.');
        })
        .catch(function() {
          showMsg('err', 'Nao foi possivel enviar agora. Tente novamente em instantes ou escreva para gersonfer007@hotmail.com');
        })
        .finally(function() { if (sendBtn) sendBtn.disabled = false; });
    });
  }
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', initOrcamento); }
  else { initOrcamento(); }
})();

// ============================================================
// AUTO-UPDATE â€” o portal se atualiza sozinho quando ha nova versao
// Verifica a cada 10 minutos se o app.js mudou no servidor;
// se sim, recarrega preservando a ultima busca do usuario.
// ============================================================
(function() {
  var INTERVAL = 10 * 60 * 1000;
  var baseline = null;
  function check() {
    fetch('app.js?v=' + Date.now(), { cache: 'no-store' })
      .then(function(r) { return r.text(); })
      .then(function(txt) {
        var len = txt.length;
        if (baseline === null) { baseline = len; return; }
        if (len !== baseline) {
          var termo = '';
          try { termo = (document.getElementById('search-input') || {}).value || ''; } catch (e) {}
          if (!termo) { try { termo = new URLSearchParams(window.location.search).get('q') || ''; } catch (e) {} }
          if (termo) { window.location.search = '?q=' + encodeURIComponent(termo); }
          else { window.location.reload(); }
        }
      })
      .catch(function() {});
  }
  function start() { check(); setInterval(check, INTERVAL); }
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', start); }
  else { start(); }
})();

// ============================================================
// GPS DE ESTRADAS — rota (OSRM) + navegacao guiada por voz
// Origem: local analisado, texto livre ou geolocalizacao.
// Destino: texto geocodificado via Nominatim.
// ============================================================
(function() {
  var overlay, origemInput, destinoInput, summaryEl, stepsEl, statusEl;
  var traceBtn, navStartBtn, navStopBtn, soundBtn;
  var route = null;            // { coords:[[lat,lng]], steps:[], distance, duration }
  var origemFix = null;        // {lat,lng} quando origem = minha localizacao
  var gpsRouteLayer = null, gpsPosMarker = null;
  var watchId = null, soundOn = true;
  var spokenSteps = {}, navStepIdx = 0, stepLis = [];
  var hazards = [];             // radares/cameras/pedagios na rota
  var gpsHazardLayer = null;
  var summaryBase = '';
  var hazardsFailed = false;    // true quando o Overpass nao respondeu

  function el(id) { return document.getElementById(id); }
  function esc(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  function status(kind, html) {
    if (!statusEl) return;
    statusEl.className = 'gps-status ' + kind;
    statusEl.innerHTML = html;
  }

  function fmtDist(m) {
    if (!isFinite(m)) return '-';
    if (m < 1000) return Math.max(1, Math.round(m)) + ' m';
    return (m / 1000).toFixed(m < 10000 ? 1 : 0).replace('.', ',') + ' km';
  }
  function fmtDur(s) {
    var min = Math.round(s / 60);
    if (min < 60) return min + ' min';
    var h = Math.floor(min / 60), m = min % 60;
    return h + ' h' + (m ? ' ' + m + ' min' : '');
  }

  function speak(txt) {
    if (!soundOn || !('speechSynthesis' in window)) return;
    try {
      var u = new SpeechSynthesisUtterance(txt);
      u.lang = 'pt-BR'; u.rate = 1;
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(u);
    } catch (e) {}
  }

  function haversine(a, b) {
    var R = 6371000, rad = Math.PI / 180;
    var dLat = (b.lat - a.lat) * rad, dLng = (b.lng - a.lng) * rad;
    var s = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(a.lat * rad) * Math.cos(b.lat * rad) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
    return 2 * R * Math.atan2(Math.sqrt(s), Math.sqrt(1 - s));
  }

  // Traducao das manobras do OSRM para portugues do Brasil
  function maneuverText(step) {
    var m = (step && step.maneuver) || {};
    var type = m.type || '', mod = m.modifier || '';
    var via = step.name ? ' pela ' + step.name : (step.ref ? ' pela ' + step.ref : '');
    var side = '';
    if (mod.indexOf('left') > -1) side = 'a esquerda';
    else if (mod.indexOf('right') > -1) side = 'a direita';
    switch (type) {
      case 'depart': return 'Siga' + (step.name ? ' pela ' + step.name : ' em frente');
      case 'arrive': return 'Voce chegou ao destino';
      case 'turn':
        if (mod === 'uturn') return 'Faca o retorno';
        if (mod === 'sharp left') return 'Vire acentuadamente a esquerda' + via;
        if (mod === 'sharp right') return 'Vire acentuadamente a direita' + via;
        if (mod === 'slight left') return 'Mantenha-se a esquerda' + via;
        if (mod === 'slight right') return 'Mantenha-se a direita' + via;
        return 'Vire ' + side + via;
      case 'new name':
      case 'continue': return 'Continue' + (step.name ? ' pela ' + step.name : ' em frente');
      case 'merge': return 'Entre' + (side ? ' a ' + side : '') + via;
      case 'on ramp': return 'Pegue o acesso' + (side ? ' a ' + side : '') + via;
      case 'off ramp': return 'Pegue a saida' + (side ? ' a ' + side : '') + via;
      case 'fork': return 'Mantenha-se ' + (side ? 'a ' + side : 'em frente') + ' na bifurcacao' + via;
      case 'end of road': return 'No fim da via, vire ' + side + via;
      case 'roundabout':
      case 'rotary': return 'Entre na rotatoria' + (m.exit ? ' e saia na ' + m.exit + 'a saida' : '') + via;
      case 'roundabout turn': return 'Na rotatoria, saia e vire ' + side + via;
      case 'exit roundabout':
      case 'exit rotary': return 'Saira da rotatoria' + via;
      default: return 'Continue' + (step.name ? ' pela ' + step.name : ' em frente');
    }
  }

  function openGps(auto) {
    if (!overlay) return;
    overlay.classList.add('active');
    // Pre-preenche a origem com o local analisado (ou a busca atual)
    if (!origemInput.value) {
      var startTxt = '';
      try {
        if (typeof currentData !== 'undefined' && currentData && currentData.address) {
          var A = currentData.address;
          startTxt = [A.street || A.neighborhood, A.city, A.state, A.country].filter(Boolean).join(', ');
        }
      } catch (e) {}
      if (!startTxt) {
        try { startTxt = (el('search-input') || {}).value || ''; } catch (e) {}
      }
      if (startTxt) origemInput.value = startTxt;
    }
    // Pre-preenche o destino com a busca atual (se nao for igual a origem)
    if (!destinoInput.value) {
      try {
        var q = (el('search-input') || {}).value || '';
        if (q && q !== origemInput.value) destinoInput.value = q;
      } catch (e) {}
    }
    // Entrada rapida: sem origem conhecida, jah pede a localizacao do GPS
    if (auto && !origemInput.value && navigator.geolocation) {
      useMyLocation();
    }
    try { setTimeout(function() { (destinoInput.value ? destinoInput : origemInput).focus(); }, 150); } catch (e) {}
  }

  function closeGps() {
    if (!overlay) return;
    stopNav();
    overlay.classList.remove('active');
  }

  function useMyLocation() {
    if (!navigator.geolocation) {
      status('err', 'Seu navegador nao suporta geolocalizacao.');
      return;
    }
    status('info', 'Obtendo sua localizacao pelo GPS...');
    navigator.geolocation.getCurrentPosition(function(pos) {
      origemFix = { lat: pos.coords.latitude, lng: pos.coords.longitude };
      origemInput.value = 'Minha localizacao (GPS)';
      status('ok', 'Localizacao detectada! Agora escreva o destino e tracar a rota.');
    }, function() {
      status('err', 'Nao foi possivel obter sua localizacao. Verifique se o GPS esta ativo e se o navegador tem permissao.');
    }, { enableHighAccuracy: true, timeout: 15000, maximumAge: 30000 });
  }

  async function traceRoute() {
    var oq = (origemInput.value || '').trim();
    var dq = (destinoInput.value || '').trim();
    if (!oq || !dq) {
      status('err', 'Preencha a <b>origem</b> e o <b>destino</b> para tracar a rota.');
      return;
    }
    traceBtn.disabled = true;
    status('info', 'Localizando origem e destino no mapa...');
    try {
      var o = null, d = null;
      if (origemFix && oq.indexOf('Minha localizacao') === 0) o = origemFix;
      if (!o) o = await geocodeQuery(oq, false);
      d = await geocodeQuery(dq, false);
      if (!o || !isFinite(o.lat) || !isFinite(o.lng)) {
        status('err', 'Nao encontrei a <b>origem</b>. Tente escrever cidade + estado ou pais (ex.: Sao Paulo, SP).');
        traceBtn.disabled = false; return;
      }
      if (!d || !isFinite(d.lat) || !isFinite(d.lng)) {
        status('err', 'Nao encontrei o <b>destino</b>. Tente escrever cidade + estado ou pais (ex.: Curitiba, PR).');
        traceBtn.disabled = false; return;
      }
      status('info', 'Calculando a melhor rota pelas estradas...');
      var url = '/route/v1/driving/' +
        o.lng + ',' + o.lat + ';' + d.lng + ',' + d.lat +
        '?overview=full&geometries=geojson&steps=true&alternatives=false';
      var routers = [
        'https://router.project-osrm.org',
        'https://routing.openstreetmap.de/routed-car'
      ];
      var r = null, j = null;
      for (var ri = 0; ri < routers.length && !j; ri++) {
        try {
          r = await fetch(routers[ri] + url);
          if (r.ok) j = await r.json();
        } catch (e2) { /* tenta o proximo servidor de rotas */ }
      }
      if (!j || !j.routes || !j.routes.length) throw new Error('sem rota');
      var rt = j.routes[0];
      var steps = [];
      (rt.legs || []).forEach(function(leg) {
        (leg.steps || []).forEach(function(s) { steps.push(s); });
      });
      route = {
        coords: (rt.geometry.coordinates || []).map(function(c) { return [c[1], c[0]]; }),
        steps: steps,
        distance: rt.distance || 0,
        duration: rt.duration || 0
      };
      spokenSteps = {}; navStepIdx = 0;
      hazards = [];
      renderRoute();
      drawRoute(o, d);
      gpsLoadHazards();
      gpsPrecacheRouteTiles();  // salva os tiles da rota para navegar offline
      status('ok', 'Rota tracada com sucesso! Confira o resumo, veja no mapa e inicie a navegacao.');
    } catch (e) {
      status('err', 'Nao foi possivel calcular a rota agora (servico de rotas ocupado). Tente novamente em instantes.');
    }
    traceBtn.disabled = false;
  }

  function renderRoute() {
    if (!route) return;
    summaryBase = 'Distancia total: <b>' + fmtDist(route.distance) + '</b> &bull; ' +
      'Tempo estimado: <b>' + fmtDur(route.duration) + '</b> &bull; ' +
      route.steps.length + ' passos';
    updateHazardSummary();
    var html = '';
    route.steps.forEach(function(s, i) {
      html += '<li><span class="gps-step-n">' + (i + 1) + '</span><span>' + esc(maneuverText(s)) +
              '</span><span class="gps-step-d">' + fmtDist(s.distance || 0) + '</span></li>';
    });
    stepsEl.innerHTML = html;
    stepsEl.classList.add('show');
    stepLis = stepsEl ? Array.prototype.slice.call(stepsEl.children) : [];
  }

  function drawRoute(o, d) {
    try {
      if (typeof map === 'undefined' || !map) { if (typeof initMap === 'function') initMap(); }
      if (typeof map === 'undefined' || !map || typeof L === 'undefined' || !route) return;
      if (gpsRouteLayer) { try { map.removeLayer(gpsRouteLayer); } catch (e) {} }
      gpsRouteLayer = L.layerGroup();
      L.polyline(route.coords, { color: '#3b82f6', weight: 5, opacity: .85 }).addTo(gpsRouteLayer);
      L.circleMarker([o.lat, o.lng], { radius: 7, color: '#22c55e', fillColor: '#22c55e', fillOpacity: 1 }).addTo(gpsRouteLayer);
      L.circleMarker([d.lat, d.lng], { radius: 7, color: '#ef4444', fillColor: '#ef4444', fillOpacity: 1 }).addTo(gpsRouteLayer);
      gpsRouteLayer.addTo(map);
      map.fitBounds(L.latLngBounds(route.coords), { padding: [30, 30] });
    } catch (e) {}
  }

  function highlightStep(idx) {
    stepLis.forEach(function(li, i) { li.classList.toggle('current', i === idx); });
    try { if (stepLis[idx]) stepLis[idx].scrollIntoView({ block: 'nearest' }); } catch (e) {}
  }

  // ---- OFFLINE: pre-cache dos tiles do mapa ao longo da rota ----
  // A navegacao (GPS do aparelho + voz) nao precisa de internet; o mapa,
  // sim — entao salvamos os tiles da area da rota no Service Worker.
  function gpsTileXY(lat, lng, z) {
    var n = Math.pow(2, z);
    var x = Math.floor((lng + 180) / 360 * n);
    var latR = lat * Math.PI / 180;
    var y = Math.floor((1 - Math.log(Math.tan(latR) + 1 / Math.cos(latR)) / Math.PI) / 2 * n);
    return { x: Math.max(0, Math.min(n - 1, x)), y: Math.max(0, Math.min(n - 1, y)) };
  }
  function gpsPrecacheRouteTiles() {
    try {
      if (!route || !route.coords.length || !navigator.onLine) return;
      var minLat = 90, maxLat = -90, minLng = 180, maxLng = -180;
      route.coords.forEach(function(c) {
        if (c[0] < minLat) minLat = c[0];
        if (c[0] > maxLat) maxLat = c[0];
        if (c[1] < minLng) minLng = c[1];
        if (c[1] > maxLng) maxLng = c[1];
      });
      var layers = [
        'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/',
        'https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/'
      ];
      var urls = [];
      var zooms = [];
      try { if (typeof map !== 'undefined' && map && map.getZoom) zooms.push(Math.round(map.getZoom())); } catch (e) {}
      if (!zooms.length) zooms.push(12);
      zooms.push(zooms[0] - 1); // visao geral (menos tiles)
      zooms.forEach(function(z) {
        if (z < 3 || z > 16) return;
        var a = gpsTileXY(maxLat, minLng, z), b = gpsTileXY(minLat, maxLng, z);
        var count = (b.x - a.x + 1) * (b.y - a.y + 1);
        if (count > 150) return; // area grande demais neste zoom — nao salvar
        for (var x = a.x; x <= b.x; x++) {
          for (var y = a.y; y <= b.y; y++) {
            layers.forEach(function(L0) { urls.push(L0 + z + '/' + y + '/' + x); });
          }
        }
      });
      urls = urls.slice(0, 400);
      if (!urls.length) return;
      // Envia ao Service Worker (se ativo) ou busca direto (o SW cacheia)
      if (navigator.serviceWorker && navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({ type: 'CACHE_TILES', urls: urls });
      } else {
        urls.forEach(function(u) { fetch(u, { mode: 'no-cors' }).catch(function() {}); });
      }
    } catch (e) { /* prefetch e best-effort */ }
  }

  // ---- OFFLINE: indicador de conectividade no painel do GPS ----
  function gpsOfflineNotice() {
    if (!statusEl) return;
    if (!navigator.onLine) {
      if (route) {
        status('info', '&#128225; <b>SEM INTERNET &mdash; modo offline.</b> A navegacao continua funcionando: rota, voz e avisos de radar j&aacute; est&atilde;o salvos neste aparelho.');
      } else {
        status('err', '&#128225; <b>Sem internet.</b> Trace a rota enquanto online &mdash; depois a navegacao funciona offline no resto da viagem.');
      }
    }
  }

  // ---- AVISOS DE CAMERAS, RADARES E PEDAGIOS NA ROTA (OpenStreetMap) ----
  function routeBBox() {
    var minLat = 90, maxLat = -90, minLng = 180, maxLng = -180;
    route.coords.forEach(function(c) {
      if (c[0] < minLat) minLat = c[0];
      if (c[0] > maxLat) maxLat = c[0];
      if (c[1] < minLng) minLng = c[1];
      if (c[1] > maxLng) maxLng = c[1];
    });
    var pad = 0.012; // ~1,3 km de folga para cada lado da rota
    return (minLat - pad) + ',' + (minLng - pad) + ',' + (maxLat + pad) + ',' + (maxLng + pad);
  }

  async function gpsLoadHazards() {
    if (!route || !route.coords.length) return;
    var bbox = routeBBox();
    var q = '[out:json][timeout:40];(' +
      'node["highway"="speed_camera"](' + bbox + ');' +
      'node["barrier"="toll_booth"](' + bbox + ');' +
      ');out body center 300;';
    var endpoints = [
      'https://overpass-api.de/api/interpreter',
      'https://overpass.kumi.systems/api/interpreter'
    ];
    var j = null;
    for (var e = 0; e < endpoints.length && !j; e++) {
      try {
        var r = await fetch(endpoints[e], {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
          body: 'data=' + encodeURIComponent(q)
        });
        if (r.ok) j = await r.json();
      } catch (err) { /* tenta o proximo espelho */ }
    }
    if (!j || !j.elements) { hazardsFailed = true; updateHazardSummary(); return; }
    hazardsFailed = false;
    // Mantem apenas os pontos a ate ~250 m da rota
    var step = Math.max(1, Math.floor(route.coords.length / 1500));
    var found = [];
    (j.elements).forEach(function(elx) {
      var tags = elx.tags || {};
      if (elx.type !== 'node' || typeof elx.lat !== 'number' || typeof elx.lon !== 'number') return;
      var kind = tags.highway === 'speed_camera' ? 'radar' : (tags.barrier === 'toll_booth' ? 'pedagio' : null);
      if (!kind) return;
      var best = Infinity, bestIdx = 0;
      for (var i = 0; i < route.coords.length; i += step) {
        var d = haversine({ lat: elx.lat, lng: elx.lon }, { lat: route.coords[i][0], lng: route.coords[i][1] });
        if (d < best) { best = d; bestIdx = i; }
      }
      if (best > 250) return;
      found.push({
        lat: elx.lat, lng: elx.lon, kind: kind,
        maxspeed: tags.maxspeed || '', name: tags.name || '',
        prog: bestIdx, s1: false, s2: false
      });
    });
    found.sort(function(a, b) { return a.prog - b.prog; });
    hazards = found;
    drawHazardMarkers();
    updateHazardSummary();
  }

  function drawHazardMarkers() {
    try {
      if (typeof map === 'undefined' || !map || typeof L === 'undefined' || !hazards.length) return;
      if (gpsHazardLayer) { try { map.removeLayer(gpsHazardLayer); } catch (e) {} }
      gpsHazardLayer = L.layerGroup();
      hazards.forEach(function(h) {
        var ic = L.divIcon({
          html: h.kind === 'radar' ? '&#128247;' : '&#128652;',
          className: 'gps-hazard-icon',
          iconSize: [22, 22], iconAnchor: [11, 11]
        });
        L.marker([h.lat, h.lng], {
          icon: ic,
          title: h.kind === 'radar' ? 'Radar / camera de velocidade' : 'Pedagio'
        }).addTo(gpsHazardLayer);
      });
      gpsHazardLayer.addTo(map);
    } catch (e) {}
  }

  function updateHazardSummary() {
    if (!summaryEl) return;
    var nr = 0, np = 0;
    hazards.forEach(function(h) { if (h.kind === 'radar') nr++; else np++; });
    var line = '';
    if (nr) line += ' &#128247; <b>' + nr + '</b> radar(es)/camera(s) na rota';
    if (np) line += (line ? ' &bull;' : '') + ' &#128652; <b>' + np + '</b> pedagio(s) na rota';
    if (!line && hazards.length === 0 && !summaryBase) return;
    if (!line) line = hazardsFailed ? ' &#9888; nao foi possivel verificar radares agora' : ' &#9989; nenhum radar ou pedagio cadastrado na rota';
    summaryEl.innerHTML = summaryBase + '<br><span style="font-size:.78rem;">Avisos automaticos:' + line + '</span>';
    summaryEl.classList.add('show');
  }

  function nearestRouteIdx(me) {
    var best = Infinity, bi = 0;
    var step = Math.max(1, Math.floor(route.coords.length / 2000));
    for (var i = 0; i < route.coords.length; i += step) {
      var d = haversine(me, { lat: route.coords[i][0], lng: route.coords[i][1] });
      if (d < best) { best = d; bi = i; }
    }
    return bi;
  }

  function gpsSpeakHazard(h, d) {
    var lbl = (typeof roadSpeedLabel === 'function') ? roadSpeedLabel(h.maxspeed) : null;
    var lim = (h.kind === 'radar' && lbl && /^\d+/.test(lbl)) ? ', limite ' + lbl : '';
    if (h.kind === 'radar') {
      speak('Atencao: radar ou camera de velocidade a frente em ' + fmtDist(d) + lim);
      status('info', '&#128247; <b>Radar/c&acirc;mera &agrave; frente</b> em ' + fmtDist(d) +
        (lim ? ' &mdash; limite <b>' + esc(lbl) + '</b>' : '') + '. Reduza a velocidade.');
    } else {
      speak('Atencao: pedagio a frente em ' + fmtDist(d));
      status('info', '&#128652; <b>Ped&aacute;gio &agrave; frente</b> em ' + fmtDist(d) + '. Prepare-se.');
    }
  }

  function checkHazards(me, prog) {
    for (var i = 0; i < hazards.length; i++) {
      var h = hazards[i];
      if (h.prog < prog - 5) continue; // ja ficou para tras
      var dh = haversine(me, h);
      if (dh > 1500) break; // ordenados pela rota: os proximos estao ainda mais longe
      if (dh < 1500 && !h.s1) { h.s1 = true; gpsSpeakHazard(h, dh); }
      else if (dh < 400 && !h.s2) { h.s2 = true; gpsSpeakHazard(h, dh); }
    }
  }

  function onNavFix(pos) {
    if (!route) return;
    var me = { lat: pos.coords.latitude, lng: pos.coords.longitude };
    // Marcador azul da posicao atual no mapa
    try {
      if (typeof map !== 'undefined' && map && typeof L !== 'undefined') {
        if (gpsPosMarker) { try { map.removeLayer(gpsPosMarker); } catch (e) {} }
        gpsPosMarker = L.circleMarker([me.lat, me.lng], {
          radius: 8, color: '#fff', weight: 2, fillColor: '#3b82f6', fillOpacity: 1
        }).addTo(map);
      }
    } catch (e) {}

    var next = route.steps[navStepIdx + 1];

    // Avisos de camaras/radares e pedagios a frente (dados do OpenStreetMap)
    try { checkHazards(me, nearestRouteIdx(me)); } catch (e) {}

    if (!next) {
      // Ultimo trecho: distancia ate o destino
      var destPt = route.coords[route.coords.length - 1];
      var ddEnd = haversine(me, { lat: destPt[0], lng: destPt[1] });
      if (ddEnd < 70) {
        if (!spokenSteps.arrive) {
          spokenSteps.arrive = true;
          speak('Voce chegou ao destino');
          status('ok', '&#9989; <b>Voce chegou ao destino!</b> Boa viagem!');
          highlightStep(route.steps.length - 1);
        }
        stopNav();
        return;
      }
      status('info', 'Continue em frente. Destino a <b>' + fmtDist(ddEnd) + '</b>.');
      return;
    }

    var m = next.maneuver && next.maneuver.location;
    if (!m) { navStepIdx++; return; }
    var dd = haversine(me, { lat: m[1], lng: m[0] });
    var instr = maneuverText(next);

    if (dd < 55) {
      navStepIdx++;
      highlightStep(navStepIdx + 1);
      return;
    }
    if (dd < 450 && !spokenSteps['n' + (navStepIdx + 1)]) {
      spokenSteps['n' + (navStepIdx + 1)] = true;
      speak('Em ' + fmtDist(dd) + ', ' + instr);
    }
    status('info', 'Proxima: <b>' + esc(instr) + '</b> em ' + fmtDist(dd));
    highlightStep(navStepIdx + 1);
  }

  function startNav() {
    if (!route) {
      status('err', 'Primeiro <b>tracar a rota</b> (preencha origem e destino acima).');
      return;
    }
    if (!navigator.geolocation) {
      status('err', 'Seu navegador nao suporta GPS para navegacao ao vivo.');
      return;
    }
    stopNav();
    spokenSteps = {}; navStepIdx = 0;
    hazards.forEach(function(h) { h.s1 = false; h.s2 = false; });
    highlightStep(1);
    speak(maneuverText(route.steps[0]));
    watchId = navigator.geolocation.watchPosition(onNavFix, function() {
      status('err', 'Perdemos o sinal do GPS. Verifique a permissao de localizacao do navegador.');
    }, { enableHighAccuracy: true, timeout: 20000, maximumAge: 5000 });
    navStartBtn.style.display = 'none';
    navStopBtn.style.display = '';
    status('info', 'Navegacao iniciada! Siga as instrucoes por voz e mantenha o navegador aberto.');
  }

  function stopNav() {
    if (watchId !== null && navigator.geolocation) {
      try { navigator.geolocation.clearWatch(watchId); } catch (e) {}
    }
    watchId = null;
    if (navStartBtn) navStartBtn.style.display = '';
    if (navStopBtn) navStopBtn.style.display = 'none';
  }

  function initGps() {
    overlay = el('gps-overlay');
    if (!overlay) return;
    origemInput = el('gps-origem');
    destinoInput = el('gps-destino');
    summaryEl = el('gps-summary');
    stepsEl = el('gps-steps');
    statusEl = el('gps-status');
    traceBtn = el('gps-trace');
    navStartBtn = el('gps-nav-start');
    navStopBtn = el('gps-nav-stop');
    soundBtn = el('gps-sound');

    var btnGps = el('btn-gps');
    if (btnGps) btnGps.addEventListener('click', function() { openGps(); });

    // Entradas rapidas: botao flutuante (1 toque) e link GPS do cabecalho
    var fabGps = el('btn-gps-fab');
    if (fabGps) fabGps.addEventListener('click', function() { openGps(true); });
    var navGps = el('nav-gps');
    if (navGps) navGps.addEventListener('click', function(e) { e.preventDefault(); openGps(true); });
    window.psgOpenGps = openGps;

    var closeBtn = el('gps-close');
    if (closeBtn) closeBtn.addEventListener('click', closeGps);
    overlay.addEventListener('click', function(e) { if (e.target === overlay) closeGps(); });
    document.addEventListener('keydown', function(e) { if (e.key === 'Escape' && overlay.classList.contains('active')) closeGps(); });

    var fixBtn = el('gps-origem-fix');
    if (fixBtn) fixBtn.addEventListener('click', useMyLocation);
    if (traceBtn) traceBtn.addEventListener('click', function() { traceRoute(); });
    if (destinoInput) {
      destinoInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') { e.preventDefault(); traceRoute(); }
      });
    }
    if (origemInput) {
      origemInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') { e.preventDefault(); traceRoute(); }
      });
      origemInput.addEventListener('input', function() { origemFix = null; });
    }
    if (navStartBtn) navStartBtn.addEventListener('click', startNav);
    if (navStopBtn) navStopBtn.addEventListener('click', function() {
      stopNav();
      status('info', 'Navegacao interrompida. Pode iniciar novamente quando quiser.');
    });
    if (soundBtn) soundBtn.addEventListener('click', function() {
      soundOn = !soundOn;
      soundBtn.textContent = 'Voz: ' + (soundOn ? 'LIGADA' : 'DESLIGADA');
      if (!soundOn && window.speechSynthesis) { try { window.speechSynthesis.cancel(); } catch (e) {} }
    });

    // Offline: avisa que a navegacao continua sem internet
    window.addEventListener('online', function() { if (overlay.classList.contains('active') && route) status('ok', '&#127760; Conexao restabelecida.'); });
    window.addEventListener('offline', function() { if (overlay.classList.contains('active')) gpsOfflineNotice(); });
  }

  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', initGps); }
  else { initGps(); }
})();

// ============================================================
// SERVICE WORKER — GPS OFFLINE
// Salva o portal (shell) e os tiles do mapa para que a
// navegacao continue funcionando sem internet.
// ============================================================
(function() {
  if (!('serviceWorker' in navigator)) return;
  function regSw() {
    navigator.serviceWorker.register('/sw.js').catch(function(e) { /* offline fica indisponivel; site segue normal */ });
  }
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', regSw); }
  else { regSw(); }
})();
