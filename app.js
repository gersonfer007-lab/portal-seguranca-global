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
  var base = raw.replace(/\bkm\.?\s*\d+(\s*[-â€“]\s*\d+)?/gi, '').replace(/\s{2,}/g, ' ').replace(/^[\s,]+|[\s,]+$/g, '');
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
    ');out body 80;';
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
        var pedagios = [], radares = [];
        (j.elements || []).forEach(function(el) {
          if (typeof el.lat !== 'number' || typeof el.lon !== 'number') return;
          var tags = el.tags || {};
          var item = {
            lat: el.lat, lng: el.lon,
            name: tags.name || tags.operator || tags.ref || '',
            maxspeed: tags['maxspeed'] || ''
          };
          if (tags.barrier === 'toll_booth') pedagios.push(item);
          else if (tags.highway === 'speed_camera') radares.push(item);
        });
        alerts = { pedagios: pedagios, radares: radares };
      }
    } catch (err) { /* tenta o proximo espelho */ }
  }
  renderRoadAlerts(alerts, lat, lng);
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
  'amapa': 'Bandeira do AmapÃ¡.svg', 'ap': 'Bandeira do AmapÃ¡.svg',
  'amazonas': 'Bandeira do Amazonas.svg', 'am': 'Bandeira do Amazonas.svg',
  'bahia': 'Bandeira da Bahia.svg', 'ba': 'Bandeira da Bahia.svg',
  'ceara': 'Bandeira do CearÃ¡.svg', 'ce': 'Bandeira do CearÃ¡.svg',
  'distrito federal': 'Bandeira do Distrito Federal (Brasil).svg', 'df': 'Bandeira do Distrito Federal (Brasil).svg',
  'espirito santo': 'Bandeira do EspÃ­rito Santo.svg', 'es': 'Bandeira do EspÃ­rito Santo.svg',
  'goias': 'Bandeira de GoiÃ¡s.svg', 'go': 'Bandeira de GoiÃ¡s.svg',
  'maranhao': 'Bandeira do MaranhÃ£o.svg', 'ma': 'Bandeira do MaranhÃ£o.svg',
  'mato grosso': 'Bandeira de Mato Grosso.svg', 'mt': 'Bandeira de Mato Grosso.svg',
  'mato grosso do sul': 'Bandeira de Mato Grosso do Sul.svg', 'ms': 'Bandeira de Mato Grosso do Sul.svg',
  'minas gerais': 'Bandeira de Minas Gerais.svg', 'mg': 'Bandeira de Minas Gerais.svg',
  'para': 'Bandeira do ParÃ¡.svg', 'pa': 'Bandeira do ParÃ¡.svg',
  'paraiba': 'Bandeira da ParaÃ­ba.svg', 'pb': 'Bandeira da ParaÃ­ba.svg',
  'parana': 'Bandeira do ParanÃ¡.svg', 'pr': 'Bandeira do ParanÃ¡.svg',
  'pernambuco': 'Bandeira de Pernambuco.svg', 'pe': 'Bandeira de Pernambuco.svg',
  'piaui': 'Bandeira do PiauÃ­.svg', 'pi': 'Bandeira do PiauÃ­.svg',
  'rio de janeiro': 'Bandeira do estado do Rio de Janeiro.svg', 'rj': 'Bandeira do estado do Rio de Janeiro.svg',
  'rio grande do norte': 'Bandeira do Rio Grande do Norte.svg', 'rn': 'Bandeira do Rio Grande do Norte.svg',
  'rio grande do sul': 'Bandeira do Rio Grande do Sul.svg', 'rs': 'Bandeira do Rio Grande do Sul.svg',
  'rondonia': 'Bandeira de RondÃ´nia.svg', 'ro': 'Bandeira de RondÃ´nia.svg',
  'roraima': 'Bandeira de Roraima.svg', 'rr': 'Bandeira de Roraima.svg',
  'santa catarina': 'Bandeira de Santa Catarina.svg', 'sc': 'Bandeira de Santa Catarina.svg',
  'sao paulo': 'Bandeira do estado de SÃ£o Paulo.svg', 'sp': 'Bandeira do estado de SÃ£o Paulo.svg',
  'sergipe': 'Bandeira de Sergipe.svg', 'se': 'Bandeira de Sergipe.svg',
  'tocantins': 'Bandeira do Tocantins.svg', 'to': 'Bandeira do Tocantins.svg'
};
var PSG_BR_STATE_NAMES = {
  ac:'Acre',al:'Alagoas',ap:'AmapÃ¡',am:'Amazonas',ba:'Bahia',ce:'CearÃ¡',df:'Distrito Federal',
  es:'EspÃ­rito Santo',go:'GoiÃ¡s',ma:'MaranhÃ£o',mt:'Mato Grosso',ms:'Mato Grosso do Sul',mg:'Minas Gerais',
  pa:'ParÃ¡',pb:'ParaÃ­ba',pr:'ParanÃ¡',pe:'Pernambuco',pi:'PiauÃ­',rj:'Rio de Janeiro',rn:'Rio Grande do Norte',
  rs:'Rio Grande do Sul',ro:'RondÃ´nia',rr:'Roraima',sc:'Santa Catarina',sp:'SÃ£o Paulo',se:'Sergipe',to:'Tocantins'
};
function _psgNorm(s) {
  return (s || '').toLowerCase().normalize('NFD').replace(/[Ì€-Í¯]/g, '').trim();
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
    return [bairro, cidade].filter(function(v, i, arr) { return v && arr.indexOf(v) === i; }).join(' â€” ');
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
  citySeal.textContent = (city || '?').replace(/[^A-Za-zÃ€-Ã¿ ]/g, '').split(' ').filter(Boolean).map(function(w) { return w[0]; }).slice(0, 2).join('').toUpperCase();
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
  var mesesExtenso = ['janeiro','fevereiro','marÃ§o','abril','maio','junho','julho','agosto','setembro','outubro','novembro','dezembro'];
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
    safe: 'SEGURO', mod: 'MODERADO', crit: 'CRITICO', subject: 'Analise de Seguranca â€” Portal Seguranca Global' },
  en: { title: 'Share Result', sub: 'Send this safety analysis to those who need to know',
    score: 'Safety Score', at: 'at', cta: 'Check the safety of any address in the world:',
    copy: 'Copy link', copyMsg: 'Copy message', copied: 'Copied successfully!',
    native: 'More options', email: 'Email', cancel: 'Close', preview: 'Message preview',
    safe: 'SAFE', mod: 'MODERATE', crit: 'CRITICAL', subject: 'Safety Analysis â€” Global Security Portal' },
  es: { title: 'Compartir Resultado', sub: 'Envie este analisis de seguridad a quien necesite saberlo',
    score: 'Safety Score', at: 'en', cta: 'Consulte la seguridad de cualquier direccion del mundo:',
    copy: 'Copiar enlace', copyMsg: 'Copiar mensaje', copied: 'Copiado con exito!',
    native: 'Mas opciones', email: 'Correo', cancel: 'Cerrar', preview: 'Vista previa del mensaje',
    safe: 'SEGURO', mod: 'MODERADO', crit: 'CRITICO', subject: 'Analisis de Seguridad â€” Portal Seguridad Global' }
};

function openShare() {
  if (!currentData) return alert('Pesquise um local antes de compartilhar.');
  var lang = window.PSG_LANG || 'pt';
  var ui = shareI18n[lang] || shareI18n.pt;
  var scoreText = (currentData.safetyScore >= 70 ? ui.safe : currentData.safetyScore >= 40 ? ui.mod : ui.crit);
  var msg = "*" + ui.subject + "*\n\n"
    + "ðŸ“ " + currentData.address.fullAddress + "\n"
    + "ðŸ›¡ï¸ " + ui.score + ": *" + currentData.safetyScore + "/100* (" + scoreText + ")\n\n"
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
        { h: '1. Digite um local', p: 'Use CEP, endereco completo ou coordenadas GPS no campo de busca.' },
        { h: '2. Escolha no mapa (opcional)', p: 'Clique no botao do mapa para selecionar um ponto com o toque.' },
        { h: '3. Veja o Safety Score', p: 'O sistema calcula uma nota de seguranca baseada em dados abertos e estatisticas.' },
        { h: '4. Compartilhe ou baixe o PDF', p: 'Envie o relatorio por WhatsApp, email ou faca o download gratuito.' },
        { h: '5. Importante', p: 'Nao consultamos CPF, CNPJ, RG ou dados pessoais. Use apenas enderecos.' },
        { h: '6. Caminhada Segura', p: 'Na pagina Caminhada Segura, toque em iniciar, envie o link por WhatsApp e o responsavel acompanha sua rota em tempo real, com botao de emergencia.' },
        { h: '7. Central de Noticias', p: 'A pagina Noticias traz artigos e manchetes atualizadas automaticamente sobre seguranca: camaras, protecao pessoal, pets, bikes, motos e carros.' }
      ]
    },
    en: {
      title: 'User Manual',
      steps: [
        { h: '1. Enter a location', p: 'Use ZIP code, full address or GPS coordinates in the search field.' },
        { h: '2. Pick on the map (optional)', p: 'Click the map button to select a point by touch.' },
        { h: '3. See the Safety Score', p: 'The system calculates a safety score based on open data and statistics.' },
        { h: '4. Share or download PDF', p: 'Send the report via WhatsApp, email or download it for free.' },
        { h: '5. Important', p: 'We do not query SSN, tax ID, ID cards or personal data. Use addresses only.' },
        { h: '6. Safe Walk', p: 'On the Safe Walk page, tap start, send the link via WhatsApp and a guardian follows your route in real time, with an emergency button.' },
        { h: '7. News Center', p: 'The News page brings articles and automatically updated headlines about security: cameras, personal protection, pets, bikes, motorcycles and cars.' }
      ]
    },
    es: {
      title: 'Manual de Uso',
      steps: [
        { h: '1. Escriba un lugar', p: 'Use codigo postal, direccion completa o coordenadas GPS en el campo de busqueda.' },
        { h: '2. Elija en el mapa (opcional)', p: 'Toque el boton del mapa para seleccionar un punto.' },
        { h: '3. Vea la Puntuacion de Seguridad', p: 'El sistema calcula una puntuacion basada en datos abiertos y estadisticas.' },
        { h: '4. Comparta o descargue el PDF', p: 'Envie el informe por WhatsApp, email o descarguelo gratis.' },
        { h: '5. Importante', p: 'No consultamos DNI, NIF, CIF ni datos personales. Use solo direcciones.' },
        { h: '6. Caminata Segura', p: 'En la pagina Caminata Segura, toque iniciar, envie el enlace por WhatsApp y un responsable sigue su ruta en tiempo real, con boton de emergencia.' },
        { h: '7. Central de Noticias', p: 'La pagina Noticias trae articulos y titulares actualizados automaticamente: camaras, proteccion personal, mascotas, bicis, motos y coches.' }
      ]
    },
    fr: {
      title: 'Manuel d\'Utilisation',
      steps: [
        { h: '1. Saisissez un lieu', p: 'Utilisez le code postal, l\'adresse complete ou les coordonnees GPS.' },
        { h: '2. Choisir sur la carte (facultatif)', p: 'Touchez le bouton de la carte pour selectionner un point.' },
        { h: '3. Consultez le Safety Score', p: 'Le systeme calcule un score de securite base sur des donnees ouvertes.' },
        { h: '4. Partagez ou telechargez le PDF', p: 'Envoyez le rapport par WhatsApp, email ou telechargez-le gratuitement.' },
        { h: '5. Important', p: 'Nous ne consultons pas les numeros de securite sociale, SIRET ou donnees personnelles.' },
        { h: '6. Marche sure', p: 'Sur la page Marche sure, touchez demarrer, envoyez le lien par WhatsApp et un proche suit votre trajet en temps reel, avec bouton d\'urgence.' },
        { h: '7. Centre de nouvelles', p: 'La page Nouvelles propose des articles et des titres mis a jour automatiquement : cameras, protection personnelle, animaux, velos, motos et voitures.' }
      ]
    },
    de: {
      title: 'Bedienungsanleitung',
      steps: [
        { h: '1. Ort eingeben', p: 'Verwenden Sie Postleitzahl, vollstandige Adresse oder GPS-Koordinaten.' },
        { h: '2. Auf Karte wahlen (optional)', p: 'Tippen Sie auf die Karte, um einen Punkt auszuwahlen.' },
        { h: '3. Safety Score anzeigen', p: 'Das System berechnet einen Sicherheitswert basierend auf offenen Daten.' },
        { h: '4. Teilen oder PDF herunterladen', p: 'Senden Sie den Bericht uber WhatsApp, E-Mail oder laden Sie ihn kostenlos herunter.' },
        { h: '5. Wichtig', p: 'Wir fragen keine Sozialversicherungsnummern, Steuernummern oder personenbezogene Daten ab.' },
        { h: '6. Sicherer Spaziergang', p: 'Auf der Seite Sicherer Spaziergang starten Sie die Freigabe, senden den Link per WhatsApp, und eine Vertrauensperson verfolgt Ihre Route in Echtzeit â€“ mit Notfallknopf.' },
        { h: '7. News-Center', p: 'Die News-Seite bietet Artikel und automatisch aktualisierte Schlagzeilen: Kameras, Personenschutz, Haustiere, FahrrÃ¤der, MotorrÃ¤der und Autos.' }
      ]
    },
    it: {
      title: 'Manuale d\'Uso',
      steps: [
        { h: '1. Inserisci un luogo', p: 'Usa CAP, indirizzo completo o coordinate GPS nel campo di ricerca.' },
        { h: '2. Scegli sulla mappa (opzionale)', p: 'Tocca il pulsante mappa per selezionare un punto.' },
        { h: '3. Vedi il Safety Score', p: 'Il sistema calcola un punteggio di sicurezza basato su dati aperti.' },
        { h: '4. Condividi o scarica il PDF', p: 'Invia il rapporto via WhatsApp, email o scaricalo gratuitamente.' },
        { h: '5. Importante', p: 'Non consultiamo codici fiscali, partite IVA o dati personali. Usa solo indirizzi.' },
        { h: '6. Camminata Sicura', p: 'Nella pagina Camminata Sicura, tocca avvia, invia il link via WhatsApp e un familiare segue il tuo percorso in tempo reale, con pulsante di emergenza.' },
        { h: '7. Centro Notizie', p: 'La pagina Notizie offre articoli e titoli aggiornati automaticamente: telecamere, protezione personale, animali, bici, moto e auto.' }
      ]
    },
    zh: {
      title: 'ä½¿ç”¨æ‰‹å†Œ',
      steps: [
        { h: '1. è¾“å…¥åœ°ç‚¹', p: 'åœ¨æœç´¢æ¡†ä¸­è¾“å…¥é‚®æ”¿ç¼–ç ã€å®Œæ•´åœ°å€æˆ–GPSåæ ‡ã€‚' },
        { h: '2. åœ¨åœ°å›¾ä¸Šé€‰æ‹©ï¼ˆå¯é€‰ï¼‰', p: 'ç‚¹å‡»åœ°å›¾æŒ‰é’®é€‰æ‹©åœ°ç‚¹ã€‚' },
        { h: '3. æŸ¥çœ‹å®‰å…¨è¯„åˆ†', p: 'ç³»ç»Ÿæ ¹æ®å…¬å¼€æ•°æ®å’Œç»Ÿè®¡æ•°æ®è®¡ç®—å®‰å…¨è¯„åˆ†ã€‚' },
        { h: '4. åˆ†äº«æˆ–ä¸‹è½½PDF', p: 'é€šè¿‡WhatsAppã€é‚®ä»¶å‘é€æŠ¥å‘Šæˆ–å…è´¹ä¸‹è½½ã€‚' },
        { h: '5. é‡è¦æç¤º', p: 'æˆ‘ä»¬ä¸æŸ¥è¯¢èº«ä»½è¯ã€ç¨Žå·æˆ–ä¸ªäººæ•°æ®ã€‚è¯·ä»…ä½¿ç”¨åœ°å€ã€‚' },
        { h: '6. å®‰å…¨æ­¥è¡Œ', p: 'åœ¨â€œå®‰å…¨æ­¥è¡Œâ€é¡µé¢ç‚¹å‡»å¼€å§‹ï¼Œé€šè¿‡WhatsAppå‘é€é“¾æŽ¥ï¼Œå®¶äººå³å¯å®žæ—¶æŸ¥çœ‹æ‚¨çš„è·¯çº¿ï¼Œå¹¶é…æœ‰ç´§æ€¥æ±‚æ•‘æŒ‰é’®ã€‚' },
        { h: '7. æ–°é—»ä¸­å¿ƒ', p: 'æ–°é—»é¡µé¢æä¾›æ–‡ç« å’Œè‡ªåŠ¨æ›´æ–°çš„å®‰å…¨èµ„è®¯ï¼šæ‘„åƒå¤´ã€äººèº«ä¿æŠ¤ã€å® ç‰©ã€è‡ªè¡Œè½¦ã€æ‘©æ‰˜è½¦å’Œæ±½è½¦ã€‚' }
      ]
    },
    ja: {
      title: 'å–æ‰±èª¬æ˜Žæ›¸',
      steps: [
        { h: '1. å ´æ‰€ã‚’å…¥åŠ›', p: 'éƒµä¾¿ç•ªå·ã€ä½æ‰€ã€ã¾ãŸã¯GPSåº§æ¨™ã‚’æ¤œç´¢æ¬„ã«å…¥åŠ›ã—ã¦ãã ã•ã„ã€‚' },
        { h: '2. åœ°å›³ã§é¸æŠžï¼ˆä»»æ„ï¼‰', p: 'åœ°å›³ãƒœã‚¿ãƒ³ã‚’ã‚¿ãƒƒãƒ—ã—ã¦ãƒã‚¤ãƒ³ãƒˆã‚’é¸æŠžã—ã¾ã™ã€‚' },
        { h: '3. ã‚»ãƒ¼ãƒ•ãƒ†ã‚£ã‚¹ã‚³ã‚¢ã‚’è¦‹ã‚‹', p: 'ã‚·ã‚¹ãƒ†ãƒ ã¯å…¬é–‹ãƒ‡ãƒ¼ã‚¿ã¨çµ±è¨ˆã«åŸºã¥ã„ã¦å®‰å…¨ã‚¹ã‚³ã‚¢ã‚’è¨ˆç®—ã—ã¾ã™ã€‚' },
        { h: '4. å…±æœ‰ã¾ãŸã¯PDFãƒ€ã‚¦ãƒ³ãƒ­ãƒ¼ãƒ‰', p: 'WhatsAppã€ãƒ¡ãƒ¼ãƒ«ã§é€ä¿¡ã™ã‚‹ã‹ã€ç„¡æ–™ã§ãƒ€ã‚¦ãƒ³ãƒ­ãƒ¼ãƒ‰ã—ã¦ãã ã•ã„ã€‚' },
        { h: '5. é‡è¦', p: 'å€‹äººç•ªå·ã€æ³•äººç•ªå·ã€å€‹äººãƒ‡ãƒ¼ã‚¿ã¯ç…§ä¼šã—ã¾ã›ã‚“ã€‚ä½æ‰€ã®ã¿ã‚’ã”åˆ©ç”¨ãã ã•ã„ã€‚' },
        { h: '6. å®‰å…¨ã‚¦ã‚©ãƒ¼ã‚­ãƒ³ã‚°', p: 'ã€Œå®‰å…¨ã‚¦ã‚©ãƒ¼ã‚­ãƒ³ã‚°ã€ãƒšãƒ¼ã‚¸ã§é–‹å§‹ã‚’ã‚¿ãƒƒãƒ—ã—ã€WhatsAppã§ãƒªãƒ³ã‚¯ã‚’é€ã‚‹ã¨ã€ä¿è­·è€…ãŒãƒªã‚¢ãƒ«ã‚¿ã‚¤ãƒ ã§ãƒ«ãƒ¼ãƒˆã‚’ç¢ºèªã§ãã¾ã™ã€‚ç·Šæ€¥ãƒœã‚¿ãƒ³ä»˜ãã€‚' },
        { h: '7. ãƒ‹ãƒ¥ãƒ¼ã‚¹ã‚»ãƒ³ã‚¿ãƒ¼', p: 'ãƒ‹ãƒ¥ãƒ¼ã‚¹ãƒšãƒ¼ã‚¸ã§ã¯ã€ã‚«ãƒ¡ãƒ©ãƒ»èº«è¾ºå®‰å…¨ãƒ»ãƒšãƒƒãƒˆãƒ»è‡ªè»¢è»Šãƒ»ãƒã‚¤ã‚¯ãƒ»è‡ªå‹•è»Šã«é–¢ã™ã‚‹è¨˜äº‹ã¨è‡ªå‹•æ›´æ–°ã®è¦‹å‡ºã—ã‚’æä¾›ã—ã¾ã™ã€‚' }
      ]
    },
    ar: {
      title: 'Ø¯Ù„ÙŠÙ„ Ø§Ù„Ø§Ø³ØªØ®Ø¯Ø§Ù…',
      steps: [
        { h: '1. Ø£Ø¯Ø®Ù„ Ù…ÙˆÙ‚Ø¹Ù‹Ø§', p: 'Ø§Ø³ØªØ®Ø¯Ù… Ø§Ù„Ø±Ù…Ø² Ø§Ù„Ø¨Ø±ÙŠØ¯ÙŠ Ø£Ùˆ Ø§Ù„Ø¹Ù†ÙˆØ§Ù† Ø§Ù„ÙƒØ§Ù…Ù„ Ø£Ùˆ Ø¥Ø­Ø¯Ø§Ø«ÙŠØ§Øª GPS ÙÙŠ Ø­Ù‚Ù„ Ø§Ù„Ø¨Ø­Ø«.' },
        { h: '2. Ø§Ø®ØªØ± Ø¹Ù„Ù‰ Ø§Ù„Ø®Ø±ÙŠØ·Ø© (Ø§Ø®ØªÙŠØ§Ø±ÙŠ)', p: 'Ø§Ø¶ØºØ· Ø¹Ù„Ù‰ Ø²Ø± Ø§Ù„Ø®Ø±ÙŠØ·Ø© Ù„ØªØ­Ø¯ÙŠØ¯ Ù†Ù‚Ø·Ø©.' },
        { h: '3. Ø´Ø§Ù‡Ø¯ Ø¯Ø±Ø¬Ø© Ø§Ù„Ø£Ù…Ø§Ù†', p: 'ÙŠØ­Ø³Ø¨ Ø§Ù„Ù†Ø¸Ø§Ù… Ø¯Ø±Ø¬Ø© Ø£Ù…Ø§Ù† Ø¨Ù†Ø§Ø¡Ù‹ Ø¹Ù„Ù‰ Ø§Ù„Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„Ù…ÙØªÙˆØ­Ø© ÙˆØ§Ù„Ø¥Ø­ØµØ§Ø¦ÙŠØ§Øª.' },
        { h: '4. Ø´Ø§Ø±Ùƒ Ø£Ùˆ Ø­Ù…Ù‘Ù„ PDF', p: 'Ø£Ø±Ø³Ù„ Ø§Ù„ØªÙ‚Ø±ÙŠØ± Ø¹Ø¨Ø± ÙˆØ§ØªØ³Ø§Ø¨ Ø£Ùˆ Ø§Ù„Ø¨Ø±ÙŠØ¯ Ø§Ù„Ø¥Ù„ÙƒØªØ±ÙˆÙ†ÙŠ Ø£Ùˆ Ø­Ù…Ù‘Ù„Ù‡ Ù…Ø¬Ø§Ù†Ù‹Ø§.' },
        { h: '5. Ù…Ù‡Ù…', p: 'Ù„Ø§ Ù†Ø³ØªØ¹Ù„Ù… Ø¹Ù† Ø£Ø±Ù‚Ø§Ù… Ø§Ù„Ù‡ÙˆÙŠØ© Ø£Ùˆ Ø§Ù„Ø¶Ø±ÙŠØ¨Ø© Ø£Ùˆ Ø§Ù„Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„Ø´Ø®ØµÙŠØ©. Ø§Ø³ØªØ®Ø¯Ù… Ø§Ù„Ø¹Ù†Ø§ÙˆÙŠÙ† ÙÙ‚Ø·.' },
        { h: '6. Ø§Ù„Ù…Ø´ÙŠ Ø§Ù„Ø¢Ù…Ù†', p: 'ÙÙŠ ØµÙØ­Ø© Ø§Ù„Ù…Ø´ÙŠ Ø§Ù„Ø¢Ù…Ù†ØŒ Ø§Ø¶ØºØ· Ø§Ø¨Ø¯Ø£ ÙˆØ£Ø±Ø³Ù„ Ø§Ù„Ø±Ø§Ø¨Ø· Ø¹Ø¨Ø± ÙˆØ§ØªØ³Ø§Ø¨ØŒ ÙˆØ³ÙŠØªØ§Ø¨Ø¹ Ø£Ø­Ø¯ Ø§Ù„Ù…Ø³Ø¤ÙˆÙ„ÙŠÙ† Ù…Ø³Ø§Ø±Ùƒ ÙÙŠ Ø§Ù„ÙˆÙ‚Øª Ø§Ù„ÙØ¹Ù„ÙŠØŒ Ù…Ø¹ Ø²Ø± Ø·ÙˆØ§Ø±Ø¦.' },
        { h: '7. Ù…Ø±ÙƒØ² Ø§Ù„Ø£Ø®Ø¨Ø§Ø±', p: 'ØªÙˆÙØ± ØµÙØ­Ø© Ø§Ù„Ø£Ø®Ø¨Ø§Ø± Ù…Ù‚Ø§Ù„Ø§Øª ÙˆØ¹Ù†Ø§ÙˆÙŠÙ† ØªÙØ­Ø¯ÙŽÙ‘Ø« ØªÙ„Ù‚Ø§Ø¦ÙŠÙ‹Ø§: ÙƒØ§Ù…ÙŠØ±Ø§ØªØŒ Ø­Ù…Ø§ÙŠØ© Ø´Ø®ØµÙŠØ©ØŒ Ø­ÙŠÙˆØ§Ù†Ø§Øª Ø£Ù„ÙŠÙØ©ØŒ Ø¯Ø±Ø§Ø¬Ø§ØªØŒ Ø¯Ø±Ø§Ø¬Ø§Øª Ù†Ø§Ø±ÙŠØ© ÙˆØ³ÙŠØ§Ø±Ø§Øª.' }
      ]
    },
    ru: {
      title: 'Ð ÑƒÐºÐ¾Ð²Ð¾Ð´ÑÑ‚Ð²Ð¾ Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»Ñ',
      steps: [
        { h: '1. Ð’Ð²ÐµÐ´Ð¸Ñ‚Ðµ Ð¼ÐµÑÑ‚Ð¾', p: 'Ð˜ÑÐ¿Ð¾Ð»ÑŒÐ·ÑƒÐ¹Ñ‚Ðµ Ð¿Ð¾Ñ‡Ñ‚Ð¾Ð²Ñ‹Ð¹ Ð¸Ð½Ð´ÐµÐºÑ, Ð¿Ð¾Ð»Ð½Ñ‹Ð¹ Ð°Ð´Ñ€ÐµÑ Ð¸Ð»Ð¸ GPS-ÐºÐ¾Ð¾Ñ€Ð´Ð¸Ð½Ð°Ñ‚Ñ‹ Ð² Ð¿Ð¾Ð»Ðµ Ð¿Ð¾Ð¸ÑÐºÐ°.' },
        { h: '2. Ð’Ñ‹Ð±ÐµÑ€Ð¸Ñ‚Ðµ Ð½Ð° ÐºÐ°Ñ€Ñ‚Ðµ (Ð½ÐµÐ¾Ð±ÑÐ·Ð°Ñ‚ÐµÐ»ÑŒÐ½Ð¾)', p: 'ÐÐ°Ð¶Ð¼Ð¸Ñ‚Ðµ ÐºÐ½Ð¾Ð¿ÐºÑƒ ÐºÐ°Ñ€Ñ‚Ñ‹, Ñ‡Ñ‚Ð¾Ð±Ñ‹ Ð²Ñ‹Ð±Ñ€Ð°Ñ‚ÑŒ Ñ‚Ð¾Ñ‡ÐºÑƒ.' },
        { h: '3. ÐŸÐ¾ÑÐ¼Ð¾Ñ‚Ñ€Ð¸Ñ‚Ðµ Safety Score', p: 'Ð¡Ð¸ÑÑ‚ÐµÐ¼Ð° Ñ€Ð°ÑÑÑ‡Ð¸Ñ‚Ñ‹Ð²Ð°ÐµÑ‚ Ð¾Ñ†ÐµÐ½ÐºÑƒ Ð±ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ð¾ÑÑ‚Ð¸ Ð½Ð° Ð¾ÑÐ½Ð¾Ð²Ðµ Ð¾Ñ‚ÐºÑ€Ñ‹Ñ‚Ñ‹Ñ… Ð´Ð°Ð½Ð½Ñ‹Ñ….' },
        { h: '4. ÐŸÐ¾Ð´ÐµÐ»Ð¸Ñ‚ÐµÑÑŒ Ð¸Ð»Ð¸ ÑÐºÐ°Ñ‡Ð°Ð¹Ñ‚Ðµ PDF', p: 'ÐžÑ‚Ð¿Ñ€Ð°Ð²ÑŒÑ‚Ðµ Ð¾Ñ‚Ñ‡ÐµÑ‚ Ñ‡ÐµÑ€ÐµÐ· WhatsApp, email Ð¸Ð»Ð¸ ÑÐºÐ°Ñ‡Ð°Ð¹Ñ‚Ðµ Ð±ÐµÑÐ¿Ð»Ð°Ñ‚Ð½Ð¾.' },
        { h: '5. Ð’Ð°Ð¶Ð½Ð¾', p: 'ÐœÑ‹ Ð½Ðµ Ð·Ð°Ð¿Ñ€Ð°ÑˆÐ¸Ð²Ð°ÐµÐ¼ Ð˜ÐÐ, ÐžÐ“Ð Ð Ð¸Ð»Ð¸ Ð¿ÐµÑ€ÑÐ¾Ð½Ð°Ð»ÑŒÐ½Ñ‹Ðµ Ð´Ð°Ð½Ð½Ñ‹Ðµ. Ð˜ÑÐ¿Ð¾Ð»ÑŒÐ·ÑƒÐ¹Ñ‚Ðµ Ñ‚Ð¾Ð»ÑŒÐºÐ¾ Ð°Ð´Ñ€ÐµÑÐ°.' },
        { h: '6. Ð‘ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ð°Ñ Ð¿Ñ€Ð¾Ð³ÑƒÐ»ÐºÐ°', p: 'ÐÐ° ÑÑ‚Ñ€Ð°Ð½Ð¸Ñ†Ðµ Â«Ð‘ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ð°Ñ Ð¿Ñ€Ð¾Ð³ÑƒÐ»ÐºÐ°Â» Ð½Ð°Ð¶Ð¼Ð¸Ñ‚Ðµ ÑÑ‚Ð°Ñ€Ñ‚ Ð¸ Ð¾Ñ‚Ð¿Ñ€Ð°Ð²ÑŒÑ‚Ðµ ÑÑÑ‹Ð»ÐºÑƒ Ñ‡ÐµÑ€ÐµÐ· WhatsApp â€” Ð±Ð»Ð¸Ð·ÐºÐ¸Ð¹ Ñ‡ÐµÐ»Ð¾Ð²ÐµÐº ÑƒÐ²Ð¸Ð´Ð¸Ñ‚ Ð²Ð°Ñˆ Ð¼Ð°Ñ€ÑˆÑ€ÑƒÑ‚ Ð² Ñ€ÐµÐ°Ð»ÑŒÐ½Ð¾Ð¼ Ð²Ñ€ÐµÐ¼ÐµÐ½Ð¸, ÐµÑÑ‚ÑŒ ÐºÐ½Ð¾Ð¿ÐºÐ° SOS.' },
        { h: '7. Ð¦ÐµÐ½Ñ‚Ñ€ Ð½Ð¾Ð²Ð¾ÑÑ‚ÐµÐ¹', p: 'Ð¡Ñ‚Ñ€Ð°Ð½Ð¸Ñ†Ð° Ð½Ð¾Ð²Ð¾ÑÑ‚ÐµÐ¹ ÑÐ¾Ð´ÐµÑ€Ð¶Ð¸Ñ‚ ÑÑ‚Ð°Ñ‚ÑŒÐ¸ Ð¸ Ð°Ð²Ñ‚Ð¾Ð¼Ð°Ñ‚Ð¸Ñ‡ÐµÑÐºÐ¸ Ð¾Ð±Ð½Ð¾Ð²Ð»ÑÐµÐ¼Ñ‹Ðµ Ð·Ð°Ð³Ð¾Ð»Ð¾Ð²ÐºÐ¸: ÐºÐ°Ð¼ÐµÑ€Ñ‹, Ð»Ð¸Ñ‡Ð½Ð°Ñ Ð·Ð°Ñ‰Ð¸Ñ‚Ð°, Ð¿Ð¸Ñ‚Ð¾Ð¼Ñ†Ñ‹, Ð²ÐµÐ»Ð¾ÑÐ¸Ð¿ÐµÐ´Ñ‹, Ð¼Ð¾Ñ‚Ð¾Ñ†Ð¸ÐºÐ»Ñ‹ Ð¸ Ð°Ð²Ñ‚Ð¾Ð¼Ð¾Ð±Ð¸Ð»Ð¸.' }
      ]
    },
    ko: {
      title: 'ì‚¬ìš© ì„¤ëª…ì„œ',
      steps: [
        { h: '1. ìž¥ì†Œ ìž…ë ¥', p: 'ìš°íŽ¸ë²ˆí˜¸, ì „ì²´ ì£¼ì†Œ ë˜ëŠ” GPS ì¢Œí‘œë¥¼ ê²€ìƒ‰ì°½ì— ìž…ë ¥í•˜ì„¸ìš”.' },
        { h: '2. ì§€ë„ì—ì„œ ì„ íƒ(ì„ íƒì‚¬í•­)', p: 'ì§€ë„ ë²„íŠ¼ì„ ëˆŒëŸ¬ ì§€ì ì„ ì„ íƒí•˜ì„¸ìš”.' },
        { h: '3. ì•ˆì „ ì ìˆ˜ ë³´ê¸°', p: 'ì‹œìŠ¤í…œì€ ê³µê°œ ë°ì´í„°ì™€ í†µê³„ë¥¼ ê¸°ë°˜ìœ¼ë¡œ ì•ˆì „ ì ìˆ˜ë¥¼ ê³„ì‚°í•©ë‹ˆë‹¤.' },
        { h: '4. ê³µìœ  ë˜ëŠ” PDF ë‹¤ìš´ë¡œë“œ', p: 'WhatsApp, ì´ë©”ì¼ë¡œ ë³´ê³ ì„œë¥¼ ë³¸ê±°ë‚˜ ë¬£ìœ¼ë¡œ ë‹¤ìš´ë¡œë“œí•˜ì„¸ìš”.' },
        { h: '5. ì¤‘ìš”', p: 'ì£¼ë¯¼ë“±ë¡ë²ˆí˜¸, ì‚¬ì—…ìžë²ˆí˜¸ ë˜ëŠ” ê°œì¸ ë°ì´í„°ëŠ” ì¡°íšŒí•˜ì§€ ì•ŠìŠµë‹ˆë‹¤. ì£¼ì†Œë§Œ ì‚¬ìš©í•˜ì„¸ìš”.' },
        { h: '6. ì•ˆì „ ì‚°ì±…', p: 'ì•ˆì „ ì‚°ì±… íŽ˜ì´ì§€ì—ì„œ ì‹œìž‘ì„ ëˆ„ubc88 íƒ€ë¥³ WhatsAppìœ¼ë¡œ ë§í¬ë¥¼ ë³´ë‚´ë©´ ë³´í˜¸ìžê°€ ì‹¤ì‹œê°„ìœ¼ë¡œ ê²½ë¡œë¥¼ í™•ì¸í•  ìˆ˜ ìžˆìŠµë‹ˆë‹¤. ê¸´ê¸‰ ë²„íŠ¼ë„ ìžˆìŠµë‹ˆë‹¤.' },
        { h: '7. ë‰´ìŠ¤ ì„¼í„°', p: 'ë‰´ìŠ¤ íŽ˜ì´ì§€ì—ì„œëŠ” ì¹´ë©”ë¼, ê°œì¸ ë³´í˜¸, ë°˜ë ¤ë™ë¬¼, ìžì „ê±°, ì˜¤í† ë°”ì´, ìžë™ì°¨ì— ê´€í•œ ê¸°ì‚¬ì™€ ìžë™ ì—…ë°ì´íŠ¸ í—¤ë“œë¼ì¸ì„ ì œê³µí•©ë‹ˆë‹¤.' }
      ]
    },
    hi: {
      title: 'à¤‰à¤ªà¤¯à¥‹à¤—à¤•à¤°à¥à¤¤à¤¾ à¤®à¤¾à¤°à¥à¤—à¤¦à¤°à¥à¤¶à¤¿à¤•à¤¾',
      steps: [
        { h: '1. à¤¸à¥à¤¥à¤¾à¤¨ à¤¦à¤°à¥à¤œ à¤•à¤°à¥‡à¤‚', p: 'à¤–à¥‹à¤œ à¤¬à¥‰à¤•à¥à¤¸ à¤®à¥‡à¤‚ à¤ªà¤¿à¤¨ à¤•à¥‹à¤¡, à¤ªà¥‚à¤°à¤¾ à¤ªà¤¤à¤¾ à¤¯à¤¾ GPS à¤¨à¤¿à¤°à¥à¤¦à¥‡à¤¶à¤¾à¤‚à¤• à¤•à¤¾ à¤‰à¤ªà¤¯à¥‹à¤— à¤•à¤°à¥‡à¤‚à¥¤' },
        { h: '2. à¤¨à¤•à¥à¤¶à¥‡ à¤ªà¤° à¤šà¥à¤¨à¥‡à¤‚ (à¤µà¥ˆà¤•à¤²à¥à¤ªà¤¿à¤•)', p: 'à¤¬à¤¿à¤‚à¤¦à¥ à¤šà¥à¤¨à¤¨à¥‡ à¤•à¥‡ à¤²à¤¿à¤ à¤¨à¤•à¥à¤¶à¤¾ à¤¬à¤Ÿà¤¨ à¤¦à¤¬à¤¾à¤à¤‚à¥¤' },
        { h: '3. à¤¸à¥à¤°à¤•à¥à¤·à¤¾ à¤¸à¥à¤•à¥‹à¤° à¤¦à¥‡à¤–à¥‡à¤‚', p: 'à¤¸à¤¿à¤¸à¥à¤Ÿà¤® à¤–à¥à¤²à¥‡ à¤¡à¥‡à¤Ÿà¤¾ à¤”à¤° à¤†à¤‚à¤•à¤¡à¤¼à¥‹à¤‚ à¤•à¥‡ à¤†à¤§à¤¾à¤° à¤ªà¤° à¤¸à¥à¤°à¤•à¥à¤·à¤¾ à¤¸à¥à¤•à¥‹à¤° à¤•à¥€ à¤—à¤£à¤¨à¤¾ à¤•à¤°à¤¤à¤¾ à¤¹à¥ˆà¥¤' },
        { h: '4. à¤¸à¤¾à¤à¤¾ à¤•à¤°à¥‡à¤‚ à¤¯à¤¾ PDF à¤¡à¤¾à¤‰à¤¨à¤²à¥‹à¤¡ à¤•à¤°à¥‡à¤‚', p: 'WhatsApp, à¤ˆà¤®à¥‡à¤² à¤•à¥‡ à¤®à¤¾à¤§à¥à¤¯à¤® à¤¸à¥‡ à¤°à¤¿à¤ªà¥‹à¤°à¥à¤Ÿ à¤­à¥‡à¤œà¥‡à¤‚ à¤¯à¤¾ à¤®à¥à¤«à¥à¤¤ à¤®à¥‡à¤‚ à¤¡à¤¾à¤‰à¤¨à¤²à¥‹à¤¡ à¤•à¤°à¥‡à¤‚à¥¤' },
        { h: '5. à¤®à¤¹à¤¤à¥à¤µà¤ªà¥‚à¤°à¥à¤£', p: 'à¤¹à¤® à¤†à¤§à¤¾à¤°, à¤ªà¥ˆà¤¨ à¤¯à¤¾ à¤µà¥à¤¯à¤•à¥à¤¤à¤¿à¤—à¤¤ à¤¡à¥‡à¤Ÿà¤¾ à¤•à¥€ à¤œà¤¾à¤‚à¤š à¤¨à¤¹à¥€à¤‚ à¤•à¤°à¤¤à¥‡à¥¤ à¤•à¥‡à¤µà¤² à¤ªà¤¤à¥‡ à¤•à¤¾ à¤‰à¤ªà¤¯à¥‹à¤— à¤•à¤°à¥‡à¤‚à¥¤' },
        { h: '6. à¤¸à¥à¤°à¥à¤·à¤¿à¤¤ à¤¸à¥ˆà¤°', p: 'à¤¸à¥à¤°à¥à¤·à¤¿à¤¤ à¤¸à¥ˆà¤° à¤ªà¥‡à¤œ à¤ªà¤° à¤¶à¥à¤°à¥‚ à¤•à¤°à¥‡à¤‚ à¤¦à¤¬à¤¾à¤à¤‚ à¤”à¤° WhatsApp à¤ªà¤° à¤²à¤¿à¤‚à¤• à¤­à¥‡à¤œà¥‡à¤‚ â€” à¤…à¤­à¤¿à¤­à¤¾à¤µà¤• à¤†à¤ªà¤•à¥‡ à¤°à¤¾à¤¸à¥à¤¤à¥‡ à¤•à¥‹ à¤°à¥€à¤¯à¤²-à¤Ÿà¤¾à¤‡à¤® à¤®à¥‡à¤‚ à¤¦à¥‡à¤– à¤¸à¤•à¤¤à¥‡ à¤¹à¥ˆà¤‚à¥¤ à¤†à¤ªà¤¾à¤¤à¤•à¤¾à¤²à¥€à¤¨ à¤¬à¤Ÿà¤¨ à¤­à¥€ à¤¹à¥ˆà¥¤' },
        { h: '7. à¤¸à¤®à¤¾à¤šà¤¾à¤° à¤•à¥‡à¤‚à¤¦à¥à¤°', p: 'à¤¸à¤®à¤¾à¤šà¤¾à¤° à¤ªà¥‡à¤œ à¤ªà¤° à¤²à¥‡à¤– à¤”à¤° à¤¸à¥à¤µà¤¤à¤ƒ à¤…à¤ªà¤¡à¥‡à¤Ÿ à¤¹à¥‹à¤¨à¥‡ à¤µà¤¾à¤²à¥€ à¤–à¤¬à¤°à¥‡à¤‚ à¤®à¤¿à¤²à¤¤à¥€ à¤¹à¥ˆà¤‚: à¤•à¥ˆà¤®à¤°à¥‡, à¤µà¥à¤¯à¤•à¥à¤¤à¤¿à¤—à¤¤ à¤¸à¥à¤°à¤•à¥à¤·à¤¾, à¤ªà¤¾à¤²à¤¤à¥‚, à¤¸à¤¾à¤‡à¤•à¤¿à¤², à¤®à¥‹à¤Ÿà¤°à¤¸à¤¾à¤‡à¤•à¤¿à¤² à¤”à¤° à¤•à¤¾à¤°à¥‡à¤‚à¥¤' }
      ]
    }
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
          _subject: 'Novo inscrito na newsletter - Portal SeguranÃ§a Global',
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