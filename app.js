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
    if (typeof str !== 'string') return ''
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

  var btnLoadGlobe = document.getElementById('btn-load-globe');
  if (btnLoadGlobe) btnLoadGlobe.addEventListener('click', loadGlobeOnDemand);

  observeMapLazy();
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
  var url = (window.PSG_BACKEND_URL || '') + '/api/health';
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

function initMap() {
  map = L.map('map', { center: [-23.55, -46.63], zoom: 13, zoomControl: false, attributionControl: false, scrollWheelZoom: false });
  L.control.zoom({ position: 'topright' }).addTo(map);
  darkTileLayer = L.tileLayer(TILES.dark, { maxZoom: 19 }).addTo(map);
  heatLayer = L.heatLayer([], { radius: 30, blur: 20, maxZoom: 17, gradient: { 0.2: '#22c55e', 0.5: '#eab308', 0.8: '#f97316', 1: '#ef4444' } });
  markersLayer = L.layerGroup();
}

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

async function handleSearch() {
  const rawQuery = document.getElementById('search-input').value.trim();
  if (!rawQuery) return;
  if (!termsAccepted()) { window._pendingSearch = true; showTermsModal(); return; }
  if (!SH_SECURITY.checkRateLimit('search')) { alert('Limite de buscas atingido. Aguarde um momento e tente novamente.'); return; }
  if (!SH_SECURITY.throttle()) return;
  if (SH_SECURITY.detectInjection(rawQuery)) { alert('Entrada invalida detectada.'); SH_SECURITY.logEvent('SEARCH_BLOCKED', rawQuery.substring(0, 50)); return; }
  const query = SH_SECURITY.sanitizeInput(rawQuery);
  if (!query) return;
  try {
    var valRes = await fetch('/api/search', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: query }) });
    var valData = await valRes.json();
    if (!valRes.ok) { alert(valData.error || 'Erro de validacao no servidor.'); return; }
  } catch(serverErr) {
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
    if (currentMapView === '3d') { loadGlobeOnDemand(); }
    hideLoading();
  } catch (err) { hideLoading(); alert('Erro: ' + err.message); }
}

var mapselMap = null;
var mapselMarker = null;
var mapselChoice = null;
var mapselReverseSeq = 0;

function openMapSearch() {
  if (!termsAccepted()) { window._pendingMapSearch = true; showTermsModal(); return; }
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
  if (typeof L === 'undefined') { alert('O mapa ainda esta carregando. Aguarde um instante e tente de novo.'); return; }
  if (mapselMap) { mapselMap.invalidateSize(); return; }
  mapselMap = L.map('mapsel-map', { center: [12, 0], zoom: 2, zoomControl: true, attributionControl: false, scrollWheelZoom: true, worldCopyJump: true });
  L.tileLayer(TILES.dark, { maxZoom: 19 }).addTo(mapselMap);
  if (currentData && currentData.lat != null && currentData.lng != null) { mapselMap.setView([currentData.lat, currentData.lng], 13); }
  mapselMap.on('click', function(e) { mapselPick(e.latlng.lat, e.latlng.lng); });
  setTimeout(function() { if (mapselMap) mapselMap.invalidateSize(); }, 120);
}

function mapselPick(lat, lng) {
  if (!mapselMap) return;
  mapselChoice = null;
  var icon = L.divIcon({ className: '', html: '<div class="mapsel-pin-pulse"></div>', iconSize: [18, 18], iconAnchor: [9, 9] });
  if (mapselMarker) { mapselMarker.setLatLng([lat, lng]); }
  else { mapselMarker = L.marker([lat, lng], { icon: icon, draggable: true }).addTo(mapselMap); mapselMarker.on('dragend', function(ev) { var p = ev.target.getLatLng(); mapselPick(p.lat, p.lng); }); }
  var hint = document.getElementById('mapsel-hint'); if (hint) hint.classList.add('gone');
  var box = document.getElementById('mapsel-picked'); var addrEl = document.getElementById('mapsel-picked-addr'); var coordEl = document.getElementById('mapsel-picked-coords'); var btn = document.getElementById('mapsel-confirm');
  if (box) box.classList.add('filled');
  if (coordEl) coordEl.textContent = lat.toFixed(5) + ', ' + lng.toFixed(5);
  if (addrEl) addrEl.textContent = 'Identificando endereco...';
  if (btn) btn.disabled = true;
  mapselReverseGeocode(lat, lng);
}

async function mapselReverseGeocode(lat, lng) {
  var seq = ++mapselReverseSeq;
  var addrEl = document.getElementById('mapsel-picked-addr'); var btn = document.getElementById('mapsel-confirm');
  var addressData = null;
  try {
    var url = 'https://nominatim.openstreetmap.org/reverse?format=json&lat=' + encodeURIComponent(lat) + '&lon=' + encodeURIComponent(lng) + '&zoom=18&addressdetails=1';
    var res = await fetch(url, { headers: { 'Accept': 'application/json' } });
    var data = await res.json();
    if (seq !== mapselReverseSeq) return;
    var a = (data && data.address) ? data.address : {};
    addressData = { street: a.road || a.pedestrian || a.footway || '', neighborhood: a.suburb || a.neighbourhood || a.quarter || a.city_district || '', city: a.city || a.town || a.village || a.municipality || a.county || '', state: a.state || a.region || '', country: a.country || '', cep: a.postcode || '', fullAddress: (data && data.display_name) ? data.display_name : '' };
  } catch (e) { if (seq !== mapselReverseSeq) return; }
  if (!addressData || !addressData.fullAddress) { addressData = addressData || { street: '', neighborhood: '', city: '', state: '', country: '', cep: '' }; addressData.fullAddress = 'Local no mapa (' + lat.toFixed(5) + ', ' + lng.toFixed(5) + ')'; }
  mapselChoice = { lat: lat, lng: lng, addressData: addressData };
  if (addrEl) addrEl.textContent = addressData.fullAddress;
  if (btn) btn.disabled = false;
}

async function mapselFind() {
  var inp = document.getElementById('mapsel-find'); if (!inp || !mapselMap) return;
  var q = inp.value.trim(); if (!q) return;
  if (SH_SECURITY.detectInjection(q)) { alert('Entrada invalida detectada.'); return; }
  var btn = document.getElementById('mapsel-find-btn'); if (btn) btn.disabled = true;
  try {
    var geo = await geocodeQuery(SH_SECURITY.sanitizeInput(q));
    if (!geo) { alert('Local nao encontrado. Tente incluir o pais.'); return; }
    mapselMap.setView([geo.lat, geo.lng], 13); mapselPick(geo.lat, geo.lng);
  } catch (e) { alert('Nao foi possivel localizar. Tente novamente.'); }
  finally { if (btn) btn.disabled = false; }
}

function runMapselGps() {
  if (!navigator.geolocation) { alert('Seu navegador nao permite localizacao por GPS.'); return; }
  var btn = document.getElementById('mapsel-gps'); if (btn) btn.disabled = true;
  navigator.geolocation.getCurrentPosition(function(pos) {
    if (btn) btn.disabled = false;
    var lat = pos.coords.latitude, lng = pos.coords.longitude;
    if (mapselMap) { mapselMap.setView([lat, lng], 16); mapselPick(lat, lng); }
  }, function(err) {
    if (btn) btn.disabled = false;
    alert(err.code === 1 ? 'Permissao de localizacao negada. Autorize o acesso no navegador para usar o GPS.' : 'Nao foi possivel obter sua localizacao. Escolha o ponto no mapa.');
  }, { enableHighAccuracy: true, timeout: 12000, maximumAge: 60000 });
}

function searchByGps() {
  if (!termsAccepted()) { window._pendingGpsSearch = true; showTermsModal(); return; }
  if (!navigator.geolocation) { alert('Seu navegador nao permite localizacao por GPS.'); return; }
  showLoading('Obtendo sua localizacao...');
  navigator.geolocation.getCurrentPosition(function(pos) {
    analyzeCoords(pos.coords.latitude, pos.coords.longitude, null);
  }, function(err) {
    hideLoading();
    alert(err.code === 1 ? 'Permissao de localizacao negada. Autorize o acesso no navegador ou use "Pesquisar pelo Mapa".' : 'Nao foi possivel obter sua localizacao. Use "Pesquisar pelo Mapa".');
  }, { enableHighAccuracy: true, timeout: 12000, maximumAge: 60000 });
}

function confirmMapSearch() {
  if (!mapselChoice) return;
  var c = mapselChoice; closeMapSearch();
  setTimeout(function() { analyzeCoords(c.lat, c.lng, c.addressData); }, 280);
}

async function analyzeCoords(lat, lng, addressData) {
  if (!SH_SECURITY.checkRateLimit('search')) { hideLoading(); alert('Limite de buscas atingido.'); return; }
  SH_SECURITY.logEvent('SEARCH_MAP', lat.toFixed(4) + ',' + lng.toFixed(4));
  showLoading('Consultando local...');
  try {
    if (!addressData) {
      updateLoading('Identificando o endereco...');
      try {
        var url = 'https://nominatim.openstreetmap.org/reverse?format=json&lat=' + encodeURIComponent(lat) + '&lon=' + encodeURIComponent(lng) + '&zoom=18&addressdetails=1';
        var res = await fetch(url, { headers: { 'Accept': 'application/json' } });
        var data = await res.json();
        var a = (data && data.address) ? data.address : {};
        addressData = { street: a.road || a.pedestrian || '', neighborhood: a.suburb || a.neighbourhood || a.quarter || '', city: a.city || a.town || a.village || a.municipality || a.county || '', state: a.state || a.region || '', country: a.country || '', cep: a.postcode || '', fullAddress: (data && data.display_name) ? data.display_name : '' };
      } catch (e) { addressData = null; }
      if (!addressData || !addressData.fullAddress) { addressData = { street: '', neighborhood: '', city: '', state: '', country: '', cep: '', fullAddress: 'Local no mapa (' + lat.toFixed(5) + ', ' + lng.toFixed(5) + ')' }; }
    }
    var si = document.getElementById('search-input'); if (si) si.value = addressData.fullAddress;
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

async function geocodeQuery(q) {
  if (!q) return null;
  try {
    const r = await fetch('https://nominatim.openstreetmap.org/search?format=jsonv2&addressdetails=1&limit=1&accept-language=pt,en&q=' + encodeURIComponent(q));
    if (!r.ok) return null;
    const j = await r.json();
    if (!j || !j.length) return null;
    const a = j[0].address || {};
    return { lat: parseFloat(j[0].lat), lng: parseFloat(j[0].lon), displayName: j[0].display_name || q, city: a.city || a.town || a.village || a.municipality || '', state: a.state || '', country: a.country || '' };
  } catch (e) { return null; }
}

async function geocodeAddress(addressData, rawQuery) {
  const A = addressData || {};
  const attempts = [];
  const push = function(parts) { const s = parts.filter(Boolean).join(', ').replace(/\s+/g, ' ').trim(); if (s && attempts.indexOf(s) === -1) attempts.push(s); };
  push([A.street, A.neighborhood, A.city, A.state, A.country]);
  push([A.street, A.city, A.state, A.country]);
  push([A.street, A.city, A.country]);
  push([A.neighborhood, A.city, A.state, A.country]);
  push([A.city, A.state, A.country]);
  push([A.city, A.country]);
  if (rawQuery) {
    const norm = String(rawQuery).replace(/\s*[\/|]\s*/g, ', ').replace(/\s+-\s+/g, ', ').trim();
    push([norm]);
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

function randomRecentDate() { const d = new Date(); d.setDate(d.getDate() - Math.floor(Math.random() * 90)); return d.toLocaleDateString('pt-BR'); }

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
  data.markerPoints.forEach(p => { markersLayer.addLayer(L.circleMarker([p.lat, p.lng], { radius: 5, color: '#ef4444', fillColor: '#ef4444', fillOpacity: .7, weight: 1 }).bindPopup('<b>' + p.type + '</b><br>' + p.date)); });
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

function animatePillar(barId, valId, value) { document.getElementById(barId).style.width = value + '%'; document.getElementById(valId).textContent = value; }

function renderCharts(data) {
  Chart.defaults.color = '#8b95a8'; Chart.defaults.borderColor = '#2a3550';
  if (chartTypes) chartTypes.destroy();
  chartTypes = new Chart(document.getElementById('chart-types'), { type: 'doughnut', data: { labels: Object.keys(data.crimeTypes), datasets: [{ data: Object.values(data.crimeTypes), backgroundColor: ['#ef4444','#f97316','#eab308','#a855f7','#3b82f6','#6b7280'], borderWidth: 0 }] }, options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'right', labels: { padding: 12, font: { size: 11 } } } } } });
  if (chartMonthly) chartMonthly.destroy();
  chartMonthly = new Chart(document.getElementById('chart-monthly'), { type: 'line', data: { labels: data.months, datasets: [{ label: 'Ocorrencias', data: data.monthlyData, borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,.1)', fill: true, tension: .4, pointRadius: 3, pointBackgroundColor: '#3b82f6', borderWidth: 2 }] }, options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,.04)' } }, x: { grid: { display: false } } }, plugins: { legend: { display: false } } } });
}

function showLoading(msg) { var ov = document.getElementById('loading-overlay'); var txt = document.getElementById('loading-text'); if (ov) ov.style.display = 'flex'; if (txt) txt.textContent = msg || 'Analisando...'; }
function updateLoading(msg) { var txt = document.getElementById('loading-text'); if (txt) txt.textContent = msg; }
function hideLoading() { var ov = document.getElementById('loading-overlay'); if (ov) ov.style.display = 'none'; }
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function termsAccepted() { return sessionStorage.getItem('psg_terms_accepted') === '1'; }
function showTermsModal() { var m = document.getElementById('terms-modal'); if (m) m.style.display = 'flex'; }
function hideTermsModal() { var m = document.getElementById('terms-modal'); if (m) m.style.display = 'none'; }
function acceptTerms() {
  sessionStorage.setItem('psg_terms_accepted', '1');
  hideTermsModal();
  if (window._pendingSearch) { window._pendingSearch = false; handleSearch(); }
  else if (window._pendingMapSearch) { window._pendingMapSearch = false; openMapSearch(); }
  else if (window._pendingGpsSearch) { window._pendingGpsSearch = false; searchByGps(); }
}

function toggleHeatmap() {
  if (!map || !heatLayer) return;
  heatVisible = !heatVisible;
  if (heatVisible) { if (!map.hasLayer(heatLayer)) map.addLayer(heatLayer); }
  else { if (map.hasLayer(heatLayer)) map.removeLayer(heatLayer); }
  var btn = document.getElementById('btn-heatmap');
  if (btn) btn.classList.toggle('active', heatVisible);
}

function toggleMarkers() {
  if (!map || !markersLayer) return;
  markersVisible = !markersVisible;
  if (markersVisible) { if (!map.hasLayer(markersLayer)) map.addLayer(markersLayer); }
  else { if (map.hasLayer(markersLayer)) map.removeLayer(markersLayer); }
  var btn = document.getElementById('btn-markers');
  if (btn) btn.classList.toggle('active', markersVisible);
}

function generatePDF() {
  if (!currentData) { alert('Faca uma busca primeiro.'); return; }
  var win = window.open('', '_blank');
  var d = currentData;
  var scoreColor = d.safetyScore >= 70 ? '#22c55e' : d.safetyScore >= 40 ? '#eab308' : '#ef4444';
  var scoreLabel = d.safetyScore >= 70 ? 'SEGURO' : d.safetyScore >= 40 ? 'MODERADO' : 'CRITICO';
  win.document.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Relatorio PSG</title><style>body{font-family:Arial,sans-serif;padding:32px;background:#fff;color:#222;}h1{color:#1a2540;}table{border-collapse:collapse;width:100%;}td,th{border:1px solid #ddd;padding:8px;}th{background:#f5f5f5;}.score{font-size:64px;font-weight:bold;color:' + scoreColor + ';}.label{font-size:24px;color:' + scoreColor + ';font-weight:bold;}</style></head><body>');
  win.document.write('<h1>Portal de Seguranca Global</h1><p><b>Local:</b> ' + d.address.fullAddress + '</p><p><b>Coordenadas:</b> ' + d.lat.toFixed(4) + ', ' + d.lng.toFixed(4) + '</p><p><b>Data:</b> ' + new Date().toLocaleString('pt-BR') + '</p><hr>');
  win.document.write('<div class="score">' + d.safetyScore + '</div><div class="label">' + scoreLabel + '</div><p>Score calculado com base em dados de endereco, infraestrutura e movimentacao urbana.</p><hr>');
  win.document.write('<h2>Pilares</h2><table><tr><th>Pilar</th><th>Score</th></tr><tr><td>Criminalidade</td><td>' + d.crimeScore + '</td></tr><tr><td>Infraestrutura</td><td>' + d.infraScore + '</td></tr><tr><td>Movimentacao</td><td>' + d.movementScore + '</td></tr></table><br>');
  win.document.write('<h2>Infraestrutura</h2><table><tr><th>Item</th><th>Valor</th></tr><tr><td>Ocorrencias (90d)</td><td>' + d.totalOccurrences + '</td></tr><tr><td>Cameras</td><td>' + d.cameras + '</td></tr><tr><td>Iluminacao</td><td>' + d.lightCoverage + '%</td></tr><tr><td>Comercios</td><td>' + d.commerce + '</td></tr><tr><td>Delegacias</td><td>' + d.policeStations + '</td></tr><tr><td>Hospitais</td><td>' + d.hospitals + '</td></tr></table>');
  win.document.write('<br><p style="color:#888;font-size:12px;">Dados simulados para fins ilustrativos. Portal de Seguranca Global v2.0 &mdash; Uso exclusivo para enderecos.</p></body></html>');
  win.document.close();
  setTimeout(function() { win.print(); }, 800);
}

function openShare() {
  var m = document.getElementById('share-modal');
  if (!m) return;
  if (currentData) {
    var url = window.location.origin + '/?q=' + encodeURIComponent(currentData.address.fullAddress);
    var linkEl = document.getElementById('share-link'); if (linkEl) linkEl.value = url;
    var msgEl = document.getElementById('share-msg');
    if (msgEl) msgEl.value = 'Confira a analise de seguranca deste local: ' + currentData.address.fullAddress + ' - Safety Score: ' + currentData.safetyScore + '/100. Acesse: ' + url;
  }
  m.style.display = 'flex';
}
function closeShare() { var m = document.getElementById('share-modal'); if (m) m.style.display = 'none'; }
function copyShareLink() { var el = document.getElementById('share-link'); if (el) { el.select(); document.execCommand('copy'); alert('Link copiado!'); } }
function copyShareMsg() { var el = document.getElementById('share-msg'); if (el) { el.select(); document.execCommand('copy'); alert('Mensagem copiada!'); } }
function nativeShare() {
  if (!navigator.share) { alert('Compartilhamento nativo nao disponivel no seu navegador.'); return; }
  var url = document.getElementById('share-link') ? document.getElementById('share-link').value : window.location.href;
  navigator.share({ title: 'Portal de Seguranca Global', text: 'Analise de seguranca urbana', url: url }).catch(function() {});
}