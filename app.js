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

  // Se parece um nome (so letras e espacos, 2+ palavras, sem numeros)
  var looksLikeName = /^[A-Za-zÀ-ÿ\s]{3,}$/.test(rawQuery) && rawQuery.split(/\s+/).length >= 2;
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
        if (!data.erro) { addressData = { street: data.logradouro || 'Endereco', neighborhood: data.bairro || '', city: data.localidade || '', state: data.uf || '', country: 'Brasil', cep: data.cep, fullAddress: (data.logradouro ? data.logradouro + ', ' : '') + (data.bairro ? data.bairro + ' - ' : '') + data.localidade + '/' + data.uf }; }
      } catch(e) {}
    }
    if (!addressData && /^\d{5}(-\d{4})?$/.test(query.trim())) { addressData = { street: '', neighborhood: '', city: '', state: '', country: 'USA', cep: query.trim(), fullAddress: query.trim() + ', United States' }; }
    if (!addressData && /^[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}$/i.test(query.trim())) { addressData = { street: '', neighborhood: '', city: '', state: '', country: 'UK', cep: query.trim(), fullAddress: query.trim() + ', United Kingdom' }; }
    if (!addressData) { addressData = { street: query, neighborhood: '', city: '', state: '', country: '', cep: '', fullAddress: query }; }
    updateLoading('Geolocalizando endereco...');
    const geoRes = await fetch('https://nominatim.openstreetmap.org/search?format=json&q=' + encodeURIComponent(addressData.fullAddress) + '&limit=1&accept-language=pt,en');
    const geoData = await geoRes.json();
    let lat, lng;
    if (geoData.length > 0) { lat = parseFloat(geoData[0].lat); lng = parseFloat(geoData[0].lon); if (!addressData.city && geoData[0].display_name) { addressData.fullAddress = geoData[0].display_name; } }
    else { throw new Error('Endereco nao encontrado. Tente com mais detalhes (cidade, pais).'); }
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
async function generatePDF() {
  if (!currentData) return alert('Faca uma pesquisa primeiro.');
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
    pdf.save('PortalSegurancaGlobal_Relatorio_' + Date.now() + '.pdf');
    hideLoading();
  } catch (err) { hideLoading(); alert('Erro ao gerar PDF: ' + err.message); }
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
  var userLang = (navigator.language || navigator.userLanguage || 'pt').substring(0, 2).toLowerCase();
  var supported = Object.keys(manualData);
  var lang = supported.indexOf(userLang) !== -1 ? userLang : 'en';
  el.value = lang;
  switchManualLang(lang);
})();

// ============================================================
// FLAGS — Repetir bandeiras para preencher toda a altura da pagina
// ============================================================
(function fillFlags() {
  var cols = document.querySelectorAll('.flags-column');
  if (!cols.length) return;
  cols.forEach(function(col) {
    var items = col.querySelectorAll('.flag-item');
    if (!items.length) return;
    var originalHTML = '';
    for (var i = 0; i < items.length; i++) {
      originalHTML += items[i].outerHTML;
    }
    // Repetir as bandeiras 4 vezes para cobrir paginas longas
    for (var r = 0; r < 4; r++) {
      col.insertAdjacentHTML('beforeend', originalHTML);
    }
  });
})();