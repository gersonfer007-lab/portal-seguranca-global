// ============================================================
// Portal Seguranca Global — Urban Intelligence Portal v5
// ============================================================

// 1. GLOBAL STATE — Gerenciamento centralizado de dados e UI
var PSG_STATE = {
  isLoaded: false,
  isProcessing: false,
  currentLocale: 'pt',
  currentLocation: null,
  map: null,
  marker: null,
  heatmap: null,
  score: 0,
  stats: {
    incidents: 0,
    cameras: 0,
    lighting: 85,
    patrols: 12
  },
  // Dicionário Multilíngue (Otimizado para o Engenheiro)
  i18n: {
    pt: {
      title: "PORTAL SEGURANÇA GLOBAL",
      tagline: "INTELIGÊNCIA URBANA E PREVENÇÃO",
      placeholder: "Digite um endereço, CEP ou cidade...",
      search_btn: "ANALISAR LOCAL",
      btn_map: "ESCOLHER NO MAPA",
      btn_gps: "USAR MEU GPS",
      analyzing: "Processando dados de satélite e segurança...",
      safety_score: "PONTUAÇÃO DE SEGURANÇA",
      score_label: "Nível de Proteção",
      pillars: {
        crime: "Índice de Ocorrências",
        infra: "Infraestrutura e Luz",
        patrol: "Patrulhamento Próximo"
      },
      stats: {
        incidents: "Ocorrências (Raio 1km)",
        cameras: "Câmeras Monitoradas",
        lighting: "Iluminação Pública",
        patrols: "Viaturas na Região"
      },
      charts: {
        incidents: "Histórico Mensal",
        types: "Tipos de Alerta"
      },
      pdf_btn: "GERAR RELATÓRIO PDF",
      paywall_title: "RELATÓRIO COMPLETO DISPONÍVEL",
      paywall_text: "Para visualizar a análise detalhada, mapas de calor históricos e recomendações de segurança, adquira o PDF oficial.",
      pay_btn: "PAGAR COM PIX OU CARTÃO (R$ 10,00)",
      terms_accept: "Eu li e aceito os Termos de Uso e Política de Privacidade."
    },
    en: {
      title: "GLOBAL SECURITY PORTAL",
      tagline: "URBAN INTELLIGENCE & PREVENTION",
      placeholder: "Enter address, Zip Code or city...",
      search_btn: "ANALYZE AREA",
      btn_map: "PICK ON MAP",
      btn_gps: "USE MY GPS",
      analyzing: "Processing satellite and security data...",
      safety_score: "SAFETY SCORE",
      score_label: "Protection Level",
      pillars: {
        crime: "Crime Statistics",
        infra: "Infra & Lighting",
        patrol: "Police Presence"
      },
      stats: {
        incidents: "Incidents (1km Radius)",
        cameras: "Monitored Cameras",
        lighting: "Public Lighting",
        patrols: "Patrol Units"
      },
      charts: {
        incidents: "Monthly History",
        types: "Alert Types"
      },
      pdf_btn: "GENERATE PDF REPORT",
      paywall_title: "FULL REPORT AVAILABLE",
      paywall_text: "To view detailed analysis, historical heatmaps, and security recommendations, purchase the official PDF.",
      pay_btn: "PAY WITH PAYPAL OR CARD ($10.00)",
      terms_accept: "I have read and agree to the Terms of Use and Privacy Policy."
    },
    es: {
      title: "PORTAL SEGURIDAD GLOBAL",
      tagline: "INTELIGENCIA URBANA Y PREVENCIÓN",
      placeholder: "Ingrese dirección, código postal o ciudad...",
      search_btn: "ANALIZAR LOCAL",
      btn_map: "ELEGIR NO MAPA",
      btn_gps: "USAR MI GPS",
      analyzing: "Procesando datos satelitales y de seguridad...",
      safety_score: "PUNTUACIÓN DE SEGURIDAD",
      score_label: "Nivel de Protección",
      pillars: {
        crime: "Índice de Incidentes",
        infra: "Infraestructura y Luz",
        patrol: "Patrullaje Próximo"
      },
      stats: {
        incidents: "Incidentes (Radio 1km)",
        cameras: "Cámaras Monitoreadas",
        lighting: "Alumbrado Público",
        patrols: "Unidades de Patrulla"
      },
      charts: {
        incidents: "Historial Mensual",
        types: "Tipos de Alerta"
      },
      pdf_btn: "GENERAR INFORME PDF",
      paywall_title: "INFORME COMPLETO DISPONIBLE",
      paywall_text: "Para ver análisis detallados, mapas de calor históricos y recomendaciones, adquiera el PDF oficial.",
      pay_btn: "PAGAR CON TARJETA ($10.00)",
      terms_accept: "He leído y acepto los Términos de Uso y la Política de Privacidad."
    },
    fr: {
      title: "PORTAIL SÉCURITÉ GLOBALE",
      tagline: "INTELLIGENCE URBAINE ET PRÉVENTION",
      placeholder: "Entrez une adresse, un code postal ou une ville...",
      search_btn: "ANALYSER LA ZONE",
      btn_map: "CHOISIR SUR CARTE",
      btn_gps: "UTILISER MON GPS",
      analyzing: "Traitement des données satellite et sécurité...",
      safety_score: "SCORE DE SÉCURITÉ",
      score_label: "Niveau de Protection",
      pillars: {
        crime: "Statistiques de Criminalité",
        infra: "Infra et Éclairage",
        patrol: "Présence Policière"
      },
      stats: {
        incidents: "Incidents (Rayon 1km)",
        cameras: "Caméras Surveillées",
        lighting: "Éclairage Public",
        patrols: "Unités de Patrouille"
      },
      charts: {
        incidents: "Historique Mensuel",
        types: "Types d'Alerte"
      },
      pdf_btn: "GÉNÉRER LE RAPPORT PDF",
      paywall_title: "RAPPORT COMPLET DISPONIBLE",
      paywall_text: "Pour consulter l'analyse détaillée, les cartes historiques et les recommandations, achetez le PDF officiel.",
      pay_btn: "PAYER PAR CARTE ($10.00)",
      terms_accept: "J'ai lu et j'accepte les conditions d'utilisation et la politique de confidentialité."
    }
  }
};

// ============================================================
// 2. CORE FUNCTIONS — Inicialização e Eventos
// ============================================================
document.addEventListener('DOMContentLoaded', function() {
  PSG_CORE.init();
});

var PSG_CORE = {
  init: function() {
    console.log("[PSG] Iniciando Sistema...");
    this.setupTerms();
    this.setupLanguage();
    this.setupSearch();
    this.setupMapSelection();
    this.setupGPSSearch();
    PSG_STATE.isLoaded = true;
  },

  setupTerms: function() {
    const overlay = document.getElementById('terms-overlay');
    const btn = document.getElementById('terms-btn');
    const check = document.getElementById('terms-check');

    if (!localStorage.getItem('psg_terms_accepted')) {
      overlay.classList.add('active');
    }

    check.addEventListener('change', () => {
      btn.className = check.checked ? 'terms-btn enabled' : 'terms-btn disabled';
    });

    btn.addEventListener('click', () => {
      if (check.checked) {
        localStorage.setItem('psg_terms_accepted', 'true');
        overlay.classList.add('hidden');
        setTimeout(() => overlay.style.display = 'none', 400);
      }
    });
  },

  setupLanguage: function() {
    // Bandeiras laterais (desktop)
    document.querySelectorAll('.flag-item').forEach(flag => {
      flag.addEventListener('click', () => {
        this.changeLanguage(flag.dataset.lang);
      });
    });
    // Barra mobile
    document.querySelectorAll('.mlb-flag').forEach(flag => {
      flag.addEventListener('click', () => {
        this.changeLanguage(flag.dataset.lang);
      });
    });
  },

  changeLanguage: function(lang) {
    if (!PSG_STATE.i18n[lang]) return;
    PSG_STATE.currentLocale = lang;
    console.log("[PSG] Mudando idioma para:", lang);

    const t = PSG_STATE.i18n[lang];
    
    // Atualiza Textos
    document.querySelector('.emblem-title').textContent = t.title;
    document.querySelector('.emblem-tagline').textContent = t.tagline;
    document.getElementById('search-input').placeholder = t.placeholder;
    document.querySelector('.search-box button span').textContent = t.search_btn;
    document.querySelector('.btn-map-search span').textContent = t.btn_map;
    document.querySelector('.btn-gps-search span').textContent = t.btn_gps;

    // Atualiza Ativo
    document.querySelectorAll('.flag-item').forEach(f => {
      f.classList.toggle('flag-active', f.dataset.lang === lang);
    });
    document.querySelectorAll('.mlb-flag').forEach(f => {
      f.classList.toggle('active', f.dataset.lang === lang);
    });

    if (PSG_STATE.currentLocation) {
      this.updateResultUI();
    }
  },

  setupSearch: function() {
    const input = document.getElementById('search-input');
    const btn = document.getElementById('search-btn');

    btn.addEventListener('click', () => {
      const query = input.value.trim();
      if (query.length > 3) this.performSearch(query);
    });

    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && input.value.length > 3) this.performSearch(input.value);
    });
  },

  performSearch: async function(query) {
    if (PSG_STATE.isProcessing) return;
    PSG_STATE.isProcessing = true;
    
    PSG_UI.showLoading(true);

    try {
      console.log("[PSG] Pesquisando:", query);
      const resp = await fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(query)}&addressdetails=1&limit=1`);
      const data = await resp.json();

      if (data && data[0]) {
        const res = data[0];
        PSG_STATE.currentLocation = {
          name: res.display_name,
          lat: parseFloat(res.lat),
          lon: parseFloat(res.lon),
          city: res.address.city || res.address.town || res.address.village || "Região Analisada",
          country: res.address.country
        };
        this.processSafetyData();
      } else {
        alert("Local não encontrado. Tente um endereço mais específico.");
        PSG_UI.showLoading(false);
        PSG_STATE.isProcessing = false;
      }
    } catch (e) {
      console.error(e);
      PSG_UI.showLoading(false);
      PSG_STATE.isProcessing = false;
    }
  },

  // ============================================================
  // NOVO: PESQUISAR PELO MAPA (MODAL)
  // ============================================================
  setupMapSelection: function() {
    const btnOpen = document.getElementById('btn-map-search');
    const overlay = document.getElementById('mapsel-overlay');
    const btnClose = document.getElementById('mapsel-close');
    const btnCancel = document.getElementById('mapsel-btn-cancel');
    const btnGo = document.getElementById('mapsel-btn-go');
    const selInput = document.getElementById('mapsel-input');
    const btnSelSearch = document.getElementById('mapsel-search-btn');

    let mapselMap = null;
    let mapselMarker = null;
    let selectedPoint = null;

    btnOpen.addEventListener('click', () => {
      overlay.style.display = 'flex';
      setTimeout(() => {
        overlay.classList.add('active');
        if (!mapselMap) {
          // Inicia no Brasil (aprox centro)
          mapselMap = L.map('mapsel-map', { zoomControl: false }).setView([-15.78, -47.92], 4);
          L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png').addTo(mapselMap);
          L.control.zoom({ position: 'bottomright' }).addTo(mapselMap);

          mapselMap.on('click', (e) => {
            updateSelection(e.latlng.lat, e.latlng.lng);
            document.querySelector('.mapsel-crosshair-hint').classList.add('gone');
          });
        }
        mapselMap.invalidateSize();
      }, 50);
    });

    const closeMap = () => {
      overlay.classList.remove('active');
      setTimeout(() => overlay.style.display = 'none', 300);
    };

    btnClose.addEventListener('click', closeMap);
    btnCancel.addEventListener('click', closeMap);

    btnSelSearch.addEventListener('click', async () => {
      const q = selInput.value.trim();
      if (q.length < 3) return;
      try {
        const r = await fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(q)}&limit=1`);
        const d = await r.json();
        if (d && d[0]) {
          const lat = parseFloat(d[0].lat);
          const lon = parseFloat(d[0].lon);
          mapselMap.setView([lat, lon], 16);
          updateSelection(lat, lon);
        }
      } catch(err) {}
    });

    const updateSelection = async (lat, lon) => {
      selectedPoint = { lat, lon };
      if (mapselMarker) mapselMap.removeLayer(mapselMarker);

      // Icone de pino pulsante
      const pinIcon = L.divIcon({
        className: 'mapsel-pin-wrap',
        html: '<div class="mapsel-pin-pulse"></div>',
        iconSize: [20, 20],
        iconAnchor: [10, 10]
      });
      mapselMarker = L.marker([lat, lon], { icon: pinIcon }).addTo(mapselMap);
      
      document.getElementById('mapsel-picked-addr').textContent = "Buscando endereço...";
      document.getElementById('mapsel-coords').textContent = `${lat.toFixed(5)}, ${lon.toFixed(5)}`;
      document.getElementById('mapsel-picked').classList.add('filled');
      btnGo.disabled = false;

      try {
        const r = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&addressdetails=1`);
        const d = await r.json();
        selectedPoint.name = d.display_name;
        selectedPoint.city = d.address.city || d.address.town || d.address.village || "Região Selecionada";
        selectedPoint.country = d.address.country;
        document.getElementById('mapsel-picked-addr').textContent = d.display_name;
      } catch(e) {
        document.getElementById('mapsel-picked-addr').textContent = "Coordenadas selecionadas";
      }
    };

    btnGo.addEventListener('click', () => {
      if (selectedPoint) {
        PSG_STATE.currentLocation = selectedPoint;
        closeMap();
        PSG_CORE.processSafetyData();
      }
    });
  },

  // ============================================================
  // NOVO: PESQUISAR POR GPS
  // ============================================================
  setupGPSSearch: function() {
    const btn = document.getElementById('btn-gps-search');
    btn.addEventListener('click', () => {
      if (!navigator.geolocation) {
        alert("Geolocalização não suportada pelo seu navegador.");
        return;
      }

      PSG_UI.showLoading(true);
      navigator.geolocation.getCurrentPosition(async (pos) => {
        const lat = pos.coords.latitude;
        const lon = pos.coords.longitude;
        
        try {
          const r = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&addressdetails=1`);
          const d = await r.json();
          PSG_STATE.currentLocation = {
            lat, lon,
            name: d.display_name,
            city: d.address.city || d.address.town || d.address.village || "Minha Localização",
            country: d.address.country
          };
          this.processSafetyData();
        } catch(e) {
          PSG_STATE.currentLocation = { lat, lon, name: "Localização GPS", city: "Sua Posição", country: "" };
          this.processSafetyData();
        }
      }, (err) => {
        PSG_UI.showLoading(false);
        alert("Erro ao acessar GPS. Verifique as permissões do navegador.");
      }, { timeout: 10000 });
    });
  },

  processSafetyData: function() {
    // Algoritmo de segurança simulado (baseado em dados reais do Nominatim)
    const loc = PSG_STATE.currentLocation;
    
    // Gera um score baseado na "densidade" do endereço para simulação determinística
    let seed = loc.name.length + (loc.lat + loc.lon);
    const pseudoRandom = (max) => {
      seed = (seed * 9301 + 49297) % 233280;
      return Math.floor((seed / 233280) * max);
    };

    PSG_STATE.score = 60 + pseudoRandom(35);
    PSG_STATE.stats = {
      incidents: 5 + pseudoRandom(15),
      cameras: 12 + pseudoRandom(40),
      lighting: 70 + pseudoRandom(25),
      patrols: 4 + pseudoRandom(10)
    };

    this.updateResultUI();
    PSG_UI.showLoading(false);
    PSG_STATE.isProcessing = false;
  },

  updateResultUI: function() {
    document.getElementById('main-content').classList.add('active');
    document.getElementById('res-addr').textContent = PSG_STATE.currentLocation.name;
    document.getElementById('res-city').textContent = `${PSG_STATE.currentLocation.city}, ${PSG_STATE.currentLocation.country}`;

    PSG_UI.updateScore(PSG_STATE.score);
    PSG_UI.updateStats(PSG_STATE.stats);
    PSG_UI.renderCharts();
    
    // Scroll suave para os resultados
    document.getElementById('main-content').scrollIntoView({ behavior: 'smooth' });

    // Inicia Mapa
    this.initResultMap();
  },

  initResultMap: function() {
    const { lat, lon } = PSG_STATE.currentLocation;

    if (!PSG_STATE.map) {
      PSG_STATE.map = L.map('map', { zoomControl: false }).setView([lat, lon], 15);
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '© OpenStreetMap'
      }).addTo(PSG_STATE.map);
      L.control.zoom({ position: 'bottomright' }).addTo(PSG_STATE.map);
    } else {
      PSG_STATE.map.setView([lat, lon], 15);
    }

    if (PSG_STATE.marker) PSG_STATE.map.removeLayer(PSG_STATE.marker);
    
    const mainIcon = L.divIcon({
      className: 'custom-marker',
      html: `<div style="width:16px;height:16px;background:#3b82f6;border:3px solid #fff;border-radius:50%;box-shadow:0 0 15px #3b82f6;"></div>`,
      iconSize: [16, 16]
    });
    PSG_STATE.marker = L.marker([lat, lon], { icon: mainIcon }).addTo(PSG_STATE.map);

    // Heatmap Simulado (Ocorrências na Região)
    if (PSG_STATE.heatmap) PSG_STATE.map.removeLayer(PSG_STATE.heatmap);
    const points = [];
    for(let i=0; i<20; i++) {
      points.push([lat + (Math.random()-.5)*0.01, lon + (Math.random()-.5)*0.01, Math.random()]);
    }
    PSG_STATE.heatmap = L.heatLayer(points, {radius: 25, blur: 15, max: 1.0}).addTo(PSG_STATE.map);

    // Atualiza Earth View
    this.updateEarthView(lat, lon);
  },

  updateEarthView: function(lat, lon) {
    const iframe = document.getElementById('earth-iframe');
    const loading = document.getElementById('globe-loading');
    const info = document.getElementById('globe-info');
    
    loading.classList.remove('hidden');
    // URL do Google Earth com parâmetros de zoom e inclinação para efeito 3D
    const earthUrl = `https://www.google.com/maps/embed?pb=!1m14!1m12!1m3!1d1500!2d${lon}!3d${lat}!2m3!1f45!2f45!3f0!3m2!1i1024!2i768!4f35!4m2!3m1!1s0x0:0x0!5m1!1e4&hl=pt-BR`;
    
    iframe.src = earthUrl;
    document.getElementById('globe-coords').textContent = `${lat.toFixed(6)}, ${lon.toFixed(6)}`;

    iframe.onload = () => {
      setTimeout(() => {
        loading.classList.add('hidden');
        info.classList.add('active');
      }, 800);
    };
  }
};

// ============================================================
// 3. UI COMPONENTS — Gráficos, Gauges e Modais
// ============================================================
var PSG_UI = {
  showLoading: function(show) {
    document.getElementById('loading').classList.toggle('active', show);
  },

  updateScore: function(val) {
    const num = document.getElementById('score-num');
    const label = document.getElementById('score-label');
    const fill = document.getElementById('score-fill');
    
    num.textContent = val;
    
    // Calcula offset do círculo (stroke-dasharray: 283)
    const offset = 283 - (283 * val / 100);
    fill.style.strokeDashoffset = offset;

    if (val > 80) {
      fill.style.stroke = "#22c55e";
      label.textContent = "EXCELENTE";
      label.style.color = "#22c55e";
    } else if (val > 50) {
      fill.style.stroke = "#eab308";
      label.textContent = "MODERADO";
      label.style.color = "#eab308";
    } else {
      fill.style.stroke = "#ef4444";
      label.textContent = "CRÍTICO";
      label.style.color = "#ef4444";
    }

    // Pilares
    this.updatePillar('pillar-crime', val - 5);
    this.updatePillar('pillar-infra', val + 10);
    this.updatePillar('pillar-patrol', val - 15);
  },

  updatePillar: function(id, val) {
    const v = Math.min(100, Math.max(0, val));
    const p = document.getElementById(id);
    p.querySelector('.pillar-bar-fill').style.width = v + "%";
    p.querySelector('.pillar-score').textContent = v;
    
    let color = "#ef4444";
    if (v > 75) color = "#22c55e";
    else if (v > 45) color = "#eab308";
    p.querySelector('.pillar-bar-fill').style.background = color;
  },

  updateStats: function(stats) {
    document.getElementById('stat-incidents').textContent = stats.incidents;
    document.getElementById('stat-cameras').textContent = stats.cameras;
    document.getElementById('stat-lighting').textContent = stats.lighting + "%";
    document.getElementById('stat-patrols').textContent = stats.patrols;
  },

  renderCharts: function() {
    // Chart Incidents
    const ctx1 = document.getElementById('chart-incidents').getContext('2d');
    if (window.incChart) window.incChart.destroy();
    window.incChart = new Chart(ctx1, {
      type: 'line',
      data: {
        labels: ['Jan', 'Fev', 'Mar', 'Abr', 'Mai', 'Jun'],
        datasets: [{
          label: 'Ocorrências',
          data: [12, 19, 8, 15, 11, PSG_STATE.stats.incidents],
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59,130,246,0.1)',
          fill: true,
          tension: 0.4
        }]
      },
      options: this.getChartOptions()
    });

    // Chart Types
    const ctx2 = document.getElementById('chart-types').getContext('2d');
    if (window.typeChart) window.typeChart.destroy();
    window.typeChart = new Chart(ctx2, {
      type: 'doughnut',
      data: {
        labels: ['Furtos', 'Roubos', 'Outros'],
        datasets: [{
          data: [45, 25, 30],
          backgroundColor: ['#3b82f6', '#f97316', '#1f2a40'],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: '#8b95a8', boxWidth: 12 } } }
      }
    });
  },

  getChartOptions: function() {
    return {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { grid: { color: 'rgba(255,255,255,0.05)' }, border: { display: false }, ticks: { color: '#5a6478' } },
        x: { grid: { display: false }, ticks: { color: '#5a6478' } }
      }
    };
  },

  toggleMapView: function(view) {
    const mapDiv = document.getElementById('map');
    const globeDiv = document.getElementById('cesium-globe');
    const btn2d = document.getElementById('btn-view-2d');
    const btn3d = document.getElementById('btn-view-3d');

    if (view === '3d') {
      mapDiv.style.display = 'none';
      globeDiv.style.display = 'block';
      btn3d.classList.add('active');
      btn2d.classList.remove('active');
    } else {
      mapDiv.style.display = 'block';
      globeDiv.style.display = 'none';
      btn2d.classList.add('active');
      btn3d.classList.remove('active');
    }
  }
};

// ============================================================
// 4. PDF & PAYWALL — Entrega de Resultados
// ============================================================
var PSG_PDF = {
  handleGenerate: function() {
    console.log("[PSG] Abrindo Cadeado de Pagamento...");
    this.showPaywall();
  },

  showPaywall: function() {
    const t = PSG_STATE.i18n[PSG_STATE.currentLocale];
    const paywallHtml = `
      <div id="paywall-modal" style="position:fixed;inset:0;background:rgba(0,0,0,0.9);z-index:3000;display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(10px);">
        <div class="card" style="max-width:480px;width:100%;padding:2rem;text-align:center;">
          <div style="font-size:3rem;margin-bottom:1rem;">🔒</div>
          <h2 style="margin-bottom:1rem;">${t.paywall_title}</h2>
          <p style="color:var(--text-secondary);margin-bottom:2rem;font-size:.9rem;">${t.paywall_text}</p>
          
          <button id="btn-pay-mp" class="btn btn-primary" style="width:100%;justify-content:center;height:54px;font-size:1rem;margin-bottom:1rem;">
            ${t.pay_btn}
          </button>
          
          <button onclick="document.getElementById('paywall-modal').remove()" class="btn btn-outline" style="width:100%;justify-content:center;">
            FECHAR
          </button>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', paywallHtml);

    const payBtn = document.getElementById('btn-pay-mp');
    if (payBtn) payBtn.addEventListener('click', this.handlePayment);
  },

  handlePayment: async function() {
    const btn = document.getElementById('btn-pay-mp');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span>Processando...</span>';

    try {
      // Chamada real para o backend Node.js (server.js)
      const response = await fetch('/api/create-preference', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: `Relatório Segurança: ${PSG_STATE.currentLocation.city}`,
          unit_price: 10.00,
          quantity: 1
        })
      });

      const data = await response.json();
      
      if (data.id) {
        // Redireciona para o Checkout Pro do Mercado Pago
        console.log("[Payment] Redirecionando para Mercado Pago Preference:", data.id);
        window.location.href = `https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=${data.id}`;
      } else {
        throw new Error("Preference ID not found");
      }
    } catch (error) {
      console.error("[Payment] Erro:", error);
      alert("Erro ao iniciar pagamento. Tente novamente em instantes.");
      btn.disabled = false;
      btn.innerHTML = originalText;
    }
  },

  // Função chamada automaticamente pelo back_url se o pagamento for sucesso
  checkPaymentStatus: function() {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('payment') === 'success') {
      this.executePDFGeneration();
    }
  },

  executePDFGeneration: function() {
    console.log("[PSG] Pagamento Confirmado. Gerando PDF...");
    PSG_UI.showLoading(true);
    
    // Carrega bibliotecas necessárias
    this.loadScript("https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js", () => {
      this.loadScript("https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js", () => {
        this.generateNow();
      });
    });
  },

  loadScript: function(url, callback) {
    const s = document.createElement('script');
    s.src = url;
    s.onload = callback;
    document.head.appendChild(s);
  },

  generateNow: async function() {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF('p', 'mm', 'a4');
    const report = document.getElementById('pdf-report');
    
    // Preenche dados no template oculto
    report.querySelector('.pdf-location').textContent = PSG_STATE.currentLocation.name;
    report.querySelector('.pdf-score-number').textContent = PSG_STATE.score;
    
    const canvas = await html2canvas(report, { scale: 2 });
    const imgData = canvas.toDataURL('image/png');
    
    doc.addImage(imgData, 'PNG', 0, 0, 210, 297);
    doc.save(`PSG-Relatorio-${PSG_STATE.currentLocation.city}.pdf`);
    
    PSG_UI.showLoading(false);
    alert("Relatório gerado com sucesso! Verifique seus downloads.");
    
    // Limpa URL
    window.history.replaceState({}, document.title, "/");
  }
};

// Monitora status de pagamento ao carregar
document.addEventListener('DOMContentLoaded', () => {
  PSG_PDF.checkPaymentStatus();
});
