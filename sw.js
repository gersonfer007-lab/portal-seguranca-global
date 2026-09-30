/* ============================================================
   PORTAL SEGURANCA GLOBAL — Service Worker (GPS offline)
   - App shell em cache: o portal abre sem internet
   - Tiles de mapa (Esri) em cache: a rota vista continua
     visivel offline durante a navegacao
   - APIs (rotas, geocodificacao, mar): so online, sem cache
   Versao: psg-sw-v2
   ============================================================ */
var CACHE_SHELL = 'psg-shell-v2';
var CACHE_TILES = 'psg-tiles-v1';
var SHELL_ASSETS = [
  '/',
  '/index.html',
  '/app.js',
  '/brasao-sh.png',
  '/caminhada-segura.html',
  '/noticias.html',
  '/zona-rural.html',
  '/constituicao.html',
  '/constituicao-data.js',
  '/quem-somos.html',
  'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css',
  'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js',
  'https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js'
];
var API_HOSTS = [
  'nominatim.openstreetmap.org',
  'router.project-osrm.org',
  'routing.openstreetmap.de',
  'overpass-api.de',
  'overpass.kumi.systems',
  'marine-api.open-meteo.com',
  'formsubmit.co',
  'viacep.com.br'
];

self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE_SHELL).then(function(c) {
      // addAll falha inteiro se 1 item falhar; usa add individual tolerante
      return Promise.allSettled(SHELL_ASSETS.map(function(u) { return c.add(u); }));
    }).then(function() { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(keys.filter(function(k) {
        return k !== CACHE_SHELL && k !== CACHE_TILES;
      }).map(function(k) { return caches.delete(k); }));
    }).then(function() { return self.clients.claim(); })
  );
});

self.addEventListener('message', function(e) {
  var d = e.data || {};
  if (d.type === 'CACHE_TILES' && d.urls && d.urls.length) {
    e.waitUntil(
      caches.open(CACHE_TILES).then(function(c) {
        return Promise.allSettled(d.urls.slice(0, 400).map(function(u) {
          return c.match(u).then(function(hit) {
            if (hit) return null;
            return fetch(u, { mode: 'no-cors' }).then(function(r) {
              if (r && (r.ok || r.type === 'opaque')) return c.put(u, r);
            }).catch(function() { /* tile individual pode falhar */ });
          });
        }));
      })
    );
  }
  if (d.type === 'SKIP_WAITING') { self.skipWaiting(); }
});

self.addEventListener('fetch', function(e) {
  var req = e.request;
  if (req.method !== 'GET') return;
  var url;
  try { url = new URL(req.url); } catch (err) { return; }

  // 1) APIs de dados: apenas online, nunca cacheia
  if (API_HOSTS.indexOf(url.hostname) !== -1) return;

  // Sondas de diagnostico do service worker (mesma origem e cross-origin)
  if (url.pathname === '/swprobe' || url.pathname === '/swprobe-x') {
    e.respondWith(new Response('SW_ALIVE', { headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' } }));
    return;
  }

  // 2) Tiles de mapa (Esri): cache-first — tile salvo nunca expira
  if (url.hostname === 'server.arcgisonline.com') {
    e.respondWith(
      caches.open(CACHE_TILES).then(function(c) {
        return c.match(req).then(function(hit) {
          if (hit) return hit;
          return fetch(req).then(function(r) {
            // tiles via <img> chegam como opaque (r.ok=false, mas validos)
            if (r && (r.ok || r.type === 'opaque')) { c.put(req, r.clone()); }
            return r;
          }).catch(function() { return Response.error(); });
        });
      })
    );
    return;
  }

  // 3) Bibliotecas CDN (Leaflet): cache-first
  if (url.hostname === 'unpkg.com' || url.hostname === 'cdnjs.cloudflare.com' || url.hostname === 'cdn.jsdelivr.net') {
    e.respondWith(
      caches.open(CACHE_SHELL).then(function(c) {
        return c.match(req).then(function(hit) {
          if (hit) return hit;
          return fetch(req).then(function(r) {
            if (r && (r.ok || r.type === 'opaque')) { c.put(req, r.clone()); }
            return r;
          }).catch(function() { return Response.error(); });
        });
      })
    );
    return;
  }

  // 4) Mesma origem: network-first (atualizacoes do portal fluem),
  //    com fallback para o cache quando offline
  if (url.origin === self.location.origin) {
    // Navegacao de pagina
    if (req.mode === 'navigate' || url.pathname.endsWith('.html') || url.pathname === '/') {
      e.respondWith(
        fetch(req).then(function(r) {
          var cp = r.clone();
          caches.open(CACHE_SHELL).then(function(c) { c.put(req, cp); });
          return r;
        }).catch(function() {
          return caches.open(CACHE_SHELL).then(function(c) {
            return c.match(req).then(function(hit) {
              if (hit) return hit;
              return c.match('/index.html');
            });
          });
        })
      );
      return;
    }
    // Assets do portal (app.js, imagens, manifest, css)
    e.respondWith(
      fetch(req).then(function(r) {
        if (r && (r.ok || r.type === 'opaque')) {
          var cp = r.clone();
          caches.open(CACHE_SHELL).then(function(c) { c.put(req, cp); });
        }
        return r;
      }).catch(function() {
        return caches.open(CACHE_SHELL).then(function(c) {
          return c.match(req).then(function(hit) { if (hit) return hit; throw new Error('offline'); });
        });
      })
    );
  }
  // Outros hosts (Google Fonts, etc.): deixa o navegador cuidar
});
