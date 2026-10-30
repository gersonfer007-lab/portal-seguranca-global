// ============================================================
// Portal Seguranca Global — MOTOR DE DADOS (contexto urbano real)
// ------------------------------------------------------------
// Substitui os numeros inventados que existiam em paywall.js.
// Tudo aqui vem de fonte publica, com data de coleta, e quando a
// fonte nao responde o resultado e "sem dado" — nunca zero.
//
// Fonte: OpenStreetMap, consultado pela Overpass API (varios espelhos,
// com retry e backoff — os espelhos oficiais saturam com frequencia).
// Nao existe base publica de crime por endereco no Brasil; por isso o
// relatorio entrega INVENTARIO do entorno (equipamentos, servicos,
// transporte, presenca de seguranca) e nao ocorrencias.
// ============================================================
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIO_KM = 1.5;
const RAIO_M = Math.round(RAIO_KM * 1000);
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 dias: OSM muda devagar
const TIMEOUT_POR_ENDPOINT_MS = 7000;
const ORCAMENTO_TOTAL_MS = 14000;

const FONTE = {
  nome: 'OpenStreetMap (Overpass API)',
  url: 'https://www.openstreetmap.org',
  licenca: 'ODbL 1.0'
};

// Espelhos: os dois primeiros respondem quando os oficiais estao saturados.
const ENDPOINTS = [
  'https://maps.mail.ru/osm/tools/overpass/api/interpreter',
  'https://overpass-api.de/api/interpreter',
  'https://overpass.kumi.systems/api/interpreter',
  'https://overpass.osm.ch/api/interpreter'
];

const UA = 'PortalSegurancaGlobal/1.0 (+https://portalsegurancaglobal.com.br)';

// ------------------------------------------------------------
// CACHE (memoria + arquivo temporario)
// ------------------------------------------------------------
const CACHE_ARQ = path.join(os.tmpdir(), 'psg-osm-cache.json');
let cacheMem = null;

function lerCache() {
  if (cacheMem) return cacheMem;
  try { cacheMem = JSON.parse(fs.readFileSync(CACHE_ARQ, 'utf8')) || {}; }
  catch (e) { cacheMem = {}; }
  return cacheMem;
}

function gravarCache() {
  try { fs.writeFileSync(CACHE_ARQ, JSON.stringify(cacheMem)); }
  catch (e) { /* cache e otimizacao: se falhar, segue sem ele */ }
}

const CACHE_VERSAO = 'v2';
function chave(lat, lng) {
  return CACHE_VERSAO + '|' + lat.toFixed(3) + ',' + lng.toFixed(3);
}

// ------------------------------------------------------------
// COLETA NO OPENSTREETMAP
// ------------------------------------------------------------
function montarQuery(lat, lng) {
  const a = `(around:${RAIO_M},${lat},${lng})`;
  return `[out:json][timeout:25];
(
  nwr["amenity"~"^(school|university|kindergarten)$"]${a};
  nwr["amenity"~"^(hospital|clinic|doctors|pharmacy)$"]${a};
  nwr["amenity"~"^(bank|police|fire_station|fuel|marketplace)$"]${a};
  nwr["shop"~"^(supermarket|mall|department_store)$"]${a};
  nwr["shop"]${a};
  nwr["leisure"~"^(park|garden|pitch|sports_centre)$"]${a};
  nwr["man_made"="surveillance"]${a};
  nwr["highway"="bus_stop"]${a};
  nwr["public_transport"="station"]${a};
  nwr["railway"~"^(station|subway_entrance|tram_stop)$"]${a};
);
out center tags;`;
}

async function tentarEndpoint(endpoint, query, timeoutMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': UA,
        'Accept': 'application/json'
      },
      body: 'data=' + encodeURIComponent(query),
      signal: ctl.signal
    });
    if (!r.ok) return { ok: false, motivo: 'HTTP ' + r.status };
    const texto = await r.text();
    let json;
    try { json = JSON.parse(texto); }
    catch (e) {
      // alguns espelhos respondem XML mesmo com out:json
      if (/^<\?xml|<osm/i.test(texto)) return { ok: false, motivo: 'XML nao suportado' };
      return { ok: false, motivo: 'resposta invalida' };
    }
    if (!json || !Array.isArray(json.elements)) return { ok: false, motivo: 'sem elementos' };
    return { ok: true, elementos: json.elements };
  } catch (e) {
    return { ok: false, motivo: e.name === 'AbortError' ? 'timeout' : e.message };
  } finally {
    clearTimeout(t);
  }
}

async function tentarOverpass(lat, lng) {
  const query = montarQuery(lat, lng);
  const inicio = Date.now();
  const falhas = [];
  for (const ep of ENDPOINTS) {
    if (Date.now() - inicio > ORCAMENTO_TOTAL_MS) { falhas.push('orcamento esgotado'); break; }
    const r = await tentarEndpoint(ep, query, TIMEOUT_POR_ENDPOINT_MS);
    if (r.ok) return { ok: true, elementos: r.elementos, endpoint: ep, via: 'overpass' };
    falhas.push((new URL(ep)).host + ': ' + r.motivo);
  }
  return { ok: false, falhas: falhas };
}

// Overpass e API oficial do OSM correm em paralelo: a Overpass e menor e
// mais rapida quando esta livre; a API oficial responde quando os
// espelhos da Overpass saturam (o que acontece com frequencia).
async function coletarElementos(lat, lng) {
  const tarefas = [tentarOverpass(lat, lng), coletarPorBBox(lat, lng, [])];
  const falhas = [];
  let abertas = tarefas.length;
  return new Promise(function (resolve) {
    let resolvido = false;
    tarefas.forEach(function (t) {
      t.then(function (r) {
        if (!resolvido && r && r.ok) { resolvido = true; resolve(r); return; }
        if (r && r.falhas) falhas.push.apply(falhas, r.falhas);
      }).catch(function (e) {
        falhas.push(e.message);
      }).then(function () {
        abertas--;
        if (abertas === 0 && !resolvido) resolve({ ok: false, falhas: falhas });
      });
    });
  });
}

// ------------------------------------------------------------
// PLANO B — API oficial do OSM (/api/0.6/map?bbox=)
// ------------------------------------------------------------
const OSM_API = 'https://api.openstreetmap.org/api/0.6/map?bbox=';

function bboxDoRaio(lat, lng) {
  const dLat = RAIO_M / 111320;
  const dLng = RAIO_M / (111320 * Math.cos(lat * Math.PI / 180));
  return { lat0: lat - dLat, lat1: lat + dLat, lng0: lng - dLng, lng1: lng + dLng };
}

function tiles(lat, lng, n) {
  const b = bboxDoRaio(lat, lng);
  const dLat = (b.lat1 - b.lat0) / n;
  const dLng = (b.lng1 - b.lng0) / n;
  const lista = [];
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      lista.push([b.lng0 + dLng * j, b.lat0 + dLat * i, b.lng0 + dLng * (j + 1), b.lat0 + dLat * (i + 1)]);
    }
  }
  return lista;
}

// Parser do XML do OSM. Devolve elementos COM tags, ja com coordenada
// (node lat/lon ou centroide do way calculado pelos nos). Elementos cujo
// centroide fica fora do raio sao descartados depois, em coletarPorBBox —
// o recorte e quadrado e o raio e circular.
const TAG_RE = /<tag\s+k="([^"]*)"\s+v="([^"]*)"\s*\/?>/g;
const NODE_RE = /<node\b([^>]*?)(\/?)>/g;
const ELEM_RE = /<(node|way|relation)\b([^>]*?)(\/?)>/g;

function parseOsmXml(xml) {
  const coords = new Map();
  let m;
  // 1) coordenadas de todos os nos (inclusive os que vieram so como geometria)
  NODE_RE.lastIndex = 0;
  while ((m = NODE_RE.exec(xml)) !== null) {
    const attrs = m[1] || '';
    const id = /id="(\d+)"/.exec(attrs);
    const lat = /lat="([-\d.]+)"/.exec(attrs);
    const lon = /lon="([-\d.]+)"/.exec(attrs);
    if (id && lat && lon) coords.set(id[1], [Number(lat[1]), Number(lon[1])]);
  }

  const elementos = [];
  ELEM_RE.lastIndex = 0;
  while ((m = ELEM_RE.exec(xml)) !== null) {
    const tipo = m[1];
    const attrs = m[2] || '';
    const autoFechado = m[3] === '/';
    const fechamento = autoFechado ? -1 : xml.indexOf('</' + tipo + '>', ELEM_RE.lastIndex);
    const trecho = autoFechado ? '' : (fechamento === -1 ? '' : xml.slice(ELEM_RE.lastIndex, fechamento));

    const tags = {};
    TAG_RE.lastIndex = 0;
    let t;
    while ((t = TAG_RE.exec(trecho)) !== null) tags[t[1]] = t[2];

    if (Object.keys(tags).length) {
      const id = /id="(\d+)"/.exec(attrs);
      const lat = /lat="([-\d.]+)"/.exec(attrs);
      const lon = /lon="([-\d.]+)"/.exec(attrs);
      let ponto = null;
      if (lat && lon) {
        ponto = [Number(lat[1]), Number(lon[1])];
      } else if (tipo === 'way') {
        // centroide aproximado pelos nos do caminho
        const nd = /<nd\s+ref="(\d+)"/g;
        let soma = 0, sla = 0, slo = 0, n;
        while ((n = nd.exec(trecho)) !== null) {
          const c = coords.get(n[1]);
          if (c) { sla += c[0]; slo += c[1]; soma++; }
        }
        if (soma) ponto = [sla / soma, slo / soma];
      }

      elementos.push({
        tipo: tipo,
        id: id ? tipo + '/' + id[1] : null,
        tags: tags,
        lat: ponto ? ponto[0] : undefined,
        lon: ponto ? ponto[1] : undefined
      });
    }

    if (fechamento !== -1) ELEM_RE.lastIndex = fechamento + tipo.length + 3;
  }
  return elementos;
}

function distanciaM(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLng = (lng2 - lng1) * rad;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(a)));
}

async function baixarTile(bbox) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 20000);
  try {
    const url = OSM_API + bbox.join(',');
    const r = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': UA, 'Accept': 'application/xml' },
      signal: ctl.signal
    });
    if (!r.ok) return { ok: false, motivo: 'HTTP ' + r.status };
    const xml = await r.text();
    return { ok: true, elementos: parseOsmXml(xml) };
  } catch (e) {
    return { ok: false, motivo: e.name === 'AbortError' ? 'timeout' : e.message };
  } finally {
    clearTimeout(t);
  }
}

async function coletarPorBBox(lat, lng, falhasAnteriores) {
  const falhas = (falhasAnteriores || []).slice();
  const partes = tiles(lat, lng, 2);
  const respostas = await Promise.all(partes.map(function (b) { return baixarTile(b); }));

  const acumulado = [];
  const vistos = new Set();
  for (let k = 0; k < respostas.length; k++) {
    const r = respostas[k];
    if (!r.ok) { falhas.push('api.osm.org: ' + r.motivo); return { ok: false, falhas: falhas }; }
    for (let i = 0; i < r.elementos.length; i++) {
      const el = r.elementos[i];
      // elemento que cruza dois recortes aparece nas duas respostas
      if (el.id) {
        if (vistos.has(el.id)) continue;
        vistos.add(el.id);
      }
      // recorte quadrado: mantem apenas o que esta dentro do raio
      if (el.lat != null && el.lon != null && distanciaM(lat, lng, el.lat, el.lon) > RAIO_M) continue;
      acumulado.push(el);
    }
  }
  if (!acumulado.length) { falhas.push('api.osm.org: nenhum elemento com tag'); return { ok: false, falhas: falhas }; }
  return { ok: true, elementos: acumulado, via: 'osm-api' };
}

// ------------------------------------------------------------
// MONTAGEM DO RESULTADO
// ------------------------------------------------------------
// ------------------------------------------------------------
// CLASSIFICACAO DOS ELEMENTOS
// ------------------------------------------------------------
const temTag = (t, chaveTag, re) => {
  const v = t && t[chaveTag];
  return typeof v === 'string' && re.test(v);
};

function classificar(elementos) {
  const c = {
    escolas: 0, universidades: 0, saude: 0, farmacias: 0, bancos: 0,
    unidadesPoliciais: 0, bombeiros: 0, postosCombustivel: 0,
    mercados: 0, comercios: 0, parques: 0, areasEsporte: 0,
    cameras: 0, pontosOnibus: 0, estacoes: 0
  };
  const pontos = { policia: [], bombeiros: [] };

  (elementos || []).forEach(function (el) {
    const t = el.tags || {};
    const lat = el.lat != null ? el.lat : (el.center && el.center.lat);
    const lng = el.lon != null ? el.lon : (el.center && el.center.lon);

    if (temTag(t, 'amenity', /^(school|kindergarten)$/)) c.escolas++;
    if (temTag(t, 'amenity', /^university$/)) c.universidades++;
    if (temTag(t, 'amenity', /^(hospital|clinic|doctors)$/)) c.saude++;
    if (temTag(t, 'amenity', /^pharmacy$/)) c.farmacias++;
    if (temTag(t, 'amenity', /^bank$/)) c.bancos++;
    if (temTag(t, 'amenity', /^police$/)) {
      c.unidadesPoliciais++;
      if (lat != null && pontos.policia.length < 12) {
        pontos.policia.push({ lat: lat, lng: lng, nome: t.name || 'Unidade policial' });
      }
    }
    if (temTag(t, 'amenity', /^fire_station$/)) {
      c.bombeiros++;
      if (lat != null && pontos.bombeiros.length < 8) {
        pontos.bombeiros.push({ lat: lat, lng: lng, nome: t.name || 'Corpo de bombeiros' });
      }
    }
    if (temTag(t, 'amenity', /^fuel$/)) c.postosCombustivel++;
    if (temTag(t, 'amenity', /^marketplace$/) || temTag(t, 'shop', /^(supermarket|mall|department_store)$/)) c.mercados++;
    if (temTag(t, 'shop', /./)) c.comercios++;
    if (temTag(t, 'leisure', /^(park|garden)$/)) c.parques++;
    if (temTag(t, 'leisure', /^(pitch|sports_centre)$/)) c.areasEsporte++;
    if (temTag(t, 'man_made', /^surveillance$/)) c.cameras++;
    if (temTag(t, 'highway', /^bus_stop$/)) c.pontosOnibus++;
    if (temTag(t, 'public_transport', /^station$/) || temTag(t, 'railway', /^(station|subway_entrance|tram_stop)$/)) c.estacoes++;
  });

  return { contagens: c, pontos: pontos };
}

// ------------------------------------------------------------
// INDICE DE CONTEXTO URBANO
// Cada dimensao nasce de contagens reais, normalizadas por uma funcao
// saturante (mais equipamentos = mais contexto, com retorno decrescente).
// Nenhum valor e sorteado: mesma coordenada, mesmo resultado no mesmo dia.
// ------------------------------------------------------------
const NORMALIZACAO = {
  escolas: { k: 8, peso: 0.25 },
  saude: { k: 15, peso: 0.25 },
  farmacias: { k: 15, peso: 0.15 },
  bancos: { k: 12, peso: 0.10 },
  comercios: { k: 120, peso: 0.25 }
};

function saturar(n, k) {
  if (n == null || !isFinite(n)) return null;
  if (n <= 0) return 0;
  return 100 * (1 - Math.exp(-n / k));
}

function mediaPonderada(itens) {
  const validos = itens.filter(function (i) { return i.valor != null; });
  if (!validos.length) return null;
  const somaPeso = validos.reduce(function (a, i) { return a + i.peso; }, 0);
  if (!somaPeso) return null;
  return Math.round(validos.reduce(function (a, i) { return a + i.valor * i.peso; }, 0) / somaPeso);
}

function calcularIndice(c) {
  const servicos = mediaPonderada(Object.keys(NORMALIZACAO).map(function (campo) {
    const def = NORMALIZACAO[campo];
    return { valor: saturar(c[campo], def.k), peso: def.peso };
  }));

  const mobilidade = mediaPonderada([
    { valor: saturar(c.pontosOnibus, 60), peso: 0.7 },
    { valor: saturar(c.estacoes, 3), peso: 0.3 }
  ]);

  const seguranca = mediaPonderada([
    { valor: saturar(c.unidadesPoliciais, 3), peso: 0.75 },
    { valor: saturar(c.bombeiros, 1.5), peso: 0.25 }
  ]);

  const dims = { servicos: servicos, mobilidade: mobilidade, seguranca: seguranca };
  const pesos = { servicos: 0.40, mobilidade: 0.25, seguranca: 0.35 };

  let somaPeso = 0, soma = 0, faltando = 0;
  Object.keys(dims).forEach(function (d) {
    if (dims[d] == null) { faltando++; return; }
    soma += dims[d] * pesos[d];
    somaPeso += pesos[d];
  });

  if (!somaPeso) return { valor: null, faixa: 'Sem dado', dimensoes: dims, parcial: true };

  const valor = Math.round(soma / somaPeso);
  return {
    valor: valor,
    faixa: valor >= 70 ? 'Amplo' : (valor >= 40 ? 'Moderado' : 'Restrito'),
    dimensoes: dims,
    parcial: faltando > 0
  };
}

function dataHoraBR(d) {
  return new Intl.DateTimeFormat('pt-BR', {
    timeZone: 'America/Sao_Paulo',
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  }).format(d);
}

function semDado(motivo) {
  return {
    ok: false,
    raioKm: RAIO_KM,
    fonte: { nome: FONTE.nome, url: FONTE.url, licenca: FONTE.licenca, coletadoEm: null },
    indice: { valor: null, faixa: 'sem dado', dimensoes: { servicos: null, mobilidade: null, seguranca: null }, parcial: true },
    inventario: null,
    pontos: { policia: [], bombeiros: [] },
    aviso: motivo || 'A fonte publica de dados nao respondeu agora. Tente novamente em alguns minutos.',
    semDado: true
  };
}

async function coletar(lat, lng, opcoes) {
  const opts = opcoes || {};
  const km = opts.raioKm || RAIO_KM;
  const agora = Date.now();
  const k = chave(lat, lng);

  if (!opts.forcarAtualizacao) {
    const c = lerCache()[k];
    if (c && c.expiraEm > agora && c.valor) {
      return Object.assign({}, c.valor, { cache: true });
    }
  }

  const res = await coletarElementos(lat, lng);
  if (!res.ok) {
    console.warn('[DADOS] Overpass indisponivel:', (res.falhas || []).join(' | '));
    return semDado();
  }

  const todos = res.elementos.length;
  if (todos < 3) {
    // raio sem equipamentos mapeados: nao da para afirmar nada
    return semDado('Nenhum equipamento urbano mapeado no raio de ' + km + ' km. O resultado fica como "sem dado" em vez de zero.');
  }

  const classificado = classificar(res.elementos);
  const c = classificado.contagens;
  let índice = calcularIndice(c);
  // Indice 0 em area com quase nada mapeado nao e medicao confiavel:
  // vira "sem dado" com explicacao, nunca zero na tela.
  let avisoIndice = null;
  if (índice.valor === 0) {
    avisoIndice = 'Sem cobertura de dados suficiente para calcular o indice neste raio. Nao significa ausencia de recursos — significa ausencia de mapeamento.';
    índice = { valor: null, faixa: 'Sem dado', dimensoes: índice.dimensoes, parcial: true };
  }
  const quando = dataHoraBR(new Date());
  const fonteNome = res.via === 'osm-api' ? 'OpenStreetMap (API oficial)' : FONTE.nome;

  // Cada numero carrega fonte e data. Categorias que o OSM cobre mal
  // (cameras) nunca viram zero: ficam como "sem dado".
  const inventario = {
    escolas: { n: c.escolas, fonte: fonteNome, data: quando, rotulo: 'Escolas e creches' },
    saude: { n: c.saude, fonte: fonteNome, data: quando, rotulo: 'Saude (hospitais, clinicas e consultorios)' },
    farmacias: { n: c.farmacias, fonte: fonteNome, data: quando, rotulo: 'Farmacias' },
    bancos: { n: c.bancos, fonte: fonteNome, data: quando, rotulo: 'Bancos' },
    unidadesPoliciais: { n: c.unidadesPoliciais, fonte: fonteNome, data: quando, rotulo: 'Unidades policiais' },
    bombeiros: { n: c.bombeiros, fonte: fonteNome, data: quando, rotulo: 'Corpos de bombeiros' },
    pontosOnibus: { n: c.pontosOnibus, fonte: fonteNome, data: quando, rotulo: 'Pontos de onibus' },
    estacoes: { n: c.estacoes, fonte: fonteNome, data: quando, rotulo: 'Estacoes de transporte' },
    comercios: { n: c.comercios, fonte: fonteNome, data: quando, rotulo: 'Comercios' },
    parques: { n: c.parques, fonte: fonteNome, data: quando, rotulo: 'Parques e jardins' },
    cameras: { n: null, fonte: null, data: null, rotulo: 'Cameras de vigilancia', nota: 'Nao existe base publica de cameras por endereco; o OpenStreetMap registra poucas.' }
  };

  const coberturaBaixa = todos < 30;

  const valor = {
    ok: true,
    raioKm: km,
    elementos: todos,
    fonte: { nome: fonteNome, url: FONTE.url, licenca: FONTE.licenca, coletadoEm: quando },
    indice: índice,
    inventario: inventario,
    pontos: classificado.pontos,
    coberturaBaixa: coberturaBaixa,
    aviso: avisoIndice || (coberturaBaixa
      ? 'Cobertura do OpenStreetMap baixa neste raio (' + todos + ' elementos mapeados). O indice reflete apenas o que esta mapeado.'
      : null),
    semDado: false
  };

  const mem = lerCache();
  mem[k] = { expiraEm: agora + CACHE_TTL_MS, valor: valor };
  // limpeza simples para o cache nao crescer sem limite
  const chaves = Object.keys(mem);
  if (chaves.length > 500) {
    chaves.slice(0, chaves.length - 500).forEach(function (ck) { delete mem[ck]; });
  }
  gravarCache();

  return valor;
}

module.exports = {
  coletar: coletar,
  RAIO_KM: RAIO_KM,
  FONTE: FONTE,
  // expostos para teste
  _classificar: classificar,
  _calcularIndice: calcularIndice,
  _montarQuery: montarQuery
};
