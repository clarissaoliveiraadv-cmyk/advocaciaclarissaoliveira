// Service Worker — Clarissa Oliveira Advocacia
// Phase 4: cache offline para uso em campo sem internet
// IMPORTANTE: bumpar CACHE_NAME sempre que bundle.js/styles.css mudarem.
// Versão atual precisa bater (ou ser maior que) o ?v= no index.html.
const CACHE_NAME = 'co-advocacia-v73';
const ASSETS = [
  './',
  './index.html',
  './styles.css?v=60',
  './bundle.js?v=73',
  './manifest.json'
];

// Install: pre-cache assets
self.addEventListener('install', function(e){
  e.waitUntil(
    caches.open(CACHE_NAME).then(function(cache){
      return cache.addAll(ASSETS);
    })
  );
  self.skipWaiting();
});

// Permitir que a página force o SW a ativar imediatamente (via postMessage)
self.addEventListener('message', function(e){
  if(e.data && e.data.type==='SKIP_WAITING'){ self.skipWaiting(); }
});

// Activate: cleanup old caches + tomar controle imediato das abas abertas
self.addEventListener('activate', function(e){
  e.waitUntil(
    caches.keys().then(function(names){
      return Promise.all(
        names.filter(function(n){ return n !== CACHE_NAME; })
             .map(function(n){ return caches.delete(n); })
      );
    }).then(function(){
      return self.clients.claim();
    }).then(function(){
      // Notificar todas as abas abertas que um SW novo assumiu o controle
      return self.clients.matchAll({includeUncontrolled:true}).then(function(clients){
        clients.forEach(function(c){
          try{ c.postMessage({type:'SW_UPDATED', version:CACHE_NAME}); }catch(e){}
        });
      });
    })
  );
});

// Fetch: NETWORK-FIRST agressivo para HTML/JS/CSS (sempre pega última versão
// se online), cache-first apenas para fontes e assets estáticos.
self.addEventListener('fetch', function(e){
  var url = new URL(e.request.url);

  // Google Fonts — cache-first (raramente mudam)
  if(url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com'){
    e.respondWith(
      caches.match(e.request).then(function(cached){
        return cached || fetch(e.request).then(function(resp){
          var clone = resp.clone();
          caches.open(CACHE_NAME).then(function(c){ c.put(e.request, clone); });
          return resp;
        });
      })
    );
    return;
  }

  // App files — network-first com fallback ao cache (offline ainda funciona)
  if(url.origin === self.location.origin){
    e.respondWith(
      fetch(e.request, {cache:'no-store'}).then(function(resp){
        // Só cachear respostas OK (evita cachear 500/404)
        if(resp && resp.ok){
          var clone = resp.clone();
          caches.open(CACHE_NAME).then(function(c){ c.put(e.request, clone); });
        }
        return resp;
      }).catch(function(){
        return caches.match(e.request);
      })
    );
    return;
  }

  // Qualquer outra coisa — network only (Supabase, APIs externas)
  e.respondWith(fetch(e.request));
});
