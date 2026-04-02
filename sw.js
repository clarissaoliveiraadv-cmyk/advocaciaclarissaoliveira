// Service Worker — Clarissa Oliveira Advocacia
// Phase 4: cache offline para uso em campo sem internet
const CACHE_NAME = 'co-advocacia-v21';
const ASSETS = [
  './',
  './Escritorio_Clarissa_App_v2 (1).html',
  './styles.css',
  './app.js',
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

// Activate: cleanup old caches
self.addEventListener('activate', function(e){
  e.waitUntil(
    caches.keys().then(function(names){
      return Promise.all(
        names.filter(function(n){ return n !== CACHE_NAME; })
             .map(function(n){ return caches.delete(n); })
      );
    })
  );
  self.clients.claim();
});

// Fetch: network-first for HTML/JS/CSS, cache-first for fonts/assets
self.addEventListener('fetch', function(e){
  var url = new URL(e.request.url);

  // Google Fonts — cache-first (rarely change)
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

  // App files — network-first with cache fallback (always get latest, work offline)
  if(url.origin === self.location.origin){
    e.respondWith(
      fetch(e.request).then(function(resp){
        var clone = resp.clone();
        caches.open(CACHE_NAME).then(function(c){ c.put(e.request, clone); });
        return resp;
      }).catch(function(){
        return caches.match(e.request);
      })
    );
    return;
  }

  // Everything else — network only
  e.respondWith(fetch(e.request));
});
