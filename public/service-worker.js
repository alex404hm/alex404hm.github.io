const CACHE_NAME = 'my-site-cache-v1';
const urlsToCache = [
  '/',
  '/index.html',
  '/styles.css',
  '/offline.html',
  '/script.js',
];

// Installer Service Worker
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('Åbner cache og gemmer filer');
      return cache.addAll(urlsToCache);
    })
  );
});

// Aktivér Service Worker og ryd gammel cache
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            console.log('Sletter gammel cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// Håndtér fetch-forespørgsler
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      // Returnér cache, hvis tilgængelig, ellers fetch
      return response || fetch(event.request).catch(() => {
        // Hvis der ikke er internet, returnér offline-side
        return caches.match('/offline.html');
      });
    })
  );
});
