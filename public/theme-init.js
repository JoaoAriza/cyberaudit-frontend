// Aplica o tema salvo (ou o do sistema) ANTES do paint, evitando flash.
//
// Vive em public/ em vez de inline no index.html para que a CSP possa usar
// script-src 'self' — com o script inline, a única alternativa seria
// 'unsafe-inline', que anula boa parte da proteção contra XSS (e o token JWT
// mora no localStorage). Script clássico no <head> é render-blocking, então
// roda antes do primeiro paint igual à versão inline.
(function () {
  try {
    var t = localStorage.getItem('cyberaudit.theme');
    if (t !== 'light' && t !== 'dark') {
      t = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
    }
    document.documentElement.setAttribute('data-theme', t);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
})();
