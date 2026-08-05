import { defineConfig, loadEnv, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

/**
 * Injeta a CSP como <meta> no index.html — mas SÓ no build.
 *
 * O SPA não tinha CSP nenhuma: nem no HTML, nem em config de host. Como o token
 * JWT mora no localStorage, qualquer XSS levava a sessão junto.
 *
 * Por que só no build: em dev o Vite injeta o preamble do React Fast Refresh
 * inline, que uma CSP com script-src 'self' bloquearia.
 *
 * `frame-ancestors` é ignorado em <meta> — anti-clickjacking depende do header
 * do host (ver vercel.json / public/_headers). Esta meta é o piso que funciona
 * em qualquer host estático, inclusive um nginx sem configuração extra.
 */
function cspPlugin(apiOrigin: string): Plugin {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    // CSS Modules + <link> do Google Fonts. 'unsafe-inline' cobre o <style> que o
    // Vite embute em builds pequenos; o style={{}} do React passa por CSSOM e não
    // é alcançado por style-src.
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    `img-src 'self' data: blob: ${apiOrigin}`.trim(),
    `connect-src 'self' ${apiOrigin}`.trim(),
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    'upgrade-insecure-requests',
  ].join('; ')

  return {
    name: 'cyberaudit-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '<head>',
        `<head>\n    <meta http-equiv="Content-Security-Policy" content="${csp}" />`,
      )
    },
  }
}

/** Origem da API a partir de VITE_API_URL — a CSP precisa liberar connect-src/img-src para ela. */
function apiOriginFrom(url: string | undefined): string {
  if (!url) return ''
  try {
    return new URL(url).origin
  } catch {
    return ''
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_')
  return {
    plugins: [react(), cspPlugin(apiOriginFrom(env.VITE_API_URL))],
    build: {
      // Source maps expõem o código-fonte original em produção — o próprio módulo
      // Source Map do scanner reporta isso como achado. Default do Vite já é false;
      // explícito para não virar `true` num ajuste de performance distraído.
      sourcemap: false,
    },
  }
})
