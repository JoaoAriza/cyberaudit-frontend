import { defineConfig, loadEnv, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

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
    // sdk.mercadopago.com: SDK v2 do checkout transparente (CheckoutModal). Carrega
    // scripts adicionais de http2.mlstatic.com (CDN da MercadoLibre). Os dois hashes
    // cobrem <script>s inline que o próprio SDK injeta pro handshake do Secure Fields —
    // confirmado com uma public key de PRODUÇÃO de verdade em 2026-09-30: sem eles o
    // DevTools acusa "Executing inline script violates..." e o campo de número do
    // cartão fica com o iframe montado mas sem aceitar digitação nenhuma. Apareceram DOIS
    // hashes diferentes em sequência (cada um só aparece no console depois que o anterior
    // já não bloqueia mais) — se a Ionic/MP atualizar o bundle e algum hash não bater mais,
    // o DevTools mostra o hash novo certinho na mensagem de bloqueio, é só trocar aqui. Se
    // isso continuar aparecendo a cada ajuste (sinal de script gerado dinamicamente, não
    // hash estável), considerar 'unsafe-inline' em vez de perseguir hash — mas só depois
    // de confirmar que não tem outra saída, porque isso relaxa a CSP do app inteiro.
    "script-src 'self' https://sdk.mercadopago.com https://http2.mlstatic.com 'sha256-YrbqwkkBIN/ldKH2ZnPl8wvIxqXnaTqKwsOijQhOkUU=' 'sha256-p5HjIQRfHCR1Ff6Itca6Y/9IaQHQUlJdZsIhOrvtm1o='",
    // CSS Modules + <link> do Google Fonts. 'unsafe-inline' cobre o <style> que o
    // Vite embute em builds pequenos; o style={{}} do React passa por CSSOM e não
    // é alcançado por style-src.
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    `img-src 'self' data: blob: ${apiOrigin}`.trim(),
    // Secure Fields (número do cartão/validade/CVV) monta um iframe do domínio do MP —
    // é o que mantém o dado do cartão fora do nosso DOM (SAQ A). Mas antes de montar o
    // iframe, o SDK faz fetch/XHR DIRETO da página (não do iframe, que teria CSP própria)
    // pro handshake em secure-fields.mercadopago.com e pro config em
    // api-static.mercadopago.com/secure-fields — confirmado em produção: sem os dois,
    // o campo de número do cartão renderiza a caixa mas não aceita nenhum caractere.
    `connect-src 'self' ${apiOrigin} https://api.mercadopago.com https://secure-fields.mercadopago.com https://api-static.mercadopago.com`.trim(),
    // secure-fields.mercadopago.com: origem real do iframe que hospeda número/validade/CVV
    // (confirmado em produção — o console acusava "Framing ... violates" sem ele, e o
    // iframe simplesmente não montava).
    "frame-src https://www.mercadopago.com https://api.mercadopago.com https://secure-fields.mercadopago.com",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    'upgrade-insecure-requests',
  ].join('; ')

  // Versão para HEADER: mesma política + frame-ancestors, que é ignorado em
  // <meta> e só vale como header.
  const cspHeader = `${csp}; frame-ancestors 'none'`

  return {
    name: 'cyberaudit-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '<head>',
        `<head>\n    <meta http-equiv="Content-Security-Policy" content="${csp}" />`,
      )
    },

    /**
     * Escreve a política completa também no `_headers`.
     *
     * O arquivo trazia só `frame-ancestors 'none'`, contando com a <meta> para o
     * resto. Só que a <meta> não é visível para quem inspeciona a resposta HTTP:
     * um scanner (o nosso inclusive) lê o header, encontra uma política sem
     * `default-src` nem `script-src` e classifica como fraca — corretamente, já
     * que um cliente que não executa HTML não recebe proteção nenhuma.
     *
     * Gerado aqui, e não escrito à mão no public/_headers, porque a política
     * depende de VITE_API_URL: duplicar levaria os dois a divergirem no primeiro
     * ajuste de origem da API.
     */
    closeBundle() {
      const arquivo = resolve(__dirname, 'dist/_headers')
      if (!existsSync(arquivo)) {
        console.warn('[cyberaudit] dist/_headers não encontrado — CSP não foi para o header.')
        return
      }
      const original = readFileSync(arquivo, 'utf8')
      const atualizado = original.replace(
        /^(\s*)Content-Security-Policy:.*$/m,
        `$1Content-Security-Policy: ${cspHeader}`,
      )
      if (original === atualizado) {
        console.warn('[cyberaudit] nenhuma linha Content-Security-Policy em _headers para substituir.')
        return
      }
      writeFileSync(arquivo, atualizado)
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

/**
 * Aborta o build de produção quando VITE_API_URL não chegou.
 *
 * Sem isto o erro é invisível e sai no ar: o `?? "http://localhost:8081"` do
 * client.ts faz o bundle publicado chamar a máquina de quem abriu o site, e a
 * CSP daqui de cima nasce com `connect-src 'self'` — que bloquearia a API de
 * qualquer jeito. O build passa, o deploy passa, e só o navegador do usuário
 * final descobre. Foi exatamente assim que a produção quebrou: o `.gitignore`
 * cobre `.env.*`, então o `.env.production` não vai para o repositório e o host
 * de build (Cloudflare Pages) compilava sem a variável.
 *
 * Falhar aqui transforma uma quebra silenciosa em produção num build vermelho.
 */
function assertApiUrl(mode: string, url: string | undefined): void {
  if (mode !== 'production') return

  const hint =
    'Defina VITE_API_URL nas variáveis de ambiente do host de build ' +
    '(ex.: Cloudflare Pages → Settings → Environment variables), ' +
    'ou em .env.production para builds locais. Ex.: https://api.cyberauditapp.com'

  if (!url) {
    throw new Error(`[cyberaudit] build de produção sem VITE_API_URL.\n${hint}`)
  }
  if (!apiOriginFrom(url)) {
    throw new Error(
      `[cyberaudit] VITE_API_URL não é uma URL absoluta válida: ${JSON.stringify(url)}.\n${hint}`,
    )
  }

  // localhost também é fatal. O `.env` de desenvolvimento existe em toda máquina
  // e aponta para localhost:8081, então `npm run build` numa estação de trabalho
  // produz um bundle de produção quebrado sem nenhum sinal — o mesmo defeito que
  // foi ao ar, só que por outro caminho. `build && preview` contra um backend
  // local continua possível pela variável de escape abaixo.
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '')
  if (/^(localhost|127\.|::1$|0\.0\.0\.0$)/.test(host)) {
    if (process.env.VITE_ALLOW_LOCAL_API === '1') {
      console.warn(
        `\n[cyberaudit] AVISO: build de produção apontando para ${url} ` +
          '(liberado por VITE_ALLOW_LOCAL_API=1).\nNão publique este bundle.\n',
      )
      return
    }
    throw new Error(
      `[cyberaudit] build de produção apontando para ${url}.\n` +
        'Publicado assim, nenhuma chamada à API funciona: o navegador do usuário ' +
        'chamaria a própria máquina dele.\n' +
        `${hint}\n` +
        'Para gerar um bundle local de propósito (build && preview): VITE_ALLOW_LOCAL_API=1',
    )
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_')
  assertApiUrl(mode, env.VITE_API_URL)
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
