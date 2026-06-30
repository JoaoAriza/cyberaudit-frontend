# CyberAudit — Frontend (cyberaudit-ui)

SPA (dashboard) do **CyberAudit** — consome a API de auditoria de segurança e apresenta
nota, issues, detalhamento por módulo, histórico, agendamentos e relatórios.

> React 19 · TypeScript · Vite 7. Consome o backend Spring Boot (`Seg_site`).

---

## Índice
- [Stack](#stack)
- [Como rodar](#como-rodar)
- [Variáveis de ambiente](#variáveis-de-ambiente)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Telas](#telas)
- [Como conversa com o backend](#como-conversa-com-o-backend)
- [Convenções de cor / score](#convenções-de-cor--score)
- [Build e deploy](#build-e-deploy)
- [Notas / dívidas conhecidas](#notas--dívidas-conhecidas)

---

## Stack

| Função | Lib |
|---|---|
| UI | React 19 + React DOM |
| Build / dev | Vite 7 |
| Linguagem | TypeScript 5.9 |
| HTTP | axios (cliente único em `src/api/client.ts`) |
| Data fetching | @tanstack/react-query |
| Formulários | react-hook-form + zod (`@hookform/resolvers`) |
| Gráficos | recharts (ex: histórico de score) |
| Estilo | CSS Modules (`App.module.css`) + variáveis globais (`index.css`) |
| Lint | ESLint 9 + typescript-eslint |

---

## Como rodar

```bash
npm install
npm run dev        # http://localhost:5173
```

O backend precisa estar de pé (por padrão em `http://localhost:8081`) e com essa origem
liberada no CORS (`ALLOWED_ORIGINS` do backend).

Scripts:

```bash
npm run dev        # servidor de desenvolvimento (HMR)
npm run build      # tsc -b && vite build  → gera dist/
npm run preview    # serve o build de produção localmente
npm run lint       # ESLint
```

---

## Variáveis de ambiente

Vite expõe variáveis prefixadas com `VITE_`. Crie um `.env` (ou `.env.local`):

```env
# URL base da API. Sem isso, cai no default http://localhost:8081
VITE_API_URL=http://localhost:8081
```

Em produção, aponte para o domínio da API, ex: `VITE_API_URL=https://api.seudominio.com.br`.
O valor é lido **em tempo de build** (`import.meta.env.VITE_API_URL`).

---

## Estrutura do projeto

```
src/
├── main.tsx              entry point (monta o React)
├── App.tsx               ⚠️ monolito (~6k linhas): tipos, componentes e todas as telas
├── api/client.ts         axios pré-configurado (baseURL + token JWT + interceptors)
├── context/AuthContext.tsx   estado de autenticação
├── App.module.css        estilos (CSS Modules)
└── index.css             reset + variáveis CSS globais (cores, fontes, --radius…)
```

> **Heads-up:** `App.tsx` concentra praticamente toda a UI (interfaces de tipo,
> componentes e telas num arquivo só). É a maior dívida técnica do projeto — um bom
> primeiro refactor seria quebrar por feature (`components/`, `views/`, `types/`).

---

## Telas

Acessadas pela barra de navegação (`view`/`openModule` em `App.tsx`):

| Tela | O que mostra |
|---|---|
| **Scanner** | Input de URL + modo ACTIVE/EMAIL, gauge de score, breakdown, distribuição de severidade, painéis por módulo (Security Headers, Transport, DNS, etc.), export PDF. |
| **Admin** | Gestão administrativa (usuários, etc.). |
| **Agendamentos** | Scans recorrentes por domínio (frequência, próximo/último scan, pausar/remover). |
| **Domínios** | Domínios da conta e verificação de propriedade. |
| **Histórico** | Mudanças entre scans, visão por domínio, análise de score. |
| **Segurança** | Configurações de segurança da conta (2FA, etc.). |

O painel **Security Headers** mostra também os **hosts relacionados** (`api.`, `server.`,
`www.`) com a postura de headers de cada um — informativo, esclarece que outros hosts do
mesmo site podem ter configuração diferente do host escaneado.

---

## Como conversa com o backend

- **Cliente único:** `src/api/client.ts` cria um axios com `baseURL = VITE_API_URL`.
- **Token JWT:** guardado em `localStorage` sob a chave `cyberaudit.token`. Um interceptor
  injeta `Authorization: Bearer <token>` em todo request.
- **Logout automático:** resposta `401` limpa o token e dispara o evento `auth:logout`
  (o `AuthContext` reage e desloga).
- **Sem `/api` na frente:** as rotas batem direto nos endpoints do backend
  (`/scan`, `/scheduled-scans`, `/badge/{host}`, …).

---

## Convenções de cor / score

A cor do score reflete o **nível de risco** (o veredito), não só o número cru — consistente
entre o gauge do Scanner e a barra do Histórico:

| Nível | Cor |
|---|---|
| SECURE | verde (`--secure`) |
| LOW | azul (`--info`) |
| MEDIUM | laranja (`--warning`) |
| HIGH | laranja-forte (`--high`) |
| CRITICAL | vermelho (`--critical`) |

> Por isso um site com nota 83 mas com uma issue HIGH aparece **MEDIUM/laranja** (e não
> azul): o backend aplica um *severity override* e a UI segue o risco, não o número.

---

## Build e deploy

```bash
VITE_API_URL=https://api.seudominio.com.br npm run build   # → dist/
```

O `dist/` é estático e pode ser servido por qualquer CDN/host estático (Vercel, Cloudflare
Pages, Netlify) ou por um reverse proxy (Caddy/nginx) no mesmo VPS do backend. Para SPA,
configure **fallback para `index.html`** (rotas client-side).

Arquitetura recomendada (dois subdomínios):
- `app.seudominio.com.br` → este SPA (estático)
- `api.seudominio.com.br` → backend (reverse proxy)

---

## Notas / dívidas conhecidas

- **`App.tsx` é um monolito** — candidato número 1 a refactor por feature.
- **`VITE_API_URL` é build-time** — trocar de ambiente exige novo build.
- **Sem testes automatizados** de UI no momento.
