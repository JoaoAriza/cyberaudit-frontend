# Dockerfile só para o ambiente de teste do cyberaudit-qa (env/docker-compose.test.yml).
# O deploy de produção real é Cloudflare Pages — ver Frontend/HANDOFF ou README.

# ── build ─────────────────────────────────────────────────────────────────────
FROM node:22-alpine AS build
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
# VITE_API_URL aqui é "http://localhost:8081" de propósito — quem chama essa URL
# é o NAVEGADOR rodando no host (Cypress/Selenium/você), fora da rede do Docker,
# então tem que ser a porta publicada, não o nome do serviço "backend" (que só
# resolve entre containers). vite.config.ts trata build de produção apontando
# pra localhost como o erro clássico de esquecer VITE_API_URL — aqui é
# intencional, daí o escape hatch documentado nele mesmo.
ARG VITE_API_URL
ENV VITE_API_URL=${VITE_API_URL}
ENV VITE_ALLOW_LOCAL_API=1
RUN npm run build

# ── runtime ───────────────────────────────────────────────────────────────────
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.test.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD wget -qO- http://127.0.0.1:80/ || exit 1
