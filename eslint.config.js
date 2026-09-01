import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    rules: {
      // Sombra de variável, aqui, não é preciosismo de estilo.
      //
      // Na tradução da interface apareceram cinco sombras da função `t` do
      // useI18n — um `.map((t) => …)` onde `t` era o item da lista. Dentro daquele
      // callback, `t("chave")` deixava de ser a tradução e virava uma chamada no
      // item, que quebrava em runtime. Uma delas derrubava o painel de Subdomain
      // Takeover, e o `any` do parâmetro escondia o erro do TypeScript: para o
      // compilador, chamar `any` é legal.
      //
      // A prevenção era um grep manual (`grep -nE '\.map\(\s*\(?t\b'`), que só
      // funciona enquanto alguém lembra de rodar.
      //
      // A regra base é desligada porque a versão do typescript-eslint entende
      // declaração de tipo e enum — a do ESLint acusa falso positivo neles.
      'no-shadow': 'off',
      '@typescript-eslint/no-shadow': 'error',
    },
  },
])
