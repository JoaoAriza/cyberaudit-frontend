/**
 * Catálogo de textos da interface.
 *
 * Espelha o messages.properties do Backend de propósito: mesma forma de chave
 * (`tela.elemento`), mesmos parâmetros `{0}`. Quem mexe nos dois lados não troca
 * de modelo mental no meio do caminho.
 *
 * Sem biblioteca de i18n: com dois idiomas e interpolação posicional, uma `t()`
 * de vinte linhas resolve o mesmo que react-i18next cobrando configuração e
 * bundle. É a mesma escolha do AuthContext, feito à mão pelo mesmo motivo.
 *
 * FORA DO ESCOPO por decisão: Termos de Uso e Política de Privacidade continuam
 * só em português. São documento jurídico — a política responde à LGPD, e uma
 * versão em inglês passaria a valer para quem a lê em inglês. Traduzir aquilo é
 * trabalho de advogado, não de quem escreve rótulo de botão.
 */

export type Lang = "pt-BR" | "en";

export const IDIOMA_PADRAO: Lang = "pt-BR";

/** Ordem é a que aparece no seletor. */
export const IDIOMAS: { code: Lang; label: string; short: string }[] = [
  { code: "pt-BR", label: "Português", short: "PT" },
  { code: "en",    label: "English",   short: "EN" },
];

const CHAVE_ARMAZENADA = "cyberaudit.lang";

/**
 * Preferência de idioma, na ordem: escolha salva → idioma do navegador → português.
 *
 * Mora aqui, e não no I18nContext, porque quem mais precisa dela é o cliente HTTP
 * — que vive fora do React. O interceptor lê a cada requisição, do mesmo jeito que
 * já lê o token. Guardar uma cópia em memória sincronizada com o provider daria
 * duas fontes para a mesma verdade, e elas divergiriam na primeira aba aberta em
 * paralelo.
 */
export function idiomaAtual(): Lang {
  const salvo = localStorage.getItem(CHAVE_ARMAZENADA);
  if (salvo && IDIOMAS.some(i => i.code === salvo)) return salvo as Lang;

  // Casa por IDIOMA, não por locale completo: en-GB recebe inglês em vez de cair
  // no português por causa da região. Mesma regra do LocaleConfig no Backend.
  const doNavegador = navigator.language?.split("-")[0];
  const suportado = IDIOMAS.find(i => i.code.split("-")[0] === doNavegador);
  return suportado ? suportado.code : IDIOMA_PADRAO;
}

export function salvarIdioma(lang: Lang) {
  localStorage.setItem(CHAVE_ARMAZENADA, lang);
}

export type Catalogo = Record<string, string>;

/**
 * Português é a base e também o fallback: chave sem tradução em outro idioma cai
 * aqui, igual ao Backend. Meia tela traduzida ainda é legível; texto vazio, não.
 */
export const pt: Catalogo = {
  "idioma.seletor": "Idioma",
  "idioma.mudarPara": "Mudar para {0}",
};

export const en: Catalogo = {
  "idioma.seletor": "Language",
  "idioma.mudarPara": "Switch to {0}",
};

const CATALOGOS: Record<Lang, Catalogo> = { "pt-BR": pt, en };

/**
 * Resolve a chave no idioma pedido.
 *
 * Chave inexistente devolve a própria chave, que aparece feia na tela. É o mesmo
 * princípio do id cru no cardápio e da chave crua no laudo: texto novo sem
 * tradução salta aos olhos em vez de sumir.
 */
export function traduzir(lang: Lang, chave: string, ...args: unknown[]): string {
  const texto = CATALOGOS[lang]?.[chave] ?? pt[chave] ?? chave;
  if (args.length === 0) return texto;
  return texto.replace(/\{(\d+)\}/g, (marca, i) => {
    const valor = args[Number(i)];
    return valor === undefined ? marca : String(valor);
  });
}
