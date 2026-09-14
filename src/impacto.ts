/**
 * Rótulo de impacto: o que há para perder numa página.
 *
 * Eixo separado do score. A nota diz quão frágil está a configuração; o rótulo diz
 * o que está em jogo — uma vitrine que só leva ao WhatsApp e um checkout podem ter
 * a mesma nota e riscos que não se comparam.
 *
 * O nível vem pronto do Backend (ImpactLabelService). Aqui só mora o que a tela
 * precisa decidir: ordem da escala, agrupamento e a ligação com os módulos.
 */

/** A ordem é a escala: o último é o mais grave. Mesma ordem do enum ImpactLevel. */
export const NIVEIS_IMPACTO = ["SHOWCASE", "CONTACT", "ACCOUNT", "PAYMENT"] as const;
export type NivelImpacto = (typeof NIVEIS_IMPACTO)[number];

/** Um motivo do rótulo. `detail` vem nulo para guest/FREE — é o porquê travado. */
export interface SinalImpacto { source: string; detail: string | null; }

export function ehNivelImpacto(valor: unknown): valor is NivelImpacto {
  return typeof valor === "string" && (NIVEIS_IMPACTO as readonly string[]).includes(valor);
}

/**
 * Posição na escala; -1 para ausente ou desconhecido.
 *
 * Ausente é normal: scan gravado antes do rótulo existir. Ele fica abaixo de
 * VITRINE, e não igual a ela — "não medido" não é "sem nada em risco".
 */
export function pesoImpacto(nivel: string | null | undefined): number {
  return ehNivelImpacto(nivel) ? NIVEIS_IMPACTO.indexOf(nivel) : -1;
}

/** O nível mais grave de uma lista; null quando nenhum tem rótulo. */
export function maiorImpacto(niveis: Iterable<string | null | undefined>): NivelImpacto | null {
  let maior: NivelImpacto | null = null;
  for (const nivel of niveis) {
    if (ehNivelImpacto(nivel) && pesoImpacto(nivel) > pesoImpacto(maior)) maior = nivel;
  }
  return maior;
}

/**
 * Impacto de cada domínio: o MAIOR entre os caminhos escaneados dele.
 *
 * Decisão de produto: a home VITRINE e o /checkout PAGAMENTO fazem do domínio
 * PAGAMENTO. Usar só o último scan faria uma loja cair para VITRINE sempre que a
 * home fosse a última página escaneada — e é esse domínio que o filtro de
 * prospecção precisa fazer subir.
 *
 * Chave sem "www.": o Backend grava o host assim, e a Visão Geral compara por ele.
 */
export function impactoPorDominio(caminhos: { host: string; impact?: string | null }[]): Map<string, NivelImpacto> {
  const porDominio = new Map<string, NivelImpacto>();
  for (const c of caminhos) {
    const host = c.host.replace(/^www\./, "");
    const maior = maiorImpacto([porDominio.get(host), c.impact]);
    if (maior) porDominio.set(host, maior);
  }
  return porDominio;
}

/**
 * Do mais grave para o menos; sem rótulo por último. Empate mantém a ordem
 * recebida — que já vem do mais recente para o mais antigo.
 */
export function ordenarPorImpacto<T>(lista: T[], impactoDe: (item: T) => string | null | undefined): T[] {
  return [...lista].sort((a, b) => pesoImpacto(impactoDe(b)) - pesoImpacto(impactoDe(a)));
}

/**
 * Origens distintas dos sinais, na ordem em que chegaram.
 *
 * É o que o plano gratuito enxerga: EM QUAL módulo a página é sensível, sem o
 * detalhe. Cookie de sessão repetido três vezes vira uma origem só.
 */
export function origensDosSinais(sinais: SinalImpacto[] | null | undefined): string[] {
  return [...new Set((sinais ?? []).map(s => s.source))];
}

/**
 * Módulo da barra lateral que mostra cada origem. FORM e PATH não têm módulo
 * próprio — o que casou ali aparece no próprio rótulo.
 */
export const MODULO_DA_ORIGEM: Readonly<Record<string, string>> = {
  COOKIES: "cookies",
  JWT: "jwt",
  API_DOCS: "apidocs",
  GRAPHQL: "graphql",
};
