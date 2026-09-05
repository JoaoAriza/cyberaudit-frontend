import { describe, expect, it } from "vitest";
import { pt, en } from "./catalog";

/**
 * A guarda de paridade do catálogo.
 *
 * O Backend tem esta trava desde que ganhou `messages_en.properties`. Aqui não
 * havia nada: os pares eram conferidos por script avulso, reescrito a cada etapa e
 * jogado fora depois.
 *
 * O que torna o buraco perigoso é o próprio fallback. `traduzir()` resolve chave
 * ausente no português, de propósito — meia tela traduzida ainda é legível. Mas
 * isso significa que **chave sem tradução não quebra nada**: a tela funciona, o
 * texto aparece, e ninguém percebe que apareceu no idioma errado.
 */

const chavesPt = Object.keys(pt).sort();
const chavesEn = Object.keys(en).sort();

/** Letra acentuada não existe em inglês — é português que vazou para o `en`. */
const ACENTO = /[áàâãéèêíìîóòôõúùûüç]/i;

/**
 * Valores legitimamente iguais nos dois idiomas.
 *
 * Sigla, nome próprio e rótulo técnico não têm tradução. Cada entrada aqui é uma
 * afirmação — "esta linha é a mesma nos dois idiomas de propósito" — e não um
 * silenciador de aviso. Antes de somar uma, vale perguntar se o texto realmente
 * não muda em inglês.
 */
const IGUAL_DE_PROPOSITO = new Set<string>([
  // Nomes dos módulos e das sondas — termo de arte, já em inglês na tela em
  // português. Traduzir "Reflected XSS" para "XSS Refletido" afastaria o rótulo do
  // vocabulário que o próprio analista usa.
  "ativo.corsAnalysis",
  "ativo.dbErrorLeak",
  "ativo.inputSurface",
  "ativo.reflectedXss",
  "ativo.reflectsOrigin",
  "ativo.sensitiveFiles",
  "ativo.wafDetection",
  "ativo.wildcardOrigin",
  "ativo.xssSqli",
  "grupo.httpHeaders",
  "apikey.titulo",

  // Títulos de seção e selos: caixa alta em inglês nos dois idiomas, do mesmo jeito
  // que os selos SECURE e VULNERABLE, que nunca foram traduzidos.
  "ativo.tituloCors",
  "ativo.tituloProbes",
  "ativo.tituloWaf",
  "resultado.breakdown",
  "selo.protocoloFraco",

  // Nome de produto de terceiro.
  "config.totpApp",
]);

describe("paridade entre pt e en", () => {
  it("toda chave do português tem tradução em inglês", () => {
    const semTraducao = chavesPt.filter((k) => !(k in en));
    expect(semTraducao, "sem tradução em en").toEqual([]);
  });

  it("o inglês não inventa chave que o português não tenha", () => {
    // Chave só no `en` é quase sempre erro de digitação: a tela lê a chave do
    // português, então a versão em inglês nunca é usada e o texto sai em português.
    const orfas = chavesEn.filter((k) => !(k in pt));
    expect(orfas, "chave existe só em en (provável erro de digitação)").toEqual([]);
  });
});

describe("o inglês é mesmo inglês", () => {
  it("nenhum texto em inglês carrega acento do português", () => {
    // Vazamento silencioso: a chave existe nos dois lados, a paridade passa, e o
    // cliente estrangeiro lê "Configurações" no meio da tela.
    const comAcento = chavesEn
      .filter((k) => ACENTO.test(en[k]))
      .map((k) => `${k} = ${en[k]}`);

    expect(comAcento, "português vazou para o catálogo em inglês").toEqual([]);
  });

  it("frase idêntica nos dois idiomas é decisão declarada, não descuido", () => {
    // Sigla e nome próprio são iguais de propósito — por isso o filtro exige espaço
    // e algum tamanho. Frase inteira repetida é tradução que não aconteceu.
    const copiadas = chavesPt
      .filter((k) => k in en)
      .filter((k) => !IGUAL_DE_PROPOSITO.has(k))
      .filter((k) => pt[k] === en[k])
      .filter((k) => pt[k].includes(" ") && pt[k].length > 12)
      .map((k) => `${k} = ${pt[k]}`);

    expect(copiadas, "cópia do português em en — traduza ou declare em IGUAL_DE_PROPOSITO")
      .toEqual([]);
  });
});

describe("os parâmetros sobrevivem à tradução", () => {
  const marcadores = (texto: string) =>
    [...texto.matchAll(/\{(\d+)\}/g)].map((m) => m[1]).sort();

  it("cada chave usa os mesmos {n} nos dois idiomas", () => {
    // `traduzir()` interpola por posição. Tradução que perde o {0} engole o dado
    // sem erro nenhum — o texto sai completo, só que sem o número, o nome ou a
    // data que ele deveria carregar.
    const divergentes = chavesPt
      .filter((k) => k in en)
      .filter((k) => marcadores(pt[k]).join() !== marcadores(en[k]).join())
      .map((k) => `${k}: pt {${marcadores(pt[k])}} vs en {${marcadores(en[k])}}`);

    expect(divergentes, "os marcadores não batem entre os idiomas").toEqual([]);
  });
});

describe("o catálogo não está vazio por acidente", () => {
  it("nenhum valor é string vazia", () => {
    const vazias = [
      ...chavesPt.filter((k) => !pt[k].trim()).map((k) => `pt: ${k}`),
      ...chavesEn.filter((k) => !en[k].trim()).map((k) => `en: ${k}`),
    ];
    expect(vazias, "valor vazio some da tela sem deixar rastro").toEqual([]);
  });
});
