import { describe, expect, it } from "vitest";
import { ehNivelImpacto, origensDosSinais, pesoImpacto } from "./impacto";

describe("pesoImpacto", () => {
  it("segue a escala do Backend, do menos para o mais grave", () => {
    expect(["SHOWCASE", "CONTACT", "ACCOUNT", "PAYMENT"].map(pesoImpacto)).toEqual([0, 1, 2, 3]);
  });

  it("scan sem rótulo fica abaixo de vitrine, não igual a ela", () => {
    // Laudo anterior ao rótulo não mediu formulário: tratá-lo como VITRINE
    // rebaixaria um checkout só por ter sido escaneado cedo.
    expect(pesoImpacto(null)).toBeLessThan(pesoImpacto("SHOWCASE"));
    expect(pesoImpacto(undefined)).toBe(-1);
  });

  it("valor desconhecido não entra na escala", () => {
    expect(pesoImpacto("CRITICAL")).toBe(-1);
    expect(ehNivelImpacto("payment")).toBe(false);
  });
});

describe("origensDosSinais", () => {
  it("devolve cada origem uma vez, na ordem em que chegou", () => {
    expect(origensDosSinais([
      { source: "FORM", detail: null },
      { source: "COOKIES", detail: null },
      { source: "COOKIES", detail: null },
    ])).toEqual(["FORM", "COOKIES"]);
  });

  it("resultado antigo, sem sinais, não quebra", () => {
    expect(origensDosSinais(undefined)).toEqual([]);
  });
});
