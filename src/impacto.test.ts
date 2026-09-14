import { describe, expect, it } from "vitest";
import {
  ehNivelImpacto, impactoPorDominio, maiorImpacto, ordenarPorImpacto, origensDosSinais, pesoImpacto,
} from "./impacto";

describe("impactoPorDominio", () => {
  it("o domínio leva o MAIOR impacto entre os caminhos, não o do último scan", () => {
    // A lista vem do mais recente para o mais antigo: a home foi escaneada por
    // último, mas o /checkout do mesmo domínio é que define o que está em jogo.
    const m = impactoPorDominio([
      { host: "loja.com.br", impact: "SHOWCASE" },
      { host: "loja.com.br", impact: "PAYMENT" },
      { host: "loja.com.br", impact: "CONTACT" },
    ]);
    expect(m.get("loja.com.br")).toBe("PAYMENT");
  });

  it("junta www e sem www no mesmo domínio", () => {
    const m = impactoPorDominio([
      { host: "www.loja.com.br", impact: "ACCOUNT" },
      { host: "loja.com.br", impact: "CONTACT" },
    ]);
    expect(m.get("loja.com.br")).toBe("ACCOUNT");
    expect(m.has("www.loja.com.br")).toBe(false);
  });

  it("domínio só com scans antigos, sem rótulo, fica fora do mapa", () => {
    expect(impactoPorDominio([{ host: "antigo.com.br", impact: null }]).has("antigo.com.br")).toBe(false);
  });
});

describe("maiorImpacto e ordenarPorImpacto", () => {
  it("ignora ausentes e desconhecidos", () => {
    expect(maiorImpacto([null, "CONTACT", "XYZ", undefined])).toBe("CONTACT");
    expect(maiorImpacto([null, undefined])).toBeNull();
  });

  it("ordena do mais grave para o menos, sem rótulo por último, e o empate mantém a ordem", () => {
    const lista = [
      { id: "a", impact: "CONTACT" },
      { id: "b", impact: null },
      { id: "c", impact: "PAYMENT" },
      { id: "d", impact: "CONTACT" },
    ];
    expect(ordenarPorImpacto(lista, x => x.impact).map(x => x.id)).toEqual(["c", "a", "d", "b"]);
  });
});

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
