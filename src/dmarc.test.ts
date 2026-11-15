import { describe, expect, it } from "vitest";
import { politicaDmarc } from "./dmarc";

describe("politicaDmarc", () => {
  it("mostra a política do registro, não o nível que o Backend atribuiu", () => {
    // O card dizia "p=medium" para este registro.
    expect(politicaDmarc("v=DMARC1; p=quarantine; rua=mailto:dmarc@exemplo.com.br")).toBe("p=quarantine");
    expect(politicaDmarc("v=DMARC1; p=reject")).toBe("p=reject");
    expect(politicaDmarc("v=DMARC1; p=none")).toBe("p=none");
  });

  it("aceita caixa e espaço em volta do =", () => {
    expect(politicaDmarc("v=DMARC1;P = Reject")).toBe("p=reject");
  });

  it("não confunde sp= (subdomínio) com p=", () => {
    expect(politicaDmarc("v=DMARC1; sp=none; p=reject")).toBe("p=reject");
    expect(politicaDmarc("v=DMARC1; sp=none")).toBeNull();
  });

  it("mostra o pct só quando ele é menor que 100", () => {
    expect(politicaDmarc("v=DMARC1; p=quarantine; pct=50")).toBe("p=quarantine; pct=50");
    expect(politicaDmarc("v=DMARC1; p=reject; pct=25")).toBe("p=reject; pct=25");
    expect(politicaDmarc("v=DMARC1; p=reject; pct=100")).toBe("p=reject");
  });

  it("pct inválido vale 100 e não aparece (RFC 7489 §6.3)", () => {
    expect(politicaDmarc("v=DMARC1; p=quarantine; pct=abc")).toBe("p=quarantine");
    expect(politicaDmarc("v=DMARC1; p=quarantine; pct=50.5")).toBe("p=quarantine");
  });

  it("sem registro ou sem p=, devolve nulo — o card usa o que tiver", () => {
    expect(politicaDmarc(null)).toBeNull();
    expect(politicaDmarc(undefined)).toBeNull();
    expect(politicaDmarc("")).toBeNull();
    expect(politicaDmarc("v=DMARC1; rua=mailto:x@y")).toBeNull();
  });
});
