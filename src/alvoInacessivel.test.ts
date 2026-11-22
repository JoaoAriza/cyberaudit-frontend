import { describe, expect, it } from "vitest";
import { alvoInacessivel, avisoAlvoInacessivel } from "./alvoInacessivel";

describe("alvoInacessivel", () => {
  it("reconhece os dois códigos do alvo inacessível (BUG-16)", () => {
    expect(alvoInacessivel("TARGET_NOT_FOUND")).toBe(true);
    expect(alvoInacessivel("TARGET_UNREACHABLE")).toBe(true);
  });

  it("outros códigos seguem o caminho deles", () => {
    // A posse tem cartão próprio; o bloqueio de SSRF mostra a mensagem do Backend.
    expect(alvoInacessivel("OWNERSHIP_REQUIRED")).toBe(false);
    expect(alvoInacessivel("DOMAIN_BLOCKED")).toBe(false);
  });

  it("sem código não é alvo inacessível", () => {
    expect(alvoInacessivel(null)).toBe(false);
    expect(alvoInacessivel(undefined)).toBe(false);
    expect(alvoInacessivel("")).toBe(false);
  });
});

describe("avisoAlvoInacessivel", () => {
  const generico = "⚠ Domínio não encontrado ou inacessível: \"x\".";

  it("usa a mensagem do Backend, que diz qual dos dois casos foi", () => {
    expect(avisoAlvoInacessivel("O site x não respondeu.", generico))
      .toBe("⚠ O site x não respondeu.");
  });

  it("sem mensagem, cai no aviso genérico", () => {
    expect(avisoAlvoInacessivel(null, generico)).toBe(generico);
    expect(avisoAlvoInacessivel(undefined, generico)).toBe(generico);
    expect(avisoAlvoInacessivel("   ", generico)).toBe(generico);
  });
});
