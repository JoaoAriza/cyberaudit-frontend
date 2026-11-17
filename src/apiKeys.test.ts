import { describe, expect, it } from "vitest";
import type { UserDto } from "./context/AuthContext";
import { painelApiKey, podeCriarApiKey } from "./apiKeys";

/** Usuário como sai do cadastro: sempre OWNER da própria conta. */
function usuario(plan: "FREE" | "PRO" | "ENTERPRISE", type: "INDIVIDUAL" | "COMPANY" = "INDIVIDUAL",
                 extra: Partial<UserDto> = {}): UserDto {
  return {
    id: "u", name: "Teste", email: "teste@exemplo.com", role: "OWNER",
    jobTitle: null, country: null, timezone: null, timezoneManual: false,
    remainingScans: null, dailyLimit: null,
    account: { type, plan } as UserDto["account"],
    ...extra,
  };
}

describe("podeCriarApiKey", () => {
  it("FREE não cria, mesmo sendo OWNER — o papel não decide (BUG-18)", () => {
    // O painel liberava por isAdmin() = OWNER/ADMIN, e todo cadastro é OWNER.
    expect(podeCriarApiKey(usuario("FREE"))).toBe(false);
  });

  it("conta Empresa no FREE não cria — o tipo sai do cadastro", () => {
    expect(podeCriarApiKey(usuario("FREE", "COMPANY"))).toBe(false);
  });

  it("plano pago cria", () => {
    expect(podeCriarApiKey(usuario("PRO"))).toBe(true);
    expect(podeCriarApiKey(usuario("ENTERPRISE", "COMPANY"))).toBe(true);
    expect(podeCriarApiKey(usuario("ENTERPRISE", "COMPANY", { role: "FREE_EMPLOYEE" }))).toBe(true);
  });

  it("equipe da plataforma cria, mesmo com conta FREE", () => {
    expect(podeCriarApiKey(usuario("FREE", "INDIVIDUAL", { platformStaff: true }))).toBe(true);
  });

  it("sem usuário ou sem conta, não cria", () => {
    expect(podeCriarApiKey(null)).toBe(false);
    expect(podeCriarApiKey({ ...usuario("PRO"), account: null })).toBe(false);
  });
});

describe("painelApiKey", () => {
  it("quem pode criar vê o painel completo", () => {
    expect(painelApiKey(true, [], false)).toBe("completo");
  });

  it("FREE com chave ativa antiga vê a lista, para poder revogar", () => {
    // A chave continua valendo (decisão do dono no BUG-18); escondê-la deixaria uma
    // credencial viva que o dono da conta não consegue revogar pela tela.
    expect(painelApiKey(false, [{ active: true }], false)).toBe("so-lista");
  });

  it("FREE sem chave ativa vê o cartão travado", () => {
    expect(painelApiKey(false, [], false)).toBe("travado");
    expect(painelApiKey(false, [{ active: false }], false)).toBe("travado");
  });

  it("enquanto carrega, quem não pode criar vê o travado — sem piscar o painel", () => {
    expect(painelApiKey(false, [{ active: true }], true)).toBe("travado");
  });
});
