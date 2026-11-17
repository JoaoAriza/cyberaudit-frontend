import type { UserDto } from "./context/AuthContext";

/**
 * Quem pode CRIAR API key — a mesma regra do `ApiKeyService.checkApiKeyAccess` no
 * Backend: plano pago (PRO ou ENTERPRISE) ou equipe da plataforma.
 *
 * Não olha o papel: todo cadastro é OWNER da própria conta, e o `isAdmin()` que estava
 * aqui liberava o painel para qualquer conta FREE (BUG-18). Nem o tipo da conta: "Empresa"
 * se escolhe no cadastro, inclusive no FREE.
 */
export function podeCriarApiKey(user: UserDto | null | undefined): boolean {
  if (!user) return false;
  if (user.platformStaff === true) return true;
  const plano = user.account?.plan;
  return plano === "PRO" || plano === "ENTERPRISE";
}

/**
 * O que o painel de API keys mostra.
 *
 * - `completo`: formulário de nova chave + lista.
 * - `so-lista`: conta sem direito a criar, mas com chave ativa (criada quando o plano
 *   permitia). A chave continua valendo — decisão do dono no BUG-18 —, então ela precisa
 *   aparecer para poder ser revogada; só o formulário some.
 * - `travado`: sem direito e sem chave ativa — o cartão "disponível no PRO".
 *
 * Enquanto carrega, quem não pode criar vê o cartão travado, para não piscar o painel.
 */
export type PainelApiKey = "completo" | "so-lista" | "travado";

export function painelApiKey(
  podeCriar: boolean,
  chaves: ReadonlyArray<{ active: boolean }>,
  carregando: boolean,
): PainelApiKey {
  if (podeCriar) return "completo";
  if (!carregando && chaves.some(k => k.active)) return "so-lista";
  return "travado";
}
