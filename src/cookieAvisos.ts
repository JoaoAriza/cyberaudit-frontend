// Avisos explicativos do card de cookie (BUG-13).
//
// O Backend decide o que está errado em cada cookie e manda o veredito em `problems`,
// com os códigos do catálogo. A tela só desenha. Antes ela refazia a conta pelas flags
// e errava de três jeitos: procurava SameSite vazio (o Backend grava "MISSING", então o
// aviso nunca aparecia), avisava SameSite=None mesmo com Secure, e cobrava HttpOnly do
// token CSRF, que existe para o JavaScript ler.

export type AvisoCookie = "httpOnly" | "secure" | "sameSite";

export interface CookieParaAviso {
  httpOnly: boolean;
  secure: boolean;
  sameSite?: string | null;
  problems?: string[] | null;
}

/** Os avisos do card, na ordem em que a tela mostra. */
export function avisosDoCookie(c: CookieParaAviso): AvisoCookie[] {
  const avisos: AvisoCookie[] = [];
  if (Array.isArray(c.problems)) {
    const p = c.problems;
    if (p.includes("COOKIE_SEM_HTTPONLY")) avisos.push("httpOnly");
    if (p.includes("COOKIE_SEM_SECURE")) avisos.push("secure");
    if (p.includes("COOKIE_SEM_SAMESITE") || p.includes("COOKIE_SAMESITE_NONE_SEM_SECURE")) {
      avisos.push("sameSite");
    }
    return avisos;
  }
  // Scan gravado no histórico antes de o campo existir: a regra das flags, com o
  // "MISSING" que o Backend grava. Sem o código, não dá para saber se é token CSRF.
  if (!c.httpOnly) avisos.push("httpOnly");
  if (!c.secure) avisos.push("secure");
  const ss = c.sameSite;
  if (!ss || ss === "MISSING" || (ss === "None" && !c.secure)) avisos.push("sameSite");
  return avisos;
}
