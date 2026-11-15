/**
 * Política DMARC para o card do módulo DNS: o `p=` do registro, com o `pct=` quando ele
 * não é 100.
 *
 * O Backend manda em `dmarcPolicy` o NÍVEL que ele atribuiu à política (STRONG, MEDIUM,
 * WEAK), não a política. O card escrevia `p=${dmarcPolicy}` e saía "p=medium" — valor que
 * não existe no DMARC, e que o dono do domínio procura no próprio registro sem achar.
 *
 * O `pct` aparece porque muda a leitura: `p=quarantine; pct=50` não é quarantine aplicado
 * (o Backend dá MEDIUM, ver BUG-10). Ausente ou inválido vale 100 (RFC 7489 §6.3) e não
 * aparece.
 */
export function politicaDmarc(registro: string | null | undefined): string | null {
  if (!registro) return null;
  // Ancorado no início ou num ";": "sp=" (política de subdomínio) não é "p=".
  const p = /(?:^|;)\s*p\s*=\s*([^;\s]+)/i.exec(registro);
  if (!p) return null;
  const politica = `p=${p[1].toLowerCase()}`;

  const pct = /(?:^|;)\s*pct\s*=\s*([^;\s]+)/i.exec(registro);
  const n = pct ? Number(pct[1]) : NaN;
  return Number.isInteger(n) && n >= 0 && n < 100 ? `${politica}; pct=${n}` : politica;
}
