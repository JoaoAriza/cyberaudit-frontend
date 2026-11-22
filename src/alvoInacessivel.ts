/**
 * Alvo que não existe ou não respondeu (BUG-16 do cyberaudit-qa).
 *
 * O Backend recusa esses scans com 422 e um código: `TARGET_NOT_FOUND` (o domínio não
 * resolve no DNS) ou `TARGET_UNREACHABLE` (resolve, mas nada aceitou conexão em http nem
 * em https). Antes o scan saía com nota, e a tela mostrava o laudo de um site que nem
 * existe.
 *
 * O código chega por dois caminhos: no `error` da resposta HTTP (o 422 do POST, quando o
 * domínio não resolve) e no `errorCode` do polling (quando a conexão falha já dentro do
 * scan assíncrono).
 */
export function alvoInacessivel(codigo: string | null | undefined): boolean {
  return codigo === "TARGET_NOT_FOUND" || codigo === "TARGET_UNREACHABLE";
}

/**
 * Texto do aviso. A mensagem do Backend já vem no idioma da tela (o cliente manda o
 * `Accept-Language`) e diz qual dos dois casos foi; o aviso genérico só entra quando ela
 * falta.
 */
export function avisoAlvoInacessivel(mensagem: string | null | undefined, generico: string): string {
  const texto = mensagem?.trim();
  return texto ? `⚠ ${texto}` : generico;
}
