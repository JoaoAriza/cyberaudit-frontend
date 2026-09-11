/**
 * Agrupamento de agendamentos por familia de URL.
 *
 * Familia = dominio sem "www.", a mesma regra do historico e do backend
 * (ScheduledScanService.mesmaFamilia): www.linkedin.com e linkedin.com sao o
 * mesmo site. Dentro da familia a raiz vem primeiro e os caminhos seguem em
 * ordem alfabetica, para a pagina principal ficar sempre no topo do grupo.
 *
 * Fica fora do App.tsx para poder ser testada sem montar a tela.
 */
export interface AgendamentoDaFamilia {
  host: string;
  path: string | null;
}

export function chaveDaFamilia(host: string): string {
  return host.replace(/^www\./i, "").toLowerCase();
}

export function ehRaiz(a: AgendamentoDaFamilia): boolean {
  return !a.path || a.path === "/";
}

export function agruparFamilias<T extends AgendamentoDaFamilia>(lista: T[]): [string, T[]][] {
  const m = new Map<string, T[]>();
  for (const a of lista) {
    const chave = chaveDaFamilia(a.host);
    m.set(chave, [...(m.get(chave) ?? []), a]);
  }
  for (const grupo of m.values()) {
    grupo.sort((a, b) =>
      ehRaiz(a) && !ehRaiz(b) ? -1 :
      ehRaiz(b) && !ehRaiz(a) ? 1 :
      (a.path ?? "").localeCompare(b.path ?? ""));
  }
  return Array.from(m.entries());
}
