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

/**
 * Familia de uma URL digitada no formulario — que pode vir com esquema, caminho
 * e porta ("https://www.site.com:8443/login"). Serve para abrir o grupo certo
 * logo depois de agendar, sem esperar o servidor devolver o host limpo.
 */
export function familiaDaUrl(url: string): string {
  const semEsquema = url.trim().replace(/^https?:\/\//i, "");
  const host = semEsquema.split(/[/?#]/)[0].split(":")[0];
  return chaveDaFamilia(host);
}

/**
 * Separa dominio e caminho de uma URL digitada ("https://site.com/login?x=1").
 *
 * Caminho nulo quando so o dominio foi digitado — quem chama decide o padrao
 * (a aba de analise escolhe a raiz, ou o caminho mais recente se nao houver raiz).
 * Barra final e query nao entram, igual a normalizacao do backend
 * (ScanHistoryService.normalizarCaminho).
 */
export function separarUrl(url: string): { host: string; path: string | null } {
  const semEsquema = url.trim().replace(/^https?:\/\//i, "");
  const corte = semEsquema.search(/[/?#]/);
  const host = (corte >= 0 ? semEsquema.slice(0, corte) : semEsquema).split(":")[0].toLowerCase();
  if (corte < 0 || semEsquema[corte] !== "/") return { host, path: null };
  const bruto = semEsquema.slice(corte).split(/[?#]/)[0];
  const path = bruto.length > 1 ? bruto.replace(/\/+$/, "") : "/";
  return { host, path: path || "/" };
}
