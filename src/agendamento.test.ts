import { describe, expect, it } from "vitest";
import { agruparFamilias } from "./agendamento";

describe("agruparFamilias", () => {
  it("junta www e sem www na mesma familia", () => {
    const grupos = agruparFamilias([
      { host: "www.linkedin.com", path: "/in/joaoariza" },
      { host: "linkedin.com", path: null },
    ]);
    expect(grupos).toHaveLength(1);
    expect(grupos[0][0]).toBe("linkedin.com");
    expect(grupos[0][1]).toHaveLength(2);
  });

  it("poe a raiz primeiro e os caminhos em ordem alfabetica", () => {
    const [[, grupo]] = agruparFamilias([
      { host: "site.com", path: "/zeta" },
      { host: "site.com", path: "/alfa" },
      { host: "site.com", path: "/" },
    ]);
    expect(grupo.map(a => a.path)).toEqual(["/", "/alfa", "/zeta"]);
  });

  it("mantem dominios diferentes em familias diferentes, na ordem em que chegaram", () => {
    const grupos = agruparFamilias([
      { host: "google.com", path: null },
      { host: "linkedin.com", path: null },
      { host: "www.google.com", path: "/maps" },
    ]);
    expect(grupos.map(([f]) => f)).toEqual(["google.com", "linkedin.com"]);
  });

  it("nao confunde dominio que so comeca parecido", () => {
    const grupos = agruparFamilias([
      { host: "www.site.com", path: null },
      { host: "wwwsite.com", path: null },
    ]);
    expect(grupos).toHaveLength(2);
  });
});
