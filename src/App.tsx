import { useMemo, useRef, useState } from "react";
import styles from "./App.module.css";
import { api } from "./api/client";

type ScanResult = any;
type HistoryItem = {
  id: string;
  createdAt: string;
  url: string;
  active: boolean;
  score: number | null;
  riskLevel: string | null;
  httpStatus: number | null;
  finalUrl: string | null;
  result: ScanResult;
};

const HISTORY_KEY = "cyberaudit.history.v1";
const HISTORY_LIMIT = 20;

function loadHistory(): HistoryItem[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveHistory(items: HistoryItem[]) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, HISTORY_LIMIT)));
}

function makeId() {
  return `${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

function downloadBlob(blob: Blob, filename: string) {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

function riskBadgeClass(level?: string) {
  if (level === "SECURE") return styles.badgeSecure;
  if (level === "WARNING") return styles.badgeWarn;
  if (level === "CRITICAL") return styles.badgeCrit;
  return "";
}

function sevClass(sev?: string) {
  const s = (sev ?? "").toUpperCase();
  if (s.includes("HIGH")) return styles.sevHIGH;
  if (s.includes("MEDIUM")) return styles.sevMEDIUM;
  if (s.includes("LOW")) return styles.sevLOW;
  return styles.sevINFO;
}

function PortRow({ p }: { p: any }) {
  return (
    <tr>
      <td colSpan={3}>
        <details className={styles.portDetails}>
          <summary className={styles.portSummary}>
            <span className={styles.portColPort}>{p.port}</span>
            <span className={styles.portColService}>{p.service}</span>

            <span className={`${styles.sev} ${sevClass(p.severity)}`}>
              {p.severity}
            </span>
          </summary>

          <div className={styles.portBody}>
            <div>
              <b>Impacto:</b> {p.impact ?? "—"}
            </div>
            <div style={{ marginTop: 6 }}>
              <b>Recomendação:</b> {p.recommendation ?? "—"}
            </div>

            {p.evidence && (
              <div style={{ marginTop: 6 }}>
                <b>Evidência:</b> {p.evidence}
              </div>
            )}

            {(p.latencyMs ?? p.latency) != null && (
              <div style={{ marginTop: 6 }}>
                <b>Latência:</b> {p.latencyMs ?? p.latency}ms
              </div>
            )}
          </div>
        </details>
      </td>
    </tr>
  );
}

type NoteGroup = { title: string; details: string[] };

function isNoteDetail(line: string) {
  const t = (line ?? "").trim();
  return t.startsWith("↳") || t.startsWith("->") || t.startsWith("→");
}

function cleanNoteDetail(line: string) {
  return (line ?? "")
    .trim()
    .replace(/^↳\s?/, "")
    .replace(/^(->|→)\s?/, "");
}

function groupScoreNotes(notes: string[] = []): NoteGroup[] {
  const groups: NoteGroup[] = [];
  let current: NoteGroup | null = null;

  for (const raw of notes) {
    const line = String(raw ?? "").trim();
    if (!line) continue;

    if (!isNoteDetail(line)) {
      current = { title: line, details: [] };
      groups.push(current);
    } else {
      if (!current) {
        // Se vier detalhe sem título, cria um grupo “genérico”
        current = { title: "Detalhes", details: [] };
        groups.push(current);
      }
      current.details.push(cleanNoteDetail(line));
    }
  }

  return groups;
}

function ScoreNoteItem({ g }: { g: NoteGroup }) {
  const hasDetails = g.details.length > 0;

  const showNoDetailsHint = !hasDetails && /total|resumo|overall|sumário/i.test(g.title);

  if (!hasDetails) {
    // ✅ Item simples (sem seta, sem clique)
    return (
      <div className={styles.noteItemStatic}>
        <span className={styles.noteTitle}>{g.title}</span>
        {showNoDetailsHint && <span className={styles.noteHint}>sem detalhes</span>}
      </div>
    );
  }

  // ✅ Item com detalhes (expansível, com seta)
  return (
    <details className={styles.noteItem}>
      <summary className={styles.noteSummary}>
        <span className={styles.noteChevron} aria-hidden="true" />
        <span className={styles.noteTitle}>{g.title}</span>
      </summary>

      <div className={styles.noteBody}>
        {g.details.map((d, idx) => (
          <div key={idx} className={styles.noteDetail}>
            {d}
          </div>
        ))}
      </div>
    </details>
  );
}

export default function App() {
  const scanAbortRef = useRef<AbortController | null>(null);

  const [url, setUrl] = useState("github.com");
  const [active, setActive] = useState(false);

  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>(() => loadHistory());

  const HISTORY_UI_KEY = "cyberaudit.history.open.v1";
  const [historyOpen, setHistoryOpen] = useState<boolean>(() => {
    try {
      const v = localStorage.getItem(HISTORY_UI_KEY);
      return v ? JSON.parse(v) : false;
    } catch {
      return false;
    }
  });

  const toggleHistory = () => {
    setHistoryOpen((prev) => {
      const next = !prev;
      localStorage.setItem(HISTORY_UI_KEY, JSON.stringify(next));
      return next;
    });
  };

  const riskLevel = result?.score?.riskLevel as string | undefined;

  const overview = useMemo(() => {
    if (!result) return null;
    return {
      score: result.score?.score ?? "-",
      risk: result.score?.riskLevel ?? "-",
      status: result.httpStatus ?? "-",
      finalUrl: result.finalUrl ?? "-",
    };
  }, [result]);

  function handleOpenHistory(item: HistoryItem) {
    setError(null);
    setResult(item.result);
    setUrl(item.url);
    setActive(item.active);
  }

  function handleClearHistory() {
    if (!confirm("Limpar todo o histórico?")) return;
    setHistory([]);
    localStorage.removeItem(HISTORY_KEY);
  }

  async function handleRescan(item: HistoryItem) {
    setUrl(item.url);
    setActive(item.active);
    await handleScan(); // usa o scan atual com url/active do state
  }

  function sanitizeUrlForFile(url: string) {
    return url
      .replace(/^https?:\/\//, "")
      .replace(/[^\w.-]+/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "");
  }

  async function handlePdfFor(item: { url: string; active: boolean }) {
    setPdfLoading(true);
    setError(null);

    try {
      const res = await api.get("/scan/report/pdf", {
        params: { url: item.url, active: item.active },
        responseType: "blob",
      });

      const sanitized = sanitizeUrlForFile(item.url);
      const now = new Date();

      const timestamp =
        now.getFullYear() +
        "-" +
        String(now.getMonth() + 1).padStart(2, "0") +
        "-" +
        String(now.getDate()).padStart(2, "0") +
        "-" +
        String(now.getHours()).padStart(2, "0") +
        "-" +
        String(now.getMinutes()).padStart(2, "0") +
        "-" +
        String(now.getSeconds()).padStart(2, "0");

      const filename = `cyberaudit-${sanitized}-${timestamp}.pdf`;

      downloadBlob(new Blob([res.data], { type: "application/pdf" }), filename);
    } catch (err: any) {
      console.error(err);
      const msg =
        err?.response
          ? `Erro ${err.response.status}: ${JSON.stringify(err.response.data)}`
          : `Falha ao gerar PDF: ${err.message}`;
      setError(msg);
    } finally {
      setPdfLoading(false);
    }
  }

  async function handleScan() {
    scanAbortRef.current?.abort();

    const controller = new AbortController();
    scanAbortRef.current = controller;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await api.get("/scan", {
        params: { url, active },
        signal: controller.signal,
      });

      setResult(res.data);

      const item: HistoryItem = {
        id: makeId(),
        createdAt: new Date().toISOString(),
        url,
        active,
        score: res.data?.score?.score ?? null,
        riskLevel: res.data?.score?.riskLevel ?? null,
        httpStatus: res.data?.httpStatus ?? null,
        finalUrl: res.data?.finalUrl ?? null,
        result: res.data,
      };

      setHistory((prev) => {
        const next = [item, ...prev].slice(0, HISTORY_LIMIT);
        saveHistory(next);
        return next;
      });
    } catch (err: any) {
      console.error(err);

      const aborted =
        err?.name === "CanceledError" ||
        err?.code === "ERR_CANCELED" ||
        err?.message?.toLowerCase?.().includes("canceled");

      if (aborted) {
        setError("Scan cancelado.");
        return;
      }

      const msg =
        err?.response
          ? `Erro ${err.response.status}: ${JSON.stringify(err.response.data)}`
          : `Falha de rede/CORS: ${err.message}`;

      setError(msg);
    } finally {
      setLoading(false);
      scanAbortRef.current = null;
    }
  }

  function handleCancelScan() {
    if (scanAbortRef.current) {
      scanAbortRef.current.abort();
    }
  }

  return (
    <div className={styles.page}>
      <div className={styles.container}>
        <div className={styles.header}>
          <div>
            <div className={styles.title}>CyberAudit</div>
            <div className={styles.subtitle}>
              Scanner de segurança web (SSL, headers, XSS, DB leakage, portas) — modo ativo opcional
            </div>
          </div>
          <div className={styles.kicker}>
            API: {import.meta.env.VITE_API_URL ?? "http://localhost:8080"}
          </div>
        </div>

        <div className={styles.panel}>
          <div className={styles.formRow}>
            <div>
              <label className={styles.label}>URL</label>
              <input
                className={styles.input}
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="github.com ou https://example.com"
              />
            </div>

            <label className={styles.checkboxWrap} title="Ativa probes e port scan (pode demorar mais)">
              <input
                type="checkbox"
                checked={active}
                disabled={loading}
                onChange={(e) => setActive(e.target.checked)}
              />
              <span>active</span>
            </label>

            <button className={`${styles.btn} ${styles.btnPrimary}`} onClick={handleScan} disabled={loading}>
              <span className={styles.btnInner}>
                {loading && <span className={styles.spinner} />}
                {loading ? "Scanning..." : "Scan"}
              </span>
            </button>

            {loading ? (
              <button className={styles.btn} onClick={handleCancelScan}>
                Cancel
              </button>
            ) : (
              <button
                className={styles.btn}
                onClick={() => handlePdfFor({ url, active })}
                disabled={pdfLoading || loading}
              >
                {pdfLoading ? "Gerando..." : "PDF"}
              </button>
            )}
          </div>

          <div className={styles.smallNote}>
            Dica: active=true pode demorar mais (port scan e probes). Use apenas em ambientes autorizados.
          </div>

          {loading && (
            <div className={styles.progressWrap} aria-label="Scanning progress">
              <div className={styles.progressBar} />
            </div>
          )}

          {error && <div className={styles.errorBox}>{error}</div>}
        </div>

        {history.length > 0 && (
          <div className={styles.card} style={{ marginTop: 16 }}>
            <div
              className={styles.accordionHeader}
              onClick={toggleHistory}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") toggleHistory();
              }}
            >
              <div className={styles.accordionLeft}>
                <span className={`${styles.chev} ${historyOpen ? styles.chevOpen : ""}`} />
                <span>Histórico</span>
                <span className={styles.badge}>{history.length} itens</span>
              </div>

              <div className={styles.actionsRight} onClick={(e) => e.stopPropagation()}>
                <button
                  className={styles.btn}
                  onClick={handleClearHistory}
                  disabled={loading || pdfLoading}
                  title="Limpar histórico"
                >
                  Limpar
                </button>
              </div>
            </div>

            {historyOpen && (
              <div className={styles.accordionBody}>
                <table className={styles.table}>
                  <thead>
                    <tr>
                      <th>Quando</th>
                      <th>URL</th>
                      <th>Active</th>
                      <th>Score</th>
                      <th>Risk</th>
                      <th>Ações</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((h) => (
                      <tr key={h.id}>
                        <td>{new Date(h.createdAt).toLocaleString()}</td>
                        <td style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {h.url}
                        </td>
                        <td>{String(h.active)}</td>
                        <td>{h.score ?? "-"}</td>
                        <td>{h.riskLevel ?? "-"}</td>
                        <td style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                          <button className={styles.btn} onClick={() => handleOpenHistory(h)} disabled={loading}>
                            Reabrir
                          </button>
                          <button className={styles.btn} onClick={() => handleRescan(h)} disabled={loading}>
                            Re-scan
                          </button>
                          <button
                            className={styles.btn}
                            onClick={() => handlePdfFor({ url: h.url, active: h.active })}
                            disabled={pdfLoading}
                          >
                            PDF
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                <div className={styles.smallNote}>
                  O histórico fica salvo no seu navegador (localStorage). Máx: {HISTORY_LIMIT}.
                </div>
              </div>
            )}
          </div>
        )}

        {!result && !loading && (
          <div className={styles.smallNote} style={{ marginTop: 14 }}>
            Faça um scan para ver o dashboard.
          </div>
        )}

        {loading && (
          <div className={styles.grid}>
            <div className={styles.skeletonCard}>
              <div className={`${styles.skLine} ${styles.skLineSm}`} />
              <div className={styles.skBig} />
              <div className={`${styles.skLine} ${styles.skLineMd}`} />
              <div className={`${styles.skLine} ${styles.skLineLg}`} />
              <div className={`${styles.skLine} ${styles.skLineMd}`} />
              <div className={`${styles.skLine} ${styles.skLineLg}`} />
            </div>

            <div className={styles.skeletonCard}>
              <div className={`${styles.skLine} ${styles.skLineSm}`} />
              <div className={`${styles.skLine} ${styles.skLineLg}`} />
              <div className={`${styles.skLine} ${styles.skLineMd}`} />
              <div className={`${styles.skLine} ${styles.skLineLg}`} />
              <div className={`${styles.skLine} ${styles.skLineMd}`} />
              <div className={`${styles.skLine} ${styles.skLineLg}`} />
              <div className={`${styles.skLine} ${styles.skLineMd}`} />
            </div>
          </div>
        )}

        {result && (
          <div className={`${styles.grid} ${styles.fadeIn}`}>
            <div className={styles.card}>
              <div className={styles.cardTitle}>
                <span>Score</span>
                <span className={`${styles.badge} ${riskBadgeClass(riskLevel)}`}>
                  {overview?.risk}
                </span>
              </div>

              <div className={styles.bigScore}>{overview?.score}</div>
              <div className={styles.meta}>
                HTTP {overview?.status} • Final: {overview?.finalUrl}
              </div>

              <div className={styles.sectionTitle} style={{ marginTop: 14 }}>SSL</div>
              <div className={styles.kv}>
                <div className={styles.kvRow}><span>HTTPS suportado</span><span>{String(result.sslInfo?.https)}</span></div>
                <div className={styles.kvRow}><span>Certificado válido</span><span>{String(result.sslInfo?.valid)}</span></div>
                <div className={styles.kvRow}><span>Expira em</span><span>{result.sslInfo?.expirationDate ?? "-"}</span></div>
                <div className={styles.kvRow}><span>Dias restantes</span><span>{result.sslInfo?.daysRemaining ?? "-"}</span></div>
                <div className={styles.kvRow}><span>Força HTTPS</span><span>{String(result.redirectsToHttps)}</span></div>
              </div>

              <div className={styles.sectionTitle} style={{ marginTop: 16 }}>Active checks</div>
              <div className={styles.kv}>
                <div className={styles.kvRow}><span>Modo ativo</span><span>{String(result.activeMode ?? active)}</span></div>
                <div className={styles.kvRow}><span>DB error leakage</span><span>{String(result.dbErrorLeakageSuspected ?? false)}</span></div>
                <div className={styles.kvRow}><span>XSS probe</span><span>{String(result.xssProbePerformed ?? false)}</span></div>
                <div className={styles.kvRow}><span>Reflected XSS suspeito</span><span>{String(result.reflectedXssSuspected ?? false)}</span></div>
              </div>
            </div>

            <div className={styles.card}>
              <div className={styles.cardTitle}>
                <span>Issues</span>
                <span className={styles.badge}>{(result.score?.issues?.length ?? 0) + " findings"}</span>
              </div>

              {result.score?.issues?.length ? (
                <div className={styles.issues}>
                  {result.score.issues.map((i: any) => (
                    <div key={i.id} className={styles.issue}>
                      <div className={styles.issueTop}>
                        <div className={styles.issueTitle}>{i.title}</div>
                        <span className={`${styles.sev} ${sevClass(i.severity)}`}>{i.severity}</span>
                      </div>
                      <div className={styles.issueBody}>
                        <b>Impacto:</b> {i.impact}<br />
                        <b>Recomendação:</b> {i.recommendation}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className={styles.smallNote} style={{ marginTop: 10 }}>
                  Nenhuma issue relevante encontrada.
                </div>
              )}

              <div className={styles.sectionTitle} style={{ marginTop: 18 }}>Portas abertas (active)</div>

              {result.openPorts?.length ? (
                <table className={styles.table}>
                  <thead>
                    <tr>
                      <th>Porta</th>
                      <th>Serviço</th>
                      <th>Severidade</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.openPorts.map((p: any) => (
                      <PortRow key={p.port} p={p} />
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className={styles.smallNote} style={{ marginTop: 10 }}>
                  Sem portas detectadas (ou active desativado).
                </div>
              )}

              <div className={styles.sectionTitle} style={{ marginTop: 18 }}>Notas do score</div>

              {result.score?.notes?.length ? (
                <div className={styles.notesList}>
                  {groupScoreNotes(result.score.notes).map((g, idx) => (
                    <ScoreNoteItem key={idx} g={g} />
                  ))}
                </div>
              ) : (
                <div className={styles.smallNote} style={{ marginTop: 10 }}>
                  Sem notas.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}