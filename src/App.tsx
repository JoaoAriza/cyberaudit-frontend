import { useCallback, useEffect, useRef, useState } from "react";
import styles from "./App.module.css";
import { api } from "./api/client";

// ── Types ─────────────────────────────────────────────────────────────────────

interface SSLInfo {
  https: boolean; valid: boolean;
  expirationDate: string | null; daysRemaining: number; message: string;
}
interface TlsDetails {
  negotiatedProtocol: string; cipherSuite: string;
  weakProtocol: boolean; message: string;
}
interface CorsResult {
  tested: boolean; allowOriginValue: string;
  wildcardOrigin: boolean; reflectsOrigin: boolean;
  credentialsAllowed: boolean; nullOriginAccepted: boolean; message: string;
}
interface CookieFinding {
  name: string; httpOnly: boolean; secure: boolean;
  sameSite: string; risk: string; issues: string;
}
interface PortFinding {
  port: number; service: string; state: string;
  severity: string; latencyMs: number; evidence: string;
  impact: string; recommendation: string;
}
interface SecurityIssue {
  id: string; title: string; severity: string;
  impact: string; recommendation: string;
}
interface ScoreResult {
  score: number; riskLevel: string;
  notes: string[]; issues: SecurityIssue[];
}
interface SensitiveFileFinding {
  path: string; statusCode: number; exposure: string;
  contentPreview: string | null; severity: string;
}
interface HttpMethodFinding {
  method: string; statusCode: number; enabled: boolean;
  severity: string; risk: string;
}
interface OpenRedirectFinding {
  parameter: string; testedUrl: string; redirectedTo: string;
  vulnerable: boolean; severity: string;
}
interface DirectoryListingFinding {
  path: string; statusCode: number; listingEnabled: boolean;
  evidence: string; severity: string;
}
interface ScanResult {
  url: string; finalUrl: string; httpStatus: number;
  redirectsToHttps: boolean;
  sslInfo: SSLInfo; tlsDetails: TlsDetails;
  headers: Record<string, string>; serverVersionExposed: boolean;
  activeMode: boolean; inputSurfaceDetected: boolean;
  dbErrorLeakageSuspected: boolean; xssProbePerformed: boolean;
  reflectedXssSuspected: boolean;
  openPorts: PortFinding[];
  corsResult: CorsResult;
  cookieIssues: CookieFinding[];
  sensitiveRobotsPaths: string[];
  sensitiveFiles: SensitiveFileFinding[];
  dangerousHttpMethods: HttpMethodFinding[];
  securityTxtPresent: boolean; securityTxtContact: string | null;
  openRedirectFindings: OpenRedirectFinding[];
  directoryListingFindings: DirectoryListingFinding[];
  score: ScoreResult;
}
interface OwnershipState {
  message: string; host: string; token: string | null;
  passiveResult: ScanResult | null;
}
interface AsyncStatus { state: "PENDING" | "RUNNING" | "DONE" | "ERROR"; result: ScanResult | null; errorMessage: string | null; }

// ── Utilities ─────────────────────────────────────────────────────────────────

function riskColor(level?: string) {
  if (level === "SECURE")   return styles.secure;
  if (level === "WARNING")  return styles.warning;
  if (level === "CRITICAL") return styles.critical;
  return styles.muted;
}
function sevColor(sev?: string) {
  const s = (sev ?? "").toUpperCase();
  if (s === "CRITICAL") return styles.critical;
  if (s === "HIGH")     return styles.high;
  if (s === "MEDIUM")   return styles.warning;
  if (s === "LOW")      return styles.low;
  return styles.info;
}
function boolIcon(v: boolean, trueLabel = "✓", falseLabel = "✗") {
  return <span className={v ? styles.ok : styles.bad}>{v ? trueLabel : falseLabel}</span>;
}
function headerStatus(v: string) {
  if (v.startsWith("OK"))      return <span className={styles.ok}>✓ {v}</span>;
  if (v.startsWith("MISSING")) return <span className={styles.bad}>✗ MISSING</span>;
  if (v.startsWith("WEAK"))    return <span className={styles.warn}>⚠ {v}</span>;
  if (v.startsWith("error"))   return <span className={styles.bad}>ERR</span>;
  return <span className={styles.muted}>{v}</span>;
}
function downloadBlob(blob: Blob, filename: string) {
  const url = window.URL.createObjectURL(blob);
  const a   = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  a.remove(); window.URL.revokeObjectURL(url);
}
function sanitizeFilename(url: string) {
  return url.replace(/^https?:\/\//, "").replace(/[^\w.-]+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
}

// ── Small components ───────────────────────────────────────────────────────────

function Tag({ label, cls }: { label: string; cls?: string }) {
  return <span className={`${styles.tag} ${cls ?? ""}`}>{label}</span>;
}
function KV({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className={styles.kv}>
      <span className={styles.kvLabel}>{label}</span>
      <span className={styles.kvValue}>{value}</span>
    </div>
  );
}
function Section({ title, count, children, defaultOpen = true }: {
  title: string; count?: number; children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={styles.section}>
      <button className={styles.sectionHeader} onClick={() => setOpen(o => !o)}>
        <span className={`${styles.chevron} ${open ? styles.chevronOpen : ""}`}>›</span>
        <span className={styles.sectionTitle}>{title}</span>
        {count !== undefined && <span className={styles.count}>{count}</span>}
      </button>
      {open && <div className={styles.sectionBody}>{children}</div>}
    </div>
  );
}
function Card({ title, children, accent }: {
  title?: string; children: React.ReactNode; accent?: string;
}) {
  return (
    <div className={styles.card} style={accent ? { borderTopColor: accent } : {}}>
      {title && <div className={styles.cardTitle}>{title}</div>}
      {children}
    </div>
  );
}

// ── Score gauge ────────────────────────────────────────────────────────────────

function ScoreGauge({ score, risk }: { score: number; risk: string }) {
  const color = risk === "SECURE" ? "var(--secure)" : risk === "WARNING" ? "var(--warning)" : "var(--critical)";
  const r = 54; const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  return (
    <div className={styles.gauge}>
      <svg viewBox="0 0 130 130" className={styles.gaugeSvg}>
        <circle cx="65" cy="65" r={r} className={styles.gaugeTrack} />
        <circle cx="65" cy="65" r={r} className={styles.gaugeArc}
          style={{ stroke: color, strokeDasharray: circ, strokeDashoffset: offset }} />
      </svg>
      <div className={styles.gaugeInner}>
        <div className={styles.gaugeScore} style={{ color }}>{score}</div>
        <div className={styles.gaugeLabel}>/100</div>
      </div>
    </div>
  );
}

// ── Issue card ─────────────────────────────────────────────────────────────────

function IssueItem({ issue }: { issue: SecurityIssue }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`${styles.issue} ${sevColor(issue.severity)}`}>
      <button className={styles.issueHeader} onClick={() => setOpen(o => !o)}>
        <span className={`${styles.issueSev} ${sevColor(issue.severity)}`}>{issue.severity}</span>
        <span className={styles.issueTitle}>{issue.title}</span>
        <span className={`${styles.chevron} ${open ? styles.chevronOpen : ""}`}>›</span>
      </button>
      {open && (
        <div className={styles.issueBody}>
          <div><span className={styles.label}>IMPACT</span> {issue.impact}</div>
          <div><span className={styles.label}>FIX</span> {issue.recommendation}</div>
        </div>
      )}
    </div>
  );
}

// ── Terminal loading ───────────────────────────────────────────────────────────

const SCAN_LINES = [
  "→ resolving target...",
  "→ probing SSL certificate...",
  "→ negotiating TLS handshake...",
  "→ analyzing security headers...",
  "→ running CORS probe...",
  "→ inspecting cookies...",
  "→ checking robots.txt...",
  "→ scanning sensitive files...",
  "→ testing HTTP methods...",
  "→ verifying security.txt...",
  "→ detecting open redirects...",
  "→ checking directory listings...",
  "→ calculating risk score...",
];

function TerminalLoader({ asyncState }: { asyncState?: string }) {
  const [lines, setLines] = useState<string[]>([SCAN_LINES[0]]);
  const idx = useRef(1);
  useEffect(() => {
    const t = setInterval(() => {
      if (idx.current < SCAN_LINES.length) {
        setLines(prev => [...prev, SCAN_LINES[idx.current++]]);
      }
    }, 800);
    return () => clearInterval(t);
  }, []);
  return (
    <div className={styles.terminal}>
      <div className={styles.terminalBar}>
        <span className={styles.termDot} style={{ background: "#ff5f57" }} />
        <span className={styles.termDot} style={{ background: "#febc2e" }} />
        <span className={styles.termDot} style={{ background: "#28c840" }} />
        <span className={styles.termTitle}>cyberaudit scan {asyncState ? `[${asyncState}]` : ""}</span>
      </div>
      <div className={styles.terminalBody}>
        {lines.map((l, i) => (
          <div key={i} className={styles.termLine} style={{ animationDelay: `${i * 0.05}s` }}>{l}</div>
        ))}
        <div className={styles.termCursor}>█</div>
      </div>
    </div>
  );
}

// ── Ownership verification card ────────────────────────────────────────────────

function OwnershipCard({ state, passiveResult, onDismiss }: {
  state: OwnershipState; passiveResult: ScanResult | null; onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [checking, setChecking] = useState(false);
  const [verified, setVerified] = useState(false);

  async function checkVerification() {
    setChecking(true);
    try {
      const res = await api.get("/scan/verify-check", { params: { host: state.host } });
      setVerified(res.data.verified);
    } catch { setVerified(false); }
    setChecking(false);
  }

  function copyToken() {
    if (state.token) { navigator.clipboard.writeText(state.token); setCopied(true); setTimeout(() => setCopied(false), 2000); }
  }

  return (
    <div className={styles.ownershipCard}>
      <div className={styles.ownershipHeader}>
        <span className={styles.ownershipIcon}>⚠</span>
        <span>VERIFICAÇÃO DE PROPRIEDADE NECESSÁRIA</span>
      </div>
      <p className={styles.ownershipText}>
        O scan passivo detectou riscos de segurança em <strong>{state.host}</strong>.
        Para executar o scan ativo, prove que você é o dono do domínio.
      </p>
      <div className={styles.ownershipSteps}>
        <div className={styles.ownershipStep}>
          <span className={styles.stepNum}>1</span>
          <div>
            <div className={styles.stepTitle}>Crie o arquivo de verificação</div>
            <code className={styles.stepCode}>
              https://{state.host}/.well-known/cyberaudit.txt
            </code>
          </div>
        </div>
        <div className={styles.ownershipStep}>
          <span className={styles.stepNum}>2</span>
          <div>
            <div className={styles.stepTitle}>Conteúdo do arquivo</div>
            <div className={styles.tokenRow}>
              <code className={styles.stepCode}>{state.token ?? "—"}</code>
              <button className={styles.copyBtn} onClick={copyToken}>{copied ? "✓ Copiado" : "Copiar"}</button>
            </div>
          </div>
        </div>
        <div className={styles.ownershipStep}>
          <span className={styles.stepNum}>3</span>
          <div>
            <div className={styles.stepTitle}>Confirme a verificação</div>
            <div className={styles.tokenRow}>
              <button className={styles.verifyBtn} onClick={checkVerification} disabled={checking}>
                {checking ? "Verificando..." : "Checar agora"}
              </button>
              {verified && <span className={styles.ok}>✓ Verificado! Refaça o scan ativo.</span>}
              {!verified && !checking && <span className={styles.bad}>Arquivo não encontrado ainda.</span>}
            </div>
          </div>
        </div>
      </div>
      {passiveResult && (
        <div className={styles.ownershipNote}>
          Resultado do scan passivo disponível abaixo ↓
        </div>
      )}
      <button className={styles.dismissBtn} onClick={onDismiss}>Fechar</button>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────────

export default function App() {
  const [url, setUrl]           = useState("github.com");
  const [active, setActive]     = useState(false);
  const [useAsync, setUseAsync] = useState(false);
  const [loading, setLoading]   = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [result, setResult]     = useState<ScanResult | null>(null);
  const [error, setError]       = useState<string | null>(null);
  const [ownership, setOwnership] = useState<OwnershipState | null>(null);
  const [asyncState, setAsyncState] = useState<string | undefined>();
  const abortRef  = useRef<AbortController | null>(null);
  const pollRef   = useRef<ReturnType<typeof setInterval> | null>(null);

  // Clean up on unmount
  useEffect(() => () => { pollRef.current && clearInterval(pollRef.current); }, []);

  const stopPoll = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  async function handleScan() {
    abortRef.current?.abort(); stopPoll();
    setLoading(true); setError(null); setResult(null); setOwnership(null); setAsyncState(undefined);

    if (useAsync) {
      await runAsync();
    } else {
      await runSync();
    }
  }

  async function runSync() {
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    try {
      const res = await api.get("/scan", { params: { url, active }, signal: ctrl.signal });
      setResult(res.data);
    } catch (err: any) {
      handleError(err);
    } finally {
      setLoading(false);
    }
  }

  async function runAsync() {
    try {
      const res = await api.post(`/scan/async`, null, { params: { url, active } });
      const scanId: string = res.data.scanId;
      setAsyncState("PENDING");

      pollRef.current = setInterval(async () => {
        try {
          const status: AsyncStatus = (await api.get(`/scan/async/${scanId}`)).data;
          setAsyncState(status.state);
          if (status.state === "DONE") {
            stopPoll(); setResult(status.result); setLoading(false);
          } else if (status.state === "ERROR") {
            stopPoll(); setError(status.errorMessage ?? "Erro desconhecido."); setLoading(false);
          }
        } catch { stopPoll(); setError("Falha ao consultar status."); setLoading(false); }
      }, 2000);
    } catch (err: any) {
      handleError(err); setLoading(false);
    }
  }

  function handleError(err: any) {
    const aborted = err?.name === "CanceledError" || err?.code === "ERR_CANCELED";
    if (aborted) { setError("Scan cancelado."); return; }

    if (err?.response?.status === 403) {
      const data = err.response.data;
      if (data?.error === "OWNERSHIP_REQUIRED") {
        // Extract token from message
        const tokenMatch = data.message?.match(/cyberaudit-verify=[a-f0-9-]+/);
        const host = url.replace(/^https?:\/\//, "").split("/")[0];
        setOwnership({ message: data.message, host, token: tokenMatch?.[0] ?? null, passiveResult: data.passiveResult ?? null });
        if (data.passiveResult) setResult(data.passiveResult);
        return;
      }
    }
    const msg = err?.response
      ? `Erro ${err.response.status}: ${JSON.stringify(err.response.data)}`
      : `Falha: ${err.message}`;
    setError(msg);
  }

  function handleCancel() {
    abortRef.current?.abort(); stopPoll(); setLoading(false); setError("Scan cancelado.");
  }

  async function handlePdf() {
    setPdfLoading(true); setError(null);
    try {
      const res = await api.get("/scan/report/pdf", { params: { url, active }, responseType: "blob" });
      const now = new Date();
      const ts = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,"0")}-${String(now.getDate()).padStart(2,"0")}`;
      downloadBlob(new Blob([res.data], { type: "application/pdf" }), `cyberaudit-${sanitizeFilename(url)}-${ts}.pdf`);
    } catch (err: any) {
      setError(`PDF: ${err?.response ? JSON.stringify(err.response.data) : err.message}`);
    } finally { setPdfLoading(false); }
  }

  async function fetchToken() {
    const host = url.replace(/^https?:\/\//, "").split("/")[0];
    try {
      const res = await api.get("/scan/verify-token", { params: { host } });
      setOwnership({ message: "", host, token: res.data.token, passiveResult: null });
    } catch { /* silent */ }
  }

  const r = result;
  const risk = r?.score?.riskLevel;

  return (
    <div className={styles.app}>
      {/* ── Header ── */}
      <header className={styles.header}>
        <div className={styles.logo}>
          <span className={styles.logoIcon}>◈</span>
          <span className={styles.logoText}>CyberAudit</span>
        </div>
        <div className={styles.headerMeta}>
          <span className={styles.apiTag}>API {import.meta.env.VITE_API_URL ?? "localhost:8080"}</span>
        </div>
      </header>

      <main className={styles.main}>
        {/* ── Scan form ── */}
        <div className={styles.scanPanel}>
          <div className={styles.scanForm}>
            <div className={styles.inputWrap}>
              <span className={styles.inputPrefix}>https://</span>
              <input
                className={styles.urlInput}
                value={url}
                onChange={e => setUrl(e.target.value)}
                placeholder="example.com"
                onKeyDown={e => e.key === "Enter" && !loading && handleScan()}
              />
            </div>

            <div className={styles.toggles}>
              <label className={styles.toggle}>
                <input type="checkbox" checked={active} disabled={loading} onChange={e => setActive(e.target.checked)} />
                <span className={styles.toggleLabel}>ACTIVE</span>
              </label>
              <label className={styles.toggle}>
                <input type="checkbox" checked={useAsync} disabled={loading} onChange={e => setUseAsync(e.target.checked)} />
                <span className={styles.toggleLabel}>ASYNC</span>
              </label>
            </div>

            <div className={styles.actions}>
              {loading ? (
                <button className={`${styles.btn} ${styles.btnCancel}`} onClick={handleCancel}>
                  ✕ Cancel
                </button>
              ) : (
                <button className={`${styles.btn} ${styles.btnScan}`} onClick={handleScan}>
                  ◈ Scan
                </button>
              )}
              <button className={`${styles.btn} ${styles.btnGhost}`} onClick={handlePdf} disabled={pdfLoading || loading}>
                {pdfLoading ? "..." : "PDF"}
              </button>
              <button className={`${styles.btn} ${styles.btnGhost}`} onClick={fetchToken} title="Obter token de verificação">
                Token
              </button>
            </div>
          </div>

          {active && (
            <div className={styles.activeWarning}>
              ⚠ Modo ativo: realiza probes e port scan. Use apenas em domínios autorizados.
            </div>
          )}

          {loading && <div className={styles.progressBar}><div className={styles.progressFill} /></div>}
          {error && <div className={styles.errorBox}>{error}</div>}
        </div>

        {/* ── Ownership verification ── */}
        {ownership && (
          <OwnershipCard
            state={ownership}
            passiveResult={ownership.passiveResult}
            onDismiss={() => setOwnership(null)}
          />
        )}

        {/* ── Terminal loader ── */}
        {loading && <TerminalLoader asyncState={asyncState} />}

        {/* ── Result dashboard ── */}
        {r && !loading && (
          <div className={styles.dashboard}>

            {/* Row 1: Score + Overview */}
            <div className={styles.row}>
              <Card>
                <div className={styles.overviewCard}>
                  <ScoreGauge score={r.score?.score ?? 0} risk={risk ?? "CRITICAL"} />
                  <div className={styles.overviewMeta}>
                    <div className={`${styles.riskBadge} ${riskColor(risk)}`}>{risk}</div>
                    <div className={styles.metaRow}>
                      <span className={styles.metaLabel}>URL</span>
                      <span className={styles.metaVal}>{r.finalUrl ?? r.url}</span>
                    </div>
                    <div className={styles.metaRow}>
                      <span className={styles.metaLabel}>HTTP</span>
                      <span className={styles.metaVal}>{r.httpStatus}</span>
                    </div>
                    <div className={styles.metaRow}>
                      <span className={styles.metaLabel}>HTTPS REDIRECT</span>
                      <span className={styles.metaVal}>{boolIcon(r.redirectsToHttps)}</span>
                    </div>
                    <div className={styles.metaRow}>
                      <span className={styles.metaLabel}>ACTIVE MODE</span>
                      <span className={styles.metaVal}>{boolIcon(r.activeMode)}</span>
                    </div>
                    <div className={styles.metaRow}>
                      <span className={styles.metaLabel}>SERVER EXPOSED</span>
                      <span className={styles.metaVal}>{boolIcon(!r.serverVersionExposed, "✓ Clean", "⚠ Exposed")}</span>
                    </div>
                    <div className={styles.badgePreview}>
                      <img
                        src={`${import.meta.env.VITE_API_URL ?? "http://localhost:8080"}/badge/${(r.finalUrl ?? r.url).replace(/^https?:\/\//, "").split("/")[0]}`}
                        alt="Security badge"
                        className={styles.badgeImg}
                      />
                    </div>
                  </div>
                </div>
              </Card>

              {/* Issues */}
              <Card title={`ISSUES  [${r.score?.issues?.length ?? 0}]`}>
                {r.score?.issues?.length ? (
                  <div className={styles.issuesList}>
                    {r.score.issues.map(i => <IssueItem key={i.id} issue={i} />)}
                  </div>
                ) : (
                  <div className={styles.empty}>◈ Nenhuma issue detectada</div>
                )}
              </Card>
            </div>

            {/* Row 2: Transport + Headers */}
            <div className={styles.row}>
              <Card title="TRANSPORT SECURITY">
                <Section title="SSL / TLS">
                  <KV label="Protocol"    value={<span className={r.tlsDetails?.weakProtocol ? styles.bad : styles.ok}>{r.tlsDetails?.negotiatedProtocol ?? "—"}</span>} />
                  <KV label="Cipher"      value={<code className={styles.code}>{r.tlsDetails?.cipherSuite ?? "—"}</code>} />
                  <KV label="Certificate" value={boolIcon(r.sslInfo?.valid, "Valid", "Invalid")} />
                  <KV label="Expires"     value={r.sslInfo?.expirationDate ?? "—"} />
                  <KV label="Days left"   value={
                    <span className={(r.sslInfo?.daysRemaining ?? 0) < 30 ? styles.bad : (r.sslInfo?.daysRemaining ?? 0) < 90 ? styles.warn : styles.ok}>
                      {r.sslInfo?.daysRemaining ?? "—"}d
                    </span>
                  } />
                  {r.tlsDetails?.message && <div className={styles.note}>{r.tlsDetails.message}</div>}
                </Section>
              </Card>

              <Card title="SECURITY HEADERS">
                <Section title="Headers">
                  {Object.entries(r.headers ?? {}).map(([k, v]) => (
                    <KV key={k} label={k} value={headerStatus(v)} />
                  ))}
                </Section>
              </Card>
            </div>

            {/* Row 3: CORS + Cookies */}
            <div className={styles.row}>
              <Card title="CORS ANALYSIS">
                {r.corsResult?.tested ? (
                  <Section title="CORS Probe Results">
                    <KV label="Allow-Origin"  value={<code className={styles.code}>{r.corsResult.allowOriginValue}</code>} />
                    <KV label="Wildcard"      value={boolIcon(!r.corsResult.wildcardOrigin, "✓ No", "⚠ YES")} />
                    <KV label="Reflects Origin" value={boolIcon(!r.corsResult.reflectsOrigin, "✓ No", "⚠ YES")} />
                    <KV label="Credentials"   value={boolIcon(!r.corsResult.credentialsAllowed, "✓ No", "⚠ YES")} />
                    <KV label="Null Origin"   value={boolIcon(!r.corsResult.nullOriginAccepted, "✓ No", "⚠ YES")} />
                    <div className={styles.note}>{r.corsResult.message}</div>
                  </Section>
                ) : <div className={styles.empty}>Probe não executado</div>}
              </Card>

              <Card title="COOKIE SECURITY">
                {r.cookieIssues?.length ? (
                  <Section title={`${r.cookieIssues.length} cookie(s) com problemas`}>
                    {r.cookieIssues.map((c, i) => (
                      <div key={i} className={styles.cookieRow}>
                        <div className={styles.cookieName}>
                          <code>{c.name}</code>
                          <Tag label={c.risk} cls={sevColor(c.risk)} />
                        </div>
                        <div className={styles.cookieFlags}>
                          <span className={c.httpOnly ? styles.ok : styles.bad}>HttpOnly</span>
                          <span className={c.secure  ? styles.ok : styles.bad}>Secure</span>
                          <span className={styles.muted}>SameSite: {c.sameSite}</span>
                        </div>
                        <div className={styles.cookieIssue}>{c.issues}</div>
                      </div>
                    ))}
                  </Section>
                ) : <div className={styles.empty}>◈ Nenhum problema detectado</div>}
              </Card>
            </div>

            {/* Row 4: Attack surface */}
            <div className={styles.row}>
              {/* Sensitive files */}
              <Card title="SENSITIVE FILES">
                {r.sensitiveFiles?.length ? (
                  <Section title={`${r.sensitiveFiles.length} arquivo(s) encontrado(s)`}>
                    {r.sensitiveFiles.map((f, i) => (
                      <div key={i} className={styles.findingRow}>
                        <div className={styles.findingPath}>
                          <code>{f.path}</code>
                          <Tag label={f.exposure} cls={f.exposure === "EXPOSED" ? styles.critical : styles.warning} />
                          <Tag label={f.severity} cls={sevColor(f.severity)} />
                        </div>
                        {f.contentPreview && (
                          <pre className={styles.preview}>{f.contentPreview}</pre>
                        )}
                      </div>
                    ))}
                  </Section>
                ) : <div className={styles.empty}>◈ Nenhum arquivo sensível exposto</div>}
              </Card>

              {/* HTTP Methods */}
              <Card title="HTTP METHODS">
                {r.dangerousHttpMethods?.length ? (
                  <Section title={`${r.dangerousHttpMethods.length} método(s) perigoso(s)`}>
                    {r.dangerousHttpMethods.map((m, i) => (
                      <div key={i} className={styles.findingRow}>
                        <div className={styles.findingPath}>
                          <code className={styles.method}>{m.method}</code>
                          <span className={styles.muted}>HTTP {m.statusCode}</span>
                          <Tag label={m.severity} cls={sevColor(m.severity)} />
                        </div>
                        <div className={styles.findingNote}>{m.risk}</div>
                      </div>
                    ))}
                  </Section>
                ) : <div className={styles.empty}>◈ Nenhum método perigoso detectado</div>}
              </Card>
            </div>

            {/* Row 5: Redirect + Directory listing */}
            <div className={styles.row}>
              <Card title="OPEN REDIRECT">
                {r.openRedirectFindings?.filter(f => f.vulnerable).length ? (
                  <Section title={`${r.openRedirectFindings.length} vulnerabilidade(s)`}>
                    {r.openRedirectFindings.filter(f => f.vulnerable).map((f, i) => (
                      <div key={i} className={styles.findingRow}>
                        <div className={styles.findingPath}>
                          <code>?{f.parameter}=</code>
                          <Tag label="VULNERABLE" cls={styles.critical} />
                        </div>
                        <div className={styles.findingNote}>→ {f.redirectedTo}</div>
                      </div>
                    ))}
                  </Section>
                ) : <div className={styles.empty}>◈ Nenhum open redirect detectado</div>}
              </Card>

              <Card title="DIRECTORY LISTING">
                {r.directoryListingFindings?.filter(f => f.listingEnabled).length ? (
                  <Section title={`${r.directoryListingFindings.length} diretório(s) exposto(s)`}>
                    {r.directoryListingFindings.filter(f => f.listingEnabled).map((f, i) => (
                      <div key={i} className={styles.findingRow}>
                        <div className={styles.findingPath}>
                          <code>{f.path}</code>
                          <Tag label={f.severity} cls={sevColor(f.severity)} />
                        </div>
                        <div className={styles.findingNote}>Evidência: {f.evidence}</div>
                      </div>
                    ))}
                  </Section>
                ) : <div className={styles.empty}>◈ Nenhum directory listing detectado</div>}
              </Card>
            </div>

            {/* Row 6: Recon */}
            <div className={styles.row}>
              <Card title="RECONNAISSANCE">
                <Section title="robots.txt">
                  {r.sensitiveRobotsPaths?.length ? (
                    r.sensitiveRobotsPaths.map((p, i) => (
                      <div key={i} className={styles.findingRow}>
                        <code>{p}</code>
                        <Tag label="SENSITIVE" cls={styles.warning} />
                      </div>
                    ))
                  ) : <div className={styles.empty}>◈ Nenhum path sensível</div>}
                </Section>
                <Section title="security.txt" defaultOpen={false}>
                  <KV label="Presente" value={boolIcon(r.securityTxtPresent)} />
                  {r.securityTxtContact && <KV label="Contact" value={<code>{r.securityTxtContact}</code>} />}
                </Section>
              </Card>

              {/* Active checks */}
              <Card title="ACTIVE CHECKS">
                <Section title="Application Probes">
                  <KV label="Input surface"   value={boolIcon(r.inputSurfaceDetected, "Detected", "—")} />
                  <KV label="XSS probe"       value={boolIcon(r.xssProbePerformed, "Executed", "—")} />
                  <KV label="Reflected XSS"   value={
                    r.xssProbePerformed
                      ? boolIcon(!r.reflectedXssSuspected, "✓ Clean", "⚠ Suspected")
                      : <span className={styles.muted}>—</span>
                  } />
                  <KV label="DB error leak"   value={boolIcon(!r.dbErrorLeakageSuspected, "✓ Clean", "⚠ Suspected")} />
                </Section>

                <Section title={`Port Scan [${r.openPorts?.length ?? 0}]`} defaultOpen={false}>
                  {r.openPorts?.length ? (
                    <table className={styles.table}>
                      <thead><tr><th>Port</th><th>Service</th><th>Sev</th><th>ms</th></tr></thead>
                      <tbody>
                        {r.openPorts.map(p => (
                          <tr key={p.port}>
                            <td><code>{p.port}</code></td>
                            <td>{p.service}</td>
                            <td><Tag label={p.severity} cls={sevColor(p.severity)} /></td>
                            <td className={styles.muted}>{p.latencyMs}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : <div className={styles.empty}>Sem portas abertas (ou modo ativo desativado)</div>}
                </Section>
              </Card>
            </div>

            {/* Score notes */}
            <Card title="SCORE BREAKDOWN">
              <div className={styles.notesList}>
                {(r.score?.notes ?? []).map((n, i) => (
                  <div key={i} className={`${styles.noteRow} ${n.includes("-") ? styles.noteMinus : styles.noteOk}`}>
                    <span className={styles.noteBullet}>{n.includes("-") ? "▼" : "◈"}</span>
                    {n}
                  </div>
                ))}
              </div>
            </Card>

          </div>
        )}
      </main>
    </div>
  );
}
