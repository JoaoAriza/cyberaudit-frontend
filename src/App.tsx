import { useCallback, useEffect, useRef, useState } from "react";
import styles from "./App.module.css";
import { api, setToken } from "./api/client";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine } from "recharts";
import { useAuth } from "./context/AuthContext";
import { useI18n } from "./i18n/I18nContext";
import { IDIOMAS } from "./i18n/catalog";
import type { TwoFactorPending } from "./context/AuthContext";

// ── Backend Types ─────────────────────────────────────────────────────────────

interface SSLInfo { https: boolean; valid: boolean; expirationDate: string | null; daysRemaining: number; message: string; totalValidityDays?: number; }
interface TlsDetails { negotiatedProtocol: string; cipherSuite: string; weakProtocol: boolean; message: string; }
interface CorsResult { tested: boolean; allowOriginValue: string; wildcardOrigin: boolean; reflectsOrigin: boolean; credentialsAllowed: boolean; nullOriginAccepted: boolean; message: string; }
interface CookieFinding { name: string; httpOnly: boolean; secure: boolean; sameSite: string; risk: string; issues: string; }
interface PortFinding { port: number; service: string; state: string; severity: string; latencyMs: number; evidence: string; impact: string; recommendation: string; }
interface SecurityIssue { id: string; title: string; severity: string; impact: string; recommendation: string; }
interface ScoreResult { score: number; riskLevel: string; notes: string[]; issues: SecurityIssue[]; }
interface SensitiveFileFinding { path: string; statusCode: number; exposure: string; contentPreview: string | null; severity: string; }
interface HttpMethodFinding { method: string; statusCode: number; enabled: boolean; severity: string; risk: string; }
interface OpenRedirectFinding { parameter: string; testedUrl: string; redirectedTo: string; vulnerable: boolean; severity: string; }
interface DirectoryListingFinding { path: string; statusCode: number; listingEnabled: boolean; evidence: string; severity: string; }
interface DnsSecurityResult { spfPresent: boolean; spfRecord: string | null; spfPolicy: string; dmarcPresent: boolean; dmarcRecord: string | null; dmarcPolicy: string; dkimHintFound: boolean; dkimSelector: string | null; caaPresent: boolean; caaRecord: string | null; mxPresent: boolean; mxRecords: string[]; emailSpoofingRisk: string; summary: string; lookupFailed?: boolean; }
interface WafDetectionResult { detected: boolean; provider: string | null; confidence: string | null; evidence: string | null; probeResponse: string | null; summary: string; }
interface CVEFinding { cveId: string; severity: string; cvssScore: number; description: string; affectedSoftware: string; publishedDate: string; referenceUrl: string; }
interface CertEntry { commonName: string; issuer: string; notBefore: string; notAfter: string; wildcard: boolean; loggedAt: string; }
interface CertTransparencyResult {
  totalCertificates: number; uniqueSubdomains: number;
  mostRecentIssuance: string | null; oldestIssuance: string | null;
  recentlyIssued: boolean; wildcardDetected: boolean; unexpectedIssuer: boolean;
  discoveredSubdomains: string[]; issuers: string[];
  unexpectedIssuers: string[]; wildcardDomains: string[];
  recentCerts: CertEntry[];
}
interface SubdomainTakeoverFinding { subdomain: string; cnameTarget: string; service: string; vulnerability: string; evidence: string; severity: string; status: string; }
interface ScanChange { category: string; field: string; changeType: string; oldValue: string; newValue: string; severity: string; description: string; }
interface TechFingerprintResult { webServer: string | null; backend: string | null; framework: string | null; cms: string | null; cdn: string | null; language: string | null; libraries: string[]; evidence: string[]; }
interface RelatedHostHeaders { host: string; reachable: boolean; headers: Record<string, string>; missingCount: number; }
interface ScanResult {
  url: string; finalUrl: string; analyzedHost?: string | null; httpStatus: number; redirectsToHttps: boolean;
  sslInfo: SSLInfo; tlsDetails: TlsDetails; headers: Record<string, string>;
  serverVersionExposed: boolean; activeMode: boolean; inputSurfaceDetected: boolean;
  dbErrorLeakageSuspected: boolean; xssProbePerformed: boolean; reflectedXssSuspected: boolean;
  openPorts: PortFinding[]; corsResult: CorsResult; cookieIssues: CookieFinding[];
  sensitiveRobotsPaths: string[]; sensitiveFiles: SensitiveFileFinding[];
  dangerousHttpMethods: HttpMethodFinding[]; securityTxtPresent: boolean;
  securityTxtContact: string | null; openRedirectFindings: OpenRedirectFinding[];
  directoryListingFindings: DirectoryListingFinding[]; score: ScoreResult;
  dnsSecurityResult: DnsSecurityResult | null; wafDetectionResult: WafDetectionResult | null;
  techFingerprint: TechFingerprintResult | null;
  relatedHostHeaders?: RelatedHostHeaders[];
  cveFindings: CVEFinding[];
  changes: ScanChange[];
  subdomainTakeover: SubdomainTakeoverFinding[];
  certTransparency: CertTransparencyResult | null;
  apiDocsExposure: ApiDocsExposureFinding[];
  graphQlIntrospection: GraphQlIntrospectionFinding[];
  jwtSecurity: JwtSecurityFinding[];
  pathTraversal: PathTraversalFinding[];
  ssrfFindings: SsrfFinding[];
  hostHeaderFindings: HostHeaderFinding[];
  sourceMapFindings: SourceMapFinding[];
  crlfFindings: CrlfFinding[];
  compliance?: ComplianceReport;
  /** true p/ guest/FREE: issues vêm sem impacto/correção e o breakdown fica travado. */
  detailsLocked?: boolean;
}
interface ApiDocsExposureFinding { path: string; type: string; severity: string; evidence: string | null; description: string; }
interface GraphQlIntrospectionFinding { endpoint: string; introspectionEnabled: boolean; playgroundExposed: boolean; typeCount: number; severity: string; evidence: string | null; }
interface JwtSecurityFinding { source: string; algorithm: string; hasExpiry: boolean; expired: boolean; hasIssuer: boolean; hasAudience: boolean; issues: string[]; severity: string; evidence: string | null; }
interface PathTraversalFinding { parameter: string; payload: string; target: string; evidence: string | null; severity: string; }
interface SsrfFinding { parameter: string; payload: string; indicator: string; evidence: string | null; severity: string; }
interface HostHeaderFinding { injectedHeader: string; injectedValue: string; reflectionPoint: string; evidence: string | null; severity: string; }
interface SourceMapFinding { type: string; url: string; evidence: string | null; severity: string; }
interface CrlfFinding { parameter: string; payload: string; injectionType: string; evidence: string | null; severity: string; }
interface AsyncStatus { state: "PENDING" | "RUNNING" | "DONE" | "ERROR"; result: ScanResult | null; errorMessage: string | null; }
interface ScheduledScanDto {
  id: string;
  host: string;
  active: boolean;
  frequency: "DAILY" | "WEEKLY";
  preferredHour: number;
  nextRun: string | null;
  lastRun: string | null;
  enabled: boolean;
  notifyEmail: boolean;
  createdAt: string;
}
interface OwnershipState { message: string; host: string; token: string | null; passiveResult: ScanResult | null; }
interface GuestStatus { used: number; remaining: number; dailyLimit: number; resetsAt: string; }
interface UserManagementDto { id: string; name: string; email: string; role: string; jobTitle: string | null; active: boolean; createdAt: string; invitedByName: string; }
interface InviteDto { id: string; name: string; email: string; role: string; jobTitle: string | null; invitedByName: string; accepted: boolean; expired: boolean; expiresAt: string; acceptLink: string | null; }
interface DomainDto { id: string; host: string; verified: boolean; verifiedAt: string | null; createdAt: string; verificationToken: string; }

type View = "scan" | "login" | "admin" | "schedules" | "domains" | "changes" | "settings";

// ── Utilities ─────────────────────────────────────────────────────────────────

function getInviteTokenFromUrl(): string | null {
  const path = window.location.pathname;
  const match = path.match(/\/auth\/accept-invite\/([a-f0-9-]+)/);
  return match ? match[1] : null;
}
function getStatusTokenFromUrl(): string | null {
  const path = window.location.pathname;
  const match = path.match(/\/status\/([a-f0-9]{32,64})/);
  return match ? match[1] : null;
}
/** Token do link de redefinição: /redefinir-senha?token=... (64 hex). */
function getResetTokenFromUrl(): string | null {
  if (window.location.pathname !== "/redefinir-senha") return null;
  const token = new URLSearchParams(window.location.search).get("token");
  return token && /^[a-f0-9]{64}$/.test(token) ? token : null;
}
function isBillingReturnPath(): boolean {
  return window.location.pathname === "/billing/return";
}
function riskColor(level?: string) {
  if (level === "SECURE")   return styles.secure;
  if (level === "LOW")      return styles.low;
  if (level === "MEDIUM")   return styles.warning;
  if (level === "HIGH")     return styles.high;
  if (level === "CRITICAL") return styles.critical;
  // legacy alias
  if (level === "WARNING")  return styles.warning;
  return styles.muted;
}
function sevColor(sev?: string) {
  const s = (sev ?? "").toUpperCase();
  if (s === "CRITICAL") return styles.critical;
  if (s === "HIGH") return styles.high;
  if (s === "MEDIUM") return styles.warning;
  if (s === "LOW") return styles.low;
  return styles.info;
}
function boolIcon(v: boolean, t = "✓", f = "✗") {
  return <span className={v ? styles.ok : styles.bad}>{v ? t : f}</span>;
}
function downloadBlob(blob: Blob, filename: string) {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  a.remove(); window.URL.revokeObjectURL(url);
}

// ── Small Components ──────────────────────────────────────────────────────────

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
function Section({ title, children, defaultOpen = true }: {
  title: string; children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  useEffect(() => { setOpen(defaultOpen); }, [defaultOpen]);
  return (
    <div className={styles.section}>
      <button className={styles.sectionHeader} onClick={() => setOpen(o => !o)}>
        <span className={`${styles.chevron} ${open ? styles.chevronOpen : ""}`}>›</span>
        <span className={styles.sectionTitle}>{title}</span>
      </button>
      {open && <div className={styles.sectionBody}>{children}</div>}
    </div>
  );
}
function Card({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <div className={styles.card}>
      {title && <div className={styles.cardTitle}>{title}</div>}
      {children}
    </div>
  );
}

// ── Score Gauge ───────────────────────────────────────────────────────────────

function ScoreGauge({ score, risk }: { score: number; risk: string }) {
  const color = risk === "SECURE" ? "var(--secure)"
              : risk === "LOW"    ? "var(--info)"
              : risk === "MEDIUM" ? "var(--warning)"
              : risk === "HIGH"   ? "var(--high)"
              : "var(--critical)";
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

// ── Issue Item ────────────────────────────────────────────────────────────────

function IssueItem({ issue, onContest, locked, onUpgrade }: { issue: SecurityIssue; onContest?: (findingLabel: string) => void; locked?: boolean; onUpgrade?: () => void }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const safeTitle = issue.title ?? "";
  // HIGH/MEDIUM em guest/FREE vêm com título nulo do backend — esconde o "o quê" do problema
  const titleHidden = !!locked && !issue.title;
  const isCve = (issue.id ?? "").startsWith("CVE_");
  // recommendation/impact vêm null quando o plano não tem acesso (guest/FREE) — guarda contra null
  const recommendation = issue.recommendation ?? "";
  const refMatch = recommendation.match(/Ref:\s*(https?:\/\/\S+)/);
  const refUrl   = refMatch ? refMatch[1] : null;
  const fixText  = refUrl ? recommendation.replace(/\s*Ref:\s*https?:\/\/\S+/, "").trim() : recommendation;
  // Extract CVE ID from title (e.g. "CVE-2021-41773 — ...")
  const cveIdMatch = safeTitle.match(/^(CVE-\d{4}-\d+)/);
  const cveId = cveIdMatch ? cveIdMatch[1] : null;

  return (
    <div className={`${styles.issue} ${sevColor(issue.severity)}`}>
      <button className={styles.issueHeader} onClick={() => setOpen(o => !o)}>
        <span className={`${styles.issueSev} ${sevColor(issue.severity)}`}>{issue.severity}</span>
        {isCve && !titleHidden && <span className={styles.issueCveBadge}>CVE</span>}
        <span className={styles.issueTitle}>
          {titleHidden
            ? <span style={{ display: "inline-block", height: 11, width: 170, maxWidth: "55%", background: "var(--border2)", borderRadius: 3, verticalAlign: "middle", filter: "blur(1.5px)" }} />
            : safeTitle}
        </span>
        {titleHidden && <span style={{ fontSize: 11, marginLeft: 4 }}>🔒</span>}
        <span className={`${styles.chevron} ${open ? styles.chevronOpen : ""}`}>›</span>
      </button>
      {open && (
        <div className={styles.issueBody}>
          {locked ? (
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span style={{ fontSize: 18 }}>🔒</span>
              <span style={{ fontSize: 12, color: "var(--text-dim)", flex: 1, minWidth: 180 }}>
                <strong style={{ color: "var(--text)" }}>{t("achado.impactoCorrecao")}</strong> disponíveis nos planos pagos.
              </span>
              {onUpgrade && (
                <button className={`${styles.btn} ${styles.btnScan} ${styles.btnSm}`} onClick={onUpgrade}>
                  Ver planos →
                </button>
              )}
            </div>
          ) : (
          <>
          <div><span className={styles.label}>IMPACTO</span> {issue.impact}</div>
          <div>
            <span className={styles.label}>{t("achado.correcao")}</span> {fixText}
            {refUrl && cveId && (
              <a href={refUrl} target="_blank" rel="noopener noreferrer" className={styles.issueCveLink}>
                Ver {cveId} no NVD ↗
              </a>
            )}
          </div>
          </>
          )}
          {onContest && (
            <div style={{ marginTop: 8 }}>
              <button
                onClick={() => onContest(issue.title)}
                title={t("achado.contestar")}
                style={{ background: "none", border: "none", color: "var(--text-muted)", fontSize: 11, cursor: "pointer", padding: 0, textDecoration: "underline" }}
              >
                ⚑ Isso está errado?
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Ghost travado (breakdown gated p/ guest/FREE) ─────────────────────────────

function LockedGhost({ onUpgrade, rows = 4 }: { onUpgrade: () => void; rows?: number }) {
  const { t } = useI18n();
  return (
    <div style={{ position: "relative", minHeight: 96 }}>
      <div style={{ filter: "blur(5px)", pointerEvents: "none", userSelect: "none", opacity: 0.4 }}>
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 11 }}>
            <div style={{ height: 8, width: `${68 - i * 9}%`, background: "var(--border2)", borderRadius: 3 }} />
            <div style={{ height: 8, width: 22, background: "var(--border)", borderRadius: 3, marginLeft: "auto" }} />
          </div>
        ))}
      </div>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 8, textAlign: "center", padding: 8 }}>
        <div style={{ fontSize: 22 }}>🔒</div>
        <div style={{ fontSize: 11, color: "var(--text-dim)", maxWidth: 230, lineHeight: 1.5 }}>
          Breakdown detalhado disponível nos planos pagos.
        </div>
        <button className={`${styles.btn} ${styles.btnScan} ${styles.btnSm}`} onClick={onUpgrade}>{t("bloqueio.verPlanos")}</button>
      </div>
    </div>
  );
}

// ── Módulo travado (detalhe gated p/ guest/FREE) ──────────────────────────────

function ModuleLocked({ onUpgrade }: { onUpgrade: () => void }) {
  const { t } = useI18n();
  return (
    <div style={{ position: "relative", minHeight: 280, borderRadius: "var(--radius)", overflow: "hidden" }}>
      <div style={{ filter: "blur(6px)", pointerEvents: "none", userSelect: "none", opacity: 0.3 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: 14, minHeight: 92 }}>
              <div style={{ height: 9, width: "55%", background: "var(--border2)", borderRadius: 3, marginBottom: 10 }} />
              <div style={{ height: 7, width: "85%", background: "var(--border)", borderRadius: 3, marginBottom: 5 }} />
              <div style={{ height: 7, width: "70%", background: "var(--border)", borderRadius: 3 }} />
            </div>
          ))}
        </div>
      </div>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 10, textAlign: "center", padding: 24, background: "linear-gradient(to bottom, transparent, var(--bg) 62%)" }}>
        <div style={{ fontSize: 30 }}>🔒</div>
        <div style={{ fontFamily: "var(--mono)", fontSize: 13, fontWeight: 700, color: "var(--text)", letterSpacing: ".5px" }}>{t("bloqueio.detalheModulo")}</div>
        <div style={{ fontSize: 12, color: "var(--text-dim)", maxWidth: 380, lineHeight: 1.7 }}>
          Evidências, riscos e correções de cada módulo estão disponíveis nos planos pagos.
        </div>
        <button className={`${styles.btn} ${styles.btnScan}`} onClick={onUpgrade} style={{ marginTop: 4 }}>{t("bloqueio.verPlanos")}</button>
      </div>
    </div>
  );
}

/**
 * Página inteira travada por plano (Agendamentos, Domínios).
 *
 * Mantém o item no menu de propósito: o usuário FREE precisa ver que o recurso
 * existe para ter motivo de assinar. Esconder o menu economiza um clique e perde
 * a conversão. O bloqueio real é do backend — isto aqui é só o aviso.
 */
function PagePlanLocked({ titulo, descricao, onUpgrade }: { titulo: string; descricao: string; onUpgrade: () => void }) {
  const { t } = useI18n();
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 12, textAlign: "center", padding: "72px 24px", minHeight: 280 }}>
      <div style={{ fontSize: 30, lineHeight: 1 }}>🔒</div>
      <div style={{ fontSize: 15, fontWeight: 600 }}>{titulo}</div>
      <div style={{ fontSize: 12, color: "var(--text-dim)", maxWidth: 420, lineHeight: 1.7 }}>{descricao}</div>
      <button className={`${styles.btn} ${styles.btnScan}`} onClick={onUpgrade} style={{ marginTop: 4 }}>{t("bloqueio.verPlanos")}</button>
    </div>
  );
}

// ── Feedback (contestação de achados) ─────────────────────────────────────────

type FeedbackStatus = "OPEN" | "REVIEWING" | "RESOLVED";

interface FeedbackDto {
  id: string;
  scanId: string | null;
  host: string;
  module: string | null;
  findingLabel: string | null;
  message: string;
  status: FeedbackStatus;
  adminResponse: string | null;
  submittedByName: string | null;
  submittedByEmail: string | null;
  reviewedByName: string | null;
  createdAt: string;
  updatedAt: string | null;
  resolvedAt: string | null;
  /** Preenchido quando a equipe excluiu a contestação — vale com deletionReason. */
  deletedAt: string | null;
  deletionReason: string | null;
}

interface FeedbackTarget {
  host: string;
  scanId?: string | null;
  module?: string | null;
  findingLabel?: string | null;
}

/** Devolve a CHAVE do catálogo; quem renderiza resolve — a função vive fora de componente. */
function fbStatusKey(s: FeedbackStatus) {
  return s === "OPEN" ? "feedback.aberto" : s === "REVIEWING" ? "feedback.emAnalise" : "feedback.resolvido";
}
function fbStatusColor(s: FeedbackStatus) {
  return s === "OPEN" ? "var(--warning, #f5a623)"
    : s === "REVIEWING" ? "var(--info, #4aa3ff)"
    : "var(--secure, #00c87a)";
}

const RESPOSTAS_VISTAS_KEY = "cyberaudit.feedbackRespostasVistas";

/** Uma contestação só conta como respondida quando há texto da equipe. */
function temResposta(f: FeedbackDto): boolean {
  return !!(f.adminResponse && f.adminResponse.trim()) || !!f.deletionReason;
}

/**
 * Identidade da resposta, não do feedback: se a equipe responder de novo depois
 * de o cliente dispensar o aviso, o carimbo muda e o aviso volta.
 */
function chaveResposta(f: FeedbackDto): string {
  return `${f.id}:${f.deletedAt ?? f.updatedAt ?? ""}`;
}

function lerVistas(): string[] {
  try { return JSON.parse(localStorage.getItem(RESPOSTAS_VISTAS_KEY) ?? "[]"); }
  catch { return []; }
}

/**
 * Aviso na tela principal quando a equipe respondeu uma contestação.
 *
 * Antes a resposta só aparecia dentro do modal de contestação, que por sua vez
 * só abre a partir de um resultado de scan na tela — ou seja, o cliente tinha de
 * refazer o scan do host certo para descobrir que havia resposta. Aqui a resposta
 * é mostrada direto: não há motivo para exigir um scan novo só para ler um texto
 * que já está na API (/feedback/mine).
 */
function AvisoRespostasFeedback() {
  const { t } = useI18n();
  const [itens, setItens]   = useState<FeedbackDto[]>([]);
  const [aberto, setAberto] = useState(false);
  const [vistas, setVistas] = useState<string[]>(lerVistas);

  useEffect(() => {
    api.get<FeedbackDto[]>("/feedback/mine")
      .then(r => setItens(r.data.filter(temResposta)))
      .catch(() => {});
  }, []);

  const naoLidas = itens.filter(f => !vistas.includes(chaveResposta(f)));
  if (naoLidas.length === 0) return null;

  function dispensar() {
    const novo = [...vistas, ...naoLidas.map(chaveResposta)];
    setVistas(novo);
    try { localStorage.setItem(RESPOSTAS_VISTAS_KEY, JSON.stringify(novo)); } catch { /* modo privado */ }
  }

  return (
    <div style={{ border: "1px solid var(--accent)", borderRadius: "var(--radius)", background: "var(--surface)", padding: "12px 14px", marginBottom: 14 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <span style={{ fontSize: 15 }}>✉</span>
        <span style={{ fontSize: 13, color: "var(--text)", fontWeight: 600 }}>
          {naoLidas.length === 1
            ? t("feedback.respondida")
            : `${naoLidas.length} contestações suas foram respondidas`}
        </span>
        <button
          className={`${styles.btn} ${styles.btnGhost} ${styles.btnSm}`}
          style={{ marginLeft: "auto" }}
          onClick={() => setAberto(a => !a)}
        >
          {aberto ? "Ocultar" : "Ver resposta"}
        </button>
        <button className={`${styles.btn} ${styles.btnGhost} ${styles.btnSm}`} onClick={dispensar}>
          Dispensar
        </button>
      </div>

      {aberto && (
        <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 10 }}>
          {naoLidas.map(f => (
            <div key={f.id} style={{ border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "10px 12px" }}>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>
                <code className={styles.code}>{f.host}</code>
                <span style={{ marginLeft: 6 }}>{f.findingLabel || f.module || t("feedback.scanInteiro")}</span>
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>{t("feedback.voceEscreveu")}</div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", whiteSpace: "pre-wrap", marginBottom: 8 }}>{f.message}</div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                {f.deletionReason ? t("feedback.equipeEncerrou") : t("feedback.respostaEquipe")}
              </div>
              <div style={{ fontSize: 13, color: "var(--text)", whiteSpace: "pre-wrap" }}>
                {f.deletionReason ?? f.adminResponse}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Modal do cliente: contesta um achado/módulo/scan e vê respostas anteriores. */
function FeedbackModal({ target, onClose }: { target: FeedbackTarget; onClose: () => void }) {
  const { t } = useI18n();
  const [message, setMessage] = useState("");
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mine, setMine] = useState<FeedbackDto[]>([]);

  const targetLabel = target.findingLabel || target.module || t("feedback.scanInteiro");

  useEffect(() => {
    api.get<FeedbackDto[]>("/feedback/mine")
      .then(r => setMine(r.data.filter(f => f.host === target.host)))
      .catch(() => {});
  }, [target.host, sent]);

  async function submit() {
    if (!message.trim()) { setError(t("feedback.descreva")); return; }
    setSending(true); setError(null);
    try {
      await api.post("/feedback", {
        scanId: target.scanId ?? null,
        host: target.host,
        module: target.module ?? null,
        findingLabel: target.findingLabel ?? null,
        message: message.trim(),
      });
      setSent(true); setMessage("");
    } catch (e: any) {
      setError(e?.response?.data?.message ?? t("feedback.erroEnviar"));
    } finally { setSending(false); }
  }

  return (
    <div className={styles.modalOverlay} onClick={onClose}>
      <div className={styles.modal} onClick={e => e.stopPropagation()} style={{ maxWidth: 720, width: "94vw" }}>
        <div className={styles.modalHeader}>
          <span className={styles.modalTitle}>{t("feedback.contestar")}</span>
          <button className={styles.modalClose} onClick={onClose}>✕</button>
        </div>
        <div className={styles.modalBody}>
          {sent ? (
            <div style={{ textAlign: "center", padding: "12px 0" }}>
              <div style={{ fontSize: 32, marginBottom: 8, color: "var(--secure)" }}>✓</div>
              <div style={{ color: "var(--text)", fontWeight: 600, marginBottom: 4 }}>{t("feedback.enviado")}</div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>{t("feedback.obrigado")}</div>
              <button className={`${styles.btn} ${styles.btnGhost}`} style={{ marginTop: 16 }} onClick={() => setSent(false)}>
                Enviar outro
              </button>
            </div>
          ) : (
            <>
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 12 }}>
                Contestando <strong style={{ color: "var(--text)" }}>{targetLabel}</strong> em <code className={styles.code}>{target.host}</code>. Explique por que acredita que o resultado está errado.
              </div>
              <div className={styles.formGroup}>
                <label className={styles.formLabel}>{t("feedback.oQueErrado")}</label>
                <textarea
                  className={styles.formInput}
                  rows={10}
                  value={message}
                  maxLength={4000}
                  onChange={e => setMessage(e.target.value)}
                  style={{ minHeight: 180, resize: "vertical", lineHeight: 1.6 }}
                  placeholder={t("feedback.phMensagem")}
                />
                <div style={{ fontSize: 10, color: "var(--text-muted)", textAlign: "right", marginTop: 4 }}>
                  {message.length}/4000
                </div>
              </div>
              {error && <div className={styles.errorBox}>{error}</div>}
              <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={sending} onClick={submit}>
                {sending ? t("comum.enviando") : t("feedback.enviarContestacao")}
              </button>
            </>
          )}

          {mine.length > 0 && (
            <div style={{ marginTop: 18, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
              <div className={styles.formLabel} style={{ marginBottom: 8 }}>{t("feedback.seusFeedbacks")}</div>
              {mine.map(f => (
                <div key={f.id} style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "8px 10px", marginBottom: 8 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                    <span style={{ fontSize: 12, color: "var(--text)" }}>{f.findingLabel || f.module || t("feedback.scanInteiro")}</span>
                    <span style={{ fontSize: 10, fontWeight: 700, color: f.deletedAt ? "var(--text-muted)" : fbStatusColor(f.status) }}>
                      {f.deletedAt ? t("feedback.encerrada") : t(fbStatusKey(f.status))}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 3, whiteSpace: "pre-wrap" }}>{f.message}</div>
                  {f.adminResponse && (
                    <div style={{ fontSize: 11, color: "var(--text)", marginTop: 6, paddingLeft: 8, borderLeft: "2px solid var(--secure)" }}>
                      <strong>Resposta:</strong> {f.adminResponse}
                    </div>
                  )}
                  {f.deletionReason && (
                    <div style={{ fontSize: 11, color: "var(--text)", marginTop: 6, paddingLeft: 8, borderLeft: "2px solid var(--text-muted)", whiteSpace: "pre-wrap" }}>
                      <strong>{t("feedback.encerradaPelaEquipe")}</strong> {f.deletionReason}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** Linha de triagem de um feedback no painel admin (resposta + status). */
function FeedbackAdminRow({ f, onReply, onDelete }: {
  f: FeedbackDto;
  onReply: (id: string, resp: string, status: FeedbackStatus) => Promise<void>;
  onDelete: (id: string, reason: string) => Promise<void>;
}) {
  const { t } = useI18n();
  const [resp, setResp] = useState(f.adminResponse ?? "");
  const [status, setStatus] = useState<FeedbackStatus>(f.status);
  const [saving, setSaving] = useState(false);
  // A justificativa só aparece depois de pedir a exclusão — e sem ela o botão
  // não fecha, porque é ela que o cliente vai ler no lugar da contestação.
  const [confirmandoExclusao, setConfirmandoExclusao] = useState(false);
  const [motivo, setMotivo] = useState("");
  const [excluindo, setExcluindo] = useState(false);
  const [erroExclusao, setErroExclusao] = useState<string | null>(null);

  return (
    <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "12px 14px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 6 }}>
        <div>
          <code className={styles.code}>{f.host}</code>
          <span style={{ marginLeft: 8, fontSize: 12, color: "var(--text)" }}>{f.findingLabel || f.module || t("feedback.scanInteiro")}</span>
        </div>
        <span style={{ fontSize: 10, fontWeight: 700, color: fbStatusColor(f.status) }}>{t(fbStatusKey(f.status))}</span>
      </div>
      <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
        {f.submittedByName ?? f.submittedByEmail ?? "—"} · {new Date(f.createdAt).toLocaleString("pt-BR")}
      </div>
      <div style={{ fontSize: 13, color: "var(--text)", marginBottom: 10, whiteSpace: "pre-wrap" }}>{f.message}</div>
      <textarea
        className={styles.formInput}
        rows={7}
        value={resp}
        onChange={e => setResp(e.target.value)}
        style={{ minHeight: 140, resize: "vertical", lineHeight: 1.6 }}
        placeholder={t("feedback.phResposta")}
      />
      <div style={{ display: "flex", gap: 8, marginTop: 8, alignItems: "center" }}>
        <select className={styles.roleSelect} value={status} onChange={e => setStatus(e.target.value as FeedbackStatus)}>
          <option value="OPEN">Aberto</option>
          <option value="REVIEWING">{t("feedback.emAnalise")}</option>
          <option value="RESOLVED">Resolvido</option>
        </select>
        <button
          className={`${styles.btn} ${styles.btnScan} ${styles.btnSm}`}
          disabled={saving}
          onClick={async () => { setSaving(true); try { await onReply(f.id, resp, status); } finally { setSaving(false); } }}
        >
          {saving ? t("comum.salvando") : "Salvar"}
        </button>
        {!confirmandoExclusao && (
          <button
            className={`${styles.btn} ${styles.btnGhost} ${styles.btnSm}`}
            style={{ marginLeft: "auto", color: "var(--critical)", borderColor: "var(--critical)" }}
            onClick={() => { setConfirmandoExclusao(true); setErroExclusao(null); }}
          >
            Excluir
          </button>
        )}
      </div>

      {confirmandoExclusao && (
        <div style={{ marginTop: 12, borderTop: "1px solid var(--border)", paddingTop: 12 }}>
          <label className={styles.formLabel}>{t("feedback.porQueExcluindo")}</label>
          <div style={{ fontSize: 11, color: "var(--text-muted)", margin: "4px 0 8px" }}>
            Esta justificativa aparece para {f.submittedByName ?? t("feedback.quemEnviou")} no lugar da contestação.
          </div>
          <textarea
            className={styles.formInput}
            rows={5}
            value={motivo}
            maxLength={4000}
            onChange={e => setMotivo(e.target.value)}
            style={{ minHeight: 110, resize: "vertical", lineHeight: 1.6 }}
            placeholder={t("feedback.phMotivoExclusao")}
          />
          {erroExclusao && <div className={styles.errorBox} style={{ marginTop: 8 }}>{erroExclusao}</div>}
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            <button
              className={`${styles.btn} ${styles.btnSm}`}
              style={{ background: "var(--critical)", color: "#fff" }}
              disabled={excluindo || !motivo.trim()}
              onClick={async () => {
                setExcluindo(true); setErroExclusao(null);
                try { await onDelete(f.id, motivo.trim()); }
                catch (e: any) {
                  setErroExclusao(e?.response?.data?.message ?? t("feedback.erroExcluir"));
                  setExcluindo(false);
                }
              }}
            >
              {excluindo ? t("feedback.excluindo") : t("feedback.confirmarExclusao")}
            </button>
            <button
              className={`${styles.btn} ${styles.btnGhost} ${styles.btnSm}`}
              disabled={excluindo}
              onClick={() => { setConfirmandoExclusao(false); setMotivo(""); setErroExclusao(null); }}
            >
              Cancelar
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Terminal Loader ───────────────────────────────────────────────────────────

// ── Slow Scan Toast ───────────────────────────────────────────────────────────

function SlowScanToast({ visible }: { visible: boolean }) {
  const { t } = useI18n();
  const [expanded, setExpanded] = useState(false);
  const checks = [
    { icon: "⬟", label: "SSL / TLS",         detail: "Handshake real + validação do certificado" },
    { icon: "⬡", label: "Security Headers",   detail: "Analisa 8+ headers na resposta HTTP" },
    { icon: "◉", label: "DNS Security",       detail: "Consultas DNS: SPF, DMARC, DKIM, CAA, MX" },
    { icon: "⟨⟩", label: t("toast.techFingerprint"),  detail: t("toast.techFingerprintDesc") },
    { icon: "◈", label: "CVE Lookup",         detail: "Cruza versões detectadas com base NVD/CVE" },
    { icon: "▣", label: "WAF & Port Scan",    detail: "Probes ativos + 21 portas (modo ACTIVE)" },
  ];
  if (!visible) return null;
  return (
    <div style={{
      position: "fixed", bottom: 24, right: 24, zIndex: 9999,
      fontFamily: "var(--mono)", display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 8,
    }}>
      {expanded && (
        <div style={{
          width: 320, background: "var(--surface)",
          border: "1px solid rgba(0,212,160,.25)", borderRadius: "var(--radius)",
          boxShadow: "0 8px 32px rgba(0,0,0,.7)",
          overflow: "hidden", animation: "fadeUp .25s ease",
        }}>
          <div style={{ height: 2, background: "linear-gradient(90deg, var(--accent), var(--info))" }} />
          <div style={{ padding: "12px 14px", borderBottom: "1px solid rgba(255,255,255,.06)" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text)", letterSpacing: ".5px" }}>{t("toast.porQue")}</div>
            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>{t("toast.cadaModulo")}</div>
          </div>
          <div style={{ padding: "10px 14px", display: "flex", flexDirection: "column", gap: 6 }}>
            {checks.map((c, i) => (
              <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <span style={{ color: "var(--accent)", fontSize: 12, marginTop: 1, flexShrink: 0 }}>{c.icon}</span>
                <div>
                  <span style={{ fontSize: 10, fontWeight: 600, color: "var(--text)", marginRight: 6 }}>{c.label}</span>
                  <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{c.detail}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      <button
        onClick={() => setExpanded(v => !v)}
        style={{
          display: "flex", alignItems: "center", gap: 8,
          padding: "8px 14px",
          background: "var(--surface)",
          border: "1px solid rgba(0,212,160,.35)",
          borderLeft: "3px solid var(--accent)",
          borderRadius: "var(--radius)",
          boxShadow: "0 4px 16px rgba(0,0,0,.6)",
          cursor: "pointer", fontFamily: "var(--mono)", color: "var(--text)",
          fontSize: 11, animation: "fadeUp .3s ease",
        }}
      >
        <span style={{ color: "var(--warning)", fontSize: 13 }}>⏱</span>
        <span>{t("toast.demorando")} <span style={{ color: "var(--accent)" }}>{expanded ? t("toast.fechar") : t("toast.verCausas")}</span></span>
      </button>
    </div>
  );
}

// ── Severity → CSS var helpers ───────────────────────────────────────────────

function sev2var(sev?: string): string {
  const s = (sev ?? "").toUpperCase();
  if (s === "CRITICAL") return "var(--critical)";
  if (s === "HIGH")     return "var(--high)";
  if (s === "MEDIUM")   return "var(--warning)";
  if (s === "LOW")      return "var(--low)";
  if (s === "SECURE")   return "var(--secure)";
  return "var(--info)";
}
function worstVar(items: { severity?: string }[]): string {
  if (!items?.length) return "var(--secure)";
  for (const lv of ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    if (items.some(i => (i.severity ?? "").toUpperCase() === lv)) return sev2var(lv);
  return "var(--info)";
}

// ── Sidebar Nav Item ─────────────────────────────────────────────────────────

// ── Module info descriptions ─────────────────────────────────────────────────

const MODULE_INFO: Record<string, { title: string; icon: string; what: string; does: string; tip: string }> = {
  issues:    { title: "Issues", icon: "⚠", what: "Painel consolidado de todas as vulnerabilidades detectadas no scan.", does: "Lista cada problema encontrado com severidade (CRITICAL → LOW), impacto descrito e recomendação objetiva de correção. É o ponto de partida para priorizar o que corrigir primeiro.", tip: "Comece pelos itens CRITICAL e HIGH — são os que mais comprometem o score e representam risco real de exploração." },
  headers:   { title: "Security Headers", icon: "⬡", what: "Verifica a presença e configuração dos headers HTTP de segurança enviados pelo servidor.", does: "Analisa 8+ headers: Content-Security-Policy, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options, entre outros. Cada header ausente ou mal configurado aumenta a superfície de ataque.", tip: "HSTS e CSP são os mais críticos. Um site sem HSTS pode ser atacado via downgrade para HTTP mesmo com HTTPS ativo." },
  transport: { title: "Transport Security", icon: "⬟", what: "Analisa a camada de criptografia SSL/TLS que protege a comunicação entre o usuário e o servidor.", does: "Verifica validade do certificado, protocolo negociado (TLS 1.2/1.3), cipher suite utilizado, data de expiração e dias restantes. Protocolos antigos (SSLv3, TLS 1.0/1.1) são considerados inseguros.", tip: "Certificados expirados ou protocolos fracos ativam avisos de segurança no navegador e afastam usuários instantaneamente." },
  http:      { title: "HTTP Methods", icon: "⚙", what: "Testa quais métodos HTTP o servidor aceita além do GET/POST padrão.", does: "Envia requisições com métodos PUT, DELETE, PATCH, TRACE, OPTIONS e HEAD. Métodos como TRACE e PUT habilitados podem permitir upload de arquivos maliciosos ou revelar headers internos via XSS refletido.", tip: "TRACE deve estar sempre desabilitado. PUT/DELETE só devem existir em APIs protegidas por autenticação." },
  redirect:  { title: "Open Redirect", icon: "↪", what: "Detecta endpoints da aplicação que redirecionam usuários para URLs externas sem validação.", does: "Injeta URLs maliciosas nos parâmetros de redirecionamento comuns (returnUrl, next, redirect, url, etc.) e verifica se o servidor segue o redirecionamento. Explorado em ataques de phishing e bypass de OAuth.", tip: "Open Redirect é frequentemente subestimado — mas é usado para dar aparência legítima a links de phishing." },
  dirlist:   { title: "Directory Listing", icon: "◫", what: "Verifica se o servidor expõe a listagem de conteúdo de diretórios publicamente.", does: "Testa caminhos comuns (/uploads, /files, /static, /backup, etc.) para verificar se o servidor retorna listagem de arquivos em vez de erro 403. Permite que atacantes descubram arquivos sensíveis sem precisar adivinhar nomes.", tip: "Desative a opção 'Indexes' no Apache ou 'autoindex' no Nginx. Nunca armazene backups em diretórios públicos." },
  recon:     { title: "Reconnaissance DNS", icon: "◉", what: "Analisa os registros DNS do domínio relacionados à segurança de email e autoridade de certificados.", does: "Consulta registros SPF (anti-spoofing de email), DMARC (política de autenticação de email), DKIM, CAA (restringe quais CAs podem emitir certificados) e MX. Configurações ausentes facilitam spoofing e phishing.", tip: "SPF + DMARC juntos bloqueiam a maioria dos ataques de spoofing de email em nome do seu domínio." },
  cert:      { title: "Certificate Transparency", icon: "◑", what: "Consulta os logs públicos de CT (Certificate Transparency) para mapear todos os certificados já emitidos para o domínio.", does: "Retorna quantidade total de certificados, subdomínios descobertos via CT logs, emissoras (CAs) utilizadas, wildcards detectados e certificados emitidos recentemente. Útil para descoberta de infraestrutura e detecção de emissões não autorizadas.", tip: "Se aparecer um certificado de uma CA desconhecida, investigue imediatamente — pode indicar comprometimento." },
  takeover:  { title: "Subdomain Takeover", icon: "◎", what: "Detecta subdomínios que apontam para serviços externos desativados, permitindo que atacantes assumam o controle.", does: "Verifica CNAMEs que apontam para GitHub Pages, Heroku, Netlify, AWS S3, Azure e outros. Se o serviço foi deletado mas o DNS ainda aponta para ele, qualquer pessoa pode registrar esse serviço e servir conteúdo em nome do seu domínio.", tip: "Subdomínio takeover é silencioso e frequentemente não detectado por meses. Remova CNAMEs órfãos imediatamente." },
  tech:      { title: "Technology Stack", icon: "⟨⟩", what: "Identifica as tecnologias usadas pelo site através de análise de headers, body HTML e comportamento do servidor.", does: "Detecta servidor web (Apache, Nginx, IIS), framework (Laravel, Django, Rails), CMS (WordPress, Drupal), CDN (Cloudflare, Fastly) e linguagem. Tecnologias expostas publicamente podem direcionar ataques a CVEs específicos.", tip: "Oculte cabeçalhos como Server e X-Powered-By para não entregar informações de stack para atacantes." },
  cookies:   { title: "Cookie Security", icon: "☰", what: "Analisa os atributos de segurança de todos os cookies definidos pelo servidor.", does: "Verifica presença dos atributos Secure (só enviado via HTTPS), HttpOnly (inacessível ao JavaScript), SameSite (proteção CSRF) e escopo de domínio/path. Cookies de sessão sem esses atributos podem ser roubados via XSS ou enviados em ataques CSRF.", tip: "Todo cookie de sessão deve ter Secure + HttpOnly + SameSite=Strict ou Lax. Sem isso, uma vulnerabilidade XSS vira sequestro de conta." },
  cve:       { title: "CVE Correlation", icon: "◈", what: "Cruza as tecnologias detectadas com a base de dados pública de vulnerabilidades CVE/NVD.", does: "Usa as versões identificadas no módulo Technology para consultar o NVD e retornar CVEs conhecidos. Exibe CVSS score, nível de severidade e links de referência para cada vulnerabilidade. Versões desatualizadas podem ter exploits públicos disponíveis.", tip: "Um CVSS ≥ 9.0 com exploit público disponível deve ser tratado como emergência — atualize imediatamente." },
  changes:   { title: "Changes Since Last Scan", icon: "△", what: "Compara o resultado atual com o último scan registrado do mesmo domínio.", does: "Detecta configurações que melhoraram (IMPROVED), pioraram (DEGRADED) ou são novas (NEW) desde o scan anterior. Útil para monitorar o impacto de deploys e mudanças de infraestrutura na postura de segurança.", tip: "Use este módulo após cada deploy para garantir que nenhuma configuração de segurança foi acidentalmente removida." },
  apidocs:   { title: "API Docs Exposure", icon: "◈", what: "Detecta documentação de APIs (Swagger, OpenAPI, ReDoc) exposta publicamente sem autenticação.", does: "Testa 18 paths comuns (/swagger-ui, /api-docs, /openapi.json, etc.) e confirma com marcadores de conteúdo específicos. Exibe tipo de doc, severidade e evidência. Specs JSON/YAML são HIGH pois expõem todos os endpoints, parâmetros e modelos da API.", tip: "Coloque autenticação básica (ou desative completamente) nos endpoints de documentação em produção. Nunca exponha a spec completa da API publicamente." },
  graphql:   { title: "GraphQL Introspection", icon: "◈", what: "Detecta endpoints GraphQL com introspection habilitada ou interface interativa (GraphiQL/Playground) acessível publicamente.", does: "Envia a query { __schema { types { name } } } para 11 paths comuns. Se aceita, conta os tipos retornados — quanto mais tipos, mais informação exposta. Verifica também se há UI interativa via GET.", tip: "Desabilite introspection em produção. Em frameworks como Apollo, use 'introspection: false'. Nunca exponha o Playground publicamente." },
  jwt:       { title: "JWT Security", icon: "◈", what: "Analisa tokens JWT presentes em cookies ou headers de resposta em busca de configurações inseguras.", does: "Decodifica o header do JWT sem fazer requests adicionais (passivo). Verifica: alg:none (sem assinatura), algoritmos simétricos fracos (HS256), ausência de exp (token que nunca expira), tokens expirados sendo servidos, e ausência de iss/aud.", tip: "Use RS256 ou ES256, sempre inclua exp (máx 1h para tokens de acesso), valide iss e aud no backend. Nunca aceite alg:none." },
  crlf: { title: "CRLF Injection", icon: "◈", what: "Detecta HTTP Response Splitting via injeção de caracteres \\r\\n em parâmetros da query string. Permite ao atacante injetar headers HTTP arbitrários, set-cookies fraudulentos, XSS via header e cache poisoning.", does: "Injeta 4 variantes de CRLF (%0d%0a, %0a, %250d%250a, Unicode) em todos os parâmetros. Confirma vulnerabilidade se o header probe aparecer nos headers da resposta HTTP ou refletido no body.", tip: "Sanitize todos os parâmetros antes de usá-los em headers HTTP. Nunca reflita input do usuário em Location, Set-Cookie ou headers customizados sem remover caracteres de nova linha." },
  sourcemap: { title: "Source Map / Debug", icon: "◈", what: "Detecta vazamento de código-fonte via arquivos .map e exposição de endpoints de debug/diagnóstico (Spring Boot Actuator, Symfony Profiler, Laravel Debugbar, phpinfo, .env, etc.).", does: "Extrai URLs de scripts do HTML e verifica headers SourceMap/X-SourceMap; tenta acessar arquivos .js.map diretamente. Proba endpoints Actuator de alta severidade (env, beans, heapdump) e debug paths de frameworks conhecidos. Exige conteúdo JSON específico para evitar FPs em 404 customizados.", tip: "Remova source maps de builds de produção ou sirva-os apenas para IPs internos. Proteja endpoints Actuator com Spring Security e exponha apenas /health para checks externos." },
  hostheader: { title: "Host Header Injection", icon: "◈", what: "Detecta se o servidor reflete o valor do header Host (ou X-Forwarded-Host) na resposta, permitindo ataques de password-reset poisoning, cache poisoning e open redirect.", does: "Injeta um valor probe distinto nos headers Host, X-Forwarded-Host, X-Host, X-Forwarded-Server e X-Original-Host. Confirma vulnerabilidade se o valor aparecer no body HTML, no header Location ou no Set-Cookie.", tip: "Valide o Host header contra uma whitelist de domínios permitidos no servidor. Nunca use o Host header diretamente para gerar links em emails de reset de senha ou respostas HTTP." },
  ssrf: { title: "SSRF", icon: "◈", what: "Detecta Server-Side Request Forgery: o servidor faz requests HTTP para URLs controladas pelo atacante, permitindo acesso a metadados de cloud (AWS/GCP), serviços internos ou máquinas na rede interna.", does: "Injeta payloads SSRF em 24 parâmetros URL-like (url, callback, webhook, redirect, etc.). Detecta via conteúdo de metadata AWS/GCP na resposta, error disclosure revelando IPs internos, banners SSH/SMTP, e redirecionamento para endereços RFC1918.", tip: "Nunca faça requests server-side para URLs arbitrárias vindas do usuário. Use whitelists de domínios permitidos, bloqueie IPs privados/loopback e metadata endpoints no nível de rede." },
  traversal: { title: "Path Traversal / LFI", icon: "◈", what: "Testa parâmetros que referenciam arquivos (file, page, path, template, etc.) com payloads de traversal para verificar se o servidor serve arquivos do sistema.", does: "Injeta payloads Unix e Windows (../../../etc/passwd, ..\..\windows\win.ini, variantes com %2F, %5C) em 12 parâmetros file-like. Confirma exploração com assinaturas de conteúdo — exige dupla evidência para evitar FPs.", tip: "Nunca passe nomes de arquivo diretamente de parâmetros de usuário ao filesystem. Use whitelists de páginas permitidas, nunca concatenação direta de path." },
  active:    { title: "Active Checks", icon: "▣", what: "Módulo avançado que executa probes ativos contra o servidor. Requer autorização explícita do proprietário do modulo contratante.", does: "Executa: detecção de WAF (Web Application Firewall), análise de política CORS, varredura de ~25 arquivos sensíveis (.env, backup.sql, etc.), probes de XSS refletido e injeção de DB error, e port scan em 21 portas comuns. Cada probe faz requests reais ao servidor.", tip: "Use APENAS em domínios que você é proprietário ou tem autorização explícita. Probes não autorizados podem ser ilegais." },
  compliance: { title: "LGPD / ISO 27001:2022", icon: "⊕", what: "Mapeia os resultados técnicos do scan para obrigações legais da LGPD (Lei 13.709/2018) e controles da norma ISO/IEC 27001:2022.", does: "Cruza cada vulnerabilidade encontrada com artigos da LGPD (Arts. 46–50) e controles ISO 27001 (A.5–A.8). Classifica cada item como CONFORME ou NÃO CONFORME e calcula um Compliance Score percentual. Os itens não conformes são agrupados por artigo/controle com a lista de issues que os causam.", tip: "Use o relatório de compliance como base para comunicação com DPO, auditorias internas ou due diligence. Corrija os itens CRITICAL e HIGH primeiro — eles tendem a gerar o maior número de não conformidades." },
};

// ── Module Info Modal ─────────────────────────────────────────────────────────

function ModuleInfoModal({ moduleKey, onClose }: { moduleKey: string | null; onClose: () => void }) {
  const { t } = useI18n();
  const info = moduleKey ? MODULE_INFO[moduleKey] : null;
  useEffect(() => {
    if (!info) return;
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [info, onClose]);
  if (!info) return null;
  return (
    <div className={styles.modalBackdrop} onClick={onClose}>
      <div className={styles.moduleInfoPanel} onClick={e => e.stopPropagation()}>
        <div className={styles.moduleInfoHeader}>
          <span className={styles.moduleInfoIcon}>{info.icon}</span>
          <div>
            <div className={styles.moduleInfoTitle}>{info.title}</div>
            <div className={styles.moduleInfoSub}>{t("modulo.info")}</div>
          </div>
          <button className={styles.moduleInfoClose} onClick={onClose}>✕</button>
        </div>
        <div className={styles.moduleInfoBody}>
          <div className={styles.moduleInfoSection}>
            <div className={styles.moduleInfoLabel}>{t("modulo.escopo")}</div>
            <p className={styles.moduleInfoText}>{info.what}</p>
          </div>
          <div className={styles.moduleInfoSection}>
            <div className={styles.moduleInfoLabel}>{t("modulo.metodologia")}</div>
            <p className={styles.moduleInfoText}>{info.does}</p>
          </div>
          <div className={styles.moduleInfoTip}>
            <span className={styles.moduleInfoTipIcon}>◈</span>
            <p>{info.tip}</p>
          </div>
        </div>
      </div>
    </div>
  );
}

function SidebarNavItem({
  icon, title, color, metric, label, locked, active, onClick,
}: {
  icon: string; title: string; color: string;
  metric: React.ReactNode; label: string;
  locked?: boolean; active?: boolean; onClick?: () => void;
}) {
  return (
    <button
      className={`${styles.sidebarNavItem} ${active ? styles.sidebarNavItemActive : ""} ${locked ? styles.sidebarNavItemLocked : ""}`}
      style={{ "--mc-color": color } as React.CSSProperties}
      onClick={onClick}
      title={locked ? "Módulo bloqueado — disponível nos planos pagos" : undefined}
    >
      <span className={styles.sidebarNavAccent} />
      <span className={styles.sidebarNavIcon}>{icon}</span>
      <div className={styles.sidebarNavInfo}>
        <span className={styles.sidebarNavTitle}>{title}</span>
        <span className={styles.sidebarNavLabel}>{label}</span>
      </div>
      <span className={styles.sidebarNavMetric}>{locked ? "🔒" : metric}</span>
    </button>
  );
}

// ── Guest Banner ──────────────────────────────────────────────────────────────

function GuestBanner({ onLogin, refreshKey }: { onLogin: () => void; refreshKey: number }) {
  const { t } = useI18n();
  const [status, setStatus] = useState<GuestStatus | null>(null);
  useEffect(() => { api.get<GuestStatus>("/auth/guest-status").then(r => setStatus(r.data)).catch(() => {}); }, [refreshKey]);
  if (!status) return null;
  const pct = Math.round((status.used / status.dailyLimit) * 100);
  const critical = status.remaining <= 2;
  return (
    <div className={`${styles.guestBanner} ${critical ? styles.guestBannerCritical : ""}`}>
      <div className={styles.guestBannerLeft}>
        <span className={styles.guestBannerIcon}>{critical ? "⚠" : "◈"}</span>
        <div>
          <div className={styles.guestBannerTitle}>
            {status.remaining === 0 ? t("visitante.limiteAtingido") : t("visitante.scansRestantes", status.remaining)}
          </div>
          <div className={styles.guestBannerSub}>{status.used}/{status.dailyLimit} utilizados · reseta meia-noite</div>
          <div className={styles.guestProgress}>
            <div className={styles.guestProgressFill} style={{ width: `${pct}%`, background: critical ? "var(--critical)" : "var(--accent)" }} />
          </div>
        </div>
      </div>
      <button className={`${styles.btn} ${styles.btnScan}`} onClick={onLogin}>{t("visitante.loginIlimitado")}</button>
    </div>
  );
}

// ── Ownership Card ────────────────────────────────────────────────────────────

function OwnershipCard({ state, onDismiss }: { state: OwnershipState; onDismiss: () => void }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const [checking, setChecking] = useState(false);
  const [verified, setVerified] = useState(false);
  async function check() {
    setChecking(true);
    try { const r = await api.get("/scan/verify-check", { params: { host: state.host } }); setVerified(r.data.verified); }
    catch { setVerified(false); }
    setChecking(false);
  }
  function copy() {
    if (state.token) { navigator.clipboard.writeText(state.token); setCopied(true); setTimeout(() => setCopied(false), 2000); }
  }
  return (
    <div className={styles.ownershipCard}>
      <div className={styles.ownershipHeader}><span>⚠</span><span>{t("posse.titulo")}</span></div>
      <p className={styles.ownershipText}>{t("posse.riscoDetectado")} <strong>{state.host}</strong>. Prove que você é o dono do domínio.</p>
      <div className={styles.ownershipSteps}>
        <div className={styles.ownershipStep}><span className={styles.stepNum}>1</span><div><div className={styles.stepTitle}>{t("posse.crieArquivo")}</div><code className={styles.stepCode}>https://{state.host}/.well-known/cyberaudit.txt</code></div></div>
        <div className={styles.ownershipStep}><span className={styles.stepNum}>2</span><div><div className={styles.stepTitle}>{t("posse.conteudoArquivo")}</div><div className={styles.tokenRow}><code className={styles.stepCode}>{state.token ?? "—"}</code><button className={styles.copyBtn} onClick={copy}>{copied ? t("posse.copiado") : "Copiar"}</button></div></div></div>
        <div className={styles.ownershipStep}><span className={styles.stepNum}>3</span><div><div className={styles.stepTitle}>{t("posse.confirme")}</div><div className={styles.tokenRow}><button className={styles.verifyBtn} onClick={check} disabled={checking}>{checking ? t("posse.verificando") : t("posse.checarAgora")}</button>{verified ? <span className={styles.ok}>{t("posse.verificado")}</span> : <span className={styles.bad}>{t("posse.naoEncontrado")}</span>}</div></div></div>
      </div>
      <button className={styles.dismissBtn} onClick={onDismiss}>Fechar</button>
    </div>
  );
}

// ── Login Page ────────────────────────────────────────────────────────────────

// ── Terms / Privacy Modal ────────────────────────────────────────────────────

function TermsModal({ type, onClose }: { type: "terms" | "privacy"; onClose: () => void }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const isTerms = type === "terms";
  return (
    <div className={styles.modalOverlay} onClick={onClose}>
      <div className={styles.termsModalCard} onClick={e => e.stopPropagation()}>
        <div className={styles.termsModalHeader}>
          <span>{isTerms ? "📄 Termos de Uso" : "🔒 Política de Privacidade"}</span>
          <button className={styles.modalClose} onClick={onClose}>✕</button>
        </div>
        <div className={styles.termsModalBody}>
          {isTerms ? (
            <>
              <p><strong>1. Aceitação dos Termos</strong><br />
              Ao utilizar o CyberAudit, você concorda com estes Termos de Uso. O serviço é destinado exclusivamente a profissionais de segurança e proprietários de sistemas que desejam auditar sua própria infraestrutura.</p>
              <p><strong>2. Uso Permitido</strong><br />
              O CyberAudit deve ser utilizado apenas em sistemas e domínios para os quais você possui autorização explícita. O uso não autorizado em sistemas de terceiros é estritamente proibido e pode constituir crime conforme a Lei nº 12.737/2012 (Lei Carolina Dieckmann) e o Marco Civil da Internet (Lei nº 12.965/2014).</p>
              <p><strong>3. Responsabilidades do Usuário</strong><br />
              Você é inteiramente responsável pelo uso do serviço. O CyberAudit não se responsabiliza por danos causados pelo uso inadequado da plataforma ou pela interpretação incorreta dos resultados.</p>
              <p><strong>4. Limitação de Responsabilidade</strong><br />
              Os resultados dos scans são informativos e não constituem garantia de segurança absoluta. O CyberAudit não garante a detecção de todas as vulnerabilidades existentes.</p>
              <p><strong>5. Propriedade Intelectual</strong><br />
              Todo o conteúdo, software e metodologias do CyberAudit são propriedade exclusiva da plataforma e protegidos por lei.</p>
              <p><strong>6. Alterações nos Termos</strong><br />
              Reservamo-nos o direito de modificar estes termos a qualquer momento. Alterações significativas serão comunicadas por email.</p>
              <p className={styles.termsNote}>Última atualização: Junho de 2026</p>
            </>
          ) : (
            <>
              <p><strong>1. Dados Coletados</strong><br />
              Coletamos nome, email, endereço IP, domínios auditados e resultados de scans para fornecer o serviço e melhorar a plataforma, conforme a LGPD (Lei nº 13.709/2018).</p>
              <p><strong>2. Uso dos Dados</strong><br />
              Seus dados são utilizados para: autenticação, entrega do serviço, envio de notificações relacionadas ao serviço e geração de relatórios. Não vendemos seus dados a terceiros.</p>
              <p><strong>3. Retenção de Dados</strong><br />
              Dados de scan são retidos por 12 meses para histórico. Dados pessoais são mantidos enquanto a conta estiver ativa. Você pode solicitar exclusão a qualquer momento.</p>
              <p><strong>4. Seus Direitos (LGPD Art. 18)</strong><br />
              Você tem direito a: confirmação de tratamento, acesso, correção, anonimização, portabilidade, eliminação e revogação de consentimento. Exercite esses direitos em Configurações → Privacidade.</p>
              <p><strong>5. Segurança</strong><br />
              Utilizamos criptografia TLS, hashing bcrypt para senhas, e logs de auditoria para proteger seus dados.</p>
              <p><strong>6. Cookies</strong><br />
              Utilizamos apenas cookies técnicos essenciais para autenticação. Não utilizamos cookies de rastreamento ou publicidade.</p>
              <p><strong>7. Contato DPO</strong><br />
              Para questões sobre privacidade: <strong>privacidade@cyberaudit.com.br</strong></p>
              <p className={styles.termsNote}>Última atualização: Junho de 2026 · Conforme LGPD (Lei nº 13.709/2018)</p>
            </>
          )}
        </div>
        <div className={styles.termsModalFooter}>
          <button className={`${styles.btn} ${styles.btnScan}`} onClick={onClose}>Entendi</button>
        </div>
      </div>
    </div>
  );
}

/**
 * Pedido de redefinição.
 *
 * A mensagem de sucesso é a mesma exista ou não a conta — o backend responde
 * igual de propósito, e a tela não pode desfazer isso dizendo "e-mail não
 * encontrado". Seria um verificador de cadastro.
 */
function EsqueciSenha({ onVoltar }: { onVoltar: () => void }) {
  const { t } = useI18n();
  const [email, setEmail]   = useState("");
  const [enviado, setEnviado] = useState(false);
  const [loading, setLoading] = useState(false);
  const [erro, setErro]     = useState<string | null>(null);

  async function enviar(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setErro(null);
    try {
      await api.post("/auth/forgot-password", { email });
      setEnviado(true);
    } catch (err: any) {
      setErro(err?.response?.data?.message ?? t("senha.esqueci.erro"));
    } finally { setLoading(false); }
  }

  if (enviado) {
    return (
      <div className={styles.loginForm}>
        <div style={{ textAlign: "center", padding: "12px 0" }}>
          <div style={{ fontSize: 32, marginBottom: 8, color: "var(--secure)" }}>✓</div>
          <div style={{ color: "var(--text)", fontWeight: 600, marginBottom: 6 }}>{t("senha.esqueci.enviadoTitulo")}</div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.6 }}>
            {t("senha.esqueci.enviadoTexto")}
          </div>
        </div>
        <button type="button" className={styles.backLink} onClick={onVoltar}>{t("comum.voltarLogin")}</button>
      </div>
    );
  }

  return (
    <form className={styles.loginForm} onSubmit={enviar}>
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 4, lineHeight: 1.6 }}>
        {t("senha.esqueci.instrucao")}
      </div>
      <div className={styles.formGroup}>
        <label className={styles.formLabel}>{t("comum.email")}</label>
        <input className={styles.formInput} type="email" value={email}
               onChange={e => setEmail(e.target.value)} placeholder={t("comum.phEmail")} required />
      </div>
      {erro && <div className={styles.errorBox}>{erro}</div>}
      <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={loading}>
        {loading ? t("comum.enviando") : t("senha.esqueci.enviar")}
      </button>
      <button type="button" className={styles.backLink} onClick={onVoltar}>{t("comum.voltarLogin")}</button>
    </form>
  );
}

/** Tela aberta pelo link do e-mail: /redefinir-senha?token=... */
function RedefinirSenha({ token }: { token: string }) {
  const { t } = useI18n();
  const [senha, setSenha]         = useState("");
  const [confirma, setConfirma]   = useState("");
  const [pronto, setPronto]       = useState(false);
  const [loading, setLoading]     = useState(false);
  const [erro, setErro]           = useState<string | null>(null);

  async function enviar(e: React.FormEvent) {
    e.preventDefault();
    if (senha !== confirma) { setErro(t("senha.redefinir.naoConferem")); return; }
    setLoading(true); setErro(null);
    try {
      await api.post("/auth/reset-password", { token, password: senha });
      setPronto(true);
    } catch (err: any) {
      setErro(err?.response?.data?.message ?? t("senha.redefinir.erro"));
    } finally { setLoading(false); }
  }

  function irParaLogin() {
    // Troca a URL para não deixar o token no histórico do navegador.
    window.location.replace("/");
  }

  return (
    <div className={styles.loginPage}>
      <div className={styles.loginCard}>
        <div className={styles.loginLogo}>◈ CYBERAUDIT</div>
        <div className={styles.loginTitle}>{t("senha.redefinir.titulo")}</div>

        {pronto ? (
          <div className={styles.loginForm}>
            <div style={{ textAlign: "center", padding: "12px 0" }}>
              <div style={{ fontSize: 32, marginBottom: 8, color: "var(--secure)" }}>✓</div>
              <div style={{ color: "var(--text)", fontWeight: 600, marginBottom: 6 }}>{t("senha.redefinir.prontoTitulo")}</div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                {t("senha.redefinir.prontoTexto")}
              </div>
            </div>
            <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} onClick={irParaLogin}>
              {t("senha.redefinir.irLogin")}
            </button>
          </div>
        ) : (
          <form className={styles.loginForm} onSubmit={enviar}>
            <div className={styles.formGroup}>
              <label className={styles.formLabel}>{t("senha.redefinir.nova")}</label>
              <input className={styles.formInput} type="password" value={senha} minLength={8}
                     onChange={e => setSenha(e.target.value)} placeholder={t("comum.phSenha")} required />
            </div>
            <div className={styles.formGroup}>
              <label className={styles.formLabel}>{t("senha.redefinir.confirme")}</label>
              <input className={styles.formInput} type="password" value={confirma} minLength={8}
                     onChange={e => setConfirma(e.target.value)} placeholder={t("comum.phSenha")} required />
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
              {t("senha.redefinir.minimo")}
            </div>
            {erro && <div className={styles.errorBox}>{erro}</div>}
            <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={loading}>
              {loading ? t("comum.salvando") : t("senha.redefinir.titulo")}
            </button>
            <button type="button" className={styles.backLink} onClick={irParaLogin}>{t("comum.voltarLogin")}</button>
          </form>
        )}
      </div>
    </div>
  );
}

/**
 * Monta uma frase que contém links, sem picá-la no catálogo.
 *
 * "Li e aceito os {0} e a {1}" chega inteira ao tradutor, que pode reordenar as
 * partes — em inglês a ordem e as preposições são outras. Concatenar fragmentos
 * ("Li e aceito os " + link + " e a " + link) travaria a frase na gramática do
 * português.
 */
function fraseComLinks(texto: string, links: React.ReactNode[]): React.ReactNode[] {
  return texto.split(/(\{\d\})/).map((parte, i) => {
    const marca = parte.match(/^\{(\d)\}$/);
    return <span key={i}>{marca ? links[Number(marca[1])] : parte}</span>;
  });
}

function LoginPage({ onBack }: { onBack: () => void }) {
  const { t } = useI18n();
  const { login, register, verify2fa, resendEmailOtp } = useAuth();
  const [authTab, setAuthTab] = useState<"login" | "register" | "forgot">("login");
  const [termsModal, setTermsModal] = useState<"terms" | "privacy" | null>(null);

  // ── Login state ───────────────────────────────────────────────────────────
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // ── 2FA step ──────────────────────────────────────────────────────────────
  const [pending2fa, setPending2fa] = useState<TwoFactorPending | null>(null);
  const [twoFaMethod, setTwoFaMethod] = useState<string>("TOTP");
  const [twoFaCode, setTwoFaCode] = useState("");
  const [resendInfo, setResendInfo] = useState<string | null>(null);

  // ── Register state ────────────────────────────────────────────────────────
  const [rName, setRName] = useState("");
  const [rEmail, setREmail] = useState("");
  const [rPassword, setRPassword] = useState("");
  const [rConfirm, setRConfirm] = useState("");
  const [rTerms, setRTerms] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setError(null);
    try {
      const result = await login(email, password);
      if (result?.requires2fa) {
        setPending2fa(result);
        setTwoFaMethod(result.twoFactorMethods[0] ?? "TOTP");
      } else {
        onBack();
      }
    }
    catch (err: any) { setError(err?.response?.data?.message ?? err?.response?.data?.error ?? t("login.credenciaisInvalidas")); }
    finally { setLoading(false); }
  }

  async function handle2faSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setError(null);
    try {
      await verify2fa(twoFaCode.replace(/\s/g, ""), twoFaMethod);
      onBack();
    }
    catch (err: any) { setError(err?.response?.data?.message ?? t("login.2fa.codigoInvalido")); }
    finally { setLoading(false); }
  }

  async function handleResend() {
    setResendInfo(null); setError(null);
    try { await resendEmailOtp(); setResendInfo(t("login.2fa.reenviado")); }
    catch (err: any) {
      // O backend agora distingue "não consegui enviar" de erro genérico. Mostrar
      // a mensagem dele importa: antes a tela dizia "reenviado" mesmo quando nada
      // saía, e o usuário ficava tentando um código que não existia.
      setError(err?.response?.data?.message ?? t("login.2fa.falhaReenviar"));
    }
  }

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    if (rPassword !== rConfirm) { setError(t("login.senhasNaoCoincidem")); return; }
    if (rPassword.length < 8) { setError(t("login.senhaMinima")); return; }
    if (!rTerms) { setError(t("login.precisaAceitar")); return; }
    setLoading(true); setError(null);
    try {
      await register({
        name: rName.trim(),
        email: rEmail.trim().toLowerCase(),
        password: rPassword,
        accountType: "INDIVIDUAL",
        termsAccepted: true,
      });
      onBack();
    }
    catch (err: any) { setError(err?.response?.data?.message ?? t("login.erroCriarConta")); }
    finally { setLoading(false); }
  }

  // ── 2FA screen ────────────────────────────────────────────────────────────
  if (pending2fa) {
    const hasBoth = pending2fa.twoFactorMethods.length > 1;
    return (
      <div className={styles.loginPage}>
        <div className={styles.loginCard}>
          <div className={styles.loginLogo}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div>
          <div className={styles.loginTitle}>{t("login.2fa.titulo")}</div>
          <div className={styles.loginSub}>
            {twoFaMethod === "EMAIL"
              ? t("login.2fa.subEmail")
              : t("login.2fa.subApp")}
          </div>
          {hasBoth && (
            <div className={styles.tfMethodRow}>
              {pending2fa.twoFactorMethods.map(m => (
                <button key={m}
                  className={`${styles.tfMethodBtn} ${twoFaMethod === m ? styles.tfMethodBtnActive : ""}`}
                  onClick={() => { setTwoFaMethod(m); setError(null); }}>
                  {m === "TOTP" ? t("login.2fa.metodoApp") : t("login.2fa.metodoEmail")}
                </button>
              ))}
            </div>
          )}
          <form className={styles.loginForm} onSubmit={handle2faSubmit}>
            <div className={styles.formGroup}>
              <label className={styles.formLabel}>{t("login.2fa.codigo")}</label>
              <input className={`${styles.formInput} ${styles.tfCodeInput}`}
                type="text" inputMode="numeric" pattern="[\d ]{6,7}"
                value={twoFaCode} onChange={e => setTwoFaCode(e.target.value)}
                placeholder={twoFaMethod === "TOTP" ? "000000" : "000 000"}
                maxLength={7} autoFocus required />
            </div>
            {error && <div className={styles.errorBox}>{error}</div>}
            {resendInfo && <div className={styles.infoBox}>{resendInfo}</div>}
            <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={loading}>
              {loading ? t("login.2fa.verificando") : t("login.2fa.confirmar")}
            </button>
            {twoFaMethod === "EMAIL" && (
              <button type="button" className={styles.backLink} onClick={handleResend}>
                {t("login.2fa.reenviar")}
              </button>
            )}
          </form>
          <button className={styles.backLink} onClick={() => { setPending2fa(null); setTwoFaCode(""); setError(null); }}>
            {t("comum.voltarLogin")}
          </button>
        </div>
      </div>
    );
  }

  return (
    <>
      {termsModal && <TermsModal type={termsModal} onClose={() => setTermsModal(null)} />}
      <div className={styles.loginPage}>
        <div className={styles.loginCard}>
          <div className={styles.loginLogo}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div>

          {/* Tabs */}
          <div className={styles.authTabs}>
            <button
              className={`${styles.authTab} ${authTab === "login" ? styles.authTabActive : ""}`}
              onClick={() => { setAuthTab("login"); setError(null); }}
            >{t("login.entrar")}</button>
            <button
              className={`${styles.authTab} ${authTab === "register" ? styles.authTabActive : ""}`}
              onClick={() => { setAuthTab("register"); setError(null); }}
            >{t("login.criarConta")}</button>
          </div>

          {/* ── Login form ── */}
          {authTab === "login" && (
            <form className={styles.loginForm} onSubmit={handleSubmit}>
              <div className={styles.formGroup}><label className={styles.formLabel}>{t("comum.email")}</label><input className={styles.formInput} type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder={t("comum.phEmail")} required /></div>
              <div className={styles.formGroup}><label className={styles.formLabel}>{t("comum.senha")}</label><input className={styles.formInput} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder={t("comum.phSenha")} required /></div>
              {error && <div className={styles.errorBox}>{error}</div>}
              <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={loading}>{loading ? t("login.entrando") : t("login.entrar")}</button>
              <button type="button" className={styles.backLink} onClick={() => setAuthTab("forgot")}>{t("login.esqueci")}</button>
              <button type="button" className={styles.backLink} onClick={onBack}>{t("comum.voltarSemAuth")}</button>
            </form>
          )}

          {authTab === "forgot" && <EsqueciSenha onVoltar={() => setAuthTab("login")} />}

          {/* ── Register form ── */}
          {authTab === "register" && (
            <form className={styles.loginForm} onSubmit={handleRegister}>
              <div className={styles.formGroup}>
                <label className={styles.formLabel}>{t("login.nomeCompleto")}</label>
                <input className={styles.formInput} value={rName} onChange={e => setRName(e.target.value)} placeholder={t("login.phNome")} required />
              </div>
              <div className={styles.formGroup}>
                <label className={styles.formLabel}>{t("login.emailObrig")}</label>
                <input className={styles.formInput} type="email" value={rEmail} onChange={e => setREmail(e.target.value)} placeholder={t("comum.phEmail")} required />
              </div>
              <div className={styles.formGroup}>
                <label className={styles.formLabel}>{t("login.senhaObrig")}</label>
                <input className={styles.formInput} type="password" value={rPassword} onChange={e => setRPassword(e.target.value)} placeholder={t("login.phSenhaMinima")} required />
              </div>
              <div className={styles.formGroup}>
                <label className={styles.formLabel}>{t("login.confirmarSenha")}</label>
                <input className={styles.formInput} type="password" value={rConfirm} onChange={e => setRConfirm(e.target.value)} placeholder={t("login.phRepitaSenha")} required />
              </div>
              <label className={styles.termsRow}>
                <input type="checkbox" checked={rTerms} onChange={e => setRTerms(e.target.checked)} required />
                <span>
                  {fraseComLinks(t("login.aceitoTermos"), [
                    <button type="button" className={styles.termsLink} onClick={() => setTermsModal("terms")}>{t("login.termosDeUso")}</button>,
                    <button type="button" className={styles.termsLink} onClick={() => setTermsModal("privacy")}>{t("login.politica")}</button>,
                  ])}
                </span>
              </label>
              {error && <div className={styles.errorBox}>{error}</div>}
              <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`}
                disabled={loading || !rTerms}>
                {loading ? t("login.criandoConta") : t("login.criarConta")}
              </button>
              <button type="button" className={styles.backLink} onClick={onBack}>{t("comum.voltarSemAuth")}</button>
            </form>
          )}
        </div>
      </div>
    </>
  );
}

// ── Seletor de idioma ─────────────────────────────────────────────────────────

/**
 * Fica ao lado do tema, no header, e vale para VISITANTE também: a tela de planos
 * e o scan público são justamente o que o cliente estrangeiro vê antes de existir
 * conta dele.
 *
 * `flutuante` é para as telas que NÃO desenham o header — login, setup, convite,
 * redefinição de senha, página de status pública. Todas retornam antes dele, e
 * são justamente as primeiras que um estrangeiro vê: sem isto, ele chegaria numa
 * tela em português sem nenhuma forma de trocar.
 *
 * Trocar o idioma recarrega a página. Parece grosseiro, mas é o certo aqui: o
 * resultado do scan que já está na tela veio do Backend no idioma anterior, e
 * re-renderizar só a moldura deixaria metade em cada idioma — exatamente o
 * meio-termo que este bloco existe para evitar. O reload refaz as chamadas com o
 * header novo.
 */
function LanguagePicker({ flutuante = false }: { flutuante?: boolean }) {
  const { lang, setLang, t } = useI18n();

  return (
    <div
      className={`${styles.langPicker} ${flutuante ? styles.langPickerFloat : ""}`}
      role="group"
      aria-label={t("idioma.seletor")}
    >
      {IDIOMAS.map(i => (
        <button
          key={i.code}
          className={`${styles.langBtn} ${i.code === lang ? styles.langBtnActive : ""}`}
          onClick={() => { if (i.code !== lang) { setLang(i.code); window.location.reload(); } }}
          title={t("idioma.mudarPara", i.label)}
          aria-pressed={i.code === lang}
        >
          {i.short}
        </button>
      ))}
    </div>
  );
}

// ── Plans Modal ───────────────────────────────────────────────────────────────

/**
 * O cardápio vem de GET /billing/plans, montado a partir do enum Plan do Backend.
 *
 * Antes era uma lista paralela mantida aqui à mão, e ela envelheceu em silêncio:
 * quatro recursos criados no Backend nunca chegaram a esta tela — um deles o
 * principal diferencial pago — e os preços ficavam chumbados enquanto o Backend
 * já os lia de configuração.
 *
 * A API manda ESTADO (id + state + limit). O texto continua aqui porque é redação
 * de produto, e é o que a internacionalização vai traduzir depois.
 */

type PlanKey     = "FREE" | "PRO" | "ENTERPRISE";
type FeatureState = "YES" | "NO" | "VERIFIED_DOMAINS_ONLY";

interface ApiFeature {
  id: string;
  state: FeatureState;
  /** Quantidade quando o recurso é contável: -1 = ilimitado. null = liga/desliga. */
  limit: number | null;
}

interface ApiPlan {
  plan: PlanKey;
  /** null no FREE, que não se assina. */
  amount: number | null;
  currency: string;
  features: ApiFeature[];
}

/** Identidade do card. Nome, documento e recado não são diferença de plano. */
const PLAN_CARDS: Record<PlanKey, { name: string; doc: string; note?: string }> = {
  FREE:       { name: "Pessoal Free", doc: "CPF opcional" },
  PRO:        { name: "Pessoal Pro",  doc: "CPF opcional" },
  ENTERPRISE: {
    name: "Empresa",
    doc:  "CNPJ obrigatório",
    // Multi-usuário fica fora da comparação de propósito: convite é liberado por
    // tipo de conta (InviteService), não por plano — uma conta Empresa no FREE já
    // monta o time. Por isso é nota do card, não linha de comparação.
    note: "Equipe, convites e 2FA obrigatório vêm da conta Empresa — valem em qualquer plano.",
  },
};

/**
 * Rótulo de cada recurso. A chave vem do Backend; o texto é daqui.
 *
 * Id desconhecido cai no próprio id, de propósito: recurso novo aparece feio na
 * tela em vez de sumir dela. Sumir em silêncio foi o problema original.
 */
function rotuloDoRecurso(f: ApiFeature, plano: PlanKey): string {
  const soVerificado = f.state === "VERIFIED_DOMAINS_ONLY";
  switch (f.id) {
    case "FINDING_DETAIL":
      return "Impacto e correção de cada achado";
    case "DAILY_SCANS":
      return f.limit === -1 ? "Scans ilimitados" : `${f.limit} scans por dia`;
    case "PDF_EXPORT":
      return soVerificado      ? "PDF do scan (só domínios verificados)"
           : f.state === "YES" ? "PDF de qualquer domínio"
           :                     "PDF do scan";
    case "EMAIL_NOTIFY":
      return soVerificado ? "Notificação por e-mail (só domínios verificados)"
                          : "Notificação por e-mail";
    case "CHANGES_MODULE":
      return "Módulo Changes";
    case "HISTORY_CHART":
      return "Gráfico histórico";
    case "SCHEDULED_SCANS":
      return f.limit === -1                 ? "Agendamentos ilimitados"
           : f.limit != null && f.limit > 0  ? `${f.limit} agendamentos`
           :                                   "Agendamentos";
    case "DOMAIN_REGISTRATION":
      return "Cadastro de domínio";
    // Na Empresa o relatório é da equipe; nos cards pessoais, da conta.
    case "ACCOUNT_REPORTS":
      return plano === "ENTERPRISE" ? "Relatórios da equipe e PDF executivo"
                                    : "Relatórios da conta e PDF executivo";
    case "ACTIVE_SCAN":
      return soVerificado      ? "Active Scan (só domínios verificados)"
           : f.state === "YES" ? "Active Scan em qualquer domínio"
           :                     "Active Scan";
    default:
      return f.id;
  }
}

/** Preço formatado na moeda que a API informou. */
function precoDoPlano(p: ApiPlan): string {
  if (p.amount == null) return "Grátis";
  const valor = new Intl.NumberFormat("pt-BR", {
    style: "currency", currency: p.currency || "BRL",
  }).format(p.amount);
  return `${valor}/mês`;
}

/** FREE não se assina. */
function ehPago(plano: PlanKey): boolean {
  return plano !== "FREE";
}

function PlansModal({ onClose }: { onClose: () => void }) {
  const { user, refreshUser } = useAuth();

  // Esta é a tela que afirma "Seu plano atual", então é a que menos pode estar
  // desatualizada. O plano pode ter mudado desde o login sem passar por aqui —
  // webhook confirmando a assinatura, cancelamento, pagamento recusado.
  useEffect(() => { void refreshUser(); }, [refreshUser]);

  const [planos, setPlanos]           = useState<ApiPlan[] | null>(null);
  const [erroCardapio, setErroCardapio] = useState(false);

  const carregarCardapio = useCallback(async () => {
    setErroCardapio(false);
    try {
      const res = await api.get<ApiPlan[]>("/billing/plans");
      setPlanos(res.data);
    } catch {
      // Sem lista de reserva de propósito. Um cardápio estático aqui voltaria a
      // envelhecer, e mostraria preço velho como se fosse o atual justamente
      // quando a API está fora. Errar em voz alta é melhor que mentir baixinho.
      setErroCardapio(true);
    }
  }, []);

  useEffect(() => { void carregarCardapio(); }, [carregarCardapio]);

  /**
   * O card atual sai do PLANO, nunca do tipo da conta. Toda conta nasce em
   * Plan.FREE — COMPANY inclusive (AuthService.buildAccountFromRegister) — então
   * derivar do tipo marcava o card Empresa como atual numa conta que ainda era
   * FREE, e o guard `!current` escondia o botão: a empresa não tinha como assinar
   * o plano Empresa. O tipo da conta vale para CNPJ e equipe, não para plano.
   */
  const currentPlan: PlanKey = user?.account?.plan ?? "FREE";

  const loggedIn = !!user;
  const [subscribing, setSubscribing] = useState<string | null>(null);
  const [subError, setSubError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  /**
   * O endpoint existia desde sempre e nenhuma tela chamava: quem assinava não
   * tinha como cancelar pelo produto.
   *
   * O texto avisa que o corte é imediato porque é o que BillingService.cancelSubscription
   * faz — grava CANCELLED e rebaixa a conta para FREE na hora, sem carência até o
   * fim do período já pago.
   */
  async function cancelar() {
    if (!confirm("Cancelar a assinatura? O acesso aos recursos pagos termina "
               + "imediatamente, não no fim do período já pago.")) return;
    setCancelling(true); setSubError(null);
    try {
      await api.post("/billing/cancel");
      // Sem isto o cartão continuaria marcado como plano atual até um reload.
      await refreshUser();
    } catch (e: any) {
      setSubError(e?.response?.data?.message ?? "Não foi possível cancelar a assinatura.");
    } finally {
      setCancelling(false);
    }
  }

  async function subscribe(plano: PlanKey) {
    if (!ehPago(plano)) return;
    setSubscribing(plano); setSubError(null);
    try {
      const res = await api.post<{ initPoint: string }>("/billing/subscribe", { plan: plano });
      if (res.data?.initPoint) {
        window.location.href = res.data.initPoint; // → checkout do Mercado Pago
      } else {
        setSubError("Não foi possível iniciar o checkout."); setSubscribing(null);
      }
    } catch (e: any) {
      setSubError(e?.response?.data?.message ?? e?.response?.data?.error ?? "Erro ao iniciar assinatura.");
      setSubscribing(null);
    }
  }

  return (
    <div className={styles.modalOverlay} onClick={onClose}>
      <div className={`${styles.modal} ${styles.plansModal}`} onClick={e => e.stopPropagation()}>
        <div className={styles.plansModalHeader}>
          <span className={styles.plansModalTitle}>◈ PLANOS & FUNCIONALIDADES</span>
          <button className={styles.modalClose} onClick={onClose}>✕</button>
        </div>

        {erroCardapio ? (
          <div className={styles.empty} style={{ padding: 32 }}>
            Não foi possível carregar os planos.{" "}
            <button className={styles.backLink} onClick={() => void carregarCardapio()}>
              Tentar de novo
            </button>
          </div>
        ) : planos === null ? (
          <div className={styles.empty} style={{ padding: 32 }}>Carregando planos...</div>
        ) : (
          <div className={styles.plansGrid}>
            {planos.map(p => {
              const card    = PLAN_CARDS[p.plan];
              const current = p.plan === currentPlan;
              const preco   = precoDoPlano(p);
              return (
                <div key={p.plan} className={`${styles.planCard} ${current ? styles.planCardCurrent : ""}`}>
                  {current && <div className={styles.planCurrentBadge}>Seu plano atual</div>}
                  <div className={styles.planName}>{card.name}</div>
                  <div className={styles.planPrice}>{preco}</div>
                  <div className={styles.planDoc}>{card.doc}</div>
                  <ul className={styles.planFeatures}>
                    {p.features.map(f => {
                      const parcial = f.state === "VERIFIED_DOMAINS_ONLY";
                      const ligado  = f.state !== "NO";
                      return (
                        <li key={f.id} className={styles.planFeatureRow}>
                          {parcial
                            ? <span className={styles.partial}>◑</span>
                            : <span className={ligado ? styles.ok : styles.bad}>{ligado ? "✓" : "✗"}</span>
                          }
                          <span className={parcial ? styles.planFeaturePartial : ligado ? styles.planFeatureOn : styles.planFeatureOff}>
                            {rotuloDoRecurso(f, p.plan)}
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                  {card.note && <div className={styles.planNote}>{card.note}</div>}
                  {current && ehPago(p.plan) && loggedIn && (
                    <button
                      className={`${styles.btn} ${styles.btnDanger} ${styles.btnFull}`}
                      disabled={cancelling}
                      onClick={cancelar}
                    >
                      {cancelling ? "Cancelando..." : "Cancelar assinatura"}
                    </button>
                  )}
                  {!current && (
                    ehPago(p.plan) ? (
                      loggedIn ? (
                        // Qualquer plano pago é assinável, não só o sugerido pelo tipo
                        // de conta: empresa pequena pode querer o Pro, e pessoa física
                        // pode querer os recursos do Empresa. O backend recusa o que
                        // não faz sentido (mesmo plano, ou downgrade sem cancelar).
                        <button
                          className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`}
                          disabled={subscribing !== null}
                          onClick={() => subscribe(p.plan)}
                        >
                          {subscribing === p.plan ? "Redirecionando..." : `Assinar ${preco} →`}
                        </button>
                      ) : (
                        <div className={styles.planCta}>Faça login para assinar</div>
                      )
                    ) : (
                      <div className={styles.planCta}>Grátis</div>
                    )
                  )}
                </div>
              );
            })}
          </div>
        )}
        {subError && <div className={styles.errorBox} style={{ margin: "0 16px 16px" }}>{subError}</div>}
      </div>
    </div>
  );
}

// ── Setup Wizard ──────────────────────────────────────────────────────────────

function formatCnpj(raw: string): string {
  const d = raw.replace(/\D/g, "").slice(0, 14);
  if (d.length <=  2) return d;
  if (d.length <=  5) return `${d.slice(0,2)}.${d.slice(2)}`;
  if (d.length <=  8) return `${d.slice(0,2)}.${d.slice(2,5)}.${d.slice(5)}`;
  if (d.length <= 12) return `${d.slice(0,2)}.${d.slice(2,5)}.${d.slice(5,8)}/${d.slice(8)}`;
  return `${d.slice(0,2)}.${d.slice(2,5)}.${d.slice(5,8)}/${d.slice(8,12)}-${d.slice(12)}`;
}

function SetupPage() {
  const { t } = useI18n();
  const [step, setStep]               = useState<1 | 2 | 3>(1);
  const [accountType, setAccountType] = useState<"COMPANY" | "INDIVIDUAL" | null>(null);

  // Empresa
  const [companyName,   setCompanyName]   = useState("");
  const [cnpj,          setCnpj]          = useState("");
  const [companyDomain, setCompanyDomain] = useState("");
  const [companySize,   setCompanySize]   = useState("1-10");

  // Individual
  const [profession, setProfession] = useState("");
  const [website,    setWebsite]    = useState("");

  // Comum (passo 2)
  const [country, setCountry] = useState("BR");

  // Pessoal (passo 3)
  const [name,     setName]     = useState("");
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [confirm,  setConfirm]  = useState("");

  const [termsAccepted, setTermsAccepted] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState<string | null>(null);

  function goNext() { setError(null); setStep(s => (s + 1) as 1 | 2 | 3); }
  function goBack() { setError(null); setStep(s => (s - 1) as 1 | 2 | 3); }

  function step2Valid(): boolean {
    if (accountType === "COMPANY") {
      return companyName.trim().length > 0 && cnpj.replace(/\D/g, "").length === 14;
    }
    return true;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm)  { setError(t("login.senhasNaoCoincidem")); return; }
    if (password.length < 8)   { setError(t("login.senhaMinima")); return; }
    setLoading(true); setError(null);
    try {
      const payload: Record<string, unknown> = {
        name: name.trim(),
        email: email.trim().toLowerCase(),
        password,
        accountType,
        country: country || undefined,
      };
      if (accountType === "COMPANY") {
        payload.companyName   = companyName.trim();
        payload.cnpj          = cnpj.replace(/\D/g, "");
        payload.companyDomain = companyDomain.trim() || undefined;
        payload.companySize   = companySize;
      } else {
        payload.profession = profession.trim() || undefined;
        payload.website    = website.trim() || undefined;
      }
      payload.termsAccepted = termsAccepted;
      const res = await api.post<{ token: string }>("/auth/setup", payload);
      setToken(res.data.token);
      window.location.href = "/";
    } catch (err: any) {
      setError(err?.response?.data?.message ?? t("setup.erro"));
    } finally {
      setLoading(false);
    }
  }

  const stepLabels = [t("setup.passo1"), t("setup.passo2"), t("setup.passo3")];

  return (
    <div className={styles.loginPage}>
      <div className={`${styles.loginCard} ${styles.setupCard}`}>
        <div className={styles.loginLogo}>
          <span className={styles.logoIcon}>◈</span>
          <span className={styles.logoText}>CyberAudit</span>
        </div>

        {/* Indicador de progresso */}
        <div className={styles.setupProgress}>
          {stepLabels.map((label, i) => {
            const n    = i + 1;
            const done = step > n;
            const active = step === n;
            return (
              <div key={label} className={styles.setupProgressStep}>
                <div className={`${styles.setupDot} ${active ? styles.setupDotActive : done ? styles.setupDotDone : ""}`}>
                  {done ? "✓" : n}
                </div>
                <span className={`${styles.setupDotLabel} ${active ? styles.setupDotLabelActive : ""}`}>{label}</span>
              </div>
            );
          })}
        </div>

        {/* Passo 1: Tipo de conta */}
        {step === 1 && (
          <>
            <div className={styles.loginTitle}>{t("setup.titulo")}</div>
            <div className={styles.loginSub}>{t("setup.subtitulo")}</div>
            <div className={styles.setupTypeGrid}>
              <button
                type="button"
                className={`${styles.setupTypeCard} ${accountType === "COMPANY" ? styles.setupTypeCardSelected : ""}`}
                onClick={() => setAccountType("COMPANY")}
              >
                <div className={styles.setupTypeIcon}>🏢</div>
                <div className={styles.setupTypeName}>{t("setup.empresa")}</div>
                <div className={styles.setupTypeDesc}>{t("setup.empresaDesc")}</div>
              </button>
              <button
                type="button"
                className={`${styles.setupTypeCard} ${accountType === "INDIVIDUAL" ? styles.setupTypeCardSelected : ""}`}
                onClick={() => setAccountType("INDIVIDUAL")}
              >
                <div className={styles.setupTypeIcon}>👤</div>
                <div className={styles.setupTypeName}>{t("setup.individual")}</div>
                <div className={styles.setupTypeDesc}>{t("setup.individualDesc")}</div>
              </button>
            </div>
            <button
              className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`}
              disabled={!accountType}
              onClick={goNext}
            >
              {t("setup.continuar")}
            </button>
          </>
        )}

        {/* Passo 2: Detalhes da conta */}
        {step === 2 && (
          <form onSubmit={e => { e.preventDefault(); if (step2Valid()) goNext(); }}>
            <div className={styles.loginTitle}>
              {accountType === "COMPANY" ? t("setup.dadosEmpresa") : t("setup.dadosProfissionais")}
            </div>
            {accountType === "COMPANY" ? (
              <>
                <div className={styles.formGroup}><label className={styles.formLabel}>{t("setup.nomeEmpresa")}</label><input className={styles.formInput} value={companyName} onChange={e => setCompanyName(e.target.value)} placeholder={t("setup.phNomeEmpresa")} required /></div>
                <div className={styles.formGroup}><label className={styles.formLabel}>{t("setup.cnpj")}</label><input className={styles.formInput} value={cnpj} onChange={e => setCnpj(formatCnpj(e.target.value))} placeholder="XX.XXX.XXX/XXXX-XX" maxLength={18} required /></div>
                <div className={styles.formGroup}><label className={styles.formLabel}>{t("setup.dominioPrincipal")}</label><input className={styles.formInput} value={companyDomain} onChange={e => setCompanyDomain(e.target.value)} placeholder="empresa.com.br" /></div>
                <div className={styles.formGroup}>
                  <label className={styles.formLabel}>{t("setup.tamanhoEmpresa")}</label>
                  <select className={styles.formInput} value={companySize} onChange={e => setCompanySize(e.target.value)}>
                    <option value="1-10">{t("setup.funcionarios", "1–10")}</option>
                    <option value="11-50">{t("setup.funcionarios", "11–50")}</option>
                    <option value="51-200">{t("setup.funcionarios", "51–200")}</option>
                    <option value="201+">{t("setup.funcionarios", "201+")}</option>
                  </select>
                </div>
              </>
            ) : (
              <>
                <div className={styles.formGroup}><label className={styles.formLabel}>{t("setup.profissao")}</label><input className={styles.formInput} value={profession} onChange={e => setProfession(e.target.value)} placeholder={t("setup.phProfissao")} /></div>
                <div className={styles.formGroup}><label className={styles.formLabel}>{t("setup.website")}</label><input className={styles.formInput} value={website} onChange={e => setWebsite(e.target.value)} placeholder="https://meusite.com.br" /></div>
              </>
            )}
            <div className={styles.formGroup}>
              <label className={styles.formLabel}>{t("setup.pais")}</label>
              <select className={styles.formInput} value={country} onChange={e => setCountry(e.target.value)}>
                <option value="BR">Brasil</option>
                <option value="PT">Portugal</option>
                <option value="US">United States</option>
                <option value="OTHER">{t("setup.paisOutro")}</option>
              </select>
            </div>
            {error && <div className={styles.errorBox}>{error}</div>}
            <div className={styles.setupBtnRow}>
              <button type="button" className={`${styles.btn} ${styles.btnGhost}`} onClick={goBack}>{t("setup.voltar")}</button>
              <button type="submit" className={`${styles.btn} ${styles.btnScan}`} disabled={!step2Valid()}>{t("setup.continuarSeta")}</button>
            </div>
          </form>
        )}

        {/* Passo 3: Dados de acesso */}
        {step === 3 && (
          <form className={styles.loginForm} onSubmit={handleSubmit}>
            <div className={styles.loginTitle}>{t("setup.dadosAcesso")}</div>
            <div className={styles.loginSub}>{t("setup.subAcesso")}</div>
            <div className={styles.formGroup}><label className={styles.formLabel}>{t("login.nomeCompleto")}</label><input className={styles.formInput} value={name} onChange={e => setName(e.target.value)} placeholder={t("setup.phNomeCompleto")} required /></div>
            <div className={styles.formGroup}><label className={styles.formLabel}>{t("login.emailObrig")}</label><input className={styles.formInput} type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder={t("setup.phEmailAdmin")} required /></div>
            <div className={styles.formGroup}><label className={styles.formLabel}>{t("login.senhaObrig")}</label><input className={styles.formInput} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder={t("login.phSenhaMinima")} required /></div>
            <div className={styles.formGroup}><label className={styles.formLabel}>{t("login.confirmarSenha")}</label><input className={styles.formInput} type="password" value={confirm} onChange={e => setConfirm(e.target.value)} placeholder={t("login.phRepitaSenha")} required /></div>
            <label className={styles.termsCheck}>
              <input type="checkbox" checked={termsAccepted} onChange={e => setTermsAccepted(e.target.checked)} required />
              <span>{fraseComLinks(t("setup.aceiteLgpd"), [
                <strong>{t("login.termosDeUso")}</strong>,
                <strong>{t("login.politica")}</strong>,
              ])}</span>
            </label>
            {error && <div className={styles.errorBox}>{error}</div>}
            <div className={styles.setupBtnRow}>
              <button type="button" className={`${styles.btn} ${styles.btnGhost}`} onClick={goBack} disabled={loading}>{t("setup.voltar")}</button>
              <button type="submit" className={`${styles.btn} ${styles.btnScan}`}
                disabled={loading || !name.trim() || !email.trim() || !password || !confirm || !termsAccepted}>
                {loading ? t("setup.configurando") : t("setup.finalizar")}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

// ── Accept Invite Page ────────────────────────────────────────────────────────

function AcceptInvitePage({ token }: { token: string }) {
  const { t } = useI18n();
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) { setError(t("login.senhasNaoCoincidem")); return; }
    if (password.length < 6) { setError(t("convite.senhaMinima")); return; }
    if (!termsAccepted) { setError(t("convite.precisaAceitar")); return; }
    setLoading(true); setError(null);
    try { await api.post(`/auth/accept-invite/${token}`, { name, password, termsAccepted }); setSuccess(true); setTimeout(() => { window.location.href = "/"; }, 2000); }
    catch (err: any) { setError(err?.response?.data?.message ?? t("convite.invalido")); }
    finally { setLoading(false); }
  }
  if (success) return (<div className={styles.loginPage}><div className={styles.loginCard}><div className={styles.loginLogo}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div><div className={styles.loginTitle} style={{ color: "var(--secure)" }}>{t("convite.criadaTitulo")}</div><div className={styles.loginSub}>{t("convite.redirecionando")}</div></div></div>);
  return (
    <div className={styles.loginPage}><div className={styles.loginCard}>
      <div className={styles.loginLogo}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div>
      <div className={styles.loginTitle}>{t("convite.titulo")}</div>
      <div className={styles.loginSub}>{t("convite.subtitulo")}</div>
      <form className={styles.loginForm} onSubmit={handleSubmit}>
        <div className={styles.formGroup}><label className={styles.formLabel}>{t("convite.nomeCompleto")}</label><input className={styles.formInput} value={name} onChange={e => setName(e.target.value)} placeholder={t("login.phNome")} /></div>
        <div className={styles.formGroup}><label className={styles.formLabel}>{t("login.senhaObrig")}</label><input className={styles.formInput} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder={t("convite.phSenhaMinima")} required /></div>
        <div className={styles.formGroup}><label className={styles.formLabel}>{t("login.confirmarSenha")}</label><input className={styles.formInput} type="password" value={confirm} onChange={e => setConfirm(e.target.value)} placeholder={t("login.phRepitaSenha")} required /></div>
        <label className={styles.termsCheck}>
          <input type="checkbox" checked={termsAccepted} onChange={e => setTermsAccepted(e.target.checked)} required />
          <span>{fraseComLinks(t("setup.aceiteLgpd"), [
            <strong>{t("login.termosDeUso")}</strong>,
            <strong>{t("login.politica")}</strong>,
          ])}</span>
        </label>
        {error && <div className={styles.errorBox}>{error}</div>}
        <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={loading || !termsAccepted}>{loading ? t("login.criandoConta") : t("convite.criar")}</button>
      </form>
    </div></div>
  );
}

// ── Invite Item Row ───────────────────────────────────────────────────────────

function InviteItemRow({ inv, onRevoke, roleBadge }: { inv: InviteDto; onRevoke: () => void; roleBadge: (r: string) => React.ReactNode; }) {
  const { t } = useI18n();
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const link = inv.acceptLink ? `${window.location.origin}${inv.acceptLink}` : null;
  function copyLink() { if (!link) return; navigator.clipboard.writeText(link); setCopied(true); setTimeout(() => setCopied(false), 2000); }
  return (
    <div className={styles.inviteItem} style={{ flexDirection: "column", alignItems: "stretch", gap: 0 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer" }} onClick={() => setExpanded(o => !o)}>
        <div className={styles.inviteItemLeft}>
          <div className={styles.inviteItemName}>{inv.name}</div>
          <code className={styles.code}>{inv.email}</code>
          <div className={styles.inviteItemMeta}>{roleBadge(inv.role)}<span className={styles.muted}>· expira {new Date(inv.expiresAt).toLocaleDateString()}</span></div>
        </div>
        <div className={styles.actionBtns} onClick={e => e.stopPropagation()}>
          <span className={`${styles.chevron} ${expanded ? styles.chevronOpen : ""}`} style={{ fontSize: 20, color: "var(--text-dim)", cursor: "pointer", padding: "0 6px" }} onClick={() => setExpanded(o => !o)}>›</span>
          <button className={`${styles.btn} ${styles.btnDanger}`} onClick={onRevoke}>Revogar</button>
        </div>
      </div>
      {expanded && (
        <div style={{ marginTop: 10, padding: 12, background: "var(--surface3)", borderRadius: "var(--radius)", display: "flex", flexDirection: "column", gap: 10, borderTop: "1px solid var(--border)" }}>
          <div>
            <div style={{ fontSize: 10, letterSpacing: 1, color: "var(--text-muted)", marginBottom: 6 }}>{t("convite.linkAceite")}</div>
            {link ? (<div className={styles.tokenRow}><code className={styles.stepCode} style={{ flex: 1, fontSize: 11, wordBreak: "break-all" }}>{link}</code><button className={styles.copyBtn} onClick={copyLink}>{copied ? "✓" : "Copiar link"}</button></div>) : <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{t("convite.linkIndisponivel")}</span>}
          </div>
          <div style={{ display: "flex", gap: 20, fontSize: 11, color: "var(--text-dim)", flexWrap: "wrap" }}>
            <span>{t("convite.convidadoPor")} <strong style={{ color: "var(--text)" }}>{inv.invitedByName}</strong></span>
            {inv.jobTitle && <span>Cargo: <strong style={{ color: "var(--text)" }}>{inv.jobTitle}</strong></span>}
          </div>
        </div>
      )}
    </div>
  );
}



// ── Schedule Scan Detail Modal ────────────────────────────────────────────────

function ScheduleScanDetailModal({ id, onClose }: { id: string; onClose: () => void }) {
  const { t } = useI18n();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);
  const [sec, setSec]         = useState("issues");

  useEffect(() => {
    api.get<ScanResult>(`/history/${id}/result`)
      .then(r => { setResult(r.data); setLoading(false); })
      .catch(() => { setError(t("agenda.detalhe.erro")); setLoading(false); });
  }, [id]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === "Escape") onClose(); }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  function handleBackdrop(e: React.MouseEvent) {
    if ((e.target as HTMLElement).dataset.overlay) onClose();
  }

  const TABS: [string, string][] = [
    ["issues",    t("agenda.detalhe.issues")],
    ["transport", t("agenda.detalhe.tls")],
    ["headers",   t("agenda.detalhe.headers")],
    ["dns",       t("agenda.detalhe.dns")],
    ["tech",      t("agenda.detalhe.tech")],
    ["cookies",   t("agenda.detalhe.cookies")],
    ["ports",     t("agenda.detalhe.portas")],
  ];

  return (
    <div className={styles.modalOverlay} data-overlay="1" onClick={handleBackdrop}>
      <div className={styles.modal} style={{ maxWidth: 720 }}>
        <div className={styles.modalHeader}>
          <div className={styles.modalTitleRow}>
            <span className={styles.modalIconLg}>◈</span>
            <span className={styles.modalTitleText}>{t("agenda.detalhe.titulo")}</span>
          </div>
          <button className={styles.modalClose} onClick={onClose}>✕</button>
        </div>

        {loading && <div className={styles.empty} style={{ padding: "2rem" }}>{t("app.carregando")}</div>}
        {error   && <div className={styles.errorBox} style={{ margin: "1rem" }}>{error}</div>}

        {result && (() => {
          const r  = result;
          const sc = r.score;
          return (
            <div style={{ padding: "1.25rem" }}>

              {/* ── Score header ── */}
              <div style={{ display: "flex", alignItems: "center", gap: "1.5rem", marginBottom: "1.25rem" }}>
                <ScoreGauge score={sc.score} risk={sc.riskLevel} />
                <div>
                  <div style={{ fontWeight: 700, fontSize: "1rem", marginBottom: 6 }}>{r.url}</div>
                  <span className={`${styles.tag} ${riskColor(sc.riskLevel)}`}>{sc.riskLevel}</span>
                  {r.activeMode && <span className={`${styles.tag} ${styles.info}`} style={{ marginLeft: 6 }}>ATIVO</span>}
                  {sc.notes?.map((n, i) => (
                    <div key={i} className={styles.note} style={{ marginTop: 4 }}>{n}</div>
                  ))}
                </div>
              </div>

              {/* ── Section tabs ── */}
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginBottom: "1rem", borderBottom: "1px solid var(--border)", paddingBottom: "0.75rem" }}>
                {TABS.map(([key, label]) => (
                  <button key={key} onClick={() => setSec(key)}
                    className={`${styles.btn} ${sec === key ? styles.btnScan : styles.btnGhost}`}
                    style={{ fontSize: "0.72rem", padding: "3px 10px" }}>
                    {label}
                  </button>
                ))}
              </div>

              {/* ── Issues ── */}
              {sec === "issues" && (
                sc.issues?.length
                  ? <div className={styles.issuesList}>{sc.issues.map((i, idx) => <IssueItem key={`${i.id}-${idx}`} issue={i} />)}</div>
                  : <div className={styles.empty}>{t("resultado.semIssues")}</div>
              )}

              {/* ── TLS / SSL ── */}
              {sec === "transport" && <TransportCardsPanel r={r} />}

              {/* ── Headers ── */}
              {sec === "headers" && <HeaderCardsPanel headers={r.headers ?? {}} host={r.analyzedHost ?? (r.finalUrl ?? r.url ?? "").replace(/^https?:\/\//, "").split("/")[0]} related={r.relatedHostHeaders} />}

              {/* ── DNS ── */}
              {sec === "dns" && <DnsCardsPanel r={r} />}

              {/* ── Tech ── */}
              {sec === "tech" && <TechCardsPanel tf={r.techFingerprint} />}

              {/* ── Cookies ── */}
              {sec === "cookies" && <CookieCardsPanel cookies={r.cookieIssues ?? []} />}

              {/* ── Ports ── */}
              {sec === "ports" && (
                r.openPorts?.length
                  ? <FindingCardsPanel
                      emptyMsg="Nenhuma porta aberta detectada"
                      items={r.openPorts.map((p: any, i: number) => ({
                        id: `port-${i}`, title: String(p.port), severity: p.severity,
                        summary: p.service ?? t("agenda.detalhe.servicoDesconhecido"),
                        details: [{ label: "PORTA", value: String(p.port) }, { label: "SERVIÇO", value: p.service ?? "—" }],
                      }))}
                    />
                  : <div className={styles.empty}>{t("agenda.detalhe.semPortas")}</div>
              )}

            </div>
          );
        })()}
      </div>
    </div>
  );
}

// ── Schedules Page ────────────────────────────────────────────────────────────

function SchedulesPage() {
  const { user } = useAuth();
  const { t } = useI18n();
  // Agendar já é PRO+, então o e-mail está sempre liberado aqui — o que pode
  // barrar é o domínio: no Pro pessoal, só os verificados.
  const reportVerifiedOnly = user?.account?.reportOnVerifiedOnly === true;
  const [schedules, setSchedules]   = useState<ScheduledScanDto[]>([]);
  const [loading, setLoading]       = useState(true);
  const [host, setHost]             = useState("");
  const [frequency, setFrequency]   = useState<"DAILY" | "WEEKLY">("DAILY");
  const [hour, setHour]             = useState(8);
  const [notifyEmail, setNotifyEmail] = useState(false);
  const [activeMode, setActiveMode] = useState(false);
  const [creating, setCreating]     = useState(false);
  const [error, setError]           = useState<string | null>(null);

  // history per host
  const [expandedHost, setExpandedHost]     = useState<string | null>(null);
  const [hostHistory, setHostHistory]       = useState<Record<string, HistorySummary[]>>({});
  const [historyLoading, setHistoryLoading] = useState<Record<string, boolean>>({});

  // detail modal
  const [detailId, setDetailId] = useState<string | null>(null);

  async function load() {
    try {
      const res = await api.get<ScheduledScanDto[]>("/scheduled-scans");
      setSchedules(res.data);
    } catch { setError(t("agenda.erroCarregar")); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!host.trim()) return;
    setCreating(true); setError(null);
    try {
      await api.post("/scheduled-scans", {
        host: host.trim(), active: activeMode, frequency,
        preferredHour: hour, notifyEmail,
      });
      setHost(""); await load();
    } catch (e: any) {
      setError(e?.response?.data?.message ?? t("agenda.erroCriar"));
    } finally { setCreating(false); }
  }

  async function toggle(id: string) {
    try { await api.patch(`/scheduled-scans/${id}/toggle`); await load(); }
    catch { setError(t("agenda.erroAtualizar")); }
  }

  async function remove(id: string) {
    if (!confirm(t("agenda.confirmaRemover"))) return;
    try { await api.delete(`/scheduled-scans/${id}`); await load(); }
    catch { setError(t("agenda.erroRemover")); }
  }

  async function toggleHistory(h: string) {
    if (expandedHost === h) { setExpandedHost(null); return; }
    setExpandedHost(h);
    if (hostHistory[h]) return; // already loaded
    setHistoryLoading(p => ({ ...p, [h]: true }));
    try {
      const res = await api.get<HistorySummary[]>(`/history/${h}?origin=SCHEDULED`);
      setHostHistory(p => ({ ...p, [h]: res.data.slice(0, 10) }));
    } catch {
      setHostHistory(p => ({ ...p, [h]: [] }));
    } finally {
      setHistoryLoading(p => ({ ...p, [h]: false }));
    }
  }

  function fmtDate(d: string | null) {
    if (!d) return "—";
    return new Date(d).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
  }

  function scoreBadgeCls(score: number) {
    if (score >= 80) return styles.secure;
    if (score >= 60) return styles.low;
    if (score >= 40) return styles.warning;
    if (score >= 20) return styles.high;
    return styles.critical;
  }

  return (
    <div className={styles.adminWrap}>
      <h2 className={styles.adminTitle}>{t("agenda.titulo")}</h2>

      {/* Formulário de criação */}
      <form onSubmit={create} className={styles.scheduleForm}>
        <input
          className={styles.urlInput}
          value={host}
          onChange={e => setHost(e.target.value)}
          placeholder={t("scan.placeholder")}
          disabled={creating}
        />
        <select
          className={styles.roleSelect}
          value={frequency}
          onChange={e => setFrequency(e.target.value as "DAILY" | "WEEKLY")}
          disabled={creating}
        >
          <option value="DAILY">{t("agenda.diario")}</option>
          <option value="WEEKLY">{t("agenda.semanal")}</option>
        </select>
        <select
          className={styles.roleSelect}
          value={hour}
          onChange={e => setHour(Number(e.target.value))}
          disabled={creating}
        >
          {Array.from({ length: 24 }, (_, i) => (
            <option key={i} value={i}>{String(i).padStart(2, "0")}:00 UTC</option>
          ))}
        </select>
        <label className={styles.toggle} title={reportVerifiedOnly
          ? t("scan.emailSoVerificados")
          : t("agenda.emailAoConcluir")}>
          <input type="checkbox" checked={notifyEmail} onChange={e => setNotifyEmail(e.target.checked)} disabled={creating} />
          <span className={styles.toggleLabel}>EMAIL</span>
        </label>
        <label className={styles.toggle} title={t("agenda.modoAtivo")}>
          <input type="checkbox" checked={activeMode} onChange={e => setActiveMode(e.target.checked)} disabled={creating} />
          <span className={styles.toggleLabel} style={{ color: activeMode ? "var(--warning)" : undefined }}>ACTIVE</span>
        </label>
        <button className={`${styles.btn} ${styles.btnScan}`} type="submit" disabled={creating || !host.trim()}>
          {creating ? "..." : t("agenda.agendar")}
        </button>
      </form>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading ? (
        <div className={styles.empty}>{t("app.carregando")}</div>
      ) : schedules.length === 0 ? (
        <div className={styles.empty}>{t("agenda.vazio")}</div>
      ) : (
        <table className={styles.userTable}>
          <thead>
            <tr>
              <th>{t("agenda.dominio")}</th>
              <th>{t("agenda.frequencia")}</th>
              <th>{t("agenda.proximoScan")}</th>
              <th>{t("agenda.ultimoScan")}</th>
              <th>Email</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {schedules.map(s => (
              <>
                <tr key={s.id}>
                  <td>
                    <button
                      className={`${styles.btn} ${styles.btnGhost}`}
                      style={{ fontFamily: "var(--mono)", fontSize: "0.78rem", padding: "2px 8px" }}
                      onClick={() => toggleHistory(s.host)}
                      title={t("agenda.verHistorico")}
                    >
                      {expandedHost === s.host ? "▾" : "▸"} {s.host}
                    </button>
                  </td>
                  <td>
                    {s.frequency === "DAILY" ? t("agenda.diario") : t("agenda.semanal")} {String(s.preferredHour).padStart(2, "0")}:00 UTC
                    {s.active && <span className={`${styles.tag} ${styles.warning}`} style={{ marginLeft: 6, fontSize: "0.65rem" }}>ACTIVE</span>}
                  </td>
                  <td className={styles.muted}>{fmtDate(s.nextRun)}</td>
                  <td className={styles.muted}>{fmtDate(s.lastRun)}</td>
                  <td>{s.notifyEmail ? <span className={styles.ok}>✓</span> : <span className={styles.muted}>—</span>}</td>
                  <td>
                    {s.enabled
                      ? <span className={styles.ok}>Ativo</span>
                      : <span className={styles.muted}>Pausado</span>}
                  </td>
                  <td>
                    <div className={styles.actionBtns}>
                      <button className={`${styles.btn} ${styles.btnGhost}`} onClick={() => toggle(s.id)}>
                        {s.enabled ? "Pausar" : "Retomar"}
                      </button>
                      <button className={`${styles.btn} ${styles.btnDanger}`} onClick={() => remove(s.id)}>
                        Remover
                      </button>
                    </div>
                  </td>
                </tr>

                {/* ── Histórico expandido ── */}
                {expandedHost === s.host && (
                  <tr key={`${s.id}-history`}>
                    <td colSpan={7} style={{ padding: "0 0 0 1rem", background: "var(--bg)" }}>
                      <div style={{ borderLeft: "2px solid var(--border2)", padding: "0.75rem 1rem", margin: "0.25rem 0 0.5rem" }}>
                        {historyLoading[s.host] ? (
                          <div className={styles.muted} style={{ fontSize: "0.8rem" }}>{t("agenda.carregandoScans")}</div>
                        ) : !hostHistory[s.host]?.length ? (
                          <div style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: 8 }}><span className={`${styles.tag} ${styles.warning}`}>PENDENTE</span><span className={styles.muted}>Nenhum scan agendado executado ainda. Próximo: {fmtDate(s.nextRun)}</span></div>
                        ) : (
                          <>
                            <div style={{ fontSize: "0.7rem", fontWeight: 700, letterSpacing: "1.5px", color: "var(--text-muted)", marginBottom: "0.5rem", textTransform: "uppercase" }}>
                              Últimos {hostHistory[s.host].length} scans
                            </div>
                            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                              {hostHistory[s.host].map(h => (
                                <button
                                  key={h.id}
                                  onClick={() => setDetailId(h.id)}
                                  style={{
                                    display: "flex", alignItems: "center", gap: 10,
                                    background: "var(--surface)", border: "1px solid var(--border)",
                                    borderRadius: "var(--radius-sm)", padding: "6px 10px",
                                    cursor: "pointer", textAlign: "left", width: "100%",
                                    transition: "border-color .15s",
                                  }}
                                  onMouseEnter={e => (e.currentTarget.style.borderColor = "var(--accent)")}
                                  onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--border)")}
                                >
                                  {/* Score badge */}
                                  <span className={`${styles.tag} ${scoreBadgeCls(h.score)}`} style={{ minWidth: 38, textAlign: "center", fontWeight: 700 }}>
                                    {h.score}
                                  </span>
                                  {/* Risk */}
                                  <span className={`${styles.tag} ${riskColor(h.riskLevel)}`} style={{ minWidth: 60, textAlign: "center" }}>
                                    {h.riskLevel}
                                  </span>
                                  {/* Date */}
                                  <span className={styles.muted} style={{ fontSize: "0.78rem", flex: 1 }}>
                                    {fmtDate(h.scannedAt)}
                                  </span>
                                  {/* Active mode badge */}
                                  {h.activeMode && (
                                    <span className={`${styles.tag} ${styles.info}`} style={{ fontSize: "0.65rem" }}>ATIVO</span>
                                  )}
                                  {/* Open icon */}
                                  <span className={styles.muted} style={{ fontSize: "0.75rem" }}>{t("agenda.verDetalhes")}</span>
                                </button>
                              ))}
                            </div>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      )}

      {/* Modal de detalhe do scan */}
      {detailId && (
        <ScheduleScanDetailModal id={detailId} onClose={() => setDetailId(null)} />
      )}
    </div>
  );
}

// ── Admin Panel ───────────────────────────────────────────────────────────────

// ── Audit Logs types ─────────────────────────────────────────────────────────

interface AuditLogEntry {
  id: string;
  userId: string | null;
  userEmail: string | null;
  userName: string | null;
  action: string;
  details: string | null;
  ipAddress: string | null;
  timestamp: string;
  success: boolean;
}

/**
 * Rótulos do log de auditoria.
 *
 * Tabela no nível do MÓDULO — fora de componente não existe `t()`. Por isso
 * guarda CHAVES de catálogo, e quem renderiza resolve. É o mesmo formato do
 * TECH_RISK, e o padrão para qualquer tabela de módulo com texto de tela.
 *
 * Ação desconhecida cai no próprio código da ação (ver AuditLogsTab): ação nova
 * no Backend aparece crua na tela em vez de sumir dela.
 */
const AUDIT_ACTION_KEYS: Record<string, string> = {
  LOGIN_SUCCESS:       "auditoria.loginOk",
  LOGIN_FAILED:        "auditoria.loginFalha",
  LOGIN_2FA_VERIFIED:  "auditoria.2faVerificado",
  SCAN_STARTED:        "auditoria.scanIniciado",
  SCAN_COMPLETED:      "auditoria.scanConcluido",
  DOMAIN_ADDED:        "auditoria.dominioAdicionado",
  DOMAIN_VERIFIED:     "auditoria.dominioVerificado",
  DOMAIN_REMOVED:      "auditoria.dominioRemovido",
  USER_INVITED:        "auditoria.conviteCriado",
  USER_ROLE_CHANGED:   "auditoria.roleAlterado",
  USER_DEACTIVATED:    "auditoria.usuarioDesativado",
  USER_REACTIVATED:    "auditoria.usuarioReativado",
  TOTP_ENABLED:        "auditoria.totpAtivado",
  TOTP_DISABLED:       "auditoria.totpDesativado",
  EMAIL_OTP_ENABLED:   "auditoria.emailOtpAtivado",
  EMAIL_OTP_DISABLED:  "auditoria.emailOtpDesativado",
  REQUIRE_2FA_CHANGED: "auditoria.require2faAlterado",
  DATA_EXPORTED:       "auditoria.dadosExportados",
  ACCOUNT_DELETED:     "auditoria.contaExcluida",
};

function AuditLogsTab() {
  const { t } = useI18n();
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [page, setPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [totalElements, setTotalElements] = useState(0);
  const [loading, setLoading] = useState(false);
  const [filterFrom, setFilterFrom] = useState("");
  const [filterTo,   setFilterTo]   = useState("");

  useEffect(() => { loadLogs(0); }, []);

  async function loadLogs(p: number, from?: string, to?: string) {
    setLoading(true);
    try {
      const params: Record<string, string> = { page: String(p), size: "50" };
      if (from) params.from = from;
      if (to)   params.to   = to;
      const r = await api.get<{ logs: AuditLogEntry[]; totalPages: number; totalElements: number }>(
        `/admin/audit-logs?${new URLSearchParams(params).toString()}`
      );
      setLogs(r.data.logs);
      setTotalPages(r.data.totalPages);
      setTotalElements(r.data.totalElements);
      setPage(p);
    } catch {}
    finally { setLoading(false); }
  }

  function applyFilter() { loadLogs(0, filterFrom || undefined, filterTo || undefined); }
  function clearFilter() { setFilterFrom(""); setFilterTo(""); loadLogs(0); }

  function actionBadge(action: string, success: boolean) {
    // Ação sem chave cai no próprio código: ação nova no Backend aparece crua
    // na tela, em vez de sumir dela.
    const chave = AUDIT_ACTION_KEYS[action];
    const label = chave ? t(chave) : action;
    const isFailure = action === "LOGIN_FAILED" || !success;
    const isAuth = action.startsWith("LOGIN") || action.includes("2FA") || action.includes("TOTP") || action.includes("OTP");
    const isScan = action.startsWith("SCAN");
    const isDomain = action.startsWith("DOMAIN");
    const isUser = action.startsWith("USER") || action === "REQUIRE_2FA_CHANGED";
    const isData = action === "DATA_EXPORTED" || action === "ACCOUNT_DELETED";
    const cls = isFailure ? styles.critical : isScan ? styles.info : isDomain ? styles.secure : isUser ? styles.warning : isData ? styles.critical : isAuth ? styles.ok : styles.muted;
    return <span className={`${styles.tag} ${cls}`}>{label}</span>;
  }

  const hasFilter = !!filterFrom || !!filterTo;

  return (
    <div className={styles.adminContent}>
      <Card title={`AUDIT LOG — ${totalElements} evento${totalElements !== 1 ? "s" : ""}${hasFilter ? " (filtrado)" : ""}`}>
        {/* Filtro de datas */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{t("auditoria.filtrarPeriodo")}</span>
          <input
            type="date"
            value={filterFrom}
            onChange={e => setFilterFrom(e.target.value)}
            className={styles.formInput}
            style={{ padding: "4px 8px", fontSize: 12, width: 140 }}
            placeholder={t("auditoria.phDe")}
          />
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{t("auditoria.ate")}</span>
          <input
            type="date"
            value={filterTo}
            onChange={e => setFilterTo(e.target.value)}
            className={styles.formInput}
            style={{ padding: "4px 8px", fontSize: 12, width: 140 }}
            placeholder={t("auditoria.phAte")}
          />
          <button className={`${styles.btn} ${styles.btnScan} ${styles.btnSm}`} onClick={applyFilter}>
            Filtrar
          </button>
          {hasFilter && (
            <button className={`${styles.btn} ${styles.btnGhost} ${styles.btnSm}`} onClick={clearFilter}>
              Limpar
            </button>
          )}
        </div>

        {loading ? (
          <div className={styles.empty}>{t("auditoria.carregando")}</div>
        ) : logs.length === 0 ? (
          <div className={styles.empty}>{t("auditoria.semEventos", hasFilter ? t("auditoria.noPeriodo") : t("auditoria.registrado"))}</div>
        ) : (
          <>
            <div className={styles.auditTableWrap}>
              <table className={styles.adminTable}>
                <thead>
                  <tr>
                    <th>Data/Hora</th>
                    <th>{t("auditoria.usuario")}</th>
                    <th>{t("auditoria.acao")}</th>
                    <th>Detalhes</th>
                    <th>IP</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map(log => (
                    <tr key={log.id} className={log.success ? "" : styles.inactiveRow}>
                      <td className={styles.muted} style={{ whiteSpace: "nowrap", fontSize: 11 }}>
                        {new Date(log.timestamp).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "medium" })}
                      </td>
                      <td>
                        <div style={{ lineHeight: 1.3 }}>
                          <span style={{ fontSize: 12 }}>{log.userName ?? "—"}</span>
                          {log.userEmail && <div className={styles.muted} style={{ fontSize: 10 }}>{log.userEmail}</div>}
                        </div>
                      </td>
                      <td>{actionBadge(log.action, log.success)}</td>
                      <td className={styles.muted} style={{ fontSize: 11, maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {log.details ?? "—"}
                      </td>
                      <td><code className={styles.code} style={{ fontSize: 10 }}>{log.ipAddress ?? "—"}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {totalPages > 1 && (
              <div className={styles.auditPagination}>
                <button className={`${styles.btn} ${styles.btnGhost}`} disabled={page === 0} onClick={() => loadLogs(page - 1, filterFrom || undefined, filterTo || undefined)}>{t("auditoria.anterior")}</button>
                <span className={styles.muted}>Página {page + 1} de {totalPages}</span>
                <button className={`${styles.btn} ${styles.btnGhost}`} disabled={page >= totalPages - 1} onClick={() => loadLogs(page + 1, filterFrom || undefined, filterTo || undefined)}>{t("auditoria.proxima")}</button>
              </div>
            )}
          </>
        )}
      </Card>
    </div>
  );
}

function AdminPanel({ onUpgrade }: { onUpgrade: () => void }) {
  const { t } = useI18n();
  const { user } = useAuth();
  const isCompany = user?.account?.type === "COMPANY";
  const [tab, setTab] = useState<"users" | "invites" | "audit" | "feedback">(
    isCompany && user?.role === "OWNER" ? "users" : isCompany ? "invites" : "audit"
  );
  const [users, setUsers] = useState<UserManagementDto[]>([]);
  const [invites, setInvites] = useState<InviteDto[]>([]);
  const [loading, setLoading] = useState(false);
  const [invName, setInvName] = useState("");
  const [invEmail, setInvEmail] = useState("");
  const [invRole, setInvRole] = useState<"ADMIN" | "FREE_EMPLOYEE">("FREE_EMPLOYEE");
  const [invJob, setInvJob] = useState("");
  const [inviting, setInviting] = useState(false);
  const [newInvite, setNewInvite] = useState<InviteDto | null>(null);
  // Relatórios da conta (auditoria, PDF executivo, página de status) são PRO+.
  // Gestão de equipe abaixo continua valendo só o role, de propósito.
  const canReports = user?.account?.reportsModuleAllowed === true;
  // Triagem de contestação é da equipe da plataforma, não do dono da conta —
  // quem julga se o scanner errou somos nós. O backend revalida em
  // PlatformStaffService; isto aqui só evita mostrar uma aba que daria 403.
  const isStaff = user?.platformStaff === true;
  const [statusToken, setStatusToken] = useState<string | null>(user?.account?.publicStatusToken ?? null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [copiedStatus, setCopiedStatus] = useState(false);
  const [invError, setInvError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [showPdfModal,  setShowPdfModal]  = useState(false);
  const [pdfScope,      setPdfScope]      = useState<"DOMAINS" | "TEAM_SCANS" | "BOTH">("DOMAINS");
  const [pdfFrom,       setPdfFrom]       = useState("");
  const [pdfTo,         setPdfTo]         = useState("");
  const [feedbacks,     setFeedbacks]     = useState<FeedbackDto[]>([]);
  const [fbLoading,     setFbLoading]     = useState(false);
  const [fbFilter,      setFbFilter]      = useState<"" | FeedbackStatus>("");

  useEffect(() => { loadUsers(); loadInvites(); }, []);
  useEffect(() => { if (user?.role === "ADMIN") setInvRole("FREE_EMPLOYEE"); }, [user]);
  useEffect(() => { if (tab === "feedback" && isStaff) loadFeedbacks(); /* eslint-disable-next-line */ }, [tab, fbFilter, isStaff]);

  async function loadFeedbacks() {
    setFbLoading(true);
    try {
      const params = fbFilter ? { status: fbFilter } : {};
      setFeedbacks((await api.get<FeedbackDto[]>("/admin/feedback", { params })).data);
    } catch {} finally { setFbLoading(false); }
  }
  async function replyFeedback(id: string, adminResponse: string, status: FeedbackStatus) {
    try { await api.put(`/admin/feedback/${id}`, { adminResponse, status }); await loadFeedbacks(); }
    catch (e: any) { alert(e?.response?.data?.message ?? t("admin.erroSalvar")); }
  }

  async function deleteFeedback(id: string, reason: string) {
    // Deixa o erro subir: quem chama mostra a mensagem junto do campo de
    // justificativa, em vez de um alert que perde o texto já digitado.
    await api.post(`/admin/feedback/${id}/delete`, { reason });
    await loadFeedbacks();
  }

  async function loadUsers() { setLoading(true); try { setUsers((await api.get<UserManagementDto[]>("/admin/users")).data); } catch {} finally { setLoading(false); } }
  async function loadInvites() { try { setInvites((await api.get<InviteDto[]>("/admin/invites")).data); } catch {} }
  async function deactivate(id: string) { if (!confirm(t("admin.confirmaDesativar"))) return; try { await api.delete(`/admin/users/${id}`); loadUsers(); } catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); } }
  async function reactivate(id: string) { try { await api.put(`/admin/users/${id}/reactivate`); loadUsers(); } catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); } }
  async function changeRole(id: string, role: string) { try { await api.put(`/admin/users/${id}/role`, { role }); loadUsers(); } catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); } }
  async function revokeInvite(id: string) { if (!confirm(t("admin.confirmaRevogar"))) return; try { await api.delete(`/admin/invites/${id}`); loadInvites(); } catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); } }
  async function sendInvite(e: React.FormEvent) {
    e.preventDefault(); setInviting(true); setInvError(null); setNewInvite(null);
    try { const r = await api.post<InviteDto>("/admin/invite", { name: invName, email: invEmail, role: invRole, jobTitle: invJob || null }); setNewInvite(r.data); setInvName(""); setInvEmail(""); setInvJob(""); loadInvites(); }
    catch (e: any) { setInvError(e?.response?.data?.message ?? t("admin.erroConvite")); }
    finally { setInviting(false); }
  }
  function copyLink() { if (!newInvite?.acceptLink) return; navigator.clipboard.writeText(window.location.origin + newInvite.acceptLink); setCopied(true); setTimeout(() => setCopied(false), 2000); }
  async function downloadExecutivePdf() {
    setShowPdfModal(false);
    setDownloadingPdf(true);
    try {
      const params: Record<string, string> = { scope: pdfScope };
      if (pdfFrom) params.from = pdfFrom;
      if (pdfTo)   params.to   = pdfTo;
      const response = await api.get("/admin/report/executive-pdf", {
        responseType: "blob",
        params,
      });
      const url = URL.createObjectURL(new Blob([response.data], { type: "application/pdf" }));
      const link = document.createElement("a");
      link.href = url;
      const today = new Date().toISOString().slice(0, 10);
      link.download = `cyberaudit-report-${pdfScope.toLowerCase()}-${today}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (e: any) {
      alert(t("admin.erroPdf"));
    } finally {
      setDownloadingPdf(false);
    }
  }
  async function toggleStatusPage(enable: boolean) {
    setStatusLoading(true);
    try {
      const res = await api.post<{ enabled: boolean; token: string }>("/admin/account/status-page", { enabled: enable });
      setStatusToken(enable ? res.data.token : null);
    } catch (e: any) {
      alert(e?.response?.data?.message ?? t("admin.erroStatusPage"));
    } finally {
      setStatusLoading(false);
    }
  }
  function copyStatusLink() {
    if (!statusToken) return;
    navigator.clipboard.writeText(`${window.location.origin}/status/${statusToken}`);
    setCopiedStatus(true);
    setTimeout(() => setCopiedStatus(false), 2000);
  }
  function roleBadge(role: string) {
    const cls = role === "OWNER" ? styles.secure : role === "ADMIN" ? styles.warning : styles.info;
    return <Tag label={role} cls={cls} />;
  }

  return (
    <div className={styles.adminPage}>
      <div className={styles.adminHeader}>
        <div className={styles.adminHeaderLeft}>
          <div className={styles.adminTitle}>{t("admin.titulo")}</div>
          {canReports && (
            <button
              className={`${styles.btn} ${styles.btnGhost} ${styles.btnSm}`}
              onClick={() => setShowPdfModal(true)}
              disabled={downloadingPdf}
              title={t("admin.gerarPdfTitulo")}
            >
              {downloadingPdf ? t("admin.gerando") : t("admin.relatorioPdf")}
            </button>
          )}
        </div>

        {/* Modal de configuração do PDF executivo */}
        {showPdfModal && (
          <div className={styles.modalOverlay} onClick={() => setShowPdfModal(false)}>
            <div className={styles.modal} onClick={e => e.stopPropagation()} style={{ maxWidth: 440 }}>
              <div className={styles.modalHeader}>
                <span className={styles.modalTitle}>{t("admin.relatorioExecutivo")}</span>
                <button className={styles.modalClose} onClick={() => setShowPdfModal(false)}>✕</button>
              </div>
              <div className={styles.modalBody}>
                <div className={styles.formGroup}>
                  <label className={styles.formLabel}>{t("admin.escopoRelatorio")}</label>
                  <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 6 }}>
                    {([
                      ["DOMAINS",    t("admin.escopoDominios"),  t("admin.escopoDominiosDesc")],
                      ["TEAM_SCANS", t("admin.escopoEquipe"),       t("admin.escopoEquipeDesc")],
                      ["BOTH",       t("admin.ambos"),                 t("admin.escopoAmbos")],
                    ] as const).map(([val, label, desc]) => (
                      <label key={val} className={styles.roleOption} style={{ cursor: "pointer" }}>
                        <input
                          type="radio"
                          name="pdfScope"
                          value={val}
                          checked={pdfScope === val}
                          onChange={() => setPdfScope(val)}
                        />
                        <div>
                          <strong style={{ fontSize: 13 }}>{label}</strong>
                          <div className={styles.roleDesc}>{desc}</div>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>

                <div className={styles.formGroup} style={{ marginTop: 16 }}>
                  <label className={styles.formLabel}>{t("admin.filtroPeriodo")}</label>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 6 }}>
                    <input
                      type="date"
                      value={pdfFrom}
                      onChange={e => setPdfFrom(e.target.value)}
                      className={styles.formInput}
                      style={{ flex: 1 }}
                    />
                    <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{t("auditoria.ate")}</span>
                    <input
                      type="date"
                      value={pdfTo}
                      onChange={e => setPdfTo(e.target.value)}
                      className={styles.formInput}
                      style={{ flex: 1 }}
                    />
                  </div>
                  <div className={styles.roleDesc} style={{ marginTop: 4 }}>
                    Sem filtro: inclui todos os scans disponíveis.
                  </div>
                </div>

                <button
                  className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`}
                  style={{ marginTop: 20 }}
                  onClick={downloadExecutivePdf}
                  disabled={downloadingPdf}
                >
                  {downloadingPdf ? t("admin.gerandoPdf") : t("admin.gerarBaixar")}
                </button>
              </div>
            </div>
          </div>
        )}
        {(isCompany || user?.role === "OWNER" || user?.role === "ADMIN") && (
          <div className={styles.adminTabs}>
            {isCompany && user?.role === "OWNER" && (<button className={`${styles.adminTab} ${tab === "users" ? styles.adminTabActive : ""}`} onClick={() => setTab("users")}>Usuários ({users.length})</button>)}
            {isCompany && (<button className={`${styles.adminTab} ${tab === "invites" ? styles.adminTabActive : ""}`} onClick={() => setTab("invites")}>Convites ({invites.length})</button>)}
            {(user?.role === "OWNER" || user?.role === "ADMIN") && (<button className={`${styles.adminTab} ${tab === "audit" ? styles.adminTabActive : ""}`} onClick={() => setTab("audit")}>{t("admin.abaAuditoria")}{canReports ? "" : " 🔒"}</button>)}
            {isStaff && (<button className={`${styles.adminTab} ${tab === "feedback" ? styles.adminTabActive : ""}`} onClick={() => setTab("feedback")}>Feedback</button>)}
          </div>
        )}
      </div>
      {tab === "users" && (
        <div className={styles.adminContent}>
          <Card title={t("admin.usuarios")}>
            {loading ? <div className={styles.empty}>{t("app.carregando")}</div> : (
              <table className={styles.adminTable}>
                <thead><tr><th>Nome</th><th>Email</th><th>Role</th><th>Status</th><th>{t("admin.convidadoPor")}</th><th>{t("admin.acoes")}</th></tr></thead>
                <tbody>
                  {users.map(u => (
                    <tr key={u.id} className={!u.active ? styles.inactiveRow : ""}>
                      <td>{u.name}{u.jobTitle && <span className={styles.jobTitle}> · {u.jobTitle}</span>}</td>
                      <td><code className={styles.code}>{u.email}</code></td>
                      <td>{roleBadge(u.role)}</td>
                      <td><span className={u.active ? styles.ok : styles.bad}>{u.active ? "Ativo" : "Inativo"}</span></td>
                      <td className={styles.muted}>{u.invitedByName}</td>
                      <td>{u.role !== "OWNER" && (<div className={styles.actionBtns}>{u.active ? <button className={`${styles.btn} ${styles.btnDanger}`} onClick={() => deactivate(u.id)}>Desativar</button> : <button className={`${styles.btn} ${styles.btnGhost}`} onClick={() => reactivate(u.id)}>Reativar</button>}<select className={styles.roleSelect} value={u.role} onChange={e => changeRole(u.id, e.target.value)}><option value="ADMIN">ADMIN</option><option value="FREE_EMPLOYEE">EMPLOYEE</option></select></div>)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </div>
      )}
      {tab === "invites" && (
        <div className={styles.adminContent}>
          <div className={styles.adminRow}>
            <Card title="NOVO CONVITE">
              <form className={styles.inviteForm} onSubmit={sendInvite}>
                <div className={styles.formGroup}><label className={styles.formLabel}>{t("admin.nome")}</label><input className={styles.formInput} value={invName} onChange={e => setInvName(e.target.value)} placeholder={t("admin.phNome")} required /></div>
                <div className={styles.formGroup}><label className={styles.formLabel}>{t("login.emailObrig")}</label><input className={styles.formInput} type="email" value={invEmail} onChange={e => setInvEmail(e.target.value)} placeholder={t("admin.phEmailEmpresa")} required /></div>
                <div className={styles.formGroup}><label className={styles.formLabel}>CARGO</label><input className={styles.formInput} value={invJob} onChange={e => setInvJob(e.target.value)} placeholder={t("admin.phCargo")} /></div>
                <div className={styles.formGroup}>
                  <label className={styles.formLabel}>{t("admin.nivelAcesso")}</label>
                  <div className={styles.roleOptions}>
                    {user?.role === "OWNER" && (<label className={styles.roleOption}><input type="radio" name="role" value="ADMIN" checked={invRole === "ADMIN"} onChange={() => setInvRole("ADMIN")} /><div><strong>{t("admin.admin")}</strong><div className={styles.roleDesc}>{t("admin.adminDesc")}</div></div></label>)}
                    <label className={styles.roleOption}><input type="radio" name="role" value="FREE_EMPLOYEE" checked={invRole === "FREE_EMPLOYEE" || user?.role === "ADMIN"} onChange={() => setInvRole("FREE_EMPLOYEE")} /><div><strong>{t("admin.funcionario")}</strong><div className={styles.roleDesc}>{t("admin.funcionarioDesc")}</div></div></label>
                  </div>
                </div>
                {invError && <div className={styles.errorBox}>{invError}</div>}
                {newInvite && (<div className={styles.inviteSuccess}><div className={styles.inviteSuccessTitle}>{t("admin.conviteCriado")}</div><div className={styles.tokenRow}><code className={styles.stepCode}>{newInvite.acceptLink}</code><button type="button" className={styles.copyBtn} onClick={copyLink}>{copied ? "✓" : "Copiar link"}</button></div></div>)}
                <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={inviting}>{inviting ? t("admin.criando") : t("admin.enviarConvite")}</button>
              </form>
            </Card>
            <Card title="CONVITES PENDENTES">
              {invites.length === 0 ? <div className={styles.empty}>{t("admin.semConvites")}</div> : (
                <div className={styles.pendingInvites}>{invites.map(inv => (<InviteItemRow key={inv.id} inv={inv} onRevoke={() => revokeInvite(inv.id)} roleBadge={roleBadge} />))}</div>
              )}
            </Card>
          </div>
        </div>
      )}
      {tab === "audit" && (canReports
        ? <AuditLogsTab />
        : <PagePlanLocked
            titulo={t("admin.auditoriaPro")}
            descricao={t("admin.auditoriaProDesc")}
            onUpgrade={onUpgrade} />)}

      {tab === "feedback" && isStaff && (
        <div className={styles.adminContent}>
          <Card title="FEEDBACK DE CLIENTES">
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 12 }}>
              Contestações enviadas por clientes sobre resultados de scan. Responda e atualize o status para triar.
            </div>
            <div style={{ display: "flex", gap: 6, marginBottom: 14, flexWrap: "wrap" }}>
              {([["", t("feedback.todos")], ["OPEN", t("feedback.abertos")], ["REVIEWING", t("feedback.emAnalise")], ["RESOLVED", t("feedback.resolvidos")]] as const).map(([val, label]) => (
                <button
                  key={val || "ALL"}
                  className={`${styles.btn} ${styles.btnSm} ${fbFilter === val ? styles.btnScan : styles.btnGhost}`}
                  onClick={() => setFbFilter(val as "" | FeedbackStatus)}
                >
                  {label}
                </button>
              ))}
            </div>
            {fbLoading ? <div className={styles.empty}>{t("app.carregando")}</div>
              : feedbacks.length === 0 ? <div className={styles.empty}>{t("admin.semFeedback", fbFilter ? t("admin.comEsseStatus") : "")}</div>
              : <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {feedbacks.map(f => <FeedbackAdminRow key={f.id} f={f} onReply={replyFeedback} onDelete={deleteFeedback} />)}
                </div>}
          </Card>
        </div>
      )}

      {/* Status Page toggle — OWNER e plano com relatórios (PRO+) */}
      {user?.role === "OWNER" && canReports && (
        <div className={styles.adminContent} style={{ marginTop: 20 }}>
          <Card title={t("admin.paginaStatus")}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 14 }}>
              Gera um link público (sem login) com o status de segurança dos seus domínios. Compartilhe com clientes ou equipe.
            </div>
            {statusToken ? (
              <div>
                <div className={styles.tokenRow} style={{ marginBottom: 10 }}>
                  <code className={styles.stepCode} style={{ fontSize: 10, wordBreak: "break-all" }}>
                    {window.location.origin}/status/{statusToken}
                  </code>
                  <button className={styles.copyBtn} onClick={copyStatusLink}>{copiedStatus ? "✓" : "Copiar link"}</button>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button className={`${styles.btn} ${styles.btnGhost} ${styles.btnSm}`} onClick={() => toggleStatusPage(true)} disabled={statusLoading}>
                    {statusLoading ? "..." : t("admin.regenerarToken")}
                  </button>
                  <button className={`${styles.btn} ${styles.btnDanger} ${styles.btnSm}`} onClick={() => toggleStatusPage(false)} disabled={statusLoading}>
                    {statusLoading ? "..." : "Desativar"}
                  </button>
                </div>
              </div>
            ) : (
              <button className={`${styles.btn} ${styles.btnScan}`} onClick={() => toggleStatusPage(true)} disabled={statusLoading}>
                {statusLoading ? t("admin.ativando") : t("admin.ativarStatus")}
              </button>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}

// ── Changes History Page ──────────────────────────────────────────────────────

// ── Shared: scan row used in both tabs ───────────────────────────────────────

function ScanTimelineRow({
  s, idx: _idx, isFirst, showHost,
  scanDetails, toggleScan,
  changeTypeBadge, sevBadge, riskBadgeStyle,
}: {
  s: HistorySummary; idx: number; isFirst: boolean; showHost: boolean;
  scanDetails: Record<string, { open: boolean; loading: boolean; changes: ScanChange[] | null; error: string | null }>;
  toggleScan: (id: string) => void;
  changeTypeBadge: (t: string) => React.ReactNode;
  sevBadge: (s: string) => React.ReactNode;
  riskBadgeStyle: (r: string) => string;
}) {
  const { t } = useI18n();
  const detail      = scanDetails[s.id];
  const isOpen      = detail?.open ?? false;
  const changes     = detail?.changes ?? null;
  const changeCount = changes?.length ?? null;
  const hasDegraded = changes?.some(c => c.changeType === "DEGRADED");

  return (
    <div key={s.id} className={`${styles.changesScanRow} ${isFirst ? styles.changesScanRowLatest : ""}`}>
      <div className={styles.changesScanHeader} onClick={() => toggleScan(s.id)}>
        <div className={styles.changesScanLeft}>
          <div className={styles.changesTimelineDot} style={{
            background: hasDegraded ? "var(--critical)" :
                        changeCount === 0 ? "var(--secure)" :
                        changeCount === null ? "var(--border2)" : "var(--warning)",
          }} />
          <div className={styles.changesScanInfo}>
            <span className={styles.changesScanDate}>
              {showHost && <code className={styles.code} style={{ fontSize: 11, marginRight: 6 }}>{s.host}</code>}
              {new Date(s.scannedAt).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" })}
              {isFirst && <span className={styles.changesLatestBadge}>{t("changes.maisRecente")}</span>}
              {s.activeMode && <span className={`${styles.tag} ${styles.info}`} style={{ fontSize: 9 }}>ACTIVE</span>}
              {s.origin === "SCHEDULED" && <span className={`${styles.tag} ${styles.warning}`} style={{ fontSize: 9 }}>AGENDADO</span>}
            </span>
            <div className={styles.changesScanBadges}>
              <span className={`${styles.tag} ${riskBadgeStyle(s.riskLevel)}`}>{s.riskLevel}</span>
              <span className={styles.changesScanScore}>{s.score}<span className={styles.muted}>/100</span></span>
              {changeCount !== null && (
                <span className={styles.muted} style={{ fontSize: 11 }}>
                  {changeCount === 0 ? t("changes.semMudancas") : `${changeCount} mudança${changeCount !== 1 ? "s" : ""}`}
                </span>
              )}
            </div>
          </div>
        </div>
        <div className={styles.changesScanRight}>
          {detail?.loading && <span className={styles.muted} style={{ fontSize: 11 }}>carregando...</span>}
          <span className={`${styles.chevron} ${isOpen ? styles.chevronOpen : ""}`}>›</span>
        </div>
      </div>

      {isOpen && (
        <div className={styles.changesScanBody}>
          {detail?.error && <div className={styles.errorBox}>{detail.error}</div>}
          {detail?.loading && <div className={styles.empty}>{t("changes.carregandoDetalhes")}</div>}
          {changes !== null && changes.length === 0 && (
            <div className={styles.empty} style={{ padding: "12px 0" }}>
              ✓ Nenhuma mudança detectada em relação ao scan anterior.
            </div>
          )}
          {changes !== null && changes.length > 0 && (
            <table className={styles.changesTable}>
              <thead>
                <tr>
                  <th>Tipo</th>
                  <th>Categoria</th>
                  <th>Campo</th>
                  <th>{t("changes.severidade")}</th>
                  <th>Antes</th>
                  <th>Depois</th>
                </tr>
              </thead>
              <tbody>
                {changes.map((c, i) => (
                  <tr key={i} className={
                    c.changeType === "DEGRADED" ? styles.changeDegraded :
                    c.changeType === "IMPROVED" ? styles.changeImproved : ""
                  }>
                    <td>{changeTypeBadge(c.changeType)}</td>
                    <td className={styles.muted}>{c.category}</td>
                    <td><code className={styles.code} style={{ fontSize: 11 }}>{c.field}</code></td>
                    <td>{sevBadge(c.severity)}</td>
                    <td className={styles.changeOld}>{c.oldValue || "—"}</td>
                    <td className={styles.changeNew}>{c.newValue || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

function ChangesPage() {
  const { t } = useI18n();
  const [tab, setTab] = useState<"overview" | "domain" | "analysis">("overview");
  // ── Análise tab state ──────────────────────────────────────────────────────
  const [analysisHost, setAnalysisHost]     = useState<string | null>(null);
  const [analysisSearch, setAnalysisSearch] = useState("");
  // ── Overview tab state ────────────────────────────────────────────────────
  const [overviewList, setOverviewList]       = useState<HistorySummary[]>([]);
  const [overviewLoading, setOverviewLoading] = useState(false);
  const [overviewFilter, setOverviewFilter]   = useState<"all" | "active" | "passive">("all");

  // ── Shared lazy-load state ─────────────────────────────────────────────────
  const [scanDetails, setScanDetails] = useState<Record<string, {
    open: boolean; loading: boolean; changes: ScanChange[] | null; error: string | null;
  }>>({});

  function toggleScan(id: string) {
    setScanDetails(prev => {
      const cur = prev[id];
      // `cur` is undefined on first click — undefined !== null is true, so guard explicitly
      if (cur && (cur.changes !== null || cur.loading)) {
        return { ...prev, [id]: { ...cur, open: !cur.open } };
      }
      // First open — kick off fetch
      api.get<ScanResult>(`/history/${id}/result`)
        .then(r => setScanDetails(p => ({
          ...p, [id]: { open: true, loading: false, changes: r.data.changes ?? [], error: null },
        })))
        .catch(() => setScanDetails(p => ({
          ...p, [id]: { open: true, loading: false, changes: [], error: t("changes.erroDetalhes") },
        })));
      return { ...prev, [id]: { open: true, loading: true, changes: null, error: null } };
    });
  }

  // ── Shared badge helpers ───────────────────────────────────────────────────
  function changeTypeBadge(type: string) {
    if (type === "IMPROVED") return <span className={`${styles.tag} ${styles.secure}`}>IMPROVED</span>;
    if (type === "DEGRADED") return <span className={`${styles.tag} ${styles.critical}`}>DEGRADED</span>;
    return <span className={`${styles.tag} ${styles.info}`}>NEW</span>;
  }
  function sevBadge(sev: string) {
    const cls = sev === "CRITICAL" ? styles.critical : sev === "HIGH" ? styles.high : sev === "MEDIUM" ? styles.warning : styles.low;
    return <span className={`${styles.tag} ${cls}`}>{sev}</span>;
  }
  function riskBadgeStyle(risk: string) {
    return risk === "SECURE" ? styles.secure : risk === "LOW" ? styles.low :
           risk === "MEDIUM" ? styles.warning : risk === "HIGH" ? styles.high : styles.critical;
  }


  useEffect(() => {
    if (tab !== "overview") return;
    setOverviewLoading(true);
    api.get<HistorySummary[]>("/history/overview")
      .then(r => setOverviewList(r.data))
      .catch(() => setOverviewList([]))
      .finally(() => setOverviewLoading(false));
  }, [tab]);

  // ── Tab: Por domínio ───────────────────────────────────────────────────────
  const [registeredDomains, setRegisteredDomains] = useState<DomainDto[]>([]);
  const [searchHost, setSearchHost]               = useState("");
  const [activeHost, setActiveHost]               = useState<string | null>(null);
  const [domainList, setDomainList]               = useState<HistorySummary[]>([]);
  const [domainLoading, setDomainLoading]         = useState(false);
  const [domainError, setDomainError]             = useState<string | null>(null);
  const [domainFilter, setDomainFilter]           = useState<"all" | "manual" | "scheduled" | "active" | "passive">("all");

  useEffect(() => {
    api.get<DomainDto[]>("/domains").then(r => setRegisteredDomains(r.data)).catch(() => {});
  }, []);

  async function searchByHost(host: string) {
    const h = host.trim().replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
    if (!h) return;
    setActiveHost(h);
    setDomainFilter("all");
    setDomainLoading(true); setDomainError(null); setDomainList([]);
    try {
      const res = await api.get<HistorySummary[]>(`/history/${h}`);
      setDomainList([...res.data].sort((a, b) =>
        new Date(b.scannedAt).getTime() - new Date(a.scannedAt).getTime()
      ));
    } catch { setDomainError(t("changes.semScans")); }
    finally { setDomainLoading(false); }
  }

  const rowProps = { scanDetails, toggleScan, changeTypeBadge, sevBadge, riskBadgeStyle };

  return (
    <div className={styles.adminWrap}>
      <h2 className={styles.adminTitle}>{t("changes.titulo")}</h2>

      {/* Tabs */}
      <div className={styles.adminTabs} style={{ marginBottom: 16 }}>
        <button
          className={`${styles.adminTab} ${tab === "overview" ? styles.adminTabActive : ""}`}
          onClick={() => setTab("overview")}
        >{t("changes.visaoGeral")}</button>
        <button
          className={`${styles.adminTab} ${tab === "domain" ? styles.adminTabActive : ""}`}
          onClick={() => setTab("domain")}
        >{t("changes.porDominio")}</button>
        <button
          className={`${styles.adminTab} ${tab === "analysis" ? styles.adminTabActive : ""}`}
          onClick={() => setTab("analysis")}
        >{t("changes.analiseScore")}</button>
      </div>

      {/* ── Aba: Recentes ── */}
      {/* ── Aba: Visão Geral ── */}
      {tab === "overview" && (
        <>
          {overviewLoading && <div className={styles.empty}>{t("app.carregando")}</div>}
          {!overviewLoading && overviewList.length === 0 && (
            <div className={styles.empty}>{t("changes.vazio")}</div>
          )}
          {!overviewLoading && overviewList.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 8 }}>
              {/* Filter toggle */}
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 12 }}>
                {(["all", "active", "passive"] as const).map(f => (
                  <button
                    key={f}
                    onClick={() => setOverviewFilter(f)}
                    className={`${styles.btn} ${overviewFilter === f ? styles.btnScan : styles.btnGhost}`}
                    style={{ fontSize: 11, padding: "3px 10px" }}
                  >
                    {f === "all" ? "Todos" : f === "active" ? "Ativo" : "Passivo"}
                  </button>
                ))}
                <span className={styles.muted} style={{ fontSize: 11, marginLeft: 6 }}>
                  {overviewList.filter(s =>
                    overviewFilter === "all" ? true :
                    overviewFilter === "active" ? s.activeMode : !s.activeMode
                  ).length} domínio(s) · último scan por domínio
                </span>
              </div>
              {overviewList.filter(s =>
                overviewFilter === "all" ? true :
                overviewFilter === "active" ? s.activeMode : !s.activeMode
              ).length === 0 && (
                <div className={styles.empty}>
                  ◈ Nenhum domínio com scan {overviewFilter === "active" ? "ativo" : "passivo"} registrado.
                </div>
              )}
              {overviewList.filter(s =>
                overviewFilter === "all" ? true :
                overviewFilter === "active" ? s.activeMode : !s.activeMode
              ).map(s => {
                const riskCls = s.riskLevel === "SECURE" ? styles.secure
                  : s.riskLevel === "LOW"      ? styles.low
                  : s.riskLevel === "MEDIUM"   ? styles.warning
                  : s.riskLevel === "HIGH"     ? styles.high
                  : styles.critical;
                // Cor pelo nível de risco (mesma regra do ScoreGauge), não pelo número cru,
                // para Scanner e Histórico mostrarem a mesma cor para o mesmo scan.
                const scoreColor = s.riskLevel === "SECURE" ? "var(--secure)"
                  : s.riskLevel === "LOW"      ? "var(--info)"
                  : s.riskLevel === "MEDIUM"   ? "var(--warning)"
                  : s.riskLevel === "HIGH"     ? "var(--high)"
                  : "var(--critical)";
                const pct = Math.max(2, s.score);
                const dt  = new Date(s.scannedAt);
                const dateStr = dt.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit", year: "numeric" });
                const timeStr = dt.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
                return (
                  <button
                    key={s.id}
                    onClick={() => { setTab("domain"); setSearchHost(s.host); searchByHost(s.host); }}
                    style={{
                      background: "var(--surface)", border: "1px solid var(--border)",
                      borderRadius: "var(--radius)", padding: "14px 18px",
                      textAlign: "left", cursor: "pointer", width: "100%",
                      transition: "border-color .15s",
                    }}
                    onMouseEnter={e => (e.currentTarget.style.borderColor = "var(--accent)")}
                    onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--border)")}
                  >
                    {/* Row 1: host + score badge */}
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <code style={{ color: "var(--accent)", fontFamily: "var(--mono)", fontSize: 13, fontWeight: 700 }}>
                          {s.host}
                        </code>
                        <span className={`${styles.tag} ${riskCls}`}>{s.riskLevel}</span>
                        {s.activeMode && (
                          <span className={`${styles.tag} ${styles.info}`} style={{ fontSize: "0.65rem" }}>ACTIVE</span>
                        )}
                      </div>
                      <span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 18, color: scoreColor }}>
                        {s.score}<span style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 400 }}>/100</span>
                      </span>
                    </div>
                    {/* Row 2: progress bar */}
                    <div style={{
                      height: 4, background: "var(--bg)", borderRadius: 2, overflow: "hidden", marginBottom: 8,
                    }}>
                      <div style={{
                        width: `${pct}%`, height: "100%",
                        background: scoreColor, borderRadius: 2,
                        transition: "width .4s ease",
                      }} />
                    </div>
                    {/* Row 3: date + hint */}
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <span className={styles.muted} style={{ fontSize: 11 }}>
                        Último scan: {dateStr} {timeStr}
                      </span>
                      <span className={styles.muted} style={{ fontSize: 10 }}>
                        clique para ver histórico →
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </>
      )}

      {/* ── Aba: Por domínio ── */}
      {tab === "domain" && (
        <>
          {registeredDomains.length > 0 && (
            <div className={styles.changesQuickSelect}>
              <span className={styles.muted} style={{ fontSize: 11, letterSpacing: ".5px" }}>{t("changes.dominiosCadastrados")}</span>
              <div className={styles.changesChips}>
                {registeredDomains.map(d => (
                  <button
                    key={d.id}
                    className={`${styles.changesChip} ${activeHost === d.host ? styles.changesChipActive : ""}`}
                    onClick={() => { setSearchHost(d.host); searchByHost(d.host); }}
                  >
                    {d.verified && <span className={styles.ok} style={{ fontSize: 10 }}>✓ </span>}
                    {d.host}
                  </button>
                ))}
              </div>
            </div>
          )}

          <form onSubmit={e => { e.preventDefault(); searchByHost(searchHost); }} className={styles.scheduleForm}>
            <input
              className={styles.urlInput}
              value={searchHost}
              onChange={e => setSearchHost(e.target.value)}
              placeholder={t("scan.placeholder")}
            />
            <button className={`${styles.btn} ${styles.btnScan}`} type="submit" disabled={domainLoading || !searchHost.trim()}>
              {domainLoading ? "..." : "Buscar"}
            </button>
          </form>

          {domainError && <div className={styles.errorBox}>{domainError}</div>}

          {domainList.length > 0 && (() => {
            const filteredDomain = domainList.filter(s => {
              if (domainFilter === "manual")    return s.origin !== "SCHEDULED";
              if (domainFilter === "scheduled") return s.origin === "SCHEDULED";
              if (domainFilter === "active")    return s.activeMode === true;
              if (domainFilter === "passive")   return s.activeMode === false;
              return true;
            });
            return (
              <div className={styles.changesTimeline}>
                <div className={styles.changesMeta}>
                  <code className={styles.code}>{activeHost}</code>
                  <span className={styles.muted}>{domainList.length} scans registrados</span>
                </div>
                {/* Filter bar */}
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 12, flexWrap: "wrap" }}>
                  {([
                    { key: "all",       label: "Todos" },
                    { key: "manual",    label: "Manual" },
                    { key: "scheduled", label: "Agendado" },
                    { key: "active",    label: "Ativo" },
                    { key: "passive",   label: "Passivo" },
                  ] as const).map(f => (
                    <button
                      key={f.key}
                      onClick={() => setDomainFilter(f.key)}
                      className={`${styles.btn} ${domainFilter === f.key ? styles.btnScan : styles.btnGhost}`}
                      style={{ fontSize: 11, padding: "3px 10px" }}
                    >
                      {f.label}
                    </button>
                  ))}
                  <span className={styles.muted} style={{ fontSize: 11, marginLeft: 4 }}>
                    {filteredDomain.length} resultado(s)
                  </span>
                </div>
                {filteredDomain.length === 0 ? (
                  <div className={styles.empty}>{t("changes.semFiltro")}</div>
                ) : (
                  filteredDomain.map((s, idx) => (
                    <ScanTimelineRow key={s.id} s={s} idx={idx} isFirst={idx === 0} showHost={false} {...rowProps} />
                  ))
                )}
              </div>
            );
          })()}

          {!domainLoading && !domainError && domainList.length === 0 && activeHost && (
            <div className={styles.empty}>{t("changes.semScanPara")} <code>{activeHost}</code>.</div>
          )}
        </>
      )}

      {/* ── Aba: Análise de Score ── */}
      {tab === "analysis" && (
        <>
          {/* Domain selector */}
          {registeredDomains.length > 0 && (
            <div className={styles.changesQuickSelect}>
              <span className={styles.muted} style={{ fontSize: 11, letterSpacing: ".5px" }}>{t("changes.dominiosCadastrados")}</span>
              <div className={styles.changesChips}>
                {registeredDomains.map(d => (
                  <button
                    key={d.id}
                    className={`${styles.changesChip} ${analysisHost === d.host ? styles.changesChipActive : ""}`}
                    onClick={() => setAnalysisHost(d.host)}
                  >
                    {d.verified && <span className={styles.ok} style={{ fontSize: 10 }}>✓ </span>}
                    {d.host}
                  </button>
                ))}
              </div>
            </div>
          )}
          <form
            onSubmit={e => {
              e.preventDefault();
              const h = analysisSearch.trim().replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
              if (h) setAnalysisHost(h);
            }}
            className={styles.scheduleForm}
          >
            <input
              className={styles.urlInput}
              value={analysisSearch}
              onChange={e => setAnalysisSearch(e.target.value)}
              placeholder={t("scan.placeholder")}
            />
            <button
              className={`${styles.btn} ${styles.btnScan}`}
              type="submit"
              disabled={!analysisSearch.trim()}
            >
              Buscar
            </button>
          </form>

          {analysisHost && (
            <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 12 }}>
              <div className={styles.muted} style={{ fontFamily: "var(--mono)", fontSize: 11 }}>
                ◈ Analisando: <code style={{ color: "var(--accent)" }}>{analysisHost}</code>
              </div>
              <ScoreHistoryChart host={analysisHost} showFilter />
              <IntradayChart host={analysisHost} />
            </div>
          )}

          {!analysisHost && (
            <div className={styles.empty}>{t("changes.selecioneDominio")}</div>
          )}
        </>
      )}
    </div>
  );
}

// ── Domains Page ─────────────────────────────────────────────────────────────

// ── Compliance ─────────────────────────────────────────────────────────────────

interface ComplianceItem {
  reference: string;
  title: string;
  requirement: string;
  status: "PASS" | "FAIL" | "WARN" | "NA";
  findings: string[];
  recommendation: string;
}

interface ComplianceReport {
  overallScore: number;
  riskLevel: string;
  lgpdItems: ComplianceItem[];
  isoItems: ComplianceItem[];
  lgpdPassed: number;
  lgpdFailed: number;
  isoPassed: number;
  isoFailed: number;
}

function CompliancePanel({ compliance }: { compliance: ComplianceReport }) {
  const { t } = useI18n();
  const [tab, setTab] = useState<"lgpd" | "iso">("lgpd");
  const [expanded, setExpanded] = useState<string | null>(null);

  const scoreColor =
    compliance.overallScore >= 80 ? "var(--secure)" :
    compliance.overallScore >= 60 ? "var(--info)" :
    compliance.overallScore >= 40 ? "var(--warning)" : "var(--critical)";

  const riskColor =
    compliance.riskLevel === "COMPLIANT" ? "var(--secure)" :
    compliance.riskLevel === "LOW"       ? "var(--info)"   :
    compliance.riskLevel === "MEDIUM"    ? "var(--warning)":
    "var(--critical)";

  const items = tab === "lgpd" ? compliance.lgpdItems : compliance.isoItems;
  const passed = tab === "lgpd" ? compliance.lgpdPassed : compliance.isoPassed;
  const failed = tab === "lgpd" ? compliance.lgpdFailed : compliance.isoFailed;

  function statusColor(s: string) {
    return s === "PASS" ? "var(--secure)" : s === "FAIL" ? "var(--critical)" : "var(--warning)";
  }
  function statusIcon(s: string) {
    return s === "PASS" ? "✓" : s === "FAIL" ? "✗" : "⚠";
  }

  return (
    <div>
      {/* Header de score */}
      <div style={{ display: "flex", gap: 16, marginBottom: 16, alignItems: "center" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontFamily: "var(--mono)", fontSize: 32, fontWeight: 900, color: scoreColor, lineHeight: 1 }}>
            {compliance.overallScore}%
          </div>
          <div style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: ".5px", marginTop: 2 }}>
            COMPLIANCE SCORE
          </div>
        </div>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-muted)" }}>{t("compliance.riscoGeral")}</span>
            <span style={{ fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700, color: riskColor }}>{compliance.riskLevel}</span>
          </div>
          <div style={{ display: "flex", gap: 12 }}>
            <span style={{ fontFamily: "var(--mono)", fontSize: 10 }}>
              LGPD: <span style={{ color: "var(--secure)" }}>{compliance.lgpdPassed}✓</span>{" "}
              <span style={{ color: "var(--critical)" }}>{compliance.lgpdFailed}✗</span>
            </span>
            <span style={{ fontFamily: "var(--mono)", fontSize: 10 }}>
              ISO: <span style={{ color: "var(--secure)" }}>{compliance.isoPassed}✓</span>{" "}
              <span style={{ color: "var(--critical)" }}>{compliance.isoFailed}✗</span>
            </span>
          </div>
          {/* Progress bar */}
          <div style={{ height: 4, background: "var(--border2)", borderRadius: 2, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${compliance.overallScore}%`, background: scoreColor, transition: "width .4s" }} />
          </div>
        </div>
      </div>

      {/* Tabs LGPD / ISO */}
      <div style={{ display: "flex", gap: 4, marginBottom: 12 }}>
        {(["lgpd", "iso"] as const).map(aba => (
          <button key={aba} onClick={() => { setTab(aba); setExpanded(null); }}
            style={{
              fontFamily: "var(--mono)", fontSize: 10, fontWeight: 700, letterSpacing: ".5px",
              padding: "4px 12px", border: "1px solid",
              borderColor: tab === aba ? "var(--accent)" : "var(--border2)",
              background: tab === aba ? "var(--accent)" : "transparent",
              color: tab === aba ? "var(--bg)" : "var(--text-muted)",
              cursor: "pointer", borderRadius: 2
            }}>
            {aba === "lgpd" ? "LGPD" : t("compliance.iso")}
            <span style={{ marginLeft: 6, opacity: .7 }}>
              ({aba === "lgpd" ? compliance.lgpdFailed : compliance.isoFailed} issues)
            </span>
          </button>
        ))}
      </div>

      {/* Summary row */}
      <div style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: ".5px", marginBottom: 8 }}>
        {passed} CONFORMES / {failed} NÃO CONFORMES — {tab === "lgpd" ? t("compliance.lgpdLei") : t("compliance.isoAnexo")}
      </div>

      {/* Items */}
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {items.map(item => {
          const key = item.reference;
          const isOpen = expanded === key;
          return (
            <div key={key}
              style={{
                border: "1px solid",
                borderColor: item.status === "PASS" ? "var(--border2)" : "var(--critical)30",
                borderRadius: 4,
                background: item.status === "FAIL" ? "var(--critical)08" : "var(--surface)",
                overflow: "hidden"
              }}>
              <div onClick={() => setExpanded(isOpen ? null : key)}
                style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", cursor: "pointer", userSelect: "none" }}>
                <span style={{ fontFamily: "var(--mono)", fontSize: 13, color: statusColor(item.status), minWidth: 16 }}>
                  {statusIcon(item.status)}
                </span>
                <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--accent)", minWidth: 60, fontWeight: 700 }}>
                  {item.reference}
                </span>
                <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text)", flex: 1 }}>
                  {item.title}
                </span>
                {item.status === "FAIL" && (
                  <span style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--critical)", background: "var(--critical)20", padding: "1px 6px", borderRadius: 2 }}>
                    {item.findings.length} issue{item.findings.length !== 1 ? "s" : ""}
                  </span>
                )}
                <span style={{ color: "var(--text-muted)", fontSize: 10 }}>{isOpen ? "▲" : "▼"}</span>
              </div>
              {isOpen && (
                <div style={{ borderTop: "1px solid var(--border2)", padding: "10px 12px", display: "flex", flexDirection: "column", gap: 8, userSelect: "text" }}
                     onClick={e => e.stopPropagation()}>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--text-muted)", lineHeight: 1.5 }}>
                    {item.requirement}
                  </div>
                  {item.findings.length > 0 && (
                    <div>
                      <div style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--critical)", letterSpacing: ".5px", marginBottom: 4 }}>
                        NÃO CONFORMIDADES
                      </div>
                      {item.findings.map((f, i) => (
                        <div key={i} style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text)", padding: "2px 0 2px 8px", borderLeft: "2px solid var(--critical)" }}>
                          {f}
                        </div>
                      ))}
                    </div>
                  )}
                  <div style={{ background: "var(--accent)10", borderRadius: 3, padding: "6px 10px" }}>
                    <div style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--accent)", letterSpacing: ".5px", marginBottom: 3 }}>
                      RECOMENDAÇÃO
                    </div>
                    <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text)", lineHeight: 1.5 }}>
                      {item.recommendation}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

interface SubdomainInfo {
  host: string;
  alive: boolean;
  httpStatus: number | null;
  ip: string | null;
}

function DomainsPage() {
  const { t } = useI18n();
  const { user } = useAuth();
  const [domains, setDomains]   = useState<DomainDto[]>([]);
  const [loading, setLoading]   = useState(true);
  const [host, setHost]         = useState("");
  const [adding, setAdding]     = useState(false);
  const [error, setError]       = useState<string | null>(null);
  const [verifying, setVerifying] = useState<string | null>(null);
  const [copied, setCopied]     = useState<string | null>(null);
  const [enumerating, setEnumerating] = useState<string | null>(null);
  const [subdomains, setSubdomains]   = useState<Record<string, SubdomainInfo[]>>({});
  const [openEnum, setOpenEnum]       = useState<string | null>(null);

  const isCompany = user?.account?.type === "COMPANY";

  async function load() {
    try { setDomains((await api.get<DomainDto[]>("/domains")).data); }
    catch { setError(t("dominio.erroCarregar")); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    if (!host.trim()) return;
    setAdding(true); setError(null);
    try { await api.post("/domains", { host: host.trim() }); setHost(""); await load(); }
    catch (e: any) { setError(e?.response?.data?.message ?? t("dominio.erroCadastrar")); }
    finally { setAdding(false); }
  }

  async function remove(id: string, h: string) {
    if (!confirm(`Remover domínio "${h}"?`)) return;
    try { await api.delete(`/domains/${id}`); await load(); }
    catch (e: any) { setError(e?.response?.data?.message ?? "Erro ao remover."); }
  }

  async function verify(id: string) {
    setVerifying(id); setError(null);
    try { await api.post(`/domains/${id}/verify`); await load(); }
    catch (e: any) { setError(e?.response?.data?.message ?? t("dominio.erroVerificar")); }
    finally { setVerifying(null); }
  }

  async function enumerate(id: string) {
    setEnumerating(id); setError(null);
    setOpenEnum(id);
    try {
      const res = await api.post<SubdomainInfo[]>(`/domains/${id}/enumerate`);
      setSubdomains(prev => ({ ...prev, [id]: res.data }));
    } catch (e: any) {
      setError(e?.response?.data?.message ?? t("dominio.erroEnumerar"));
      setOpenEnum(null);
    } finally { setEnumerating(null); }
  }

  function copyToken(token: string, id: string) {
    navigator.clipboard.writeText(token);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  }

  function statusColor(s: number | null) {
    if (!s) return "var(--text-muted)";
    if (s < 300) return "var(--secure)";
    if (s < 400) return "var(--info)";
    if (s < 500) return "var(--warning)";
    return "var(--critical)";
  }

  return (
    <div className={styles.adminWrap}>
      <h2 className={styles.adminTitle}>{t("dominio.titulo")}</h2>

      <form onSubmit={add} className={styles.scheduleForm}>
        <input
          className={styles.urlInput}
          value={host}
          onChange={e => setHost(e.target.value)}
          placeholder={t("scan.placeholder")}
          disabled={adding}
        />
        <button className={`${styles.btn} ${styles.btnScan}`} type="submit" disabled={adding || !host.trim()}>
          {adding ? "..." : t("dominio.adicionar")}
        </button>
      </form>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading ? (
        <div className={styles.empty}>{t("app.carregando")}</div>
      ) : domains.length === 0 ? (
        <div className={styles.empty}>{t("dominio.vazio")}</div>
      ) : (
        <div className={styles.domainList}>
          {domains.map(d => (
            <div key={d.id} className={styles.domainCard}>
              <div className={styles.domainCardHeader}>
                <div className={styles.domainCardLeft}>
                  <span className={d.verified ? styles.ok : styles.bad}>
                    {d.verified ? "✓" : "✗"}
                  </span>
                  <code className={styles.code}>{d.host}</code>
                  <span className={d.verified ? `${styles.tag} ${styles.secure}` : `${styles.tag} ${styles.tagFree}`}>
                    {d.verified ? "Verificado" : "Pendente"}
                  </span>
                  {d.verifiedAt && (
                    <span className={styles.muted} style={{ fontSize: 11 }}>
                      em {new Date(d.verifiedAt).toLocaleDateString("pt-BR")}
                    </span>
                  )}
                </div>
                <div className={styles.actionBtns}>
                  {!d.verified && (
                    <button className={`${styles.btn} ${styles.btnGhost}`}
                      onClick={() => verify(d.id)} disabled={verifying === d.id}>
                      {verifying === d.id ? t("dominio.verificando") : "Verificar"}
                    </button>
                  )}
                  {/* Enumeração de subdomínios — apenas EMPRESA + domínio verificado */}
                  {d.verified && isCompany && (
                    <button
                      className={`${styles.btn} ${styles.btnGhost}`}
                      onClick={() => openEnum === d.id ? setOpenEnum(null) : enumerate(d.id)}
                      disabled={enumerating === d.id}
                      title={t("dominio.enumerar")}
                    >
                      {enumerating === d.id ? t("dominio.enumerando") : openEnum === d.id ? t("dominio.fechar") : t("dominio.subdominios")}
                    </button>
                  )}
                  <button className={`${styles.btn} ${styles.btnDanger}`} onClick={() => remove(d.id, d.host)}>
                    Remover
                  </button>
                </div>
              </div>

              {!d.verified && (
                <div className={styles.domainVerifyInstructions}>
                  <div className={styles.domainVerifyStep}>
                    <span className={styles.stepNum}>1</span>
                    <div>
                      <div className={styles.stepTitle}>{t("dominio.crieArquivo")}</div>
                      <code className={styles.stepCode}>https://{d.host}/.well-known/cyberaudit.txt</code>
                    </div>
                  </div>
                  <div className={styles.domainVerifyStep}>
                    <span className={styles.stepNum}>2</span>
                    <div>
                      <div className={styles.stepTitle}>{t("posse.conteudoArquivo")}</div>
                      <div className={styles.tokenRow}>
                        <code className={styles.stepCode}>{d.verificationToken}</code>
                        <button className={styles.copyBtn} onClick={() => copyToken(d.verificationToken, d.id)}>
                          {copied === d.id ? t("posse.copiado") : "Copiar"}
                        </button>
                      </div>
                    </div>
                  </div>
                  <div className={styles.domainVerifyStep}>
                    <span className={styles.stepNum}>3</span>
                    <div>
                      <div className={styles.stepTitle}>{t("dominio.cliqueVerificar")}</div>
                    </div>
                  </div>
                </div>
              )}

              {/* Resultados de enumeração */}
              {openEnum === d.id && subdomains[d.id] && (
                <div style={{ marginTop: 12, borderTop: "1px solid var(--border2)", paddingTop: 12 }}>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-muted)", letterSpacing: ".5px", marginBottom: 8 }}>
                    SUBDOMÍNIOS DESCOBERTOS — {subdomains[d.id].length} encontrados via Certificate Transparency
                    <span style={{ marginLeft: 8, color: "var(--secure)" }}>
                      ({subdomains[d.id].filter(s => s.alive).length} ativos)
                    </span>
                  </div>
                  <table className={styles.table} style={{ width: "100%" }}>
                    <thead>
                      <tr>
                        <th>{t("dominio.subdominio")}</th>
                        <th>Status</th>
                        <th>HTTP</th>
                        <th>IP</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {subdomains[d.id].map((s, i) => (
                        <tr key={i}>
                          <td><code style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{s.host}</code></td>
                          <td>
                            <span style={{ color: s.alive ? "var(--secure)" : "var(--text-muted)", fontFamily: "var(--mono)", fontSize: 10 }}>
                              {s.alive ? t("dominio.ativo") : t("dominio.inativo")}
                            </span>
                          </td>
                          <td>
                            {s.httpStatus
                              ? <span style={{ color: statusColor(s.httpStatus), fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700 }}>{s.httpStatus}</span>
                              : <span className={styles.muted}>—</span>}
                          </td>
                          <td><span className={styles.muted} style={{ fontSize: 10 }}>{s.ip ?? "—"}</span></td>
                          <td>
                            {s.alive && (
                              <button
                                className={`${styles.btn} ${styles.btnGhost}`}
                                style={{ fontSize: 10, padding: "2px 8px" }}
                                onClick={() => {
                                  // Copia o host para o scanner (navega para scan tab)
                                  navigator.clipboard.writeText(s.host);
                                }}
                                title={t("dominio.copiarScanner")}
                              >
                                Copiar
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {subdomains[d.id].length === 0 && (
                    <div className={styles.empty}>{t("dominio.semSubdominios")}</div>
                  )}
                </div>
              )}
              {openEnum === d.id && enumerating === d.id && (
                <div style={{ marginTop: 10, fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-muted)" }}>
                  ◈ Consultando Certificate Transparency e verificando DNS... pode levar até 60s.
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────



// ── Intraday Score Chart ──────────────────────────────────────────────────────

function IntradayChart({ host }: { host: string }) {
  const { t } = useI18n();
  const todayStr = new Date().toISOString().slice(0, 10);
  const [selectedDate, setSelectedDate] = useState(todayStr);
  const [scans, setScans]   = useState<HistorySummary[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!host || !selectedDate) return;
    setLoading(true);
    setScans([]);
    api.get<HistorySummary[]>(`/history/${host}?from=${selectedDate}&to=${selectedDate}`)
      .then(res => setScans([...res.data].sort((a, b) =>
        new Date(a.scannedAt).getTime() - new Date(b.scannedAt).getTime()
      )))
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  }, [host, selectedDate]);

  const points = scans.map(s => {
    const dt = new Date(s.scannedAt);
    return {
      ts:    dt.getTime(),
      score: s.score,
      risk:  s.riskLevel,
      label: dt.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }),
    };
  });

  const dateLabel = selectedDate
    ? new Date(selectedDate + "T12:00:00").toLocaleDateString("pt-BR", {
        weekday: "short", day: "2-digit", month: "2-digit", year: "numeric",
      })
    : "";

  return (
    <Card title={t("grafico.intraday")}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
        <input
          type="date"
          value={selectedDate}
          max={todayStr}
          onChange={e => setSelectedDate(e.target.value)}
          style={{
            background: "var(--surface)", border: "1px solid var(--border2)",
            borderRadius: "var(--radius-sm)", color: "var(--text)",
            fontFamily: "var(--mono)", fontSize: 11, padding: "3px 8px",
            cursor: "pointer", outline: "none",
          }}
        />
        <span className={styles.muted} style={{ fontSize: 11 }}>{dateLabel}</span>
        {loading && <span className={styles.muted} style={{ fontSize: 11 }}>{t("grafico.carregando")}</span>}
      </div>

      {!loading && points.length === 0 && (
        <div className={styles.empty} style={{ fontSize: 12, padding: "10px 0" }}>
          ◈ Nenhum scan registrado neste dia.
        </div>
      )}

      {!loading && points.length === 1 && (
        <div style={{ fontFamily: "var(--mono)", fontSize: 12, padding: "8px 0", color: "var(--text)" }}>
          1 scan · {points[0].label} · Score{" "}
          <strong style={{ color: "var(--info)" }}>{points[0].score}/100</strong>
        </div>
      )}

      {points.length >= 2 && (
        <>
          <div onMouseDown={e => e.preventDefault()} style={{ cursor: "default" }}>
            <ResponsiveContainer width="100%" height={140}>
              <LineChart data={points} margin={{ top: 8, right: 8, left: -28, bottom: 0 }}>
                <XAxis
                  dataKey="ts"
                  type="number"
                  scale="time"
                  domain={["dataMin", "dataMax"]}
                  tickCount={Math.min(points.length, 6)}
                  tickFormatter={(v: number) =>
                    new Date(v).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })
                  }
                  tick={{ fill: "var(--text-muted)", fontSize: 10, fontFamily: "var(--mono)" }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fill: "var(--text-muted)", fontSize: 10, fontFamily: "var(--mono)" }}
                  axisLine={false}
                  tickLine={false}
                  ticks={[0, 25, 50, 75, 100]}
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--surface)",
                    border: "1px solid var(--border)",
                    borderRadius: 4,
                    fontSize: 11,
                    fontFamily: "var(--mono)",
                    color: "var(--text)",
                  }}
                  formatter={(value) => [`${(value as number) ?? 0}/100`, "Score"]}
                  labelFormatter={(_: unknown, payload: readonly any[]) =>
                    payload?.length ? payload[0]?.payload?.label ?? "" : ""
                  }
                  trigger="hover"
                />
                <ReferenceLine y={85} stroke="var(--secure)"   strokeDasharray="3 3" strokeOpacity={0.3} />
                <ReferenceLine y={70} stroke="var(--info)"     strokeDasharray="3 3" strokeOpacity={0.3} />
                <ReferenceLine y={45} stroke="var(--warning)"  strokeDasharray="3 3" strokeOpacity={0.3} />
                <ReferenceLine y={20} stroke="var(--critical)" strokeDasharray="3 3" strokeOpacity={0.3} />
                <Line
                  type="monotone"
                  dataKey="score"
                  stroke="var(--info)"
                  strokeWidth={2}
                  dot={{ r: 3, fill: "var(--info)", strokeWidth: 0 }}
                  activeDot={{ r: 5, fill: "var(--info)", strokeWidth: 0 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className={styles.muted} style={{ fontSize: 10, marginTop: 2 }}>
            {points.length} scan(s) neste dia
          </div>
        </>
      )}
    </Card>
  );
}

// ── Score History Chart ───────────────────────────────────────────────────────

interface HistorySummary { id: string; url: string; host: string; scannedAt: string; activeMode: boolean; score: number; riskLevel: string; origin?: string; }

// ── Security Headers — Card Grid ──────────────────────────────────────────────

/**
 * Metadados dos headers de segurança.
 *
 * Terceira tabela de módulo do arquivo, mesmo formato do TECH_RISK e do
 * AUDIT_ACTION_KEYS: fora de componente não existe `t()`, então guarda CHAVES e
 * quem renderiza resolve.
 *
 * `short` e `example` ficam literais de propósito — são termo técnico e valor de
 * configuração, iguais em qualquer idioma. Traduzir `default-src 'self'` seria
 * dar ao cliente um valor que não funciona.
 */
const HEADER_META: Record<string, { short: string; descKey: string; riskKey: string; example: string; tipKey: string }> = {
  "Content-Security-Policy":   { short: "CSP",        descKey: "hdr.csp.desc",      riskKey: "hdr.csp.risk",      example: "default-src 'self'; script-src 'self'",       tipKey: "hdr.csp.tip" },
  "Strict-Transport-Security": { short: "HSTS",       descKey: "hdr.hsts.desc",     riskKey: "hdr.hsts.risk",     example: "max-age=31536000; includeSubDomains; preload", tipKey: "hdr.hsts.tip" },
  "X-Frame-Options":           { short: "X-Frame",    descKey: "hdr.xframe.desc",   riskKey: "hdr.xframe.risk",   example: "DENY",                                        tipKey: "hdr.xframe.tip" },
  "X-Content-Type-Options":    { short: "MIME Guard", descKey: "hdr.nosniff.desc",  riskKey: "hdr.nosniff.risk",  example: "nosniff",                                     tipKey: "hdr.nosniff.tip" },
  "Referrer-Policy":           { short: "Referrer",   descKey: "hdr.referrer.desc", riskKey: "hdr.referrer.risk", example: "strict-origin-when-cross-origin",             tipKey: "hdr.referrer.tip" },
  "Permissions-Policy":        { short: "Permissions", descKey: "hdr.perms.desc",    riskKey: "hdr.perms.risk",    example: "camera=(), microphone=(), geolocation=()",     tipKey: "hdr.perms.tip" },
  "X-XSS-Protection":          { short: "XSS Filter", descKey: "hdr.xss.desc",      riskKey: "hdr.xss.risk",      example: "1; mode=block",                               tipKey: "hdr.xss.tip" },
  "Cache-Control":             { short: "Cache",      descKey: "hdr.cache.desc",    riskKey: "hdr.cache.risk",    example: "no-store, no-cache",                          tipKey: "hdr.cache.tip" },
};

function HeaderCardsPanel({ headers, host, related }: { headers: Record<string, string>; host?: string | null; related?: RelatedHostHeaders[] }) {
  const { t } = useI18n();
  const [openSet, setOpenSet] = useState<Set<string>>(new Set());

  const toggle = (key: string) =>
    setOpenSet(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });

  const entries = Object.entries(headers);
  if (entries.length === 0) return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div className={styles.empty}>{t("card.header.vazio")}</div>
      <RelatedHostsPanel related={related} />
    </div>
  );

  // 3 colunas flex independentes — expandir um card não afeta as outras colunas
  const cols: [string, string][][] = [[], [], []];
  entries.forEach(([k, v], i) => cols[i % 3].push([k, v]));

  const renderCard = ([key, val]: [string, string]) => {
        const isOk      = val.startsWith("OK");
        const isMissing = val.startsWith("MISSING");
        const color     = isOk ? "var(--secure)" : isMissing ? "var(--critical)" : "var(--warning)";
        const icon      = isOk ? "✓" : isMissing ? "✗" : "⚠";
        const statusTxt = isOk ? "OK" : isMissing ? "MISSING" : "WEAK";
        const meta      = HEADER_META[key];
        const isOpen    = openSet.has(key);

        return (
          <div
            key={key}
            onClick={() => toggle(key)}
            style={{
              background: "var(--surface)",
              border: `1px solid ${isOpen ? color : "var(--border)"}`,
              borderLeft: `3px solid ${color}`,
              borderRadius: "var(--radius)",
              padding: "12px 14px",
              cursor: "pointer",
              transition: "border-color .15s",
              userSelect: "none",
              display: "flex",
              flexDirection: "column",
              gap: 0,
              minHeight: 130,
            }}
            onMouseEnter={e => !isOpen && ((e.currentTarget as HTMLDivElement).style.borderColor = color)}
            onMouseLeave={e => !isOpen && ((e.currentTarget as HTMLDivElement).style.borderColor = "var(--border)")}
          >
            {/* Top row: name + status */}
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8 }}>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: 700 }}>
                  {meta?.short ?? key}
                </div>
                <code style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--mono)", display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {key}
                </code>
              </div>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 1, flexShrink: 0 }}>
                <span style={{ color, fontFamily: "var(--mono)", fontSize: 15, lineHeight: 1 }}>{icon}</span>
                <span style={{ color, fontSize: 9, fontFamily: "var(--mono)", fontWeight: 700, letterSpacing: ".5px" }}>{statusTxt}</span>
              </div>
            </div>

            {/* Brief description — always visible */}
            {meta && (
              <p style={{ fontSize: 10, color: "var(--text-dim)", margin: "8px 0 0", lineHeight: 1.55, flex: 1 }}>
                {t(meta.descKey)}
              </p>
            )}

            {/* Hint to click */}
            {!isOpen && (
              <span style={{ fontSize: 9, color: "var(--text-muted)", marginTop: 8, fontFamily: "var(--mono)" }}>
                clique para {isOk ? "ver detalhes" : "ver como corrigir"} ›
              </span>
            )}

            {/* Expanded detail */}
            {isOpen && meta && (
              <div style={{ marginTop: 10, borderTop: "1px solid var(--border2)", paddingTop: 8 }} onClick={e => e.stopPropagation()}>
                {isOk ? (
                  <p style={{ fontSize: 11, color: "var(--secure)", margin: "0 0 6px", fontFamily: "var(--mono)" }}>
                    ✓ Header presente e configurado corretamente.
                  </p>
                ) : (
                  <p style={{ fontSize: 11, color: "var(--text-dim)", margin: "0 0 8px", lineHeight: 1.5 }}>
                    <span style={{ color }}>{t("card.risco")} </span>{t(meta.riskKey)}
                  </p>
                )}
                <div style={{ marginBottom: 8 }}>
                  <span style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--mono)", letterSpacing: ".5px", display: "block", marginBottom: 4 }}>{t("card.header.valorRecomendado")}</span>
                  <code style={{ fontSize: 10, color: "var(--accent)", fontFamily: "var(--mono)", wordBreak: "break-all", display: "block", background: "var(--bg)", padding: "5px 8px", borderRadius: 3 }}>
                    {meta.example}
                  </code>
                </div>
                <p style={{ fontSize: 10, color: "var(--text-muted)", margin: 0, lineHeight: 1.5, fontStyle: "italic" }}>
                  ◈ {t(meta.tipKey)}
                </p>
              </div>
            )}
            {isOpen && !meta && (
              <div style={{ marginTop: 8, borderTop: "1px solid var(--border2)", paddingTop: 8, fontSize: 11, color: "var(--text-dim)" }}>
                Valor: <code style={{ fontFamily: "var(--mono)", color: "var(--text)" }}>{val}</code>
              </div>
            )}
          </div>
        );
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {host && (
        <div style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.5 }}>
          ◈ Headers do host{" "}
          <code style={{ fontFamily: "var(--mono)", color: "var(--text)" }}>{host}</code>.
          {" "}Outros hosts do mesmo site (ex: APIs em{" "}
          <code style={{ fontFamily: "var(--mono)" }}>server.…</code>) podem ter configuração diferente.
        </div>
      )}
      <div style={{ display: "flex", gap: 12 }}>
        {cols.map((col, ci) => (
          <div key={ci} style={{ flex: 1, display: "flex", flexDirection: "column", gap: 10 }}>
            {col.map(renderCard)}
          </div>
        ))}
      </div>
      <RelatedHostsPanel related={related} />
    </div>
  );
}

// ── Related Hosts — Security Headers (informativo, fora do score) ──────────────

function RelatedHostsPanel({ related }: { related?: RelatedHostHeaders[] }) {
  if (!related || related.length === 0) return null;
  return (
    <div style={{ marginTop: 4 }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text)", marginBottom: 6 }}>
        Hosts relacionados{" "}
        <span style={{ fontWeight: 400, color: "var(--text-muted)", fontSize: 11 }}>
          — informativo, não entra no score
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {related.map(rh => (
          <div key={rh.host} style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "10px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <code style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)" }}>{rh.host}</code>
              <span style={{ fontSize: 11, color: rh.missingCount > 0 ? "var(--critical)" : "var(--secure)" }}>
                {rh.missingCount} ausente{rh.missingCount === 1 ? "" : "s"}
              </span>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {Object.entries(rh.headers ?? {}).map(([k, v]) => {
                const ok = v.startsWith("OK");
                const missing = v.startsWith("MISSING");
                const color = ok ? "var(--secure)" : missing ? "var(--critical)" : "var(--warning)";
                const short = HEADER_META[k]?.short ?? k;
                return (
                  <span key={k} title={`${k}: ${v}`} style={{ fontSize: 10, fontFamily: "var(--mono)", color, border: `1px solid ${color}`, borderRadius: 3, padding: "1px 6px" }}>
                    {ok ? "✓" : missing ? "✗" : "⚠"} {short}
                  </span>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Shared card toggle hook ───────────────────────────────────────────────────

function useCardSet() {
  const [openSet, setOpenSet] = useState<Set<string>>(new Set());
  const toggle = (k: string) =>
    setOpenSet(prev => { const n = new Set(prev); n.has(k) ? n.delete(k) : n.add(k); return n; });
  return { openSet, toggle };
}

/** Distribui items em N colunas flex independentes — expande sem afetar outras colunas */
function ColsGrid({ items, cols = 3, gap = 8 }: { items: React.ReactNode[]; cols?: number; gap?: number }) {
  const columns: React.ReactNode[][] = Array.from({ length: cols }, () => []);
  items.forEach((item, i) => columns[i % cols].push(item));
  return (
    <div style={{ display: "flex", gap, alignItems: "flex-start", marginTop: gap }}>
      {columns.map((col, ci) => (
        <div key={ci} style={{ flex: 1, display: "flex", flexDirection: "column", gap }}>
          {col}
        </div>
      ))}
    </div>
  );
}

// ── Shared card shell ─────────────────────────────────────────────────────────

function ModCard({
  id: _id, color, isOpen, onToggle, top, mid, bottom, minH = 110,
}: {
  id: string; color: string; isOpen: boolean; onToggle: () => void;
  top: React.ReactNode; mid?: React.ReactNode; bottom: React.ReactNode; minH?: number;
}) {
  const { t } = useI18n();
  return (
    <div
      onClick={onToggle}
      style={{
        background: "var(--surface)",
        border: `1px solid ${isOpen ? color : "var(--border)"}`,
        borderLeft: `3px solid ${color}`,
        borderRadius: "var(--radius)",
        padding: "12px 14px",
        cursor: "pointer",
        transition: "border-color .15s",
        userSelect: "none",
        minHeight: minH,
        display: "flex",
        flexDirection: "column",
      }}
      onMouseEnter={e => !isOpen && ((e.currentTarget as HTMLDivElement).style.borderColor = color)}
      onMouseLeave={e => !isOpen && ((e.currentTarget as HTMLDivElement).style.borderColor = "var(--border)")}
    >
      {top}
      {mid && <div style={{ flex: 1 }}>{mid}</div>}
      {!isOpen && (
        <span style={{ fontSize: 9, color: "var(--text-muted)", marginTop: 6, fontFamily: "var(--mono)" }}>
          {t("card.verDetalhes")}
        </span>
      )}
      {isOpen && (
        <div style={{ marginTop: 8, borderTop: "1px solid var(--border2)", paddingTop: 8, userSelect: "text" }}
             onClick={e => e.stopPropagation()}>
          {bottom}
        </div>
      )}
    </div>
  );
}

function SecureEmptyCard({ msg }: { msg: string }) {
  return (
    <div style={{
      background: "var(--surface)", border: "1px solid var(--secure)",
      borderLeft: "3px solid var(--secure)", borderRadius: "var(--radius)",
      padding: "16px 18px", marginTop: 8, display: "flex", alignItems: "center", gap: 10,
    }}>
      <span style={{ color: "var(--secure)", fontSize: 18 }}>✓</span>
      <span style={{ color: "var(--secure)", fontFamily: "var(--mono)", fontSize: 12 }}>{msg}</span>
    </div>
  );
}

const GRID3: React.CSSProperties = { display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginTop: 8, alignItems: "start" };
const GRID2: React.CSSProperties = { display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 8, marginTop: 8, alignItems: "start" };

// ── Transport Security Cards ───────────────────────────────────────────────────

/**
 * A partir de quantos dias restantes o certificado merece alerta — em proporção
 * à vida útil total, espelhando o ScoreService.renewalWarningThreshold do backend.
 *
 * Julgar por dias absolutos fica cada vez mais errado: o CA/Browser Forum está
 * reduzindo o máximo para 200 dias (2026), 100 (2027) e 47 (2029).
 */
function certRenewalThreshold(totalValidityDays?: number | null): number {
  if (!totalValidityDays || totalValidityDays <= 0) return 7;   // vida útil desconhecida
  return Math.min(Math.max(Math.round(totalValidityDays * 0.1), 1), 30);
}

function TransportCardsPanel({ r }: { r: any }) {
  const { t } = useI18n();
  const { openSet, toggle } = useCardSet();
  const tls = r?.tlsDetails;
  const ssl = r?.sslInfo;
  const days = ssl?.daysRemaining ?? null;
  // Proporcional à vida útil do certificado, igual ao ScoreService. Com o limite
  // antigo em dias absolutos (<30 vermelho, <90 amarelo), um Let's Encrypt — que
  // vive 90 dias e renova aos 30 — ficava amarelo quase o ciclo inteiro e vermelho
  // justamente durante a renovação normal.
  const daysColor = days === null
    ? "var(--text-muted)"
    : days <= 0
      ? "var(--critical)"
      : days < certRenewalThreshold(ssl?.totalValidityDays)
        ? "var(--warning)"
        : "var(--secure)";
  const proto = tls?.negotiatedProtocol ?? "—";
  const protoColor = tls?.weakProtocol ? "var(--critical)" : "var(--secure)";
  const certColor = ssl?.valid ? "var(--secure)" : "var(--critical)";

  const cards = [
    {
      key: "protocol", title: t("card.tls.protocolo"), value: proto, color: protoColor,
      icon: tls?.weakProtocol ? "✗" : "✓", status: tls?.weakProtocol ? t("card.fraco") : "OK",
      desc: t("card.tls.protocoloDesc"),
      detail: tls?.weakProtocol
        ? t("card.tls.protocoloFraco")
        : t("card.tls.protocoloOk"),
    },
    {
      key: "cipher", title: t("card.tls.cipher"), value: tls?.cipherSuite ?? "—", color: "var(--info)",
      icon: "◈", status: "INFO",
      desc: t("card.tls.cipherDesc"),
      detail: (tls?.message ?? "") + " Cifras com ECDHE oferecem Perfect Forward Secrecy — sessões passadas permanecem seguras mesmo se a chave privada vazar.",
    },
    {
      key: "cert", title: t("card.cert.valido"), value: ssl?.valid ? t("card.cert.sim") : t("card.cert.nao"), color: certColor,
      icon: ssl?.valid ? "✓" : "✗", status: ssl?.valid ? "OK" : t("card.critico"),
      desc: t("card.cert.validoDesc"),
      detail: ssl?.valid
        ? t("card.cert.validoOk")
        : t("card.cert.validoRuim"),
    },
    {
      key: "expiry", title: t("card.cert.expiracao"), value: ssl?.expirationDate ?? "—", color: daysColor,
      icon: days !== null ? (days < 30 ? "✗" : days < 90 ? "⚠" : "✓") : "—",
      status: days !== null ? (days < 30 ? t("card.urgente") : days < 90 ? t("card.atencao") : "OK") : "—",
      desc: t("card.cert.expiracaoDesc"),
      detail: t("card.cert.expiracaoDica"),
    },
    {
      key: "days", title: t("card.cert.diasRestantes"), value: days !== null ? `${days} dias` : "—", color: daysColor,
      icon: days !== null ? (days < 30 ? "✗" : days < 90 ? "⚠" : "✓") : "—",
      status: days !== null ? (days < 30 ? t("card.urgente") : days < 90 ? t("card.atencao") : "OK") : "—",
      desc: t("card.cert.diasDesc"),
      detail: days !== null && days < 30
        ? t("card.cert.dias30")
        : days !== null && days < 90
        ? t("card.cert.dias90")
        : t("card.cert.diasOk"),
    },
  ];

  return (
    <div style={GRID3}>
      {cards.map(c => (
        <ModCard key={c.key} id={c.key} color={c.color} isOpen={openSet.has(c.key)} onToggle={() => toggle(c.key)}
          top={
            <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
              <div>
                <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text)", fontWeight: 700 }}>{c.title}</div>
                <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: c.color, fontWeight: 700, marginTop: 3 }}>{c.value}</div>
              </div>
              <div style={{ flexShrink: 0, textAlign: "right" }}>
                <div style={{ color: c.color, fontSize: 14 }}>{c.icon}</div>
                <div style={{ color: c.color, fontSize: 9, fontFamily: "var(--mono)", fontWeight: 700 }}>{c.status}</div>
              </div>
            </div>
          }
          mid={<p style={{ fontSize: 10, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>{c.desc}</p>}
          bottom={<p style={{ fontSize: 11, color: "var(--text-dim)", margin: 0, lineHeight: 1.5 }}>{c.detail}</p>}
        />
      ))}
    </div>
  );
}

// ── DNS / Recon Cards ──────────────────────────────────────────────────────────

function DnsCardsPanel({ r }: { r: any }) {
  const { t } = useI18n();
  const { openSet, toggle } = useCardSet();
  const dns = r?.dnsSecurityResult;

  /**
   * A consulta DNS não chegou ao servidor — os registros podem existir.
   *
   * Sem isto, o painel se contradizia: o cabeçalho dizia "inconclusivo" e os
   * cards logo abaixo afirmavam "AUSENTE" em vermelho. Quem lê acredita no card,
   * não no cabeçalho, e vai reconfigurar um DNS que já estava correto.
   *
   * Vale só para os cards que dependem de DNS. security.txt e robots.txt são
   * verificados por HTTP e continuam válidos mesmo quando o DNS falha.
   */
  const dnsIndisponivel = dns?.lookupFailed === true;
  const semDns = (valor: string) => (dnsIndisponivel ? t("selo.naoVerificado") : valor);

  const cards = [
    {
      key: "spf", title: "SPF", present: dns?.spfPresent, warn: false, dependeDeDns: true,
      value: semDns(dns?.spfPresent ? dns.spfPolicy : "AUSENTE"),
      desc: t("card.dns.spfDesc"),
      record: dns?.spfRecord,
      tip: t("card.dns.spfDica"),
    },
    {
      key: "dmarc", title: "DMARC", present: dns?.dmarcPresent, warn: false, dependeDeDns: true,
      value: semDns(dns?.dmarcPresent ? `p=${dns.dmarcPolicy?.toLowerCase()}` : "AUSENTE"),
      desc: t("card.dns.dmarcDesc"),
      record: dns?.dmarcRecord,
      tip: t("card.dns.dmarcDica"),
    },
    {
      key: "dkim", title: "DKIM", present: dns?.dkimHintFound, warn: true, dependeDeDns: true,
      value: semDns(dns?.dkimHintFound ? `seletor: ${dns.dkimSelector}` : t("card.dns.naoDetectado")),
      desc: t("card.dns.dkimDesc"),
      record: null,
      tip: t("card.dns.dkimDica"),
    },
    {
      key: "caa", title: t("card.dns.caa"), present: dns?.caaPresent, warn: true, dependeDeDns: true,
      value: semDns(dns?.caaPresent ? t("card.dns.configurado") : "AUSENTE"),
      desc: t("card.dns.caaDesc"),
      record: dns?.caaRecord,
      tip: t("card.dns.caaDica"),
    },
    {
      key: "mx", title: t("card.dns.mx"), present: dns?.mxPresent, warn: true, dependeDeDns: true,
      value: semDns(dns?.mxPresent ? `${dns.mxRecords?.length ?? 0} servidor(es)` : t("card.dns.semMx")),
      desc: t("card.dns.mxDesc"),
      record: dns?.mxRecords?.slice(0, 3).join(", ") ?? null,
      tip: t("card.dns.mxDica"),
    },
    {
      key: "sectxt", title: t("card.dns.securityTxt"), present: r?.securityTxtPresent, warn: true,
      value: r?.securityTxtPresent ? (r.securityTxtContact || "Presente") : "AUSENTE",
      desc: t("card.dns.securityTxtDesc"),
      record: r?.securityTxtContact ? `Contact: ${r.securityTxtContact}` : null,
      tip: t("card.dns.securityTxtDica"),
    },
    {
      key: "robots", title: "robots.txt", present: !(r?.sensitiveRobotsPaths?.length > 0), warn: false,
      value: r?.sensitiveRobotsPaths?.length > 0 ? `${r.sensitiveRobotsPaths.length} path(s) sensíveis` : t("card.dns.semExposicoes"),
      desc: t("card.dns.robotsDesc"),
      record: r?.sensitiveRobotsPaths?.slice(0, 3).join(", ") ?? null,
      tip: t("card.dns.robotsDica"),
    },
  ];

  const cardNodes = cards.map(c => {
    // Três estados, não dois: encontrado, não encontrado e NÃO CONSULTADO.
    // O terceiro usa âmbar de propósito — vermelho afirmaria um problema que
    // não sabemos existir, e verde esconderia que a verificação não ocorreu.
    const naoVerificado = c.dependeDeDns === true && dnsIndisponivel;

    const color = naoVerificado ? "var(--warning)"
                : c.present     ? "var(--secure)"
                : c.warn        ? "var(--warning)"
                                : "var(--critical)";
    const icon  = naoVerificado ? "?" : c.present ? "✓" : c.warn ? "⚠" : "✗";
    const st    = naoVerificado ? "N/A" : c.present ? "OK" : c.warn ? "WARN" : "MISSING";

    // Por que não entrou na nota. Só aparece quando é o caso, para não virar
    // ruído nos cards que de fato pesaram.
    const notaScore = naoVerificado
      ? t("card.dns.foraDoScoreFalha")
      : (c.warn && !c.present)
        ? t("card.dns.foraDoScoreRecomendacao")
        : null;

    return (
      <ModCard key={c.key} id={c.key} color={color} isOpen={openSet.has(c.key)} onToggle={() => toggle(c.key)}
        top={
          <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
            <div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: 700 }}>{c.title}</div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 10, color, marginTop: 2 }}>{c.value}</div>
            </div>
            <div style={{ flexShrink: 0, textAlign: "right" }}>
              <div style={{ color, fontSize: 14 }}>{icon}</div>
              <div style={{ color, fontSize: 9, fontFamily: "var(--mono)", fontWeight: 700 }}>{st}</div>
            </div>
          </div>
        }
        mid={
          <>
            <p style={{ fontSize: 10, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>{c.desc}</p>
            {notaScore && (
              <p style={{ fontSize: 9, color: "var(--warning)", margin: "6px 0 0", lineHeight: 1.5 }}>
                ⚠ {notaScore}
              </p>
            )}
          </>
        }
        bottom={
          <>
            {naoVerificado && (
              <div style={{ marginBottom: 8, fontSize: 10, color: "var(--text-dim)", lineHeight: 1.5 }}>
                O servidor não conseguiu consultar o DNS deste domínio. O registro
                pode existir normalmente — refaça o scan em alguns minutos.
              </div>
            )}
            {c.record && (
              <div style={{ marginBottom: 8 }}>
                <span style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--mono)", display: "block", marginBottom: 3 }}>REGISTRO</span>
                <code style={{ fontSize: 10, color: "var(--accent)", fontFamily: "var(--mono)", wordBreak: "break-all", display: "block", background: "var(--bg)", padding: "4px 6px", borderRadius: 3 }}>
                  {c.record}
                </code>
              </div>
            )}
            <p style={{ fontSize: 10, color: "var(--text-muted)", margin: 0, lineHeight: 1.5, fontStyle: "italic" }}>◈ {c.tip}</p>
          </>
        }
      />
    );
  });

  return (
    <div>
      {dns?.emailSpoofingRisk && (
        <div style={{
          background: "var(--surface)", borderRadius: "var(--radius)", border: "1px solid var(--border2)",
          padding: "8px 14px", display: "flex", alignItems: "center", gap: 12, marginTop: 8,
        }}>
          <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--mono)", letterSpacing: ".5px" }}>RISCO DE EMAIL SPOOFING</span>
          <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 700, color: dns.emailSpoofingRisk === "LOW" ? "var(--secure)" : dns.emailSpoofingRisk === "MEDIUM" ? "var(--warning)" : "var(--critical)" }}>
            {dns.emailSpoofingRisk}
          </span>
          {dns.summary && <span style={{ fontSize: 10, color: "var(--text-dim)", marginLeft: "auto" }}>{dns.summary}</span>}
        </div>
      )}
      <ColsGrid items={cardNodes} cols={3} />
    </div>
  );
}

// ── Cookie Cards ───────────────────────────────────────────────────────────────

function CookieCardsPanel({ cookies }: { cookies: any[] }) {
  const { t } = useI18n();
  const { openSet, toggle } = useCardSet();
  if (!cookies?.length) return <SecureEmptyCard msg={t("card.cookie.semProblemas")} />;
  return (
    <div style={GRID2}>
      {cookies.map((c, idx) => {
        const key = `${c.name}-${idx}`;
        const color = c.risk === "CRITICAL" ? "var(--critical)" : c.risk === "HIGH" ? "var(--high)" : c.risk === "MEDIUM" ? "var(--warning)" : "var(--low)";
        return (
          <ModCard key={key} id={key} color={color} isOpen={openSet.has(key)} onToggle={() => toggle(key)} minH={90}
            top={
              <>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 6, marginBottom: 8 }}>
                  <code style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: 700, wordBreak: "break-all" }}>{c.name}</code>
                  <span style={{ color, fontSize: 9, fontFamily: "var(--mono)", fontWeight: 700, background: `${color}22`, padding: "2px 5px", borderRadius: 3, flexShrink: 0 }}>{c.risk}</span>
                </div>
                <div style={{ display: "flex", gap: 10 }}>
                  <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: c.httpOnly ? "var(--secure)" : "var(--critical)" }}>{c.httpOnly ? "✓" : "✗"} HttpOnly</span>
                  <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: c.secure ? "var(--secure)" : "var(--critical)" }}>{c.secure ? "✓" : "✗"} Secure</span>
                  <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--text-muted)" }}>SS: {c.sameSite || "—"}</span>
                </div>
              </>
            }
            mid={<p style={{ fontSize: 10, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>{c.issues}</p>}
            bottom={
              <>
                {!c.httpOnly && <p style={{ fontSize: 10, color: "var(--text-muted)", margin: "0 0 5px", lineHeight: 1.5 }}>• <strong>{t("card.cookie.httpOnlyAusente")}</strong>: {t("card.cookie.httpOnlyTexto")}</p>}
                {!c.secure  && <p style={{ fontSize: 10, color: "var(--text-muted)", margin: "0 0 5px", lineHeight: 1.5 }}>• <strong>{t("card.cookie.secureAusente")}</strong>: {t("card.cookie.secureTexto")}</p>}
                {(!c.sameSite || c.sameSite === "None") && <p style={{ fontSize: 10, color: "var(--text-muted)", margin: 0, lineHeight: 1.5 }}>• <strong>{t("card.cookie.sameSiteAusente")}</strong>: {t("card.cookie.sameSiteTexto")}</p>}
              </>
            }
          />
        );
      })}
    </div>
  );
}

// ── Technology Cards ───────────────────────────────────────────────────────────

/**
 * Tabela de módulo, fora de componente — não tem acesso ao `t()`. Por isso guarda
 * CHAVES de catálogo, não texto: quem renderiza resolve. Foi a armadilha que a
 * tradução destes cards revelou.
 */
const TECH_RISK: Record<string, { descKey: string; riskKey: string; icon: string }> = {
  webServer:  { icon: "⬡",  descKey: "card.tech.webServerDesc",  riskKey: "card.tech.webServerRisco" },
  language:   { icon: "⟨⟩", descKey: "card.tech.linguagemDesc",  riskKey: "card.tech.linguagemDica" },
  backend:    { icon: "◻",  descKey: "card.tech.backendDesc",    riskKey: "card.tech.backendRisco" },
  framework:  { icon: "◈",  descKey: "card.tech.frameworkDesc",  riskKey: "card.tech.frameworkRisco" },
  cms:        { icon: "▦",  descKey: "card.tech.cmsDesc",        riskKey: "card.tech.cmsRisco" },
  cdn:        { icon: "◉",  descKey: "card.tech.cdnDesc",        riskKey: "card.tech.cdnRisco" },
  library:    { icon: "◎",  descKey: "card.tech.libraryDesc",    riskKey: "card.tech.libraryRisco" },
};

function TechCardsPanel({ tf }: { tf: any }) {
  const { t } = useI18n();
  const { openSet, toggle } = useCardSet();
  if (!tf || (!tf.webServer && !tf.backend && !tf.framework && !tf.cms && !tf.cdn && !tf.language && !tf.libraries?.length)) {
    return <div className={styles.empty}>{t("card.tech.vazio")}</div>;
  }
  const items: { key: string; cat: string; val: string; type: string }[] = [];
  if (tf.webServer)  items.push({ key: "webServer",  cat: t("card.tech.webServer"), val: tf.webServer,  type: "webServer" });
  if (tf.language)   items.push({ key: "language",   cat: "Language",   val: tf.language,   type: "language" });
  if (tf.backend)    items.push({ key: "backend",    cat: "Backend",    val: tf.backend,    type: "backend" });
  if (tf.framework)  items.push({ key: "framework",  cat: "Framework",  val: tf.framework,  type: "framework" });
  if (tf.cms)        items.push({ key: "cms",        cat: "CMS",        val: tf.cms,        type: "cms" });
  if (tf.cdn)        items.push({ key: "cdn",        cat: "CDN",        val: tf.cdn,        type: "cdn" });
  tf.libraries?.forEach((lib: string, i: number) => items.push({ key: `lib-${i}`, cat: "Library", val: lib, type: "library" }));

  return (
    <div style={GRID3}>
      {items.map(item => {
        const meta = TECH_RISK[item.type] ?? TECH_RISK.library;
        const isOpen = openSet.has(item.key);
        return (
          <ModCard key={item.key} id={item.key} color="var(--info)" isOpen={isOpen} onToggle={() => toggle(item.key)} minH={90}
            top={
              <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
                <div>
                  <span style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--mono)", letterSpacing: ".5px" }}>{item.cat.toUpperCase()}</span>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 13, color: "var(--info)", fontWeight: 700, marginTop: 2 }}>{item.val}</div>
                </div>
                <span style={{ fontSize: 16, color: "var(--info)", lineHeight: 1 }}>{meta.icon}</span>
              </div>
            }
            mid={<p style={{ fontSize: 10, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>{t(meta.descKey)}</p>}
            bottom={<p style={{ fontSize: 11, color: "var(--text-dim)", margin: 0, lineHeight: 1.5 }}><span style={{ color: "var(--warning)" }}>{t("card.risco")} </span>{t(meta.riskKey)}</p>}
          />
        );
      })}
      {tf.evidence?.length > 0 && (
        <div style={{ gridColumn: "1 / -1", background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "10px 14px" }}>
          <span style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--mono)", letterSpacing: ".5px" }}>{t("card.tech.evidencias")}</span>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
            {tf.evidence.map((e: string, i: number) => (
              <code key={i} style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--mono)", background: "var(--bg)", padding: "2px 6px", borderRadius: 3 }}>{e}</code>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── CVE Cards ──────────────────────────────────────────────────────────────────

function CveCardsPanel({ cves }: { cves: any[] }) {
  const { t } = useI18n();
  const { openSet, toggle } = useCardSet();
  if (!cves?.length) return <SecureEmptyCard msg={t("card.cve.vazio")} />;
  return (
    <div style={GRID2}>
      {cves.map((cve, i) => {
        const key = `${cve.cveId}-${i}`;
        const color = cve.severity === "CRITICAL" ? "var(--critical)" : cve.severity === "HIGH" ? "var(--high)" : cve.severity === "MEDIUM" ? "var(--warning)" : "var(--low)";
        return (
          <ModCard key={key} id={key} color={color} isOpen={openSet.has(key)} onToggle={() => toggle(key)} minH={90}
            top={
              <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
                <div>
                  <a href={cve.referenceUrl} target="_blank" rel="noopener noreferrer"
                     style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--accent)", fontWeight: 700, textDecoration: "none" }}
                     onClick={e => e.stopPropagation()}>{cve.cveId}</a>
                  <span style={{ fontSize: 10, color: "var(--text-muted)", display: "block", marginTop: 2 }}>{cve.affectedSoftware}</span>
                </div>
                <div style={{ textAlign: "right", flexShrink: 0 }}>
                  <span style={{ color, fontSize: 9, fontFamily: "var(--mono)", fontWeight: 700, background: `${color}22`, padding: "2px 5px", borderRadius: 3, display: "block" }}>{cve.severity}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 11, color, fontWeight: 700 }}>CVSS {cve.cvssScore?.toFixed(1)}</span>
                </div>
              </div>
            }
            mid={<p style={{ fontSize: 10, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>{cve.description?.slice(0, 110)}{(cve.description?.length ?? 0) > 110 ? "..." : ""}</p>}
            bottom={
              <>
                <p style={{ fontSize: 11, color: "var(--text-dim)", margin: "0 0 8px", lineHeight: 1.5 }}>{cve.description}</p>
                <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--mono)" }}>Publicado: {cve.publishedDate}</span>
                  <a href={cve.referenceUrl} target="_blank" rel="noopener noreferrer"
                     style={{ fontSize: 10, color: "var(--accent)", fontFamily: "var(--mono)", textDecoration: "none" }}
                     onClick={e => e.stopPropagation()}>{t("card.cve.verNvd")}</a>
                </div>
              </>
            }
          />
        );
      })}
    </div>
  );
}

// ── Generic Finding Cards ──────────────────────────────────────────────────────

interface FindingItem {
  id: string;
  title: string;
  subtitle?: string;
  severity: string;
  extraTags?: { label: string; color: string }[];
  summary?: string;
  details: { label: string; value: React.ReactNode }[];
}

function FindingCardsPanel({ items, emptyMsg, cols = 2 }: { items: FindingItem[]; emptyMsg: string; cols?: number }) {
  const { openSet, toggle } = useCardSet();
  if (!items.length) return <SecureEmptyCard msg={emptyMsg} />;
  return (
    <div style={{ display: "grid", gridTemplateColumns: `repeat(${cols}, 1fr)`, gap: 8, marginTop: 8, alignItems: "start" }}>
      {items.map(item => {
        const color = item.severity === "CRITICAL" ? "var(--critical)" : item.severity === "HIGH" ? "var(--high)" : item.severity === "MEDIUM" ? "var(--warning)" : item.severity === "LOW" ? "var(--low)" : "var(--info)";
        return (
          <ModCard key={item.id} id={item.id} color={color} isOpen={openSet.has(item.id)} onToggle={() => toggle(item.id)} minH={80}
            top={
              <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <code style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text)", fontWeight: 700, wordBreak: "break-all" }}>{item.title}</code>
                  {item.subtitle && <span style={{ fontSize: 10, color: "var(--text-muted)", display: "block", marginTop: 2 }}>{item.subtitle}</span>}
                </div>
                <div style={{ flexShrink: 0, display: "flex", flexDirection: "column", gap: 2, alignItems: "flex-end" }}>
                  <span style={{ color, fontSize: 9, fontFamily: "var(--mono)", fontWeight: 700, background: `${color}22`, padding: "2px 5px", borderRadius: 3 }}>{item.severity}</span>
                  {item.extraTags?.map((tag, i) => (
                    <span key={i} style={{ color: tag.color, fontSize: 9, fontFamily: "var(--mono)", fontWeight: 700, background: `${tag.color}22`, padding: "2px 5px", borderRadius: 3 }}>{tag.label}</span>
                  ))}
                </div>
              </div>
            }
            mid={item.summary ? <p style={{ fontSize: 10, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>{item.summary}</p> : undefined}
            bottom={
              <div>
                {item.details.map((d, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, marginBottom: 5, alignItems: "flex-start" }}>
                    <span style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--mono)", letterSpacing: ".5px", flexShrink: 0, paddingTop: 1, minWidth: 70 }}>{d.label}</span>
                    <span style={{ fontSize: 10, color: "var(--text)", fontFamily: "var(--mono)", wordBreak: "break-all" }}>{d.value}</span>
                  </div>
                ))}
              </div>
            }
          />
        );
      })}
    </div>
  );
}

// ── Active Checks Panel ────────────────────────────────────────────────────────

function ActiveChecksPanel({ r, onShowPlans }: { r: any; onShowPlans: () => void }) {
  const { t } = useI18n();
  const { openSet, toggle } = useCardSet();

  const SecLabel = ({ label }: { label: string }) => (
    <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-muted)", letterSpacing: "1px",
      marginTop: 20, marginBottom: 4, paddingBottom: 6, borderBottom: "1px solid var(--border2)" }}>
      {label}
    </div>
  );

  /* ── UPSELL (scan passivo) ── */
  if (!r.activeMode) {
    const GHOST_COLORS = ["var(--critical)", "var(--secure)", "var(--warning)", "var(--info)", "var(--high)", "var(--secure)"];
    const ghostCards = Array.from({ length: 6 }, (_, i) => (
      <div key={i} style={{
        background: "var(--surface)", border: `1px solid var(--border)`,
        borderLeft: `3px solid ${GHOST_COLORS[i]}`,
        borderRadius: "var(--radius)", padding: 14, minHeight: 110,
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
          <div style={{ height: 10, width: "55%", background: "var(--border2)", borderRadius: 3 }} />
          <div style={{ height: 10, width: "14%", background: "var(--border)", borderRadius: 3 }} />
        </div>
        <div style={{ height: 8, width: "38%", background: "var(--border)", borderRadius: 3, marginBottom: 10 }} />
        <div style={{ height: 7, width: "88%", background: "var(--border)", borderRadius: 3, marginBottom: 4 }} />
        <div style={{ height: 7, width: "72%", background: "var(--border)", borderRadius: 3 }} />
      </div>
    ));

    return (
      <div style={{ position: "relative", borderRadius: "var(--radius)", marginTop: 8, minHeight: 400, overflow: "hidden" }}>
        {/* Blurred ghost */}
        <div style={{ filter: "blur(5px)", pointerEvents: "none", userSelect: "none", opacity: 0.3 }}>
          <ColsGrid items={ghostCards} cols={3} />
        </div>
        {/* Gradient overlay */}
        <div style={{
          position: "absolute", inset: 0,
          background: "linear-gradient(to bottom, transparent 0%, var(--bg) 50%)",
          display: "flex", flexDirection: "column", alignItems: "center",
          justifyContent: "flex-end", padding: "0 24px 32px", textAlign: "center",
        }}>
          <div style={{ fontSize: 30, marginBottom: 10 }}>🔒</div>
          <div style={{ fontFamily: "var(--mono)", fontSize: 14, fontWeight: 700, color: "var(--text)", marginBottom: 8, letterSpacing: ".5px" }}>
            MÓDULO ACTIVE CHECKS
          </div>
          <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 20, maxWidth: 400, lineHeight: 1.75 }}>
            Análise invasiva com simulação real de ataques — WAF bypass, CORS injection, port scan,
            XSS/SQLi probes e exposição de arquivos sensíveis. Disponível apenas em <strong style={{ color: "var(--accent)" }}>scan ativo</strong>.
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "7px 32px", marginBottom: 24, textAlign: "left" }}>
            {[t("ativo.wafDetection"), t("ativo.corsAnalysis"), t("ativo.sensitiveFiles"), t("ativo.xssSqli"), t("ativo.portScan"), t("ativo.dbErrorLeak")].map(f => (
              <div key={f} style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)", display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ color: "var(--secure)", fontSize: 13 }}>✓</span> {f}
              </div>
            ))}
          </div>
          <button onClick={onShowPlans} style={{
            background: "var(--accent)", color: "var(--bg)", border: "none",
            borderRadius: "var(--radius)", padding: "10px 26px",
            fontFamily: "var(--mono)", fontSize: 12, fontWeight: 700,
            cursor: "pointer", letterSpacing: ".5px",
          }}>
            VER PLANOS →
          </button>
        </div>
      </div>
    );
  }

  /* ── CONTEÚDO ATIVO ── */
  const waf  = r.wafDetectionResult;
  const cors = r.corsResult;

  const wafColor   = waf?.detected ? "var(--secure)" : "var(--text-muted)";
  const probeColor = waf?.probeResponse === "BLOCKED" ? "var(--secure)" : waf?.probeResponse === "PASSED" ? "var(--warning)" : "var(--text-muted)";
  const confColor  = waf?.confidence === "HIGH" ? "var(--secure)" : waf?.confidence === "MEDIUM" ? "var(--warning)" : "var(--text-muted)";

  const corsCards = cors?.tested ? [
    { key: "wildcard", title: t("ativo.wildcardOrigin"),  ok: !cors.wildcardOrigin,    value: cors.wildcardOrigin    ? t("ativo.aberto")   : t("ativo.seguro"),
      desc: t("ativo.wildcardDesc"), tip: t("ativo.wildcardDica") },
    { key: "reflects", title: t("ativo.reflectsOrigin"),  ok: !cors.reflectsOrigin,    value: cors.reflectsOrigin    ? t("ativo.reflete")  : t("ativo.seguro"),
      desc: t("ativo.refleteDesc"), tip: t("ativo.refleteDica") },
    { key: "creds",    title: t("ativo.credentials"),      ok: !cors.credentialsAllowed, value: cors.credentialsAllowed ? t("ativo.permitido"): t("ativo.seguro"),
      desc: t("ativo.credentialsDesc"), tip: t("ativo.credentialsDica") },
    { key: "null",     title: t("ativo.nullOrigin"),       ok: !cors.nullOriginAccepted, value: cors.nullOriginAccepted ? t("ativo.aceito")  : t("ativo.seguro"),
      desc: t("ativo.nullOriginDesc"), tip: t("ativo.nullOriginDica") },
  ] : [];

  const probeCards = [
    { key: "surface", title: t("ativo.inputSurface"),  neutral: !r.inputSurfaceDetected, ok: false,
      value: r.inputSurfaceDetected ? "Detectada" : t("ativo.naoDetectada"),
      desc: t("ativo.inputSurfaceDesc"),
      tip: t("ativo.inputSurfaceDica") },
    { key: "xss",     title: t("ativo.xssProbe"),      neutral: !r.xssProbePerformed,    ok: r.xssProbePerformed,
      value: r.xssProbePerformed ? "Executado" : t("ativo.naoExecutado"),
      desc: t("ativo.xssProbeDesc"),
      tip: t("ativo.xssProbeDica") },
    { key: "rxss",    title: t("ativo.reflectedXss"),  neutral: !r.xssProbePerformed,    ok: r.xssProbePerformed ? !r.reflectedXssSuspected : true,
      value: r.xssProbePerformed ? (r.reflectedXssSuspected ? t("ativo.suspeito") : t("selo.limpo")) : t("ativo.semSuperficie"),
      desc: t("ativo.reflectedXssDesc"),
      tip: t("ativo.reflectedXssDica") },
    { key: "dberr",   title: t("ativo.dbErrorLeak"),   neutral: false,                   ok: !r.dbErrorLeakageSuspected,
      value: r.dbErrorLeakageSuspected ? t("ativo.suspeito") : t("selo.limpo"),
      desc: t("ativo.dbErrorDesc"),
      tip: t("ativo.dbErrorDica") },
  ];

  const sensitiveItems: FindingItem[] = (r.sensitiveFiles ?? []).map((f: any, i: number) => ({
    id: `sf-${i}`, title: f.path, severity: f.severity,
    extraTags: [{ label: f.exposure, color: f.exposure === "EXPOSED" ? "var(--critical)" : "var(--warning)" }],
    summary: f.contentPreview ? f.contentPreview.slice(0, 90) + "…" : t("ativo.arquivoPublico"),
    details: [
      { label: "PATH",     value: <code style={{ fontFamily: "var(--mono)", fontSize: 10, wordBreak: "break-all" }}>{f.path}</code> },
      { label: "EXPOSURE", value: f.exposure },
      ...(f.contentPreview ? [{ label: "PREVIEW", value: <pre style={{ fontFamily: "var(--mono)", fontSize: 9, margin: 0, whiteSpace: "pre-wrap" as const, wordBreak: "break-all" as const }}>{f.contentPreview}</pre> }] : []),
    ],
  }));

  return (
    <div>
      {/* WAF Detection */}
      <SecLabel label="WAF DETECTION" />
      <ColsGrid cols={3} items={[
        <ModCard key="waf-det" id="waf-det" color={wafColor} isOpen={openSet.has("waf-det")} onToggle={() => toggle("waf-det")}
          top={
            <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
              <div>
                <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: 700 }}>{t("ativo.wafDetectado")}</div>
                <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: wafColor, marginTop: 2 }}>
                  {waf?.detected ? (waf.provider ?? "Sim") : t("ativo.naoConfirmado")}
                </div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: 14, color: wafColor }}>{waf?.detected ? "✓" : "○"}</div>
                <div style={{ fontSize: 9, color: wafColor, fontFamily: "var(--mono)", fontWeight: 700 }}>{waf?.detected ? "ATIVO" : "NONE"}</div>
              </div>
            </div>
          }
          mid={<p style={{ fontSize: 10, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>
            {t("ativo.wafDesc")}
          </p>}
          bottom={<>
            {waf?.provider && <div style={{ marginBottom: 6 }}>
              <span style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--mono)" }}>PROVIDER </span>
              <span style={{ fontSize: 11, color: "var(--accent)", fontFamily: "var(--mono)" }}>{waf.provider}</span>
            </div>}
            <p style={{ fontSize: 10, color: "var(--text-muted)", fontStyle: "italic", margin: 0 }}>{t("ativo.wafReduz")}</p>
          </>}
        />,
        <ModCard key="waf-conf" id="waf-conf" color={confColor} isOpen={openSet.has("waf-conf")} onToggle={() => toggle("waf-conf")}
          top={
            <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
              <div>
                <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: 700 }}>{t("ativo.confianca")}</div>
                <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: confColor, marginTop: 2 }}>{waf?.confidence ?? "—"}</div>
              </div>
              <div style={{ textAlign: "right", fontSize: 14, color: confColor }}>
                {waf?.confidence === "HIGH" ? "✓" : waf?.confidence === "MEDIUM" ? "⚠" : "—"}
              </div>
            </div>
          }
          mid={<p style={{ fontSize: 10, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>
            {t("ativo.confiancaDesc")}
          </p>}
          bottom={<>
            {waf?.evidence && <div style={{ marginBottom: 8 }}>
              <span style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--mono)", display: "block", marginBottom: 3 }}>{t("ativo.evidencia")}</span>
              <code style={{ fontSize: 10, color: "var(--accent)", fontFamily: "var(--mono)", wordBreak: "break-all", display: "block" }}>{waf.evidence}</code>
            </div>}
            <p style={{ fontSize: 10, color: "var(--text-muted)", fontStyle: "italic", margin: 0 }}>{t("ativo.confiancaLegenda")}</p>
          </>}
        />,
        <ModCard key="waf-probe" id="waf-probe" color={probeColor} isOpen={openSet.has("waf-probe")} onToggle={() => toggle("waf-probe")}
          top={
            <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
              <div>
                <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: 700 }}>Probe</div>
                <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: probeColor, marginTop: 2 }}>{waf?.probeResponse ?? "—"}</div>
              </div>
              <div style={{ textAlign: "right", fontSize: 14, color: probeColor }}>
                {waf?.probeResponse === "BLOCKED" ? "✓" : waf?.probeResponse === "PASSED" ? "⚠" : "—"}
              </div>
            </div>
          }
          mid={<p style={{ fontSize: 10, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>
            {t("ativo.probeDesc")}
          </p>}
          bottom={<>
            {waf?.summary && <div style={{ marginBottom: 8, fontSize: 10, color: "var(--text-dim)", lineHeight: 1.5 }}>{waf.summary}</div>}
            <p style={{ fontSize: 10, color: "var(--text-muted)", fontStyle: "italic", margin: 0 }}>{t("ativo.probeLegenda")}</p>
          </>}
        />,
      ]} />

      {/* CORS Analysis */}
      <SecLabel label="CORS ANALYSIS" />
      {cors?.tested ? (<>
        {cors.message && (
          <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)", marginBottom: 8,
            padding: "6px 10px", background: "var(--surface)", borderRadius: "var(--radius)", border: "1px solid var(--border2)" }}>
            {cors.message}
          </div>
        )}
        <ColsGrid cols={2} items={corsCards.map(c => {
          const color = c.ok ? "var(--secure)" : "var(--warning)";
          return (
            <ModCard key={c.key} id={`cors-${c.key}`} color={color} isOpen={openSet.has(`cors-${c.key}`)} onToggle={() => toggle(`cors-${c.key}`)}
              top={
                <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
                  <div>
                    <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: 700 }}>{c.title}</div>
                    <div style={{ fontFamily: "var(--mono)", fontSize: 10, color, marginTop: 2 }}>{c.value}</div>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ fontSize: 14, color }}>{c.ok ? "✓" : "⚠"}</div>
                    <div style={{ fontSize: 9, color, fontFamily: "var(--mono)", fontWeight: 700 }}>{c.ok ? "OK" : "WARN"}</div>
                  </div>
                </div>
              }
              mid={<p style={{ fontSize: 10, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>{c.desc}</p>}
              bottom={<p style={{ fontSize: 10, color: "var(--text-muted)", fontStyle: "italic", margin: 0 }}>◈ {c.tip}</p>}
            />
          );
        })} />
        {cors.allowOriginValue && (
          <div style={{ marginTop: 8, fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-muted)" }}>
            Allow-Origin: <code style={{ color: "var(--accent)" }}>{cors.allowOriginValue}</code>
          </div>
        )}
      </>) : (
        <div style={{ color: "var(--text-muted)", fontFamily: "var(--mono)", fontSize: 11, padding: "10px 0" }}>{t("ativo.probeNaoExecutado")}</div>
      )}

      {/* Sensitive Files */}
      <SecLabel label={`SENSITIVE FILES${r.sensitiveFiles?.length ? ` [${r.sensitiveFiles.length}]` : ""}`} />
      {sensitiveItems.length > 0
        ? <FindingCardsPanel items={sensitiveItems} emptyMsg={t("ativo.semArquivosSensiveis")} cols={2} />
        : <SecureEmptyCard msg={t("ativo.semArquivosSensiveis")} />}

      {/* Application Probes */}
      <SecLabel label="APPLICATION PROBES" />
      <ColsGrid cols={2} items={probeCards.map(p => {
        const color = p.neutral ? "var(--text-muted)" : p.ok ? "var(--secure)" : "var(--warning)";
        return (
          <ModCard key={p.key} id={`probe-${p.key}`} color={color} isOpen={openSet.has(`probe-${p.key}`)} onToggle={() => toggle(`probe-${p.key}`)}
            top={
              <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: 700 }}>{p.title}</div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 10, color, marginTop: 2 }}>{p.value}</div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ fontSize: 14, color }}>{p.neutral ? "○" : p.ok ? "✓" : "⚠"}</div>
                  <div style={{ fontSize: 9, color, fontFamily: "var(--mono)", fontWeight: 700 }}>{p.neutral ? "—" : p.ok ? "OK" : "WARN"}</div>
                </div>
              </div>
            }
            mid={<p style={{ fontSize: 10, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>{p.desc}</p>}
            bottom={<p style={{ fontSize: 10, color: "var(--text-muted)", fontStyle: "italic", margin: 0 }}>◈ {p.tip}</p>}
          />
        );
      })} />

      {/* Port Scan */}
      <SecLabel label={`PORT SCAN [${r.openPorts?.length ?? 0}]`} />
      {r.openPorts?.length ? (
        <table className={styles.table}>
          <thead><tr><th>Port</th><th>Service</th><th>Sev</th><th>ms</th></tr></thead>
          <tbody>
            {r.openPorts.map((p: any, i: number) => (
              <tr key={i}>
                <td><code>{p.port}</code></td>
                <td>{p.service}</td>
                <td><Tag label={p.severity} cls={sevColor(p.severity)} /></td>
                <td className={styles.muted}>{p.latencyMs}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <SecureEmptyCard msg={t("ativo.semPortas")} />}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────

function ScoreHistoryChart({ host, showFilter = false }: { host: string; showFilter?: boolean }) {
  const { t } = useI18n();
  const [allData, setAllData] = useState<HistorySummary[]>([]);
  const [fromDate, setFromDate] = useState("");
  const [toDate,   setToDate]   = useState("");

  useEffect(() => {
    if (!host) return;
    setAllData([]);
    setFromDate("");
    setToDate("");
    api.get<HistorySummary[]>(`/history/${host}`)
      .then(res => {
        // Oldest first for the chart
        setAllData([...res.data].reverse());
      })
      .catch(() => {});
  }, [host]);

  // Without filter (Scanner sidebar): last 30 records. With filter: apply date range.
  const data = showFilter
    ? allData.filter(d => {
        const day = d.scannedAt.slice(0, 10);
        if (fromDate && day < fromDate) return false;
        if (toDate   && day > toDate)   return false;
        return true;
      })
    : allData.slice(-30);

  if (allData.length < 2) return null;

  // Um ponto por dia — último scan do dia
  const pointsMap = new Map<string, typeof data[0]>();
  for (const d of data) {
    const day = new Date(d.scannedAt).toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit", year: "numeric" });
    pointsMap.set(day, d);
  }
  const points = Array.from(pointsMap.values()).map(d => {
    const dt = new Date(d.scannedAt);
    return {
      ts: dt.getTime(),
      score: d.score,
      risk: d.riskLevel,
      fullLabel: dt.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" }) + " " +
                 dt.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }),
    };
  });

  const latest = data[data.length - 1];
  const prev   = data[data.length - 2];
  const delta  = latest && prev ? latest.score - prev.score : 0;
  const deltaStr = delta > 0 ? `+${delta}` : String(delta);
  const deltaColor = delta > 0 ? "var(--secure)" : delta < 0 ? "var(--critical)" : "var(--text-dim)";

  const hasFilter = !!fromDate || !!toDate;

  return (
    <Card title={t("grafico.historico")}>
      <div className={styles.historyChartWrap}>
        {/* Period filter — only in Histórico tab */}
        {showFilter && <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 10 }}>
          <span className={styles.muted} style={{ fontSize: 11 }}>{t("grafico.periodo")}</span>
          <input
            type="date"
            value={fromDate}
            max={toDate || undefined}
            onChange={e => setFromDate(e.target.value)}
            style={{
              background: "var(--surface)", border: "1px solid var(--border2)",
              borderRadius: "var(--radius-sm)", color: "var(--text)",
              fontFamily: "var(--mono)", fontSize: 11, padding: "3px 8px",
              cursor: "pointer", outline: "none",
            }}
          />
          <span className={styles.muted} style={{ fontSize: 11 }}>{t("auditoria.ate")}</span>
          <input
            type="date"
            value={toDate}
            min={fromDate || undefined}
            onChange={e => setToDate(e.target.value)}
            style={{
              background: "var(--surface)", border: "1px solid var(--border2)",
              borderRadius: "var(--radius-sm)", color: "var(--text)",
              fontFamily: "var(--mono)", fontSize: 11, padding: "3px 8px",
              cursor: "pointer", outline: "none",
            }}
          />
          {hasFilter && (
            <button
              className={`${styles.btn} ${styles.btnGhost}`}
              style={{ fontSize: 11, padding: "3px 10px" }}
              onClick={() => { setFromDate(""); setToDate(""); }}
            >
              Limpar
            </button>
          )}
        </div>}

        {points.length < 2 ? (
          <div className={styles.empty} style={{ fontSize: 12, padding: "12px 0" }}>
            ◈ {data.length === 0
              ? t("grafico.semScans")
              : t("grafico.doisDias")}
          </div>
        ) : (
          <>
            <div className={styles.historyChartMeta}>
              <span className={styles.muted}>
                {points.length} dias · {data.length} scan{data.length !== 1 ? "s" : ""}
                {hasFilter ? " " + t("grafico.filtrado") : " " + t("grafico.todoPeriodo")}
              </span>
              <span style={{ color: deltaColor, fontWeight: 600, fontFamily: "var(--mono)", fontSize: 13 }}>
                {deltaStr} vs anterior
              </span>
            </div>
            <div onMouseDown={e => e.preventDefault()} style={{ cursor: "default" }}>
              <ResponsiveContainer width="100%" height={140}>
                <LineChart data={points} margin={{ top: 8, right: 8, left: -28, bottom: 0 }}>
                  <XAxis
                    dataKey="ts"
                    type="number"
                    scale="time"
                    domain={["dataMin", "dataMax"]}
                    tickCount={Math.min(points.length, 6)}
                    tickFormatter={(v: number) =>
                      new Date(v).toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" })
                    }
                    tick={{ fill: "var(--text-muted)", fontSize: 10, fontFamily: "var(--mono)" }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    domain={[0, 100]}
                    tick={{ fill: "var(--text-muted)", fontSize: 10, fontFamily: "var(--mono)" }}
                    axisLine={false}
                    tickLine={false}
                    ticks={[0, 25, 50, 75, 100]}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "var(--surface)",
                      border: "1px solid var(--border)",
                      borderRadius: 4,
                      fontSize: 11,
                      fontFamily: "var(--mono)",
                      color: "var(--text)",
                    }}
                    formatter={(value) => [`${(value as number) ?? 0}/100`, "Score"]}
                    labelFormatter={(_: unknown, payload: readonly any[]) =>
                      payload?.length ? payload[0]?.payload?.fullLabel ?? "" : ""
                    }
                    trigger="hover"
                  />
                  <ReferenceLine y={85} stroke="var(--secure)"   strokeDasharray="3 3" strokeOpacity={0.3} />
                  <ReferenceLine y={70} stroke="var(--info)"     strokeDasharray="3 3" strokeOpacity={0.3} />
                  <ReferenceLine y={45} stroke="var(--warning)"  strokeDasharray="3 3" strokeOpacity={0.3} />
                  <ReferenceLine y={20} stroke="var(--critical)" strokeDasharray="3 3" strokeOpacity={0.3} />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="var(--accent)"
                    strokeWidth={2}
                    dot={{ r: 3, fill: "var(--accent)", strokeWidth: 0 }}
                    activeDot={{ r: 5, fill: "var(--accent)", strokeWidth: 0 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </>
        )}
      </div>
    </Card>
  );
}

// ── Settings Page (2FA + conta) ───────────────────────────────────────────────

function SettingsPage() {
  const { t } = useI18n();
  const { user, isOwner } = useAuth();

  // TOTP state
  const [totpEnabled, setTotpEnabled]     = useState(false);
  const [emailEnabled, setEmailEnabled]   = useState(false);
  const [require2fa, setRequire2fa]       = useState(false);
  const [loadedSettings, setLoadedSettings] = useState(false);

  // TOTP setup flow
  const [totpSetup, setTotpSetup]         = useState<{ secret: string; qrUri: string; qrImage?: string } | null>(null);
  const [totpConfirmCode, setTotpConfirmCode] = useState("");

  const [msg, setMsg]   = useState<string | null>(null);
  const [err, setErr]   = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Load current 2FA status from /auth/me (UserDto includes totpEnabled, emailOtpEnabled, account.require2fa)
  useEffect(() => {
    api.get<{ totpEnabled: boolean; emailOtpEnabled: boolean; account: { require2fa: boolean } | null }>("/auth/me")
      .then(res => {
        setTotpEnabled(res.data.totpEnabled   ?? false);
        setEmailEnabled(res.data.emailOtpEnabled ?? false);
        setRequire2fa(res.data.account?.require2fa ?? false);
        setLoadedSettings(true);
      }).catch(() => setLoadedSettings(true));
  }, []);

  function flash(m: string, isErr = false) {
    if (isErr) { setErr(m); setMsg(null); } else { setMsg(m); setErr(null); }
    setTimeout(() => { setMsg(null); setErr(null); }, 4000);
  }

  async function startTotp() {
    setBusy(true);
    try {
      const res = await api.post<{ secret: string; qrUri: string }>("/auth/2fa/setup/totp");
      setTotpSetup(res.data);
    } catch { flash(t("config.erroTotp"), true); }
    finally { setBusy(false); }
  }

  async function confirmTotp() {
    if (!totpConfirmCode) return;
    setBusy(true);
    try {
      await api.post("/auth/2fa/setup/totp/confirm", { code: totpConfirmCode });
      setTotpEnabled(true); setTotpSetup(null); setTotpConfirmCode("");
      flash(t("config.totpAtivado"));
    } catch { flash(t("config.codigoInvalido"), true); }
    finally { setBusy(false); }
  }

  async function disableTotp() {
    setBusy(true);
    try {
      await api.delete("/auth/2fa/totp");
      setTotpEnabled(false); flash(t("config.totpDesativado"));
    } catch { flash(t("config.erroDesativarTotp"), true); }
    finally { setBusy(false); }
  }

  async function toggleEmailOtp() {
    setBusy(true);
    try {
      if (emailEnabled) {
        await api.delete("/auth/2fa/email");
        setEmailEnabled(false); flash(t("config.emailOtpDesativado"));
      } else {
        // O backend envia um código de teste antes de ativar. Se o e-mail não
        // sai, a ativação falha aqui — de propósito: ativar assim mesmo trancaria
        // a conta, já que não existe código de backup.
        await api.post("/auth/2fa/email");
        setEmailEnabled(true);
        flash(t("config.emailOtpAtivado"));
      }
    } catch (e: any) {
      flash(e?.response?.data?.message ?? t("config.erroEmailOtp"), true);
    }
    finally { setBusy(false); }
  }

  async function toggleRequire2fa() {
    setBusy(true);
    const next = !require2fa;
    try {
      await api.put("/admin/account/require2fa", { require2fa: next });
      setRequire2fa(next); flash(next ? "2FA obrigatório para todos os usuários da conta." : "2FA voltou a ser opcional.");
    } catch { flash(t("config.erroAlterar"), true); }
    finally { setBusy(false); }
  }

  if (!loadedSettings) return <div className={styles.settingsPage}><p className={styles.muted}>{t("app.carregando")}</p></div>;

  // QR vem do backend como data URI. Antes era montado em api.qrserver.com com a
  // otpauth:// na query string — ou seja, o SEGREDO TOTP e o e-mail do usuário
  // eram enviados para um terceiro a cada setup de 2FA.
  const qrImageUrl = totpSetup?.qrImage ?? null;

  return (
    <div className={styles.settingsPage}>
      <h2 className={styles.settingsTitle}>{t("config.titulo")}</h2>

      {msg && <div className={styles.infoBox}>{msg}</div>}
      {err && <div className={styles.errorBox}>{err}</div>}

      {/* ── TOTP ── */}
      <div className={styles.settingsCard}>
        <div className={styles.settingsCardHeader}>
          <div>
            <div className={styles.settingsCardTitle}>Autenticador TOTP <span className={styles.settingsBadge2fa}>{t("config.totpApp")}</span></div>
            <div className={styles.settingsCardSub}>{t("config.totpDesc")}</div>
          </div>
          <span className={totpEnabled ? styles.tf2faBadgeOn : styles.tf2faBadgeOff}>{totpEnabled ? "ATIVO" : "INATIVO"}</span>
        </div>

        {!totpEnabled && !totpSetup && (
          <button className={`${styles.btn} ${styles.btnScan}`} disabled={busy} onClick={startTotp}>
            Ativar TOTP
          </button>
        )}

        {totpSetup && (
          <div className={styles.totpSetupBox}>
            <p className={styles.settingsCardSub}>
              1. Escaneie o QR code com seu app autenticador, ou insira a chave manualmente.
            </p>
            {qrImageUrl && <img src={qrImageUrl} alt={t("config.qrTotp")} className={styles.totpQr} />}
            <div className={styles.totpSecretBox}>
              <span className={styles.formLabel}>{t("config.chaveManual")}</span>
              <code className={styles.totpSecret}>{totpSetup.secret}</code>
            </div>
            <p className={styles.settingsCardSub}>2. Digite o código de 6 dígitos exibido no app para confirmar:</p>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 8 }}>
              <input className={`${styles.formInput} ${styles.tfCodeInput}`}
                type="text" inputMode="numeric" maxLength={6}
                value={totpConfirmCode} onChange={e => setTotpConfirmCode(e.target.value)}
                placeholder="000000" />
              <button className={`${styles.btn} ${styles.btnScan}`} disabled={busy} onClick={confirmTotp}>
                Confirmar
              </button>
              <button className={`${styles.btn} ${styles.btnGhost}`} onClick={() => { setTotpSetup(null); setTotpConfirmCode(""); }}>
                Cancelar
              </button>
            </div>
          </div>
        )}

        {totpEnabled && (
          <button className={`${styles.btn} ${styles.btnDanger}`} disabled={busy} onClick={disableTotp}>
            Desativar TOTP
          </button>
        )}
      </div>

      {/* ── Email OTP ── */}
      <div className={styles.settingsCard}>
        <div className={styles.settingsCardHeader}>
          <div>
            <div className={styles.settingsCardTitle}>{t("config.emailOtp")}</div>
            <div className={styles.settingsCardSub}>Código de 6 dígitos enviado para {user?.email} a cada login.</div>
          </div>
          <span className={emailEnabled ? styles.tf2faBadgeOn : styles.tf2faBadgeOff}>{emailEnabled ? "ATIVO" : "INATIVO"}</span>
        </div>
        <button
          className={`${styles.btn} ${emailEnabled ? styles.btnDanger : styles.btnScan}`}
          disabled={busy}
          onClick={toggleEmailOtp}>
          {emailEnabled ? t("config.desativarEmailOtp") : t("config.ativarEmailOtp")}
        </button>
      </div>

      {/* ── Conta: require2fa (só OWNER) ── */}
      {isOwner() && (
        <div className={styles.settingsCard}>
          <div className={styles.settingsCardHeader}>
            <div>
              <div className={styles.settingsCardTitle}>2FA obrigatório para a conta <span className={styles.settingsBadge2fa}>OWNER</span></div>
              <div className={styles.settingsCardSub}>{t("config.obrigatorioDesc")}</div>
            </div>
            <span className={require2fa ? styles.tf2faBadgeOn : styles.tf2faBadgeOff}>{require2fa ? t("config.obrigatorio") : t("config.opcional")}</span>
          </div>
          <button
            className={`${styles.btn} ${require2fa ? styles.btnDanger : styles.btnScan}`}
            disabled={busy}
            onClick={toggleRequire2fa}>
            {require2fa ? t("config.tornarOpcional") : t("config.tornarObrigatorio")}
          </button>
        </div>
      )}

      {/* ── Privacidade e Dados (LGPD) ── */}
      <div className={styles.settingsCard}>
        <div className={styles.settingsCardHeader}>
          <div>
            <div className={styles.settingsCardTitle}>Privacidade e Dados <span className={styles.settingsBadge2fa}>LGPD</span></div>
            <div className={styles.settingsCardSub}>{t("config.privacidadeDesc")}</div>
          </div>
        </div>

        {/* Exportar dados */}
        <div className={styles.dangerZoneRow}>
          <div>
            <div className={styles.dangerZoneLabel}>{t("config.exportar")}</div>
            <div className={styles.settingsCardSub}>{t("config.exportarDesc")}</div>
          </div>
          <button className={`${styles.btn} ${styles.btnGhost}`} disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                const res = await api.get<object>("/user/data-export");
                const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url; a.download = "cyberaudit-meus-dados.json";
                document.body.appendChild(a); a.click(); a.remove();
                window.URL.revokeObjectURL(url);
              } catch { flash(t("config.erroExportar"), true); }
              finally { setBusy(false); }
            }}>
            ↓ Exportar JSON
          </button>
        </div>

        {/* Excluir conta */}
        <div className={`${styles.dangerZoneRow} ${styles.dangerZoneBorder}`}>
          <div>
            <div className={`${styles.dangerZoneLabel} ${styles.dangerZoneLabelRed}`}>{t("config.excluir")}</div>
            <div className={styles.settingsCardSub}>{t("config.excluirDesc")}</div>
          </div>
          <DeleteAccountButton onDelete={() => { flash(t("config.contaExcluida")); window.location.href = "/"; }} />
        </div>
      </div>

      {/* ── API Keys ── */}
      <ApiKeysSection />

      {/* ── Identidade Visual (EMPRESA) ── */}
      <BrandingSection />
    </div>
  );
}

// ── API Keys Section (dentro de SettingsPage via componente separado) ──────────

interface ApiKeyDto {
  id: string;
  name: string;
  keyPrefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  expiresAt: string | null;
  active: boolean;
  createdByName: string | null;
  plainKey?: string;
}

function ApiKeysSection() {
  const { t } = useI18n();
  const { user, isAdmin } = useAuth();
  const [keys, setKeys]         = useState<ApiKeyDto[]>([]);
  const [loading, setLoading]   = useState(true);
  const [newName, setNewName]   = useState("");
  const [creating, setCreating] = useState(false);
  const [newKey, setNewKey]     = useState<ApiKeyDto | null>(null);
  const [copied, setCopied]     = useState(false);
  const [error, setError]       = useState<string | null>(null);

  const canApiKeys = isAdmin()
      || user?.account?.type === "COMPANY"
      || user?.account?.plan === "PRO"
      || user?.account?.plan === "ENTERPRISE";

  async function load() {
    try { setKeys((await api.get<ApiKeyDto[]>("/api-keys")).data); }
    catch { /* silencioso */ }
    finally { setLoading(false); }
  }

  useEffect(() => { if (canApiKeys) load(); else setLoading(false); }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!newName.trim()) return;
    setCreating(true); setError(null);
    try {
      const res = await api.post<ApiKeyDto>("/api-keys", { name: newName.trim() });
      setNewKey(res.data);
      setNewName("");
      await load();
    } catch (e: any) { setError(e?.response?.data?.message ?? t("apikey.erroCriar")); }
    finally { setCreating(false); }
  }

  async function revoke(id: string) {
    if (!confirm(t("apikey.confirmaRevogar"))) return;
    try { await api.delete(`/api-keys/${id}`); await load(); }
    catch (e: any) { setError(e?.response?.data?.message ?? t("apikey.erroRevogar")); }
  }

  function copyKey(k: string) {
    navigator.clipboard.writeText(k);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  }

  if (!canApiKeys) {
    return (
      <div className={styles.settingsCard}>
        <div className={styles.settingsCardHeader}>
          <div>
            <div className={styles.settingsCardTitle}>{t("apikey.titulo")}</div>
            <div className={styles.settingsCardSub}>{t("apikey.desc")}</div>
          </div>
          <span className={styles.tf2faBadgeOff}>PRO</span>
        </div>
        <div className={styles.settingsCardSub} style={{ color: "var(--text-muted)", marginTop: 4 }}>
          Disponível para planos PRO e contas Empresa.{" "}
          <span style={{ color: "var(--accent)", cursor: "pointer" }}>{t("bloqueio.verPlanos")}</span>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.settingsCard}>
      <div className={styles.settingsCardHeader}>
        <div>
          <div className={styles.settingsCardTitle}>{t("apikey.titulo")}</div>
          <div className={styles.settingsCardSub}>
            Use <code style={{ fontFamily: "var(--mono)", fontSize: 11 }}>X-Api-Key: ca_...</code> para autenticar chamadas à API. Máx. 10 keys ativas.
          </div>
        </div>
      </div>

      {/* Modal: nova key gerada */}
      {newKey?.plainKey && (
        <div style={{ background: "var(--secure)15", border: "1px solid var(--secure)50", borderRadius: 6, padding: 14, marginBottom: 12 }}>
          <div style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--secure)", letterSpacing: ".5px", marginBottom: 6 }}>
            ✓ KEY CRIADA — COPIE AGORA, NÃO SERÁ EXIBIDA NOVAMENTE
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <code style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", flex: 1, wordBreak: "break-all" }}>
              {newKey.plainKey}
            </code>
            <button className={`${styles.btn} ${styles.btnScan}`} style={{ fontSize: 11, whiteSpace: "nowrap" }}
              onClick={() => copyKey(newKey.plainKey!)}>
              {copied ? t("posse.copiado") : "Copiar"}
            </button>
          </div>
          <div style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--text-muted)", marginTop: 8 }}>
            Exemplo CI/CD:<br />
            <code style={{ color: "var(--accent)" }}>
              curl -H "X-Api-Key: {newKey.plainKey}" "https://sua-api.com/api-keys/ci?url=example.com&threshold=80"
            </code>
          </div>
          <button style={{ marginTop: 8, fontSize: 10, color: "var(--text-muted)", background: "none", border: "none", cursor: "pointer" }}
            onClick={() => setNewKey(null)}>{t("apikey.fechar")}</button>
        </div>
      )}

      {error && <div className={styles.errorBox} style={{ marginBottom: 8 }}>{error}</div>}

      {/* Form nova key */}
      <form onSubmit={create} style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input className={styles.urlInput} value={newName}
          onChange={e => setNewName(e.target.value)}
          placeholder='Nome da key (ex: "GitHub CI")'
          disabled={creating} style={{ flex: 1 }} />
        <button className={`${styles.btn} ${styles.btnScan}`} type="submit"
          disabled={creating || !newName.trim()}>
          {creating ? "..." : t("apikey.gerar")}
        </button>
      </form>

      {/* Lista de keys */}
      {loading ? (
        <div className={styles.muted}>{t("app.carregando")}</div>
      ) : keys.length === 0 ? (
        <div className={styles.muted} style={{ fontSize: 11 }}>{t("apikey.vazio")}</div>
      ) : (
        <table className={styles.table} style={{ width: "100%" }}>
          <thead>
            <tr><th>Nome</th><th>Prefixo</th><th>Criada</th><th>{t("apikey.ultimoUso")}</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {keys.map(k => (
              <tr key={k.id} style={{ opacity: k.active ? 1 : .45 }}>
                <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{k.name}</span></td>
                <td><code style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--accent)" }}>{k.keyPrefix}...</code></td>
                <td><span className={styles.muted} style={{ fontSize: 10 }}>{new Date(k.createdAt).toLocaleDateString("pt-BR")}</span></td>
                <td><span className={styles.muted} style={{ fontSize: 10 }}>{k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleDateString("pt-BR") : "—"}</span></td>
                <td>
                  <span style={{
                    fontFamily: "var(--mono)", fontSize: 9, fontWeight: 700,
                    color: k.active ? "var(--secure)" : "var(--text-muted)"
                  }}>
                    {k.active ? "ATIVA" : "REVOGADA"}
                  </span>
                </td>
                <td>
                  {k.active && (
                    <button className={`${styles.btn} ${styles.btnDanger}`} style={{ fontSize: 10, padding: "2px 8px" }}
                      onClick={() => revoke(k.id)}>
                      Revogar
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--text-muted)", marginTop: 10, lineHeight: 1.6 }}>
        Gate CI/CD: <code style={{ color: "var(--accent)" }}>GET /api-keys/ci?url=example.com&threshold=80</code>
        &nbsp;→ HTTP 200 (aprovado) ou 422 (score abaixo do threshold)
      </div>
    </div>
  );
}

// ── Branding Section (S16 — Branded PDF Reports) ─────────────────────────────

interface BrandingDto {
  brandLogoBase64: string | null;
  brandColor: string | null;
  brandReportName: string | null;
}

function BrandingSection() {
  const { t } = useI18n();
  const { user, isAdmin, isOwner } = useAuth();

  const isCompany = user?.account?.type === "COMPANY";
  const canBranding = isCompany && (isOwner() || isAdmin());
  const canView    = isCompany;

  const [logo, setLogo]         = useState<string | null>(null);
  const [color, setColor]       = useState<string>("#00D3A3");
  const [name, setName]         = useState<string>("");
  const [saving, setSaving]     = useState(false);
  const [saved, setSaved]       = useState(false);
  const [error, setError]       = useState<string | null>(null);
  const [loading, setLoading]   = useState(true);

  useEffect(() => {
    if (!canView) { setLoading(false); return; }
    api.get<BrandingDto>("/account/branding")
      .then(r => r.data)
      .then((d: BrandingDto) => {
        setLogo(d.brandLogoBase64 ?? null);
        setColor(d.brandColor ?? "#00D3A3");
        setName(d.brandReportName ?? "");
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  function handleLogoChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 204800) { setError(t("marca.imagemGrande")); return; }
    const reader = new FileReader();
    reader.onload = () => setLogo(reader.result as string);
    reader.readAsDataURL(file);
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      await api.put("/account/branding", {
        brandLogoBase64: logo,
        brandColor: color || null,
        brandReportName: name.trim() || null,
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("marca.erroSalvar"));
    } finally {
      setSaving(false);
    }
  }

  if (!canView) return null;

  return (
    <div className={styles.settingsCard}>
      <div className={styles.settingsCardHeader}>
        <span>{t("marca.titulo")}</span>
        <span className={styles.badge} style={{ background: "var(--accent)", color: "#000" }}>EMPRESA</span>
      </div>
      <p className={styles.settingsCardDesc}>
        Personalize o cabeçalho dos relatórios PDF com o logo e as cores da sua empresa.
      </p>

      {loading ? (
        <div className={styles.muted}>{t("app.carregando")}</div>
      ) : (
        <form onSubmit={save} style={{ display: "flex", flexDirection: "column", gap: 16 }}>

          {/* ── Logo ── */}
          <div>
            <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-muted)", marginBottom: 6 }}>
              LOGOTIPO (PNG/JPG, máx. 200 KB)
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              {logo && (
                <img
                  src={logo}
                  alt={t("marca.previewLogo")}
                  style={{ height: 40, maxWidth: 120, objectFit: "contain",
                    border: "1px solid var(--border)", borderRadius: 4, padding: 4, background: "#fff" }}
                />
              )}
              {canBranding && (
                <label style={{
                  cursor: "pointer", fontFamily: "var(--mono)", fontSize: 10,
                  padding: "5px 12px", border: "1px solid var(--border)", borderRadius: 4,
                  background: "var(--surface2)", color: "var(--text)"
                }}>
                  {logo ? t("marca.trocarLogo") : t("marca.selecionarLogo")}
                  <input type="file" accept="image/png,image/jpeg,image/svg+xml"
                    style={{ display: "none" }} onChange={handleLogoChange} />
                </label>
              )}
              {logo && canBranding && (
                <button type="button" className={`${styles.btn}`}
                  style={{ fontSize: 10, padding: "4px 10px", color: "var(--danger)" }}
                  onClick={() => setLogo(null)}>
                  Remover
                </button>
              )}
            </div>
          </div>

          {/* ── Nome no PDF ── */}
          <div>
            <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-muted)", marginBottom: 6 }}>
              NOME NO RELATÓRIO
            </div>
            <input
              className={styles.input}
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder='Ex: "ACMECORP SECURITY" (vazio = CyberAudit)'
              maxLength={100}
              disabled={!canBranding}
              style={{ width: "100%", boxSizing: "border-box" }}
            />
          </div>

          {/* ── Cor primária ── */}
          <div>
            <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-muted)", marginBottom: 6 }}>
              COR PRIMÁRIA
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <input
                type="color"
                value={color}
                onChange={e => setColor(e.target.value)}
                disabled={!canBranding}
                style={{ width: 40, height: 32, border: "1px solid var(--border)",
                  borderRadius: 4, cursor: canBranding ? "pointer" : "default",
                  background: "transparent", padding: 2 }}
              />
              <input
                className={styles.input}
                value={color}
                onChange={e => {
                  const v = e.target.value;
                  if (/^#[0-9A-Fa-f]{0,6}$/.test(v)) setColor(v);
                }}
                maxLength={7}
                disabled={!canBranding}
                style={{ width: 100, fontFamily: "var(--mono)", fontSize: 12 }}
              />
              <div style={{
                width: 24, height: 24, borderRadius: 4,
                background: /^#[0-9A-Fa-f]{6}$/.test(color) ? color : "var(--accent)"
              }} />
              <span className={styles.muted} style={{ fontSize: 10 }}>
                Usada no destaque do cabeçalho do PDF
              </span>
            </div>
          </div>

          {/* ── Preview header ── */}
          <div style={{
            borderRadius: 6, overflow: "hidden", border: "1px solid var(--border)",
            fontFamily: "var(--mono)"
          }}>
            <div style={{
              background: "#0D1421", padding: "10px 16px",
              borderLeft: `4px solid ${/^#[0-9A-Fa-f]{6}$/.test(color) ? color : "#00D3A3"}`,
              display: "flex", alignItems: "center", gap: 12
            }}>
              {logo && (
                <img src={logo} alt="" style={{ height: 30, maxWidth: 80, objectFit: "contain" }} />
              )}
              <div>
                <div style={{ fontSize: 13, fontWeight: 700,
                  color: /^#[0-9A-Fa-f]{6}$/.test(color) ? color : "#00D3A3" }}>
                  {name.trim().toUpperCase() || "CYBERAUDIT"}
                </div>
                <div style={{ fontSize: 9, color: "#fff", marginTop: 2 }}>Web Security Report</div>
              </div>
              <div style={{ marginLeft: "auto", fontSize: 8, color: "#4A5568" }}>
                <div>Generated: {new Date().toLocaleDateString("pt-BR")}</div>
                <div style={{ fontWeight: 700 }}>CONFIDENTIAL</div>
              </div>
            </div>
            <div style={{ background: "var(--surface)", padding: "5px 16px", fontSize: 9, color: "var(--text-muted)" }}>
              Prévia do cabeçalho do PDF
            </div>
          </div>

          {!canBranding && (
            <div className={styles.muted} style={{ fontSize: 10 }}>
              Somente OWNER e ADMIN podem alterar o branding.
            </div>
          )}

          {error && <div style={{ color: "var(--danger)", fontSize: 11 }}>{error}</div>}

          {canBranding && (
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button className={`${styles.btn} ${styles.btnScan}`} type="submit" disabled={saving}>
                {saving ? t("comum.salvando") : saved ? t("marca.salvo") : t("marca.salvar")}
              </button>
            </div>
          )}
        </form>
      )}
    </div>
  );
}

function DeleteAccountButton({ onDelete }: { onDelete: () => void }) {
  const { t } = useI18n();
  const { logout } = useAuth();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function doDelete() {
    setBusy(true);
    try {
      await api.delete("/user/account");
      logout();
      onDelete();
    } catch (e: any) {
      setErr(e?.response?.data?.message ?? t("config.erroExcluir"));
      setBusy(false);
      setConfirming(false);
    }
  }

  if (!confirming) {
    return (
      <button className={`${styles.btn} ${styles.btnDanger}`} onClick={() => setConfirming(true)}>
        Excluir conta
      </button>
    );
  }

  return (
    <div className={styles.deleteConfirmBox}>
      <div className={styles.deleteConfirmText}>{t("config.confirmaExcluir")}</div>
      {err && <div className={styles.errorBox} style={{ fontSize: 11, padding: "6px 10px" }}>{err}</div>}
      <div style={{ display: "flex", gap: 8 }}>
        <button className={`${styles.btn} ${styles.btnDanger}`} disabled={busy} onClick={doDelete}>
          {busy ? t("config.excluindo") : t("config.simExcluir")}
        </button>
        <button className={`${styles.btn} ${styles.btnGhost}`} onClick={() => { setConfirming(false); setErr(null); }}>
          Cancelar
        </button>
      </div>
    </div>
  );
}

// ── Public Status Page ────────────────────────────────────────────────────────

interface PublicDomainStatus {
  host: string;
  verified: boolean;
  score: number | null;
  riskLevel: string | null;
  lastScanAt: string | null;
  activeMode: boolean;
  /** Só a contagem — a página é pública, título e correção não saem daqui. */
  issueCounts: { critical: number; high: number; medium: number; low: number };
}
interface PublicStatus {
  accountName: string;
  plan: string;
  generatedAt: string;
  overallScore: number;
  overallRisk: string;
  domains: PublicDomainStatus[];
}

/** Contagem de achados de uma severidade num domínio da página pública. */
function contagem(d: PublicDomainStatus, sev: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"): number {
  const c = d.issueCounts;
  if (!c) return 0;
  return sev === "CRITICAL" ? c.critical
       : sev === "HIGH"     ? c.high
       : sev === "MEDIUM"   ? c.medium
       : c.low;
}

function PublicStatusPage({ token }: { token: string }) {
  const { t } = useI18n();
  const [data, setData] = useState<PublicStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const baseUrl = import.meta.env.VITE_API_URL ?? "http://localhost:8081";
    fetch(`${baseUrl}/public/status/${token}`)
      .then(res => {
        if (!res.ok) throw new Error("not_found");
        return res.json();
      })
      .then(setData)
      .catch(() => setError(t("status.naoEncontrada")))
      .finally(() => setLoading(false));
  }, [token]);

  const riskBadgeCls = (risk?: string | null) => {
    switch (risk) {
      case "CRITICAL": return styles.critical;
      case "HIGH":     return styles.high;
      case "MEDIUM":   return styles.warning;
      case "LOW":      return styles.low;
      case "MINIMAL":  return styles.secure;
      default:         return styles.muted;
    }
  };
  const severityCls = (s: string) => {
    if (s === "CRITICAL") return styles.critical;
    if (s === "HIGH")     return styles.high;
    if (s === "MEDIUM")   return styles.warning;
    if (s === "LOW")      return styles.low;
    return styles.muted;
  };

  if (loading) return (
    <div className={styles.app}>
      <div className={styles.loadingScreen}><span className={styles.logoIcon}>◈</span> Carregando...</div>
    </div>
  );

  if (error || !data) return (
    <div className={styles.app}>
      <div className={styles.loginPage}>
        <div className={styles.loginCard}>
          <div className={styles.loginLogo}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div>
          <div className={styles.loginTitle} style={{ color: "var(--critical)" }}>{t("status.tituloNaoEncontrada")}</div>
          <div className={styles.loginSub}>{error ?? t("status.descNaoEncontrada")}</div>
        </div>
      </div>
    </div>
  );

  return (
    <div className={styles.app}>
      <header className={styles.header}>
        <div className={styles.logo}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div>
        <div className={styles.headerRight}>
          <span className={styles.muted} style={{ fontSize: 11 }}>{t("status.titulo")}</span>
        </div>
      </header>
      <div className={styles.mainContent} style={{ maxWidth: 860, margin: "0 auto", padding: "32px 20px" }}>
        {/* Account header */}
        <div className={styles.card} style={{ marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
            <div>
              <div style={{ fontSize: 18, fontWeight: 700, color: "var(--accent)", letterSpacing: 1 }}>{data.accountName}</div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>Atualizado em {data.generatedAt}</div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: 36, fontWeight: 700, color: data.overallScore >= 75 ? "var(--secure)" : data.overallScore >= 50 ? "var(--warning)" : "var(--critical)" }}>
                {data.overallScore >= 0 ? data.overallScore : "—"}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{t("status.scoreGeral")}</div>
              <span className={`${styles.tag} ${riskBadgeCls(data.overallRisk)}`} style={{ marginTop: 4 }}>{data.overallRisk}</span>
            </div>
          </div>
        </div>

        {/* Domain list */}
        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 2, color: "var(--accent)", marginBottom: 12 }}>
          DOMÍNIOS ({data.domains.length})
        </div>
        {data.domains.map(d => (
          <div key={d.host} className={styles.card} style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
              <div>
                <div style={{ fontWeight: 700, fontSize: 14, color: "var(--text)" }}>
                  {d.host}
                  {d.verified && <span className={`${styles.tag} ${styles.secure}`} style={{ marginLeft: 8, fontSize: 9 }}>{t("status.verificado")}</span>}
                </div>
                {d.lastScanAt && (
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
                    Último scan: {d.lastScanAt} {d.activeMode ? "(ativo)" : "(passivo)"}
                  </div>
                )}
              </div>
              {d.score != null ? (
                <div style={{ textAlign: "right" }}>
                  <div style={{ fontSize: 28, fontWeight: 700, color: d.score >= 75 ? "var(--secure)" : d.score >= 50 ? "var(--warning)" : "var(--critical)" }}>
                    {d.score}
                  </div>
                  {d.riskLevel && <span className={`${styles.tag} ${riskBadgeCls(d.riskLevel)}`} style={{ fontSize: 9 }}>{d.riskLevel}</span>}
                </div>
              ) : (
                <span className={styles.muted} style={{ fontSize: 11 }}>Sem scan</span>
              )}
            </div>
            {/* Contagem por severidade, sem título nem correção: a página é
                pública e listar os achados entregaria o roteiro de ataque. */}
            {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).some(s => contagem(d, s) > 0) && (
              <div style={{ marginTop: 10, borderTop: "1px solid var(--border)", paddingTop: 10, display: "flex", flexWrap: "wrap", gap: 8 }}>
                {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const)
                  .filter(s => contagem(d, s) > 0)
                  .map(s => (
                    <div key={s} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                      <span className={`${styles.tag} ${severityCls(s)}`} style={{ fontSize: 8, whiteSpace: "nowrap" }}>{s}</span>
                      <span style={{ fontSize: 11, color: "var(--text)" }}>{contagem(d, s)}</span>
                    </div>
                  ))}
              </div>
            )}
          </div>
        ))}

        <div style={{ textAlign: "center", marginTop: 32, fontSize: 10, color: "var(--text-muted)" }}>
          Relatório gerado por <strong style={{ color: "var(--accent)" }}>CyberAudit</strong> · Esta página é pública e pode ser compartilhada.
        </div>
      </div>
    </div>
  );
}

/** Retorno do checkout do Mercado Pago (back_url = /billing/return). Confirma a assinatura. */
function BillingReturnPage() {
  const { t } = useI18n();
  const [state, setState] = useState<"processing" | "active" | "pending">("processing");
  useEffect(() => {
    let stop = false, tries = 0;
    const check = async () => {
      tries++;
      try {
        const res = await api.get("/billing/subscription");
        const sub: any = res.data;
        if (sub && sub.status === "AUTHORIZED") {
          setState("active"); stop = true;
          setTimeout(() => { window.location.href = "/"; }, 1800);
          return;
        }
      } catch { /* ainda processando */ }
      if (!stop && tries >= 12) { setState("pending"); stop = true; }
    };
    check();
    const iv = setInterval(() => { if (stop) { clearInterval(iv); return; } check(); }, 3000);
    return () => { stop = true; clearInterval(iv); };
  }, []);

  return (
    <div className={styles.app}>
      <div className={styles.loginPage}>
        <div className={styles.loginCard} style={{ textAlign: "center" }}>
          <div className={styles.loginLogo}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div>
          {state === "processing" && (<>
            <div className={styles.loginTitle}>{t("billing.processando")}</div>
            <div className={styles.loginSub}>{t("billing.confirmando")}</div>
          </>)}
          {state === "active" && (<>
            <div className={styles.loginTitle} style={{ color: "var(--secure)" }}>{t("billing.ativa")}</div>
            <div className={styles.loginSub}>{t("billing.liberado")}</div>
          </>)}
          {state === "pending" && (<>
            <div className={styles.loginTitle} style={{ color: "var(--warning)" }}>{t("billing.quaseLa")}</div>
            <div className={styles.loginSub}>{t("billing.aindaConfirmando")}</div>
            <button className={`${styles.btn} ${styles.btnScan}`} style={{ marginTop: 16 }} onClick={() => { window.location.href = "/"; }}>Voltar ao app</button>
          </>)}
        </div>
      </div>
    </div>
  );
}

/** Módulos informativos liberados p/ guest/FREE mesmo com detailsLocked (sincronizar com ScanEntitlementService no backend). */
const FREE_MODULES = ["transport", "tech", "cert"];

export default function App() {
  const { t } = useI18n();
  const { user, loading, logout, isAdmin, isAuthenticated } = useAuth();
  const [view, setView] = useState<View>("scan");
  const [url, setUrl] = useState("github.com");
  const [active, setActive] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [lastScanId, setLastScanId] = useState<string | null>(null);
  const [feedbackTarget, setFeedbackTarget] = useState<FeedbackTarget | null>(null);
  const [theme, setTheme] = useState<"dark" | "light">(
    () => (typeof document !== "undefined" && document.documentElement.getAttribute("data-theme") === "light") ? "light" : "dark"
  );
  const toggleTheme = () => {
    // Efeitos colaterais FORA do updater (StrictMode invoca o updater 2x → cancelaria o flip).
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("cyberaudit.theme", next); } catch { /* ignore */ }
    setTheme(next);
  };
  const [notify, setNotify] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ownership, setOwnership] = useState<OwnershipState | null>(null);
  const [showSlowToast, setShowSlowToast] = useState(false);
  const [guestRefreshKey, setGuestRefreshKey] = useState(0);
  const [openModule, setOpenModule] = useState<string | null>(null);
  const [openModuleInfo, setOpenModuleInfo] = useState<string | null>(null);
  const moduleContentRef = useRef<HTMLDivElement>(null);
  // Abre o módulo e rola a página até o detalhe (não precisa rolar na mão).
  const selectModule = (key: string) => {
    setOpenModule(key);
    // pequeno delay p/ o React renderizar o novo conteúdo antes de rolar
    setTimeout(() => {
      moduleContentRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 60);
  };
  // Volta ao topo (aba Scanner) SEM perder o scan atual — usado no clique da logo.
  const goHome = () => {
    setView("scan");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };
  const abortRef = useRef<AbortController | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const slowTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [showPlans, setShowPlans] = useState(false);

  // Verifica se o sistema já foi configurado (primeiro OWNER criado)
  const [setupConfigured, setSetupConfigured] = useState<boolean | null>(null);
  useEffect(() => {
    api.get<{ configured: boolean }>("/auth/setup-status")
      .then(res => setSetupConfigured(res.data.configured))
      .catch(() => setSetupConfigured(true)); // fail-safe: se API cair, assume configurado
  }, []);

  useEffect(() => { if (user && view === "login") setView("scan"); }, [user]);
  useEffect(() => () => { pollRef.current && clearInterval(pollRef.current); }, []);

  // Limpa resultado ao trocar de conta (login/logout)
  const prevUserIdRef = useRef<string | null | undefined>(undefined);
  useEffect(() => {
    const currentId = user?.id ?? null;
    if (prevUserIdRef.current !== undefined && prevUserIdRef.current !== currentId) {
      setResult(null); setError(null); setOwnership(null); setOpenModule(null);
      stopPoll(); stopSlowTimer();
    }
    prevUserIdRef.current = currentId;
  }, [user]);

  const stopPoll = useCallback(() => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } }, []);

  function stopSlowTimer() {
    setShowSlowToast(false);
    if (slowTimerRef.current) { clearTimeout(slowTimerRef.current); slowTimerRef.current = null; }
  }

  async function handleScan() {
    abortRef.current?.abort(); stopPoll(); stopSlowTimer();
    setResult(null); setError(null); setOwnership(null);
    slowTimerRef.current = setTimeout(() => setShowSlowToast(true), 30000);
    setScanLoading(true);
    await runAsync();
  }

  async function runAsync() {
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const res = await api.post("/scan/async", null, { params: { url, active, refresh: true, notify: notify && canEmailNotify }, signal: controller.signal });
      const scanId = res.data.scanId as string;
      pollRef.current = setInterval(async () => {
        try {
          const status: AsyncStatus = (await api.get(`/scan/async/${scanId}`)).data;
          if (status.state === "DONE") { stopPoll(); stopSlowTimer(); setResult(status.result); setLastScanId(scanId); setOpenModule("issues"); setScanLoading(false); setGuestRefreshKey(k => k + 1); }
          else if (status.state === "ERROR") {
            stopPoll(); stopSlowTimer(); setScanLoading(false);
            const msg = status.errorMessage ?? "";
            const isUnreachable = msg.includes("UnknownHostException") || msg.includes("Name or service not known") || msg.includes("nodename nor servname provided") || msg.includes("No address associated");
            setError(isUnreachable ? `⚠ Domínio não encontrado ou inacessível: "${url}". Verifique o endereço e tente novamente.` : `Erro ao processar scan: ${msg}`);
          }
        } catch { stopPoll(); stopSlowTimer(); setError(t("scan.falhaStatus")); setScanLoading(false); }
      }, 2000);
    } catch (err: any) { stopSlowTimer(); handleError(err); setScanLoading(false); }
  }

  function handleError(err: any) {
    const aborted = err?.name === "CanceledError" || err?.code === "ERR_CANCELED";
    if (aborted) { setError(t("scan.cancelado")); return; }
    if (err?.response?.status === 401) { setError(t("scan.requerAuth")); setView("login"); return; }
    const data = err?.response?.data;
    const isOwnership = err?.response?.status === 403 && (data?.error === "OWNERSHIP_REQUIRED" || data?.message?.includes("proprietário verificado") || data?.message?.includes("OWNERSHIP"));
    if (isOwnership) {
      const host = url.replace(/^https?:\/\//, "").split("/")[0];
      const tokenMatch = data?.message?.match(/cyberaudit-verify=[^\s"]+/);
      setOwnership({ message: data?.message ?? "", host, token: tokenMatch?.[0] ?? null, passiveResult: data?.passiveResult ?? null });
      return;
    }
    const message = data?.message ?? err?.message ?? "";
    const isUnreachable = message.toLowerCase().includes("connect timed out") || message.toLowerCase().includes("connection refused") || message.toLowerCase().includes("unknown host") || message.toLowerCase().includes("name or service not known") || message.toLowerCase().includes("no route to host") || message.toLowerCase().includes("network is unreachable") || err?.response?.status === 400;
    if (isUnreachable) { setError(`⚠ Domínio não encontrado ou inacessível: "${url}". Verifique se o endereço está correto e tente novamente.`); return; }
    setError(err?.response ? `Erro ${err.response.status}: ${JSON.stringify(err.response.data)}` : `Falha: ${err.message}`);
  }

  async function handlePdf() {
    setPdfLoading(true);
    const ts = new Date().toISOString().slice(0, 10);
    const filename = `cyberaudit-${url.replace(/[^a-z0-9]/gi, "-")}-${ts}.pdf`;
    try {
      let res;
      if (lastScanId) {
        // Fast path: use the result already in memory — no re-scan
        res = await api.get(`/scan/report/pdf/${lastScanId}`, { responseType: "blob" });
      } else {
        // Fallback: full re-scan (used when page is refreshed or result not in memory)
        res = await api.get("/scan/report/pdf", { params: { url, active }, responseType: "blob" });
      }
      downloadBlob(new Blob([res.data], { type: "application/pdf" }), filename);
    } catch (e: any) {
      if (e?.response?.data instanceof Blob) {
        const text = await e.response.data.text();
        try { const json = JSON.parse(text); setError(`PDF erro: ${json.message ?? json.error ?? text}`); }
        catch { setError(`PDF erro: ${text || t("scan.erroDesconhecido")}`); }
      } else { setError(`PDF erro: ${e?.response?.status} — ${e.message}`); }
    } finally { setPdfLoading(false); }
  }

  const inviteToken = getInviteTokenFromUrl();
  if (inviteToken) return <div className={styles.app}><LanguagePicker flutuante /><AcceptInvitePage token={inviteToken} /></div>;

  const statusToken = getStatusTokenFromUrl();
  if (statusToken) return (<><LanguagePicker flutuante /><PublicStatusPage token={statusToken} /></>);

  // Antes de qualquer checagem de sessão: quem chega por este link está
  // justamente sem conseguir entrar.
  const resetToken = getResetTokenFromUrl();
  if (resetToken) return (<><LanguagePicker flutuante /><RedefinirSenha token={resetToken} /></>);

  if (isBillingReturnPath()) return <BillingReturnPage />;

  // Aguarda tanto a verificação de setup quanto a validação de auth
  if (setupConfigured === null || loading)
    return (<div className={styles.app}><div className={styles.loadingScreen}><span className={styles.logoIcon}>◈</span> {t("app.carregando")}</div></div>);

  // Wizard de configuração inicial (apenas quando não há usuários no sistema)
  if (!setupConfigured)
    return <div className={styles.app}><LanguagePicker flutuante /><SetupPage /></div>;

  if (view === "login") return <div className={styles.app}><LanguagePicker flutuante /><LoginPage onBack={() => setView("scan")} /></div>;

  const r = result;
  const risk = r?.score?.riskLevel;
  const tf = r?.techFingerprint;
  const badgeHost = (r?.finalUrl ?? r?.url ?? "").replace(/^https?:\/\//, "").split("/")[0];
  // Módulo bloqueado p/ este plano (guest/FREE): não é Issues nem um módulo liberado.
  const modGated = (key: string) => !!r?.detailsLocked && key !== "issues" && !FREE_MODULES.includes(key);
  const badgeUrl = `${import.meta.env.VITE_API_URL ?? "http://localhost:8081"}/badge/${badgeHost}?score=${r?.score?.score ?? 0}&risk=${r?.score?.riskLevel ?? "UNKNOWN"}`;

  // ── Module card computed values ──────────────────────────────────────────
  const headerEntries = Object.entries(r?.headers ?? {});
  const missingH      = headerEntries.filter(([, v]) => v.startsWith("MISSING")).length;
  const weakH         = headerEntries.filter(([, v]) => v.startsWith("WEAK")).length;
  const headerColor   = missingH === 0 && weakH === 0 ? "var(--secure)"
    : missingH > 2 ? "var(--critical)" : missingH > 0 ? "var(--warning)" : "var(--info)";
  const issueCount    = r?.score?.issues?.length ?? 0;
  const issueColor    = issueCount === 0 ? "var(--secure)" : worstVar(r?.score?.issues ?? []);
  const cookieCount   = r?.cookieIssues?.length ?? 0;
  const cookieColor   = cookieCount === 0 ? "var(--secure)"
    : (r?.cookieIssues ?? []).some(c => c.risk?.toUpperCase() === "HIGH") ? "var(--high)"
    : (r?.cookieIssues ?? []).some(c => c.risk?.toUpperCase() === "MEDIUM") ? "var(--warning)" : "var(--info)";
  const dangerMethods = r?.dangerousHttpMethods?.filter(m => m.enabled) ?? [];
  const httpColor     = dangerMethods.length === 0 ? "var(--secure)" : "var(--warning)";
  const redirectVuln  = r?.openRedirectFindings?.filter(f => f.vulnerable) ?? [];
  const redirectColor = redirectVuln.length > 0 ? "var(--critical)" : "var(--secure)";
  const dirExposed    = r?.directoryListingFindings?.filter(f => f.listingEnabled) ?? [];
  const dirColor      = dirExposed.length > 0 ? "var(--warning)" : "var(--secure)";
  const cveCount      = r?.cveFindings?.length ?? 0;
  const maxCvss       = cveCount > 0 ? Math.max(...(r?.cveFindings ?? []).map(c => c.cvssScore)) : 0;
  const cveColor      = cveCount === 0 ? "var(--secure)" : maxCvss >= 9 ? "var(--critical)" : maxCvss >= 7 ? "var(--high)" : maxCvss >= 4 ? "var(--warning)" : "var(--info)";
  const ct            = r?.certTransparency;
  const certColor     = !ct ? "var(--text-muted)" : ct.unexpectedIssuer ? "var(--critical)" : ct.wildcardDetected ? "var(--warning)" : "var(--info)";
  const takeoverVuln  = r?.subdomainTakeover?.filter(tk => tk.status === "VULNERABLE") ?? [];
  const takeoverColor = takeoverVuln.length > 0 ? "var(--critical)" : (r?.subdomainTakeover?.length ?? 0) > 0 ? "var(--warning)" : "var(--secure)";
  const dns           = r?.dnsSecurityResult;
  // Consulta que não chegou não conta como registro faltando: contar mostraria
  // "0/3" em vermelho para um domínio que pode estar perfeitamente configurado.
  const reconIndisponivel = dns?.lookupFailed === true;
  const reconProbs    = (dns && !reconIndisponivel)
    ? [!dns.spfPresent, !dns.dmarcPresent, !dns.caaPresent].filter(Boolean).length : 0;
  const reconColor    = reconIndisponivel ? "var(--warning)"
    : reconProbs >= 2 ? "var(--critical)" : reconProbs >= 1 ? "var(--warning)" : "var(--secure)";
  const changeCount   = r?.changes?.length ?? 0;
  const changesColor  = (r?.changes ?? []).some(c => c.changeType === "DEGRADED") ? "var(--critical)" : changeCount > 0 ? "var(--warning)" : "var(--secure)";
  // Permissões de plano (equipe da plataforma já recebe tudo pelo backend; guest = sem user)
  const canChanges              = user?.account?.changesModuleAllowed    === true;
  const canHistory              = user?.account?.historyChartAllowed     === true;
  const canActiveScan           = user?.account?.activeScanAllowed       === true;
  const canDomains              = user?.account?.domainRegistrationAllowed === true;
  // -1 = ilimitado; 0 = plano não agenda
  const canSchedules            = (user?.account?.scheduledScanLimit ?? 0) !== 0;
  const activeScanVerifiedOnly  = user?.account?.activeScanOnVerifiedOnly === true;
  // Entrega de laudo: paga, e no Pro pessoal só sobre domínio verificado. A tela
  // não sabe quais domínios são verificados, então avisa da regra — quem recusa
  // de fato é o PlanLimitService.
  const canPdf                  = user?.account?.pdfExportAllowed        === true;
  const canEmailNotify          = user?.account?.emailNotifyAllowed      === true;
  const reportVerifiedOnly      = user?.account?.reportOnVerifiedOnly    === true;
  // Compliance: EMPRESA (qualquer plano) + PRO PESSOAL (incentivo de upsell) + OWNER/ADMIN
  const canCompliance = isAdmin()
      || user?.account?.type === "COMPANY"
      || user?.account?.plan === "PRO"
      || user?.account?.plan === "ENTERPRISE";
  // Gestão de usuários: exclusivo para contas COMPANY com role OWNER ou ADMIN
  // Painel Admin visível para qualquer OWNER/ADMIN (audit logs disponíveis independente do tipo de conta)
  const canViewAdmin = isAdmin();
  const techFirst     = tf?.webServer ?? tf?.framework ?? tf?.cms ?? tf?.language ?? "—";
  const apiDocsCount   = r?.apiDocsExposure?.length ?? 0;
  const apiDocsColor   = apiDocsCount === 0 ? "var(--secure)" : (r?.apiDocsExposure ?? []).some(f => f.severity === "HIGH") ? "var(--high)" : "var(--warning)";
  const gqlFindings    = r?.graphQlIntrospection ?? [];
  const gqlColor       = gqlFindings.length === 0 ? "var(--secure)" : gqlFindings.some(f => f.severity === "HIGH") ? "var(--high)" : "var(--warning)";
  const jwtFindings    = r?.jwtSecurity ?? [];
  const jwtColor       = jwtFindings.length === 0 ? "var(--secure)" : jwtFindings.some(f => f.severity === "CRITICAL") ? "var(--critical)" : jwtFindings.some(f => f.severity === "HIGH") ? "var(--high)" : "var(--warning)";
  const ptFindings     = r?.pathTraversal ?? [];
  const ptColor        = ptFindings.length === 0 ? "var(--secure)" : "var(--critical)";
  const ssrfFindings   = r?.ssrfFindings ?? [];
  const ssrfColor      = ssrfFindings.length === 0 ? "var(--secure)" : "var(--critical)";
  const hhFindings     = r?.hostHeaderFindings ?? [];
  const hhColor        = hhFindings.length === 0 ? "var(--secure)" : "var(--high)";
  const smFindings     = r?.sourceMapFindings ?? [];
  const smColor        = smFindings.length === 0 ? "var(--secure)" : smFindings.some(f => f.severity === "HIGH") ? "var(--high)" : "var(--warning)";
  const crlfFindings   = r?.crlfFindings ?? [];
  const crlfColor      = crlfFindings.length === 0 ? "var(--secure)" : "var(--high)";
  const tlsColor       = !(r?.sslInfo?.valid) ? "var(--critical)" : r?.tlsDetails?.weakProtocol ? "var(--warning)" : "var(--secure)";

  // Painel de busca — reusado no início (standalone) e no topo da coluna de resultados.
  const searchPanel = (
    <div className={styles.scanPanel}>
      <div className={styles.scanForm}>
        <div className={styles.inputWrap}>
          <span className={styles.inputPrefix}>https://</span>
          <input className={styles.urlInput} value={url} onChange={e => setUrl(e.target.value)} placeholder={t("scan.placeholder")} onKeyDown={e => e.key === "Enter" && !scanLoading && handleScan()} />
        </div>
        <div className={styles.toggles}>
          <label className={styles.toggle} title={
            user && !canActiveScan
              ? t("scan.activeRequerPro")
              : activeScanVerifiedOnly
              ? t("scan.activeSoVerificados")
              : t("scan.activeDescricao")
          }>
            <input type="checkbox" checked={active}
              disabled={scanLoading || (!!user && !canActiveScan)}
              onChange={e => setActive(e.target.checked)} />
            <span className={`${styles.toggleLabel} ${user && !canActiveScan ? styles.disabledLabel : ""}`}>
              ACTIVE{user && !canActiveScan ? " ⛔" : ""}
            </span>
          </label>
          {user && (
            <label className={styles.toggle} title={
              !canEmailNotify
                ? t("scan.emailRequerPro")
                : reportVerifiedOnly
                ? t("scan.emailSoVerificados")
                : t("scan.emailDescricao")
            }>
              <input type="checkbox" checked={notify && canEmailNotify}
                disabled={scanLoading || !canEmailNotify}
                onChange={e => setNotify(e.target.checked)} />
              <span className={`${styles.toggleLabel} ${!canEmailNotify ? styles.disabledLabel : ""}`}>
                EMAIL{!canEmailNotify ? " ⛔" : ""}
              </span>
            </label>
          )}
        </div>
        {activeScanVerifiedOnly && active && (
          <div style={{ fontSize: 10, color: "var(--warning)", fontFamily: "var(--mono)", marginTop: 4, letterSpacing: ".3px" }}>
            {fraseComLinks(t("scan.avisoActiveVerificado"), [<strong>{t("nav.dominios")}</strong>])}
          </div>
        )}
        {/* Só aparece quando a entrega é possível: e-mail marcado, ou já há
            resultado na tela para exportar em PDF. */}
        {reportVerifiedOnly && (notify || !!r) && (
          <div style={{ fontSize: 10, color: "var(--warning)", fontFamily: "var(--mono)", marginTop: 4, letterSpacing: ".3px" }}>
            {fraseComLinks(t("scan.avisoEntregaVerificada"), [<strong>{t("nav.dominios")}</strong>])}
          </div>
        )}
        <div className={styles.actions}>
          {scanLoading
            ? <button className={`${styles.btn} ${styles.btnCancel}`} onClick={() => { abortRef.current?.abort(); stopPoll(); stopSlowTimer(); setScanLoading(false); }}>{t("scan.cancelar")}</button>
            : <button className={`${styles.btn} ${styles.btnScan}`} onClick={handleScan}>{t("scan.botao")}</button>}
          <button
            className={`${styles.btn} ${styles.btnGhost}`}
            onClick={handlePdf}
            disabled={pdfLoading || scanLoading || (!!user && !canPdf)}
            title={
              user && !canPdf
                ? t("scan.pdfRequerPro")
                : reportVerifiedOnly
                ? t("scan.pdfSoVerificados")
                : ""
            }
          >{pdfLoading ? "..." : t("scan.pdf")}</button>
        </div>
      </div>
      {active && <div className={styles.activeWarning}>{t("scan.avisoModoAtivo")}</div>}
      {scanLoading && <div className={styles.progressBar}><div className={styles.progressFill} /></div>}
      {error && <div className={styles.errorBox}>{error}</div>}
    </div>
  );

  return (
    <div className={styles.app}>
      <SlowScanToast visible={showSlowToast} />
      {showPlans && <PlansModal onClose={() => setShowPlans(false)} />}
      {feedbackTarget && <FeedbackModal target={feedbackTarget} onClose={() => setFeedbackTarget(null)} />}

      <header className={styles.header}>
        <div className={styles.logo} onClick={goHome} title={t("nav.voltarInicio")} role="button" style={{ cursor: "pointer" }}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div>
        <nav className={styles.headerNav}>
          <button className={`${styles.navBtn} ${view === "scan" ? styles.navBtnActive : ""}`} onClick={() => setView("scan")}>{t("nav.scanner")}</button>
          {canViewAdmin && (<button className={`${styles.navBtn} ${view === "admin" ? styles.navBtnActive : ""}`} onClick={() => setView("admin")}>{t("nav.admin")}</button>)}
          {isAuthenticated() && (<button className={`${styles.navBtn} ${view === "schedules" ? styles.navBtnActive : ""}`} onClick={() => setView("schedules")}>{t("nav.agendamentos")}</button>)}
          {isAuthenticated() && (<button className={`${styles.navBtn} ${view === "domains" ? styles.navBtnActive : ""}`} onClick={() => setView("domains")}>{t("nav.dominios")}</button>)}
          {isAuthenticated() && (<button className={`${styles.navBtn} ${view === "changes" ? styles.navBtnActive : ""}`} onClick={() => setView("changes")}>{t("nav.historico")}</button>)}
          {isAuthenticated() && (<button className={`${styles.navBtn} ${view === "settings" ? styles.navBtnActive : ""}`} onClick={() => setView("settings")}>{t("nav.seguranca")}</button>)}
        </nav>
        <div className={styles.headerRight}>
          <LanguagePicker />
          <button
            className={styles.themeToggle}
            onClick={toggleTheme}
            title={theme === "dark" ? t("nav.temaClaro") : t("nav.temaEscuro")}
            aria-label={t("nav.alternarTema")}
          >
            {theme === "dark" ? "☀" : "☾"}
          </button>
          {isAuthenticated() ? (
            <div className={styles.userInfo}>
              {user?.account?.plan && (
                <button
                  className={`${styles.tag} ${styles.planBadgeBtn} ${
                    user.account.plan === "ENTERPRISE" ? styles.secure :
                    user.account.plan === "PRO"        ? styles.info   : styles.tagFree
                  }`}
                  onClick={() => setShowPlans(true)}
                  title={t("nav.verPlanos")}
                >
                  {user.account.plan}
                </button>
              )}
              {user?.dailyLimit != null && user?.remainingScans != null && (
                <span className={styles.scanQuota} title={t("nav.scansRestantes")}>
                  {user.remainingScans}/{user.dailyLimit}
                </span>
              )}
              <span className={`${styles.tag} ${user?.role === "OWNER" ? styles.secure : styles.info}`}>{user?.role}</span>
              <span className={styles.userName}>{user?.name}</span>
              <button className={`${styles.btn} ${styles.btnGhost}`} onClick={logout}>{t("nav.sair")}</button>
            </div>
          ) : (
            <button className={`${styles.btn} ${styles.btnScan}`} onClick={() => setView("login")}>Login</button>
          )}
        </div>
      </header>

      <main className={styles.main}>
        {!isAuthenticated() && view === "scan" && <GuestBanner onLogin={() => setView("login")} refreshKey={guestRefreshKey} />}
        {isAuthenticated() && view === "scan" && <AvisoRespostasFeedback />}
        {view === "admin" && canViewAdmin && <AdminPanel onUpgrade={() => setShowPlans(true)} />}
        {view === "schedules" && isAuthenticated() && (canSchedules
          ? <SchedulesPage />
          : <PagePlanLocked
              titulo={t("trava.agendamentos")}
              descricao={t("trava.agendamentosDesc")}
              onUpgrade={() => setShowPlans(true)} />)}
        {view === "domains" && isAuthenticated() && (canDomains
          ? <DomainsPage />
          : <PagePlanLocked
              titulo={t("trava.dominios")}
              descricao={t("trava.dominiosDesc")}
              onUpgrade={() => setShowPlans(true)} />)}
        {view === "changes" && isAuthenticated() && (canChanges
          ? <ChangesPage />
          : <PagePlanLocked
              titulo={t("trava.historico")}
              descricao={t("trava.historicoDesc")}
              onUpgrade={() => setShowPlans(true)} />)}
        {view === "settings" && isAuthenticated() && <SettingsPage />}

        {view === "scan" && (
          <>
            {(!r || scanLoading) && searchPanel}

            {ownership && <OwnershipCard state={ownership} onDismiss={() => setOwnership(null)} />}

            {r && !scanLoading && (
              <div key={`${r.url}-${r.activeMode}-${r.score?.score}`} className={styles.dashboard}>

                {/* ── Left Nav ── */}
                  <nav className={styles.sidebarNav}>
                    <div className={styles.sidebarTarget}>
                      <div
                        className={styles.sidebarTargetScore}
                        style={{ color: risk === "SECURE" ? "var(--secure)" : risk === "LOW" ? "var(--info)" : risk === "MEDIUM" ? "var(--warning)" : risk === "HIGH" ? "var(--high)" : "var(--critical)" }}
                      >
                        {r.score?.score}<span className={styles.sidebarTargetScoreMax}>/100</span>
                      </div>
                      <div className={styles.sidebarTargetMeta}>
                        <div className={`${styles.sidebarTargetRisk} ${riskColor(risk)}`}>{risk}</div>
                        <div className={styles.sidebarTargetUrl}>{badgeHost}</div>
                      </div>
                    </div>
                    <div className={styles.sidebarNavGroup}>{t("grupo.visaoGeral")}</div>
                    <SidebarNavItem icon="⚠" title="Issues"
                      color={issueColor}
                      metric={issueCount === 0 ? "✓" : issueCount}
                      label={issueCount === 0 ? "SECURE" : (r.score?.issues?.[0]?.severity ?? "FOUND")}
                      active={openModule === "issues"}
                      onClick={() => selectModule("issues")}/>

                    <div className={styles.sidebarNavGroup}>{t("grupo.httpHeaders")}</div>
                    <SidebarNavItem icon="⬡" title="Security Headers"
                      color={headerColor}
                      metric={missingH + weakH === 0 ? "✓" : missingH + weakH}
                      label={missingH + weakH === 0 ? "SECURE" : missingH > 2 ? "CRITICAL" : "MEDIUM"}
                      active={openModule === "headers"}
                      locked={modGated("headers")}
                      onClick={() => selectModule("headers")}/>
                    <SidebarNavItem icon="⬟" title="Transport Security"
                      color={tlsColor}
                      metric={r.sslInfo?.valid ? (r.sslInfo.daysRemaining ?? "?") + "d" : "✗"}
                      label={!r.sslInfo?.valid ? t("selo.certInvalido") : r.tlsDetails?.weakProtocol ? t("selo.protocoloFraco") : "SECURE"}
                      active={openModule === "transport"}
                      onClick={() => selectModule("transport")}/>
                    <SidebarNavItem icon="⚙" title="HTTP Methods"
                      color={httpColor}
                      metric={dangerMethods.length === 0 ? "✓" : dangerMethods.length}
                      label={dangerMethods.length === 0 ? "SECURE" : "DANGEROUS"}
                      active={openModule === "http"}
                      locked={modGated("http")}
                      onClick={() => selectModule("http")}/>
                    <SidebarNavItem icon="↪" title="Open Redirect"
                      color={redirectColor}
                      metric={redirectVuln.length === 0 ? "✓" : redirectVuln.length}
                      label={redirectVuln.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "redirect"}
                      locked={modGated("redirect")}
                      onClick={() => selectModule("redirect")}/>
                    <SidebarNavItem icon="◫" title="Directory Listing"
                      color={dirColor}
                      metric={dirExposed.length === 0 ? "✓" : dirExposed.length}
                      label={dirExposed.length === 0 ? "SECURE" : "EXPOSED"}
                      active={openModule === "dirlist"}
                      locked={modGated("dirlist")}
                      onClick={() => selectModule("dirlist")}/>

                    <div className={styles.sidebarNavGroup}>{t("grupo.dns")}</div>
                    <SidebarNavItem icon="◉" title="Reconnaissance"
                      color={reconColor}
                      metric={reconIndisponivel ? "—"
                        : dns ? `${[dns.spfPresent, dns.dmarcPresent, dns.caaPresent].filter(Boolean).length}/3` : "—"}
                      label={reconIndisponivel ? t("selo.naoVerificado")
                        : dns?.emailSpoofingRisk ? `SPOOFING: ${dns.emailSpoofingRisk}` : "UNKNOWN"}
                      active={openModule === "recon"}
                      locked={modGated("recon")}
                      onClick={() => selectModule("recon")}/>
                    <SidebarNavItem icon="◑" title="Cert Transparency"
                      color={certColor}
                      metric={ct ? ct.totalCertificates : "—"}
                      label={!ct ? "N/A" : ct.unexpectedIssuer ? t("selo.issuerAlerta") : ct.wildcardDetected ? "WILDCARD" : "INFO"}
                      active={openModule === "cert"}
                      onClick={() => selectModule("cert")}/>
                    <SidebarNavItem icon="◎" title="Subdomain Takeover"
                      color={takeoverColor}
                      metric={takeoverVuln.length === 0 ? "✓" : takeoverVuln.length}
                      label={takeoverVuln.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "takeover"}
                      locked={modGated("takeover")}
                      onClick={() => selectModule("takeover")}/>

                    <div className={styles.sidebarNavGroup}>{t("grupo.aplicacao")}</div>
                    <SidebarNavItem icon="⟨⟩" title="Technology"
                      color="var(--info)"
                      metric={techFirst}
                      label="DETECTED"
                      active={openModule === "tech"}
                      onClick={() => selectModule("tech")}/>
                    <SidebarNavItem icon="☰" title="Cookie Security"
                      color={cookieColor}
                      metric={cookieCount === 0 ? "✓" : cookieCount}
                      label={cookieCount === 0 ? "SECURE" : t("selo.issuesEncontradas")}
                      active={openModule === "cookies"}
                      locked={modGated("cookies")}
                      onClick={() => selectModule("cookies")}/>
                    <SidebarNavItem icon="◈" title="API Docs"
                      color={apiDocsColor}
                      metric={apiDocsCount === 0 ? "✓" : apiDocsCount}
                      label={apiDocsCount === 0 ? "SECURE" : "EXPOSED"}
                      active={openModule === "apidocs"}
                      locked={modGated("apidocs")}
                      onClick={() => selectModule("apidocs")}/>
                    <SidebarNavItem icon="◈" title="GraphQL"
                      color={gqlColor}
                      metric={gqlFindings.length === 0 ? "✓" : gqlFindings.length}
                      label={gqlFindings.length === 0 ? "SECURE" : gqlFindings.some(f => f.playgroundExposed) ? "PLAYGROUND" : "INTROSPECTION"}
                      active={openModule === "graphql"}
                      locked={modGated("graphql")}
                      onClick={() => selectModule("graphql")}/>
                    <SidebarNavItem icon="◈" title="JWT Security"
                      color={jwtColor}
                      metric={jwtFindings.length === 0 ? "✓" : jwtFindings.length}
                      label={jwtFindings.length === 0 ? "SECURE" : jwtFindings.some(f => f.severity === "CRITICAL") ? "CRITICAL" : t("selo.issuesEncontradas")}
                      active={openModule === "jwt"}
                      locked={modGated("jwt")}
                      onClick={() => selectModule("jwt")}/>
                    <SidebarNavItem icon="◈" title="Path Traversal"
                      color={ptColor}
                      metric={ptFindings.length === 0 ? "✓" : ptFindings.length}
                      label={ptFindings.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "traversal"}
                      locked={modGated("traversal")}
                      onClick={() => selectModule("traversal")}/>
                    <SidebarNavItem icon="◈" title="SSRF"
                      color={ssrfColor}
                      metric={ssrfFindings.length === 0 ? "✓" : ssrfFindings.length}
                      label={ssrfFindings.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "ssrf"}
                      locked={modGated("ssrf")}
                      onClick={() => selectModule("ssrf")}/>
                    <SidebarNavItem icon="◈" title="CRLF Injection"
                      color={crlfColor}
                      metric={crlfFindings.length === 0 ? "✓" : crlfFindings.length}
                      label={crlfFindings.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "crlf"}
                      locked={modGated("crlf")}
                      onClick={() => selectModule("crlf")}/>
                    <SidebarNavItem icon="◈" title="Source Map/Debug"
                      color={smColor}
                      metric={smFindings.length === 0 ? "✓" : smFindings.length}
                      label={smFindings.length === 0 ? "SECURE" : smFindings.some(f => f.severity === "HIGH") ? "HIGH" : "MEDIUM"}
                      active={openModule === "sourcemap"}
                      locked={modGated("sourcemap")}
                      onClick={() => selectModule("sourcemap")}/>
                    <SidebarNavItem icon="◈" title="Host Header"
                      color={hhColor}
                      metric={hhFindings.length === 0 ? "✓" : hhFindings.length}
                      label={hhFindings.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "hostheader"}
                      locked={modGated("hostheader")}
                      onClick={() => selectModule("hostheader")}/>
                    <SidebarNavItem icon="◈" title="CVE Correlation"
                      color={cveColor}
                      metric={cveCount === 0 ? "✓" : cveCount}
                      label={cveCount === 0 ? "SECURE" : maxCvss >= 9 ? "CRITICAL" : maxCvss >= 7 ? "HIGH" : maxCvss >= 4 ? "MEDIUM" : "LOW"}
                      active={openModule === "cve"}
                      locked={modGated("cve")}
                      onClick={() => selectModule("cve")}/>

                    {/* ── Compliance ── */}
                    {canCompliance && r.compliance && (<>
                      <div className={styles.sidebarNavGroup}>{t("grupo.compliance")}</div>
                      <SidebarNavItem icon="⊕" title="LGPD / ISO 27001"
                        color={
                          r.compliance.riskLevel === "COMPLIANT" ? "var(--secure)" :
                          r.compliance.riskLevel === "LOW"       ? "var(--info)"   :
                          r.compliance.riskLevel === "MEDIUM"    ? "var(--warning)":
                          "var(--critical)"
                        }
                        metric={`${r.compliance.overallScore}%`}
                        label={r.compliance.riskLevel}
                        active={openModule === "compliance"}
                        locked={modGated("compliance")}
                        onClick={() => selectModule("compliance")}/>
                    </>)}

                    {changeCount > 0 && canChanges && (<>
                      <div className={styles.sidebarNavGroup}>{t("grupo.monitoramento")}</div>
                      <SidebarNavItem icon="△" title="Changes"
                        color={changesColor}
                        metric={changeCount}
                        label={changesColor === "var(--critical)" ? "DEGRADED" : "CHANGED"}
                        active={openModule === "changes"}
                        locked={modGated("changes")}
                        onClick={() => selectModule("changes")}/>
                    </>)}

                    <div className={styles.sidebarNavGroup}>{t("grupo.active")}</div>
                    <SidebarNavItem icon="▣" title="Active Checks"
                      color={r.activeMode ? "var(--info)" : "var(--accent)"}
                      metric={!r.activeMode ? "🔒" : r.wafDetectionResult?.detected ? "WAF" : `${r.openPorts?.length ?? 0}p`}
                      label={!r.activeMode ? "PASSIVE" : r.wafDetectionResult?.detected ? t("selo.wafDetectado") : "ACTIVE"}
                      active={openModule === "active"}
                      locked={modGated("active")}
                      onClick={() => selectModule("active")}/>

                  </nav>

                  <ModuleInfoModal moduleKey={openModuleInfo} onClose={() => setOpenModuleInfo(null)} />

                  {/* ── Right: Overview + Content ── */}
                  <div className={styles.dashboardRight}>

                    <div className={styles.scanPanelInline}>{searchPanel}</div>

                    <div className={styles.row}>
                      <Card>
                        <div className={styles.overviewCard}>
                          <ScoreGauge score={r.score?.score ?? 0} risk={risk ?? "CRITICAL"} />
                          <div className={styles.overviewMeta}>
                            <div className={`${styles.riskBadge} ${riskColor(risk)}`}>{risk}</div>
                            <KV label="URL"            value={r.finalUrl ?? r.url} />
                            <KV label="HTTP"           value={r.httpStatus} />
                            <KV label="HTTPS REDIRECT" value={boolIcon(r.redirectsToHttps)} />
                            <KV label="ACTIVE MODE"    value={boolIcon(r.activeMode)} />
                            <KV label="SERVER EXPOSED" value={boolIcon(!r.serverVersionExposed, t("selo.limpo"), t("selo.exposto"))} />
                            <div className={styles.badgePreview}>
                              <img src={badgeUrl} alt="security badge" className={styles.badgeImg} />
                            </div>
                          </div>
                        </div>
                      </Card>
                      <Card title={t("resultado.breakdown")}>
                        {r.detailsLocked ? <LockedGhost onUpgrade={() => setShowPlans(true)} /> : (
                        <div className={styles.notesList}>
                          {(r.score?.notes ?? []).map((n, i) => (
                            <div key={i} className={`${styles.noteRow} ${n.includes("-") ? styles.noteMinus : styles.noteOk}`}>
                              <span>{n.includes("-") ? "▼" : "◈"}</span>{n}
                            </div>
                          ))}
                        </div>
                        )}
                      </Card>
                      <Card title={t("resultado.distribuicao")}>
                        <div className={styles.sevDist}>
                          {(["CRITICAL","HIGH","MEDIUM","LOW"] as const).map(sev => {
                            const count = (r.score?.issues ?? []).filter(i => (i.severity ?? "").toUpperCase() === sev).length;
                            const total = r.score?.issues?.length ?? 0;
                            const pct   = total > 0 ? Math.round((count / total) * 100) : 0;
                            const color = sev === "CRITICAL" ? "var(--critical)" : sev === "HIGH" ? "var(--high)" : sev === "MEDIUM" ? "var(--warning)" : "var(--low)";
                            return (
                              <div key={sev} className={styles.sevDistRow}>
                                <span className={styles.sevDistLabel} style={{ color }}>{sev}</span>
                                <div className={styles.sevDistBar}>
                                  <div className={styles.sevDistFill} style={{ width: `${pct}%`, background: color }} />
                                </div>
                                <span className={styles.sevDistCount} style={{ color: count > 0 ? color : "var(--text-muted)" }}>{count}</span>
                              </div>
                            );
                          })}
                          <div className={styles.sevDistTotal}>
                            <span>{t("resultado.issuesTotais", r.score?.issues?.length ?? 0)}</span>
                            <span>{t("resultado.issuesGraves", (r.score?.issues ?? []).filter(i => ["CRITICAL","HIGH"].includes((i.severity ?? "").toUpperCase())).length)}</span>
                          </div>
                        </div>
                      </Card>
                    </div>

                    {badgeHost && canHistory && <ScoreHistoryChart host={badgeHost} />}

                    <div className={styles.sidebarContent} ref={moduleContentRef}>

                    {!openModule && (
                      <div className={styles.sidebarEmpty}>{t("resultado.selecioneModulo")}</div>
                    )}

                    {openModule === "issues" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": issueColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>⚠</span>
                          <span className={styles.sidebarContentTitleText}>Issues</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("issues")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                          {isAuthenticated() && (
                            <button className={styles.moduleInfoTrigger} onClick={() => setFeedbackTarget({ host: badgeHost, scanId: lastScanId, module: null, findingLabel: null })} title={t("resultado.contestarTitulo")}>{t("resultado.contestar")}</button>
                          )}
                        </div>
                        {issueCount
                          ? <div className={styles.issuesList}>{r.score.issues.map((i, idx) => <IssueItem key={`${i.id}-${idx}`} issue={i} locked={r.detailsLocked} onUpgrade={() => setShowPlans(true)} onContest={isAuthenticated() ? (label) => setFeedbackTarget({ host: badgeHost, scanId: lastScanId, module: null, findingLabel: label }) : undefined} />)}</div>
                          : <div className={styles.empty}>{t("resultado.semIssues")}</div>}
                      </>
                    )}

                    {r.detailsLocked && openModule && openModule !== "issues" && !FREE_MODULES.includes(openModule) ? (
                      <ModuleLocked onUpgrade={() => setShowPlans(true)} />
                    ) : (
                    <>
                    {openModule === "headers" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": headerColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>⬡</span>
                          <span className={styles.sidebarContentTitleText}>Security Headers</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("headers")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <HeaderCardsPanel headers={r.headers ?? {}} host={r.analyzedHost ?? (r.finalUrl ?? r.url ?? "").replace(/^https?:\/\//, "").split("/")[0]} related={r.relatedHostHeaders} />
                      </>
                    )}

                    {openModule === "transport" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": tlsColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>⬟</span>
                          <span className={styles.sidebarContentTitleText}>Transport Security</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("transport")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <TransportCardsPanel r={r} />
                      </>
                    )}

                    {openModule === "tech" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": "var(--info)" } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>⟨⟩</span>
                          <span className={styles.sidebarContentTitleText}>Technology Fingerprint</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("tech")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <TechCardsPanel tf={tf} />
                      </>
                    )}

                    {openModule === "compliance" && canCompliance && r.compliance && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color":
                          r.compliance.riskLevel === "COMPLIANT" ? "var(--secure)" :
                          r.compliance.riskLevel === "LOW"       ? "var(--info)" :
                          r.compliance.riskLevel === "MEDIUM"    ? "var(--warning)" : "var(--critical)"
                        } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>⊕</span>
                          <span className={styles.sidebarContentTitleText}>LGPD / ISO 27001:2022</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("compliance")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <CompliancePanel compliance={r.compliance} />
                      </>
                    )}

                    {openModule === "changes" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": changesColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>△</span>
                          <span className={styles.sidebarContentTitleText}>Changes Since Last Scan</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("changes")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <div className={styles.changesList}>
                          {(r.changes ?? []).map((c, i) => (
                            <div key={i} className={`${styles.changeRow} ${styles["change" + c.changeType]}`}>
                              <div className={styles.changeHeader}>
                                <span className={`${styles.changeType} ${styles["ct" + c.changeType]}`}>{c.changeType}</span>
                                <Tag label={c.severity} cls={sevColor(c.severity)} />
                                <span className={styles.changeCategory}>{c.category}</span>
                                <span className={styles.changeField}>{c.field}</span>
                              </div>
                              <div className={styles.changeDesc}>{c.description}</div>
                              {c.oldValue && c.newValue && (
                                <div className={styles.changeDiff}>
                                  <span className={styles.changeDiffOld}>{c.oldValue}</span>
                                  <span className={styles.changeDiffArrow}>→</span>
                                  <span className={styles.changeDiffNew}>{c.newValue}</span>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </>
                    )}

                    {openModule === "cookies" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": cookieColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>☰</span>
                          <span className={styles.sidebarContentTitleText}>Cookie Security</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("cookies")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <CookieCardsPanel cookies={r.cookieIssues ?? []} />
                      </>
                    )}

                    {openModule === "http" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": httpColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>⚙</span>
                          <span className={styles.sidebarContentTitleText}>HTTP Methods</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("http")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <FindingCardsPanel
                          emptyMsg={t("vazio.httpMethods")}
                          items={(r.dangerousHttpMethods ?? []).map((m: any, i: number) => ({
                            id: `${m.method}-${i}`, title: m.method, subtitle: `HTTP ${m.statusCode}`,
                            severity: m.severity, summary: m.risk,
                            details: [{ label: "STATUS", value: `HTTP ${m.statusCode}` }, { label: "RISCO", value: m.risk }],
                          }))}
                        />
                      </>
                    )}

                    {openModule === "redirect" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": redirectColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>↪</span>
                          <span className={styles.sidebarContentTitleText}>Open Redirect</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("redirect")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <FindingCardsPanel
                          emptyMsg={t("vazio.openRedirect")}
                          items={redirectVuln.map((f: any, i: number) => ({
                            id: `redirect-${i}`, title: `?${f.parameter}=`, severity: "HIGH",
                            summary: `Redireciona para: ${f.redirectedTo}`,
                            details: [{ label: t("col.parametro"), value: `?${f.parameter}=` }, { label: "DESTINO", value: f.redirectedTo }],
                          }))}
                        />
                      </>
                    )}

                    {openModule === "dirlist" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": dirColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◫</span>
                          <span className={styles.sidebarContentTitleText}>Directory Listing</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("dirlist")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <FindingCardsPanel
                          emptyMsg={t("vazio.directoryListing")}
                          items={dirExposed.map((f: any, i: number) => ({
                            id: `dir-${i}`, title: f.path, severity: f.severity,
                            summary: `Listagem de diretório exposta publicamente`,
                            details: [{ label: "PATH", value: f.path }, { label: t("col.evidencia"), value: f.evidence }],
                          }))}
                        />
                      </>
                    )}

                    {openModule === "recon" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": reconColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◉</span>
                          <span className={styles.sidebarContentTitleText}>Reconnaissance</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("recon")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <DnsCardsPanel r={r} />
                      </>
                    )}

                    {openModule === "cve" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": cveColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>CVE Correlation</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("cve")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <CveCardsPanel cves={r.cveFindings ?? []} />
                      </>
                    )}

                    {openModule === "apidocs" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": apiDocsColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>API Docs Exposure</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("apidocs")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <FindingCardsPanel
                          emptyMsg={t("vazio.apiDocs")}
                          items={(r?.apiDocsExposure ?? []).map((f: any, i: number) => ({
                            id: `apidoc-${i}`, title: f.path, severity: f.severity,
                            extraTags: [{ label: f.type, color: "var(--info)" }],
                            summary: f.description,
                            details: [{ label: "PATH", value: f.path }, { label: "TIPO", value: f.type }, ...(f.evidence ? [{ label: t("col.evidencia"), value: f.evidence }] : [])],
                          }))}
                        />
                      </>
                    )}

                    {openModule === "graphql" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": gqlColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>GraphQL Introspection</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("graphql")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <FindingCardsPanel
                          emptyMsg={t("vazio.graphql")}
                          items={gqlFindings.map((f: any, i: number) => ({
                            id: `gql-${i}`, title: f.endpoint, severity: f.severity,
                            extraTags: [
                              ...(f.playgroundExposed ? [{ label: "PLAYGROUND", color: "var(--critical)" }] : []),
                              ...(f.introspectionEnabled ? [{ label: "INTROSPECTION", color: "var(--warning)" }] : []),
                            ],
                            summary: f.typeCount > 0 ? `${f.typeCount} tipos expostos via introspection` : t("col.endpointGraphql"),
                            details: [
                              { label: "ENDPOINT", value: f.endpoint },
                              ...(f.typeCount > 0 ? [{ label: "TIPOS", value: `${f.typeCount}` }] : []),
                              ...(f.evidence ? [{ label: t("col.evidencia"), value: f.evidence }] : []),
                            ],
                          }))}
                        />
                      </>
                    )}

                    {openModule === "jwt" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": jwtColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>JWT Security</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("jwt")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <FindingCardsPanel
                          emptyMsg={t("vazio.jwt")}
                          items={jwtFindings.map((jwt: any, i: number) => ({
                            id: `jwt-${i}`, title: jwt.source, severity: jwt.severity,
                            summary: (jwt.issues ?? []).join(" · "),
                            details: [
                              { label: "ALG", value: jwt.algorithm },
                              { label: "EXP", value: !jwt.hasExpiry ? "MISSING" : jwt.expired ? "EXPIRED" : t("selo.presente") },
                              { label: "ISS", value: jwt.hasIssuer ? "✓" : "Ausente" },
                              { label: "AUD", value: jwt.hasAudience ? "✓" : "Ausente" },
                              ...(jwt.evidence ? [{ label: t("col.evidencia"), value: jwt.evidence }] : []),
                            ],
                          }))}
                        />
                      </>
                    )}

                    {openModule === "traversal" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": ptColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>Path Traversal / LFI</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("traversal")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <FindingCardsPanel
                          emptyMsg={t("vazio.pathTraversal")}
                          items={ptFindings.map((pt: any, i: number) => ({
                            id: `pt-${i}`, title: `?${pt.parameter}=`, severity: "CRITICAL",
                            summary: `Arquivo alvo: ${pt.target}`,
                            details: [
                              { label: t("col.parametro"), value: `?${pt.parameter}=` },
                              { label: "ALVO", value: pt.target },
                              { label: "PAYLOAD", value: pt.payload },
                              ...(pt.evidence ? [{ label: t("col.evidencia"), value: pt.evidence }] : []),
                            ],
                          }))}
                        />
                      </>
                    )}

                                      {openModule === "ssrf" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": "var(--critical)" } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>SSRF</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("ssrf")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <FindingCardsPanel
                          emptyMsg={t("vazio.ssrf")}
                          items={ssrfFindings.map((f: any, i: number) => ({
                            id: `ssrf-${i}`, title: `param: ${f.parameter}`, severity: "CRITICAL",
                            summary: `Indicador: ${f.indicator}`,
                            details: [
                              { label: t("col.parametro"), value: f.parameter },
                              { label: "INDICADOR", value: f.indicator },
                              { label: "PAYLOAD", value: f.payload },
                              ...(f.evidence ? [{ label: t("col.evidencia"), value: f.evidence }] : []),
                            ],
                          }))}
                        />
                      </>
                    )}
                    {openModule === "crlf" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": "var(--high)" } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>CRLF Injection</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("crlf")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <FindingCardsPanel
                          emptyMsg={t("vazio.crlf")}
                          items={crlfFindings.map((f: any, i: number) => ({
                            id: `crlf-${i}`, title: `param: ${f.parameter}`, severity: "HIGH",
                            subtitle: `Tipo: ${f.injectionType}`,
                            details: [
                              { label: t("col.parametro"), value: f.parameter },
                              { label: "TIPO", value: f.injectionType },
                              { label: "PAYLOAD", value: f.payload },
                              ...(f.evidence ? [{ label: t("col.evidencia"), value: f.evidence }] : []),
                            ],
                          }))}
                        />
                      </>
                    )}
                  {openModule === "sourcemap" && (
                    <>
                      <div className={styles.sidebarContentTitle} style={{ "--mc-color": smFindings.length ? "var(--high)" : "var(--secure)" } as React.CSSProperties}>
                        <span className={styles.sidebarContentIcon}>◈</span>
                        <span className={styles.sidebarContentTitleText}>Source Map / Debug</span>
                        <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("sourcemap")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                      </div>
                      <FindingCardsPanel
                        emptyMsg={t("vazio.sourceMap")}
                        items={smFindings.map((f: any, i: number) => ({
                          id: `sm-${i}`, title: `[${f.type}]`, severity: f.severity,
                          summary: f.url,
                          details: [
                            { label: "TIPO", value: f.type },
                            { label: "URL", value: f.url },
                            ...(f.evidence ? [{ label: t("col.evidencia"), value: f.evidence }] : []),
                          ],
                        }))}
                      />
                    </>
                  )}
                  {openModule === "hostheader" && (
                    <>
                      <div className={styles.sidebarContentTitle} style={{ "--mc-color": hhFindings.length ? "var(--high)" : "var(--secure)" } as React.CSSProperties}>
                        <span className={styles.sidebarContentIcon}>◈</span>
                        <span className={styles.sidebarContentTitleText}>Host Header Injection</span>
                        <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("hostheader")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                      </div>
                      <FindingCardsPanel
                        emptyMsg={t("vazio.hostHeader")}
                        items={hhFindings.map((f: any, i: number) => ({
                          id: `hh-${i}`, title: f.injectedHeader, severity: "HIGH",
                          summary: `Refletido em: ${f.reflectionPoint}`,
                          details: [
                            { label: "HEADER", value: f.injectedHeader },
                            { label: t("col.refletidoEm"), value: f.reflectionPoint },
                            { label: t("col.valorInjetado"), value: f.injectedValue },
                            ...(f.evidence ? [{ label: t("col.evidencia"), value: f.evidence }] : []),
                          ],
                        }))}
                      />
                    </>
                  )}
                  {openModule === "cert" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": certColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◑</span>
                          <span className={styles.sidebarContentTitleText}>Certificate Transparency</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("cert")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        {ct ? (
                          <>
                            {/* Stats as interactive cards */}
                            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginTop: 8, marginBottom: 12 }}>
                              {[
                                { label: t("ct.certificados"), value: ct.totalCertificates, color: "var(--info)", icon: "◑", detail: "Total de certificados emitidos para este domínio registrados nos logs públicos de Certificate Transparency." },
                                { label: t("ct.subdominiosHistoricos"), value: ct.uniqueSubdomains, color: ct.uniqueSubdomains > 20 ? "var(--warning)" : "var(--info)", icon: "◎", detail: "Subdomínios descobertos via CT logs. Muitos subdomínios podem indicar superfície de ataque ampla — verifique os que não estão mais em uso." },
                                { label: "Wildcard", value: ct.wildcardDetected ? t("selo.sim") : t("selo.nao"), color: ct.wildcardDetected ? "var(--warning)" : "var(--secure)", icon: ct.wildcardDetected ? "⚠" : "✓", detail: ct.wildcardDetected ? "Certificado wildcard detectado (*.dominio). Compromisso de um subdomínio pode afetar todos os outros cobertos pelo wildcard." : "Nenhum certificado wildcard detectado." },
                                { label: t("ct.emitidoRecente"), value: ct.recentlyIssued ? t("selo.sim") : "—", color: ct.recentlyIssued ? "var(--warning)" : "var(--secure)", icon: ct.recentlyIssued ? "⚠" : "✓", detail: ct.recentlyIssued ? "Certificado emitido nos últimos 7 dias. Verifique se a emissão foi esperada — emissões inesperadas podem indicar comprometimento." : "Nenhum certificado emitido recentemente nos logs CT." },
                              ].map((stat, i) => (
                                <div key={i} style={{ background: "var(--surface)", border: `1px solid var(--border)`, borderLeft: `3px solid ${stat.color}`, borderRadius: "var(--radius)", padding: "10px 12px" }}>
                                  <div style={{ fontFamily: "var(--mono)", fontSize: 18, color: stat.color, fontWeight: 700 }}>{stat.value}</div>
                                  <div style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--mono)", marginTop: 3, letterSpacing: ".3px" }}>{stat.label.toUpperCase()}</div>
                                  <p style={{ fontSize: 9, color: "var(--text-dim)", margin: "6px 0 0", lineHeight: 1.5 }}>{stat.detail}</p>
                                </div>
                              ))}
                            </div>
                            {ct.unexpectedIssuer && (
                              <div className={styles.ctAlert}>⚠ Issuer(s) não autorizado(s) pelo CAA: {ct.unexpectedIssuers.map((iss, i) => <Tag key={i} label={iss} cls={styles.critical} />)}</div>
                            )}
                            {ct.issuers?.length > 0 && (
                              <Section title={`Issuers [${ct.issuers.length}]`} defaultOpen={true}>
                                <div className={styles.ctTagList}>{ct.issuers.map((iss, i) => <Tag key={i} label={iss} cls={styles.info} />)}</div>
                              </Section>
                            )}
                            {ct.wildcardDomains?.length > 0 && (
                              <Section title={`Wildcards [${ct.wildcardDomains.length}]`} defaultOpen={false}>
                                <div className={styles.ctTagList}>
                                  {ct.wildcardDomains.map((w, i) => (
                                    <div key={i} className={styles.findingRow}><div className={styles.findingPath}><code>{w}</code><Tag label="WILDCARD" cls={styles.warning} /></div></div>
                                  ))}
                                </div>
                              </Section>
                            )}
                            {ct.recentCerts?.length > 0 && (
                              <Section title={`Certificados recentes [${ct.recentCerts.length}]`} defaultOpen={false}>
                                <table className={styles.table}>
                                  <thead><tr><th>{t("ct.commonName")}</th><th>Issuer</th><th>{t("ct.validoDe")}</th><th>{t("ct.validoAte")}</th></tr></thead>
                                  <tbody>
                                    {ct.recentCerts.map((c, i) => (
                                      <tr key={i}>
                                        <td><code className={styles.code}>{c.commonName}{c.wildcard && <Tag label="WC" cls={styles.warning} />}</code></td>
                                        <td className={styles.muted}>{c.issuer}</td>
                                        <td className={styles.muted}>{c.notBefore}</td>
                                        <td className={(c.notAfter < new Date().toISOString().split("T")[0]) ? styles.bad : styles.ok}>{c.notAfter}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </Section>
                            )}
                            {ct.discoveredSubdomains?.length > 0 && (
                              <Section title={`Subdomínios históricos [${ct.discoveredSubdomains.length}]`} defaultOpen={false}>
                                <div className={styles.ctSubdomainGrid}>{ct.discoveredSubdomains.map((s, i) => <code key={i} className={styles.ctSubdomain}>{s}</code>)}</div>
                              </Section>
                            )}
                          </>
                        ) : <div className={styles.empty}>{t("resultado.naoAnalisado")}</div>}
                      </>
                    )}

                    {openModule === "takeover" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": takeoverColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◎</span>
                          <span className={styles.sidebarContentTitleText}>Subdomain Takeover</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("takeover")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <FindingCardsPanel
                          emptyMsg={t("vazio.takeover")}
                          cols={1}
                          items={(r.subdomainTakeover ?? []).map((tk: any, i: number) => ({
                            id: `takeover-${i}`, title: tk.subdomain, severity: tk.severity,
                            extraTags: [{ label: tk.status, color: tk.status === "VULNERABLE" ? "var(--critical)" : "var(--warning)" }],
                            summary: `${tk.vulnerability} — via ${tk.service}`,
                            details: [
                              { label: t("col.subdominio"), value: tk.subdomain },
                              { label: "STATUS", value: tk.status },
                              { label: t("col.servico"), value: tk.service },
                              { label: "CNAME →", value: tk.cnameTarget },
                              { label: "VULNERAB.", value: tk.vulnerability },
                              ...(tk.evidence ? [{ label: t("col.evidencia"), value: tk.evidence }] : []),
                            ],
                          }))}
                        />
                      </>
                    )}

                    {openModule === "active" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": "var(--info)" } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>▣</span>
                          <span className={styles.sidebarContentTitleText}>Active Checks</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("active")} title={t("resultado.saibaMaisTitulo")}>{t("resultado.saibaMais")}</button>
                        </div>
                        <ActiveChecksPanel r={r} onShowPlans={() => setShowPlans(true)} />
                      </>
                    )}
                    </>
                    )}

                    </div>
                  </div>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );}
