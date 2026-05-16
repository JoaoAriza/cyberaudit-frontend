import { useCallback, useEffect, useRef, useState } from "react";
import styles from "./App.module.css";
import { api } from "./api/client";
import { useAuth } from "./context/AuthContext";
import type { UserDto } from "./context/AuthContext";

// ── Backend Types ─────────────────────────────────────────────────────────────

interface SSLInfo { https: boolean; valid: boolean; expirationDate: string | null; daysRemaining: number; message: string; }
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
interface ScanResult { url: string; finalUrl: string; httpStatus: number; redirectsToHttps: boolean; sslInfo: SSLInfo; tlsDetails: TlsDetails; headers: Record<string, string>; serverVersionExposed: boolean; activeMode: boolean; inputSurfaceDetected: boolean; dbErrorLeakageSuspected: boolean; xssProbePerformed: boolean; reflectedXssSuspected: boolean; openPorts: PortFinding[]; corsResult: CorsResult; cookieIssues: CookieFinding[]; sensitiveRobotsPaths: string[]; sensitiveFiles: SensitiveFileFinding[]; dangerousHttpMethods: HttpMethodFinding[]; securityTxtPresent: boolean; securityTxtContact: string | null; openRedirectFindings: OpenRedirectFinding[]; directoryListingFindings: DirectoryListingFinding[]; score: ScoreResult; }
interface AsyncStatus { state: "PENDING" | "RUNNING" | "DONE" | "ERROR"; result: ScanResult | null; errorMessage: string | null; }
interface OwnershipState { message: string; host: string; token: string | null; passiveResult: ScanResult | null; }
interface GuestStatus { used: number; remaining: number; dailyLimit: number; resetsAt: string; }
interface UserManagementDto { id: string; name: string; email: string; role: string; jobTitle: string | null; active: boolean; createdAt: string; invitedByName: string; }
interface InviteDto { id: string; name: string; email: string; role: string; jobTitle: string | null; invitedByName: string; accepted: boolean; expired: boolean; expiresAt: string; acceptLink: string | null; }

type View = "scan" | "login" | "admin";

// ── Utilities ─────────────────────────────────────────────────────────────────

function getInviteTokenFromUrl(): string | null {
  const path = window.location.pathname;
  const match = path.match(/\/auth\/accept-invite\/([a-f0-9-]+)/);
  return match ? match[1] : null;
}

function riskColor(level?: string) {
  if (level === "SECURE") return styles.secure;
  if (level === "WARNING") return styles.warning;
  if (level === "CRITICAL") return styles.critical;
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
function headerStatus(v: string) {
  if (v.startsWith("OK")) return <span className={styles.ok}>✓ {v}</span>;
  if (v.startsWith("MISSING")) return <span className={styles.bad}>✗ MISSING</span>;
  if (v.startsWith("WEAK")) return <span className={styles.warn}>⚠ {v}</span>;
  return <span className={styles.muted}>{v}</span>;
}
function downloadBlob(blob: Blob, filename: string) {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  a.remove(); window.URL.revokeObjectURL(url);
}

// ── AcceptInvitePage ──────────────────────────────────────────────────────────

function AcceptInvitePage({ token }: { token: string }) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) { setError("As senhas não coincidem."); return; }
    if (password.length < 6) { setError("Senha deve ter no mínimo 6 caracteres."); return; }

    setLoading(true); setError(null);
    try {
      await api.post(`/auth/accept-invite/${token}`, { name, password });
      setSuccess(true);
      // Redireciona para a raiz após 2 segundos
      setTimeout(() => { window.location.href = "/"; }, 2000);
    } catch (err: any) {
      setError(err?.response?.data?.message ?? "Convite inválido ou expirado.");
    } finally { setLoading(false); }
  }

  if (success) return (
    <div className={styles.loginPage}>
      <div className={styles.loginCard}>
        <div className={styles.loginLogo}>
          <span className={styles.logoIcon}>◈</span>
          <span className={styles.logoText}>CyberAudit</span>
        </div>
        <div className={styles.loginTitle} style={{ color: "var(--secure)" }}>✓ Conta criada!</div>
        <div className={styles.loginSub}>Redirecionando para o login...</div>
      </div>
    </div>
  );

  return (
    <div className={styles.loginPage}>
      <div className={styles.loginCard}>
        <div className={styles.loginLogo}>
          <span className={styles.logoIcon}>◈</span>
          <span className={styles.logoText}>CyberAudit</span>
        </div>
        <div className={styles.loginTitle}>Criar sua conta</div>
        <div className={styles.loginSub}>Você foi convidado para o CyberAudit. Defina sua senha para continuar.</div>

        <form className={styles.loginForm} onSubmit={handleSubmit}>
          <div className={styles.formGroup}>
            <label className={styles.formLabel}>NOME COMPLETO</label>
            <input className={styles.formInput} value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Seu nome" />
          </div>
          <div className={styles.formGroup}>
            <label className={styles.formLabel}>SENHA *</label>
            <input className={styles.formInput} type="password" value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Mínimo 6 caracteres" required />
          </div>
          <div className={styles.formGroup}>
            <label className={styles.formLabel}>CONFIRMAR SENHA *</label>
            <input className={styles.formInput} type="password" value={confirm}
              onChange={e => setConfirm(e.target.value)}
              placeholder="Repita a senha" required />
          </div>
          {error && <div className={styles.errorBox}>{error}</div>}
          <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={loading}>
            {loading ? "Criando conta..." : "Criar conta e entrar"}
          </button>
        </form>
      </div>
    </div>
  );
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
function Section({ title, children, defaultOpen = true }: { title: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
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

// ── Issue Item ────────────────────────────────────────────────────────────────

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

// ── Terminal Loader ───────────────────────────────────────────────────────────

const SCAN_LINES = [
  "→ resolving target...", "→ probing SSL certificate...",
  "→ negotiating TLS handshake...", "→ analyzing security headers...",
  "→ running CORS probe...", "→ inspecting cookies...",
  "→ checking robots.txt...", "→ scanning sensitive files...",
  "→ testing HTTP methods...", "→ verifying security.txt...",
  "→ detecting open redirects...", "→ checking directory listings...",
  "→ calculating risk score...",
];
function TerminalLoader({ asyncState }: { asyncState?: string }) {
  const [lines, setLines] = useState<string[]>([SCAN_LINES[0]]);
  const idx = useRef(1);
  useEffect(() => {
    const t = setInterval(() => {
      if (idx.current < SCAN_LINES.length)
        setLines(prev => [...prev, SCAN_LINES[idx.current++]]);
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
        {lines.map((l, i) => <div key={i} className={styles.termLine} style={{ animationDelay: `${i * 0.05}s` }}>{l}</div>)}
        <div className={styles.termCursor}>█</div>
      </div>
    </div>
  );
}

// ── Guest Banner ──────────────────────────────────────────────────────────────

function GuestBanner({ onLogin }: { onLogin: () => void }) {
  const [status, setStatus] = useState<GuestStatus | null>(null);

  useEffect(() => {
    api.get<GuestStatus>("/auth/guest-status")
      .then(r => setStatus(r.data))
      .catch(() => { });
  }, []);

  if (!status) return null;

  const pct = Math.round((status.used / status.dailyLimit) * 100);
  const critical = status.remaining <= 2;

  return (
    <div className={`${styles.guestBanner} ${critical ? styles.guestBannerCritical : ""}`}>
      <div className={styles.guestBannerLeft}>
        <span className={styles.guestBannerIcon}>{critical ? "⚠" : "◈"}</span>
        <div>
          <div className={styles.guestBannerTitle}>
            {status.remaining === 0
              ? "Limite diário atingido"
              : `${status.remaining} scan${status.remaining !== 1 ? "s" : ""} restante${status.remaining !== 1 ? "s" : ""} hoje`}
          </div>
          <div className={styles.guestBannerSub}>
            {status.used}/{status.dailyLimit} utilizados · reseta meia-noite
          </div>
          <div className={styles.guestProgress}>
            <div className={styles.guestProgressFill} style={{ width: `${pct}%`, background: critical ? "var(--critical)" : "var(--accent)" }} />
          </div>
        </div>
      </div>
      <button className={`${styles.btn} ${styles.btnScan}`} onClick={onLogin}>
        Login para acesso ilimitado →
      </button>
    </div>
  );
}

// ── Ownership Card ────────────────────────────────────────────────────────────

function OwnershipCard({ state, onDismiss }: { state: OwnershipState; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);
  const [checking, setChecking] = useState(false);
  const [verified, setVerified] = useState(false);

  async function check() {
    setChecking(true);
    try {
      const r = await api.get("/scan/verify-check", { params: { host: state.host } });
      setVerified(r.data.verified);
    } catch { setVerified(false); }
    setChecking(false);
  }
  function copy() {
    if (state.token) { navigator.clipboard.writeText(state.token); setCopied(true); setTimeout(() => setCopied(false), 2000); }
  }
  return (
    <div className={styles.ownershipCard}>
      <div className={styles.ownershipHeader}><span>⚠</span><span>VERIFICAÇÃO DE PROPRIEDADE</span></div>
      <p className={styles.ownershipText}>Scan ativo detectou riscos em <strong>{state.host}</strong>. Prove que você é o dono.</p>
      <div className={styles.ownershipSteps}>
        <div className={styles.ownershipStep}>
          <span className={styles.stepNum}>1</span>
          <div><div className={styles.stepTitle}>Crie o arquivo</div><code className={styles.stepCode}>https://{state.host}/.well-known/cyberaudit.txt</code></div>
        </div>
        <div className={styles.ownershipStep}>
          <span className={styles.stepNum}>2</span>
          <div><div className={styles.stepTitle}>Conteúdo</div>
            <div className={styles.tokenRow}><code className={styles.stepCode}>{state.token ?? "—"}</code><button className={styles.copyBtn} onClick={copy}>{copied ? "✓" : "Copiar"}</button></div>
          </div>
        </div>
        <div className={styles.ownershipStep}>
          <span className={styles.stepNum}>3</span>
          <div><div className={styles.stepTitle}>Verifique</div>
            <div className={styles.tokenRow}>
              <button className={styles.verifyBtn} onClick={check} disabled={checking}>{checking ? "..." : "Checar"}</button>
              {verified ? <span className={styles.ok}>✓ Verificado!</span> : <span className={styles.bad}>Não encontrado.</span>}
            </div>
          </div>
        </div>
      </div>
      <button className={styles.dismissBtn} onClick={onDismiss}>Fechar</button>
    </div>
  );
}

// ── Login Page ────────────────────────────────────────────────────────────────

function LoginPage({ onBack }: { onBack: () => void }) {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setError(null);
    try {
      await login(email, password);
      onBack();
    } catch (err: any) {
      const msg = err?.response?.data?.message ?? err?.response?.data?.error ?? "Credenciais inválidas.";
      setError(msg);
    } finally { setLoading(false); }
  }

  return (
    <div className={styles.loginPage}>
      <div className={styles.loginCard}>
        <div className={styles.loginLogo}>
          <span className={styles.logoIcon}>◈</span>
          <span className={styles.logoText}>CyberAudit</span>
        </div>
        <div className={styles.loginTitle}>Acesso restrito</div>
        <div className={styles.loginSub}>Entre com suas credenciais para acesso completo</div>

        <form className={styles.loginForm} onSubmit={handleSubmit}>
          <div className={styles.formGroup}>
            <label className={styles.formLabel}>EMAIL</label>
            <input className={styles.formInput} type="email" value={email}
              onChange={e => setEmail(e.target.value)} placeholder="seu@email.com" required />
          </div>
          <div className={styles.formGroup}>
            <label className={styles.formLabel}>SENHA</label>
            <input className={styles.formInput} type="password" value={password}
              onChange={e => setPassword(e.target.value)} placeholder="••••••••" required />
          </div>
          {error && <div className={styles.errorBox}>{error}</div>}
          <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={loading}>
            {loading ? "Entrando..." : "Entrar"}
          </button>
        </form>

        <button className={styles.backLink} onClick={onBack}>
          ← Voltar sem autenticação
        </button>
      </div>
    </div>
  );
}

function InviteItemRow({ inv, onRevoke, roleBadge }: {
  inv: InviteDto;
  onRevoke: () => void;
  roleBadge: (role: string) => React.ReactNode;
}) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const link = inv.acceptLink
    ? `${window.location.origin}${inv.acceptLink}`
    : null;

  function copyLink() {
    if (!link) return;
    navigator.clipboard.writeText(link);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className={styles.inviteItem} style={{ flexDirection: "column", alignItems: "stretch", gap: 0 }}>

      {/* Linha principal */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer" }}
        onClick={() => setExpanded(o => !o)}>
        <div className={styles.inviteItemLeft}>
          <div className={styles.inviteItemName}>{inv.name}</div>
          <code className={styles.code}>{inv.email}</code>
          <div className={styles.inviteItemMeta}>
            {roleBadge(inv.role)}
            <span className={styles.muted}>· expira {new Date(inv.expiresAt).toLocaleDateString()}</span>
          </div>
        </div>
        <div className={styles.actionBtns} onClick={e => e.stopPropagation()}>
          <span
            className={`${styles.chevron} ${expanded ? styles.chevronOpen : ""}`}
            style={{ fontSize: 20, color: "var(--text-dim)", cursor: "pointer", padding: "0 6px" }}
            onClick={() => setExpanded(o => !o)}
          >›</span>
          <button className={`${styles.btn} ${styles.btnDanger}`} onClick={onRevoke}>Revogar</button>
        </div>
      </div>

      {/* Detalhes expandidos */}
      {expanded && (
        <div style={{
          marginTop: 10, padding: 12,
          background: "var(--surface3)",
          borderRadius: "var(--radius)",
          display: "flex", flexDirection: "column", gap: 10,
          borderTop: "1px solid var(--border)"
        }}>
          <div>
            <div style={{ fontSize: 10, letterSpacing: 1, color: "var(--text-muted)", marginBottom: 6 }}>
              LINK DE ACEITE
            </div>
            {link ? (
              <div className={styles.tokenRow}>
                <code className={styles.stepCode} style={{ flex: 1, fontSize: 11, wordBreak: "break-all" }}>
                  {link}
                </code>
                <button className={styles.copyBtn} onClick={copyLink}>
                  {copied ? "✓ Copiado" : "Copiar"}
                </button>
              </div>
            ) : (
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                Link não disponível — recrie o convite para gerar um novo.
              </span>
            )}
          </div>

          <div style={{ display: "flex", gap: 20, fontSize: 11, color: "var(--text-dim)", flexWrap: "wrap" }}>
            <span>Convidado por: <strong style={{ color: "var(--text)" }}>{inv.invitedByName}</strong></span>
            {inv.jobTitle && (
              <span>Cargo: <strong style={{ color: "var(--text)" }}>{inv.jobTitle}</strong></span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
// ── Admin Panel ───────────────────────────────────────────────────────────────

function AdminPanel() {
  const { user } = useAuth();
  const [tab, setTab] = useState<"users" | "invites">(
    user?.role === "OWNER" ? "users" : "invites"
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
  const [invError, setInvError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);


  useEffect(() => { loadUsers(); loadInvites(); }, []);
  useEffect(() => {
    if (user?.role === "ADMIN") setInvRole("FREE_EMPLOYEE");
  }, [user]);

  async function loadUsers() {
    setLoading(true);
    try { setUsers((await api.get<UserManagementDto[]>("/admin/users")).data); }
    catch { /* silently fail */ } finally { setLoading(false); }
  }
  async function loadInvites() {
    try { setInvites((await api.get<InviteDto[]>("/admin/invites")).data); }
    catch { /* silently fail */ }
  }
  async function deactivate(id: string) {
    if (!confirm("Desativar este usuário?")) return;
    try { await api.delete(`/admin/users/${id}`); loadUsers(); }
    catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); }
  }
  async function reactivate(id: string) {
    try { await api.put(`/admin/users/${id}/reactivate`); loadUsers(); }
    catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); }
  }
  async function changeRole(id: string, role: string) {
    try { await api.put(`/admin/users/${id}/role`, { role }); loadUsers(); }
    catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); }
  }
  async function revokeInvite(id: string) {
    if (!confirm("Revogar este convite?")) return;
    try { await api.delete(`/admin/invites/${id}`); loadInvites(); }
    catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); }
  }
  async function sendInvite(e: React.FormEvent) {
    e.preventDefault();
    setInviting(true); setInvError(null); setNewInvite(null);
    try {
      const r = await api.post<InviteDto>("/admin/invite", {
        name: invName, email: invEmail, role: invRole, jobTitle: invJob || null
      });
      setNewInvite(r.data);
      setInvName(""); setInvEmail(""); setInvJob("");
      loadInvites();
    } catch (e: any) {
      setInvError(e?.response?.data?.message ?? "Erro ao criar convite.");
    } finally { setInviting(false); }
  }
  function copyLink() {
    if (!newInvite?.acceptLink) return;
    const base = import.meta.env.VITE_APP_URL ?? window.location.origin;
    navigator.clipboard.writeText(base + newInvite.acceptLink);
    setCopied(true); setTimeout(() => setCopied(false), 2000);
  }

  function roleBadge(role: string) {
    const cls = role === "OWNER" ? styles.secure : role === "ADMIN" ? styles.warning : styles.info;
    return <Tag label={role} cls={cls} />;
  }

  return (
    <div className={styles.adminPage}>
      <div className={styles.adminHeader}>
        <div className={styles.adminTitle}>◈ PAINEL ADMIN</div>
        <div className={styles.adminTabs}>
          {user?.role === "OWNER" && (
            <button className={`${styles.adminTab} ${tab === "users" ? styles.adminTabActive : ""}`}
              onClick={() => setTab("users")}>Usuários ({users.length})</button>
          )}
          <button className={`${styles.adminTab} ${tab === "invites" ? styles.adminTabActive : ""}`}
            onClick={() => setTab("invites")}>Convites ({invites.length})</button>
        </div>
      </div>

      {tab === "users" && (
        <div className={styles.adminContent}>
          <Card title="USUÁRIOS DO SISTEMA">
            {loading ? <div className={styles.empty}>Carregando...</div> : (
              <table className={styles.adminTable}>
                <thead>
                  <tr><th>Nome</th><th>Email</th><th>Role</th><th>Status</th><th>Convidado por</th><th>Ações</th></tr>
                </thead>
                <tbody>
                  {users.map(u => (
                    <tr key={u.id} className={!u.active ? styles.inactiveRow : ""}>
                      <td>{u.name}{u.jobTitle && <span className={styles.jobTitle}> · {u.jobTitle}</span>}</td>
                      <td><code className={styles.code}>{u.email}</code></td>
                      <td>{roleBadge(u.role)}</td>
                      <td><span className={u.active ? styles.ok : styles.bad}>{u.active ? "Ativo" : "Inativo"}</span></td>
                      <td className={styles.muted}>{u.invitedByName}</td>
                      <td>
                        {u.role !== "OWNER" && (
                          <div className={styles.actionBtns}>
                            {u.active ? (
                              <button className={`${styles.btn} ${styles.btnDanger}`} onClick={() => deactivate(u.id)}>Desativar</button>
                            ) : (
                              <button className={`${styles.btn} ${styles.btnGhost}`} onClick={() => reactivate(u.id)}>Reativar</button>
                            )}
                            <select className={styles.roleSelect}
                              value={u.role}
                              onChange={e => changeRole(u.id, e.target.value)}>
                              <option value="ADMIN">ADMIN</option>
                              <option value="FREE_EMPLOYEE">EMPLOYEE</option>
                            </select>
                          </div>
                        )}
                      </td>
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
                <div className={styles.formGroup}>
                  <label className={styles.formLabel}>NOME *</label>
                  <input className={styles.formInput} value={invName} onChange={e => setInvName(e.target.value)} placeholder="Nome completo" required />
                </div>
                <div className={styles.formGroup}>
                  <label className={styles.formLabel}>EMAIL *</label>
                  <input className={styles.formInput} type="email" value={invEmail} onChange={e => setInvEmail(e.target.value)} placeholder="email@empresa.com" required />
                </div>
                <div className={styles.formGroup}>
                  <label className={styles.formLabel}>CARGO</label>
                  <input className={styles.formInput} value={invJob} onChange={e => setInvJob(e.target.value)} placeholder="Ex: Security Analyst" />
                </div>
                <div className={styles.formGroup}>
                  <label className={styles.formLabel}>NÍVEL DE ACESSO *</label>
                  <div className={styles.roleOptions}>
                    {user?.role === "OWNER" && (
                      <label className={styles.roleOption}>
                        <input type="radio" name="role" value="ADMIN"
                          checked={invRole === "ADMIN"}
                          onChange={() => setInvRole("ADMIN")} />
                        <div>
                          <strong>Admin</strong>
                          <div className={styles.roleDesc}>Scan ativo + convida funcionários</div>
                        </div>
                      </label>
                    )}
                    <label className={styles.roleOption}>
                      <input type="radio" name="role" value="FREE_EMPLOYEE"
                        checked={invRole === "FREE_EMPLOYEE" || user?.role === "ADMIN"}
                        onChange={() => setInvRole("FREE_EMPLOYEE")} />
                      <div>
                        <strong>Funcionário</strong>
                        <div className={styles.roleDesc}>Scan ativo, sem gestão</div>
                      </div>
                    </label>
                  </div>
                </div>
                {invError && <div className={styles.errorBox}>{invError}</div>}
                {newInvite && (
                  <div className={styles.inviteSuccess}>
                    <div className={styles.inviteSuccessTitle}>✓ Convite criado — expira em 48h</div>
                    <div className={styles.tokenRow}>
                      <code className={styles.stepCode}>{newInvite.acceptLink}</code>
                      <button type="button" className={styles.copyBtn} onClick={copyLink}>{copied ? "✓" : "Copiar link"}</button>
                    </div>
                  </div>
                )}
                <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={inviting}>
                  {inviting ? "Criando..." : "Enviar convite"}
                </button>
              </form>
            </Card>

            <Card title="CONVITES PENDENTES">
              {invites.length === 0 ? (
                <div className={styles.empty}>Nenhum convite pendente.</div>
              ) : (
                <div className={styles.pendingInvites}>
                  {invites.map(inv => (
                    <InviteItemRow
                      key={inv.id}
                      inv={inv}
                      onRevoke={() => revokeInvite(inv.id)}
                      roleBadge={roleBadge}
                    />
                  ))}
                </div>
              )}
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const { user, loading, logout, isOwner, isAdmin, isAuthenticated } = useAuth();
  const [view, setView] = useState<View>("scan");
  const [url, setUrl] = useState("github.com");
  const [active, setActive] = useState(false);
  const [useAsync, setUseAsync] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ownership, setOwnership] = useState<OwnershipState | null>(null);
  const [asyncState, setAsyncState] = useState<string | undefined>();
  const abortRef = useRef<AbortController | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Se logar durante a sessão, volta para scan
  useEffect(() => { if (user && view === "login") setView("scan"); }, [user]);

  useEffect(() => () => { pollRef.current && clearInterval(pollRef.current); }, []);

  const stopPoll = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  async function handleScan() {
    abortRef.current?.abort(); stopPoll();
    setScanLoading(true); setError(null); setResult(null); setOwnership(null); setAsyncState(undefined);
    useAsync ? await runAsync() : await runSync();
  }

  async function runSync() {
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    try {
      const res = await api.get("/scan", { params: { url, active }, signal: ctrl.signal });
      setResult(res.data);
    } catch (err: any) { handleError(err); }
    finally { setScanLoading(false); }
  }

  async function runAsync() {
    try {
      const res = await api.post("/scan/async", null, { params: { url, active } });
      const scanId: string = res.data.scanId;
      setAsyncState("PENDING");
      pollRef.current = setInterval(async () => {
        try {
          const status: AsyncStatus = (await api.get(`/scan/async/${scanId}`)).data;
          setAsyncState(status.state);
          if (status.state === "DONE") { stopPoll(); setResult(status.result); setScanLoading(false); }
          else if (status.state === "ERROR") { stopPoll(); setError(status.errorMessage ?? "Erro."); setScanLoading(false); }
        } catch { stopPoll(); setError("Falha ao consultar status."); setScanLoading(false); }
      }, 2000);
    } catch (err: any) { handleError(err); setScanLoading(false); }
  }

  function handleError(err: any) {
    const aborted = err?.name === "CanceledError" || err?.code === "ERR_CANCELED";
    if (aborted) { setError("Scan cancelado."); return; }

    if (err?.response?.status === 401) {
      setError("Scan ativo requer autenticação.");
      setView("login");
      return;
    }
    if (err?.response?.status === 403 && err?.response?.data?.error === "OWNERSHIP_REQUIRED") {
      const host = url.replace(/^https?:\/\//, "").split("/")[0];
      const tokenMatch = err.response.data.message?.match(/cyberaudit-verify=[a-f0-9-]+/);
      setOwnership({ message: err.response.data.message, host, token: tokenMatch?.[0] ?? null, passiveResult: null });
      return;
    }
    const msg = err?.response ? `Erro ${err.response.status}: ${JSON.stringify(err.response.data)}` : `Falha: ${err.message}`;
    setError(msg);
  }

  async function handlePdf() {
    setPdfLoading(true);
    try {
      const res = await api.get("/scan/report/pdf", { params: { url, active }, responseType: "blob" });
      const ts = new Date().toISOString().slice(0, 10);
      downloadBlob(new Blob([res.data], { type: "application/pdf" }), `cyberaudit-${url.replace(/[^a-z0-9]/gi, "-")}-${ts}.pdf`);
    } catch (e: any) { setError(`PDF: ${e.message}`); }
    finally { setPdfLoading(false); }
  }

  const inviteToken = getInviteTokenFromUrl();
  if (inviteToken) {
    return (
      <div className={styles.app}>
        <AcceptInvitePage token={inviteToken} />
      </div>
    );
  }

  if (loading) return (
    <div className={styles.app}>
      <div className={styles.loadingScreen}><span className={styles.logoIcon}>◈</span> Carregando...</div>
    </div>
  );

  if (view === "login") return (
    <div className={styles.app}>
      <LoginPage onBack={() => setView("scan")} />
    </div>
  );

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
        <nav className={styles.headerNav}>
          <button className={`${styles.navBtn} ${view === "scan" ? styles.navBtnActive : ""}`}
            onClick={() => setView("scan")}>Scanner</button>
          {isAdmin() && (
            <button className={`${styles.navBtn} ${view === "admin" ? styles.navBtnActive : ""}`}
              onClick={() => setView("admin")}>Admin</button>
          )}
        </nav>
        <div className={styles.headerRight}>
          {isAuthenticated() ? (
            <div className={styles.userInfo}>
              <span className={`${styles.tag} ${user?.role === "OWNER" ? styles.secure : styles.info}`}>{user?.role}</span>
              <span className={styles.userName}>{user?.name}</span>
              <button className={`${styles.btn} ${styles.btnGhost}`} onClick={logout}>Sair</button>
            </div>
          ) : (
            <button className={`${styles.btn} ${styles.btnScan}`} onClick={() => setView("login")}>Login</button>
          )}
        </div>
      </header>

      <main className={styles.main}>
        {/* ── Guest banner ── */}
        {!isAuthenticated() && view === "scan" && (
          <GuestBanner onLogin={() => setView("login")} />
        )}

        {/* ── Admin panel ── */}
        {view === "admin" && isAdmin() && <AdminPanel />}

        {/* ── Scan view ── */}
        {view === "scan" && (
          <>
            {/* Scan form */}
            <div className={styles.scanPanel}>
              <div className={styles.scanForm}>
                <div className={styles.inputWrap}>
                  <span className={styles.inputPrefix}>https://</span>
                  <input className={styles.urlInput} value={url} onChange={e => setUrl(e.target.value)}
                    placeholder="example.com" onKeyDown={e => e.key === "Enter" && !scanLoading && handleScan()} />
                </div>
                <div className={styles.toggles}>
                  <label className={styles.toggle} title="Ativa port scan e probes. Apenas em domínios autorizados.">
                    <input type="checkbox" checked={active} disabled={scanLoading} onChange={e => setActive(e.target.checked)} />
                    <span className={styles.toggleLabel}>ACTIVE</span>
                  </label>
                  <label className={styles.toggle}>
                    <input type="checkbox" checked={useAsync} disabled={scanLoading} onChange={e => setUseAsync(e.target.checked)} />
                    <span className={styles.toggleLabel}>ASYNC</span>
                  </label>
                </div>
                <div className={styles.actions}>
                  {scanLoading ? (
                    <button className={`${styles.btn} ${styles.btnCancel}`} onClick={() => { abortRef.current?.abort(); stopPoll(); setScanLoading(false); }}>✕ Cancel</button>
                  ) : (
                    <button className={`${styles.btn} ${styles.btnScan}`} onClick={handleScan}>◈ Scan</button>
                  )}
                  <button className={`${styles.btn} ${styles.btnGhost}`} onClick={handlePdf} disabled={pdfLoading || scanLoading}>{pdfLoading ? "..." : "PDF"}</button>
                </div>
              </div>
              {active && <div className={styles.activeWarning}>⚠ Modo ativo: port scan + probes. Use apenas em domínios autorizados.</div>}
              {scanLoading && <div className={styles.progressBar}><div className={styles.progressFill} /></div>}
              {error && <div className={styles.errorBox}>{error}</div>}
            </div>

            {/* Ownership */}
            {ownership && <OwnershipCard state={ownership} onDismiss={() => setOwnership(null)} />}

            {/* Terminal loader */}
            {scanLoading && <TerminalLoader asyncState={asyncState} />}

            {/* Results */}
            {r && !scanLoading && (
              <div className={styles.dashboard}>
                <div className={styles.row}>
                  <Card>
                    <div className={styles.overviewCard}>
                      <ScoreGauge score={r.score?.score ?? 0} risk={risk ?? "CRITICAL"} />
                      <div className={styles.overviewMeta}>
                        <div className={`${styles.riskBadge} ${riskColor(risk)}`}>{risk}</div>
                        <KV label="URL" value={r.finalUrl ?? r.url} />
                        <KV label="HTTP" value={r.httpStatus} />
                        <KV label="HTTPS REDIRECT" value={boolIcon(r.redirectsToHttps)} />
                        <KV label="ACTIVE MODE" value={boolIcon(r.activeMode)} />
                        <KV label="SERVER EXPOSED" value={boolIcon(!r.serverVersionExposed, "✓ Clean", "⚠ Exposed")} />
                        <div className={styles.badgePreview}>
                          <img src={`${import.meta.env.VITE_API_URL ?? "http://localhost:8081"}/badge/${(r.finalUrl ?? r.url).replace(/^https?:\/\//, "").split("/")[0]}`} alt="badge" className={styles.badgeImg} />
                        </div>
                      </div>
                    </div>
                  </Card>
                  <Card title={`ISSUES  [${r.score?.issues?.length ?? 0}]`}>
                    {r.score?.issues?.length ? (
                      <div className={styles.issuesList}>{r.score.issues.map(i => <IssueItem key={i.id} issue={i} />)}</div>
                    ) : <div className={styles.empty}>◈ Nenhuma issue detectada</div>}
                  </Card>
                </div>

                <div className={styles.row}>
                  <Card title="TRANSPORT SECURITY">
                    <Section title="SSL / TLS">
                      <KV label="Protocol" value={<span className={r.tlsDetails?.weakProtocol ? styles.bad : styles.ok}>{r.tlsDetails?.negotiatedProtocol ?? "—"}</span>} />
                      <KV label="Cipher" value={<code className={styles.code}>{r.tlsDetails?.cipherSuite ?? "—"}</code>} />
                      <KV label="Valid" value={boolIcon(r.sslInfo?.valid)} />
                      <KV label="Expires" value={r.sslInfo?.expirationDate ?? "—"} />
                      <KV label="Days left" value={<span className={(r.sslInfo?.daysRemaining ?? 0) < 30 ? styles.bad : (r.sslInfo?.daysRemaining ?? 0) < 90 ? styles.warn : styles.ok}>{r.sslInfo?.daysRemaining ?? "—"}d</span>} />
                      {r.tlsDetails?.message && <div className={styles.note}>{r.tlsDetails.message}</div>}
                    </Section>
                  </Card>
                  <Card title="SECURITY HEADERS">
                    <Section title="Headers">
                      {Object.entries(r.headers ?? {}).map(([k, v]) => <KV key={k} label={k} value={headerStatus(v)} />)}
                    </Section>
                  </Card>
                </div>

                <div className={styles.row}>
                  <Card title="CORS ANALYSIS">
                    {r.corsResult?.tested ? (
                      <Section title="Probe Results">
                        <KV label="Allow-Origin" value={<code className={styles.code}>{r.corsResult.allowOriginValue}</code>} />
                        <KV label="Wildcard" value={boolIcon(!r.corsResult.wildcardOrigin, "✓ No", "⚠ YES")} />
                        <KV label="Reflects Origin" value={boolIcon(!r.corsResult.reflectsOrigin, "✓ No", "⚠ YES")} />
                        <KV label="Credentials" value={boolIcon(!r.corsResult.credentialsAllowed, "✓ No", "⚠ YES")} />
                        <KV label="Null Origin" value={boolIcon(!r.corsResult.nullOriginAccepted, "✓ No", "⚠ YES")} />
                        <div className={styles.note}>{r.corsResult.message}</div>
                      </Section>
                    ) : <div className={styles.empty}>Probe não executado</div>}
                  </Card>
                  <Card title="COOKIE SECURITY">
                    {r.cookieIssues?.length ? (
                      <Section title={`${r.cookieIssues.length} cookie(s) com problemas`}>
                        {r.cookieIssues.map((c, i) => (
                          <div key={i} className={styles.cookieRow}>
                            <div className={styles.cookieName}><code>{c.name}</code><Tag label={c.risk} cls={sevColor(c.risk)} /></div>
                            <div className={styles.cookieFlags}>
                              <span className={c.httpOnly ? styles.ok : styles.bad}>HttpOnly</span>
                              <span className={c.secure ? styles.ok : styles.bad}>Secure</span>
                              <span className={styles.muted}>SameSite: {c.sameSite}</span>
                            </div>
                            <div className={styles.cookieIssue}>{c.issues}</div>
                          </div>
                        ))}
                      </Section>
                    ) : <div className={styles.empty}>◈ Nenhum problema detectado</div>}
                  </Card>
                </div>

                <div className={styles.row}>
                  <Card title="SENSITIVE FILES">
                    {r.sensitiveFiles?.length ? (
                      <Section title={`${r.sensitiveFiles.length} arquivo(s)`}>
                        {r.sensitiveFiles.map((f, i) => (
                          <div key={i} className={styles.findingRow}>
                            <div className={styles.findingPath}><code>{f.path}</code><Tag label={f.exposure} cls={f.exposure === "EXPOSED" ? styles.critical : styles.warning} /><Tag label={f.severity} cls={sevColor(f.severity)} /></div>
                            {f.contentPreview && <pre className={styles.preview}>{f.contentPreview}</pre>}
                          </div>
                        ))}
                      </Section>
                    ) : <div className={styles.empty}>◈ Nenhum arquivo sensível exposto</div>}
                  </Card>
                  <Card title="HTTP METHODS">
                    {r.dangerousHttpMethods?.length ? (
                      <Section title={`${r.dangerousHttpMethods.length} método(s) perigoso(s)`}>
                        {r.dangerousHttpMethods.map((m, i) => (
                          <div key={i} className={styles.findingRow}>
                            <div className={styles.findingPath}><code className={styles.method}>{m.method}</code><span className={styles.muted}>HTTP {m.statusCode}</span><Tag label={m.severity} cls={sevColor(m.severity)} /></div>
                            <div className={styles.findingNote}>{m.risk}</div>
                          </div>
                        ))}
                      </Section>
                    ) : <div className={styles.empty}>◈ Nenhum método perigoso</div>}
                  </Card>
                </div>

                <div className={styles.row}>
                  <Card title="OPEN REDIRECT">
                    {r.openRedirectFindings?.filter(f => f.vulnerable).length ? (
                      <Section title="Vulnerabilidades">
                        {r.openRedirectFindings.filter(f => f.vulnerable).map((f, i) => (
                          <div key={i} className={styles.findingRow}>
                            <div className={styles.findingPath}><code>?{f.parameter}=</code><Tag label="VULNERABLE" cls={styles.critical} /></div>
                            <div className={styles.findingNote}>→ {f.redirectedTo}</div>
                          </div>
                        ))}
                      </Section>
                    ) : <div className={styles.empty}>◈ Nenhum open redirect</div>}
                  </Card>
                  <Card title="DIRECTORY LISTING">
                    {r.directoryListingFindings?.filter(f => f.listingEnabled).length ? (
                      <Section title="Diretórios expostos">
                        {r.directoryListingFindings.filter(f => f.listingEnabled).map((f, i) => (
                          <div key={i} className={styles.findingRow}>
                            <div className={styles.findingPath}><code>{f.path}</code><Tag label={f.severity} cls={sevColor(f.severity)} /></div>
                            <div className={styles.findingNote}>Evidência: {f.evidence}</div>
                          </div>
                        ))}
                      </Section>
                    ) : <div className={styles.empty}>◈ Nenhum directory listing</div>}
                  </Card>
                </div>

                <div className={styles.row}>
                  <Card title="RECONNAISSANCE">
                    <Section title="robots.txt">
                      {r.sensitiveRobotsPaths?.length ? r.sensitiveRobotsPaths.map((p, i) => (
                        <div key={i} className={styles.findingRow}><code>{p}</code><Tag label="SENSITIVE" cls={styles.warning} /></div>
                      )) : <div className={styles.empty}>◈ Nenhum path sensível</div>}
                    </Section>
                    <Section title="security.txt" defaultOpen={false}>
                      <KV label="Presente" value={boolIcon(r.securityTxtPresent)} />
                      {r.securityTxtContact && <KV label="Contact" value={<code>{r.securityTxtContact}</code>} />}
                    </Section>
                  </Card>
                  <Card title="ACTIVE CHECKS">
                    <Section title="Application Probes">
                      <KV label="Input surface" value={boolIcon(r.inputSurfaceDetected, "Detected", "—")} />
                      <KV label="XSS probe" value={boolIcon(r.xssProbePerformed, "Executed", "—")} />
                      <KV label="Reflected XSS" value={r.xssProbePerformed ? boolIcon(!r.reflectedXssSuspected, "✓ Clean", "⚠ Suspected") : <span className={styles.muted}>—</span>} />
                      <KV label="DB error leak" value={boolIcon(!r.dbErrorLeakageSuspected, "✓ Clean", "⚠ Suspected")} />
                    </Section>
                    <Section title={`Port Scan [${r.openPorts?.length ?? 0}]`} defaultOpen={false}>
                      {r.openPorts?.length ? (
                        <table className={styles.table}>
                          <thead><tr><th>Port</th><th>Service</th><th>Sev</th><th>ms</th></tr></thead>
                          <tbody>{r.openPorts.map(p => (
                            <tr key={p.port}>
                              <td><code>{p.port}</code></td><td>{p.service}</td>
                              <td><Tag label={p.severity} cls={sevColor(p.severity)} /></td>
                              <td className={styles.muted}>{p.latencyMs}</td>
                            </tr>
                          ))}</tbody>
                        </table>
                      ) : <div className={styles.empty}>Sem portas abertas</div>}
                    </Section>
                  </Card>
                </div>

                <Card title="SCORE BREAKDOWN">
                  <div className={styles.notesList}>
                    {(r.score?.notes ?? []).map((n, i) => (
                      <div key={i} className={`${styles.noteRow} ${n.includes("-") ? styles.noteMinus : styles.noteOk}`}>
                        <span>{n.includes("-") ? "▼" : "◈"}</span>{n}
                      </div>
                    ))}
                  </div>
                </Card>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}