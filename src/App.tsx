import { useCallback, useEffect, useRef, useState } from "react";
import styles from "./App.module.css";
import { api } from "./api/client";
import { useAuth } from "./context/AuthContext";

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
interface DnsSecurityResult { spfPresent: boolean; spfRecord: string | null; spfPolicy: string; dmarcPresent: boolean; dmarcRecord: string | null; dmarcPolicy: string; dkimHintFound: boolean; dkimSelector: string | null; caaPresent: boolean; caaRecord: string | null; mxPresent: boolean; mxRecords: string[]; emailSpoofingRisk: string; summary: string; }
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
interface ScanResult {
  url: string; finalUrl: string; httpStatus: number; redirectsToHttps: boolean;
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

// ── Tech Badge ────────────────────────────────────────────────────────────────

function TechBadge({ label, icon }: { label: string; icon: string }) {
  return (
    <div className={styles.techBadge}>
      <span className={styles.techBadgeIcon}>{icon}</span>
      <span className={styles.techBadgeLabel}>{label}</span>
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

function IssueItem({ issue }: { issue: SecurityIssue }) {
  const [open, setOpen] = useState(false);
  const isCve = issue.id.startsWith("CVE_");
  // Extract "Ref: URL" from recommendation if present
  const refMatch = issue.recommendation.match(/Ref:\s*(https?:\/\/\S+)/);
  const refUrl   = refMatch ? refMatch[1] : null;
  const fixText  = refUrl ? issue.recommendation.replace(/\s*Ref:\s*https?:\/\/\S+/, "").trim() : issue.recommendation;
  // Extract CVE ID from title (e.g. "CVE-2021-41773 — ...")
  const cveIdMatch = issue.title.match(/^(CVE-\d{4}-\d+)/);
  const cveId = cveIdMatch ? cveIdMatch[1] : null;

  return (
    <div className={`${styles.issue} ${sevColor(issue.severity)}`}>
      <button className={styles.issueHeader} onClick={() => setOpen(o => !o)}>
        <span className={`${styles.issueSev} ${sevColor(issue.severity)}`}>{issue.severity}</span>
        {isCve && <span className={styles.issueCveBadge}>CVE</span>}
        <span className={styles.issueTitle}>{issue.title}</span>
        <span className={`${styles.chevron} ${open ? styles.chevronOpen : ""}`}>›</span>
      </button>
      {open && (
        <div className={styles.issueBody}>
          <div><span className={styles.label}>IMPACTO</span> {issue.impact}</div>
          <div>
            <span className={styles.label}>CORREÇÃO</span> {fixText}
            {refUrl && cveId && (
              <a href={refUrl} target="_blank" rel="noopener noreferrer" className={styles.issueCveLink}>
                Ver {cveId} no NVD ↗
              </a>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Terminal Loader ───────────────────────────────────────────────────────────

// ── Slow Scan Toast ───────────────────────────────────────────────────────────

function SlowScanToast({ visible }: { visible: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const checks = [
    { icon: "⬟", label: "SSL / TLS",         detail: "Handshake real + validação do certificado" },
    { icon: "⬡", label: "Security Headers",   detail: "Analisa 8+ headers na resposta HTTP" },
    { icon: "◉", label: "DNS Security",       detail: "Consultas DNS: SPF, DMARC, DKIM, CAA, MX" },
    { icon: "⟨⟩", label: "Tech Fingerprint",  detail: "Detecta stack via headers e body HTML" },
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
          width: 320, background: "#0d1219",
          border: "1px solid rgba(0,212,160,.25)", borderRadius: "var(--radius)",
          boxShadow: "0 8px 32px rgba(0,0,0,.7)",
          overflow: "hidden", animation: "fadeUp .25s ease",
        }}>
          <div style={{ height: 2, background: "linear-gradient(90deg, var(--accent), #3b9eff)" }} />
          <div style={{ padding: "12px 14px", borderBottom: "1px solid rgba(255,255,255,.06)" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text)", letterSpacing: ".5px" }}>Por que alguns checks demoram?</div>
            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>Cada módulo faz requests reais ao servidor alvo</div>
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
          background: "#0d1219",
          border: "1px solid rgba(0,212,160,.35)",
          borderLeft: "3px solid var(--accent)",
          borderRadius: "var(--radius)",
          boxShadow: "0 4px 16px rgba(0,0,0,.6)",
          cursor: "pointer", fontFamily: "var(--mono)", color: "var(--text)",
          fontSize: 11, animation: "fadeUp .3s ease",
        }}
      >
        <span style={{ color: "var(--warning)", fontSize: 13 }}>⏱</span>
        <span>Scan demorando · <span style={{ color: "var(--accent)" }}>{expanded ? "fechar" : "ver possíveis causas →"}</span></span>
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
};

// ── Module Info Modal ─────────────────────────────────────────────────────────

function ModuleInfoModal({ moduleKey, onClose }: { moduleKey: string | null; onClose: () => void }) {
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
            <div className={styles.moduleInfoSub}>Informações do módulo</div>
          </div>
          <button className={styles.moduleInfoClose} onClick={onClose}>✕</button>
        </div>
        <div className={styles.moduleInfoBody}>
          <div className={styles.moduleInfoSection}>
            <div className={styles.moduleInfoLabel}>ESCOPO DO MÓDULO</div>
            <p className={styles.moduleInfoText}>{info.what}</p>
          </div>
          <div className={styles.moduleInfoSection}>
            <div className={styles.moduleInfoLabel}>METODOLOGIA DE ANÁLISE</div>
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
      onClick={locked ? undefined : onClick}
      disabled={locked}
      tabIndex={locked ? -1 : 0}
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
            {status.remaining === 0 ? "Limite diário atingido" : `${status.remaining} scan${status.remaining !== 1 ? "s" : ""} restante${status.remaining !== 1 ? "s" : ""} hoje`}
          </div>
          <div className={styles.guestBannerSub}>{status.used}/{status.dailyLimit} utilizados · reseta meia-noite</div>
          <div className={styles.guestProgress}>
            <div className={styles.guestProgressFill} style={{ width: `${pct}%`, background: critical ? "var(--critical)" : "var(--accent)" }} />
          </div>
        </div>
      </div>
      <button className={`${styles.btn} ${styles.btnScan}`} onClick={onLogin}>Login para acesso ilimitado →</button>
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
    try { const r = await api.get("/scan/verify-check", { params: { host: state.host } }); setVerified(r.data.verified); }
    catch { setVerified(false); }
    setChecking(false);
  }
  function copy() {
    if (state.token) { navigator.clipboard.writeText(state.token); setCopied(true); setTimeout(() => setCopied(false), 2000); }
  }
  return (
    <div className={styles.ownershipCard}>
      <div className={styles.ownershipHeader}><span>⚠</span><span>VERIFICAÇÃO DE PROPRIEDADE</span></div>
      <p className={styles.ownershipText}>Scan ativo detectou riscos em <strong>{state.host}</strong>. Prove que você é o dono do domínio.</p>
      <div className={styles.ownershipSteps}>
        <div className={styles.ownershipStep}><span className={styles.stepNum}>1</span><div><div className={styles.stepTitle}>Crie o arquivo</div><code className={styles.stepCode}>https://{state.host}/.well-known/cyberaudit.txt</code></div></div>
        <div className={styles.ownershipStep}><span className={styles.stepNum}>2</span><div><div className={styles.stepTitle}>Conteúdo do arquivo</div><div className={styles.tokenRow}><code className={styles.stepCode}>{state.token ?? "—"}</code><button className={styles.copyBtn} onClick={copy}>{copied ? "✓ Copiado" : "Copiar"}</button></div></div></div>
        <div className={styles.ownershipStep}><span className={styles.stepNum}>3</span><div><div className={styles.stepTitle}>Confirme a verificação</div><div className={styles.tokenRow}><button className={styles.verifyBtn} onClick={check} disabled={checking}>{checking ? "Verificando..." : "Checar agora"}</button>{verified ? <span className={styles.ok}>✓ Verificado! Refaça o scan ativo.</span> : <span className={styles.bad}>Arquivo não encontrado ainda.</span>}</div></div></div>
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
    try { await login(email, password); onBack(); }
    catch (err: any) { setError(err?.response?.data?.message ?? err?.response?.data?.error ?? "Credenciais inválidas."); }
    finally { setLoading(false); }
  }
  return (
    <div className={styles.loginPage}>
      <div className={styles.loginCard}>
        <div className={styles.loginLogo}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div>
        <div className={styles.loginTitle}>Acesso restrito</div>
        <div className={styles.loginSub}>Entre com suas credenciais para acesso completo</div>
        <form className={styles.loginForm} onSubmit={handleSubmit}>
          <div className={styles.formGroup}><label className={styles.formLabel}>EMAIL</label><input className={styles.formInput} type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="seu@email.com" required /></div>
          <div className={styles.formGroup}><label className={styles.formLabel}>SENHA</label><input className={styles.formInput} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" required /></div>
          {error && <div className={styles.errorBox}>{error}</div>}
          <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={loading}>{loading ? "Entrando..." : "Entrar"}</button>
        </form>
        <button className={styles.backLink} onClick={onBack}>← Voltar sem autenticação</button>
      </div>
    </div>
  );
}

// ── Accept Invite Page ────────────────────────────────────────────────────────

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
    try { await api.post(`/auth/accept-invite/${token}`, { name, password }); setSuccess(true); setTimeout(() => { window.location.href = "/"; }, 2000); }
    catch (err: any) { setError(err?.response?.data?.message ?? "Convite inválido ou expirado."); }
    finally { setLoading(false); }
  }
  if (success) return (<div className={styles.loginPage}><div className={styles.loginCard}><div className={styles.loginLogo}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div><div className={styles.loginTitle} style={{ color: "var(--secure)" }}>✓ Conta criada!</div><div className={styles.loginSub}>Redirecionando para o login...</div></div></div>);
  return (
    <div className={styles.loginPage}><div className={styles.loginCard}>
      <div className={styles.loginLogo}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div>
      <div className={styles.loginTitle}>Criar sua conta</div>
      <div className={styles.loginSub}>Você foi convidado. Defina sua senha para continuar.</div>
      <form className={styles.loginForm} onSubmit={handleSubmit}>
        <div className={styles.formGroup}><label className={styles.formLabel}>NOME COMPLETO</label><input className={styles.formInput} value={name} onChange={e => setName(e.target.value)} placeholder="Seu nome" /></div>
        <div className={styles.formGroup}><label className={styles.formLabel}>SENHA *</label><input className={styles.formInput} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Mínimo 6 caracteres" required /></div>
        <div className={styles.formGroup}><label className={styles.formLabel}>CONFIRMAR SENHA *</label><input className={styles.formInput} type="password" value={confirm} onChange={e => setConfirm(e.target.value)} placeholder="Repita a senha" required /></div>
        {error && <div className={styles.errorBox}>{error}</div>}
        <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={loading}>{loading ? "Criando conta..." : "Criar conta e entrar"}</button>
      </form>
    </div></div>
  );
}

// ── Invite Item Row ───────────────────────────────────────────────────────────

function InviteItemRow({ inv, onRevoke, roleBadge }: { inv: InviteDto; onRevoke: () => void; roleBadge: (r: string) => React.ReactNode; }) {
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
            <div style={{ fontSize: 10, letterSpacing: 1, color: "var(--text-muted)", marginBottom: 6 }}>LINK DE ACEITE</div>
            {link ? (<div className={styles.tokenRow}><code className={styles.stepCode} style={{ flex: 1, fontSize: 11, wordBreak: "break-all" }}>{link}</code><button className={styles.copyBtn} onClick={copyLink}>{copied ? "✓" : "Copiar link"}</button></div>) : <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Link não disponível — recrie o convite.</span>}
          </div>
          <div style={{ display: "flex", gap: 20, fontSize: 11, color: "var(--text-dim)", flexWrap: "wrap" }}>
            <span>Convidado por: <strong style={{ color: "var(--text)" }}>{inv.invitedByName}</strong></span>
            {inv.jobTitle && <span>Cargo: <strong style={{ color: "var(--text)" }}>{inv.jobTitle}</strong></span>}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Admin Panel ───────────────────────────────────────────────────────────────

function AdminPanel() {
  const { user } = useAuth();
  const [tab, setTab] = useState<"users" | "invites">(user?.role === "OWNER" ? "users" : "invites");
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
  useEffect(() => { if (user?.role === "ADMIN") setInvRole("FREE_EMPLOYEE"); }, [user]);

  async function loadUsers() { setLoading(true); try { setUsers((await api.get<UserManagementDto[]>("/admin/users")).data); } catch {} finally { setLoading(false); } }
  async function loadInvites() { try { setInvites((await api.get<InviteDto[]>("/admin/invites")).data); } catch {} }
  async function deactivate(id: string) { if (!confirm("Desativar este usuário?")) return; try { await api.delete(`/admin/users/${id}`); loadUsers(); } catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); } }
  async function reactivate(id: string) { try { await api.put(`/admin/users/${id}/reactivate`); loadUsers(); } catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); } }
  async function changeRole(id: string, role: string) { try { await api.put(`/admin/users/${id}/role`, { role }); loadUsers(); } catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); } }
  async function revokeInvite(id: string) { if (!confirm("Revogar este convite?")) return; try { await api.delete(`/admin/invites/${id}`); loadInvites(); } catch (e: any) { alert(e?.response?.data?.message ?? "Erro"); } }
  async function sendInvite(e: React.FormEvent) {
    e.preventDefault(); setInviting(true); setInvError(null); setNewInvite(null);
    try { const r = await api.post<InviteDto>("/admin/invite", { name: invName, email: invEmail, role: invRole, jobTitle: invJob || null }); setNewInvite(r.data); setInvName(""); setInvEmail(""); setInvJob(""); loadInvites(); }
    catch (e: any) { setInvError(e?.response?.data?.message ?? "Erro ao criar convite."); }
    finally { setInviting(false); }
  }
  function copyLink() { if (!newInvite?.acceptLink) return; navigator.clipboard.writeText(window.location.origin + newInvite.acceptLink); setCopied(true); setTimeout(() => setCopied(false), 2000); }
  function roleBadge(role: string) {
    const cls = role === "OWNER" ? styles.secure : role === "ADMIN" ? styles.warning : styles.info;
    return <Tag label={role} cls={cls} />;
  }

  return (
    <div className={styles.adminPage}>
      <div className={styles.adminHeader}>
        <div className={styles.adminTitle}>◈ PAINEL ADMIN</div>
        <div className={styles.adminTabs}>
          {user?.role === "OWNER" && (<button className={`${styles.adminTab} ${tab === "users" ? styles.adminTabActive : ""}`} onClick={() => setTab("users")}>Usuários ({users.length})</button>)}
          <button className={`${styles.adminTab} ${tab === "invites" ? styles.adminTabActive : ""}`} onClick={() => setTab("invites")}>Convites ({invites.length})</button>
        </div>
      </div>
      {tab === "users" && (
        <div className={styles.adminContent}>
          <Card title="USUÁRIOS DO SISTEMA">
            {loading ? <div className={styles.empty}>Carregando...</div> : (
              <table className={styles.adminTable}>
                <thead><tr><th>Nome</th><th>Email</th><th>Role</th><th>Status</th><th>Convidado por</th><th>Ações</th></tr></thead>
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
                <div className={styles.formGroup}><label className={styles.formLabel}>NOME *</label><input className={styles.formInput} value={invName} onChange={e => setInvName(e.target.value)} placeholder="Nome completo" required /></div>
                <div className={styles.formGroup}><label className={styles.formLabel}>EMAIL *</label><input className={styles.formInput} type="email" value={invEmail} onChange={e => setInvEmail(e.target.value)} placeholder="email@empresa.com" required /></div>
                <div className={styles.formGroup}><label className={styles.formLabel}>CARGO</label><input className={styles.formInput} value={invJob} onChange={e => setInvJob(e.target.value)} placeholder="Ex: Security Analyst" /></div>
                <div className={styles.formGroup}>
                  <label className={styles.formLabel}>NÍVEL DE ACESSO *</label>
                  <div className={styles.roleOptions}>
                    {user?.role === "OWNER" && (<label className={styles.roleOption}><input type="radio" name="role" value="ADMIN" checked={invRole === "ADMIN"} onChange={() => setInvRole("ADMIN")} /><div><strong>Admin</strong><div className={styles.roleDesc}>Scan ativo + convida funcionários</div></div></label>)}
                    <label className={styles.roleOption}><input type="radio" name="role" value="FREE_EMPLOYEE" checked={invRole === "FREE_EMPLOYEE" || user?.role === "ADMIN"} onChange={() => setInvRole("FREE_EMPLOYEE")} /><div><strong>Funcionário</strong><div className={styles.roleDesc}>Scan ativo, sem gestão</div></div></label>
                  </div>
                </div>
                {invError && <div className={styles.errorBox}>{invError}</div>}
                {newInvite && (<div className={styles.inviteSuccess}><div className={styles.inviteSuccessTitle}>✓ Convite criado — expira em 48h</div><div className={styles.tokenRow}><code className={styles.stepCode}>{newInvite.acceptLink}</code><button type="button" className={styles.copyBtn} onClick={copyLink}>{copied ? "✓" : "Copiar link"}</button></div></div>)}
                <button className={`${styles.btn} ${styles.btnScan} ${styles.btnFull}`} disabled={inviting}>{inviting ? "Criando..." : "Enviar convite"}</button>
              </form>
            </Card>
            <Card title="CONVITES PENDENTES">
              {invites.length === 0 ? <div className={styles.empty}>Nenhum convite pendente.</div> : (
                <div className={styles.pendingInvites}>{invites.map(inv => (<InviteItemRow key={inv.id} inv={inv} onRevoke={() => revokeInvite(inv.id)} roleBadge={roleBadge} />))}</div>
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
  const { user, loading, logout, isAdmin, isAuthenticated } = useAuth();
  const [view, setView] = useState<View>("scan");
  const [url, setUrl] = useState("github.com");
  const [active, setActive] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [lastScanId, setLastScanId] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ownership, setOwnership] = useState<OwnershipState | null>(null);
  const [showSlowToast, setShowSlowToast] = useState(false);
  const [guestRefreshKey, setGuestRefreshKey] = useState(0);
  const [openModule, setOpenModule] = useState<string | null>(null);
  const [openModuleInfo, setOpenModuleInfo] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const slowTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => { if (user && view === "login") setView("scan"); }, [user]);
  useEffect(() => () => { pollRef.current && clearInterval(pollRef.current); }, []);

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
      const res = await api.post("/scan/async", null, { params: { url, active, refresh: true }, signal: controller.signal });
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
        } catch { stopPoll(); stopSlowTimer(); setError("Falha ao consultar status do scan. Tente novamente."); setScanLoading(false); }
      }, 2000);
    } catch (err: any) { stopSlowTimer(); handleError(err); setScanLoading(false); }
  }

  function handleError(err: any) {
    const aborted = err?.name === "CanceledError" || err?.code === "ERR_CANCELED";
    if (aborted) { setError("Scan cancelado."); return; }
    if (err?.response?.status === 401) { setError("Scan ativo requer autenticação."); setView("login"); return; }
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
        catch { setError(`PDF erro: ${text || "Erro desconhecido — verifique o log do backend"}`); }
      } else { setError(`PDF erro: ${e?.response?.status} — ${e.message}`); }
    } finally { setPdfLoading(false); }
  }

  const inviteToken = getInviteTokenFromUrl();
  if (inviteToken) return <div className={styles.app}><AcceptInvitePage token={inviteToken} /></div>;
  if (loading) return (<div className={styles.app}><div className={styles.loadingScreen}><span className={styles.logoIcon}>◈</span> Carregando...</div></div>);
  if (view === "login") return <div className={styles.app}><LoginPage onBack={() => setView("scan")} /></div>;

  const r = result;
  const risk = r?.score?.riskLevel;
  const tf = r?.techFingerprint;
  const badgeHost = (r?.finalUrl ?? r?.url ?? "").replace(/^https?:\/\//, "").split("/")[0];
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
  const takeoverVuln  = r?.subdomainTakeover?.filter(t => t.status === "VULNERABLE") ?? [];
  const takeoverColor = takeoverVuln.length > 0 ? "var(--critical)" : (r?.subdomainTakeover?.length ?? 0) > 0 ? "var(--warning)" : "var(--secure)";
  const dns           = r?.dnsSecurityResult;
  const reconProbs    = dns ? [!dns.spfPresent, !dns.dmarcPresent, !dns.caaPresent].filter(Boolean).length : 0;
  const reconColor    = reconProbs >= 2 ? "var(--critical)" : reconProbs >= 1 ? "var(--warning)" : "var(--secure)";
  const changeCount   = r?.changes?.length ?? 0;
  const changesColor  = (r?.changes ?? []).some(c => c.changeType === "DEGRADED") ? "var(--critical)" : changeCount > 0 ? "var(--warning)" : "var(--secure)";
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

  return (
    <div className={styles.app}>
      <SlowScanToast visible={showSlowToast} />

      <header className={styles.header}>
        <div className={styles.logo}><span className={styles.logoIcon}>◈</span><span className={styles.logoText}>CyberAudit</span></div>
        <nav className={styles.headerNav}>
          <button className={`${styles.navBtn} ${view === "scan" ? styles.navBtnActive : ""}`} onClick={() => setView("scan")}>Scanner</button>
          {isAdmin() && (<button className={`${styles.navBtn} ${view === "admin" ? styles.navBtnActive : ""}`} onClick={() => setView("admin")}>Admin</button>)}
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
        {!isAuthenticated() && view === "scan" && <GuestBanner onLogin={() => setView("login")} refreshKey={guestRefreshKey} />}
        {view === "admin" && isAdmin() && <AdminPanel />}

        {view === "scan" && (
          <>
            <div className={styles.scanPanel}>
              <div className={styles.scanForm}>
                <div className={styles.inputWrap}>
                  <span className={styles.inputPrefix}>https://</span>
                  <input className={styles.urlInput} value={url} onChange={e => setUrl(e.target.value)} placeholder="example.com" onKeyDown={e => e.key === "Enter" && !scanLoading && handleScan()} />
                </div>
                <div className={styles.toggles}>
                  <label className={styles.toggle} title="Apenas em domínios autorizados.">
                    <input type="checkbox" checked={active} disabled={scanLoading} onChange={e => setActive(e.target.checked)} />
                    <span className={styles.toggleLabel}>ACTIVE</span>
                  </label>
                </div>
                <div className={styles.actions}>
                  {scanLoading
                    ? <button className={`${styles.btn} ${styles.btnCancel}`} onClick={() => { abortRef.current?.abort(); stopPoll(); stopSlowTimer(); setScanLoading(false); }}>✕ Cancel</button>
                    : <button className={`${styles.btn} ${styles.btnScan}`} onClick={handleScan}>◈ Scan</button>}
                  <button className={`${styles.btn} ${styles.btnGhost}`} onClick={handlePdf} disabled={pdfLoading || scanLoading}>{pdfLoading ? "..." : "PDF"}</button>
                </div>
              </div>
              {active && <div className={styles.activeWarning}>⚠ Modo ativo: Use apenas em domínios autorizados.</div>}
              {scanLoading && <div className={styles.progressBar}><div className={styles.progressFill} /></div>}
              {error && <div className={styles.errorBox}>{error}</div>}
            </div>

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
                    <div className={styles.sidebarNavGroup}>Visão Geral</div>
                    <SidebarNavItem icon="⚠" title="Issues"
                      color={issueColor}
                      metric={issueCount === 0 ? "✓" : issueCount}
                      label={issueCount === 0 ? "SECURE" : (r.score?.issues?.[0]?.severity ?? "FOUND")}
                      active={openModule === "issues"}
                      onClick={() => setOpenModule("issues")}/>

                    <div className={styles.sidebarNavGroup}>HTTP &amp; Headers</div>
                    <SidebarNavItem icon="⬡" title="Security Headers"
                      color={headerColor}
                      metric={missingH + weakH === 0 ? "✓" : missingH + weakH}
                      label={missingH + weakH === 0 ? "SECURE" : missingH > 2 ? "CRITICAL" : "MEDIUM"}
                      active={openModule === "headers"}
                      onClick={() => setOpenModule("headers")}/>
                    <SidebarNavItem icon="⬟" title="Transport Security"
                      color={tlsColor}
                      metric={r.sslInfo?.valid ? (r.sslInfo.daysRemaining ?? "?") + "d" : "✗"}
                      label={!r.sslInfo?.valid ? "INVALID CERT" : r.tlsDetails?.weakProtocol ? "WEAK PROTOCOL" : "SECURE"}
                      active={openModule === "transport"}
                      onClick={() => setOpenModule("transport")}/>
                    <SidebarNavItem icon="⚙" title="HTTP Methods"
                      color={httpColor}
                      metric={dangerMethods.length === 0 ? "✓" : dangerMethods.length}
                      label={dangerMethods.length === 0 ? "SECURE" : "DANGEROUS"}
                      active={openModule === "http"}
                      onClick={() => setOpenModule("http")}/>
                    <SidebarNavItem icon="↪" title="Open Redirect"
                      color={redirectColor}
                      metric={redirectVuln.length === 0 ? "✓" : redirectVuln.length}
                      label={redirectVuln.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "redirect"}
                      onClick={() => setOpenModule("redirect")}/>
                    <SidebarNavItem icon="◫" title="Directory Listing"
                      color={dirColor}
                      metric={dirExposed.length === 0 ? "✓" : dirExposed.length}
                      label={dirExposed.length === 0 ? "SECURE" : "EXPOSED"}
                      active={openModule === "dirlist"}
                      onClick={() => setOpenModule("dirlist")}/>

                    <div className={styles.sidebarNavGroup}>DNS &amp; Domínio</div>
                    <SidebarNavItem icon="◉" title="Reconnaissance"
                      color={reconColor}
                      metric={dns ? `${[dns.spfPresent, dns.dmarcPresent, dns.caaPresent].filter(Boolean).length}/3` : "—"}
                      label={dns?.emailSpoofingRisk ? `SPOOFING: ${dns.emailSpoofingRisk}` : "UNKNOWN"}
                      active={openModule === "recon"}
                      onClick={() => setOpenModule("recon")}/>
                    <SidebarNavItem icon="◑" title="Cert Transparency"
                      color={certColor}
                      metric={ct ? ct.totalCertificates : "—"}
                      label={!ct ? "N/A" : ct.unexpectedIssuer ? "ISSUER ALERT" : ct.wildcardDetected ? "WILDCARD" : "INFO"}
                      active={openModule === "cert"}
                      onClick={() => setOpenModule("cert")}/>
                    <SidebarNavItem icon="◎" title="Subdomain Takeover"
                      color={takeoverColor}
                      metric={takeoverVuln.length === 0 ? "✓" : takeoverVuln.length}
                      label={takeoverVuln.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "takeover"}
                      onClick={() => setOpenModule("takeover")}/>

                    <div className={styles.sidebarNavGroup}>Aplicação</div>
                    <SidebarNavItem icon="⟨⟩" title="Technology"
                      color="var(--info)"
                      metric={techFirst}
                      label="DETECTED"
                      active={openModule === "tech"}
                      onClick={() => setOpenModule("tech")}/>
                    <SidebarNavItem icon="☰" title="Cookie Security"
                      color={cookieColor}
                      metric={cookieCount === 0 ? "✓" : cookieCount}
                      label={cookieCount === 0 ? "SECURE" : "ISSUES FOUND"}
                      active={openModule === "cookies"}
                      onClick={() => setOpenModule("cookies")}/>
                    <SidebarNavItem icon="◈" title="API Docs"
                      color={apiDocsColor}
                      metric={apiDocsCount === 0 ? "✓" : apiDocsCount}
                      label={apiDocsCount === 0 ? "SECURE" : "EXPOSED"}
                      active={openModule === "apidocs"}
                      onClick={() => setOpenModule("apidocs")}/>
                    <SidebarNavItem icon="◈" title="GraphQL"
                      color={gqlColor}
                      metric={gqlFindings.length === 0 ? "✓" : gqlFindings.length}
                      label={gqlFindings.length === 0 ? "SECURE" : gqlFindings.some(f => f.playgroundExposed) ? "PLAYGROUND" : "INTROSPECTION"}
                      active={openModule === "graphql"}
                      onClick={() => setOpenModule("graphql")}/>
                    <SidebarNavItem icon="◈" title="JWT Security"
                      color={jwtColor}
                      metric={jwtFindings.length === 0 ? "✓" : jwtFindings.length}
                      label={jwtFindings.length === 0 ? "SECURE" : jwtFindings.some(f => f.severity === "CRITICAL") ? "CRITICAL" : "ISSUES FOUND"}
                      active={openModule === "jwt"}
                      onClick={() => setOpenModule("jwt")}/>
                    <SidebarNavItem icon="◈" title="Path Traversal"
                      color={ptColor}
                      metric={ptFindings.length === 0 ? "✓" : ptFindings.length}
                      label={ptFindings.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "traversal"}
                      onClick={() => setOpenModule("traversal")}/>
                    <SidebarNavItem icon="◈" title="SSRF"
                      color={ssrfColor}
                      metric={ssrfFindings.length === 0 ? "✓" : ssrfFindings.length}
                      label={ssrfFindings.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "ssrf"}
                      onClick={() => setOpenModule("ssrf")}/>
                    <SidebarNavItem icon="◈" title="CRLF Injection"
                      color={crlfColor}
                      metric={crlfFindings.length === 0 ? "✓" : crlfFindings.length}
                      label={crlfFindings.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "crlf"}
                      onClick={() => setOpenModule("crlf")}/>
                    <SidebarNavItem icon="◈" title="Source Map/Debug"
                      color={smColor}
                      metric={smFindings.length === 0 ? "✓" : smFindings.length}
                      label={smFindings.length === 0 ? "SECURE" : smFindings.some(f => f.severity === "HIGH") ? "HIGH" : "MEDIUM"}
                      active={openModule === "sourcemap"}
                      onClick={() => setOpenModule("sourcemap")}/>
                    <SidebarNavItem icon="◈" title="Host Header"
                      color={hhColor}
                      metric={hhFindings.length === 0 ? "✓" : hhFindings.length}
                      label={hhFindings.length === 0 ? "SECURE" : "VULNERABLE"}
                      active={openModule === "hostheader"}
                      onClick={() => setOpenModule("hostheader")}/>
                    <SidebarNavItem icon="◈" title="CVE Correlation"
                      color={cveColor}
                      metric={cveCount === 0 ? "✓" : cveCount}
                      label={cveCount === 0 ? "SECURE" : maxCvss >= 9 ? "CRITICAL" : maxCvss >= 7 ? "HIGH" : maxCvss >= 4 ? "MEDIUM" : "LOW"}
                      active={openModule === "cve"}
                      onClick={() => setOpenModule("cve")}/>

                    {changeCount > 0 && (<>
                      <div className={styles.sidebarNavGroup}>Monitoramento</div>
                      <SidebarNavItem icon="△" title="Changes"
                        color={changesColor}
                        metric={changeCount}
                        label={changesColor === "var(--critical)" ? "DEGRADED" : "CHANGED"}
                        active={openModule === "changes"}
                        onClick={() => setOpenModule("changes")}/>
                    </>)}

                    <div className={styles.sidebarNavGroup}>Active</div>
                    <SidebarNavItem icon="▣" title="Active Checks"
                      color={r.activeMode ? "var(--info)" : "var(--text-muted)"}
                      metric={!r.activeMode ? "OFF" : r.wafDetectionResult?.detected ? "WAF" : `${r.openPorts?.length ?? 0}p`}
                      label={!r.activeMode ? "REQUIRES ACTIVE" : r.wafDetectionResult?.detected ? "WAF DETECTED" : "ACTIVE"}
                      locked={!r.activeMode}
                      active={openModule === "active"}
                      onClick={() => setOpenModule("active")}/>

                  </nav>

                  <ModuleInfoModal moduleKey={openModuleInfo} onClose={() => setOpenModuleInfo(null)} />

                  {/* ── Right: Overview + Content ── */}
                  <div className={styles.dashboardRight}>

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
                            <KV label="SERVER EXPOSED" value={boolIcon(!r.serverVersionExposed, "✓ Clean", "⚠ Exposed")} />
                            <div className={styles.badgePreview}>
                              <img src={badgeUrl} alt="security badge" className={styles.badgeImg} />
                            </div>
                          </div>
                        </div>
                      </Card>
                      <Card title="SCORE BREAKDOWN">
                        <div className={styles.notesList}>
                          {(r.score?.notes ?? []).map((n, i) => (
                            <div key={i} className={`${styles.noteRow} ${n.includes("-") ? styles.noteMinus : styles.noteOk}`}>
                              <span>{n.includes("-") ? "▼" : "◈"}</span>{n}
                            </div>
                          ))}
                        </div>
                      </Card>
                      <Card title="DISTRIBUIÇÃO DE SEVERIDADE">
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
                            <span>{r.score?.issues?.length ?? 0} issues totais</span>
                            <span>{(r.score?.issues ?? []).filter(i => ["CRITICAL","HIGH"].includes((i.severity ?? "").toUpperCase())).length} críticos/altos</span>
                          </div>
                        </div>
                      </Card>
                    </div>

                    <div className={styles.sidebarContent}>

                    {!openModule && (
                      <div className={styles.sidebarEmpty}>◈ Selecione um módulo para ver os detalhes</div>
                    )}

                    {openModule === "issues" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": issueColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>⚠</span>
                          <span className={styles.sidebarContentTitleText}>Issues</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("issues")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {issueCount
                          ? <div className={styles.issuesList}>{r.score.issues.map(i => <IssueItem key={i.id} issue={i} />)}</div>
                          : <div className={styles.empty}>◈ Nenhuma issue detectada</div>}
                      </>
                    )}

                    {openModule === "headers" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": headerColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>⬡</span>
                          <span className={styles.sidebarContentTitleText}>Security Headers</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("headers")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        <Section title="Headers" defaultOpen={true}>
                          {Object.entries(r.headers ?? {}).map(([k, v]) => <KV key={k} label={k} value={headerStatus(v)} />)}
                        </Section>
                      </>
                    )}

                    {openModule === "transport" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": tlsColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>⬟</span>
                          <span className={styles.sidebarContentTitleText}>Transport Security</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("transport")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        <Section title="SSL / TLS" defaultOpen={true}>
                          <KV label="Protocol"  value={<span className={r.tlsDetails?.weakProtocol ? styles.bad : styles.ok}>{r.tlsDetails?.negotiatedProtocol ?? "—"}</span>} />
                          <KV label="Cipher"    value={<code className={styles.code}>{r.tlsDetails?.cipherSuite ?? "—"}</code>} />
                          <KV label="Valid"     value={boolIcon(r.sslInfo?.valid)} />
                          <KV label="Expires"   value={r.sslInfo?.expirationDate ?? "—"} />
                          <KV label="Days left" value={<span className={(r.sslInfo?.daysRemaining ?? 0) < 30 ? styles.bad : (r.sslInfo?.daysRemaining ?? 0) < 90 ? styles.warn : styles.ok}>{r.sslInfo?.daysRemaining ?? "—"}d</span>} />
                          {r.tlsDetails?.message && <div className={styles.note}>{r.tlsDetails.message}</div>}
                        </Section>
                      </>
                    )}

                    {openModule === "tech" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": "var(--info)" } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>⟨⟩</span>
                          <span className={styles.sidebarContentTitleText}>Technology Fingerprint</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("tech")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {tf && (tf.webServer || tf.backend || tf.framework || tf.cms || tf.cdn || tf.language || (tf.libraries?.length ?? 0) > 0) ? (
                          <>
                            <div className={styles.techGrid}>
                              {tf.webServer  && <TechBadge icon="⬡"  label={`Web Server: ${tf.webServer}`} />}
                              {tf.language   && <TechBadge icon="⟨⟩" label={`Language: ${tf.language}`} />}
                              {tf.backend    && <TechBadge icon="◻"  label={`Backend: ${tf.backend}`} />}
                              {tf.framework  && <TechBadge icon="◈"  label={`Framework: ${tf.framework}`} />}
                              {tf.cms        && <TechBadge icon="▦"  label={`CMS: ${tf.cms}`} />}
                              {tf.cdn        && <TechBadge icon="◉"  label={`CDN: ${tf.cdn}`} />}
                              {tf.libraries?.map((lib, i) => <TechBadge key={i} icon="◎" label={lib} />)}
                            </div>
                            {(tf.evidence?.length ?? 0) > 0 && (
                              <Section title="Evidence" defaultOpen={false}>
                                <div className={styles.techEvidenceList}>
                                  {tf.evidence?.map((e, i) => (
                                    <div key={i} className={styles.techEvidenceItem}>
                                      <span className={styles.techEvidenceDot}>›</span>
                                      <code className={styles.code}>{e}</code>
                                    </div>
                                  ))}
                                </div>
                              </Section>
                            )}
                          </>
                        ) : <div className={styles.empty}>◈ Nenhuma tecnologia identificável — servidor oculta headers de versão</div>}
                      </>
                    )}

                    {openModule === "changes" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": changesColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>△</span>
                          <span className={styles.sidebarContentTitleText}>Changes Since Last Scan</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("changes")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
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
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("cookies")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {r.cookieIssues?.length ? (
                          <Section title={`${r.cookieIssues.length} cookie(s) com problemas`} defaultOpen={true}>
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
                      </>
                    )}

                    {openModule === "http" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": httpColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>⚙</span>
                          <span className={styles.sidebarContentTitleText}>HTTP Methods</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("http")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {r.dangerousHttpMethods?.length ? (
                          <Section title={`${r.dangerousHttpMethods.length} método(s)`} defaultOpen={true}>
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
                        ) : <div className={styles.empty}>◈ Nenhum método perigoso</div>}
                      </>
                    )}

                    {openModule === "redirect" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": redirectColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>↪</span>
                          <span className={styles.sidebarContentTitleText}>Open Redirect</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("redirect")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {redirectVuln.length ? (
                          <Section title="Vulnerabilidades detectadas" defaultOpen={true}>
                            {redirectVuln.map((f, i) => (
                              <div key={i} className={styles.findingRow}>
                                <div className={styles.findingPath}><code>?{f.parameter}=</code><Tag label="VULNERABLE" cls={styles.critical} /></div>
                                <div className={styles.findingNote}>→ {f.redirectedTo}</div>
                              </div>
                            ))}
                          </Section>
                        ) : <div className={styles.empty}>◈ Nenhum open redirect detectado</div>}
                      </>
                    )}

                    {openModule === "dirlist" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": dirColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◫</span>
                          <span className={styles.sidebarContentTitleText}>Directory Listing</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("dirlist")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {dirExposed.length ? (
                          <Section title="Diretórios expostos" defaultOpen={true}>
                            {dirExposed.map((f, i) => (
                              <div key={i} className={styles.findingRow}>
                                <div className={styles.findingPath}><code>{f.path}</code><Tag label={f.severity} cls={sevColor(f.severity)} /></div>
                                <div className={styles.findingNote}>Evidência: {f.evidence}</div>
                              </div>
                            ))}
                          </Section>
                        ) : <div className={styles.empty}>◈ Nenhum directory listing detectado</div>}
                      </>
                    )}

                    {openModule === "recon" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": reconColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◉</span>
                          <span className={styles.sidebarContentTitleText}>Reconnaissance</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("recon")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        <Section title="robots.txt" defaultOpen={true}>
                          {r.sensitiveRobotsPaths?.length ? (
                            r.sensitiveRobotsPaths.map((p, i) => (
                              <div key={i} className={styles.findingRow}>
                                <div className={styles.findingPath}><code>{p}</code><Tag label="SENSITIVE" cls={styles.warning} /></div>
                              </div>
                            ))
                          ) : <div className={styles.empty}>◈ Nenhum path sensível</div>}
                        </Section>
                        <Section title="security.txt" defaultOpen={true}>
                          <KV label="Presente" value={boolIcon(r.securityTxtPresent)} />
                          {r.securityTxtContact && <KV label="Contact" value={<code className={styles.code}>{r.securityTxtContact}</code>} />}
                          {!r.securityTxtPresent && <div className={styles.note}>Sem security.txt (RFC 9116) — dificulta reporte responsável de vulnerabilidades.</div>}
                        </Section>
                        {dns && (
                          <Section title="DNS Security" defaultOpen={true}>
                            <div style={{ marginBottom: 10 }}>
                              <Tag label={`Email Spoofing Risk: ${dns.emailSpoofingRisk}`}
                                cls={dns.emailSpoofingRisk === "LOW" ? styles.secure : dns.emailSpoofingRisk === "MEDIUM" ? styles.warning : dns.emailSpoofingRisk === "HIGH" ? styles.high : styles.critical} />
                            </div>
                            <KV label="SPF"   value={<span className={dns.spfPresent ? styles.ok : styles.bad}>{dns.spfPresent ? `✓ ${dns.spfPolicy}` : "✗ Ausente"}</span>} />
                            {dns.spfRecord   && <div className={styles.note} style={{ marginBottom: 6 }}><code className={styles.code}>{dns.spfRecord}</code></div>}
                            <KV label="DMARC" value={<span className={dns.dmarcPresent ? styles.ok : styles.bad}>{dns.dmarcPresent ? `✓ p=${dns.dmarcPolicy?.toLowerCase()}` : "✗ Ausente"}</span>} />
                            {dns.dmarcRecord && <div className={styles.note} style={{ marginBottom: 6 }}><code className={styles.code}>{dns.dmarcRecord}</code></div>}
                            <KV label="DKIM"  value={dns.dkimHintFound ? <span className={styles.ok}>✓ Seletor: {dns.dkimSelector}</span> : <span className={styles.warn}>⚠ Nenhum seletor encontrado</span>} />
                            <KV label="CAA"   value={dns.caaPresent ? <span className={styles.ok}>✓ Configurado</span> : <span className={styles.warn}>⚠ Ausente — qualquer CA pode emitir certificado</span>} />
                            {dns.caaRecord   && <div className={styles.note} style={{ marginBottom: 6 }}><code className={styles.code}>{dns.caaRecord}</code></div>}
                            <KV label="MX"    value={dns.mxPresent ? <span className={styles.ok}>✓ {dns.mxRecords?.length} servidor(es)</span> : <span className={styles.muted}>Sem servidores de email</span>} />
                            {dns.mxPresent && dns.mxRecords?.length > 0 && (
                              <div className={styles.note}>{dns.mxRecords.map((mx, i) => <div key={i}><code className={styles.code}>{mx}</code></div>)}</div>
                            )}
                            <div className={styles.note} style={{ marginTop: 8 }}>{dns.summary}</div>
                          </Section>
                        )}
                      </>
                    )}

                    {openModule === "cve" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": cveColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>CVE Correlation</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("cve")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {cveCount > 0 ? (
                          <div className={styles.cveList}>
                            {r.cveFindings.map((cve, i) => (
                              <div key={i} className={styles.cveRow}>
                                <div className={styles.cveHeader}>
                                  <a href={cve.referenceUrl} target="_blank" rel="noopener noreferrer" className={styles.cveId}>{cve.cveId}</a>
                                  <Tag label={cve.severity} cls={sevColor(cve.severity)} />
                                  <span className={styles.cveScore}>CVSS {cve.cvssScore.toFixed(1)}</span>
                                  <span className={styles.cveSoftware}>{cve.affectedSoftware}</span>
                                  <span className={styles.muted}>{cve.publishedDate}</span>
                                </div>
                                <div className={styles.cveDesc}>{cve.description}</div>
                              </div>
                            ))}
                          </div>
                        ) : <div className={styles.empty}>◈ Sem CVEs correlacionados — versão de software não detectada ou servidor oculta headers</div>}
                      </>
                    )}

                    {openModule === "apidocs" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": apiDocsColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>API Docs Exposure</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("apidocs")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {apiDocsCount > 0 ? (
                          <div className={styles.cveList}>
                            {(r?.apiDocsExposure ?? []).map((f, i) => (
                              <div key={i} className={styles.cveRow}>
                                <div className={styles.cveHeader}>
                                  <code className={styles.code}>{f.path}</code>
                                  <Tag label={f.type} cls={styles.info} />
                                  <Tag label={f.severity} cls={sevColor(f.severity)} />
                                </div>
                                <div className={styles.cveDesc}>{f.description}</div>
                                {f.evidence && <div className={styles.findingNote}><span className={styles.muted}>Evidence: </span><code className={styles.code}>{f.evidence}</code></div>}
                              </div>
                            ))}
                          </div>
                        ) : <div className={styles.empty}>◈ Nenhuma documentação de API exposta detectada</div>}
                      </>
                    )}

                    {openModule === "graphql" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": gqlColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>GraphQL Introspection</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("graphql")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {gqlFindings.length > 0 ? (
                          <div className={styles.cveList}>
                            {gqlFindings.map((f, i) => (
                              <div key={i} className={styles.cveRow}>
                                <div className={styles.cveHeader}>
                                  <code className={styles.code}>{f.endpoint}</code>
                                  <Tag label={f.severity} cls={sevColor(f.severity)} />
                                  {f.playgroundExposed && <Tag label="PLAYGROUND" cls={styles.critical} />}
                                  {f.introspectionEnabled && <Tag label="INTROSPECTION" cls={styles.warning} />}
                                  {f.typeCount > 0 && <span className={styles.muted}>{f.typeCount} tipos</span>}
                                </div>
                                {f.evidence && <div className={styles.findingNote}><code className={styles.code}>{f.evidence}</code></div>}
                              </div>
                            ))}
                          </div>
                        ) : <div className={styles.empty}>◈ Nenhum endpoint GraphQL detectado</div>}
                      </>
                    )}

                    {openModule === "jwt" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": jwtColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>JWT Security</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("jwt")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {jwtFindings.length > 0 ? (
                          <div className={styles.cveList}>
                            {jwtFindings.map((jwt, i) => (
                              <div key={i} className={styles.cveRow}>
                                <div className={styles.cveHeader}>
                                  <code className={styles.code}>{jwt.source}</code>
                                  <Tag label={jwt.severity} cls={sevColor(jwt.severity)} />
                                  <span className={styles.muted}>alg={jwt.algorithm}</span>
                                </div>
                                <div className={styles.findingPath}>
                                  <span className={jwt.hasExpiry ? (jwt.expired ? styles.bad : styles.ok) : styles.bad}>
                                    exp: {!jwt.hasExpiry ? "MISSING" : jwt.expired ? "EXPIRED" : "✓"}
                                  </span>
                                  <span className={jwt.hasIssuer ? styles.ok : styles.muted}>iss: {jwt.hasIssuer ? "✓" : "—"}</span>
                                  <span className={jwt.hasAudience ? styles.ok : styles.muted}>aud: {jwt.hasAudience ? "✓" : "—"}</span>
                                </div>
                                <div className={styles.cveDesc}>{(jwt.issues ?? []).join(" · ")}</div>
                                {jwt.evidence && <div className={styles.findingNote}><code className={styles.code}>{jwt.evidence}</code></div>}
                              </div>
                            ))}
                          </div>
                        ) : <div className={styles.empty}>◈ Nenhum JWT com problemas de segurança detectado</div>}
                      </>
                    )}

                    {openModule === "traversal" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": ptColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◈</span>
                          <span className={styles.sidebarContentTitleText}>Path Traversal / LFI</span>
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("traversal")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {ptFindings.length > 0 ? (
                          <div className={styles.cveList}>
                            {ptFindings.map((pt, i) => (
                              <div key={i} className={styles.cveRow}>
                                <div className={styles.cveHeader}>
                                  <code className={styles.code}>?{pt.parameter}=</code>
                                  <Tag label="CRITICAL" cls={styles.critical} />
                                  <span className={styles.muted}>→ {pt.target}</span>
                                </div>
                                <div className={styles.findingNote}><span className={styles.muted}>Payload: </span><code className={styles.code}>{pt.payload}</code></div>
                                {pt.evidence && <div className={styles.findingNote}><span className={styles.muted}>Evidence: </span><code className={styles.code}>{pt.evidence}</code></div>}
                              </div>
                            ))}
                          </div>
                        ) : <div className={styles.empty}>◈ Nenhum path traversal / LFI detectado</div>}
                      </>
                    )}

                                      {openModule === "ssrf" && (
                    <div>
                      <div className={styles.moduleHeader}>
                        <h2>SSRF — Server-Side Request Forgery</h2>
                        <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("ssrf")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                      </div>
                      {ssrfFindings.length > 0 ? (
                        <div className={styles.findingList}>
                          {ssrfFindings.map((ssrf, i) => (
                            <div key={i} className={styles.findingCard}>
                              <div className={styles.findingHeader}>
                                <span className={`${styles.severityBadge} ${styles.critical}`}>CRITICAL</span>
                                <span className={styles.findingTitle}>param: {ssrf.parameter}</span>
                              </div>
                              <div className={styles.findingMeta}>
                                <span><strong>Indicator:</strong> {ssrf.indicator}</span>
                                <span><strong>Payload:</strong> {ssrf.payload}</span>
                                {ssrf.evidence && <span><strong>Evidence:</strong> {ssrf.evidence}</span>}
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : <div className={styles.empty}>◈ Nenhum SSRF detectado</div>}
                    </div>
                  )}
                                                                        {openModule === "crlf" && (
                    <div>
                      <div className={styles.moduleHeader}>
                        <h2>CRLF Injection</h2>
                        <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("crlf")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                      </div>
                      {crlfFindings.length > 0 ? (
                        <div className={styles.findingList}>
                          {crlfFindings.map((crlf, i) => (
                            <div key={i} className={styles.findingCard}>
                              <div className={styles.findingHeader}>
                                <span className={`${styles.severityBadge} ${styles.high}`}>HIGH</span>
                                <span className={styles.findingTitle}>param: {crlf.parameter} [{crlf.injectionType}]</span>
                              </div>
                              <div className={styles.findingMeta}>
                                <span><strong>Payload:</strong> {crlf.payload}</span>
                                {crlf.evidence && <span><strong>Evidence:</strong> {crlf.evidence}</span>}
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : <div className={styles.empty}>◈ Nenhuma injeção CRLF detectada</div>}
                    </div>
                  )}
                  {openModule === "sourcemap" && (
                    <div>
                      <div className={styles.moduleHeader}>
                        <h2>Source Map / Debug Exposure</h2>
                        <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("sourcemap")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                      </div>
                      {smFindings.length > 0 ? (
                        <div className={styles.findingList}>
                          {smFindings.map((sm, i) => (
                            <div key={i} className={styles.findingCard}>
                              <div className={styles.findingHeader}>
                                <span className={`${styles.severityBadge} ${sm.severity === "HIGH" ? styles.high : styles.medium}`}>{sm.severity}</span>
                                <span className={styles.findingTitle}>[{sm.type}]</span>
                              </div>
                              <div className={styles.findingMeta}>
                                <span><strong>URL:</strong> {sm.url}</span>
                                {sm.evidence && <span><strong>Evidence:</strong> {sm.evidence}</span>}
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : <div className={styles.empty}>◈ Nenhum source map ou debug endpoint exposto</div>}
                    </div>
                  )}
                  {openModule === "hostheader" && (
                    <div>
                      <div className={styles.moduleHeader}>
                        <h2>Host Header Injection</h2>
                        <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("hostheader")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                      </div>
                      {hhFindings.length > 0 ? (
                        <div className={styles.findingList}>
                          {hhFindings.map((hh, i) => (
                            <div key={i} className={styles.findingCard}>
                              <div className={styles.findingHeader}>
                                <span className={`${styles.severityBadge} ${styles.high}`}>HIGH</span>
                                <span className={styles.findingTitle}>{hh.injectedHeader} → reflected in {hh.reflectionPoint}</span>
                              </div>
                              <div className={styles.findingMeta}>
                                <span><strong>Injected value:</strong> {hh.injectedValue}</span>
                                {hh.evidence && <span><strong>Evidence:</strong> {hh.evidence}</span>}
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : <div className={styles.empty}>◈ Nenhuma reflexão de Host header detectada</div>}
                    </div>
                  )}
                  {openModule === "cert" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": certColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◑</span>
                          <span className={styles.sidebarContentTitleText}>Certificate Transparency</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("cert")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {ct ? (
                          <>
                            <div className={styles.ctOverview}>
                              <div className={styles.ctStat}>
                                <span className={styles.ctStatVal}>{ct.totalCertificates}</span>
                                <span className={styles.ctStatLabel}>Certificados nos logs CT</span>
                              </div>
                              <div className={styles.ctStat}>
                                <span className={styles.ctStatVal}>{ct.uniqueSubdomains}</span>
                                <span className={styles.ctStatLabel}>Subdomínios históricos</span>
                              </div>
                              <div className={styles.ctStat}>
                                <span className={`${styles.ctStatVal} ${ct.wildcardDetected ? styles.warn : styles.ok}`}>{ct.wildcardDetected ? "⚠ Sim" : "✓ Não"}</span>
                                <span className={styles.ctStatLabel}>Wildcard (*.domínio)</span>
                              </div>
                              <div className={styles.ctStat}>
                                <span className={`${styles.ctStatVal} ${ct.recentlyIssued ? styles.warn : styles.ok}`}>{ct.recentlyIssued ? "⚠ Sim" : "—"}</span>
                                <span className={styles.ctStatLabel}>Emitido últimos 7 dias</span>
                              </div>
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
                                  <thead><tr><th>Common Name</th><th>Issuer</th><th>Válido de</th><th>Válido até</th></tr></thead>
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
                        ) : <div className={styles.empty}>◈ Não analisado</div>}
                      </>
                    )}

                    {openModule === "takeover" && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": takeoverColor } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>◎</span>
                          <span className={styles.sidebarContentTitleText}>Subdomain Takeover</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("takeover")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        {(r.subdomainTakeover?.length ?? 0) > 0 ? (
                          <div className={styles.takeoverList}>
                            {r.subdomainTakeover.map((t, i) => (
                              <div key={i} className={`${styles.takeoverRow} ${t.status === "VULNERABLE" ? styles.takeoverVulnerable : styles.takeoverPotential}`}>
                                <div className={styles.takeoverHeader}>
                                  <span className={`${styles.takeoverStatus} ${t.status === "VULNERABLE" ? styles.tsVulnerable : styles.tsPotential}`}>{t.status}</span>
                                  <Tag label={t.severity} cls={sevColor(t.severity)} />
                                  <code className={styles.code}>{t.subdomain}</code>
                                  <span className={styles.takeoverService}>via {t.service}</span>
                                </div>
                                <div className={styles.takeoverVuln}>{t.vulnerability}</div>
                                <div className={styles.takeoverCname}><span className={styles.muted}>CNAME →</span><code className={styles.code}>{t.cnameTarget}</code></div>
                                {t.evidence && <div className={styles.takeoverEvidence}>{t.evidence}</div>}
                              </div>
                            ))}
                          </div>
                        ) : <div className={styles.empty}>◈ Nenhum subdomínio vulnerável a takeover detectado</div>}
                      </>
                    )}

                    {openModule === "active" && r.activeMode && (
                      <>
                        <div className={styles.sidebarContentTitle} style={{ "--mc-color": "var(--info)" } as React.CSSProperties}>
                          <span className={styles.sidebarContentIcon}>▣</span>
                          <span className={styles.sidebarContentTitleText}>Active Checks</span>
                        
                          <button className={styles.moduleInfoTrigger} onClick={() => setOpenModuleInfo("active")} title="Saiba mais sobre este módulo">ⓘ Saiba mais</button>
                        </div>
                        <Section title="WAF Detection" defaultOpen={true}>
                          <KV label="Detectado" value={r.wafDetectionResult?.detected ? <span className={styles.ok}>✓ Sim</span> : <span className={styles.warn}>✗ Não confirmado</span>} />
                          {r.wafDetectionResult?.detected && (<>
                            <KV label="Provider"  value={<strong style={{ color: "var(--accent)" }}>{r.wafDetectionResult.provider}</strong>} />
                            <KV label="Confiança" value={<span className={r.wafDetectionResult.confidence === "HIGH" ? styles.secure : r.wafDetectionResult.confidence === "MEDIUM" ? styles.warning : styles.muted}>{r.wafDetectionResult.confidence}</span>} />
                            <KV label="Evidência" value={<code className={styles.code}>{r.wafDetectionResult.evidence}</code>} />
                          </>)}
                          <KV label="Probe" value={<span className={r.wafDetectionResult?.probeResponse === "BLOCKED" ? styles.ok : r.wafDetectionResult?.probeResponse === "PASSED" ? styles.warn : styles.muted}>{r.wafDetectionResult?.probeResponse ?? "—"}</span>} />
                          {r.wafDetectionResult?.summary && <div className={styles.note} style={{ marginTop: 8 }}>{r.wafDetectionResult.summary}</div>}
                        </Section>
                        <Section title="CORS Analysis" defaultOpen={false}>
                          {r.corsResult?.tested ? (<>
                            <KV label="Allow-Origin"   value={<code className={styles.code}>{r.corsResult.allowOriginValue}</code>} />
                            <KV label="Wildcard"        value={boolIcon(!r.corsResult.wildcardOrigin, "✓ No", "⚠ YES")} />
                            <KV label="Reflects Origin" value={boolIcon(!r.corsResult.reflectsOrigin, "✓ No", "⚠ YES")} />
                            <KV label="Credentials"     value={boolIcon(!r.corsResult.credentialsAllowed, "✓ No", "⚠ YES")} />
                            <KV label="Null Origin"     value={boolIcon(!r.corsResult.nullOriginAccepted, "✓ No", "⚠ YES")} />
                            <div className={styles.note}>{r.corsResult.message}</div>
                          </>) : <div className={styles.empty}>Probe não executado</div>}
                        </Section>
                        <Section title={`Sensitive Files${r.sensitiveFiles?.length ? ` [${r.sensitiveFiles.length}]` : ""}`} defaultOpen={false}>
                          {r.sensitiveFiles?.length ? (
                            r.sensitiveFiles.map((f, i) => (
                              <div key={i} className={styles.findingRow}>
                                <div className={styles.findingPath}>
                                  <code>{f.path}</code>
                                  <Tag label={f.exposure} cls={f.exposure === "EXPOSED" ? styles.critical : styles.warning} />
                                  <Tag label={f.severity} cls={sevColor(f.severity)} />
                                </div>
                                {f.contentPreview && <pre className={styles.preview}>{
f.contentPreview}</pre>}
                              </div>
                            ))
                          ) : <div className={styles.empty}>◈ Nenhum arquivo sensível exposto</div>}
                        </Section>
                        <Section title="Application Probes" defaultOpen={false}>
                          <>
                            <KV label="Input surface" value={boolIcon(r.inputSurfaceDetected, "Detectada", "Não detectada")} />
                            <KV label="XSS probe" value={boolIcon(r.xssProbePerformed, "Executado", "—")} />
                            <KV label="Reflected XSS" value={r.xssProbePerformed ? boolIcon(!r.reflectedXssSuspected, "✓ Clean", "⚠ Suspeito") : <span className={styles.muted}>Sem superfície de input</span>} />
                            <KV label="DB error leak" value={boolIcon(!r.dbErrorLeakageSuspected, "✓ Clean", "⚠ Suspeito")} />
                          </>
                        </Section>
                        <Section title={`Port Scan [${r.openPorts?.length ?? 0}]`} defaultOpen={false}>
                          {r.openPorts?.length ? (
                            <table className={styles.table}>
                              <thead><tr><th>Port</th><th>Service</th><th>Sev</th><th>ms</th></tr></thead>
                              <tbody>
                                {r.openPorts.map((p, i) => (
                                  <tr key={i}>
                                    <td><code>{p.port}</code></td>
                                    <td>{p.service}</td>
                                    <td><Tag label={p.severity} cls={sevColor(p.severity)} /></td>
                                    <td className={styles.muted}>{p.latencyMs}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          ) : <div className={styles.empty}>Sem portas abertas detectadas</div>}
                        </Section>
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
  );
}
