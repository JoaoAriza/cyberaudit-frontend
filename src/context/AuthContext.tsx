import { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { api, getToken, setToken, clearToken } from "../api/client";

// ── Types ─────────────────────────────────────────────────────────────────────

export type Plan = "FREE" | "PRO" | "ENTERPRISE";

export interface AccountDto {
  id: string;
  type: string;
  displayName: string;
  companyName: string | null;
  country: string | null;
  cnpj: string | null;
  plan: Plan;
  dailyScanLimit: number;       // -1 = ilimitado
  scheduledScanLimit: number;   // -1 = ilimitado
  activeScanAllowed: boolean;
  /** PRO INDIVIDUAL — scan ativo só em domínios verificados */
  activeScanOnVerifiedOnly: boolean;
  pdfExportAllowed: boolean;
  /** Notificação por e-mail do scan concluído — PRO+ */
  emailNotifyAllowed: boolean;
  /** PRO PESSOAL — PDF e e-mail só sobre domínios verificados da conta */
  reportOnVerifiedOnly: boolean;
  changesModuleAllowed: boolean;
  historyChartAllowed: boolean;
  /** Cadastrar domínio próprio — PRO ou superior */
  domainRegistrationAllowed: boolean;
  /** Relatórios da conta (auditoria, PDF executivo, página de status) — PRO+ */
  reportsModuleAllowed: boolean;
  publicStatusToken: string | null;
}
export interface UserDto {
  id: string; name: string; email: string;
  role: "OWNER" | "ADMIN" | "FREE_EMPLOYEE";
  /** Equipe da plataforma (PLATFORM_STAFF_EMAILS) — nao e o dono da conta */
  platformStaff?: boolean;
  jobTitle: string | null; country: string | null;
  /** Fuso IANA da conta; null = seguir o navegador. Ver TimeZoneSection. */
  timezone: string | null;
  /** true quando escolhido no perfil — a detecção automática não o sobrepõe. */
  timezoneManual: boolean;
  remainingScans: number | null; dailyLimit: number | null;
  account: AccountDto | null;
}
export interface TwoFactorPending {
  requires2fa: true;
  twoFactorMethods: string[];
}

export interface RegisterPayload {
  name: string;
  email: string;
  password: string;
  accountType: "INDIVIDUAL" | "COMPANY";
  companyName?: string;
  companyDomain?: string;
  companySize?: string;
  cnpj?: string;
  country?: string;
  termsAccepted: boolean;
}

interface AuthContextValue {
  user: UserDto | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<TwoFactorPending | null>;
  register: (payload: RegisterPayload) => Promise<void>;
  verify2fa: (code: string, method: string) => Promise<void>;
  resendEmailOtp: () => Promise<void>;
  /** Refaz /auth/me e reaplica o usuário — ver a implementação para o porquê. */
  refreshUser: () => Promise<void>;
  logout: () => void;
  isOwner: () => boolean;
  isAdmin: () => boolean;
  isAuthenticated: () => boolean;
}

// ── Context ───────────────────────────────────────────────────────────────────

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser]       = useState<UserDto | null>(null);
  const [loading, setLoading] = useState(true);

  // Valida token salvo ao carregar a página
  useEffect(() => {
    const token = getToken();
    if (!token) { setLoading(false); return; }

    api.get<UserDto>("/auth/me")
      .then(res => setUser(res.data))
      .catch(() => clearToken())
      .finally(() => setLoading(false));
  }, []);

  // Reage ao evento de logout (401 no interceptor)
  useEffect(() => {
    const handler = () => { setUser(null); };
    window.addEventListener("auth:logout", handler);
    return () => window.removeEventListener("auth:logout", handler);
  }, []);


  /**
   * Manda para a conta o fuso que o navegador detectou.
   *
   * Fica aqui, e não no login, porque toda entrada em sessão passa por setUser —
   * login, verificação de 2FA, registro, aceite de convite e a sessão retomada
   * pelo token guardado. Capturar no login deixaria de fora justamente a última,
   * que é a mais comum no uso diário.
   *
   * Só chama a API quando há divergência, e falha em silêncio: o fuso serve ao
   * PDF e ao agendamento, não à sessão — não é motivo para atrapalhar quem entrou.
   */
  useEffect(() => {
    if (!user || user.timezoneManual) return;
    const detectado = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (!detectado || detectado === user.timezone) return;

    api.put("/user/timezone", { timezone: detectado, manual: false })
      .then(() => setUser(u => (u ? { ...u, timezone: detectado } : u)))
      .catch(() => { /* fuso é conveniência; sessão não depende dele */ });
  }, [user?.id, user?.timezone, user?.timezoneManual]);

  const login = async (email: string, password: string): Promise<TwoFactorPending | null> => {
    const res = await api.post<{
      token: string;
      user: UserDto | null;
      requires2fa: boolean;
      twoFactorMethods: string[] | null;
    }>("/auth/login", { email, password });

    setToken(res.data.token); // pode ser pre-auth ou token completo

    if (res.data.requires2fa) {
      // Não seta user — login incompleto
      return { requires2fa: true, twoFactorMethods: res.data.twoFactorMethods ?? [] };
    }
    setUser(res.data.user!);
    return null;
  };

  const register = async (payload: RegisterPayload): Promise<void> => {
    const res = await api.post<{ token: string; user: UserDto }>("/auth/register", payload);
    setToken(res.data.token);
    setUser(res.data.user);
  };

  const verify2fa = async (code: string, method: string): Promise<void> => {
    const res = await api.post<{ token: string; user: UserDto }>(
      "/auth/2fa/verify", { code, method }
    );
    setToken(res.data.token);
    setUser(res.data.user);
  };

  const resendEmailOtp = async (): Promise<void> => {
    await api.post("/auth/2fa/send-email-otp");
  };

  /**
   * O `user` vive em memória e só era montado no login e no boot. Tudo que muda o
   * plano por fora — webhook do Mercado Pago confirmando a assinatura, cancelamento,
   * pagamento recusado que rebaixa a conta — não chegava à tela, que seguia
   * mostrando o plano antigo até um reload. Isto refaz /auth/me sob demanda.
   *
   * useCallback porque a referência é dependência de efeito em quem chama; sem ela
   * o efeito rearma a cada render do provider e vira laço.
   */
  const refreshUser = useCallback(async (): Promise<void> => {
    if (!getToken()) return;   // visitante não tem o que reconferir
    try {
      const res = await api.get<UserDto>("/auth/me");
      setUser(res.data);
    } catch {
      // 401 já dispara "auth:logout" no interceptor; qualquer outra falha só
      // mantém o que estava na tela — recarregar o plano não vale derrubar a sessão.
    }
  }, []);

  const logout = () => {
    clearToken();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{
      user, loading, login, register, verify2fa, resendEmailOtp, refreshUser, logout,
      isOwner:         () => user?.role === "OWNER",
      isAdmin:         () => user?.role === "OWNER" || user?.role === "ADMIN",
      isAuthenticated: () => user !== null,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be inside AuthProvider");
  return ctx;
}
