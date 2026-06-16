import { createContext, useContext, useEffect, useState } from "react";
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
  pdfExportAllowed: boolean;
  changesModuleAllowed: boolean;
  historyChartAllowed: boolean;
}
export interface UserDto {
  id: string; name: string; email: string;
  role: "OWNER" | "ADMIN" | "FREE_EMPLOYEE";
  jobTitle: string | null; country: string | null;
  remainingScans: number | null; dailyLimit: number | null;
  account: AccountDto | null;
}
export interface TwoFactorPending {
  requires2fa: true;
  twoFactorMethods: string[];
}

interface AuthContextValue {
  user: UserDto | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<TwoFactorPending | null>;
  verify2fa: (code: string, method: string) => Promise<void>;
  resendEmailOtp: () => Promise<void>;
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

  const logout = () => {
    clearToken();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{
      user, loading, login, verify2fa, resendEmailOtp, logout,
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