import axios from "axios";

const TOKEN_KEY = "cyberaudit.token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(t: string) {
  localStorage.setItem(TOKEN_KEY, t);
}
export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? "http://localhost:8081",
  timeout: 0,
});

// Injeta token em todo request automaticamente
api.interceptors.request.use(config => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// 401 → limpa token e dispara evento para o contexto reagir
api.interceptors.response.use(
  res => res,
  err => {
    if (err?.response?.status === 401) {
      clearToken();
      window.dispatchEvent(new Event("auth:logout"));
    }
    return Promise.reject(err);
  }
);