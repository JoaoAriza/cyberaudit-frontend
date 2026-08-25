import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";
import { AuthProvider } from "./context/AuthContext.tsx";
import { I18nProvider } from "./i18n/I18nContext.tsx";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {/* I18n por fora: o AuthProvider chama a API no boot, e a API precisa do
        idioma resolvido antes disso. */}
    <I18nProvider>
      <AuthProvider>
        <App />
      </AuthProvider>
    </I18nProvider>
  </StrictMode>
);