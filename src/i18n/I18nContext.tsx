import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { idiomaAtual, salvarIdioma, traduzir } from "./catalog";
import type { Lang } from "./catalog";

interface I18nContextValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  /** t("plans.cancel") ou t("scan.restam", 3) para chave com {0}. */
  t: (chave: string, ...args: unknown[]) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(idiomaAtual);

  // O atributo lang do documento é o que leitor de tela e corretor ortográfico
  // consultam — e o que o navegador usa para decidir se oferece tradução.
  useEffect(() => { document.documentElement.lang = lang; }, [lang]);

  const setLang = useCallback((novo: Lang) => {
    salvarIdioma(novo);
    setLangState(novo);
  }, []);

  const t = useCallback(
    (chave: string, ...args: unknown[]) => traduzir(lang, chave, ...args),
    [lang]
  );

  // Sem o memo, todo render do provider entrega um objeto novo e re-renderiza a
  // árvore inteira — que é grande.
  const valor = useMemo(() => ({ lang, setLang, t }), [lang, setLang, t]);

  return <I18nContext.Provider value={valor}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n precisa estar dentro de I18nProvider");
  return ctx;
}
