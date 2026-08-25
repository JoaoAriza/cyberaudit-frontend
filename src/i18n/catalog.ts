/**
 * Catálogo de textos da interface.
 *
 * Espelha o messages.properties do Backend de propósito: mesma forma de chave
 * (`tela.elemento`), mesmos parâmetros `{0}`. Quem mexe nos dois lados não troca
 * de modelo mental no meio do caminho.
 *
 * Sem biblioteca de i18n: com dois idiomas e interpolação posicional, uma `t()`
 * de vinte linhas resolve o mesmo que react-i18next cobrando configuração e
 * bundle. É a mesma escolha do AuthContext, feito à mão pelo mesmo motivo.
 *
 * FORA DO ESCOPO por decisão: Termos de Uso e Política de Privacidade continuam
 * só em português. São documento jurídico — a política responde à LGPD, e uma
 * versão em inglês passaria a valer para quem a lê em inglês. Traduzir aquilo é
 * trabalho de advogado, não de quem escreve rótulo de botão.
 */

export type Lang = "pt-BR" | "en";

export const IDIOMA_PADRAO: Lang = "pt-BR";

/** Ordem é a que aparece no seletor. */
export const IDIOMAS: { code: Lang; label: string; short: string }[] = [
  { code: "pt-BR", label: "Português", short: "PT" },
  { code: "en",    label: "English",   short: "EN" },
];

const CHAVE_ARMAZENADA = "cyberaudit.lang";

/**
 * Preferência de idioma, na ordem: escolha salva → idioma do navegador → português.
 *
 * Mora aqui, e não no I18nContext, porque quem mais precisa dela é o cliente HTTP
 * — que vive fora do React. O interceptor lê a cada requisição, do mesmo jeito que
 * já lê o token. Guardar uma cópia em memória sincronizada com o provider daria
 * duas fontes para a mesma verdade, e elas divergiriam na primeira aba aberta em
 * paralelo.
 */
export function idiomaAtual(): Lang {
  const salvo = localStorage.getItem(CHAVE_ARMAZENADA);
  if (salvo && IDIOMAS.some(i => i.code === salvo)) return salvo as Lang;

  // Casa por IDIOMA, não por locale completo: en-GB recebe inglês em vez de cair
  // no português por causa da região. Mesma regra do LocaleConfig no Backend.
  const doNavegador = navigator.language?.split("-")[0];
  const suportado = IDIOMAS.find(i => i.code.split("-")[0] === doNavegador);
  return suportado ? suportado.code : IDIOMA_PADRAO;
}

export function salvarIdioma(lang: Lang) {
  localStorage.setItem(CHAVE_ARMAZENADA, lang);
}

export type Catalogo = Record<string, string>;

/**
 * Português é a base e também o fallback: chave sem tradução em outro idioma cai
 * aqui, igual ao Backend. Meia tela traduzida ainda é legível; texto vazio, não.
 */
export const pt: Catalogo = {
  "idioma.seletor": "Idioma",
  "idioma.mudarPara": "Mudar para {0}",

  // ── Vocabulário repetido em mais de uma tela ──────────────────────────────
  "comum.email": "EMAIL",
  "comum.senha": "SENHA",
  "comum.enviando": "Enviando...",
  "comum.salvando": "Salvando...",
  "comum.voltarLogin": "← Voltar ao login",
  "comum.voltarSemAuth": "← Voltar sem autenticação",
  "comum.phEmail": "seu@email.com",
  "comum.phSenha": "••••••••",

  // ── Login e cadastro ──────────────────────────────────────────────────────
  "login.entrar": "Entrar",
  "login.entrando": "Entrando...",
  "login.criarConta": "Criar conta",
  "login.criandoConta": "Criando conta...",
  "login.esqueci": "Esqueci minha senha",
  "login.credenciaisInvalidas": "Credenciais inválidas.",
  "login.erroCriarConta": "Erro ao criar conta.",
  "login.senhasNaoCoincidem": "As senhas não coincidem.",
  "login.senhaMinima": "Senha deve ter no mínimo 8 caracteres.",
  "login.precisaAceitar": "Você precisa aceitar os Termos de Uso.",
  "login.nomeCompleto": "NOME COMPLETO *",
  "login.emailObrig": "EMAIL *",
  "login.senhaObrig": "SENHA *",
  "login.confirmarSenha": "CONFIRMAR SENHA *",
  "login.phNome": "Seu nome",
  "login.phSenhaMinima": "Mínimo 8 caracteres",
  "login.phRepitaSenha": "Repita a senha",
  // Frase inteira, com os links como {0} e {1}: em inglês a ordem muda, e
  // concatenar pedaços aqui tornaria a tradução impossível. Ver fraseComLinks.
  "login.aceitoTermos": "Li e aceito os {0} e a {1}",
  "login.termosDeUso": "Termos de Uso",
  "login.politica": "Política de Privacidade",

  // ── Verificação em duas etapas ────────────────────────────────────────────
  "login.2fa.titulo": "Verificação em 2 etapas",
  "login.2fa.subEmail": "Insira o código enviado para seu email.",
  "login.2fa.subApp": "Insira o código do seu app autenticador.",
  "login.2fa.metodoApp": "📱 Autenticador",
  "login.2fa.metodoEmail": "📧 Email",
  "login.2fa.codigo": "CÓDIGO",
  "login.2fa.verificando": "Verificando...",
  "login.2fa.confirmar": "Confirmar",
  "login.2fa.reenviar": "Reenviar código por email",
  "login.2fa.reenviado": "Código reenviado para seu email.",
  "login.2fa.falhaReenviar": "Falha ao reenviar código.",
  "login.2fa.codigoInvalido": "Código inválido ou expirado.",

  // ── Esqueci a senha ───────────────────────────────────────────────────────
  "senha.esqueci.instrucao":
    "Informe o e-mail da conta. Enviaremos um link para você criar uma senha nova.",
  "senha.esqueci.enviar": "Enviar link de redefinição",
  "senha.esqueci.erro": "Não foi possível processar o pedido.",
  "senha.esqueci.enviadoTitulo": "Verifique seu e-mail",
  "senha.esqueci.enviadoTexto":
    "Se houver uma conta com este e-mail, enviamos um link de redefinição. Ele vale por 30 minutos.",

  // ── Redefinir senha ───────────────────────────────────────────────────────
  "senha.redefinir.titulo": "Redefinir senha",
  "senha.redefinir.nova": "NOVA SENHA",
  "senha.redefinir.confirme": "CONFIRME A NOVA SENHA",
  "senha.redefinir.minimo": "Mínimo de 8 caracteres.",
  "senha.redefinir.naoConferem": "As senhas não conferem.",
  "senha.redefinir.erro": "Não foi possível redefinir a senha.",
  "senha.redefinir.prontoTitulo": "Senha redefinida",
  "senha.redefinir.prontoTexto": "Use a senha nova para entrar.",
  "senha.redefinir.irLogin": "Ir para o login",

  // ── Configuração inicial (primeiro acesso da instalação) ──────────────────
  "setup.passo1": "Tipo de conta",
  "setup.passo2": "Detalhes",
  "setup.passo3": "Acesso",
  "setup.titulo": "Configuração inicial",
  "setup.subtitulo": "Escolha o tipo de conta para sua organização",
  "setup.empresa": "Empresa",
  "setup.empresaDesc": "Multi-usuário, CNPJ, domínios corporativos",
  "setup.individual": "Individual",
  "setup.individualDesc": "Uso pessoal ou profissional solo",
  "setup.continuar": "Continuar",
  "setup.continuarSeta": "Continuar →",
  "setup.voltar": "← Voltar",
  "setup.dadosEmpresa": "Dados da empresa",
  "setup.dadosProfissionais": "Dados profissionais",
  "setup.nomeEmpresa": "NOME DA EMPRESA *",
  "setup.phNomeEmpresa": "Ex: Acme Security Ltda",
  "setup.cnpj": "CNPJ *",
  "setup.dominioPrincipal": "DOMÍNIO PRINCIPAL",
  "setup.tamanhoEmpresa": "TAMANHO DA EMPRESA",
  "setup.funcionarios": "{0} funcionários",
  "setup.profissao": "PROFISSÃO",
  "setup.phProfissao": "Ex: Security Researcher",
  "setup.website": "WEBSITE / PORTFÓLIO",
  "setup.pais": "PAÍS",
  "setup.paisOutro": "Outro",
  "setup.dadosAcesso": "Dados de acesso",
  "setup.subAcesso": "Credenciais do administrador principal (OWNER)",
  "setup.phNomeCompleto": "Seu nome completo",
  "setup.phEmailAdmin": "admin@empresa.com",
  "setup.aceiteLgpd": "Li e aceito os {0} e a {1} (LGPD)",
  "setup.configurando": "Configurando...",
  "setup.finalizar": "Finalizar setup",
  "setup.erro": "Erro ao configurar o sistema.",

  // ── Aceitar convite ───────────────────────────────────────────────────────
  "convite.titulo": "Criar sua conta",
  "convite.subtitulo": "Você foi convidado. Defina sua senha para continuar.",
  "convite.nomeCompleto": "NOME COMPLETO",
  "convite.senhaMinima": "Senha deve ter no mínimo 6 caracteres.",
  "convite.phSenhaMinima": "Mínimo 6 caracteres",
  "convite.precisaAceitar": "É necessário aceitar os Termos de Uso.",
  "convite.invalido": "Convite inválido ou expirado.",
  "convite.criar": "Criar conta e entrar",
  "convite.criadaTitulo": "✓ Conta criada!",
  "convite.redirecionando": "Redirecionando para o login...",
};

export const en: Catalogo = {
  "idioma.seletor": "Language",
  "idioma.mudarPara": "Switch to {0}",

  "comum.email": "EMAIL",
  "comum.senha": "PASSWORD",
  "comum.enviando": "Sending...",
  "comum.salvando": "Saving...",
  "comum.voltarLogin": "← Back to sign in",
  "comum.voltarSemAuth": "← Continue without signing in",
  "comum.phEmail": "you@email.com",
  "comum.phSenha": "••••••••",

  "login.entrar": "Sign in",
  "login.entrando": "Signing in...",
  "login.criarConta": "Create account",
  "login.criandoConta": "Creating account...",
  "login.esqueci": "I forgot my password",
  "login.credenciaisInvalidas": "Invalid credentials.",
  "login.erroCriarConta": "Could not create the account.",
  "login.senhasNaoCoincidem": "The passwords do not match.",
  "login.senhaMinima": "Password must be at least 8 characters.",
  "login.precisaAceitar": "You need to accept the Terms of Use.",
  "login.nomeCompleto": "FULL NAME *",
  "login.emailObrig": "EMAIL *",
  "login.senhaObrig": "PASSWORD *",
  "login.confirmarSenha": "CONFIRM PASSWORD *",
  "login.phNome": "Your name",
  "login.phSenhaMinima": "At least 8 characters",
  "login.phRepitaSenha": "Repeat the password",
  "login.aceitoTermos": "I have read and accept the {0} and the {1}",
  "login.termosDeUso": "Terms of Use",
  "login.politica": "Privacy Policy",

  "login.2fa.titulo": "Two-step verification",
  "login.2fa.subEmail": "Enter the code sent to your email.",
  "login.2fa.subApp": "Enter the code from your authenticator app.",
  "login.2fa.metodoApp": "📱 Authenticator",
  "login.2fa.metodoEmail": "📧 Email",
  "login.2fa.codigo": "CODE",
  "login.2fa.verificando": "Verifying...",
  "login.2fa.confirmar": "Confirm",
  "login.2fa.reenviar": "Resend code by email",
  "login.2fa.reenviado": "Code resent to your email.",
  "login.2fa.falhaReenviar": "Could not resend the code.",
  "login.2fa.codigoInvalido": "Invalid or expired code.",

  "senha.esqueci.instrucao":
    "Enter the account email. We will send a link for you to create a new password.",
  "senha.esqueci.enviar": "Send reset link",
  "senha.esqueci.erro": "Could not process the request.",
  "senha.esqueci.enviadoTitulo": "Check your email",
  "senha.esqueci.enviadoTexto":
    "If an account exists with this email, we sent a reset link. It is valid for 30 minutes.",

  "senha.redefinir.titulo": "Reset password",
  "senha.redefinir.nova": "NEW PASSWORD",
  "senha.redefinir.confirme": "CONFIRM THE NEW PASSWORD",
  "senha.redefinir.minimo": "At least 8 characters.",
  "senha.redefinir.naoConferem": "The passwords do not match.",
  "senha.redefinir.erro": "Could not reset the password.",
  "senha.redefinir.prontoTitulo": "Password reset",
  "senha.redefinir.prontoTexto": "Use the new password to sign in.",
  "senha.redefinir.irLogin": "Go to sign in",

  "setup.passo1": "Account type",
  "setup.passo2": "Details",
  "setup.passo3": "Access",
  "setup.titulo": "Initial setup",
  "setup.subtitulo": "Choose the account type for your organisation",
  "setup.empresa": "Company",
  "setup.empresaDesc": "Multi-user, company ID, corporate domains",
  "setup.individual": "Individual",
  "setup.individualDesc": "Personal or solo professional use",
  "setup.continuar": "Continue",
  "setup.continuarSeta": "Continue →",
  "setup.voltar": "← Back",
  "setup.dadosEmpresa": "Company details",
  "setup.dadosProfissionais": "Professional details",
  "setup.nomeEmpresa": "COMPANY NAME *",
  "setup.phNomeEmpresa": "e.g. Acme Security Ltd",
  "setup.cnpj": "CNPJ *",
  "setup.dominioPrincipal": "PRIMARY DOMAIN",
  "setup.tamanhoEmpresa": "COMPANY SIZE",
  "setup.funcionarios": "{0} employees",
  "setup.profissao": "OCCUPATION",
  "setup.phProfissao": "e.g. Security Researcher",
  "setup.website": "WEBSITE / PORTFOLIO",
  "setup.pais": "COUNTRY",
  "setup.paisOutro": "Other",
  "setup.dadosAcesso": "Access details",
  "setup.subAcesso": "Credentials for the main administrator (OWNER)",
  "setup.phNomeCompleto": "Your full name",
  "setup.phEmailAdmin": "admin@company.com",
  "setup.aceiteLgpd": "I have read and accept the {0} and the {1} (LGPD)",
  "setup.configurando": "Setting up...",
  "setup.finalizar": "Finish setup",
  "setup.erro": "Could not set up the system.",

  "convite.titulo": "Create your account",
  "convite.subtitulo": "You have been invited. Set your password to continue.",
  "convite.nomeCompleto": "FULL NAME",
  "convite.senhaMinima": "Password must be at least 6 characters.",
  "convite.phSenhaMinima": "At least 6 characters",
  "convite.precisaAceitar": "You must accept the Terms of Use.",
  "convite.invalido": "Invalid or expired invitation.",
  "convite.criar": "Create account and sign in",
  "convite.criadaTitulo": "✓ Account created!",
  "convite.redirecionando": "Redirecting to sign in...",
};

const CATALOGOS: Record<Lang, Catalogo> = { "pt-BR": pt, en };

/**
 * Resolve a chave no idioma pedido.
 *
 * Chave inexistente devolve a própria chave, que aparece feia na tela. É o mesmo
 * princípio do id cru no cardápio e da chave crua no laudo: texto novo sem
 * tradução salta aos olhos em vez de sumir.
 */
export function traduzir(lang: Lang, chave: string, ...args: unknown[]): string {
  const texto = CATALOGOS[lang]?.[chave] ?? pt[chave] ?? chave;
  if (args.length === 0) return texto;
  return texto.replace(/\{(\d+)\}/g, (marca, i) => {
    const valor = args[Number(i)];
    return valor === undefined ? marca : String(valor);
  });
}
