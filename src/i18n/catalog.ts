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

  // ── Navegação e header ────────────────────────────────────────────────────
  "nav.voltarInicio": "Voltar ao início",
  "nav.scanner": "Scanner",
  "nav.admin": "Admin",
  "nav.agendamentos": "Agendamentos",
  "nav.dominios": "Domínios",
  "nav.historico": "Histórico",
  "nav.seguranca": "⚙ Segurança",
  "nav.temaClaro": "Mudar para tema claro",
  "nav.temaEscuro": "Mudar para tema escuro",
  "nav.alternarTema": "Alternar tema claro/escuro",
  "nav.verPlanos": "Ver planos",
  "nav.scansRestantes": "Scans restantes hoje",
  "nav.sair": "Sair",
  "app.carregando": "Carregando...",

  // ── Painel de scan ────────────────────────────────────────────────────────
  "scan.placeholder": "example.com",
  "scan.botao": "◈ Scan",
  "scan.cancelar": "✕ Cancel",
  "scan.pdf": "PDF",
  "scan.cancelado": "Scan cancelado.",
  "scan.falhaStatus": "Falha ao consultar status do scan. Tente novamente.",
  "scan.erroDesconhecido": "Erro desconhecido — verifique o log do backend",
  "scan.activeRequerPro": "Scan ativo requer plano PRO ou superior",
  "scan.activeSoVerificados": "Scan ativo permitido apenas em domínios verificados na sua conta",
  "scan.activeDescricao": "Executa probes ativos: WAF, CORS, portas abertas e mais",
  "scan.emailRequerPro": "Receber o laudo por e-mail requer plano PRO ou superior",
  "scan.emailSoVerificados":
    "No plano Pessoal Pro, o e-mail vale apenas para domínios verificados na sua conta",
  "scan.emailDescricao": "Receber email ao concluir o scan",
  "scan.pdfRequerPro": "Exportar PDF requer plano PRO ou superior",
  "scan.pdfSoVerificados":
    "No plano Pessoal Pro, o PDF vale apenas para domínios verificados na sua conta",
  "scan.avisoModoAtivo": "⚠ Modo ativo: Use apenas em domínios autorizados.",
  // {0} é o nome da aba, destacado — frase inteira para o tradutor reordenar.
  "scan.avisoActiveVerificado":
    "⚠ Modo PRO — scan ativo restrito a domínios verificados na aba {0}",
  "scan.avisoEntregaVerificada":
    "⚠ Modo PRO — PDF e e-mail restritos a domínios verificados na aba {0}",

  // ── Cabeçalhos do resultado ───────────────────────────────────────────────
  "resultado.breakdown": "SCORE BREAKDOWN",
  "resultado.distribuicao": "DISTRIBUIÇÃO DE SEVERIDADE",
  "resultado.issuesTotais": "{0} issues totais",
  "resultado.issuesGraves": "{0} críticos/altos",
  "resultado.selecioneModulo": "◈ Selecione um módulo para ver os detalhes",
  "resultado.semIssues": "◈ Nenhuma issue detectada",
  "resultado.naoAnalisado": "◈ Não analisado",
  "resultado.saibaMais": "ⓘ Saiba mais",
  "resultado.saibaMaisTitulo": "Saiba mais sobre este módulo",
  "resultado.contestar": "⚑ Contestar",
  "resultado.contestarTitulo": "Contestar um resultado deste scan",

  // ── Grupos da barra lateral ───────────────────────────────────────────────
  "grupo.visaoGeral": "Visão Geral",
  "grupo.aplicacao": "Aplicação",
  "grupo.compliance": "Compliance",
  "grupo.monitoramento": "Monitoramento",
  "grupo.dns": "DNS & Domínio",
  "grupo.httpHeaders": "HTTP & Headers",
  "grupo.active": "Active",
  "scan.requerAuth": "Scan ativo requer autenticação.",

  // ── Selos de estado ───────────────────────────────────────────────────────
  "selo.certInvalido": "INVALID CERT",
  "selo.protocoloFraco": "WEAK PROTOCOL",
  "selo.naoVerificado": "NÃO VERIFICADO",
  "selo.issuerAlerta": "ISSUER ALERT",
  "selo.issuesEncontradas": "ISSUES FOUND",
  "selo.wafDetectado": "WAF DETECTED",
  "selo.limpo": "✓ Clean",
  "selo.exposto": "⚠ Exposed",
  "selo.presente": "✓ Presente",
  "selo.sim": "⚠ Sim",
  "selo.nao": "✓ Não",

  // ── Estados vazios por módulo ─────────────────────────────────────────────
  "vazio.httpMethods": "Nenhum método HTTP perigoso detectado",
  "vazio.openRedirect": "Nenhum open redirect detectado",
  "vazio.directoryListing": "Nenhum directory listing detectado",
  "vazio.apiDocs": "Nenhuma documentação de API exposta detectada",
  "vazio.graphql": "Nenhum endpoint GraphQL vulnerável detectado",
  "vazio.jwt": "Nenhum JWT com problemas de segurança detectado",
  "vazio.pathTraversal": "Nenhum path traversal / LFI detectado",
  "vazio.ssrf": "Nenhum SSRF detectado",
  "vazio.crlf": "Nenhuma injeção CRLF detectada",
  "vazio.sourceMap": "Nenhum source map ou debug endpoint exposto",
  "vazio.hostHeader": "Nenhuma reflexão de Host header detectada",
  "vazio.takeover": "Nenhum subdomínio vulnerável a takeover detectado",

  // ── Cabeçalhos de tabela do resultado ─────────────────────────────────────
  "col.parametro": "PARÂMETRO",
  "col.evidencia": "EVIDÊNCIA",
  "col.refletidoEm": "REFLETIDO EM",
  "col.valorInjetado": "VALOR INJETADO",
  "col.subdominio": "SUBDOMÍNIO",
  "col.servico": "SERVIÇO",
  "col.endpointGraphql": "Endpoint GraphQL exposto",

  // ── Certificate Transparency ──────────────────────────────────────────────
  "ct.certificados": "Certificados",
  "ct.subdominiosHistoricos": "Subdomínios históricos",
  "ct.emitidoRecente": "Emitido (7 dias)",
  "ct.commonName": "Common Name",
  "ct.validoDe": "Válido de",
  "ct.validoAte": "Válido até",

  // ── Páginas travadas por plano ────────────────────────────────────────────
  "trava.agendamentos": "Agendamentos são do plano PRO",
  "trava.agendamentosDesc":
    "Reexecute scans automaticamente e receba alerta quando algo mudar. Disponível a partir do plano PRO.",
  "trava.dominios": "Cadastro de domínio é do plano PRO",
  "trava.dominiosDesc":
    "Verifique a posse dos seus domínios para liberar o scan ativo e o acompanhamento contínuo. Disponível a partir do plano PRO.",
  "trava.historico": "Histórico é do plano PRO",
  "trava.historicoDesc":
    "Acompanhe a evolução do score, compare scans e veja exatamente o que mudou entre execuções. Disponível a partir do plano PRO.",
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

  "nav.voltarInicio": "Back to start",
  "nav.scanner": "Scanner",
  "nav.admin": "Admin",
  "nav.agendamentos": "Schedules",
  "nav.dominios": "Domains",
  "nav.historico": "History",
  "nav.seguranca": "⚙ Security",
  "nav.temaClaro": "Switch to light theme",
  "nav.temaEscuro": "Switch to dark theme",
  "nav.alternarTema": "Toggle light/dark theme",
  "nav.verPlanos": "View plans",
  "nav.scansRestantes": "Scans left today",
  "nav.sair": "Sign out",
  "app.carregando": "Loading...",

  "scan.placeholder": "example.com",
  "scan.botao": "◈ Scan",
  "scan.cancelar": "✕ Cancel",
  "scan.pdf": "PDF",
  "scan.cancelado": "Scan cancelled.",
  "scan.falhaStatus": "Could not check the scan status. Try again.",
  "scan.erroDesconhecido": "Unknown error — check the backend log",
  "scan.activeRequerPro": "Active scan requires the PRO plan or above",
  "scan.activeSoVerificados": "Active scan is allowed only on domains verified in your account",
  "scan.activeDescricao": "Runs active probes: WAF, CORS, open ports and more",
  "scan.emailRequerPro": "Receiving the report by email requires the PRO plan or above",
  "scan.emailSoVerificados":
    "On the Personal Pro plan, email applies only to domains verified in your account",
  "scan.emailDescricao": "Get an email when the scan finishes",
  "scan.pdfRequerPro": "Exporting a PDF requires the PRO plan or above",
  "scan.pdfSoVerificados":
    "On the Personal Pro plan, the PDF applies only to domains verified in your account",
  "scan.avisoModoAtivo": "⚠ Active mode: use only on domains you are authorised to test.",
  "scan.avisoActiveVerificado":
    "⚠ PRO mode — active scan limited to domains verified under {0}",
  "scan.avisoEntregaVerificada":
    "⚠ PRO mode — PDF and email limited to domains verified under {0}",

  "resultado.breakdown": "SCORE BREAKDOWN",
  "resultado.distribuicao": "SEVERITY DISTRIBUTION",
  "resultado.issuesTotais": "{0} issues total",
  "resultado.issuesGraves": "{0} critical/high",
  "resultado.selecioneModulo": "◈ Select a module to see the details",
  "resultado.semIssues": "◈ No issue detected",
  "resultado.naoAnalisado": "◈ Not analysed",
  "resultado.saibaMais": "ⓘ Learn more",
  "resultado.saibaMaisTitulo": "Learn more about this module",
  "resultado.contestar": "⚑ Dispute",
  "resultado.contestarTitulo": "Dispute a result from this scan",

  "grupo.visaoGeral": "Overview",
  "grupo.aplicacao": "Application",
  "grupo.compliance": "Compliance",
  "grupo.monitoramento": "Monitoring",
  "grupo.dns": "DNS & Domain",
  "grupo.httpHeaders": "HTTP & Headers",
  "grupo.active": "Active",
  "scan.requerAuth": "Active scan requires authentication.",

  "selo.certInvalido": "INVALID CERT",
  "selo.protocoloFraco": "WEAK PROTOCOL",
  "selo.naoVerificado": "UNVERIFIED",
  "selo.issuerAlerta": "ISSUER ALERT",
  "selo.issuesEncontradas": "ISSUES FOUND",
  "selo.wafDetectado": "WAF DETECTED",
  "selo.limpo": "✓ Clean",
  "selo.exposto": "⚠ Exposed",
  "selo.presente": "✓ Present",
  "selo.sim": "⚠ Yes",
  "selo.nao": "✓ No",

  "vazio.httpMethods": "No dangerous HTTP method detected",
  "vazio.openRedirect": "No open redirect detected",
  "vazio.directoryListing": "No directory listing detected",
  "vazio.apiDocs": "No exposed API documentation detected",
  "vazio.graphql": "No vulnerable GraphQL endpoint detected",
  "vazio.jwt": "No JWT with security problems detected",
  "vazio.pathTraversal": "No path traversal / LFI detected",
  "vazio.ssrf": "No SSRF detected",
  "vazio.crlf": "No CRLF injection detected",
  "vazio.sourceMap": "No source map or debug endpoint exposed",
  "vazio.hostHeader": "No Host header reflection detected",
  "vazio.takeover": "No subdomain vulnerable to takeover detected",

  "col.parametro": "PARAMETER",
  "col.evidencia": "EVIDENCE",
  "col.refletidoEm": "REFLECTED IN",
  "col.valorInjetado": "INJECTED VALUE",
  "col.subdominio": "SUBDOMAIN",
  "col.servico": "SERVICE",
  "col.endpointGraphql": "Exposed GraphQL endpoint",

  "ct.certificados": "Certificates",
  "ct.subdominiosHistoricos": "Historical subdomains",
  "ct.emitidoRecente": "Issued (7 days)",
  "ct.commonName": "Common Name",
  "ct.validoDe": "Valid from",
  "ct.validoAte": "Valid until",

  "trava.agendamentos": "Schedules are a PRO feature",
  "trava.agendamentosDesc":
    "Re-run scans automatically and get an alert when something changes. Available from the PRO plan.",
  "trava.dominios": "Domain registration is a PRO feature",
  "trava.dominiosDesc":
    "Verify ownership of your domains to unlock active scanning and continuous monitoring. Available from the PRO plan.",
  "trava.historico": "History is a PRO feature",
  "trava.historicoDesc":
    "Track how the score evolves, compare scans and see exactly what changed between runs. Available from the PRO plan.",
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
