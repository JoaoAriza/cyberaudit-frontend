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

  // ── Cards de Transport Security ───────────────────────────────────────────
  "card.tls.protocolo": "Protocolo TLS",
  "card.tls.protocoloDesc": "Versão do protocolo negociada na conexão HTTPS.",
  "card.tls.protocoloFraco":
    "Protocolo desatualizado. TLS 1.0/1.1 têm vulnerabilidades (POODLE, BEAST). Atualize para TLS 1.2 mínimo, preferencialmente 1.3.",
  "card.tls.protocoloOk":
    "TLS 1.2+ é aceito. TLS 1.3 é o ideal — mais rápido e sem cipher suites legadas.",
  "card.tls.cipher": "Cipher Suite",
  "card.tls.cipherDesc": "Conjunto de algoritmos de criptografia da sessão TLS.",
  "card.cert.valido": "Certificado Válido",
  "card.cert.sim": "✓ Válido",
  "card.cert.nao": "✗ Inválido",
  "card.cert.validoDesc": "Certificado emitido por CA confiável e não expirado.",
  "card.cert.validoOk": "Certificado válido e confiável pelos principais browsers.",
  "card.cert.validoRuim":
    "Certificado inválido ou expirado — browsers bloqueiam o acesso e exibem aviso de segurança.",
  "card.cert.expiracao": "Data de Expiração",
  "card.cert.expiracaoDesc": "Data em que o certificado SSL deixa de ser válido.",
  "card.cert.expiracaoDica":
    "Certificados expirados afastam usuários imediatamente. Configure renovação automática (Let's Encrypt/ACME) para evitar interrupções.",
  "card.cert.diasRestantes": "Dias Restantes",
  "card.cert.diasDesc": "Quantos dias faltam até o certificado expirar.",
  "card.cert.dias30": "Menos de 30 dias! Renove agora — se expirar, o site fica inacessível.",
  "card.cert.dias90": "Menos de 90 dias. Configure alertas de renovação para evitar esquecimento.",
  "card.cert.diasOk": "Certificado com vida útil confortável.",
  "card.atencao": "ATENÇÃO",
  "card.fraco": "FRACO",
  "card.critico": "CRÍTICO",
  "card.urgente": "URGENTE",
  "card.verDetalhes": "clique para ver detalhes ›",

  // ── Cards de DNS ──────────────────────────────────────────────────────────
  "card.dns.spfDesc": "Define quais servidores podem enviar email em nome do domínio.",
  "card.dns.spfDica": "SPF + DMARC juntos bloqueiam a maioria dos ataques de email spoofing.",
  "card.dns.dmarcDesc": "Política sobre o que fazer com emails que falham SPF/DKIM.",
  "card.dns.dmarcDica": "p=reject é o mais seguro. Inicie com p=none para monitorar antes de rejeitar.",
  "card.dns.naoDetectado": "Não detectado",
  "card.dns.dkimDesc": "Assina emails criptograficamente para provar autenticidade.",
  "card.dns.dkimDica":
    "Configure no seu servidor de email (Google Workspace, Office 365). Detecção passiva por heurística.",
  "card.dns.caa": "CAA Record",
  "card.dns.configurado": "Configurado",
  "card.dns.caaDesc": "Restringe quais CAs podem emitir certificados para o domínio.",
  "card.dns.caaDica": "Sem CAA, qualquer CA do mundo pode emitir certificados para seu domínio.",
  "card.dns.mx": "MX Records",
  "card.dns.semMx": "Sem MX",
  "card.dns.mxDesc": "Servidores responsáveis por receber email do domínio.",
  "card.dns.mxDica": "MX ausente significa que o domínio não recebe email — verifique se é intencional.",
  "card.dns.securityTxt": "Security.txt",
  "card.dns.securityTxtDesc":
    "Arquivo RFC 9116 com contato para reporte responsável de vulnerabilidades.",
  "card.dns.securityTxtDica":
    "Crie em /.well-known/security.txt para facilitar reports de pesquisadores.",
  "card.dns.robots": "robots.txt",
  "card.dns.semExposicoes": "Sem exposições",
  "card.dns.robotsDesc": "Paths sensíveis expostos em Disallow do robots.txt.",
  "card.dns.robotsDica":
    "Disallow revela rotas que você quer esconder — atacantes leem robots.txt como primeiro passo.",
  "card.dns.foraDoScoreFalha":
    "Não entrou no score: a consulta DNS não foi concluída, então não dá para afirmar que o registro falta.",
  "card.dns.foraDoScoreRecomendacao":
    "Não entrou no score: é uma recomendação, não uma falha.",
  "card.dns.riscoSpoofing": "RISCO DE EMAIL SPOOFING",

  // ── Cards de cookies ──────────────────────────────────────────────────────
  "card.cookie.semProblemas": "Nenhum problema detectado nos cookies",
  "card.cookie.httpOnlyAusente": "HttpOnly ausente",
  "card.cookie.httpOnlyTexto": "JS pode ler o cookie — XSS vira sequestro de sessão.",
  "card.cookie.secureAusente": "Secure ausente",
  "card.cookie.secureTexto": "Cookie enviado em HTTP não criptografado.",
  "card.cookie.sameSiteAusente": "SameSite ausente/None",
  "card.cookie.sameSiteTexto": "Cookie enviado em requests cross-site — risco de CSRF.",

  // ── Cards de tecnologia e CVE ─────────────────────────────────────────────
  "card.tech.vazio": "◈ Nenhuma tecnologia identificável — servidor oculta headers de versão",
  "card.tech.webServer": "Web Server",
  "card.tech.linguagemDesc": "Linguagem de programação detectada via headers ou body.",
  "card.tech.linguagemDica":
    "X-Powered-By com versão revela o stack. Remova este header em produção.",
  "card.tech.webServerDesc": "Servidor web detectado nos headers HTTP.",
  "card.tech.webServerRisco": "Header Server com versão específica facilita busca de CVEs. Oculte ou personalize o header Server em produção.",
  "card.tech.backendDesc": "Framework backend ou runtime identificado.",
  "card.tech.backendRisco": "Versões específicas podem ter CVEs públicos. Mantenha atualizado e oculte a versão nos headers.",
  "card.tech.frameworkDesc": "Framework frontend/fullstack detectado.",
  "card.tech.frameworkRisco": "Frameworks desatualizados têm CVEs conhecidos. Atualize e monitore novos releases.",
  "card.tech.cmsDesc": "CMS identificado — WordPress, Drupal, etc.",
  "card.tech.cmsRisco": "CMS são alvos frequentes por possuírem plugins com vulnerabilidades. Mantenha core e plugins atualizados.",
  "card.tech.cdnDesc": "CDN ou proxy reverso detectado.",
  "card.tech.cdnRisco": "CDNs ajudam na segurança, mas verifique que headers de segurança são aplicados na origem também.",
  "card.tech.libraryDesc": "Biblioteca JavaScript detectada no frontend.",
  "card.tech.libraryRisco": "Bibliotecas desatualizadas são visíveis para qualquer atacante. Mantenha dependências atualizadas.",
  "card.tech.evidencias": "EVIDÊNCIAS DETECTADAS",
  "card.risco": "⚠ Risco:",
  "card.cve.vazio": "Sem CVEs correlacionados — software não detectado ou servidor oculta versão",
  "card.cve.verNvd": "Ver no NVD →",

  // ── Cards de headers ──────────────────────────────────────────────────────
  "card.header.vazio": "◈ Nenhum header retornado.",
  "card.header.verDetalhes": "ver detalhes",
  "card.header.verComoCorrigir": "ver como corrigir",
  "card.header.valorRecomendado": "VALOR RECOMENDADO",
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

  "card.tls.protocolo": "TLS protocol",
  "card.tls.protocoloDesc": "Protocol version negotiated on the HTTPS connection.",
  "card.tls.protocoloFraco":
    "Outdated protocol. TLS 1.0/1.1 have known vulnerabilities (POODLE, BEAST). Move to TLS 1.2 at a minimum, ideally 1.3.",
  "card.tls.protocoloOk":
    "TLS 1.2+ is accepted. TLS 1.3 is ideal — faster and free of legacy cipher suites.",
  "card.tls.cipher": "Cipher suite",
  "card.tls.cipherDesc": "Set of encryption algorithms used for the TLS session.",
  "card.cert.valido": "Valid certificate",
  "card.cert.sim": "✓ Valid",
  "card.cert.nao": "✗ Invalid",
  "card.cert.validoDesc": "Certificate issued by a trusted CA and not expired.",
  "card.cert.validoOk": "Certificate is valid and trusted by the major browsers.",
  "card.cert.validoRuim":
    "Invalid or expired certificate — browsers block access and show a security warning.",
  "card.cert.expiracao": "Expiry date",
  "card.cert.expiracaoDesc": "The date the SSL certificate stops being valid.",
  "card.cert.expiracaoDica":
    "Expired certificates drive visitors away immediately. Set up automatic renewal (Let's Encrypt/ACME) to avoid outages.",
  "card.cert.diasRestantes": "Days left",
  "card.cert.diasDesc": "How many days until the certificate expires.",
  "card.cert.dias30": "Under 30 days! Renew now — if it expires, the site becomes unreachable.",
  "card.cert.dias90": "Under 90 days. Set up renewal alerts so it does not slip.",
  "card.cert.diasOk": "Certificate has a comfortable lifetime left.",
  "card.atencao": "ATTENTION",
  "card.fraco": "WEAK",
  "card.critico": "CRITICAL",
  "card.urgente": "URGENT",
  "card.verDetalhes": "click to see details ›",

  "card.dns.spfDesc": "Defines which servers may send email on behalf of the domain.",
  "card.dns.spfDica": "SPF and DMARC together block most email spoofing attacks.",
  "card.dns.dmarcDesc": "Policy for what to do with email that fails SPF/DKIM.",
  "card.dns.dmarcDica": "p=reject is the safest. Start with p=none to monitor before rejecting.",
  "card.dns.naoDetectado": "Not detected",
  "card.dns.dkimDesc": "Signs email cryptographically to prove authenticity.",
  "card.dns.dkimDica":
    "Configure it on your email provider (Google Workspace, Office 365). Detection here is passive and heuristic.",
  "card.dns.caa": "CAA record",
  "card.dns.configurado": "Configured",
  "card.dns.caaDesc": "Restricts which CAs may issue certificates for the domain.",
  "card.dns.caaDica": "Without CAA, any CA in the world can issue certificates for your domain.",
  "card.dns.mx": "MX records",
  "card.dns.semMx": "No MX",
  "card.dns.mxDesc": "Servers responsible for receiving email for the domain.",
  "card.dns.mxDica": "A missing MX means the domain receives no email — check whether that is intended.",
  "card.dns.securityTxt": "Security.txt",
  "card.dns.securityTxtDesc":
    "RFC 9116 file with a contact for responsible vulnerability disclosure.",
  "card.dns.securityTxtDica":
    "Create it at /.well-known/security.txt to make life easier for researchers reporting issues.",
  "card.dns.robots": "robots.txt",
  "card.dns.semExposicoes": "Nothing exposed",
  "card.dns.robotsDesc": "Sensitive paths exposed through Disallow in robots.txt.",
  "card.dns.robotsDica":
    "Disallow reveals the routes you want hidden — attackers read robots.txt as a first step.",
  "card.dns.foraDoScoreFalha":
    "Not counted in the score: the DNS lookup did not complete, so we cannot claim the record is missing.",
  "card.dns.foraDoScoreRecomendacao":
    "Not counted in the score: this is a recommendation, not a failure.",
  "card.dns.riscoSpoofing": "EMAIL SPOOFING RISK",

  "card.cookie.semProblemas": "No problem detected in the cookies",
  "card.cookie.httpOnlyAusente": "HttpOnly missing",
  "card.cookie.httpOnlyTexto": "JS can read the cookie — XSS turns into session hijacking.",
  "card.cookie.secureAusente": "Secure missing",
  "card.cookie.secureTexto": "Cookie sent over unencrypted HTTP.",
  "card.cookie.sameSiteAusente": "SameSite missing/None",
  "card.cookie.sameSiteTexto": "Cookie sent on cross-site requests — CSRF risk.",

  "card.tech.vazio": "◈ No identifiable technology — the server hides version headers",
  "card.tech.webServer": "Web server",
  "card.tech.linguagemDesc": "Programming language detected through headers or body.",
  "card.tech.linguagemDica":
    "X-Powered-By with a version reveals the stack. Remove this header in production.",
  "card.tech.webServerDesc": "Web server detected in the HTTP headers.",
  "card.tech.webServerRisco": "A Server header carrying a specific version makes CVE hunting easy. Hide or customise the Server header in production.",
  "card.tech.backendDesc": "Backend framework or runtime identified.",
  "card.tech.backendRisco": "Specific versions may have public CVEs. Keep it updated and hide the version from the headers.",
  "card.tech.frameworkDesc": "Frontend/fullstack framework detected.",
  "card.tech.frameworkRisco": "Outdated frameworks carry known CVEs. Update and watch for new releases.",
  "card.tech.cmsDesc": "CMS identified — WordPress, Drupal and the like.",
  "card.tech.cmsRisco": "A CMS is a frequent target because of vulnerable plugins. Keep core and plugins updated.",
  "card.tech.cdnDesc": "CDN or reverse proxy detected.",
  "card.tech.cdnRisco": "CDNs help with security, but check that security headers are applied at the origin too.",
  "card.tech.libraryDesc": "JavaScript library detected on the frontend.",
  "card.tech.libraryRisco": "Outdated libraries are visible to any attacker. Keep dependencies updated.",
  "card.tech.evidencias": "DETECTED EVIDENCE",
  "card.risco": "⚠ Risk:",
  "card.cve.vazio": "No correlated CVEs — software not detected, or the server hides its version",
  "card.cve.verNvd": "View on NVD →",

  "card.header.vazio": "◈ No header returned.",
  "card.header.verDetalhes": "see details",
  "card.header.verComoCorrigir": "see how to fix",
  "card.header.valorRecomendado": "RECOMMENDED VALUE",
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
