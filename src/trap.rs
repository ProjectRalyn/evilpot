use crate::persona::PrebakedPersona;
use serde::{Deserialize, Serialize};

/// Standardized attack categories understood by `evilpot` when the upstream caller
/// (such as Exposure's WAF or `evilpot-forefront`) diverts a detected attack request.
///
/// Includes the 12 `sigil-filter` heuristic categories plus common structural HTTP probes
/// (WordPress/CMS, Secret Leaks, API/GraphQL Discovery, Tarpit Archives, Scanner User-Agents).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttackCategory {
    SqlInjection,
    PathTraversal,
    CommandInjection,
    Ssrf,
    Ssti,
    NoSqlInjection,
    Xxe,
    Deserialization,
    LdapInjection,
    Xss,
    CrlfInjection,
    BufferOverflow,
    WordPressProbe,
    SecretLeakProbe,
    ApiDiscoveryProbe,
    TarpitArchiveProbe,
    ScannerUserAgent,
    GenericSuspicious,
}

impl AttackCategory {
    /// Parse a string category label (such as Exposure's `WafFinding.category`, e.g. `"sql-injection"`,
    /// `"path-traversal"`, `"command-injection"`, `"deserialization"`, etc.) into an [`AttackCategory`].
    pub fn from_label(label: &str) -> Self {
        match label.trim().to_ascii_lowercase().as_str() {
            "sql-injection" | "sqli" | "sql_injection" => Self::SqlInjection,
            "path-traversal" | "lfi" | "path_traversal" => Self::PathTraversal,
            "command-injection" | "cmdi" | "rce" | "command_injection" => Self::CommandInjection,
            "ssrf" => Self::Ssrf,
            "ssti" | "ssti-and-code-injection" | "code-injection" => Self::Ssti,
            "nosql-injection" | "nosqli" | "nosql_injection" => Self::NoSqlInjection,
            "xxe" | "xxe-and-xml-injection" | "xml-injection" => Self::Xxe,
            "deserialization"
            | "deserialization-and-prototype-pollution"
            | "jndi"
            | "log4shell"
            | "prototype-pollution" => Self::Deserialization,
            "ldap-injection" | "ldapi" | "ldap_injection" => Self::LdapInjection,
            "xss" => Self::Xss,
            "crlf-injection" | "crlf" | "header-injection" => Self::CrlfInjection,
            "buffer-overflow" | "overflow" | "buffer_overflow" => Self::BufferOverflow,
            "wordpress" | "wordpress-probe" | "cms" => Self::WordPressProbe,
            "secret-leak" | "dotenv" | "git-config" => Self::SecretLeakProbe,
            "api-discovery" | "graphql" | "openapi" => Self::ApiDiscoveryProbe,
            "tarpit" | "tarpit-archive" | "archive" => Self::TarpitArchiveProbe,
            "scanner" | "scanner-ua" => Self::ScannerUserAgent,
            _ => Self::GenericSuspicious,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SqlInjection => "sql-injection",
            Self::PathTraversal => "path-traversal",
            Self::CommandInjection => "command-injection",
            Self::Ssrf => "ssrf",
            Self::Ssti => "ssti",
            Self::NoSqlInjection => "nosql-injection",
            Self::Xxe => "xxe",
            Self::Deserialization => "deserialization",
            Self::LdapInjection => "ldap-injection",
            Self::Xss => "xss",
            Self::CrlfInjection => "crlf-injection",
            Self::BufferOverflow => "buffer-overflow",
            Self::WordPressProbe => "wordpress-probe",
            Self::SecretLeakProbe => "secret-leak-probe",
            Self::ApiDiscoveryProbe => "api-discovery-probe",
            Self::TarpitArchiveProbe => "tarpit-archive-probe",
            Self::ScannerUserAgent => "scanner-user-agent",
            Self::GenericSuspicious => "generic-suspicious",
        }
    }
}

/// Signal passed by the caller (e.g., Exposure WAF or `evilpot-forefront`) into `evilpot`
/// when diverting a request into the honeypot.
///
/// `evilpot` does NOT perform WAF detection itself — it takes this signal and the HTTP request
/// context to synthesize a realistic, exploitable trap response and verify whether the attacker
/// actively exploits the vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSignal {
    /// Primary attack category identified by the caller's WAF / detector.
    pub category: AttackCategory,
    /// Where the caller detected the attack (`"path"`, `"query"`, `"body"`, `"header:user-agent"`, etc.).
    pub location: String,
    /// Confidence score `[0.0, 1.0]` reported by the caller's detector.
    pub confidence: f32,
    /// Optional raw matched payload sample (e.g. the query param, body snippet, or header value)
    /// used by `evilpot` to extract SQLMap char probes, RCE shell commands, or LFI target files.
    pub matched_payload: Option<String>,
    /// Optional heuristic rule reasons from the caller.
    pub reasons: Vec<String>,
    /// Optional explicit trap override if the caller wants a specific trap regardless of category.
    pub explicit_trap: Option<TrapVerdict>,
}

impl AttackSignal {
    pub fn new(category: AttackCategory, location: impl Into<String>, confidence: f32) -> Self {
        Self {
            category,
            location: location.into(),
            confidence,
            matched_payload: None,
            reasons: Vec::new(),
            explicit_trap: None,
        }
    }

    /// Construct an [`AttackSignal`] directly from an Exposure-style WAF finding
    /// (`category` label, `location`, `confidence`, and `reasons`).
    pub fn from_waf_finding(
        category_label: &str,
        location: impl Into<String>,
        confidence: f32,
        reasons: Vec<String>,
    ) -> Self {
        Self {
            category: AttackCategory::from_label(category_label),
            location: location.into(),
            confidence,
            matched_payload: None,
            reasons,
            explicit_trap: None,
        }
    }

    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.matched_payload = Some(payload.into());
        self
    }

    pub fn with_reasons(mut self, reasons: Vec<String>) -> Self {
        self.reasons = reasons;
        self
    }

    pub fn with_explicit_trap(mut self, trap: TrapVerdict) -> Self {
        self.explicit_trap = Some(trap);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TarpitKind {
    GzipSqlBackup,
    JavaHprof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LfiTargetHint {
    EtcPasswd,
    EtcShadow,
    EtcHostname,
    EtcHosts,
    EtcGroup,
    EtcIssue,
    EtcOsRelease,
    EtcResolvConf,
    EtcSshdConfig,
    EtcNginxConf,
    EtcCrontab,
    ProcVersion,
    ProcCmdline,
    ProcCpuInfo,
    ProcMemInfo,
    ProcSelfEnviron,
    ProcSelfCmdline,
    DotEnv,
    WpConfig,
    GitConfig,
    GitHead,
    AwsCredentials,
    KubeConfig,
    SshPrivateKey,
    SshAuthorizedKeys,
    Htaccess,
    WebXml,
    WinIni,
    BootIni,
    UnknownFile,
}

/// Specific deception trap response selected by `evilpot` for an [`AttackSignal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrapVerdict {
    /// Attacker replayed an implanted canary token, cookie, or secret vault export endpoint!
    CanaryVaultExport { trigger: String },
    /// Fake WordPress login page (`GET` renders login form, `POST` delays + returns authentic WP error).
    WordPressLogin { is_post_attempt: bool },
    /// Fake `/wp-json/` REST root discovery document.
    WordPressRestIndex,
    /// Fake `/wp-json/wp/v2/users` enumeration response.
    WordPressUsersJson,
    /// Fake `/wp-json/wp/v2/posts` internal runbook leak response.
    WordPressPostsJson,
    /// Fake `/xmlrpc.php` response with artificial delay.
    WordPressXmlRpc,
    /// Fake `/wp-config.php.bak` or `.wp-config.php.swp` backup leak.
    WordPressConfigBackup,
    /// Fake `/wp-content/debug.log` PHP stack trace & credential leak.
    WordPressDebugLog,
    /// Fake `/wp-admin/admin-ajax.php` plugin AJAX response.
    WordPressAdminAjax,
    /// Fake `/readme.html` WordPress version disclosure page.
    WordPressReadme,
    /// Fake `.env` credentials leak.
    DotEnvLeak,
    /// Fake `.git/config` repository credentials leak.
    GitConfigLeak,
    /// Fake `.git/HEAD` ref leak.
    GitHeadLeak,
    /// Fake Spring Boot `/actuator/env` configuration leak.
    SpringActuatorEnv,
    /// Fake `phpinfo()` diagnostic page leaking environment variables.
    PhpInfo,
    /// Fake GraphQL introspection schema with bait fields.
    GraphqlIntrospection,
    /// Fake OpenAPI / Swagger JSON specification.
    OpenApiSchema,
    /// Fake debug endpoint leaking session previews and Canary URLs.
    ApiDebugEndpoint,
    /// SQL injection syntax error response (MySQL or PostgreSQL flavor).
    SqlInjectionError { is_postgres: bool },
    /// Boolean-based blind SQL injection response (True vs False page variants).
    SqlInjectionBoolean {
        truthy: bool,
        extracted_pos: Option<usize>,
    },
    /// Time-based blind SQL injection response with tarpit delay.
    SqlInjectionTimeBlind { delay_ms: u64 },
    /// Endless / huge archive drip-feed stream (`Content-Length: 256MB`, dripped at a few bytes/sec).
    TarpitStream { kind: TarpitKind },
    /// Path Traversal / LFI (`../`, `%252e%252e`, `php://filter`) -> serves persona's fake OS file.
    PathTraversalLfi {
        target: LfiTargetHint,
        confidence_pct: u8,
    },
    /// OS Command Injection (`; id`, `$(whoami)`, `| uname -a`) -> executes in stateful `FakeShellSession`!
    CommandInjectionRce {
        extracted_cmd: String,
        confidence_pct: u8,
    },
    /// SSRF (`169.254.169.254`, `gopher://`, `http://127.0.0.1`) -> serves rotating AWS IMDSv1 credentials JSON.
    SsrfCloudMetadata { confidence_pct: u8 },
    /// SSTI / Code Injection (`{{7*7}}`, `__globals__`, `Runtime.exec`) -> serves evaluated `49` + Flask config bait.
    SstiTemplateEval { confidence_pct: u8 },
    /// NoSQL Injection (`$ne`, `$where`, Mongo/Redis injection) -> serves fake MongoDB admin document array.
    NoSqlAdminDump { confidence_pct: u8 },
    /// XXE / XML / XPath Injection -> serves SOAP XML reflecting fake `/etc/passwd`.
    XxeEntityLeak { confidence_pct: u8 },
    /// Log4Shell / JNDI / Deserialization / Prototype Pollution (`${jndi:ldap://...}`, `rO0AB`, `__proto__`).
    DeserializationJndiTrap { confidence_pct: u8 },
    /// LDAP Injection -> serves fake LDIF directory dump with SSHA password hash.
    LdapDirectoryDump { confidence_pct: u8 },
    /// XSS -> serves page reflecting the attacker's payload verbatim with bait non-HttpOnly session cookie.
    XssBaitPage {
        confidence_pct: u8,
        reflected_payload: String,
    },
    /// CRLF / HTTP Header Injection -> serves fake internal proxy header debug output.
    CrlfProxyDebug { confidence_pct: u8 },
}

/// Select the most realistic [`TrapVerdict`] for a caller-provided [`AttackSignal`] and request context.
pub fn select_trap_for_signal(
    signal: &AttackSignal,
    method: &str,
    path: &str,
    query: Option<&str>,
    persona: &PrebakedPersona,
    default_sqli_delay_ms: u64,
) -> TrapVerdict {
    if let Some(ref explicit) = signal.explicit_trap {
        return explicit.clone();
    }

    let confidence_pct = (signal.confidence * 100.0).round().clamp(0.0, 100.0) as u8;
    let path_lower = path.to_ascii_lowercase();
    let raw_sample = signal
        .matched_payload
        .as_deref()
        .or(query)
        .unwrap_or(path);
    let decoded_sample = percent_decode_lossy(raw_sample);
    let sample_upper = decoded_sample.to_ascii_uppercase();
    let sample_lower = decoded_sample.to_ascii_lowercase();

    match signal.category {
        AttackCategory::SqlInjection => {
            if let Some(verdict) =
                refine_sqli_verdict(&decoded_sample, &sample_upper, persona, default_sqli_delay_ms)
            {
                return verdict;
            }
            // Also check query if matched_payload was only a single token
            if let Some(q) = query {
                let dec_q = percent_decode_lossy(q);
                let up_q = dec_q.to_ascii_uppercase();
                if let Some(verdict) =
                    refine_sqli_verdict(&dec_q, &up_q, persona, default_sqli_delay_ms)
                {
                    return verdict;
                }
            }
            TrapVerdict::SqlInjectionError {
                is_postgres: persona.slot_id % 2 == 1,
            }
        }
        AttackCategory::PathTraversal => {
            let target = select_lfi_target(&sample_lower, &path_lower);
            TrapVerdict::PathTraversalLfi {
                target,
                confidence_pct,
            }
        }
        AttackCategory::CommandInjection => {
            let extracted_cmd = extract_injected_command(&decoded_sample);
            TrapVerdict::CommandInjectionRce {
                extracted_cmd,
                confidence_pct,
            }
        }
        AttackCategory::Ssrf => TrapVerdict::SsrfCloudMetadata { confidence_pct },
        AttackCategory::Ssti => TrapVerdict::SstiTemplateEval { confidence_pct },
        AttackCategory::NoSqlInjection => TrapVerdict::NoSqlAdminDump { confidence_pct },
        AttackCategory::Xxe => TrapVerdict::XxeEntityLeak { confidence_pct },
        AttackCategory::Deserialization => TrapVerdict::DeserializationJndiTrap { confidence_pct },
        AttackCategory::LdapInjection => TrapVerdict::LdapDirectoryDump { confidence_pct },
        AttackCategory::Xss => {
            let reflected_payload = extract_xss_reflection(signal, query, path);
            TrapVerdict::XssBaitPage {
                confidence_pct,
                reflected_payload,
            }
        }
        AttackCategory::CrlfInjection => TrapVerdict::CrlfProxyDebug { confidence_pct },
        AttackCategory::BufferOverflow | AttackCategory::TarpitArchiveProbe => {
            let kind = if path_lower.contains("heapdump") || path_lower.ends_with(".hprof") {
                TarpitKind::JavaHprof
            } else {
                TarpitKind::GzipSqlBackup
            };
            TrapVerdict::TarpitStream { kind }
        }
        AttackCategory::WordPressProbe => select_wordpress_trap(method, &path_lower, &sample_upper),
        AttackCategory::SecretLeakProbe => select_secret_leak_trap(&path_lower),
        AttackCategory::ApiDiscoveryProbe => select_api_trap(&path_lower),
        AttackCategory::ScannerUserAgent | AttackCategory::GenericSuspicious => {
            // Check if the path itself hints at a specific decoy surface
            if path_lower.contains("wp-") || path_lower.ends_with("xmlrpc.php") {
                select_wordpress_trap(method, &path_lower, &sample_upper)
            } else if path_lower.contains(".env")
                || path_lower.contains(".git")
                || path_lower.contains("actuator")
                || path_lower.contains("phpinfo")
            {
                select_secret_leak_trap(&path_lower)
            } else if path_lower.contains("graphql")
                || path_lower.contains("swagger")
                || path_lower.contains("openapi")
            {
                select_api_trap(&path_lower)
            } else {
                TrapVerdict::ApiDebugEndpoint
            }
        }
    }
}

fn select_wordpress_trap(method: &str, path_lower: &str, query_upper: &str) -> TrapVerdict {
    if path_lower.contains("wp-config") {
        TrapVerdict::WordPressConfigBackup
    } else if path_lower.ends_with("debug.log") {
        TrapVerdict::WordPressDebugLog
    } else if path_lower.ends_with("admin-ajax.php") {
        TrapVerdict::WordPressAdminAjax
    } else if path_lower.ends_with("readme.html") || path_lower.ends_with("wlwmanifest.xml") {
        TrapVerdict::WordPressReadme
    } else if path_lower.contains("/wp-json/wp/v2/users")
        || query_upper.contains("REST_ROUTE=/WP/V2/USERS")
        || query_upper.starts_with("AUTHOR=")
    {
        TrapVerdict::WordPressUsersJson
    } else if path_lower.contains("/wp-json/wp/v2/posts")
        || path_lower.contains("/wp-json/wp/v2/pages")
        || query_upper.contains("REST_ROUTE=/WP/V2/POSTS")
    {
        TrapVerdict::WordPressPostsJson
    } else if path_lower == "/wp-json"
        || path_lower == "/wp-json/"
        || query_upper.starts_with("REST_ROUTE=/")
    {
        TrapVerdict::WordPressRestIndex
    } else if path_lower.ends_with("xmlrpc.php") {
        TrapVerdict::WordPressXmlRpc
    } else {
        TrapVerdict::WordPressLogin {
            is_post_attempt: method.eq_ignore_ascii_case("POST"),
        }
    }
}

fn select_secret_leak_trap(path_lower: &str) -> TrapVerdict {
    if path_lower.ends_with("/.git/config") {
        TrapVerdict::GitConfigLeak
    } else if path_lower.ends_with("/.git/head") {
        TrapVerdict::GitHeadLeak
    } else if path_lower.contains("actuator") {
        TrapVerdict::SpringActuatorEnv
    } else if path_lower.contains("phpinfo") || path_lower == "/info.php" {
        TrapVerdict::PhpInfo
    } else {
        TrapVerdict::DotEnvLeak
    }
}

fn select_api_trap(path_lower: &str) -> TrapVerdict {
    if path_lower.contains("graphql") {
        TrapVerdict::GraphqlIntrospection
    } else if path_lower.contains("swagger")
        || path_lower.contains("openapi")
        || path_lower.contains("api-docs")
    {
        TrapVerdict::OpenApiSchema
    } else {
        TrapVerdict::ApiDebugEndpoint
    }
}

fn select_lfi_target(sample_lower: &str, path_lower: &str) -> LfiTargetHint {
    let hay = format!("{path_lower} {sample_lower}");
    if hay.contains("shadow") {
        LfiTargetHint::EtcShadow
    } else if hay.contains("passwd") {
        LfiTargetHint::EtcPasswd
    } else if hay.contains("sshd_config") {
        LfiTargetHint::EtcSshdConfig
    } else if hay.contains("nginx.conf") {
        LfiTargetHint::EtcNginxConf
    } else if hay.contains("hostname") {
        LfiTargetHint::EtcHostname
    } else if hay.contains("/etc/hosts") || hay.ends_with("hosts") {
        LfiTargetHint::EtcHosts
    } else if hay.contains("/etc/group") {
        LfiTargetHint::EtcGroup
    } else if hay.contains("os-release") {
        LfiTargetHint::EtcOsRelease
    } else if hay.contains("resolv.conf") {
        LfiTargetHint::EtcResolvConf
    } else if hay.contains("/etc/issue") {
        LfiTargetHint::EtcIssue
    } else if hay.contains("crontab") {
        LfiTargetHint::EtcCrontab
    } else if hay.contains("proc/self/environ") || hay.contains("environ") {
        LfiTargetHint::ProcSelfEnviron
    } else if hay.contains("proc/self/cmdline") {
        LfiTargetHint::ProcSelfCmdline
    } else if hay.contains("proc/cmdline") {
        LfiTargetHint::ProcCmdline
    } else if hay.contains("proc/version") {
        LfiTargetHint::ProcVersion
    } else if hay.contains("proc/cpuinfo") {
        LfiTargetHint::ProcCpuInfo
    } else if hay.contains("proc/meminfo") {
        LfiTargetHint::ProcMemInfo
    } else if hay.contains(".git/config") {
        LfiTargetHint::GitConfig
    } else if hay.contains(".git/head") {
        LfiTargetHint::GitHead
    } else if hay.contains("wp-config") {
        LfiTargetHint::WpConfig
    } else if hay.contains(".aws/credentials") || hay.contains("credentials") {
        LfiTargetHint::AwsCredentials
    } else if hay.contains(".kube/config") {
        LfiTargetHint::KubeConfig
    } else if hay.contains("authorized_keys") {
        LfiTargetHint::SshAuthorizedKeys
    } else if hay.contains("id_rsa") || hay.contains("id_ed25519") {
        LfiTargetHint::SshPrivateKey
    } else if hay.contains(".htaccess") {
        LfiTargetHint::Htaccess
    } else if hay.contains("web.xml") {
        LfiTargetHint::WebXml
    } else if hay.contains("win.ini") {
        LfiTargetHint::WinIni
    } else if hay.contains("boot.ini") {
        LfiTargetHint::BootIni
    } else if hay.contains(".env") {
        LfiTargetHint::DotEnv
    } else if sample_lower.trim_matches(|c| c == '.' || c == '/' || c == '\\').is_empty() {
        LfiTargetHint::EtcPasswd
    } else {
        LfiTargetHint::UnknownFile
    }
}

fn looks_like_xss_text(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains('<')
        || l.contains('>')
        || l.contains("javascript:")
        || l.contains("vbscript:")
        || l.contains("data:text/html")
        || l.contains("alert(")
        || l.contains("prompt(")
        || l.contains("confirm(")
        || l.contains("eval(")
        || l.contains("document.")
        || l.contains("onerror=")
        || l.contains("onload=")
        || l.contains("onfocus=")
        || l.contains("onmouseover=")
        || l.contains("onclick=")
        || l.contains("ontoggle=")
}

fn strip_leading_param_name(decoded: &str) -> &str {
    if let Some((k, v)) = decoded.split_once('=') {
        if !k.is_empty()
            && k.len() <= 48
            && k.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return v;
        }
    }
    decoded
}

fn extract_xss_reflection(signal: &AttackSignal, query: Option<&str>, path: &str) -> String {
    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some((_, val)) = pair.split_once('=') {
                let dec_val = percent_decode_lossy(val);
                if looks_like_xss_text(&dec_val) {
                    return dec_val.chars().take(512).collect();
                }
            }
            let dec_pair = percent_decode_lossy(pair);
            if looks_like_xss_text(&dec_pair) {
                return strip_leading_param_name(&dec_pair).chars().take(512).collect();
            }
        }
    }
    if let Some(ref mp) = signal.matched_payload {
        let dec = percent_decode_lossy(mp);
        let stripped = strip_leading_param_name(&dec);
        if !stripped.is_empty() {
            return stripped.chars().take(512).collect();
        }
    }
    percent_decode_lossy(path).chars().take(512).collect()
}

/// Extract a plausible shell command from a command-injection payload (e.g. `host=127.0.0.1;id` -> `id`,
/// `host=127.0.0.1;id;#` -> `id`, `q=$(whoami)` -> `whoami`) so we can execute it safely inside `FakeShellSession`!
pub fn extract_injected_command(sample: &str) -> String {
    let decoded = percent_decode_lossy(sample);
    if let Some(start) = decoded.find("$(") {
        if let Some(end) = decoded[start + 2..].find(')') {
            let inner = decoded[start + 2..start + 2 + end].trim();
            if !inner.is_empty() {
                return inner.replace("${IFS}", " ").replace("$IFS", " ");
            }
        }
    }
    if let Some(start) = decoded.find('`') {
        if let Some(end) = decoded[start + 1..].find('`') {
            let inner = decoded[start + 1..start + 1 + end].trim();
            if !inner.is_empty() {
                return inner.replace("${IFS}", " ").replace("$IFS", " ");
            }
        }
    }

    let mut earliest: Option<(usize, usize)> = None;
    for sep in ["&&", "||", ";", "|", "\n", "\r"] {
        if let Some(idx) = decoded.find(sep) {
            match earliest {
                Some((best_idx, _)) if idx >= best_idx => {}
                _ => earliest = Some((idx, sep.len())),
            }
        }
    }

    let candidate_slice = if let Some((idx, len)) = earliest {
        &decoded[idx + len..]
    } else {
        strip_leading_param_name(decoded.trim())
    };

    let normalized = candidate_slice
        .replace("${IFS}", " ")
        .replace("$IFS", " ");

    let mut segments = Vec::new();
    for raw_seg in normalized.split([';', '\n', '\r']) {
        let trimmed = raw_seg.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        segments.push(trimmed);
    }

    if !segments.is_empty() {
        return segments.join("; ");
    }

    let cleaned = decoded.trim().replace("${IFS}", " ").replace("$IFS", " ");
    if !cleaned.is_empty() && !cleaned.contains('=') && !cleaned.starts_with('#') {
        return cleaned;
    }
    "id".to_string()
}

fn refine_sqli_verdict(
    decoded_query: &str,
    query_upper: &str,
    persona: &PrebakedPersona,
    default_sqli_delay_ms: u64,
) -> Option<TrapVerdict> {
    if query_upper.contains("SLEEP(")
        || query_upper.contains("PG_SLEEP(")
        || query_upper.contains("WAITFOR DELAY")
        || query_upper.contains("BENCHMARK(")
    {
        let extracted_secs = extract_number_after(query_upper, "SLEEP(")
            .unwrap_or((default_sqli_delay_ms / 1000).max(2))
            .clamp(1, 10);
        return Some(TrapVerdict::SqlInjectionTimeBlind {
            delay_ms: extracted_secs * 1000,
        });
    }

    if (query_upper.contains("SUBSTRING(")
        || query_upper.contains("MID(")
        || query_upper.contains("SUBSTR("))
        && (query_upper.contains("ASCII(") || query_upper.contains("ORD("))
    {
        let (truthy, pos) = evaluate_sqlmap_char_probe(query_upper, &persona.db_secret_row);
        return Some(TrapVerdict::SqlInjectionBoolean {
            truthy,
            extracted_pos: Some(pos),
        });
    }

    if query_upper.contains(" AND ") || query_upper.contains(" OR ") {
        if query_upper.contains("1=1")
            || query_upper.contains("'A'='A")
            || query_upper.contains("'1'='1")
            || query_upper.contains("TRUE")
        {
            return Some(TrapVerdict::SqlInjectionBoolean {
                truthy: true,
                extracted_pos: None,
            });
        }
        if query_upper.contains("1=2")
            || query_upper.contains("1=0")
            || query_upper.contains("'A'='B")
            || query_upper.contains("'1'='2")
            || query_upper.contains("FALSE")
        {
            return Some(TrapVerdict::SqlInjectionBoolean {
                truthy: false,
                extracted_pos: None,
            });
        }
    }

    if query_upper.contains("UNION SELECT")
        || query_upper.contains("UNION ALL SELECT")
        || query_upper.contains("INFORMATION_SCHEMA")
        || query_upper.contains("EXTRACTVALUE(")
        || query_upper.contains("UPDATEXML(")
        || query_upper.contains("PG_CATALOG")
        || decoded_query.contains('\'')
        || decoded_query.contains("--")
    {
        let is_postgres = query_upper.contains("PG_") || (persona.slot_id % 2 == 1);
        return Some(TrapVerdict::SqlInjectionError { is_postgres });
    }

    None
}

fn evaluate_sqlmap_char_probe(query_upper: &str, secret_row: &str) -> (bool, usize) {
    let pos_1based = extract_char_pos(query_upper).unwrap_or(1);
    // Keep the threshold as u64: cast to u8 would silently wrap values >255
    // (e.g. `ORD(...)>300`) and invert the boolean response.
    let threshold = extract_number_after(query_upper, ">").unwrap_or(64);

    let secret_bytes = secret_row.as_bytes();
    if pos_1based == 0 || pos_1based > secret_bytes.len() {
        return (false, pos_1based);
    }
    let actual_byte = secret_bytes[pos_1based - 1] as u64;
    (actual_byte > threshold, pos_1based)
}

fn extract_char_pos(s: &str) -> Option<usize> {
    for part in s.split(",1)") {
        if let Some(comma_idx) = part.rfind(',') {
            let candidate = part[comma_idx + 1..].trim();
            if let Ok(pos) = candidate.parse::<usize>() {
                return Some(pos);
            }
        }
    }
    None
}

fn extract_number_after(s: &str, marker: &str) -> Option<u64> {
    let idx = s.find(marker)?;
    let rest = s[idx + marker.len()..].trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u64>().ok()
}

pub fn percent_decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
