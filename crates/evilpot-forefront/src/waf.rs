use evilpot::{AttackCategory, AttackSignal, EvilpotConfig, TrapVerdict};
use http::{header, HeaderMap, Method};
use serde::{Deserialize, Serialize};
use sigil_filter::{AttackDetector, CategoryMask, DetectionResult, ScanInput, ViolationCategory};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::Path;

/// Hard ceiling on request body bytes buffered for WAF inspection (prevents OOM DoS).
pub const FOREFRONT_HARD_MAX_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ForefrontMode {
    /// Frontline reverse proxy in front of `upstream_http_url`:
    /// benign traffic is forwarded upstream; `sigil-filter` or decoy-route hits are diverted to `evilpot`.
    #[default]
    FrontlineProxy,
    /// Standalone honeypot server (no real upstream backend; benign requests hit a minimal gateway banner,
    /// attacks and decoy routes are diverted into `evilpot`).
    Standalone,
    /// Sink honeypot behind an external reverse proxy / WAF (Nginx / Caddy / Envoy):
    /// all requests routed here are treated as suspicious and diverted into `evilpot`.
    BehindProxySink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SinkFallbackTrap {
    #[default]
    ApiDebug,
    WordPressLogin,
    SqlError,
    DotEnv,
    TarpitStream,
}

impl SinkFallbackTrap {
    pub fn to_trap_verdict(self, method: &str) -> TrapVerdict {
        match self {
            Self::ApiDebug => TrapVerdict::ApiDebugEndpoint,
            Self::WordPressLogin => TrapVerdict::WordPressLogin {
                is_post_attempt: method.eq_ignore_ascii_case("POST"),
            },
            Self::SqlError => TrapVerdict::SqlInjectionError { is_postgres: false },
            Self::DotEnv => TrapVerdict::DotEnvLeak,
            Self::TarpitStream => TrapVerdict::TarpitStream {
                kind: evilpot::TarpitKind::GzipSqlBackup,
            },
        }
    }
}

/// Configuration for `evilpot-forefront`'s built-in `sigil-filter` WAF & attack recognizer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ForefrontSigilConfig {
    pub enabled: bool,
    pub min_confidence: f32,
    pub overflow_warn_len: usize,
    pub overflow_crit_len: usize,
    pub inspect_headers: bool,
    pub inspect_body: bool,
    pub max_body_bytes: usize,
    pub exempt_paths: Vec<String>,
}

impl Default for ForefrontSigilConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence: 0.55,
            overflow_warn_len: 4096,
            overflow_crit_len: 8192,
            inspect_headers: true,
            inspect_body: true,
            max_body_bytes: 32 * 1024,
            exempt_paths: Vec::new(),
        }
    }
}

/// Configuration for `evilpot-forefront`'s HTTP reverse proxy & decoy surface routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ForefrontHttpConfig {
    pub mode: ForefrontMode,
    pub bind_addr: SocketAddr,
    pub upstream_http_url: Option<String>,
    pub sink_fallback_trap: SinkFallbackTrap,
    pub real_ip_header: Option<String>,
    pub required_ingress_header: Option<String>,
    pub enable_wordpress_trap: bool,
    pub enable_secret_leak_trap: bool,
    pub enable_sqli_trap: bool,
    pub enable_api_trap: bool,
    pub enable_tarpit_archives: bool,
    pub custom_wordpress_paths: Vec<String>,
    pub custom_secret_paths: Vec<String>,
    pub custom_api_debug_paths: Vec<String>,
    pub custom_tarpit_suffixes: Vec<String>,
    pub scanner_user_agents: Vec<String>,
}

impl Default for ForefrontHttpConfig {
    fn default() -> Self {
        Self {
            mode: ForefrontMode::FrontlineProxy,
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            upstream_http_url: None,
            sink_fallback_trap: SinkFallbackTrap::ApiDebug,
            real_ip_header: Some("x-real-ip".to_string()),
            required_ingress_header: None,
            enable_wordpress_trap: true,
            enable_secret_leak_trap: true,
            enable_sqli_trap: true,
            enable_api_trap: true,
            enable_tarpit_archives: true,
            custom_wordpress_paths: vec![
                "/wp-login.php".to_string(),
                "/wp-admin".to_string(),
                "/wp-json".to_string(),
                "/xmlrpc.php".to_string(),
                "/wp-content/debug.log".to_string(),
                "/wp-config.php.bak".to_string(),
                "/wp-config.php~".to_string(),
                "/.wp-config.php.swp".to_string(),
                "/wp-includes/wlwmanifest.xml".to_string(),
                "/readme.html".to_string(),
            ],
            custom_secret_paths: vec![
                "/.env".to_string(),
                "/.git/config".to_string(),
                "/.git/HEAD".to_string(),
                "/actuator/env".to_string(),
                "/phpinfo.php".to_string(),
            ],
            custom_api_debug_paths: vec![
                "/api/v1/debug".to_string(),
                "/api/debug".to_string(),
                "/admin/debug".to_string(),
                "/_debug".to_string(),
            ],
            custom_tarpit_suffixes: vec![
                "/heapdump".to_string(),
                ".sql.gz".to_string(),
                ".sql".to_string(),
                "/backup.zip".to_string(),
                "/backup.tar.gz".to_string(),
                "/www.zip".to_string(),
                "/db_backup.gz".to_string(),
            ],
            scanner_user_agents: vec![
                "sqlmap".to_string(),
                "nuclei".to_string(),
                "nikto".to_string(),
                "dirsearch".to_string(),
                "gobuster".to_string(),
                "feroxbuster".to_string(),
                "ffuf".to_string(),
                "masscan".to_string(),
                "zgrab".to_string(),
                "acunetix".to_string(),
                "nessus".to_string(),
                "wpscan".to_string(),
            ],
        }
    }
}

/// Top-level TOML configuration for `evilpot-forefront`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ForefrontConfig {
    #[serde(flatten)]
    pub evilpot: EvilpotConfig,
    pub sigil: ForefrontSigilConfig,
    pub http: ForefrontHttpConfig,
}

impl ForefrontConfig {
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("failed to read config file {}: {e}", path.as_ref().display()))?;
        toml::from_str(&content).map_err(|e| format!("failed to parse TOML config: {e}"))
    }
}

pub fn sigil_violation_to_attack_category(cat: ViolationCategory) -> AttackCategory {
    match cat {
        ViolationCategory::BufferOverflow => AttackCategory::BufferOverflow,
        ViolationCategory::PathTraversal => AttackCategory::PathTraversal,
        ViolationCategory::SqlInjection => AttackCategory::SqlInjection,
        ViolationCategory::NoSqlInjection => AttackCategory::NoSqlInjection,
        ViolationCategory::Xss => AttackCategory::Xss,
        ViolationCategory::CommandInjection => AttackCategory::CommandInjection,
        ViolationCategory::LdapInjection => AttackCategory::LdapInjection,
        ViolationCategory::XxeAndXmlInjection => AttackCategory::Xxe,
        ViolationCategory::SstiAndCodeInjection => AttackCategory::Ssti,
        ViolationCategory::Ssrf => AttackCategory::Ssrf,
        ViolationCategory::CrlfAndHeaderInjection => AttackCategory::CrlfInjection,
        ViolationCategory::DeserializationAndPrototypePollution => AttackCategory::Deserialization,
        ViolationCategory::Custom(_) => AttackCategory::GenericSuspicious,
    }
}

pub fn is_path_exempt(path: &str, exempt_paths: &[String]) -> bool {
    for raw in exempt_paths {
        let p = raw.trim();
        if p.is_empty() {
            continue;
        }
        if p == "/" {
            return true;
        }
        if p.ends_with('/') {
            if path.starts_with(p) {
                return true;
            }
        } else if path == p || path.starts_with(&format!("{p}/")) {
            return true;
        }
    }
    false
}

/// Inspect HTTP request head (high-specificity decoy routes + `sigil-filter` across path, query, and headers).
/// Returns `Some(AttackSignal)` when an attack is recognized and should be diverted into `evilpot`.
pub fn inspect_request_head(
    http_cfg: &ForefrontHttpConfig,
    sigil_cfg: &ForefrontSigilConfig,
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
) -> Option<AttackSignal> {
    if is_path_exempt(path, &sigil_cfg.exempt_paths) {
        return None;
    }

    let path_lower = path.to_ascii_lowercase();
    let decoded_query = query.map(evilpot::percent_decode_lossy).unwrap_or_default();
    let query_upper = decoded_query.to_ascii_uppercase();

    // 1. High-specificity SQLMap blind/time/error probes in query string
    if http_cfg.enable_sqli_trap
        && !decoded_query.is_empty()
        && (query_upper.contains("SLEEP(")
            || query_upper.contains("WAITFOR DELAY")
            || query_upper.contains("BENCHMARK(")
            || ((query_upper.contains("SUBSTRING(")
                || query_upper.contains("MID(")
                || query_upper.contains("SUBSTR("))
                && (query_upper.contains("ASCII(") || query_upper.contains("ORD(")))
            || query_upper.contains("UNION SELECT")
            || query_upper.contains("UNION ALL SELECT")
            || query_upper.contains("INFORMATION_SCHEMA")
            || query_upper.contains("EXTRACTVALUE(")
            || query_upper.contains("UPDATEXML(")
            || query_upper.contains("PG_CATALOG"))
    {
        return Some(
            AttackSignal::new(AttackCategory::SqlInjection, "query", 0.98)
                .with_payload(decoded_query),
        );
    }

    // 2. Tarpit Archive paths (/actuator/heapdump, /backup.sql.gz, etc.)
    if http_cfg.enable_tarpit_archives {
        if path_lower.ends_with("/heapdump")
            || path_lower == "/heapdump"
            || http_cfg
                .custom_tarpit_suffixes
                .iter()
                .any(|suf| path_lower.ends_with(&suf.to_ascii_lowercase()))
        {
            return Some(
                AttackSignal::new(AttackCategory::TarpitArchiveProbe, "path", 0.99)
                    .with_payload(path),
            );
        }
    }

    // 3. WordPress / CMS trap routes
    if http_cfg.enable_wordpress_trap {
        let is_wp = path_lower.contains("wp-config.php")
            || path_lower.ends_with(".wp-config.php.swp")
            || path_lower.ends_with("wp-config.bak")
            || path_lower.ends_with("wp-config.old")
            || path_lower.ends_with("wp-config.txt")
            || path_lower.ends_with("/wp-content/debug.log")
            || path_lower.ends_with("/debug.log")
            || path_lower.ends_with("/wp-admin/admin-ajax.php")
            || path_lower.ends_with("/readme.html")
            || path_lower.ends_with("/wp-includes/wlwmanifest.xml")
            || path_lower == "/wp-json"
            || path_lower.starts_with("/wp-json/")
            || query_upper.starts_with("REST_ROUTE=/")
            || (path_lower == "/" && query_upper.starts_with("AUTHOR="))
            || path_lower.ends_with("/xmlrpc.php")
            || path_lower.ends_with("/wp-login.php")
            || path_lower.starts_with("/wp-admin")
            || http_cfg.custom_wordpress_paths.iter().any(|p| {
                let p_low = p.to_ascii_lowercase();
                path_lower == p_low || path_lower.starts_with(&format!("{p_low}/"))
            });
        if is_wp {
            return Some(
                AttackSignal::new(AttackCategory::WordPressProbe, "path", 0.95)
                    .with_payload(query.unwrap_or(path)),
            );
        }
    }

    // 4. Secret & Configuration Leak traps (/.env, /.git/config, /actuator/env, /phpinfo.php)
    if http_cfg.enable_secret_leak_trap {
        let is_secret = path_lower == "/.env"
            || path_lower.starts_with("/.env.")
            || path_lower.ends_with("/.env")
            || path_lower.ends_with("/.git/config")
            || path_lower.ends_with("/.git/head")
            || path_lower == "/actuator/env"
            || path_lower == "/actuator"
            || path_lower.starts_with("/actuator/")
            || path_lower.ends_with("phpinfo.php")
            || path_lower == "/info.php"
            || http_cfg
                .custom_secret_paths
                .iter()
                .any(|p| path_lower == p.to_ascii_lowercase());
        if is_secret {
            return Some(
                AttackSignal::new(AttackCategory::SecretLeakProbe, "path", 0.99).with_payload(path),
            );
        }
    }

    // 5. Vulnerable API / GraphQL / OpenAPI discovery traps
    if http_cfg.enable_api_trap {
        let is_api = path_lower == "/graphql"
            || path_lower.ends_with("/graphql")
            || path_lower.ends_with("/swagger.json")
            || path_lower.ends_with("/openapi.json")
            || path_lower.ends_with("/api-docs")
            || http_cfg.custom_api_debug_paths.iter().any(|p| {
                let p_low = p.to_ascii_lowercase();
                path_lower == p_low || path_lower.contains(&p_low)
            });
        if is_api {
            return Some(
                AttackSignal::new(AttackCategory::ApiDiscoveryProbe, "path", 0.95)
                    .with_payload(path),
            );
        }
    }

    // 6. `sigil-filter` 12-Category Heuristic WAF inspection across path, query, and headers!
    if sigil_cfg.enabled {
        let min_c = sigil_cfg.min_confidence.clamp(0.1, 1.0);
        let detector = AttackDetector::new()
            .with_min_confidence(min_c)
            .with_buffer_limits(sigil_cfg.overflow_warn_len, sigil_cfg.overflow_crit_len);

        if !path.is_empty() && path != "/" {
            let res = detector.detect(path);
            if let Some(sig) = signal_from_sigil("path", path, res) {
                return Some(sig);
            }
        }

        if let Some(q) = query.filter(|q| !q.is_empty()) {
            for pair in q.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v_opt) = match pair.split_once('=') {
                    Some((k, v)) => (k, Some(v)),
                    None => (pair, None),
                };
                let k_norm = replace_plus_with_space(k);
                let res = detector.detect(k_norm.as_ref());
                if let Some(sig) = signal_from_sigil("query", &decoded_query, res) {
                    return Some(sig);
                }
                if let Some(v) = v_opt.filter(|v| !v.is_empty()) {
                    let v_norm = replace_plus_with_space(v);
                    let res = detector.detect(v_norm.as_ref());
                    if let Some(sig) = signal_from_sigil("query", v_norm.as_ref(), res) {
                        return Some(sig);
                    }
                }
                let pair_norm = replace_plus_with_space(pair);
                let res = detector.detect(pair_norm.as_ref());
                if let Some(sig) = signal_from_sigil("query", pair_norm.as_ref(), res) {
                    return Some(sig);
                }
            }
            let q_norm = replace_plus_with_space(q);
            let res = detector.detect(q_norm.as_ref());
            if let Some(sig) = signal_from_sigil("query", q_norm.as_ref(), res) {
                return Some(sig);
            }
        }

        if sigil_cfg.inspect_headers {
            // User-Agent: exclude PathTraversal because standard browser UAs contain `/` + `Windows`
            let ua_mask = mask_without(CategoryMask::ALL, ViolationCategory::PathTraversal);
            for hv in headers.get_all(header::USER_AGENT) {
                if let Ok(s) = hv.to_str() {
                    let res = detector.detect(ScanInput::new(s).with_mask(ua_mask));
                    if let Some(sig) = signal_from_sigil("header:user-agent", s, res) {
                        return Some(sig);
                    }
                }
            }

            // Referer: exclude Ssrf because browsing from localhost sets `Referer: http://127.0.0.1/...`
            let referer_mask = mask_without(CategoryMask::ALL, ViolationCategory::Ssrf);
            for hv in headers.get_all(header::REFERER) {
                if let Ok(s) = hv.to_str() {
                    let res = detector.detect(ScanInput::new(s).with_mask(referer_mask));
                    if let Some(sig) = signal_from_sigil("header:referer", s, res) {
                        return Some(sig);
                    }
                }
            }

            // Cookie: split on `;` so standard `a=1; id=2` cookie delimiters don't look like shell `; id`
            for hv in headers.get_all(header::COOKIE) {
                if let Ok(raw_cookie) = hv.to_str() {
                    for item in raw_cookie.split(';') {
                        let trimmed = item.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        let val = trimmed
                            .split_once('=')
                            .map(|(_, v)| v.trim())
                            .unwrap_or(trimmed);
                        if val.is_empty() {
                            continue;
                        }
                        let res = detector.detect(val);
                        if let Some(sig) = signal_from_sigil("header:cookie", val, res) {
                            return Some(sig);
                        }
                    }
                }
            }

            for (h_name, loc) in [
                ("x-api-version", "header:x-api-version"),
                ("x-original-url", "header:x-original-url"),
                ("x-rewrite-url", "header:x-rewrite-url"),
                ("x-forwarded-for", "header:x-forwarded-for"),
                ("x-forwarded-host", "header:x-forwarded-host"),
                ("forwarded", "header:forwarded"),
            ] {
                for hv in headers.get_all(h_name) {
                    if let Ok(s) = hv.to_str() {
                        let res = detector.detect(s);
                        if let Some(sig) = signal_from_sigil(loc, s, res) {
                            return Some(sig);
                        }
                    }
                }
            }
        }
    }

    // 7. Scanner User-Agent fallback trap
    if let Some(ua) = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()) {
        let ua_lower = ua.to_ascii_lowercase();
        if http_cfg
            .scanner_user_agents
            .iter()
            .any(|sig| ua_lower.contains(&sig.to_ascii_lowercase()))
        {
            let cat = if ua_lower.contains("wpscan") {
                AttackCategory::WordPressProbe
            } else {
                AttackCategory::ScannerUserAgent
            };
            return Some(AttackSignal::new(cat, "header:user-agent", 0.90).with_payload(ua));
        }
    }

    let _ = method;
    None
}

pub fn should_inspect_body(
    sigil_cfg: &ForefrontSigilConfig,
    method: &Method,
    headers: &HeaderMap,
) -> Option<usize> {
    if !sigil_cfg.enabled || !sigil_cfg.inspect_body {
        return None;
    }
    if !matches!(*method, Method::POST | Method::PUT | Method::PATCH) {
        return None;
    }
    let limit = sigil_cfg.max_body_bytes.min(FOREFRONT_HARD_MAX_BODY_BYTES);
    if limit == 0 {
        return None;
    }
    if let Some(ct) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        if !is_text_inspectable_content_type(ct) {
            return None;
        }
    }
    Some(limit)
}

pub fn inspect_request_body(
    sigil_cfg: &ForefrontSigilConfig,
    content_type: Option<&str>,
    body: &[u8],
) -> Option<AttackSignal> {
    if !sigil_cfg.enabled || !sigil_cfg.inspect_body || body.is_empty() {
        return None;
    }
    let limit = sigil_cfg.max_body_bytes.min(FOREFRONT_HARD_MAX_BODY_BYTES);
    if limit == 0 {
        return None;
    }
    let slice = &body[..body.len().min(limit)];
    let text = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(e) => {
            let valid = e.valid_up_to();
            if valid == 0 {
                return None;
            }
            std::str::from_utf8(&slice[..valid]).ok()?
        }
    };

    let min_c = sigil_cfg.min_confidence.clamp(0.1, 1.0);
    let body_warn = limit.saturating_add(1).max(sigil_cfg.overflow_warn_len);
    let body_crit = body_warn.saturating_add(1);
    let detector = AttackDetector::new()
        .with_min_confidence(min_c)
        .with_buffer_limits(body_warn, body_crit);

    let is_form = content_type
        .map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
        .unwrap_or(false);

    if is_form {
        for pair in text.split('&') {
            if pair.is_empty() {
                continue;
            }
            let pair_norm = replace_plus_with_space(pair);
            let res = detector.detect(pair_norm.as_ref());
            if let Some(sig) = signal_from_sigil("body", pair_norm.as_ref(), res) {
                return Some(sig);
            }
            if let Some((_, val)) = pair.split_once('=') {
                if !val.is_empty() {
                    let val_norm = replace_plus_with_space(val);
                    let res = detector.detect(val_norm.as_ref());
                    if let Some(sig) = signal_from_sigil("body", val_norm.as_ref(), res) {
                        return Some(sig);
                    }
                }
            }
        }
        return None;
    }

    let res = detector.detect(text);
    signal_from_sigil("body", text, res)
}

#[inline]
fn signal_from_sigil(
    location: &'static str,
    sample: &str,
    res: DetectionResult,
) -> Option<AttackSignal> {
    let cat = res.violation?;
    let reasons = res
        .violations
        .first()
        .map(|v| v.reasons.iter().map(|r| (*r).to_string()).collect())
        .unwrap_or_default();
    Some(
        AttackSignal::new(
            sigil_violation_to_attack_category(cat),
            location,
            res.confidence,
        )
        .with_payload(sample)
        .with_reasons(reasons),
    )
}

#[inline]
fn mask_without(mask: CategoryMask, excluded: ViolationCategory) -> CategoryMask {
    CategoryMask(mask.0 & !excluded.bit())
}

#[inline]
fn replace_plus_with_space(s: &str) -> Cow<'_, str> {
    if s.as_bytes().contains(&b'+') {
        Cow::Owned(s.replace('+', " "))
    } else {
        Cow::Borrowed(s)
    }
}

fn is_text_inspectable_content_type(ct: &str) -> bool {
    let media = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media.is_empty() {
        return true;
    }
    media.starts_with("text/")
        || media == "application/json"
        || media.ends_with("+json")
        || media == "application/x-www-form-urlencoded"
        || media == "application/xml"
        || media.ends_with("+xml")
        || media == "application/graphql"
        || media == "application/javascript"
        || media == "application/ecmascript"
}
