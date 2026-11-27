use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Root configuration for the `evilpot` HTTP deception, exploit verification & tarpit engine.
///
/// Note: `evilpot` does NOT perform attack detection itself — callers (such as Exposure's WAF
/// or `evilpot-forefront`) detect suspicious/malicious traffic and divert it into `evilpot`
/// with a [`crate::AttackSignal`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EvilpotConfig {
    /// Rotation interval in seconds for pre-generated deception snapshots.
    pub rotation_interval_secs: u64,
    /// Number of distinct pre-baked server personas per rotation epoch.
    pub persona_slots: usize,
    /// Master secret seed used for deterministic generation across rotations.
    pub master_seed: u64,
    /// Maximum concurrent slow/tarpit connections allowed across the process.
    pub max_tarpit_connections: usize,
    /// Bytes per second dripped to tarpitted HTTP streams.
    pub tarpit_drip_bytes_per_sec: usize,
    /// Advertised size in bytes for fake `.sql.gz` / `heapdump` tarpit streams (default 256 MiB).
    pub fake_archive_size_bytes: u64,
    /// Minimum bytes an attacker must keep reading from a tarpit stream to be verified as an active download tool (default 2048).
    pub tarpit_verify_min_bytes: u64,
    /// Minimum duration (in milliseconds) an attacker must stay on a tarpit stream to be verified (default 3000ms).
    pub tarpit_verify_min_ms: u64,
    /// Default delay (in milliseconds) for time-blind SQL injection traps when `SLEEP(n)` is not explicit.
    pub sqli_time_delay_ms: u64,
    /// Canary token / webhook base URL embedded into fake `.env`, Git configs, and debug leaks.
    pub canary_webhook_url: String,
    /// Optional fixed HTTP `Server` response header (e.g. `"nginx"`).
    /// When `Some(s)`, overrides the per-persona `Server` header so deception responses match the
    /// front proxy's real `Server` header (or omit `Server` if `s` is empty).
    pub server_header: Option<String>,
    /// Whether to emit backend fingerprint headers (`X-Powered-By`, `X-Backend-Node`, `X-Pingback`).
    /// Disabled automatically when embedded behind a reverse proxy like Exposure so a single
    /// request cannot fingerprint the honeypot by header differences.
    pub emit_persona_headers: bool,
    /// Maximum number of active attacker verification sessions tracked in memory (LRU-bounded).
    pub max_tracked_sessions: usize,
    /// Number of *distinct* attack requests (differing payload / path / method) an attacker must
    /// submit within one verification session before the session can escalate to
    /// `MultiStepExploitation` (which callers such as Exposure turn into an auto-ban).
    ///
    /// Repeated identical requests never count. Values below 2 are treated as 2, since a single
    /// request can never be "multi-step". Default: 2.
    pub multi_step_min_distinct_requests: usize,
    /// Management & telemetry panel configuration (customizable / randomized secret URL).
    pub admin: AdminPanelConfig,
}

impl Default for EvilpotConfig {
    fn default() -> Self {
        Self {
            rotation_interval_secs: 300,
            persona_slots: 16,
            master_seed: 0x4556_494C_504F_5431,
            max_tarpit_connections: 1024,
            tarpit_drip_bytes_per_sec: 256,
            fake_archive_size_bytes: 256 * 1024 * 1024,
            tarpit_verify_min_bytes: 2048,
            tarpit_verify_min_ms: 3000,
            sqli_time_delay_ms: 2500,
            canary_webhook_url: "https://sso-auth.internal.corp/v1/introspect".to_string(),
            server_header: None,
            emit_persona_headers: true,
            max_tracked_sessions: 4096,
            multi_step_min_distinct_requests: 2,
            admin: AdminPanelConfig::default(),
        }
    }
}

impl EvilpotConfig {
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("failed to read config file {}: {e}", path.as_ref().display()))?;
        toml::from_str(&content).map_err(|e| format!("failed to parse TOML config: {e}"))
    }

    pub fn from_toml_str(content: &str) -> Result<Self, String> {
        toml::from_str(content).map_err(|e| format!("failed to parse TOML config: {e}"))
    }
}

/// Configuration for the internal telemetry/rotation endpoints so they are never exposed at fixed URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminPanelConfig {
    pub enabled: bool,
    /// Set to `"auto"` to generate a 37-char high-entropy random prefix at startup,
    /// or specify any custom long random prefix in TOML.
    pub path_prefix: String,
    /// Optional secret token required in the `X-Evilpot-Token` header.
    pub secret_token: Option<String>,
}

impl Default for AdminPanelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path_prefix: "auto".to_string(),
            secret_token: None,
        }
    }
}

impl AdminPanelConfig {
    pub fn resolved_prefix(&self) -> String {
        let trimmed = self.path_prefix.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
            return Self::random_prefix();
        }

        let normalized = if trimmed.starts_with('/') {
            trimmed.trim_end_matches('/').to_string()
        } else {
            format!("/{}", trimmed.trim_end_matches('/'))
        };

        // A bare "/" (or "//") trims down to an empty prefix, which would make
        // `path.starts_with(prefix)` match EVERY request and hijack the whole site.
        // Fall back to a fresh random prefix in that case.
        if normalized.is_empty() || normalized == "/" {
            return Self::random_prefix();
        }
        normalized
    }

    fn random_prefix() -> String {
        let mut rng = rand::thread_rng();
        let rand_hex: String = (0..32)
            .map(|_| {
                const HEX: &[u8] = b"0123456789abcdef";
                HEX[rng.gen_range(0..16)] as char
            })
            .collect();
        format!("/_ep_{rand_hex}")
    }
}
