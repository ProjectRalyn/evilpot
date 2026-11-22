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
    /// Maximum number of active attacker verification sessions tracked in memory (LRU-bounded).
    pub max_tracked_sessions: usize,
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
            canary_webhook_url: "https://canary.internal.example.com/t".to_string(),
            max_tracked_sessions: 4096,
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
            let mut rng = rand::thread_rng();
            let rand_hex: String = (0..32)
                .map(|_| {
                    const HEX: &[u8] = b"0123456789abcdef";
                    HEX[rng.gen_range(0..16)] as char
                })
                .collect();
            format!("/_ep_{rand_hex}")
        } else if trimmed.starts_with('/') {
            trimmed.trim_end_matches('/').to_string()
        } else {
            format!("/{}", trimmed.trim_end_matches('/'))
        }
    }
}
