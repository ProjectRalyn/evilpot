use crate::config::EvilpotConfig;
use crate::persona::{PersonaSnapshot, PrebakedPersona};
use crate::shell::{FakeShellSession, ShellExecResult};
use crate::trap::TrapVerdict;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;
use tracing::{info, warn};

// Upper bounds on per-session collections so a single attacker IP cannot exhaust
// memory by emitting an unbounded number of unique paths / commands / IOCs.
const MAX_DISTINCT_PATHS: usize = 128;
const MAX_RCE_COMMANDS: usize = 128;
const MAX_CAPTURED_IOCS: usize = 256;
const MAX_EVIDENCE: usize = 128;
const MAX_DISTINCT_SIGNATURES: usize = 256;
const MAX_ATTACK_KINDS: usize = 16;
const MAX_SQLI_TECHNIQUES: usize = 8;

/// Coarse attack family, used to detect an attacker switching techniques (SQLi → RCE → LFI).
fn attack_kind(verdict: &TrapVerdict) -> &'static str {
    match verdict {
        TrapVerdict::SqlInjectionBoolean { .. }
        | TrapVerdict::SqlInjectionTimeBlind { .. }
        | TrapVerdict::SqlInjectionError { .. } => "sqli",
        TrapVerdict::CommandInjectionRce { .. } => "rce",
        TrapVerdict::PathTraversalLfi { .. } => "lfi",
        TrapVerdict::SsrfCloudMetadata { .. } => "ssrf",
        TrapVerdict::SstiTemplateEval { .. } => "ssti",
        TrapVerdict::NoSqlAdminDump { .. } => "nosql",
        TrapVerdict::XxeEntityLeak { .. } => "xxe",
        TrapVerdict::DeserializationJndiTrap { .. } => "jndi",
        TrapVerdict::LdapDirectoryDump { .. } => "ldap",
        TrapVerdict::XssBaitPage { .. } => "xss",
        TrapVerdict::CrlfProxyDebug { .. } => "crlf",
        TrapVerdict::CanaryVaultExport { .. } => "canary",
        TrapVerdict::TarpitStream { .. } => "tarpit",
        _ => "recon",
    }
}

/// SQLi flavour (boolean / time-blind / error), used for technique-diversity checks.
fn sqli_technique(verdict: &TrapVerdict) -> Option<&'static str> {
    match verdict {
        TrapVerdict::SqlInjectionBoolean { .. } => Some("boolean"),
        TrapVerdict::SqlInjectionTimeBlind { .. } => Some("time_blind"),
        TrapVerdict::SqlInjectionError { .. } => Some("error"),
        _ => None,
    }
}

/// Fingerprint of the concrete request content (trap kind + path + method/URI).
///
/// Multi-step verification must be driven by *different* payloads: a client that retries the
/// exact same request (e.g. a legitimate user hitting a false-positive WAF rule) produces the
/// same signature and therefore never escalates the session.
fn request_signature(verdict: &TrapVerdict, path: &str, detail: &str) -> u64 {
    // `detail` looks like "GET /item?id=1' [category=sql_injection loc=query conf=0.92]";
    // the trailing analysis metadata is dropped so identical requests hash identically.
    let request_part = detail.split(" [category=").next().unwrap_or(detail);
    let mut h = DefaultHasher::new();
    std::mem::discriminant(verdict).hash(&mut h);
    path.hash(&mut h);
    request_part.hash(&mut h);
    h.finish()
}

fn note_sqli_payload(
    session: &mut AttackerSessionState,
    signature: u64,
    new_signature: bool,
    technique: Option<&'static str>,
) {
    if let Some(t) = technique {
        if session.sqli_techniques.len() < MAX_SQLI_TECHNIQUES {
            session.sqli_techniques.insert(t);
        }
    }
    if new_signature && session.sqli_payloads.len() < MAX_DISTINCT_SIGNATURES {
        session.sqli_payloads.insert(signature);
    }
}

/// Verification status indicating how strongly `evilpot` has confirmed that a WAF-diverted
/// client is actively exploiting a vulnerability rather than triggering an isolated false positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExploitVerificationStatus {
    /// Initial trap response served; awaiting follow-up interaction or canary trigger.
    Probing,
    /// Multi-step exploitation confirmed (e.g., repeated SQLMap blind char extraction,
    /// multiple LFI file reads, RCE shell chaining, or sustained tarpit download).
    MultiStepExploitation,
    /// 100% deterministic confirmation: the attacker replayed an implanted canary credential/cookie/URL
    /// or executed payload delivery (`wget`/`curl`/file write) inside the fake RCE shell.
    VerifiedExploit,
}

/// Specific evidence item proving active exploitation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerificationEvidence {
    /// Attacker replayed a fake canary token, API key, cookie, or secret vault endpoint that was
    /// leaked in a previous `evilpot` decoy response.
    CanaryTriggered {
        kind: String,
        token_or_path: String,
    },
    /// Attacker performed multi-step SQL injection extraction (e.g. SQLMap boolean/time-blind char probes).
    SqliExtractionProgress {
        probe_count: u32,
        distinct_char_positions: usize,
    },
    /// Attacker executed commands inside the command-injection `FakeShellSession` and yielded IOCs.
    RceShellInteraction {
        command_count: u32,
        last_command: String,
        captured_iocs: Vec<String>,
    },
    /// Attacker probed multiple sensitive LFI / secret-leak paths across requests.
    MultiPathRecon {
        distinct_paths_probed: usize,
    },
    /// Attacker stayed connected to a slow-drip tarpit archive stream (`heapdump` / `.sql.gz`)
    /// beyond the verification byte/duration threshold.
    SustainedTarpitRead {
        bytes_read: u64,
        duration_ms: u64,
    },
}

/// Public snapshot of an attacker's multi-request deception & verification session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerSessionReport {
    pub client_ip: String,
    pub epoch_id: u64,
    pub persona_hostname: String,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub total_trapped_requests: u64,
    pub status: ExploitVerificationStatus,
    pub canary_triggers: u32,
    pub sqli_probes: u32,
    pub sqli_distinct_positions: usize,
    pub rce_commands_executed: Vec<String>,
    pub captured_iocs: Vec<String>,
    pub distinct_paths: Vec<String>,
    pub tarpit_bytes_consumed: u64,
    pub tarpit_max_duration_ms: u64,
    pub evidence: Vec<VerificationEvidence>,
}

struct AttackerSessionState {
    client_ip: IpAddr,
    epoch_id: u64,
    persona_hostname: String,
    first_seen_unix: u64,
    last_seen_unix: u64,
    total_trapped_requests: u64,
    status: ExploitVerificationStatus,
    canary_triggers: u32,
    sqli_probes: u32,
    sqli_positions: HashSet<usize>,
    /// Distinct SQLi payloads (request signatures) seen in this session.
    sqli_payloads: HashSet<u64>,
    /// Distinct SQLi flavours (boolean / time-blind / error).
    sqli_techniques: HashSet<&'static str>,
    /// All distinct request signatures seen, so retries of the same request are ignored.
    request_signatures: HashSet<u64>,
    /// Coarse attack families exercised by this client (sqli / rce / lfi / xss ...).
    attack_kinds: HashSet<&'static str>,
    rce_commands: Vec<String>,
    captured_iocs: Vec<String>,
    distinct_paths: HashSet<String>,
    tarpit_bytes_consumed: u64,
    tarpit_max_duration_ms: u64,
    evidence: Vec<VerificationEvidence>,
    shell_session: Option<FakeShellSession>,
}

impl AttackerSessionState {
    fn new(client_ip: IpAddr, persona: &PrebakedPersona, now_unix: u64) -> Self {
        Self {
            client_ip,
            epoch_id: persona.epoch_id,
            persona_hostname: persona.hostname.clone(),
            first_seen_unix: now_unix,
            last_seen_unix: now_unix,
            total_trapped_requests: 0,
            status: ExploitVerificationStatus::Probing,
            canary_triggers: 0,
            sqli_probes: 0,
            sqli_positions: HashSet::new(),
            sqli_payloads: HashSet::new(),
            sqli_techniques: HashSet::new(),
            request_signatures: HashSet::new(),
            attack_kinds: HashSet::new(),
            rce_commands: Vec::new(),
            captured_iocs: Vec::new(),
            distinct_paths: HashSet::new(),
            tarpit_bytes_consumed: 0,
            tarpit_max_duration_ms: 0,
            evidence: Vec::new(),
            shell_session: None,
        }
    }

    /// Append verification evidence while keeping the per-session evidence log bounded.
    fn push_evidence(&mut self, ev: VerificationEvidence) {
        if self.evidence.len() < MAX_EVIDENCE {
            self.evidence.push(ev);
        }
    }

    fn to_report(&self) -> AttackerSessionReport {
        let mut paths: Vec<String> = self.distinct_paths.iter().cloned().collect();
        paths.sort();
        AttackerSessionReport {
            client_ip: self.client_ip.to_string(),
            epoch_id: self.epoch_id,
            persona_hostname: self.persona_hostname.clone(),
            first_seen_unix: self.first_seen_unix,
            last_seen_unix: self.last_seen_unix,
            total_trapped_requests: self.total_trapped_requests,
            status: self.status,
            canary_triggers: self.canary_triggers,
            sqli_probes: self.sqli_probes,
            sqli_distinct_positions: self.sqli_positions.len(),
            rce_commands_executed: self.rce_commands.clone(),
            captured_iocs: self.captured_iocs.clone(),
            distinct_paths: paths,
            tarpit_bytes_consumed: self.tarpit_bytes_consumed,
            tarpit_max_duration_ms: self.tarpit_max_duration_ms,
            evidence: self.evidence.clone(),
        }
    }
}

/// Structured threat telemetry event recorded whenever an HTTP trap or verification upgrade is triggered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub timestamp_unix: u64,
    pub epoch_id: u64,
    pub persona_hostname: String,
    pub client_ip: String,
    pub verification_status: ExploitVerificationStatus,
    pub trap_kind: String,
    pub detail: String,
    pub evidence: Vec<VerificationEvidence>,
}

/// Live atomic metrics for the evilpot HTTP deception & verification engine.
#[derive(Debug, Default)]
pub struct EvilpotMetrics {
    pub current_epoch: AtomicU64,
    pub rotations_completed: AtomicU64,
    pub requests_handled: AtomicU64,
    pub traps_triggered: AtomicU64,
    pub canary_verifications: AtomicU64,
    pub verified_attack_sessions: AtomicU64,
    pub tarpit_bytes_dripped: AtomicU64,
    pub active_tarpit_connections: AtomicUsize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvilpotMetricsSnapshot {
    pub current_epoch: u64,
    pub rotations_completed: u64,
    pub requests_handled: u64,
    pub traps_triggered: u64,
    pub canary_verifications: u64,
    pub verified_attack_sessions: u64,
    pub tarpit_bytes_dripped: u64,
    pub active_tarpit_connections: usize,
}

/// RAII permit guarding a concurrent tarpit / slow-drip connection.
pub struct TarpitPermit {
    engine: Arc<EvilpotEngine>,
}

impl Drop for TarpitPermit {
    fn drop(&mut self) {
        self.engine
            .metrics
            .active_tarpit_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Core thread-safe HTTP deception & exploit verification engine managing pre-baked persona snapshots,
/// scheduled rotation, canary token matching, stateful fake shell sessions, and tarpit watermarks.
pub struct EvilpotEngine {
    config: EvilpotConfig,
    resolved_admin_prefix: String,
    snapshot: RwLock<Arc<PersonaSnapshot>>,
    previous_snapshots: RwLock<VecDeque<Arc<PersonaSnapshot>>>,
    epoch_counter: AtomicU64,
    pub metrics: EvilpotMetrics,
    recent_events: Mutex<VecDeque<ThreatEvent>>,
    sessions: Mutex<HashMap<IpAddr, AttackerSessionState>>,
}

impl EvilpotEngine {
    /// Initialize the engine and synchronously pre-bake Epoch 1.
    pub fn new(config: EvilpotConfig) -> Arc<Self> {
        let initial_epoch = 1;
        let resolved_admin_prefix = config.admin.resolved_prefix();
        let snapshot = PersonaSnapshot::bake(
            config.master_seed,
            initial_epoch,
            config.persona_slots,
            &config.canary_webhook_url,
        );
        let metrics = EvilpotMetrics::default();
        metrics.current_epoch.store(initial_epoch, Ordering::Relaxed);

        Arc::new(Self {
            config,
            resolved_admin_prefix,
            snapshot: RwLock::new(Arc::new(snapshot)),
            previous_snapshots: RwLock::new(VecDeque::with_capacity(4)),
            epoch_counter: AtomicU64::new(initial_epoch),
            metrics,
            recent_events: Mutex::new(VecDeque::with_capacity(256)),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub fn config(&self) -> &EvilpotConfig {
        &self.config
    }

    pub fn admin_path_prefix(&self) -> &str {
        &self.resolved_admin_prefix
    }

    pub fn current_snapshot(&self) -> Arc<PersonaSnapshot> {
        self.snapshot
            .read()
            .expect("EvilpotEngine snapshot lock poisoned")
            .clone()
    }

    /// Deterministically select a pre-baked `PrebakedPersona` for `client_ip`.
    /// Pinning is stable across epoch rotations so a client's server hostname/Server header never flips mid-session.
    pub fn select_persona(&self, client_ip: IpAddr) -> Arc<PrebakedPersona> {
        let snap = self.current_snapshot();
        let subnet_key = normalize_ip_subnet(client_ip);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.config.master_seed.hash(&mut hasher);
        subnet_key.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % snap.personas.len();
        snap.personas[idx].clone()
    }

    fn match_persona_canary(
        p: &PrebakedPersona,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> Option<VerificationEvidence> {
        // 1. Canary Vault Export Path or Canary Token ID in URI path/query
        if path == p.canary_endpoint_path
            || path.contains(&p.canary_token_id)
            || p.extra_canary_paths.iter().any(|cp| path == cp)
        {
            return Some(VerificationEvidence::CanaryTriggered {
                kind: "canary_endpoint_path".to_string(),
                token_or_path: path.to_string(),
            });
        }
        if let Some(q) = query {
            if q.contains(&p.canary_api_key)
                || q.contains(&p.canary_aws_access_key)
                || q.contains(&p.canary_token_id)
            {
                return Some(VerificationEvidence::CanaryTriggered {
                    kind: "canary_query_token".to_string(),
                    token_or_path: p.canary_api_key.clone(),
                });
            }
            for (kind, tok) in &p.extra_canary_tokens {
                if q.contains(tok) {
                    return Some(VerificationEvidence::CanaryTriggered {
                        kind: format!("query:{kind}"),
                        token_or_path: tok.clone(),
                    });
                }
            }
        }

        // 2. Implanted API key / AWS key / JWT secret in Authorization or custom API headers
        for hdr_name in [
            "authorization",
            "x-api-key",
            "x-evilpot-token",
            "x-legacy-token",
            "x-debug-bypass-token",
            "x-vault-token",
            "x-internal-gateway-token",
        ] {
            if let Some(val) = headers.get(hdr_name).and_then(|v| v.to_str().ok()) {
                if val.contains(&p.canary_api_key)
                    || val.contains(&p.canary_aws_access_key)
                    || val.contains(&p.canary_jwt_secret[..20])
                {
                    return Some(VerificationEvidence::CanaryTriggered {
                        kind: format!("header:{hdr_name}"),
                        token_or_path: p.canary_api_key.clone(),
                    });
                }
                for (kind, tok) in &p.extra_canary_tokens {
                    if val.contains(tok) {
                        return Some(VerificationEvidence::CanaryTriggered {
                            kind: format!("header:{hdr_name}:{kind}"),
                            token_or_path: tok.clone(),
                        });
                    }
                }
            }
        }

        // 3. Implanted XSS / WordPress bait session cookie replayed
        if let Some(cookie) = headers.get(http::header::COOKIE).and_then(|v| v.to_str().ok()) {
            if cookie.contains(&p.canary_cookie_value) {
                return Some(VerificationEvidence::CanaryTriggered {
                    kind: "cookie:admin_session_id".to_string(),
                    token_or_path: p.canary_cookie_value[..16].to_string(),
                });
            }
        }

        None
    }

    /// Check whether an incoming HTTP request (even one that might look syntactically benign to a WAF!)
    /// replays an implanted canary credential, cookie, API key, or secret vault export path from any
    /// active or recently rotated persona snapshot.
    ///
    /// Callers (like Exposure or `evilpot-forefront`) can call this on incoming requests to catch
    /// attackers trying to use credentials stolen from an earlier honeypot response!
    pub fn check_canary_trigger(
        &self,
        client_ip: IpAddr,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> Option<VerificationEvidence> {
        let snap = self.current_snapshot();
        let assigned = self.select_persona(client_ip);

        // Check assigned persona first (O(1) fast path), then all slots in current snapshot
        for p in std::iter::once(&assigned).chain(snap.personas.iter()) {
            if let Some(ev) = Self::match_persona_canary(p, path, query, headers) {
                return Some(ev);
            }
        }

        // Also check recent prior snapshots so stolen cookies/tokens remain valid across epoch rotation
        if let Ok(prev) = self.previous_snapshots.read() {
            for old_snap in prev.iter() {
                for p in &old_snap.personas {
                    if let Some(ev) = Self::match_persona_canary(p, path, query, headers) {
                        return Some(ev);
                    }
                }
            }
        }

        None
    }

    /// Execute a command inside the attacker's stateful `FakeShellSession` (persisted per IP across requests
    /// so `cd`, environment variables, and CoW files written in `/tmp` carry over across RCE requests!).
    pub fn execute_rce_command(
        &self,
        client_ip: IpAddr,
        persona: &Arc<PrebakedPersona>,
        cmd: &str,
    ) -> ShellExecResult {
        let now_unix = now_unix_secs();
        let mut sessions = self.sessions.lock().expect("sessions lock poisoned");
        self.evict_oldest_if_full(&mut sessions, client_ip);
        let session = sessions
            .entry(client_ip)
            .or_insert_with(|| AttackerSessionState::new(client_ip, persona, now_unix));

        let shell = session
            .shell_session
            .get_or_insert_with(|| FakeShellSession::new(persona.clone(), Some("www-data")));
        shell.execute_line(cmd)
    }

    /// Record a trap hit and update the attacker's multi-step verification state machine.
    /// Returns the updated [`AttackerSessionReport`].
    pub fn record_trap_interaction(
        &self,
        client_ip: IpAddr,
        persona: &Arc<PrebakedPersona>,
        path: &str,
        verdict: &TrapVerdict,
        canary_evidence: Option<VerificationEvidence>,
        shell_result: Option<&ShellExecResult>,
        detail: impl Into<String>,
    ) -> AttackerSessionReport {
        let now_unix = now_unix_secs();
        let detail_str = detail.into();
        let mut new_evidence = Vec::new();
        let mut upgraded_to_verified = false;
        // Global precondition for any multi-step escalation: the attacker must have submitted at
        // least this many *distinct* attack requests. Configurable; a single request can never be
        // "multi-step", so values below 2 are clamped.
        let min_distinct_requests = self.config.multi_step_min_distinct_requests.max(2);

        let report = {
            let mut sessions = self.sessions.lock().expect("sessions lock poisoned");
            self.evict_oldest_if_full(&mut sessions, client_ip);
            let session = sessions
                .entry(client_ip)
                .or_insert_with(|| AttackerSessionState::new(client_ip, persona, now_unix));

            let prev_status = session.status;
            session.last_seen_unix = now_unix;
            session.total_trapped_requests += 1;
            if session.distinct_paths.len() < MAX_DISTINCT_PATHS
                || session.distinct_paths.contains(path)
            {
                session.distinct_paths.insert(path.to_string());
            }

            // 1. Canary credential / endpoint replay -> immediate VerifiedExploit!
            if let Some(ev) = canary_evidence {
                session.canary_triggers += 1;
                session.status = ExploitVerificationStatus::VerifiedExploit;
                session.push_evidence(ev.clone());
                new_evidence.push(ev);
                self.metrics
                    .canary_verifications
                    .fetch_add(1, Ordering::Relaxed);
            }

            // Fingerprint of this concrete request. Repeated identical submissions must not
            // count as multi-step progress: a legitimate client retrying after a WAF false
            // positive would otherwise be escalated and auto-banned.
            let signature = request_signature(verdict, path, &detail_str);
            let new_signature = if session.request_signatures.contains(&signature) {
                false
            } else {
                if session.request_signatures.len() < MAX_DISTINCT_SIGNATURES {
                    session.request_signatures.insert(signature);
                }
                true
            };
            if session.attack_kinds.len() < MAX_ATTACK_KINDS {
                session.attack_kinds.insert(attack_kind(verdict));
            }
            // Only escalate once the attacker submitted enough *distinct* requests. Identical
            // retries captured above never increase this count.
            let enough_distinct = session.request_signatures.len() >= min_distinct_requests;

            // 2. Payload-diverse progression inside the primary technique families.
            match verdict {
                TrapVerdict::SqlInjectionBoolean { extracted_pos, .. } => {
                    session.sqli_probes += 1;
                    if let Some(pos) = extracted_pos {
                        session.sqli_positions.insert(*pos);
                    }
                    note_sqli_payload(session, signature, new_signature, sqli_technique(verdict));
                    let distinct_payloads = session.sqli_payloads.len();
                    let distinct_techniques = session.sqli_techniques.len();
                    // Different payloads / different SQLi flavours == genuine multi-step probing.
                    if enough_distinct
                        && (distinct_payloads >= 2 || distinct_techniques >= 2)
                        && session.status < ExploitVerificationStatus::MultiStepExploitation
                    {
                        session.status = ExploitVerificationStatus::MultiStepExploitation;
                    }
                    // Two distinct extracted character positions == real blind extraction.
                    if session.sqli_positions.len() >= 2 {
                        session.status = ExploitVerificationStatus::VerifiedExploit;
                    }
                    if new_signature {
                        let ev = VerificationEvidence::SqliExtractionProgress {
                            probe_count: distinct_payloads as u32,
                            distinct_char_positions: session.sqli_positions.len(),
                        };
                        session.push_evidence(ev.clone());
                        new_evidence.push(ev);
                    }
                }
                TrapVerdict::SqlInjectionTimeBlind { .. } | TrapVerdict::SqlInjectionError { .. } => {
                    session.sqli_probes += 1;
                    note_sqli_payload(session, signature, new_signature, sqli_technique(verdict));
                    let distinct_payloads = session.sqli_payloads.len();
                    let distinct_techniques = session.sqli_techniques.len();
                    if enough_distinct
                        && (distinct_payloads >= 2 || distinct_techniques >= 2)
                        && session.status < ExploitVerificationStatus::MultiStepExploitation
                    {
                        session.status = ExploitVerificationStatus::MultiStepExploitation;
                    }
                    if new_signature {
                        let ev = VerificationEvidence::SqliExtractionProgress {
                            probe_count: distinct_payloads as u32,
                            distinct_char_positions: session.sqli_positions.len(),
                        };
                        session.push_evidence(ev.clone());
                        new_evidence.push(ev);
                    }
                }
                TrapVerdict::CommandInjectionRce { extracted_cmd, .. } => {
                    // Only *distinct* commands prove an interactive shell; retrying the same
                    // command (e.g. `id` twice) is not multi-step exploitation.
                    let cmd_is_new = !session.rce_commands.iter().any(|c| c == extracted_cmd);
                    if cmd_is_new && session.rce_commands.len() < MAX_RCE_COMMANDS {
                        session.rce_commands.push(extracted_cmd.clone());
                    }
                    let mut iocs = Vec::new();
                    if let Some(sr) = shell_result {
                        for ioc in &sr.captured_indicators {
                            if session.captured_iocs.len() < MAX_CAPTURED_IOCS
                                && !session.captured_iocs.contains(ioc)
                            {
                                session.captured_iocs.push(ioc.clone());
                            }
                            iocs.push(ioc.clone());
                        }
                    }
                    // Payload delivery inside the fake shell (wget/curl/…) is deterministic proof.
                    if !iocs.is_empty() {
                        session.status = ExploitVerificationStatus::VerifiedExploit;
                    } else if cmd_is_new
                        && enough_distinct
                        && session.rce_commands.len() >= 2
                        && session.status < ExploitVerificationStatus::MultiStepExploitation
                    {
                        session.status = ExploitVerificationStatus::MultiStepExploitation;
                    }
                    if cmd_is_new {
                        let ev = VerificationEvidence::RceShellInteraction {
                            command_count: session.rce_commands.len() as u32,
                            last_command: extracted_cmd.clone(),
                            captured_iocs: iocs,
                        };
                        session.push_evidence(ev.clone());
                        new_evidence.push(ev);
                    }
                }
                _ => {}
            }

            // 3. Switching attack techniques (SQLi → XSS → RCE …) is itself multi-step.
            if enough_distinct
                && session.attack_kinds.len() >= 2
                && session.status < ExploitVerificationStatus::MultiStepExploitation
            {
                session.status = ExploitVerificationStatus::MultiStepExploitation;
            }

            // 4. Multi-path recon across 3+ distinct sensitive routes
            if enough_distinct
                && session.distinct_paths.len() >= 3
                && session.status < ExploitVerificationStatus::MultiStepExploitation
            {
                session.status = ExploitVerificationStatus::MultiStepExploitation;
                let ev = VerificationEvidence::MultiPathRecon {
                    distinct_paths_probed: session.distinct_paths.len(),
                };
                session.push_evidence(ev.clone());
                new_evidence.push(ev);
            }

            if prev_status < ExploitVerificationStatus::VerifiedExploit
                && session.status == ExploitVerificationStatus::VerifiedExploit
            {
                upgraded_to_verified = true;
            }

            session.to_report()
        };

        if upgraded_to_verified {
            self.metrics
                .verified_attack_sessions
                .fetch_add(1, Ordering::Relaxed);
        }

        self.push_threat_event(
            client_ip,
            persona,
            report.status,
            format!("{verdict:?}"),
            detail_str,
            new_evidence,
        );

        report
    }

    /// Record bytes and duration consumed by a client from a slow-drip tarpit stream.
    /// Once the client reads past `tarpit_verify_min_bytes` or stays connected past
    /// `tarpit_verify_min_ms`, the session is automatically upgraded to `VerifiedExploit`!
    pub fn record_tarpit_progress(
        &self,
        client_ip: IpAddr,
        persona: &PrebakedPersona,
        bytes_delta: u64,
        elapsed_ms: u64,
    ) {
        self.metrics
            .tarpit_bytes_dripped
            .fetch_add(bytes_delta, Ordering::Relaxed);

        let min_bytes = self.config.tarpit_verify_min_bytes;
        let min_ms = self.config.tarpit_verify_min_ms;
        let now_unix = now_unix_secs();

        let mut verified_event: Option<(ExploitVerificationStatus, VerificationEvidence)> = None;
        {
            let mut sessions = self.sessions.lock().expect("sessions lock poisoned");
            if let Some(session) = sessions.get_mut(&client_ip) {
                session.last_seen_unix = now_unix;
                session.tarpit_bytes_consumed += bytes_delta;
                session.tarpit_max_duration_ms = session.tarpit_max_duration_ms.max(elapsed_ms);

                let qualifies = session.tarpit_bytes_consumed >= min_bytes
                    || session.tarpit_max_duration_ms >= min_ms;
                if qualifies && session.status < ExploitVerificationStatus::VerifiedExploit {
                    session.status = ExploitVerificationStatus::VerifiedExploit;
                    let ev = VerificationEvidence::SustainedTarpitRead {
                        bytes_read: session.tarpit_bytes_consumed,
                        duration_ms: session.tarpit_max_duration_ms,
                    };
                    session.push_evidence(ev.clone());
                    verified_event = Some((session.status, ev));
                }
            }
        }

        if let Some((status, ev)) = verified_event {
            self.metrics
                .verified_attack_sessions
                .fetch_add(1, Ordering::Relaxed);
            self.push_threat_event(
                client_ip,
                persona,
                status,
                "TarpitStreamVerified".to_string(),
                format!("Sustained tarpit stream consumption by {client_ip}"),
                vec![ev],
            );
        }
    }

    /// Retrieve the current verification report for a specific client IP.
    pub fn session_report(&self, client_ip: IpAddr) -> Option<AttackerSessionReport> {
        self.sessions
            .lock()
            .ok()
            .and_then(|map| map.get(&client_ip).map(|s| s.to_report()))
    }

    /// Retrieve all tracked attacker session reports (sorted by most recent activity first).
    pub fn all_session_reports(&self) -> Vec<AttackerSessionReport> {
        let mut list: Vec<AttackerSessionReport> = self
            .sessions
            .lock()
            .map(|map| map.values().map(|s| s.to_report()).collect())
            .unwrap_or_default();
        list.sort_by(|a, b| b.last_seen_unix.cmp(&a.last_seen_unix));
        list
    }

    fn evict_oldest_if_full(
        &self,
        sessions: &mut HashMap<IpAddr, AttackerSessionState>,
        incoming_ip: IpAddr,
    ) {
        let max = self.config.max_tracked_sessions.max(16);
        if sessions.len() >= max && !sessions.contains_key(&incoming_ip) {
            if let Some(oldest_ip) = sessions
                .iter()
                .min_by_key(|(_, v)| v.last_seen_unix)
                .map(|(k, _)| *k)
            {
                sessions.remove(&oldest_ip);
            }
        }
    }

    /// Pre-bake the next epoch's `PersonaSnapshot` off-lock and atomically swap it in.
    pub fn rotate_now(&self) -> Arc<PersonaSnapshot> {
        let next_epoch = self.epoch_counter.fetch_add(1, Ordering::SeqCst) + 1;

        let new_snapshot = Arc::new(PersonaSnapshot::bake(
            self.config.master_seed,
            next_epoch,
            self.config.persona_slots,
            &self.config.canary_webhook_url,
        ));

        let old_snapshot = {
            let mut guard = self
                .snapshot
                .write()
                .expect("EvilpotEngine snapshot write lock poisoned");
            std::mem::replace(&mut *guard, new_snapshot.clone())
        };
        if let Ok(mut prev) = self.previous_snapshots.write() {
            if prev.len() >= 4 {
                prev.pop_front();
            }
            prev.push_back(old_snapshot);
        }

        self.metrics.current_epoch.store(next_epoch, Ordering::Relaxed);
        self.metrics
            .rotations_completed
            .fetch_add(1, Ordering::Relaxed);

        info!(
            epoch = next_epoch,
            slots = new_snapshot.personas.len(),
            sample_host = %new_snapshot.personas[0].hostname,
            "Rotated evilpot pre-generated persona snapshot"
        );

        new_snapshot
    }

    pub fn spawn_rotation_task(self: &Arc<Self>) -> JoinHandle<()> {
        let engine = self.clone();
        let interval_secs = engine.config.rotation_interval_secs.max(1);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                engine.rotate_now();
            }
        })
    }

    pub fn try_acquire_tarpit(self: &Arc<Self>) -> Option<TarpitPermit> {
        let max = self.config.max_tarpit_connections;
        let mut current = self
            .metrics
            .active_tarpit_connections
            .load(Ordering::Relaxed);
        loop {
            if current >= max {
                return None;
            }
            match self.metrics.active_tarpit_connections.compare_exchange_weak(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(TarpitPermit {
                        engine: self.clone(),
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn push_threat_event(
        &self,
        client_ip: IpAddr,
        persona: &PrebakedPersona,
        verification_status: ExploitVerificationStatus,
        trap_kind: String,
        detail: String,
        evidence: Vec<VerificationEvidence>,
    ) {
        let timestamp_unix = now_unix_secs();

        warn!(
            epoch = persona.epoch_id,
            persona = %persona.hostname,
            client_ip = %client_ip,
            status = ?verification_status,
            trap = %trap_kind,
            detail = %detail,
            evidence = ?evidence,
            "evilpot deception & exploit verification event"
        );

        let event = ThreatEvent {
            timestamp_unix,
            epoch_id: persona.epoch_id,
            persona_hostname: persona.hostname.clone(),
            client_ip: client_ip.to_string(),
            verification_status,
            trap_kind,
            detail,
            evidence,
        };

        if let Ok(mut queue) = self.recent_events.lock() {
            if queue.len() >= 256 {
                queue.pop_front();
            }
            queue.push_back(event);
        }
    }

    pub fn recent_events(&self) -> Vec<ThreatEvent> {
        self.recent_events
            .lock()
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn metrics_snapshot(&self) -> EvilpotMetricsSnapshot {
        EvilpotMetricsSnapshot {
            current_epoch: self.metrics.current_epoch.load(Ordering::Relaxed),
            rotations_completed: self.metrics.rotations_completed.load(Ordering::Relaxed),
            requests_handled: self.metrics.requests_handled.load(Ordering::Relaxed),
            traps_triggered: self.metrics.traps_triggered.load(Ordering::Relaxed),
            canary_verifications: self.metrics.canary_verifications.load(Ordering::Relaxed),
            verified_attack_sessions: self
                .metrics
                .verified_attack_sessions
                .load(Ordering::Relaxed),
            tarpit_bytes_dripped: self.metrics.tarpit_bytes_dripped.load(Ordering::Relaxed),
            active_tarpit_connections: self
                .metrics
                .active_tarpit_connections
                .load(Ordering::Relaxed),
        }
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn normalize_ip_subnet(ip: IpAddr) -> [u8; 8] {
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            [oct[0], oct[1], oct[2], 0, 0, 0, 0, 4]
        }
        IpAddr::V6(v6) => {
            let oct = v6.octets();
            [oct[0], oct[1], oct[2], oct[3], oct[4], oct[5], oct[6], oct[7]]
        }
    }
}
