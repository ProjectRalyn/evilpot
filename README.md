# evilpot

**Embeddable zero-copy HTTP deception, exploit verification & tarpit honeypot in Rust.**

This repository provides two components with a clean separation of responsibilities:

1. **`evilpot` (Root Library Crate)**:
   - Pure HTTP deception, exploit verification, and slow-drip tarpit engine designed to be embedded directly inside an existing Rust gateway or WAF (such as **Exposure**).
   - **Zero redundant WAF scanning**: `evilpot` does **not** perform attack recognition itself (`sigil-filter` is not even a dependency of the `evilpot` library crate). Instead, the caller's WAF identifies an attack and passes an [`AttackSignal`](src/trap.rs) into `evilpot`.
   - **Exploit Verification State Machine**: Instead of returning a static `403 Forbidden`, `evilpot` disguises the endpoint as vulnerable and verifies whether the client is a real attacker or a benign false positive:
     - **Implanted Canary Credentials & Endpoints (`VerifiedExploit`)**: Every fake `.env`, `wp-config.php.bak`, SSRF IMDSv1 JSON, SQLi error, and debug dump embeds persona-bound canary API tokens (`epk_...`), AWS keys (`AKIA...`), session cookies, and a secret vault export route (`/api/v1/internal/vault-export/...`). If the client replays any of these in a subsequent request, `evilpot::EvilpotEngine::handle_canary_if_present` immediately confirms 100% real exploitation.
     - **Multi-Step Interaction & IOC Extraction**: Tracks SQLMap boolean/time-blind character extraction positions, stateful per-IP RCE commands in an in-memory Ubuntu 22.04 `FakeShellSession` (capturing `wget`/`curl` C2 URLs and CoW file writes), and multi-path LFI reconnaissance.
     - **Sustained Tarpit Consumption**: Monitors bytes and duration consumed on 256 MiB slow-drip `/actuator/heapdump` and `.sql.gz` tarpit streams.

2. **`evilpot-forefront` (`crates/evilpot-forefront` Standalone Reverse Proxy)**:
   - Standalone reverse proxy (`frontline_proxy`), honeypot (`standalone`), and WAF sink (`behind_proxy_sink`) binary.
   - Embeds `sigil-filter` ( inspects URI path, query key/values, HTTP headers with false-positive-safe category masks, and `POST`/`PUT`/`PATCH` text/JSON/form/XML bodies) plus high-specificity decoy routes (`/.env`, `/.git/config`, `/wp-login.php`, `/actuator/env`, `/heapdump`, etc.) to recognize attacks and dynamically divert them into `evilpot`.

## Embedding `evilpot` in Exposure (or any Hyper/Axum/Tower Proxy)

```rust
use evilpot::{AttackSignal, EvilpotConfig, EvilpotEngine};

// 1. Initialize once at node startup:
let engine = EvilpotEngine::new(EvilpotConfig::default());
engine.spawn_rotation_task();

// 2. Check incoming requests for replayed canary tokens (even before or after WAF):
if let Some(outcome) = engine
    .handle_canary_if_present(client_ip, req.method().as_str(), path, query, req.headers())
    .await
{
    // `outcome.session.status == ExploitVerificationStatus::VerifiedExploit`
    return outcome.response;
}

// 3. When your WAF blocks a request (e.g. Exposure's `WafVerdict::Block(finding)`),
//    divert it into `evilpot` instead of returning a static 403 page:
let signal = AttackSignal::from_waf_finding(
    finding.category,
    finding.location,
    finding.confidence,
    finding.reasons.iter().map(|s| (*s).to_string()).collect(),
)
.with_payload(raw_query_or_body_sample);

let outcome = engine
    .handle_attack(client_ip, req.method().as_str(), path, query, req.headers(), signal)
    .await;
// `outcome.response` is `http::Response<EvilpotBody>` (zero-copy `BoxBody<Bytes, Infallible>`)
// `outcome.session` contains the attacker's live `ExploitVerificationStatus` and captured IOCs!
```

## Running `evilpot-forefront` Standalone Reverse Proxy

```bash
cargo build --release --workspace
./target/release/evilpot-forefront --mode frontline-proxy --bind 0.0.0.0:8080 --upstream http://127.0.0.1:3000
```
