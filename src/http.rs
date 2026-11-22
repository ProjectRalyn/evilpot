use crate::engine::{
    AttackerSessionReport, EvilpotEngine, TarpitPermit, VerificationEvidence,
};
use crate::persona::PrebakedPersona;
use crate::trap::{
    select_trap_for_signal, AttackSignal, LfiTargetHint, TarpitKind, TrapVerdict,
};
use bytes::Bytes;
use futures_core::Future;
use http::{header, HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use http_body::{Body as HttpBody, Frame};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::convert::Infallible;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::time::Sleep;

/// Standard zero-copy HTTP response body returned by `evilpot`.
/// Can be converted directly into Hyper/Exposure `BoxBody<Bytes, E>` via `.map_err(...)`
/// or into `axum::body::Body::new(body)`.
pub type EvilpotBody = BoxBody<Bytes, Infallible>;

/// Output returned when `evilpot` handles an intercepted attack request or a canary trigger.
pub struct DeceptionOutcome {
    /// Complete HTTP response (with spoofed `Server`, `X-Powered-By`, and decoy body/tarpit stream).
    pub response: Response<EvilpotBody>,
    /// The specific deception trap selected for this request.
    pub verdict: TrapVerdict,
    /// Updated multi-step exploit verification report for this attacker IP.
    pub session: AttackerSessionReport,
}

impl EvilpotEngine {
    /// Intercept and verify an incoming request IF it triggers an implanted canary token, cookie,
    /// API key, or secret vault export path from an active persona.
    ///
    /// Returns `Some(DeceptionOutcome)` with `ExploitVerificationStatus::VerifiedExploit` if a canary
    /// was triggered, or `None` if the request does not contain any canary indicators.
    pub async fn handle_canary_if_present(
        self: &Arc<Self>,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> Option<DeceptionOutcome> {
        let canary_ev = self.check_canary_trigger(client_ip, path, query, headers)?;
        let trigger_desc = match &canary_ev {
            VerificationEvidence::CanaryTriggered {
                kind,
                token_or_path,
            } => format!("{kind}={token_or_path}"),
            _ => "canary".to_string(),
        };

        self.metrics
            .requests_handled
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .traps_triggered
            .fetch_add(1, Ordering::Relaxed);

        let persona = self.select_persona(client_ip);
        let verdict = TrapVerdict::CanaryVaultExport {
            trigger: trigger_desc.clone(),
        };
        let uri_display = match query {
            Some(q) if !q.is_empty() => format!("{path}?{q}"),
            _ => path.to_string(),
        };
        let session = self.record_trap_interaction(
            client_ip,
            &persona,
            path,
            &verdict,
            Some(canary_ev),
            None,
            format!("{method} {uri_display} (CANARY TRIGGERED: {trigger_desc})"),
        );
        let response = build_trap_http_response(self, client_ip, &persona, &verdict, None).await;

        Some(DeceptionOutcome {
            response,
            verdict,
            session,
        })
    }

    /// Divert a WAF-flagged request into `evilpot` using the caller's [`AttackSignal`].
    ///
    /// `evilpot` selects an exploitable deception trap matching `signal`, checks if the request
    /// also replays any implanted canary tokens, updates the attacker's multi-step verification
    /// state machine, and returns the spoofed HTTP response + [`AttackerSessionReport`].
    pub async fn handle_attack(
        self: &Arc<Self>,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        signal: AttackSignal,
    ) -> DeceptionOutcome {
        self.metrics
            .requests_handled
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .traps_triggered
            .fetch_add(1, Ordering::Relaxed);

        let persona = self.select_persona(client_ip);
        let canary_ev = self.check_canary_trigger(client_ip, path, query, headers);

        let verdict = if let Some(VerificationEvidence::CanaryTriggered {
            ref kind,
            ref token_or_path,
        }) = canary_ev
        {
            TrapVerdict::CanaryVaultExport {
                trigger: format!("{kind}={token_or_path}"),
            }
        } else {
            select_trap_for_signal(
                &signal,
                method,
                path,
                query,
                &persona,
                self.config().sqli_time_delay_ms,
            )
        };

        let shell_res = match &verdict {
            TrapVerdict::CommandInjectionRce { extracted_cmd, .. } => {
                Some(self.execute_rce_command(client_ip, &persona, extracted_cmd))
            }
            _ => None,
        };

        let uri_display = match query {
            Some(q) if !q.is_empty() => format!("{path}?{q}"),
            _ => path.to_string(),
        };
        let detail = format!(
            "{method} {uri_display} [category={} loc={} conf={:.2}]",
            signal.category.as_str(),
            signal.location,
            signal.confidence
        );

        let session = self.record_trap_interaction(
            client_ip,
            &persona,
            path,
            &verdict,
            canary_ev,
            shell_res.as_ref(),
            detail,
        );

        let response =
            build_trap_http_response(self, client_ip, &persona, &verdict, shell_res).await;

        DeceptionOutcome {
            response,
            verdict,
            session,
        }
    }

    /// Handle an admin panel request (`GET {admin_prefix}/status` or `POST {admin_prefix}/rotate`).
    /// Returns `Some(Response<EvilpotBody>)` if `path` starts with `self.admin_path_prefix()` and admin is enabled.
    pub fn handle_admin_request(
        self: &Arc<Self>,
        method: &str,
        path: &str,
        headers: &HeaderMap,
    ) -> Option<Response<EvilpotBody>> {
        if !self.config().admin.enabled {
            return None;
        }
        let prefix = self.admin_path_prefix();
        if !path.starts_with(prefix) {
            return None;
        }
        if !check_admin_token(headers, &self.config().admin.secret_token) {
            return Some(
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(full_body(Bytes::from_static(b"Not Found")))
                    .unwrap(),
            );
        }

        let status_path = format!("{prefix}/status");
        let rotate_path = format!("{prefix}/rotate");
        let sessions_path = format!("{prefix}/sessions");

        if method.eq_ignore_ascii_case("GET") && path == status_path {
            let snap = self.current_snapshot();
            let body = serde_json::json!({
                "epoch_id": snap.epoch_id,
                "generated_at_unix": snap.generated_at_unix,
                "admin_path_prefix": self.admin_path_prefix(),
                "persona_slots": snap.personas.len(),
                "sample_personas": snap.personas.iter().take(4).map(|p| serde_json::json!({
                    "slot_id": p.slot_id,
                    "hostname": p.hostname,
                    "internal_ip": p.internal_ip,
                    "server_header": p.server_header,
                    "wp_version": p.wp_version,
                    "canary_endpoint_path": p.canary_endpoint_path,
                })).collect::<Vec<_>>(),
                "metrics": self.metrics_snapshot(),
                "verified_sessions": self.all_session_reports(),
                "recent_events": self.recent_events(),
            });
            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(full_body(Bytes::from(
                        serde_json::to_vec_pretty(&body).unwrap_or_default(),
                    )))
                    .unwrap(),
            );
        }

        if method.eq_ignore_ascii_case("GET") && path == sessions_path {
            let body = serde_json::json!({
                "sessions": self.all_session_reports(),
            });
            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(full_body(Bytes::from(
                        serde_json::to_vec_pretty(&body).unwrap_or_default(),
                    )))
                    .unwrap(),
            );
        }

        if method.eq_ignore_ascii_case("POST") && path == rotate_path {
            let new_snap = self.rotate_now();
            let body = serde_json::json!({
                "status": "rotated",
                "new_epoch_id": new_snap.epoch_id,
                "sample_hostname": new_snap.personas[0].hostname,
            });
            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(full_body(Bytes::from(
                        serde_json::to_vec_pretty(&body).unwrap_or_default(),
                    )))
                    .unwrap(),
            );
        }

        Some(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full_body(Bytes::from_static(b"Not Found")))
                .unwrap(),
        )
    }
}

pub fn full_body(data: impl Into<Bytes>) -> EvilpotBody {
    Full::new(data.into()).boxed()
}

fn check_admin_token(headers: &HeaderMap, expected: &Option<String>) -> bool {
    let Some(expected_tok) = expected else {
        return true;
    };
    headers
        .get("x-evilpot-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == expected_tok)
        .unwrap_or(false)
}

/// Build a zero-copy pre-baked response or slow-drip tarpit stream for a matched [`TrapVerdict`].
pub async fn build_trap_http_response(
    engine: &Arc<EvilpotEngine>,
    client_ip: IpAddr,
    persona: &Arc<PrebakedPersona>,
    verdict: &TrapVerdict,
    shell_res: Option<crate::shell::ShellExecResult>,
) -> Response<EvilpotBody> {
    match verdict {
        TrapVerdict::CanaryVaultExport { .. } => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.canary_vault_export_json.clone(),
            false,
        ),
        TrapVerdict::WordPressLogin { is_post_attempt } => {
            if *is_post_attempt {
                if let Some(_permit) = engine.try_acquire_tarpit() {
                    tokio::time::sleep(Duration::from_millis(1800)).await;
                }
                static_response(
                    persona,
                    StatusCode::OK,
                    "text/html; charset=UTF-8",
                    persona.wp_login_error_html.clone(),
                    true,
                )
            } else {
                static_response(
                    persona,
                    StatusCode::OK,
                    "text/html; charset=UTF-8",
                    persona.wp_login_html.clone(),
                    true,
                )
            }
        }
        TrapVerdict::WordPressRestIndex => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.wp_json_index.clone(),
            true,
        ),
        TrapVerdict::WordPressUsersJson => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.wp_users_json.clone(),
            true,
        ),
        TrapVerdict::WordPressPostsJson => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.wp_posts_json.clone(),
            true,
        ),
        TrapVerdict::WordPressXmlRpc => {
            if let Some(_permit) = engine.try_acquire_tarpit() {
                tokio::time::sleep(Duration::from_millis(2000)).await;
            }
            static_response(
                persona,
                StatusCode::OK,
                "text/xml; charset=UTF-8",
                persona.wp_xmlrpc_fault_xml.clone(),
                true,
            )
        }
        TrapVerdict::WordPressConfigBackup => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.wp_config_bak.clone(),
            true,
        ),
        TrapVerdict::WordPressDebugLog => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.wp_debug_log.clone(),
            true,
        ),
        TrapVerdict::WordPressAdminAjax => static_response(
            persona,
            StatusCode::BAD_REQUEST,
            "application/json; charset=UTF-8",
            persona.wp_admin_ajax_json.clone(),
            true,
        ),
        TrapVerdict::WordPressReadme => static_response(
            persona,
            StatusCode::OK,
            "text/html; charset=UTF-8",
            persona.wp_readme_html.clone(),
            true,
        ),
        TrapVerdict::DotEnvLeak => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.dotenv_body.clone(),
            false,
        ),
        TrapVerdict::GitConfigLeak => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.git_config_body.clone(),
            false,
        ),
        TrapVerdict::GitHeadLeak => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.git_head_body.clone(),
            false,
        ),
        TrapVerdict::SpringActuatorEnv => static_response(
            persona,
            StatusCode::OK,
            "application/vnd.spring-boot.actuator.v3+json; charset=UTF-8",
            persona.actuator_env_json.clone(),
            false,
        ),
        TrapVerdict::PhpInfo => static_response(
            persona,
            StatusCode::OK,
            "text/html; charset=UTF-8",
            persona.phpinfo_html.clone(),
            false,
        ),
        TrapVerdict::GraphqlIntrospection => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.graphql_introspection_json.clone(),
            false,
        ),
        TrapVerdict::OpenApiSchema => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.openapi_json.clone(),
            false,
        ),
        TrapVerdict::ApiDebugEndpoint => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.api_debug_json.clone(),
            false,
        ),
        TrapVerdict::SqlInjectionError { is_postgres } => {
            let body = if *is_postgres {
                persona.sqli_error_postgres_html.clone()
            } else {
                persona.sqli_error_mysql_html.clone()
            };
            static_response(
                persona,
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/html; charset=UTF-8",
                body,
                false,
            )
        }
        TrapVerdict::SqlInjectionBoolean { truthy, .. } => {
            let body = if *truthy {
                persona.sqli_boolean_true_html.clone()
            } else {
                persona.sqli_boolean_false_html.clone()
            };
            static_response(persona, StatusCode::OK, "text/html; charset=UTF-8", body, false)
        }
        TrapVerdict::SqlInjectionTimeBlind { delay_ms } => {
            if let Some(_permit) = engine.try_acquire_tarpit() {
                tokio::time::sleep(Duration::from_millis(*delay_ms)).await;
            }
            static_response(
                persona,
                StatusCode::OK,
                "text/html; charset=UTF-8",
                persona.sqli_boolean_true_html.clone(),
                false,
            )
        }
        TrapVerdict::TarpitStream { kind } => {
            let (content_type, disposition, chunk) = match kind {
                TarpitKind::GzipSqlBackup => (
                    "application/gzip",
                    "attachment; filename=\"prod_ledger_full_dump.sql.gz\"",
                    persona.tarpit_gzip_chunk.clone(),
                ),
                TarpitKind::JavaHprof => (
                    "application/octet-stream",
                    "attachment; filename=\"heapdump.hprof\"",
                    persona.tarpit_hprof_chunk.clone(),
                ),
            };

            let advertised_size = engine.config().fake_archive_size_bytes;
            let drip_rate = engine.config().tarpit_drip_bytes_per_sec.max(16);

            if let Some(permit) = engine.try_acquire_tarpit() {
                let drip_body = TarpitDripBody::new(
                    engine.clone(),
                    client_ip,
                    persona.clone(),
                    chunk,
                    advertised_size,
                    drip_rate,
                    permit,
                );
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, content_type)
                    .header(header::CONTENT_DISPOSITION, disposition)
                    .header(header::CONTENT_LENGTH, advertised_size.to_string())
                    .body(drip_body.boxed())
                    .unwrap();
                inject_persona_headers(persona, &mut resp, false);
                resp
            } else {
                static_response(persona, StatusCode::OK, content_type, chunk, false)
            }
        }
        TrapVerdict::PathTraversalLfi { target, .. } => {
            let body = match target {
                LfiTargetHint::EtcPasswd => persona.lfi_etc_passwd_body.clone(),
                LfiTargetHint::EtcShadow => Bytes::from(
                    persona
                        .shell_vfs
                        .files
                        .get("/etc/shadow")
                        .cloned()
                        .unwrap_or_default(),
                ),
                LfiTargetHint::ProcSelfEnviron => persona.lfi_proc_environ_body.clone(),
                LfiTargetHint::DotEnv => persona.dotenv_body.clone(),
                LfiTargetHint::WpConfig => persona.wp_config_bak.clone(),
            };
            static_response(persona, StatusCode::OK, "text/plain; charset=UTF-8", body, false)
        }
        TrapVerdict::CommandInjectionRce { extracted_cmd, .. } => {
            let res = shell_res
                .unwrap_or_else(|| engine.execute_rce_command(client_ip, persona, extracted_cmd));
            if res.delay_ms > 0 {
                if let Some(_permit) = engine.try_acquire_tarpit() {
                    tokio::time::sleep(Duration::from_millis(res.delay_ms.min(2500))).await;
                }
            }
            static_response(
                persona,
                StatusCode::OK,
                "text/plain; charset=UTF-8",
                Bytes::from(res.output),
                false,
            )
        }
        TrapVerdict::SsrfCloudMetadata { .. } => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.ssrf_aws_imds_json.clone(),
            false,
        ),
        TrapVerdict::SstiTemplateEval { .. } => static_response(
            persona,
            StatusCode::OK,
            "text/html; charset=UTF-8",
            persona.ssti_eval_html.clone(),
            false,
        ),
        TrapVerdict::NoSqlAdminDump { .. } => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.nosql_dump_json.clone(),
            false,
        ),
        TrapVerdict::XxeEntityLeak { .. } => static_response(
            persona,
            StatusCode::OK,
            "application/xml; charset=UTF-8",
            persona.xxe_response_xml.clone(),
            false,
        ),
        TrapVerdict::DeserializationJndiTrap { .. } => {
            if let Some(_permit) = engine.try_acquire_tarpit() {
                tokio::time::sleep(Duration::from_millis(900)).await;
            }
            static_response(
                persona,
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain; charset=UTF-8",
                persona.deser_jndi_trace_html.clone(),
                false,
            )
        }
        TrapVerdict::LdapDirectoryDump { .. } => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.ldap_dump_ldif.clone(),
            false,
        ),
        TrapVerdict::XssBaitPage { .. } => {
            let mut resp = static_response(
                persona,
                StatusCode::OK,
                "text/html; charset=UTF-8",
                persona.xss_bait_html.clone(),
                false,
            );
            if let Ok(cookie) = HeaderValue::from_str(&format!(
                "admin_session_id={}; Path=/",
                &persona.canary_cookie_value
            )) {
                resp.headers_mut().insert(header::SET_COOKIE, cookie);
            }
            resp
        }
        TrapVerdict::CrlfProxyDebug { .. } => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.crlf_proxy_debug_html.clone(),
            false,
        ),
    }
}

fn static_response(
    persona: &PrebakedPersona,
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
    is_wordpress: bool,
) -> Response<EvilpotBody> {
    let mut resp = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(full_body(body))
        .unwrap();
    inject_persona_headers(persona, &mut resp, is_wordpress);
    resp
}

pub fn inject_persona_headers<B>(
    persona: &PrebakedPersona,
    resp: &mut Response<B>,
    is_wordpress: bool,
) {
    if let Ok(val) = HeaderValue::from_str(&persona.server_header) {
        resp.headers_mut().insert(header::SERVER, val);
    }
    if let Ok(val) = HeaderValue::from_str(&persona.powered_by_header) {
        resp.headers_mut()
            .insert(HeaderName::from_static("x-powered-by"), val);
    }
    if let Ok(val) = HeaderValue::from_str(&persona.hostname) {
        resp.headers_mut()
            .insert(HeaderName::from_static("x-backend-node"), val);
    }
    if is_wordpress {
        if let Ok(pingback) =
            HeaderValue::from_str(&format!("http://{}.internal/xmlrpc.php", persona.hostname))
        {
            resp.headers_mut()
                .insert(HeaderName::from_static("x-pingback"), pingback);
        }
        if let Ok(link) = HeaderValue::from_str(&format!(
            "<http://{}.internal/wp-json/>; rel=\"https://api.w.org/\"",
            persona.hostname
        )) {
            resp.headers_mut().insert(header::LINK, link);
        }
        if let Ok(cookie) = HeaderValue::from_str(&format!(
            "wordpress_test_cookie=WP%20Cookie%20check; path=/; wordpress_sec_{}={}; path=/wp-admin",
            &persona.wp_cookie_hash[..16],
            &persona.canary_cookie_value
        )) {
            resp.headers_mut().insert(header::SET_COOKIE, cookie);
        }
    }
}

/// Zero-allocation slow-drip HTTP body stream for tarpitting scanners & data exfiltration tools.
/// Automatically updates `EvilpotEngine::record_tarpit_progress` as the attacker reads frames,
/// verifying active download tools once they exceed the byte or duration threshold!
pub struct TarpitDripBody {
    engine: Arc<EvilpotEngine>,
    client_ip: IpAddr,
    persona: Arc<PrebakedPersona>,
    started_at: Instant,
    chunk: Bytes,
    cursor: usize,
    remaining_bytes: u64,
    drip_bytes_per_tick: usize,
    tick_interval: Duration,
    sleep: Option<Pin<Box<Sleep>>>,
    first_frame_sent: bool,
    _permit: TarpitPermit,
}

impl TarpitDripBody {
    pub fn new(
        engine: Arc<EvilpotEngine>,
        client_ip: IpAddr,
        persona: Arc<PrebakedPersona>,
        chunk: Bytes,
        total_bytes: u64,
        bytes_per_sec: usize,
        permit: TarpitPermit,
    ) -> Self {
        let drip_bytes_per_tick = (bytes_per_sec / 4).clamp(8, 1024);
        Self {
            engine,
            client_ip,
            persona,
            started_at: Instant::now(),
            chunk,
            cursor: 0,
            remaining_bytes: total_bytes,
            drip_bytes_per_tick,
            tick_interval: Duration::from_millis(250),
            sleep: None,
            first_frame_sent: false,
            _permit: permit,
        }
    }
}

impl HttpBody for TarpitDripBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.remaining_bytes == 0 {
            return Poll::Ready(None);
        }

        if self.first_frame_sent {
            if self.sleep.is_none() {
                self.sleep = Some(Box::pin(tokio::time::sleep(self.tick_interval)));
            }
            if let Some(sleep) = self.sleep.as_mut() {
                match sleep.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(()) => {
                        self.sleep = None;
                    }
                }
            }
        } else {
            self.first_frame_sent = true;
        }

        let to_send = (self.drip_bytes_per_tick as u64)
            .min(self.remaining_bytes)
            .min((self.chunk.len() - self.cursor) as u64) as usize;

        let slice = self.chunk.slice(self.cursor..self.cursor + to_send);
        self.cursor = (self.cursor + to_send) % self.chunk.len();
        self.remaining_bytes -= to_send as u64;

        let elapsed_ms = self.started_at.elapsed().as_millis() as u64;
        self.engine.record_tarpit_progress(
            self.client_ip,
            &self.persona,
            to_send as u64,
            elapsed_ms,
        );

        Poll::Ready(Some(Ok(Frame::data(slice))))
    }
}
