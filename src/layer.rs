use crate::engine::EvilpotEngine;
use crate::http::{full_body, EvilpotBody};
use crate::trap::AttackSignal;
use futures_core::Future;
use http::{Request, Response, StatusCode};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

/// Conversion trait allowing [`EvilpotBody`] to be converted seamlessly into the caller's
/// response body type (such as `axum::body::Body` or `http_body_util::combinators::BoxBody`).
pub trait IntoResponseBody {
    fn from_evilpot_body(body: EvilpotBody) -> Self;
}

impl IntoResponseBody for EvilpotBody {
    fn from_evilpot_body(body: EvilpotBody) -> Self {
        body
    }
}

#[cfg(feature = "axum")]
impl IntoResponseBody for axum::body::Body {
    fn from_evilpot_body(body: EvilpotBody) -> Self {
        axum::body::Body::new(body)
    }
}

/// A `tower::Layer` that wraps any HTTP service (Axum, Hyper, Tower) using a caller-supplied
/// classifier closure `F: Fn(&Request<ReqBody>) -> Option<AttackSignal>`.
///
/// Because `evilpot` does NOT perform attack detection itself, the caller decides when a request
/// should be diverted into `evilpot` (either via the classifier closure `F`, or by attaching an
/// [`AttackSignal`] to `req.extensions()`). Additionally, `evilpot` automatically intercepts
/// requests that trigger an implanted canary credential/path or hit the secret admin panel.
#[derive(Clone)]
pub struct EvilpotLayer<F> {
    engine: Arc<EvilpotEngine>,
    classifier: F,
    real_ip_header: Option<String>,
}

impl<F> EvilpotLayer<F> {
    pub fn new(engine: Arc<EvilpotEngine>, classifier: F) -> Self {
        Self {
            engine,
            classifier,
            real_ip_header: Some("x-real-ip".to_string()),
        }
    }

    pub fn with_real_ip_header(mut self, header_name: Option<String>) -> Self {
        self.real_ip_header = header_name;
        self
    }
}

impl<S, F: Clone> Layer<S> for EvilpotLayer<F> {
    type Service = EvilpotService<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        EvilpotService {
            inner,
            engine: self.engine.clone(),
            classifier: self.classifier.clone(),
            real_ip_header: self.real_ip_header.clone(),
        }
    }
}

#[derive(Clone)]
pub struct EvilpotService<S, F> {
    inner: S,
    engine: Arc<EvilpotEngine>,
    classifier: F,
    real_ip_header: Option<String>,
}

impl<S, F, ReqBody, RespBody> Service<Request<ReqBody>> for EvilpotService<S, F>
where
    S: Service<Request<ReqBody>, Response = Response<RespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    F: Fn(&Request<ReqBody>) -> Option<AttackSignal> + Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    RespBody: IntoResponseBody + Send + 'static,
{
    type Response = Response<RespBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // 1. Check secret admin panel routes (`/status`, `/sessions`, `/rotate`)
        if let Some(admin_resp) =
            self.engine
                .handle_admin_request(req.method().as_str(), req.uri().path(), req.headers())
        {
            return Box::pin(async move { Ok(admin_resp.map(RespBody::from_evilpot_body)) });
        }

        let client_ip = extract_client_ip(&req, self.real_ip_header.as_deref());

        // 2. Check if caller attached an AttackSignal in request extensions or via classifier closure
        let signal = req
            .extensions()
            .get::<AttackSignal>()
            .cloned()
            .or_else(|| (self.classifier)(&req));

        if let Some(sig) = signal {
            let engine = self.engine.clone();
            let method = req.method().as_str().to_string();
            let path = req.uri().path().to_string();
            let query = req.uri().query().map(str::to_string);
            let headers = req.headers().clone();
            return Box::pin(async move {
                let outcome = engine
                    .handle_attack(client_ip, &method, &path, query.as_deref(), &headers, sig)
                    .await;
                Ok(outcome.response.map(RespBody::from_evilpot_body))
            });
        }

        // 3. Even if the caller's WAF did not flag the syntax of this request, check if the client
        // is replaying a stolen canary token / API key / cookie / vault export URL from an earlier trap!
        if self
            .engine
            .check_canary_trigger(client_ip, req.uri().path(), req.uri().query(), req.headers())
            .is_some()
        {
            let engine = self.engine.clone();
            let method = req.method().as_str().to_string();
            let path = req.uri().path().to_string();
            let query = req.uri().query().map(str::to_string);
            let headers = req.headers().clone();
            return Box::pin(async move {
                match engine
                    .handle_canary_if_present(
                        client_ip,
                        &method,
                        &path,
                        query.as_deref(),
                        &headers,
                    )
                    .await
                {
                    Some(outcome) => Ok(outcome.response.map(RespBody::from_evilpot_body)),
                    // Extremely rare race: a persona rotation happened between the
                    // pre-check and the handler. Fail closed with a benign 404 instead
                    // of panicking and tearing down the connection/task.
                    None => Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(RespBody::from_evilpot_body(full_body(bytes::Bytes::from_static(
                            b"Not Found",
                        ))))
                        .expect("valid static response")),
                }
            });
        }

        // 4. Benign request -> pass through to inner service
        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

pub fn extract_client_ip<B>(req: &Request<B>, preferred_header: Option<&str>) -> IpAddr {
    if let Some(hdr_name) = preferred_header {
        if let Some(val) = req.headers().get(hdr_name).and_then(|v| v.to_str().ok()) {
            if let Some(first) = val.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    if let Some(xff) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first_ip) = xff.split(',').next() {
            if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    #[cfg(feature = "axum")]
    if let Some(axum::extract::ConnectInfo(addr)) =
        req.extensions().get::<axum::extract::ConnectInfo<SocketAddr>>()
    {
        return addr.ip();
    }
    if let Some(addr) = req.extensions().get::<SocketAddr>() {
        return addr.ip();
    }
    if let Some(ip) = req.extensions().get::<IpAddr>() {
        return *ip;
    }
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}
