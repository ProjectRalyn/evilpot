use axum::{body::Body as AxumBody, routing::get, Router};
use evilpot::{AttackCategory, AttackSignal, EvilpotConfig, EvilpotEngine, EvilpotLayer};
use http::Request;

#[tokio::main]
async fn main() {
    let engine = EvilpotEngine::new(EvilpotConfig::default());
    // Spawn scheduled background payload rotation
    engine.spawn_rotation_task();

    // Caller supplies its own WAF / route classifier closure to decide which requests enter evilpot:
    let caller_waf_classifier = |req: &Request<AxumBody>| -> Option<AttackSignal> {
        let path = req.uri().path();
        if path == "/.env" || path.starts_with("/.git") {
            return Some(AttackSignal::new(
                AttackCategory::SecretLeakProbe,
                "path",
                0.99,
            ));
        }
        if path.starts_with("/wp-") {
            return Some(AttackSignal::new(
                AttackCategory::WordPressProbe,
                "path",
                0.95,
            ));
        }
        None
    };

    let app = Router::new()
        .route("/api/health", get(|| async { "OK" }))
        .route(
            "/api/v1/items",
            get(|| async { r#"[{"id":1,"name":"real-item"}]"# }),
        )
        // Caller-classified attacks and any replayed canary credentials get trapped by evilpot!
        .layer(EvilpotLayer::new(engine, caller_waf_classifier));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("Embedded evilpot + Axum listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}
