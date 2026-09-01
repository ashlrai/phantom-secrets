use phantom_core::issuance::{
    build_http_client, default_consent_engines, Endpoints, IssuanceDeps, IssuanceError,
    IssuanceRequest, NoBrowser, StdLoopbackListener,
};

#[test]
fn every_public_consent_engine_hard_denies_in_a_shipped_library_build() {
    let endpoints = Endpoints::for_provider("github").expect("fixed provider endpoints");
    let browser = NoBrowser;
    let loopback = StdLoopbackListener::new();
    let http = build_http_client().expect("HTTP client construction");
    let deps = IssuanceDeps {
        browser: &browser,
        loopback: &loopback,
        http: &http,
        endpoints: &endpoints,
    };
    let request = IssuanceRequest {
        provider: "github".to_string(),
        client_id: None,
        client_secret: None,
        scopes: Vec::new(),
        flow: None,
        app_manifest: None,
        team_id: None,
        account: None,
        org: None,
    };

    for engine in default_consent_engines() {
        let error = match engine.issue(&request, &deps) {
            Err(error) => error,
            Ok(_) => panic!("{} unexpectedly issued a credential", engine.name()),
        };
        assert!(matches!(error, IssuanceError::NotSupported { .. }));
    }
}
