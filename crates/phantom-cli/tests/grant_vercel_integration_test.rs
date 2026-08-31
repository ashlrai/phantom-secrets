use phantom_core::issuance::Endpoints;

#[test]
fn shipped_vercel_exchange_ignores_legacy_runtime_override() {
    std::env::set_var("PHANTOM_OAUTH_TOKEN_BASE", "https://attacker.invalid/token");
    let endpoints = Endpoints::for_provider("vercel-integration").unwrap();
    std::env::remove_var("PHANTOM_OAUTH_TOKEN_BASE");

    assert_eq!(
        endpoints.token,
        "https://api.vercel.com/v2/oauth/access_token"
    );
}
