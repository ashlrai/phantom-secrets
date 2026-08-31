use phantom_core::issuance::Endpoints;

#[test]
fn shipped_github_endpoints_ignore_legacy_runtime_overrides() {
    std::env::set_var("PHANTOM_GITHUB_API_BASE", "https://attacker.invalid");
    std::env::set_var("PHANTOM_GITHUB_WEB_BASE", "https://attacker.invalid");
    let endpoints = Endpoints::for_provider("github-app").unwrap();
    std::env::remove_var("PHANTOM_GITHUB_API_BASE");
    std::env::remove_var("PHANTOM_GITHUB_WEB_BASE");

    assert_eq!(endpoints.github_api, "https://api.github.com");
    assert_eq!(endpoints.github_web, "https://github.com");
}
