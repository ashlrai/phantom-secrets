use anyhow::{Context, Result};
use colored::Colorize;

/// Resolve a friendly target name to a URL on phm.dev.
fn resolve_target(target: &str) -> String {
    match target {
        // Default — most common reason to run `phantom open`.
        "" | "dashboard" => "https://phm.dev/dashboard".to_string(),
        "billing" => "https://phm.dev/dashboard/billing".to_string(),
        "team" | "teams" => "https://phm.dev/dashboard/team".to_string(),
        "docs" => "https://phm.dev/docs".to_string(),
        "pricing" => "https://phm.dev/pricing".to_string(),
        "github" | "repo" => "https://github.com/ashlrai/phantom-secrets".to_string(),
        "issues" => "https://github.com/ashlrai/phantom-secrets/issues".to_string(),
        "site" | "home" => "https://phm.dev".to_string(),
        // Arbitrary URLs are passed through, so `phantom open https://...`
        // works as a shortcut. Anything that doesn't look like a URL falls
        // through to a project-page convention on phm.dev.
        other if other.starts_with("http://") || other.starts_with("https://") => other.to_string(),
        other => format!("https://phm.dev/{}", other.trim_start_matches('/')),
    }
}

pub fn run(target: &str) -> Result<()> {
    let url = resolve_target(target);
    open::that(&url).with_context(|| format!("Failed to open browser for {url}"))?;
    println!("{}  Opened {}", "ok".green().bold(), url);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_target_defaults_to_dashboard() {
        assert_eq!(resolve_target(""), "https://phm.dev/dashboard");
        assert_eq!(resolve_target("dashboard"), "https://phm.dev/dashboard");
    }

    #[test]
    fn known_aliases_resolve() {
        assert_eq!(
            resolve_target("billing"),
            "https://phm.dev/dashboard/billing"
        );
        assert_eq!(resolve_target("team"), "https://phm.dev/dashboard/team");
        assert_eq!(resolve_target("teams"), "https://phm.dev/dashboard/team");
        assert_eq!(resolve_target("docs"), "https://phm.dev/docs");
        assert_eq!(resolve_target("pricing"), "https://phm.dev/pricing");
        assert_eq!(
            resolve_target("github"),
            "https://github.com/ashlrai/phantom-secrets"
        );
        assert_eq!(
            resolve_target("issues"),
            "https://github.com/ashlrai/phantom-secrets/issues"
        );
        assert_eq!(resolve_target("site"), "https://phm.dev");
    }

    #[test]
    fn arbitrary_url_passes_through() {
        assert_eq!(
            resolve_target("https://example.com/foo"),
            "https://example.com/foo"
        );
        assert_eq!(
            resolve_target("http://localhost:3000"),
            "http://localhost:3000"
        );
    }

    #[test]
    fn unknown_word_routes_to_phm_dev_path() {
        assert_eq!(resolve_target("blog"), "https://phm.dev/blog");
        assert_eq!(resolve_target("/changelog"), "https://phm.dev/changelog");
    }
}
