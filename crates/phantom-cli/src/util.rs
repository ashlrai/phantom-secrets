use colored::Colorize;

/// Render a "Docs: https://phm.dev/docs/<slug>" suffix in a consistent style.
/// Use as the trailing line of a user-visible error so people can self-serve
/// the fix without context-switching to search.
pub fn docs_url(slug: &str) -> String {
    format!(
        "Docs: {}",
        format!("https://phm.dev/docs/{slug}").cyan().underline()
    )
}
