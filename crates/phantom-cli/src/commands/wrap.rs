use anyhow::{Context, Result};
use colored::Colorize;

/// Rewrite package.json scripts to auto-prefix with `npx phantom-secrets exec --`.
/// Original scripts are saved as `*:raw` variants for escape-hatch usage.
pub fn run(only: &Option<Vec<String>>, skip: &Option<Vec<String>>) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let pkg_path = project_dir.join("package.json");

    if !pkg_path.exists() {
        anyhow::bail!(
            "No package.json found in current directory.\n\
             Run this command from your project root."
        );
    }

    let content = std::fs::read_to_string(&pkg_path).context("Failed to read package.json")?;
    let mut pkg: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse package.json")?;

    let scripts = match pkg.get_mut("scripts").and_then(|s| s.as_object_mut()) {
        Some(s) => s,
        None => {
            println!(
                "{} No \"scripts\" section found in package.json.",
                "!".yellow().bold()
            );
            return Ok(());
        }
    };

    // Collect script names to wrap
    let script_names: Vec<String> = scripts.keys().cloned().collect();
    let mut wrapped_count = 0;

    for name in &script_names {
        // Skip :raw variants
        if name.ends_with(":raw") {
            continue;
        }

        let value = match scripts.get(name).and_then(|v| v.as_str()) {
            Some(v) => v.to_string(),
            None => continue,
        };

        // Skip if already wrapped
        if value.contains("phantom-secrets") || value.contains("phantom exec") {
            continue;
        }

        // Apply --only filter
        if let Some(only_list) = only {
            if !only_list.iter().any(|o| o == name) {
                continue;
            }
        }

        // Apply --skip filter
        if let Some(skip_list) = skip {
            if skip_list.iter().any(|s| s == name) {
                continue;
            }
        }

        // Default heuristic: wrap scripts that likely need secrets
        if only.is_none() && !should_wrap_script(name) {
            continue;
        }

        // Save original as :raw variant
        let raw_name = format!("{}:raw", name);
        scripts.insert(raw_name, serde_json::Value::String(value.clone()));

        // Wrap the script
        let wrapped = format!("npx phantom-secrets exec -- {}", value);
        scripts.insert(name.clone(), serde_json::Value::String(wrapped));

        println!(
            "   {} {} -> wrapped with phantom exec",
            "+".green().bold(),
            name.bold()
        );
        wrapped_count += 1;
    }

    if wrapped_count == 0 {
        println!(
            "{} No scripts to wrap (already wrapped or no matching scripts).",
            "!".yellow().bold()
        );
        return Ok(());
    }

    // Write back
    let output = serde_json::to_string_pretty(&pkg).context("Failed to serialize package.json")?;
    std::fs::write(&pkg_path, format!("{}\n", output)).context("Failed to write package.json")?;

    println!(
        "\n{} Wrapped {} script(s) in package.json",
        "ok".green().bold(),
        wrapped_count
    );
    println!(
        "{} Original scripts saved as {}",
        "->".blue().bold(),
        "*:raw".cyan()
    );
    println!(
        "{} Run {} to undo.",
        "->".blue().bold(),
        "phantom unwrap".cyan().bold()
    );

    Ok(())
}

/// Heuristic: should this script name be wrapped with phantom exec?
fn should_wrap_script(name: &str) -> bool {
    let name_lower = name.to_lowercase();

    // Scripts that typically need secrets
    let wrap_patterns = ["dev", "start", "serve", "build", "deploy", "preview"];

    // Scripts that typically don't need secrets
    let skip_patterns = [
        "lint",
        "test",
        "format",
        "fmt",
        "check",
        "type",
        "typecheck",
        "prettier",
        "eslint",
        "clean",
        "prepare",
        "postinstall",
    ];

    // Skip if matches a skip pattern
    if skip_patterns.iter().any(|p| name_lower.contains(p)) {
        return false;
    }

    // Wrap if matches a wrap pattern
    wrap_patterns.iter().any(|p| name_lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_wrap_script() {
        assert!(should_wrap_script("dev"));
        assert!(should_wrap_script("start"));
        assert!(should_wrap_script("build"));
        assert!(should_wrap_script("deploy"));
        assert!(should_wrap_script("serve"));
        assert!(should_wrap_script("preview"));
        assert!(should_wrap_script("dev:local"));

        assert!(!should_wrap_script("lint"));
        assert!(!should_wrap_script("test"));
        assert!(!should_wrap_script("format"));
        assert!(!should_wrap_script("typecheck"));
        assert!(!should_wrap_script("test:unit"));
        assert!(!should_wrap_script("lint:fix"));
    }
}
