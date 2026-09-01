use anyhow::{Context, Result};
use colored::Colorize;

/// Rewrite package.json scripts to auto-prefix with the installed local `phantom` binary.
/// Original scripts are saved as `*:raw` variants for escape-hatch usage.
pub fn run(only: &Option<Vec<String>>, skip: &Option<Vec<String>>) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let pkg_path = project_dir.join("package.json");
    let _transaction_lock = phantom_vault::acquire_project_transaction_lock(&project_dir)
        .context("Failed to acquire the project transaction lock")?;
    let before = phantom_core::fs::read_regular_file(&pkg_path)
        .context("Failed to inspect package.json")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No package.json found in current directory.\n\
                 Run this command from your project root."
            )
        })?;
    let content = std::str::from_utf8(&before).context("package.json is not valid UTF-8")?;
    let mut pkg: serde_json::Value =
        serde_json::from_str(content).context("Failed to parse package.json")?;
    let wrapped = apply_wrap(&mut pkg, only, skip)?;

    if wrapped.is_empty() {
        println!(
            "{} No scripts to wrap (already wrapped or no matching scripts).",
            "!".yellow().bold()
        );
        return Ok(());
    }

    let output = serde_json::to_string_pretty(&pkg).context("Failed to serialize package.json")?;
    phantom_core::fs::atomic_write_if_unchanged(
        &pkg_path,
        Some(&before),
        format!("{output}\n").as_bytes(),
    )
    .context("package.json changed after it was read; no scripts were wrapped")?;

    for name in &wrapped {
        println!(
            "   {} {} -> wrapped with phantom exec",
            "+".green().bold(),
            name.bold()
        );
    }

    println!(
        "\n{} Wrapped {} script(s) in package.json",
        "ok".green().bold(),
        wrapped.len()
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

fn apply_wrap(
    pkg: &mut serde_json::Value,
    only: &Option<Vec<String>>,
    skip: &Option<Vec<String>>,
) -> Result<Vec<String>> {
    let scripts = match pkg.get_mut("scripts").and_then(|s| s.as_object_mut()) {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };

    // Collect script names to wrap
    let script_names: Vec<String> = scripts.keys().cloned().collect();
    let mut candidates = Vec::new();

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

        let raw_name = format!("{}:raw", name);
        if scripts.contains_key(&raw_name) {
            anyhow::bail!(
                "Refusing to wrap '{name}': package.json already contains user-owned script '{raw_name}'. Rename or remove that script explicitly before retrying. No scripts were changed."
            );
        }
        candidates.push((name.clone(), raw_name, value));
    }

    for (name, raw_name, original) in &candidates {
        scripts.insert(
            raw_name.clone(),
            serde_json::Value::String(original.clone()),
        );
        scripts.insert(
            name.clone(),
            serde_json::Value::String(wrapped_script_command(original)),
        );
    }
    Ok(candidates.into_iter().map(|(name, _, _)| name).collect())
}

fn wrapped_script_command(original: &str) -> String {
    format!("phantom exec -- {original}")
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
    fn generated_script_uses_installed_local_binary() {
        let wrapped = wrapped_script_command("next dev");
        assert_eq!(wrapped, "phantom exec -- next dev");
        assert!(!wrapped.contains("npx"));
        assert!(!wrapped.contains("npm"));
    }

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

    #[test]
    fn existing_raw_script_aborts_without_mutating_package() {
        let mut pkg = serde_json::json!({
            "scripts": {
                "dev": "next dev",
                "dev:raw": "user-owned"
            }
        });
        let before = pkg.clone();

        let error = apply_wrap(&mut pkg, &None, &None).unwrap_err();
        assert!(error.to_string().contains("user-owned script 'dev:raw'"));
        assert_eq!(pkg, before);
    }

    #[test]
    fn one_collision_prevents_all_candidate_mutations() {
        let mut pkg = serde_json::json!({
            "scripts": {
                "build": "next build",
                "dev": "next dev",
                "dev:raw": "user-owned"
            }
        });
        let before = pkg.clone();

        apply_wrap(&mut pkg, &None, &None).unwrap_err();
        assert_eq!(pkg, before);
    }
}
