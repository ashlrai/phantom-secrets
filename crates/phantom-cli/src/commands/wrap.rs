use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::package_scripts::wrapped_script_command;

/// Rewrite package.json scripts to auto-prefix with the installed local `phantom` binary.
/// Original scripts are saved as `*:raw` variants for escape-hatch usage.
///
/// `quiet` suppresses the per-script and summary lines; warnings and errors
/// still print.
pub fn run(only: &Option<Vec<String>>, skip: &Option<Vec<String>>, quiet: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    run_in(&project_dir, only, skip, quiet, || {})
}

fn run_in(
    project_dir: &std::path::Path,
    only: &Option<Vec<String>>,
    skip: &Option<Vec<String>>,
    quiet: bool,
    after_lock: impl FnOnce(),
) -> Result<()> {
    let pkg_path = project_dir.join("package.json");
    let transaction_lock = phantom_vault::acquire_project_transaction_lock(project_dir)
        .context("Failed to acquire the project transaction lock")?;
    after_lock();
    let target = transaction_lock.target(&pkg_path)?;
    let before = target
        .read_regular()
        .context("Failed to inspect package.json")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No package.json found in current directory.\n\
                 Run this command from your project root."
            )
        })?;
    let content = std::str::from_utf8(before.bytes()).context("package.json is not valid UTF-8")?;
    let mut pkg: serde_json::Value =
        serde_json::from_str(content).context("Failed to parse package.json")?;
    let WrapOutcome { wrapped, unwrapped } = apply_wrap(&mut pkg, only, skip)?;

    // Always shown, `--quiet` included: these scripts still run without
    // Phantom, and the user has to wrap them by hand.
    for (name, reason) in &unwrapped {
        eprintln!(
            "{} Not wrapping '{}': {}. `phantom exec` runs one program without a shell, so a prefix would break it or cover only its first command. Move the command line into a script file and wrap that, or prefix the one command that needs secrets yourself.",
            "warn".yellow(),
            name,
            reason
        );
    }

    if wrapped.is_empty() {
        println!(
            "{} No scripts to wrap (already wrapped or no matching scripts).",
            "!".yellow().bold()
        );
        return Ok(());
    }

    // Only the wrapped scripts change; key order, indentation and the final
    // newline stay as the user wrote them.
    let output = phantom_core::package_scripts::rewrite_scripts_in_place(content, &pkg)
        .context("No scripts were wrapped")?;
    replace_package_json(&target, &before, output.as_bytes())
        .context("package.json changed after it was read; no scripts were wrapped")?;

    if quiet {
        return Ok(());
    }
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

fn replace_package_json(
    target: &phantom_core::fs::AnchoredTarget,
    before: &phantom_core::fs::AnchoredRead,
    content: &[u8],
) -> Result<()> {
    match target.replace_if_exact_with_permissions(Some(before), content, before.permissions())? {
        phantom_core::fs::AnchoredEffect::Durable(_) => Ok(()),
        phantom_core::fs::AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. } => {
            eprintln!(
                "warning: package.json replacement committed and was verified, but directory crash durability is not provable on this platform"
            );
            Ok(())
        }
        phantom_core::fs::AnchoredEffect::CommittedButUncertain { error, .. } => {
            anyhow::bail!(
                "package.json was replaced, but durability could not be verified: {error}"
            )
        }
    }
}

/// Scripts `apply_wrap` changed, and selected scripts it left unchanged
/// because they are a shell command line (with the reason).
#[derive(Debug, Default)]
struct WrapOutcome {
    wrapped: Vec<String>,
    unwrapped: Vec<(String, &'static str)>,
}

fn apply_wrap(
    pkg: &mut serde_json::Value,
    only: &Option<Vec<String>>,
    skip: &Option<Vec<String>>,
) -> Result<WrapOutcome> {
    let scripts = match pkg.get_mut("scripts").and_then(|s| s.as_object_mut()) {
        Some(s) => s,
        None => return Ok(WrapOutcome::default()),
    };

    // Collect script names to wrap
    let script_names: Vec<String> = scripts.keys().cloned().collect();
    let mut candidates = Vec::new();
    let mut unwrapped = Vec::new();

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

        if let Some(reason) = phantom_core::package_scripts::wrap_blocker(&value) {
            unwrapped.push((name.clone(), reason));
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
    Ok(WrapOutcome {
        wrapped: candidates.into_iter().map(|(name, _, _)| name).collect(),
        unwrapped,
    })
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

    #[test]
    fn compound_and_env_prefixed_scripts_are_left_unwrapped() {
        // `phantom exec` runs its argv directly, without a shell. Prefixing a
        // shell command line would hand `VAR=value` to exec as the program,
        // or cover only the first command of a `&&`/`|`/`;` chain.
        let mut pkg = serde_json::json!({
            "scripts": {
                "dev": "next dev",
                "start": "NODE_ENV=production node server.js",
                "build": "next build && next export",
                "serve": "node server.js | pino-pretty",
                "preview": "vite build; vite preview",
                "deploy": "node -e \"console.log('a && b; c | d')\""
            }
        });

        let outcome = apply_wrap(&mut pkg, &None, &None).unwrap();
        assert_eq!(outcome.wrapped, vec!["deploy", "dev"]);
        let unwrapped: Vec<&str> = outcome.unwrapped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(unwrapped, vec!["build", "preview", "serve", "start"]);

        let scripts = &pkg["scripts"];
        assert_eq!(scripts["dev"], "phantom exec -- next dev");
        assert_eq!(scripts["start"], "NODE_ENV=production node server.js");
        assert_eq!(scripts["build"], "next build && next export");
        assert_eq!(scripts["serve"], "node server.js | pino-pretty");
        assert_eq!(scripts["preview"], "vite build; vite preview");
        for name in ["start:raw", "build:raw", "serve:raw", "preview:raw"] {
            assert!(scripts.get(name).is_none(), "{name} must not be created");
        }
        // Operators inside quotes are arguments, not shell syntax.
        assert_eq!(
            scripts["deploy"],
            "phantom exec -- node -e \"console.log('a && b; c | d')\""
        );
    }

    #[test]
    fn explicitly_selected_compound_script_is_not_wrapped() {
        let mut pkg = serde_json::json!({
            "scripts": { "start": "PORT=3000 node server.js" }
        });
        let before = pkg.clone();

        let outcome = apply_wrap(&mut pkg, &Some(vec!["start".to_string()]), &None).unwrap();
        assert!(outcome.wrapped.is_empty());
        assert_eq!(outcome.unwrapped.len(), 1);
        assert_eq!(pkg, before);
    }

    /// A package.json laid out the way a user wrote it: unsorted keys,
    /// four-space indent, no trailing newline.
    const USER_LAYOUT: &str = "{\n    \"name\": \"demo\",\n    \"version\": \"1.0.0\",\n    \"scripts\": {\n        \"dev\": \"next dev\",\n        \"lint\": \"eslint .\",\n        \"build\": \"next build\"\n    },\n    \"dependencies\": {\n        \"next\": \"14.0.0\"\n    }\n}";

    #[test]
    fn wrap_changes_only_the_wrapped_scripts_in_package_json() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), USER_LAYOUT).unwrap();

        run_in(project.path(), &None, &None, true, || {}).unwrap();

        let expected = "{\n    \"name\": \"demo\",\n    \"version\": \"1.0.0\",\n    \"scripts\": {\n        \"dev\": \"phantom exec -- next dev\",\n        \"dev:raw\": \"next dev\",\n        \"lint\": \"eslint .\",\n        \"build\": \"phantom exec -- next build\",\n        \"build:raw\": \"next build\"\n    },\n    \"dependencies\": {\n        \"next\": \"14.0.0\"\n    }\n}";
        assert_eq!(
            std::fs::read_to_string(project.path().join("package.json")).unwrap(),
            expected
        );
    }

    #[cfg(unix)]
    #[test]
    fn wrap_uses_retained_root_after_rename() {
        let container = tempfile::tempdir().unwrap();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            br#"{"scripts":{"build":"next build"}}"#,
        )
        .unwrap();

        run_in(&project, &None, &None, false, || {
            std::fs::rename(&project, &moved).unwrap();
            std::fs::create_dir(&project).unwrap();
            std::fs::write(project.join("package.json"), br#"{"decoy":true}"#).unwrap();
        })
        .unwrap();

        let wrapped: serde_json::Value =
            serde_json::from_slice(&std::fs::read(moved.join("package.json")).unwrap()).unwrap();
        assert_eq!(wrapped["scripts"]["build"], "phantom exec -- next build");
        assert_eq!(wrapped["scripts"]["build:raw"], "next build");
        assert_eq!(
            std::fs::read(project.join("package.json")).unwrap(),
            br#"{"decoy":true}"#
        );
    }
}
