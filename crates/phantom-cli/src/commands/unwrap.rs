use anyhow::{Context, Result};
use colored::Colorize;

/// Reverse `phantom wrap` — restore original scripts from `:raw` variants.
///
/// `quiet` suppresses the per-script and summary lines; warnings and errors
/// still print.
pub fn run(quiet: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    run_in(&project_dir, quiet, || {})
}

fn run_in(project_dir: &std::path::Path, quiet: bool, after_lock: impl FnOnce()) -> Result<()> {
    let pkg_path = project_dir.join("package.json");
    let transaction_lock = phantom_vault::acquire_project_transaction_lock(project_dir)
        .context("Failed to acquire the project transaction lock")?;
    after_lock();
    let target = transaction_lock.target(&pkg_path)?;
    let before = target
        .read_regular()
        .context("Failed to inspect package.json")?
        .ok_or_else(|| anyhow::anyhow!("No package.json found in current directory."))?;
    let content = std::str::from_utf8(before.bytes()).context("package.json is not valid UTF-8")?;
    let mut pkg: serde_json::Value =
        serde_json::from_str(content).context("Failed to parse package.json")?;
    let restored = apply_unwrap(&mut pkg);

    if restored.is_empty() {
        println!(
            "{} No Phantom-owned wrapped script pairs found (user-owned `*:raw` scripts were preserved).",
            "!".yellow().bold()
        );
        return Ok(());
    }

    // The exact inverse of `phantom wrap`: each restored script gets its
    // `:raw` literal back and the `:raw` member is removed with its
    // separator; nothing else in the file is reformatted.
    let output = phantom_core::package_scripts::rewrite_scripts_in_place(content, &pkg)
        .context("No scripts were restored")?;
    match target.replace_if_exact_with_permissions(
        Some(&before),
        output.as_bytes(),
        before.permissions(),
    )? {
        phantom_core::fs::AnchoredEffect::Durable(_) => {}
        phantom_core::fs::AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. } => {
            eprintln!(
                "warning: package.json replacement committed and was verified, but directory crash durability is not provable on this platform"
            );
        }
        phantom_core::fs::AnchoredEffect::CommittedButUncertain { error, .. } => {
            anyhow::bail!(
                "package.json was replaced, but durability could not be verified: {error}"
            )
        }
    }

    if quiet {
        return Ok(());
    }
    for name in &restored {
        println!(
            "   {} {} -> restored from {}:raw",
            "+".green().bold(),
            name.bold(),
            name.dimmed()
        );
    }

    println!(
        "\n{} Restored {} script(s) to original values",
        "ok".green().bold(),
        restored.len()
    );

    Ok(())
}

/// The shared `phantom unwrap` decision (the MCP `phantom_unwrap` tool
/// applies the same one).
fn apply_unwrap(pkg: &mut serde_json::Value) -> Vec<String> {
    phantom_core::package_scripts::unwrap_scripts(pkg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_owned_raw_script_is_preserved() {
        let mut pkg = serde_json::json!({
            "scripts": {
                "dev": "next dev",
                "dev:raw": "user-owned"
            }
        });
        let before = pkg.clone();

        assert!(apply_unwrap(&mut pkg).is_empty());
        assert_eq!(pkg, before);
    }

    #[test]
    fn only_exact_phantom_pairs_are_unwrapped() {
        let mut pkg = serde_json::json!({
            "scripts": {
                "build": "phantom exec -- next build",
                "build:raw": "next build",
                "dev": "next dev",
                "dev:raw": "user-owned"
            }
        });

        assert_eq!(apply_unwrap(&mut pkg), vec!["build"]);
        assert_eq!(pkg["scripts"]["build"], "next build");
        assert!(pkg["scripts"].get("build:raw").is_none());
        assert_eq!(pkg["scripts"]["dev:raw"], "user-owned");
    }

    #[test]
    fn unwrap_restores_the_package_json_layout_exactly() {
        // Tab indent, unsorted keys, trailing newline: what `phantom wrap`
        // leaves for a user who wrote their package.json that way.
        let wrapped = "{\n\t\"name\": \"demo\",\n\t\"scripts\": {\n\t\t\"start\": \"phantom exec -- node server.js\",\n\t\t\"start:raw\": \"node server.js\",\n\t\t\"lint\": \"eslint .\"\n\t},\n\t\"private\": true\n}\n";
        let original = "{\n\t\"name\": \"demo\",\n\t\"scripts\": {\n\t\t\"start\": \"node server.js\",\n\t\t\"lint\": \"eslint .\"\n\t},\n\t\"private\": true\n}\n";
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), wrapped).unwrap();

        run_in(project.path(), true, || {}).unwrap();

        assert_eq!(
            std::fs::read_to_string(project.path().join("package.json")).unwrap(),
            original
        );
    }

    #[cfg(unix)]
    #[test]
    fn unwrap_uses_retained_root_after_rename() {
        let container = tempfile::tempdir().unwrap();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            br#"{"scripts":{"build":"phantom exec -- next build","build:raw":"next build"}}"#,
        )
        .unwrap();

        run_in(&project, false, || {
            std::fs::rename(&project, &moved).unwrap();
            std::fs::create_dir(&project).unwrap();
            std::fs::write(project.join("package.json"), br#"{"decoy":true}"#).unwrap();
        })
        .unwrap();

        let unwrapped: serde_json::Value =
            serde_json::from_slice(&std::fs::read(moved.join("package.json")).unwrap()).unwrap();
        assert_eq!(unwrapped["scripts"]["build"], "next build");
        assert!(unwrapped["scripts"].get("build:raw").is_none());
        assert_eq!(
            std::fs::read(project.join("package.json")).unwrap(),
            br#"{"decoy":true}"#
        );
    }
}
