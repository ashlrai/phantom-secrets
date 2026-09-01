use anyhow::{Context, Result};
use colored::Colorize;

/// Reverse `phantom wrap` — restore original scripts from `:raw` variants.
pub fn run() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    run_in(&project_dir, || {})
}

fn run_in(project_dir: &std::path::Path, after_lock: impl FnOnce()) -> Result<()> {
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

    let output = serde_json::to_string_pretty(&pkg).context("Failed to serialize package.json")?;
    match target.replace_if_exact_with_permissions(
        Some(&before),
        format!("{output}\n").as_bytes(),
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

fn apply_unwrap(pkg: &mut serde_json::Value) -> Vec<String> {
    let scripts = match pkg.get_mut("scripts").and_then(|s| s.as_object_mut()) {
        Some(s) => s,
        None => return Vec::new(),
    };

    // Find all :raw variants
    let raw_names: Vec<String> = scripts
        .keys()
        .filter(|k| k.ends_with(":raw"))
        .cloned()
        .collect();

    let mut owned_pairs = Vec::new();

    for raw_name in &raw_names {
        let base_name = raw_name.strip_suffix(":raw").unwrap().to_string();
        let Some(raw_value) = scripts.get(raw_name).and_then(|value| value.as_str()) else {
            continue;
        };
        let expected_wrapped = wrapped_script_command(raw_value);
        if scripts.get(&base_name).and_then(|value| value.as_str()) == Some(&expected_wrapped) {
            owned_pairs.push((base_name, raw_name.clone(), raw_value.to_string()));
        }
    }

    for (base_name, raw_name, raw_value) in &owned_pairs {
        scripts.insert(
            base_name.clone(),
            serde_json::Value::String(raw_value.clone()),
        );
        scripts.remove(raw_name);
    }
    owned_pairs
        .into_iter()
        .map(|(base_name, _, _)| base_name)
        .collect()
}

fn wrapped_script_command(original: &str) -> String {
    format!("phantom exec -- {original}")
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

        run_in(&project, || {
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
