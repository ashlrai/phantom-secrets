use anyhow::{Context, Result};
use colored::Colorize;

/// Reverse `phantom wrap` — restore original scripts from `:raw` variants.
pub fn run() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let pkg_path = project_dir.join("package.json");

    if !pkg_path.exists() {
        anyhow::bail!("No package.json found in current directory.");
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

    // Find all :raw variants
    let raw_names: Vec<String> = scripts
        .keys()
        .filter(|k| k.ends_with(":raw"))
        .cloned()
        .collect();

    if raw_names.is_empty() {
        println!(
            "{} No :raw script variants found (nothing to unwrap).",
            "!".yellow().bold()
        );
        return Ok(());
    }

    let mut restored_count = 0;

    for raw_name in &raw_names {
        let base_name = raw_name.strip_suffix(":raw").unwrap().to_string();

        if let Some(raw_value) = scripts
            .get(raw_name)
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            // Restore the original script
            scripts.insert(base_name.clone(), serde_json::Value::String(raw_value));
            println!(
                "   {} {} -> restored from {}",
                "+".green().bold(),
                base_name.bold(),
                raw_name.dimmed()
            );
            restored_count += 1;
        }
    }

    // Remove :raw entries
    for raw_name in &raw_names {
        scripts.remove(raw_name);
    }

    if restored_count == 0 {
        println!("{} Nothing to unwrap.", "!".yellow().bold());
        return Ok(());
    }

    // Write back
    let output = serde_json::to_string_pretty(&pkg).context("Failed to serialize package.json")?;
    std::fs::write(&pkg_path, format!("{}\n", output)).context("Failed to write package.json")?;

    println!(
        "\n{} Restored {} script(s) to original values",
        "ok".green().bold(),
        restored_count
    );

    Ok(())
}
