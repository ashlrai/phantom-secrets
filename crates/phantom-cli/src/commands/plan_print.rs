use std::path::{Path, PathBuf};

/// Human preview shared by init, add, and remove. Names and relative paths
/// only: callers must not pass secret values or file contents.
#[allow(clippy::too_many_arguments)]
pub(crate) fn print_plan(
    action: &str,
    keys: &[String],
    skipped_public: &[String],
    files: &[PathBuf],
    project: &Path,
    empty_vault: bool,
    may_update: &[PathBuf],
    vault_unchecked: bool,
) {
    println!("Dry run. No files, config, or vault entries will be written.");
    println!("Would {action} {} key(s):", keys.len());
    let marker = if action == "remove" { "-" } else { "+" };
    for key in keys {
        println!("  {marker} {key}");
    }
    if vault_unchecked {
        for key in keys {
            println!("would {action} {key} (vault state not checked in dry run)");
        }
    }
    if !skipped_public.is_empty() {
        println!(
            "Skipping {} public key(s) (not protected):",
            skipped_public.len()
        );
        for key in skipped_public {
            println!("  · {key}");
        }
    }
    let mut shown: Vec<String> = files
        .iter()
        .map(|file| display_path(project, file))
        .collect();
    shown.sort();
    shown.dedup();
    println!("Would write {} file(s):", shown.len());
    for path in &shown {
        println!("  {path}");
    }
    let mut updates: Vec<String> = may_update
        .iter()
        .map(|file| display_path(project, file))
        .collect();
    updates.sort();
    updates.dedup();
    for path in &updates {
        println!("may update {path}");
    }
    if empty_vault {
        println!("Would create an empty vault.");
    }
    println!("Dry run only. Nothing was written.");
}

fn display_path(project: &Path, file: &Path) -> String {
    let relative = file.strip_prefix(project).unwrap_or(file);
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_path_is_relative_to_the_project_and_uses_forward_slashes() {
        let project = Path::new("/tmp/project");
        assert_eq!(display_path(project, &project.join(".env")), ".env");
        assert_eq!(
            display_path(project, &project.join("nested").join("file")),
            "nested/file"
        );
    }
}
