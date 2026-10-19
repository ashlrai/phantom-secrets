//! `phantom setup --undo`: reverse what `setup --client` recorded in the manifest.
//!
//! Default is a dry run that lists what would happen. `--apply` performs it.
//! Entries are processed newest first. A file is acted on only when its current
//! SHA-256 equals the manifest's `sha256_after`; otherwise that file is refused
//! and named, its backup is kept, and the other files still proceed.
//! `--force-undo` skips only that hash check. It never skips the symlink or
//! backup-integrity checks. Backups are never deleted. No file contents are printed.

use super::setup_backup::{self, Manifest, ManifestEntry};
use anyhow::{bail, Result};
use colored::Colorize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Restore { from: PathBuf },
    Remove,
    AlreadyUndone,
    Refused(String),
}

#[derive(Debug)]
pub(crate) struct Planned {
    pub index: usize,
    pub path: PathBuf,
    pub outcome: Outcome,
}

fn hash_of(path: &Path) -> std::result::Result<Option<String>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => return Err("is a symlink".into()),
        Ok(m) if !m.is_file() => return Err("is not a regular file".into()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot be inspected ({})", e.kind())),
    }
    match phantom_core::fs::read_regular_file(path) {
        Ok(Some(b)) => Ok(Some(setup_backup::sha256_hex(&b))),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("cannot be read ({})", e.kind())),
    }
}

/// Decide what to do for each manifest entry, newest first. `virtual_hash`
/// tracks the hash a path will have after earlier (newer) undos in this run,
/// so a dry run predicts a chain of changes to one file correctly.
pub(crate) fn plan(manifest: &Manifest, force: bool) -> Vec<Planned> {
    let mut virt: HashMap<PathBuf, Option<String>> = HashMap::new();
    let mut out = Vec::new();
    for (index, e) in manifest.entries.iter().enumerate().rev() {
        let outcome = if e.undone_ms.is_some() {
            Outcome::AlreadyUndone
        } else {
            plan_one(e, force, &mut virt)
        };
        out.push(Planned {
            index,
            path: e.path.clone(),
            outcome,
        });
    }
    out
}

fn plan_one(
    e: &ManifestEntry,
    force: bool,
    virt: &mut HashMap<PathBuf, Option<String>>,
) -> Outcome {
    let current = match virt.get(&e.path) {
        Some(h) => h.clone(),
        None => match hash_of(&e.path) {
            Ok(h) => h,
            Err(why) => return Outcome::Refused(format!("{} {why}", e.path.display())),
        },
    };
    let Some(current) = current else {
        return Outcome::Refused(format!("{} no longer exists", e.path.display()));
    };
    if current != e.sha256_after && !force {
        return Outcome::Refused(format!(
            "{} changed after setup wrote it (hash differs from the manifest); backup kept. Re-run with --force-undo to overwrite",
            e.path.display()
        ));
    }
    match &e.backup {
        Some(b) => {
            match hash_of(b) {
                Ok(Some(h)) if Some(&h) == e.sha256_before.as_ref() => {}
                Ok(Some(_)) => {
                    return Outcome::Refused(format!(
                        "{} backup {} no longer matches the manifest; refusing to restore from it",
                        e.path.display(),
                        b.display()
                    ))
                }
                Ok(None) => {
                    return Outcome::Refused(format!(
                        "{} backup {} is missing",
                        e.path.display(),
                        b.display()
                    ))
                }
                Err(why) => {
                    return Outcome::Refused(format!(
                        "{} backup {} {why}",
                        e.path.display(),
                        b.display()
                    ))
                }
            }
            virt.insert(e.path.clone(), e.sha256_before.clone());
            Outcome::Restore { from: b.clone() }
        }
        None => {
            if e.sha256_before.is_some() {
                return Outcome::Refused(format!(
                    "{} has no backup recorded but existed before setup",
                    e.path.display()
                ));
            }
            virt.insert(e.path.clone(), None);
            Outcome::Remove
        }
    }
}

fn apply_one(e: &ManifestEntry, outcome: &Outcome) -> Result<()> {
    match outcome {
        Outcome::Restore { from } => {
            let bytes = phantom_core::fs::read_regular_file(from)?
                .ok_or_else(|| anyhow::anyhow!("backup vanished: {}", from.display()))?;
            #[cfg(unix)]
            let perms = std::fs::metadata(&e.path).map(|m| m.permissions()).ok();
            phantom_core::fs::atomic_write(&e.path, &bytes)?;
            #[cfg(unix)]
            if let Some(p) = perms {
                std::fs::set_permissions(&e.path, p)?;
            }
            Ok(())
        }
        Outcome::Remove => Ok(std::fs::remove_file(&e.path)?),
        _ => Ok(()),
    }
}

pub fn run(apply: bool, force: bool) -> Result<()> {
    let home = phantom_core::home::home_dir_with_platform_fallback()?;
    run_at(&home, apply, force)
}

pub(crate) fn run_at(home: &Path, apply: bool, force: bool) -> Result<()> {
    let mut manifest = setup_backup::load(home)?;
    let planned = plan(&manifest, force);
    if planned.iter().all(|p| p.outcome == Outcome::AlreadyUndone) {
        println!("Nothing to undo: no setup changes are recorded in the manifest.");
        return Ok(());
    }
    if !apply {
        println!("{}", "Dry run. Nothing will be written.".bold());
    }
    let mut refused = 0usize;
    let mut done = 0usize;
    for p in &planned {
        let shown = phantom_core::home::display_home_relative(&p.path);
        match &p.outcome {
            Outcome::AlreadyUndone => continue,
            Outcome::Refused(why) => {
                refused += 1;
                println!("   {} refused: {why}", "!".yellow().bold());
            }
            Outcome::Restore { from } => {
                let b = phantom_core::home::display_home_relative(from);
                if !apply {
                    println!("   would restore {shown} from {b}");
                    done += 1;
                } else {
                    let entry = manifest.entries[p.index].clone();
                    match apply_one(&entry, &p.outcome) {
                        Ok(()) => {
                            manifest.entries[p.index].undone_ms = Some(setup_backup::now_ms());
                            setup_backup::save(home, &manifest)?;
                            println!(
                                "   {} restored {shown} (backup kept at {b})",
                                "+".green().bold()
                            );
                            done += 1;
                        }
                        Err(err) => {
                            refused += 1;
                            println!("   {} failed: {shown}: {err}", "!".yellow().bold());
                        }
                    }
                }
            }
            Outcome::Remove => {
                if !apply {
                    println!("   would remove {shown} (setup created it)");
                    done += 1;
                } else {
                    let entry = manifest.entries[p.index].clone();
                    match apply_one(&entry, &p.outcome) {
                        Ok(()) => {
                            manifest.entries[p.index].undone_ms = Some(setup_backup::now_ms());
                            setup_backup::save(home, &manifest)?;
                            println!("   {} removed {shown}", "+".green().bold());
                            done += 1;
                        }
                        Err(err) => {
                            refused += 1;
                            println!("   {} failed: {shown}: {err}", "!".yellow().bold());
                        }
                    }
                }
            }
        }
    }
    if !apply {
        println!("{done} change(s) planned, {refused} refused. Re-run with --undo --apply to perform them.");
        return Ok(());
    }
    println!("{done} undone, {refused} refused.");
    if refused > 0 {
        bail!("{refused} file(s) were not undone; see the refusals above");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::setup_backup::{record, sha256_hex};
    use tempfile::tempdir;

    /// Simulate setup replacing `cfg` (holding `before`) with `after`.
    fn setup_replace(home: &Path, cfg: &Path, before: &[u8], after: &[u8]) -> PathBuf {
        std::fs::write(cfg, before).unwrap();
        let bak = setup_backup::write_backup(cfg, before).unwrap();
        std::fs::write(cfg, after).unwrap();
        record(
            home,
            ManifestEntry {
                path: cfg.to_path_buf(),
                backup: Some(bak.clone()),
                timestamp_ms: 1,
                action: "replace".into(),
                sha256_before: Some(sha256_hex(before)),
                sha256_after: sha256_hex(after),
                undone_ms: None,
            },
        )
        .unwrap();
        bak
    }

    fn setup_create(home: &Path, cfg: &Path, after: &[u8]) {
        std::fs::write(cfg, after).unwrap();
        record(
            home,
            ManifestEntry {
                path: cfg.to_path_buf(),
                backup: None,
                timestamp_ms: 2,
                action: "add".into(),
                sha256_before: None,
                sha256_after: sha256_hex(after),
                undone_ms: None,
            },
        )
        .unwrap();
    }

    #[test]
    fn restores_backed_up_entry_marks_it_undone_and_keeps_backup() {
        let home = tempdir().unwrap();
        let cfg = home.path().join("a.json");
        let bak = setup_replace(home.path(), &cfg, b"old", b"new");
        run_at(home.path(), true, false).unwrap();
        assert_eq!(std::fs::read(&cfg).unwrap(), b"old");
        assert!(bak.exists());
        let m = setup_backup::load(home.path()).unwrap();
        assert!(m.entries[0].undone_ms.is_some());
        // A second run has nothing left to do.
        run_at(home.path(), true, false).unwrap();
        assert_eq!(std::fs::read(&cfg).unwrap(), b"old");
    }

    #[test]
    fn removes_a_file_setup_created() {
        let home = tempdir().unwrap();
        let cfg = home.path().join("new.json");
        setup_create(home.path(), &cfg, b"made by setup");
        run_at(home.path(), true, false).unwrap();
        assert!(!cfg.exists());
        assert!(setup_backup::load(home.path()).unwrap().entries[0]
            .undone_ms
            .is_some());
    }

    #[test]
    fn hash_mismatch_is_refused_and_force_overrides() {
        let home = tempdir().unwrap();
        let cfg = home.path().join("a.json");
        let bak = setup_replace(home.path(), &cfg, b"old", b"new");
        std::fs::write(&cfg, b"user edited").unwrap();
        let err = run_at(home.path(), true, false).unwrap_err().to_string();
        assert!(err.contains("not undone"));
        assert_eq!(std::fs::read(&cfg).unwrap(), b"user edited");
        assert!(bak.exists());
        assert!(setup_backup::load(home.path()).unwrap().entries[0]
            .undone_ms
            .is_none());
        let planned = plan(&setup_backup::load(home.path()).unwrap(), false);
        match &planned[0].outcome {
            Outcome::Refused(why) => assert!(why.contains("a.json")),
            other => panic!("expected refusal, got {other:?}"),
        }
        run_at(home.path(), true, true).unwrap();
        assert_eq!(std::fs::read(&cfg).unwrap(), b"old");
    }

    #[test]
    fn dry_run_writes_nothing() {
        let home = tempdir().unwrap();
        let cfg = home.path().join("a.json");
        let made = home.path().join("b.json");
        setup_replace(home.path(), &cfg, b"old", b"new");
        setup_create(home.path(), &made, b"x");
        let manifest_before = std::fs::read(setup_backup::manifest_path(home.path())).unwrap();
        run_at(home.path(), false, false).unwrap();
        assert_eq!(std::fs::read(&cfg).unwrap(), b"new");
        assert!(made.exists());
        assert_eq!(
            std::fs::read(setup_backup::manifest_path(home.path())).unwrap(),
            manifest_before
        );
    }

    #[test]
    fn missing_backup_is_refused_and_current_file_untouched() {
        let home = tempdir().unwrap();
        let cfg = home.path().join("a.json");
        let bak = setup_replace(home.path(), &cfg, b"old", b"new");
        std::fs::remove_file(&bak).unwrap();
        assert!(run_at(home.path(), true, true).is_err());
        assert_eq!(std::fs::read(&cfg).unwrap(), b"new");
    }

    #[test]
    fn tampered_backup_is_refused_even_with_force() {
        let home = tempdir().unwrap();
        let cfg = home.path().join("a.json");
        let bak = setup_replace(home.path(), &cfg, b"old", b"new");
        std::fs::write(&bak, b"tampered").unwrap();
        assert!(run_at(home.path(), true, true).is_err());
        assert_eq!(std::fs::read(&cfg).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_target_is_refused_and_not_followed() {
        let home = tempdir().unwrap();
        let cfg = home.path().join("a.json");
        let other = home.path().join("other.txt");
        setup_replace(home.path(), &cfg, b"old", b"new");
        std::fs::write(&other, b"new").unwrap();
        std::fs::remove_file(&cfg).unwrap();
        std::os::unix::fs::symlink(&other, &cfg).unwrap();
        assert!(run_at(home.path(), true, true).is_err());
        assert_eq!(std::fs::read(&other).unwrap(), b"new");
        assert!(std::fs::symlink_metadata(&cfg)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn one_refusal_does_not_block_other_files() {
        let home = tempdir().unwrap();
        let a = home.path().join("a.json");
        let b = home.path().join("b.json");
        setup_replace(home.path(), &a, b"a-old", b"a-new");
        setup_replace(home.path(), &b, b"b-old", b"b-new");
        std::fs::write(&a, b"edited").unwrap();
        assert!(run_at(home.path(), true, false).is_err());
        assert_eq!(std::fs::read(&a).unwrap(), b"edited");
        assert_eq!(std::fs::read(&b).unwrap(), b"b-old");
    }

    #[test]
    fn two_changes_to_one_file_undo_in_reverse_order() {
        let home = tempdir().unwrap();
        let cfg = home.path().join("a.json");
        setup_replace(home.path(), &cfg, b"v0", b"v1");
        setup_replace(home.path(), &cfg, b"v1", b"v2");
        run_at(home.path(), false, false).unwrap();
        run_at(home.path(), true, false).unwrap();
        assert_eq!(std::fs::read(&cfg).unwrap(), b"v0");
    }

    #[test]
    fn empty_manifest_is_a_no_op() {
        let home = tempdir().unwrap();
        run_at(home.path(), true, false).unwrap();
    }
}
