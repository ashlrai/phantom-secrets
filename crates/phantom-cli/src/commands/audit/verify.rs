use super::*;

/// The audit log could not be inspected. The path is checked without following
/// symlinks, so the likely fixes are local: a real `~/.phantom` directory and a
/// log this user can read. The error text is the I/O failure, never log content.
fn audit_log_read_error(error: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!(
        "Failed to verify audit log: {error}. Check that ~/.phantom is a real directory (not a symlink) and that the audit log is readable by this user, then run `phantom audit verify` again."
    )
}

pub fn run_verify(with_context: bool, json: bool) -> Result<()> {
    let path = resolve_path()?;
    // Nothing is followed: a dangling symlink at the log is not "no log",
    // and a symlinked `~/.phantom` is refused.
    let log_present = phantom_core::audit::log_present(&path).map_err(audit_log_read_error)?;
    // A retained head checkpoint proves a signed era existed, so a missing log
    // beside it is a deletion: verify it (the walk reports a head mismatch)
    // instead of reporting a log that never started.
    let head_present = match phantom_core::audit::head_checkpoint_path() {
        Ok(head) => phantom_core::audit::log_present(&head).map_err(audit_log_read_error)?,
        Err(_) => false,
    };
    if !log_present && !head_present {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "log_present": false,
                    "clean": true,
                    "verified": 0,
                    "note": "No audit log found. Set PHANTOM_AUDIT=1 to start logging.",
                    "next_step": null,
                }))?
            );
        } else {
            println!(
                "{}  No audit log found - set {} to start logging.",
                "->".blue().bold(),
                "PHANTOM_AUDIT=1".cyan()
            );
        }
        return Ok(());
    }

    // When --with-context is requested, use the richer verify path.
    if with_context {
        if json {
            anyhow::bail!(
                "`phantom audit verify --with-context` has no JSON form; run `phantom audit verify --json` for the machine-readable result"
            );
        }
        return run_verify_with_context();
    }

    let report = phantom_core::audit::verify_log().map_err(audit_log_read_error)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&verify_report_json(&report, log_present))?
        );
        if !report.is_clean() {
            std::process::exit(1);
        }
        return Ok(());
    }

    if !log_present {
        eprintln!(
            "{}  {} is missing but its signed head checkpoint remains; the log was deleted or moved.",
            "!".red().bold(),
            path.display()
        );
    }

    let status = if report.is_clean() {
        "ok".green().bold().to_string()
    } else {
        "FAILED".red().bold().to_string()
    };

    println!(
        "{}  verified: {} · tampered: {} · malformed: {} · sequence: {} · head: {} · legacy: {}",
        status,
        report.verified.to_string().cyan(),
        if report.tampered > 0 {
            report.tampered.to_string().red().bold().to_string()
        } else {
            report.tampered.to_string()
        },
        if report.malformed > 0 {
            report.malformed.to_string().red().bold().to_string()
        } else {
            report.malformed.to_string()
        },
        if report.sequence_errors > 0 {
            report.sequence_errors.to_string().red().bold().to_string()
        } else {
            report.sequence_errors.to_string()
        },
        if report.head_missing {
            "missing".red().bold().to_string()
        } else if report.head_mismatch {
            "mismatch".red().bold().to_string()
        } else {
            "ok".to_string()
        },
        report.legacy.to_string().dimmed(),
    );

    if !report.tampered_lines.is_empty() {
        let line_list: Vec<String> = report
            .tampered_lines
            .iter()
            .map(|n| n.to_string())
            .collect();
        eprintln!(
            "{}  Tampered at line{}: {}",
            "!".red().bold(),
            if report.tampered_lines.len() == 1 {
                ""
            } else {
                "s"
            },
            line_list.join(", ").red()
        );
    }

    if !report.malformed_lines.is_empty() {
        let line_list: Vec<String> = report
            .malformed_lines
            .iter()
            .map(|n| n.to_string())
            .collect();
        eprintln!(
            "{}  Malformed JSON at line{}: {}",
            "!".red().bold(),
            if report.malformed_lines.len() == 1 {
                ""
            } else {
                "s"
            },
            line_list.join(", ").red()
        );
    }

    if !report.sequence_error_lines.is_empty() {
        let line_list: Vec<String> = report
            .sequence_error_lines
            .iter()
            .map(|n| n.to_string())
            .collect();
        eprintln!(
            "{}  Sequence error at line{}: {}",
            "!".red().bold(),
            if report.sequence_error_lines.len() == 1 {
                ""
            } else {
                "s"
            },
            line_list.join(", ").red()
        );
    }

    if report.head_missing {
        eprintln!(
            "{}  Audit head checkpoint is missing; tail truncation cannot be ruled out.",
            "!".red().bold()
        );
    }
    if report.head_mismatch {
        eprintln!(
            "{}  Audit head checkpoint does not match the log tail.",
            "!".red().bold()
        );
    }

    if !report.is_clean() {
        print_verify_failure_steps(&report);
        std::process::exit(1);
    }

    Ok(())
}

/// Guidance for a failed chain verification, shared by the human report and
/// `verify --json`'s `next_step`. Fixed vocabulary only: public commands and
/// the troubleshooting guide — never paths, event contents, or values.
fn verify_failure_steps(report: &phantom_core::audit::VerifyReport) -> Vec<&'static str> {
    if report.is_clean() {
        return Vec::new();
    }
    let mut steps = Vec::new();
    if report.tampered > 0 || report.malformed > 0 || report.sequence_errors > 0 {
        steps.push(
            "Treat the audit log as unreliable for the flagged period and compare it with a backup copy before relying on it.",
        );
    }
    if report.head_missing || report.head_mismatch {
        steps.push(
            "The signed head checkpoint is missing or does not match the log tail, so truncation cannot be ruled out; restore the log and checkpoint from a trusted backup if one exists.",
        );
    }
    steps.push(
        "If tampering is suspected, treat it as a security incident: check `phantom audit incidents` and `phantom leaks plan`, then revoke and replace affected credentials at their providers (see the audit log section of the troubleshooting guide).",
    );
    steps
}

fn print_verify_failure_steps(report: &phantom_core::audit::VerifyReport) {
    for step in verify_failure_steps(report) {
        println!("  {} {}", "->".blue().bold(), step);
    }
}

/// The `phantom audit verify --json` object. Counts, line numbers, and a
/// `next_step` sentence when verification failed: it never carries event
/// names, values, or HMACs.
fn verify_report_json(report: &phantom_core::audit::VerifyReport, log_present: bool) -> Value {
    let head = if report.head_missing {
        "missing"
    } else if report.head_mismatch {
        "mismatch"
    } else {
        "ok"
    };
    let steps = verify_failure_steps(report);
    serde_json::json!({
        "log_present": log_present,
        "clean": report.is_clean(),
        "verified": report.verified,
        "tampered": report.tampered,
        "malformed": report.malformed,
        "sequence_errors": report.sequence_errors,
        "legacy": report.legacy,
        "head": head,
        "tampered_lines": report.tampered_lines,
        "malformed_lines": report.malformed_lines,
        "sequence_error_lines": report.sequence_error_lines,
        "next_step": (!steps.is_empty()).then(|| steps.join(" ")),
    })
}

/// `phantom audit verify --with-context`: decrypt and display `encrypted_context`
/// for every event in the log, providing a forensics-grade view of audit metadata.
fn run_verify_with_context() -> Result<()> {
    let (report, events) =
        phantom_core::audit::verify_log_with_context().map_err(audit_log_read_error)?;

    let status = if report.is_clean() {
        "ok".green().bold().to_string()
    } else {
        "FAILED".red().bold().to_string()
    };

    println!(
        "{}  verified: {} · tampered: {} · malformed: {} · sequence: {} · head: {} · legacy: {}",
        status,
        report.verified.to_string().cyan(),
        if report.tampered > 0 {
            report.tampered.to_string().red().bold().to_string()
        } else {
            report.tampered.to_string()
        },
        if report.malformed > 0 {
            report.malformed.to_string().red().bold().to_string()
        } else {
            report.malformed.to_string()
        },
        if report.sequence_errors > 0 {
            report.sequence_errors.to_string().red().bold().to_string()
        } else {
            report.sequence_errors.to_string()
        },
        if report.head_missing {
            "missing".red().bold().to_string()
        } else if report.head_mismatch {
            "mismatch".red().bold().to_string()
        } else {
            "ok".to_string()
        },
        report.legacy.to_string().dimmed(),
    );

    println!();
    println!("{}  Decrypted context per event:", "->".blue().bold());
    println!();

    for ev in &events {
        let v: serde_json::Value = match serde_json::from_str(&ev.raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ts = v["ts"].as_u64().map(format_unix_ts).unwrap_or_default();
        let op = v["op"].as_str().unwrap_or("?");
        let seq = v["seq"].as_u64().map(|s| s.to_string()).unwrap_or_default();

        print!("  {} [{}] {}", ts.dimmed(), seq.cyan(), op.bold());
        if let Some(name) = v["name"].as_str() {
            print!("  {}", name.bold());
        }
        println!();

        match (&ev.context, &ev.context_error) {
            (Some(ctx), _) => {
                println!(
                    "    {} process={} hostname={} ppid={} cwd={}",
                    "context:".green(),
                    ctx.process_name.cyan(),
                    ctx.hostname.cyan(),
                    ctx.ppid.to_string().cyan(),
                    ctx.cwd.dimmed(),
                );
            }
            (None, Some(err)) => {
                println!("    {} {}", "context error:".yellow(), err.dimmed());
            }
            (None, None) => {
                println!("    {}", "no encrypted context".dimmed());
            }
        }
    }

    if !report.is_clean() {
        print_verify_failure_steps(&report);
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::audit::VerifyReport;

    fn report(
        tampered: usize,
        malformed: usize,
        sequence_errors: usize,
        head_missing: bool,
        head_mismatch: bool,
    ) -> VerifyReport {
        VerifyReport {
            verified: 3,
            tampered,
            legacy: 0,
            malformed,
            sequence_errors,
            head_missing,
            head_mismatch,
            tampered_lines: vec![],
            malformed_lines: vec![],
            sequence_error_lines: vec![],
        }
    }

    #[test]
    fn audit_log_read_error_says_what_failed_and_what_to_do() {
        let message = audit_log_read_error("Permission denied").to_string();
        assert!(
            message.starts_with("Failed to verify audit log: Permission denied."),
            "{message}"
        );
        assert!(message.contains("not a symlink"), "{message}");
        assert!(
            message.contains("`phantom audit verify` again"),
            "{message}"
        );
    }

    #[test]
    fn clean_report_has_no_failure_steps() {
        let clean = report(0, 0, 0, false, false);
        assert!(verify_failure_steps(&clean).is_empty());
    }

    #[test]
    fn content_failures_point_at_the_flagged_period() {
        for failed in [
            report(1, 0, 0, false, false),
            report(0, 1, 0, false, false),
            report(0, 0, 1, false, false),
        ] {
            let steps = verify_failure_steps(&failed);
            assert_eq!(steps.len(), 2, "{steps:?}");
            assert!(steps[0].contains("unreliable for the flagged period"));
            assert!(steps[1].contains("security incident"));
        }
    }

    #[test]
    fn head_failures_point_at_truncation() {
        for failed in [report(0, 0, 0, true, false), report(0, 0, 0, false, true)] {
            let steps = verify_failure_steps(&failed);
            assert_eq!(steps.len(), 2, "{steps:?}");
            assert!(steps[0].contains("truncation cannot be ruled out"));
            assert!(steps[1].contains("security incident"));
        }
    }

    #[test]
    fn every_failure_ends_with_the_incident_step() {
        let steps = verify_failure_steps(&report(1, 1, 1, true, true));
        assert_eq!(steps.len(), 3, "{steps:?}");
        assert!(steps[2].contains("`phantom audit incidents`"));
        assert!(steps[2].contains("`phantom leaks plan`"));
    }

    #[test]
    fn failure_steps_stay_value_free() {
        let steps = verify_failure_steps(&report(2, 1, 1, true, true));
        for step in steps {
            assert!(!step.contains('/'), "{step}");
            assert!(!step.contains(".phantom"), "{step}");
        }
    }

    #[test]
    fn json_next_step_is_null_when_clean_and_text_when_not() {
        let clean = verify_report_json(&report(0, 0, 0, false, false), true);
        assert!(clean["next_step"].is_null());

        let failed = verify_report_json(&report(1, 0, 0, false, false), true);
        let step = failed["next_step"].as_str().unwrap();
        assert!(step.contains("unreliable for the flagged period"), "{step}");
        assert!(step.contains("`phantom audit incidents`"), "{step}");
        assert!(failed["clean"].as_bool() == Some(false));
    }
}
