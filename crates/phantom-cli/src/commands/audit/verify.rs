use super::*;

pub fn run_verify(with_context: bool, json: bool) -> Result<()> {
    let path = resolve_path()?;
    // Nothing is followed: a dangling symlink at the log is not "no log",
    // and a symlinked `~/.phantom` is refused.
    let log_present = phantom_core::audit::log_present(&path)
        .map_err(|e| anyhow::anyhow!("Failed to verify audit log: {e}"))?;
    // A retained head checkpoint proves a signed era existed, so a missing log
    // beside it is a deletion: verify it (the walk reports a head mismatch)
    // instead of reporting a log that never started.
    let head_present = match phantom_core::audit::head_checkpoint_path() {
        Ok(head) => phantom_core::audit::log_present(&head)
            .map_err(|e| anyhow::anyhow!("Failed to verify audit log: {e}"))?,
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
                }))?
            );
        } else {
            println!(
                "{}  No audit log found — set {} to start logging.",
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

    let report = phantom_core::audit::verify_log()
        .map_err(|e| anyhow::anyhow!("Failed to verify audit log: {e}"))?;

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
        std::process::exit(1);
    }

    Ok(())
}

/// The `phantom audit verify --json` object. Counts and line numbers only:
/// it never carries event names, values, or HMACs.
fn verify_report_json(report: &phantom_core::audit::VerifyReport, log_present: bool) -> Value {
    let head = if report.head_missing {
        "missing"
    } else if report.head_mismatch {
        "mismatch"
    } else {
        "ok"
    };
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
    })
}

/// `phantom audit verify --with-context`: decrypt and display `encrypted_context`
/// for every event in the log, providing a forensics-grade view of audit metadata.
fn run_verify_with_context() -> Result<()> {
    let (report, events) = phantom_core::audit::verify_log_with_context()
        .map_err(|e| anyhow::anyhow!("Failed to verify audit log: {e}"))?;

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
        std::process::exit(1);
    }

    Ok(())
}
