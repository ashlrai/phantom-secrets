use super::*;

pub fn run_show(
    last: usize,
    op: Option<&str>,
    name: Option<&str>,
    json: bool,
    leaked_secrets: bool,
    output: Option<&std::path::Path>,
) -> Result<()> {
    let path = resolve_path()?;
    if let Some(dest) = output {
        let mut buf = Vec::new();
        colored::control::set_override(false);
        let shown = run_show_at(
            &path,
            last,
            op,
            name,
            json,
            leaked_secrets,
            &mut buf,
            &mut std::io::stderr(),
        );
        colored::control::unset_override();
        shown?;
        crate::report_file::write_new(dest, &buf)?;
        let lines = buf.iter().filter(|b| **b == b'\n').count();
        println!("Audit: wrote {lines} line(s) to {}", dest.display());
        return Ok(());
    }
    run_show_at(
        &path,
        last,
        op,
        name,
        json,
        leaked_secrets,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}

/// `--json` output is JSON Lines: one audit event object per stdout line.
/// With no events stdout stays empty (zero records), and the human hint goes
/// to `err` so a script parsing stdout never sees prose. Without `--json`
/// the hint stays on `out` exactly as before.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_show_at(
    path: &std::path::Path,
    last: usize,
    op: Option<&str>,
    name: Option<&str>,
    json: bool,
    leaked_secrets: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<()> {
    let hint_to = |json: bool, out: &mut dyn Write, err: &mut dyn Write, hint: String| {
        if json {
            writeln!(err, "{hint}")
        } else {
            writeln!(out, "{hint}")
        }
    };

    let present = phantom_core::audit::log_present(path)
        .map_err(|error| anyhow::anyhow!("Failed to read audit log {}: {error}", path.display()))?;
    if !present {
        hint_to(
            json,
            out,
            err,
            format!(
                "{}  No audit events yet - set {} to start logging.",
                "->".blue().bold(),
                "PHANTOM_AUDIT=1".cyan()
            ),
        )?;
        return Ok(());
    }

    // --leaked-secrets overrides --op to filter to proxy.response_leak events.
    let effective_op = if leaked_secrets {
        Some("proxy.response_leak")
    } else {
        op
    };

    // An unreadable log is not an empty one: fail instead of reporting
    // "No matching audit events" (or empty --json output) with exit 0.
    let matched = read_matching_lines(path, effective_op, name)
        .map_err(|error| anyhow::anyhow!("Failed to read audit log {}: {error}", path.display()))?;
    if matched.unparsable > 0 {
        eprintln!(
            "{} Skipped {} line(s) that are not valid audit JSON; run {} to check the chain.",
            "warn".yellow().bold(),
            matched.unparsable,
            "phantom audit verify".cyan()
        );
    }
    if matched.window_truncated && matched.lines.len() < last {
        eprintln!(
            "{}  Only the newest {} MiB of the audit log were read; older events were not examined.",
            "->".blue().bold(),
            phantom_core::audit::RECENT_WINDOW_BYTES / (1024 * 1024)
        );
    }
    let lines = matched.lines;

    if lines.is_empty() {
        hint_to(
            json,
            out,
            err,
            format!("{}  No matching audit events.", "->".blue().bold()),
        )?;
        return Ok(());
    }

    // Take the last N
    let window: Vec<&str> = lines
        .iter()
        .rev()
        .take(last)
        .rev() // restore chronological order
        .map(String::as_str)
        .collect();

    if json {
        for line in &window {
            writeln!(out, "{}", line)?;
        }
    } else {
        // Into `out`, not stdout: with --output, `out` is the file.
        for line in &window {
            write_event(line, out, err)?;
        }
    }

    Ok(())
}

pub fn run_tail(op: Option<&str>, name: Option<&str>) -> Result<()> {
    let path = resolve_path()?;
    let mut reader = open_log_for_follow(&path)?;

    println!(
        "{}  Tailing {} - press Ctrl-C to stop",
        "->".blue().bold(),
        path.display().to_string().dimmed()
    );

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            // No new data - wait and retry
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        }
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if matches_filters(trimmed, op, name) {
            print_event(trimmed);
        }
    }
}

pub fn run_path() -> Result<()> {
    let path = resolve_path()?;
    println!("{}", path.display());
    Ok(())
}
