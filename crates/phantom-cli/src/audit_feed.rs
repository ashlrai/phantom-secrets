//! Value-free workbench projection of untrusted audit NDJSON on stdin.
//!
//! Schema 1 deliberately excludes names, mappings, context, and arbitrary text.
//! This is a projection, not HMAC verification or evidence of authenticity.
use std::io::{self, BufRead, Write};

const MAX_RECORD: usize = 64 * 1024;

pub(crate) fn run() -> anyhow::Result<()> {
    emit(io::stdin().lock(), io::stdout().lock())?;
    Ok(())
}

/// Consume newline-terminated records with bounded memory. An unterminated
/// final record is never emitted, even when its JSON happens to be valid.
fn emit(mut input: impl BufRead, mut output: impl Write) -> io::Result<()> {
    let mut record = Vec::new();
    let mut oversized = false;
    loop {
        let chunk = input.fill_buf()?;
        if chunk.is_empty() {
            return output.flush();
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(chunk.len(), |index| index + 1);
        if !oversized {
            if record.len() + consumed > MAX_RECORD {
                record.clear();
                oversized = true;
            } else {
                record.extend_from_slice(&chunk[..consumed]);
            }
        }
        input.consume(consumed);
        if newline.is_some() {
            if !oversized {
                project(&record, &mut output)?;
            }
            record.clear();
            oversized = false;
        }
    }
}

fn project(record: &[u8], output: &mut impl Write) -> io::Result<()> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(record) else {
        return Ok(());
    };
    let (Some(seq), Some(ts), Some(op)) = (
        value.get("seq").and_then(|v| v.as_u64()),
        value.get("ts").and_then(|v| v.as_u64()),
        value.get("op").and_then(|v| v.as_str()),
    ) else {
        return Ok(());
    };
    // Return static labels only: never serialize a source string, including an
    // unknown operation. Adding fields requires a deliberate schema review.
    let operation = match op {
        "vault.store" => "vault.store",
        "vault.retrieve" => "vault.retrieve",
        "vault.delete" => "vault.delete",
        "cloud.push" => "cloud.push",
        "cloud.pull" => "cloud.pull",
        "proxy.response_leak" => "proxy.response_leak",
        _ => "unknown",
    };
    serde_json::to_writer(
        &mut *output,
        &serde_json::json!({
            "schema_version": 1,
            "type": "phantom.audit",
            "seq": seq,
            "ts": ts,
            "operation": operation,
        }),
    )?;
    output.write_all(b"\n")?;
    output.flush()
}
