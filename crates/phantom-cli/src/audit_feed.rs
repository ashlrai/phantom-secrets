//! Value-free workbench projection of untrusted audit NDJSON on stdin or a followed file.
//!
//! Schema 1 deliberately excludes names, mappings, context, and arbitrary text.
//! This is a projection, not HMAC verification or evidence of authenticity.
//! Follow cursors resume after a complete line; mismatched file identity or
//! prefix restarts at byte zero (duplicates are possible after a reset). Rotation
//! follows the current path, so unread events in renamed files are not recovered.
//! Prefix validation uses bounded memory and reads the consumed prefix each poll.
use std::io::{self, BufRead, Write};

const MAX_RECORD: usize = 64 * 1024;

pub(crate) fn run(
    follow: Option<std::path::PathBuf>,
    cursor: Option<String>,
) -> anyhow::Result<()> {
    if let Some(path) = follow {
        return follow_file(&path, cursor.as_deref());
    }
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
                project(&record, &mut output, None)?;
            }
            record.clear();
            oversized = false;
        }
    }
}

fn project(record: &[u8], output: &mut impl Write, cursor: Option<String>) -> io::Result<()> {
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
    let mut event = serde_json::json!({
        "schema_version": 1,
        "type": "phantom.audit",
        "seq": seq,
        "ts": ts,
        "operation": operation,
    });
    if let Some(cursor) = cursor {
        event["cursor"] = cursor.into();
    }
    serde_json::to_writer(&mut *output, &event)?;
    output.write_all(b"\n")?;
    output.flush()
}

// Cursors contain only a version, file identity, byte offset and prefix digest.
// Source fields and paths never enter the cursor. Prefix validation also detects
// truncate-and-regrow between polls. No cursor is an authenticity claim.
#[derive(serde::Serialize, serde::Deserialize)]
struct Cursor {
    version: u8,
    identity: String,
    offset: u64,
    digest: String,
}

fn identity(metadata: &std::fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        format!("{}:{}", metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        format!("{:?}", metadata.created().ok())
    }
}

fn follow_file(path: &std::path::Path, resume: Option<&str>) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut cursor: Option<Cursor> = match resume {
        Some(raw) => {
            anyhow::ensure!(raw.len() <= 1024, "invalid audit cursor");
            let parsed = hex::decode(raw)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Cursor>(&bytes).ok())
                .filter(|c| c.version == 1 && c.digest.len() == 64 && c.identity.len() <= 128)
                .ok_or_else(|| anyhow::anyhow!("invalid audit cursor"))?;
            Some(parsed)
        }
        None => None,
    };
    let mut output = io::stdout().lock();
    loop {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        anyhow::ensure!(metadata.is_file(), "audit feed requires a regular file");
        let id = identity(&metadata);
        let mut input = io::BufReader::new(file);
        let mut hash = Sha256::new();
        let mut offset = 0;
        if let Some(previous) = &cursor {
            if previous.identity == id && previous.offset <= metadata.len() {
                let mut remaining = previous.offset;
                let mut buffer = [0; 8192];
                while remaining > 0 {
                    let limit = remaining.min(buffer.len() as u64) as usize;
                    let count = input.read(&mut buffer[..limit])?;
                    if count == 0 {
                        break;
                    }
                    hash.update(&buffer[..count]);
                    remaining -= count as u64;
                }
                if remaining == 0 && hex::encode(hash.clone().finalize()) == previous.digest {
                    offset = previous.offset;
                }
            }
        }
        if offset == 0 {
            use std::io::Seek;
            input.rewind()?;
            hash = Sha256::new();
        }
        let mut record = Vec::new();
        let mut oversized = false;
        loop {
            let chunk = input.fill_buf()?;
            if chunk.is_empty() {
                break;
            }
            let newline = chunk.iter().position(|byte| *byte == b'\n');
            let count = newline.map_or(chunk.len(), |index| index + 1);
            hash.update(&chunk[..count]);
            offset += count as u64;
            if !oversized {
                if record.len() + count > MAX_RECORD {
                    record.clear();
                    oversized = true;
                } else {
                    record.extend_from_slice(&chunk[..count]);
                }
            }
            input.consume(count);
            if newline.is_some() {
                let next = Cursor {
                    version: 1,
                    identity: id.clone(),
                    offset,
                    digest: hex::encode(hash.clone().finalize()),
                };
                if !oversized {
                    project(
                        &record,
                        &mut output,
                        Some(hex::encode(serde_json::to_vec(&next)?)),
                    )?;
                }
                cursor = Some(next);
                record.clear();
                oversized = false;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
