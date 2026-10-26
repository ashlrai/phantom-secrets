//! Line-buffered, value-independent log scrubbing. No vault or project access.

use std::io::{self, BufRead, Read, Write};

use phantom_core::secret_detector::credential_spans;
use zeroize::Zeroizing;

const MAX_LINE_BYTES: usize = 1024 * 1024;
const REPLACEMENT: &[u8] = b"[REDACTED]";

/// Redact complete lines, including a final unterminated line at EOF.
///
/// Keep a whole line across arbitrary reads: emitting partial reads would leak
/// a credential split across pipe writes. Bound memory instead of forwarding an
/// oversized line unsanitized. Byte-oriented input preserves non-UTF-8 logs.
/// This is shape detection, not a guarantee against arbitrary/encoded secrets.
pub fn stream(mut input: impl BufRead, mut output: impl Write) -> io::Result<()> {
    let mut line = Zeroizing::new(Vec::new());
    loop {
        line.clear();
        let count = input
            .by_ref()
            .take((MAX_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if count == 0 {
            return Ok(());
        }
        if count > MAX_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "redact input line exceeds the 1 MiB limit",
            ));
        }
        let mut copied = 0;
        for span in credential_spans(&line) {
            output.write_all(&line[copied..span.start])?;
            output.write_all(REPLACEMENT)?;
            copied = span.end;
        }
        output.write_all(&line[copied..])?;
        output.flush()?;
        // Clear sensitive input before reusing its allocation for another line.
        use zeroize::Zeroize;
        line.zeroize();
    }
}

pub fn run() -> anyhow::Result<()> {
    stream(io::stdin().lock(), io::stdout().lock())?;
    Ok(())
}
