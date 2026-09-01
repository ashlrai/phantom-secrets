use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

const CLIPBOARD_CLEAR_DELAY: Duration = Duration::from_secs(30);
const MAX_CLEAR_DELAY_SECS: u64 = 300;
const MAX_CLIPBOARD_HANDOFF_BYTES: usize = 64 * 1024;
const CLEAR_READY_ACK: &[u8] = b"phantom-clipboard-clear-ready-v1\n";

/// Reveal a single secret value from the vault after a trusted-terminal ceremony.
pub fn run(name: &str, clipboard: bool, yes: bool) -> Result<()> {
    if yes {
        anyhow::bail!(
            "--yes is no longer supported for secret reveal; plaintext access requires a trusted interactive terminal"
        );
    }

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        anyhow::bail!("Refusing to reveal a secret without attached stdin and stderr terminals");
    }

    eprintln!(
        "{} Plaintext access can expose {} to the current terminal session.",
        "!".yellow().bold(),
        name.bold()
    );
    eprint!("Type `reveal {name}` to continue: ");
    std::io::stderr().flush()?;
    let mut confirmation = String::new();
    std::io::stdin().read_line(&mut confirmation)?;
    if confirmation.trim() != format!("reveal {name}") {
        anyhow::bail!("Secret reveal cancelled: typed confirmation did not match");
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;

    phantom_core::audit::log_result("vault.reveal", Some(name))
        .context("Failed to write audit event for secret reveal")?;

    let value: Zeroizing<String> = vault
        .retrieve(name)
        .context(format!("Secret '{}' not found in vault", name))?;

    if clipboard {
        validate_clipboard_handoff(value.as_bytes(), CLIPBOARD_CLEAR_DELAY)?;
        require_clipboard_copy(copy_to_clipboard(&value))?;
        if schedule_clipboard_clear(&value, CLIPBOARD_CLEAR_DELAY).is_err() {
            return report_clipboard_schedule_failure(&value);
        }
        println!(
            "{} Copied {} to clipboard (compare-and-clear scheduled in 30 seconds)",
            "ok".green().bold(),
            name.bold()
        );
    } else {
        println!("{}", value.as_str());
    }

    // Zeroizing<String> scrubs memory on drop automatically.

    Ok(())
}

fn require_clipboard_copy(copied: bool) -> Result<()> {
    if copied {
        Ok(())
    } else {
        anyhow::bail!("Clipboard access failed; refusing to fall back to plaintext stdout")
    }
}

fn copy_to_clipboard(text: &str) -> bool {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => clipboard.set_text(text.to_string()).is_ok(),
        Err(_) => false,
    }
}

/// Spawn a child of this same binary that receives the copied value through a
/// private pipe, sleeps `delay`, and clears the clipboard only if its contents
/// are still byte-for-byte equal to that value.
///
/// We spawn a child rather than a thread so the parent `phantom reveal`
/// process can exit immediately and return the user to their prompt; a
/// thread would die when the parent exits, and on macOS/Windows the
/// clipboard contents persist past process exit so we need a live process
/// to issue the conditional clear. The plaintext is never placed in argv,
/// environment variables, files, or diagnostic output.
fn schedule_clipboard_clear(value: &str, delay: Duration) -> Result<()> {
    validate_clipboard_handoff(value.as_bytes(), delay)?;
    let exe = std::env::current_exe().context("Failed to locate clipboard-clear helper")?;
    let mut child = spawn_clear_child(&exe, delay)?;
    let handoff_result = child
        .stdin
        .take()
        .ok_or_else(|| {
            anyhow::anyhow!("Clipboard-clear helper did not provide a private input pipe")
        })
        .and_then(|input| {
            child
                .stdout
                .take()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Clipboard-clear helper did not provide a private readiness pipe"
                    )
                })
                .and_then(|ready| handoff_and_require_ready(input, ready, value))
        });
    if let Err(error) = handoff_result {
        terminate_failed_child(&mut child);
        return Err(error);
    }
    Ok(())
}

fn spawn_clear_child(exe: &Path, delay: Duration) -> Result<Child> {
    build_clear_command(exe, delay)
        .spawn()
        .context("Failed to start clipboard-clear helper")
}

fn build_clear_command(exe: &Path, delay: Duration) -> Command {
    let mut command = Command::new(exe);
    command
        .arg("__clear-clipboard-after")
        .arg("--secs")
        .arg(delay.as_secs().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

fn terminate_failed_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn validate_clipboard_handoff(value: &[u8], delay: Duration) -> Result<()> {
    if value.len() > MAX_CLIPBOARD_HANDOFF_BYTES {
        anyhow::bail!(
            "Secret is too large for the bounded clipboard auto-clear handoff; nothing was copied"
        );
    }
    if delay.is_zero() || delay.as_secs() > MAX_CLEAR_DELAY_SECS || delay.subsec_nanos() != 0 {
        anyhow::bail!("Clipboard clear delay is outside the bounded safety policy");
    }
    Ok(())
}

fn handoff_and_require_ready(
    mut input: impl Write,
    mut ready: impl Read,
    value: &str,
) -> Result<()> {
    input
        .write_all(value.as_bytes())
        .context("Failed to hand off clipboard-clear authorization")?;
    input
        .flush()
        .context("Failed to finish clipboard-clear authorization")?;
    drop(input);

    let mut acknowledgement = [0_u8; CLEAR_READY_ACK.len()];
    ready
        .read_exact(&mut acknowledgement)
        .context("Clipboard-clear helper exited before accepting authorization")?;
    if acknowledgement != CLEAR_READY_ACK {
        anyhow::bail!("Clipboard-clear helper returned an invalid value-free readiness response");
    }
    Ok(())
}

fn report_clipboard_schedule_failure(value: &str) -> Result<()> {
    match clear_system_clipboard_if_unchanged(value) {
        Ok(ClearOutcome::Cleared) => anyhow::bail!(
            "Secret was copied, but automatic clearing could not be scheduled. Phantom immediately removed the unchanged copied value; no delayed clearer is running."
        ),
        Ok(ClearOutcome::PreservedNewerValue) => anyhow::bail!(
            "Secret was copied, but automatic clearing could not be scheduled. The clipboard changed before rollback, so Phantom preserved the newer clipboard value; no delayed clearer is running."
        ),
        Err(_) => anyhow::bail!(
            "Secret was copied, but automatic clearing could not be scheduled or verified. The copied secret may remain in the clipboard; replace or clear it manually."
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClearOutcome {
    Cleared,
    PreservedNewerValue,
}

trait ClipboardAccess {
    fn read_text(&mut self) -> Result<String>;
    fn clear_text(&mut self) -> Result<()>;
}

impl ClipboardAccess for arboard::Clipboard {
    fn read_text(&mut self) -> Result<String> {
        self.get_text()
            .context("Failed to read clipboard for conditional clear")
    }

    fn clear_text(&mut self) -> Result<()> {
        self.clear()
            .context("Failed to conditionally clear clipboard")
    }
}

fn clear_if_unchanged(
    clipboard: &mut impl ClipboardAccess,
    expected: &str,
) -> Result<ClearOutcome> {
    // Re-read immediately before clearing so a replacement that races the
    // delayed check is preserved rather than overwritten by the helper.
    for _ in 0..2 {
        let current = Zeroizing::new(clipboard.read_text()?);
        if current.as_bytes() != expected.as_bytes() {
            return Ok(ClearOutcome::PreservedNewerValue);
        }
    }
    clipboard.clear_text()?;
    Ok(ClearOutcome::Cleared)
}

fn clear_system_clipboard_if_unchanged(expected: &str) -> Result<ClearOutcome> {
    let mut clipboard = arboard::Clipboard::new().context("Failed to access clipboard")?;
    clear_if_unchanged(&mut clipboard, expected)
}

fn read_expected_value(mut input: impl Read) -> Result<Zeroizing<String>> {
    let mut expected = Zeroizing::new(String::new());
    input
        .by_ref()
        .take((MAX_CLIPBOARD_HANDOFF_BYTES + 1) as u64)
        .read_to_string(&mut expected)
        .context("Clipboard-clear authorization was not valid UTF-8")?;
    if expected.len() > MAX_CLIPBOARD_HANDOFF_BYTES {
        anyhow::bail!("Clipboard-clear authorization exceeded the bounded input limit");
    }
    Ok(expected)
}

fn accept_handoff_and_signal_ready(
    input: impl Read,
    mut ready: impl Write,
) -> Result<Zeroizing<String>> {
    let expected = read_expected_value(input)?;
    ready
        .write_all(CLEAR_READY_ACK)
        .context("Failed to acknowledge clipboard-clear authorization")?;
    ready
        .flush()
        .context("Failed to flush clipboard-clear readiness")?;
    Ok(expected)
}

/// Body of the hidden `__clear-clipboard-after` subcommand. It accepts the
/// expected clipboard contents only from a bounded private stdin pipe, keeps
/// them in zeroizing memory during the delay, and preserves any newer value.
pub fn run_clear_after(secs: u64) -> Result<()> {
    if std::io::stdin().is_terminal() {
        anyhow::bail!("Clipboard-clear helper requires a private stdin pipe");
    }
    let delay = Duration::from_secs(secs);
    validate_clipboard_handoff(&[], delay)?;
    let expected =
        accept_handoff_and_signal_ready(std::io::stdin().lock(), std::io::stdout().lock())?;
    std::thread::sleep(delay);
    clear_system_clipboard_if_unchanged(&expected)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeClipboard {
        text: String,
        clear_calls: usize,
        read_calls: usize,
        replacement_on_second_read: Option<String>,
    }

    impl ClipboardAccess for FakeClipboard {
        fn read_text(&mut self) -> Result<String> {
            self.read_calls += 1;
            if self.read_calls == 2 {
                if let Some(replacement) = self.replacement_on_second_read.take() {
                    self.text = replacement;
                }
            }
            Ok(self.text.clone())
        }

        fn clear_text(&mut self) -> Result<()> {
            self.clear_calls += 1;
            self.text.clear();
            Ok(())
        }
    }

    #[test]
    fn legacy_noninteractive_bypass_is_always_rejected() {
        let error = run("TEST_SECRET", false, true).unwrap_err();
        assert!(error.to_string().contains("--yes is no longer supported"));
    }

    #[test]
    fn clipboard_failure_never_falls_back_to_stdout() {
        let error = require_clipboard_copy(false).unwrap_err();
        assert!(error.to_string().contains("refusing to fall back"));
    }

    #[test]
    fn delayed_clear_preserves_a_newer_clipboard_value() {
        let mut clipboard = FakeClipboard {
            text: "new user value".to_string(),
            clear_calls: 0,
            read_calls: 0,
            replacement_on_second_read: None,
        };
        let outcome = clear_if_unchanged(&mut clipboard, "phantom copied value").unwrap();
        assert_eq!(outcome, ClearOutcome::PreservedNewerValue);
        assert_eq!(clipboard.text, "new user value");
        assert_eq!(clipboard.clear_calls, 0);
    }

    #[test]
    fn delayed_clear_removes_only_the_exact_copied_value() {
        let mut clipboard = FakeClipboard {
            text: "phantom copied value".to_string(),
            clear_calls: 0,
            read_calls: 0,
            replacement_on_second_read: None,
        };
        let outcome = clear_if_unchanged(&mut clipboard, "phantom copied value").unwrap();
        assert_eq!(outcome, ClearOutcome::Cleared);
        assert!(clipboard.text.is_empty());
        assert_eq!(clipboard.clear_calls, 1);
    }

    #[test]
    fn delayed_clear_preserves_value_replaced_during_final_check() {
        let mut clipboard = FakeClipboard {
            text: "phantom copied value".to_string(),
            clear_calls: 0,
            read_calls: 0,
            replacement_on_second_read: Some("new user value".to_string()),
        };
        let outcome = clear_if_unchanged(&mut clipboard, "phantom copied value").unwrap();
        assert_eq!(outcome, ClearOutcome::PreservedNewerValue);
        assert_eq!(clipboard.text, "new user value");
        assert_eq!(clipboard.clear_calls, 0);
    }

    #[test]
    fn child_handoff_is_bounded_and_value_free_from_process_metadata() {
        let secret = "not-an-actual-secret-value";
        let mut ready = Vec::new();
        let expected =
            accept_handoff_and_signal_ready(std::io::Cursor::new(secret), &mut ready).unwrap();
        assert_eq!(expected.as_str(), secret);
        assert_eq!(ready, CLEAR_READY_ACK);

        let mut parent_pipe = Vec::new();
        handoff_and_require_ready(
            &mut parent_pipe,
            std::io::Cursor::new(CLEAR_READY_ACK),
            secret,
        )
        .unwrap();
        assert_eq!(parent_pipe, secret.as_bytes());
        assert!(handoff_and_require_ready(
            Vec::new(),
            std::io::Cursor::new(b"wrong-readiness-response"),
            secret
        )
        .is_err());
        let mut wrong_ack = CLEAR_READY_ACK.to_vec();
        wrong_ack[0] ^= 1;
        assert!(
            handoff_and_require_ready(Vec::new(), std::io::Cursor::new(wrong_ack), secret).is_err()
        );

        let mut rejected_ready = Vec::new();
        assert!(accept_handoff_and_signal_ready(
            std::io::Cursor::new(vec![b'x'; MAX_CLIPBOARD_HANDOFF_BYTES + 1]),
            &mut rejected_ready
        )
        .is_err());
        assert!(rejected_ready.is_empty());
        let mut malformed_ready = Vec::new();
        assert!(accept_handoff_and_signal_ready(
            std::io::Cursor::new([0xff, 0xfe]),
            &mut malformed_ready
        )
        .is_err());
        assert!(malformed_ready.is_empty());

        let command = build_clear_command(Path::new("phantom"), Duration::from_secs(30));
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "__clear-clipboard-after");
        assert_eq!(args[1], "--secs");
        assert_eq!(args[2], "30");
        assert!(args.iter().all(|arg| arg.to_str() != Some(secret)));
        assert!(command
            .get_envs()
            .all(|(_, value)| value.and_then(|item| item.to_str()) != Some(secret)));
    }

    #[test]
    fn unsafe_clear_delays_are_rejected() {
        assert!(validate_clipboard_handoff(b"value", Duration::ZERO).is_err());
        assert!(validate_clipboard_handoff(
            b"value",
            Duration::from_secs(MAX_CLEAR_DELAY_SECS + 1)
        )
        .is_err());
        assert!(validate_clipboard_handoff(b"value", Duration::from_millis(1500)).is_err());
    }
}
