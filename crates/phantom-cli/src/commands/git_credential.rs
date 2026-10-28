//! A deliberately narrow Git credential helper. This is a plaintext handoff
//! to Git, outside the value-blind proxy boundary. Pipe checks prevent common
//! accidental disclosure, but cannot authenticate the reader of that pipe.
use anyhow::{bail, Context, Result};
use std::io::{BufRead, IsTerminal, Read, Write};
use zeroize::Zeroizing;

const MAX_INPUT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Operation {
    Get,
    Store,
    Erase,
}

pub fn run(operation: Operation, secret: &str) -> Result<()> {
    // Never consume Git's store payload: it may contain plaintext credentials.
    if !matches!(operation, Operation::Get) {
        return Ok(());
    }
    if std::io::stdout().is_terminal() || !stdout_is_pipe()? {
        bail!("git-credential requires stdout to be a pipe to Git");
    }
    if !github_request(std::io::stdin().lock())? {
        return Ok(());
    }
    let project = crate::util::project_dir()?;
    let config = crate::util::load_project_config(&project)?;
    let vault = crate::util::open_vault(config.local_project_id())?;
    gate_credential(
        &config,
        vault.as_ref(),
        secret,
        super::rotation_gate::now_secs(),
    )?;
    phantom_core::audit::log_result("vault.git_credential", Some(secret))
        .context("Failed to audit Git credential access")?;
    let value =
        crate::util::retrieve_secret(vault.as_ref(), config.local_project_id(), secret, || {
            "Git credential unavailable in project vault".to_owned()
        })?;
    write_credential(std::io::stdout().lock(), &value)
}

fn gate_credential(
    config: &phantom_core::config::PhantomConfig,
    vault: &dyn phantom_vault::VaultBackend,
    secret: &str,
    now: u64,
) -> Result<()> {
    super::rotation_gate::enforce_lifecycle_on_propagation(
        config,
        vault,
        [secret],
        "supply Git credentials",
        "Verify the secret lifecycle before retrying.",
        "No credential was emitted.",
        now,
    )
}

#[cfg(unix)]
fn stdout_is_pipe() -> Result<bool> {
    use std::os::fd::AsRawFd;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes stat on success; stdout's borrowed fd stays live.
    if unsafe { libc::fstat(std::io::stdout().as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        bail!("Cannot verify Git credential output pipe");
    }
    // SAFETY: successful fstat initialized the structure.
    Ok(unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFIFO)
}

#[cfg(windows)]
fn stdout_is_pipe() -> Result<bool> {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    extern "system" {
        #[link_name = "GetFileType"]
        fn get_file_type(handle: *mut std::ffi::c_void) -> u32;
    }
    // SAFETY: the borrowed stdout handle stays live for this query.
    Ok(unsafe { get_file_type(std::io::stdout().as_raw_handle()) } == 3) // FILE_TYPE_PIPE
}

#[cfg(not(any(unix, windows)))]
fn stdout_is_pipe() -> Result<bool> {
    // Fail closed until a platform-specific pipe check is available.
    Ok(false)
}

/// Strict, bounded Git protocol parsing. Reject ambiguous destinations before
/// opening any vault. Unknown fields never override the host; unexpanded URLs are refused.
fn github_request(mut input: impl BufRead) -> Result<bool> {
    let mut protocol = None;
    let mut host = None;
    let mut total = 0;
    loop {
        let mut line = Zeroizing::new(Vec::new());
        let count = input
            .by_ref()
            .take((MAX_INPUT + 1 - total) as u64)
            .read_until(b'\n', &mut line)
            .context("Cannot read Git credential request")?;
        total += count;
        if total > MAX_INPUT {
            bail!("Git credential request exceeds input limit");
        }
        // Git terminates helper input with EOF; standalone callers may use
        // a blank line. Require complete lines in either case.
        if count == 0 {
            break;
        }
        if line.last() != Some(&b'\n') {
            bail!("Incomplete Git credential request field");
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            break;
        }
        let text = std::str::from_utf8(&line).context("Invalid Git credential request encoding")?;
        if text.chars().any(char::is_control) {
            bail!("Invalid Git credential request field");
        }
        let (key, value) = text
            .split_once('=')
            .context("Invalid Git credential request field")?;
        let target = match key {
            "protocol" => &mut protocol,
            "host" => &mut host,
            // A URL is not part of the helper protocol's expanded destination.
            "url" => bail!("Unexpanded Git credential URL is unsupported"),
            _ => continue,
        };
        if target.is_some() {
            bail!("Duplicate Git credential destination field");
        }
        *target = Some(value.to_owned());
    }
    Ok(protocol.as_deref() == Some("https") && host.as_deref() == Some("github.com"))
}

fn write_credential(mut output: impl Write, value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_control) {
        bail!("Vault credential cannot be encoded in the Git credential protocol");
    }
    output
        .write_all(b"username=x-access-token\npassword=")
        .and_then(|()| output.write_all(value.as_bytes()))
        .and_then(|()| output.write_all(b"\n\n"))
        .and_then(|()| output.flush())
        .map_err(|_| anyhow::anyhow!("Failed to write Git credential response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_gate_refuses_overdue_credentials() {
        use crate::commands::rotation_gate::fixtures::{aged_vault, enforced_config, NOW};
        let dir = tempfile::tempdir().unwrap();
        let vault = aged_vault(&dir, &[("STALE_KEY", 45), ("FRESH_KEY", 1)]);
        let config = enforced_config(&["STALE_KEY", "FRESH_KEY"]);
        assert!(gate_credential(&config, &vault, "STALE_KEY", NOW).is_err());
        assert!(gate_credential(&config, &vault, "FRESH_KEY", NOW).is_ok());
        use phantom_vault::VaultBackend;
        vault
            .set_metadata(
                "FRESH_KEY",
                phantom_vault::SecretMetadata {
                    created_at: Some(NOW),
                    vault_mode: phantom_vault::metadata::VaultMode::ReadOnly,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(gate_credential(&config, &vault, "FRESH_KEY", NOW).is_err());
    }

    #[test]
    fn only_exact_https_github_is_eligible() {
        for host in [
            "github.com",
            "github.com:443",
            "github.com.evil",
            "evil@github.com",
            "GitHub.com",
            "github.com.",
        ] {
            for protocol in ["https", "http", "ssh", ""] {
                let request = format!("protocol={protocol}\nhost={host}\npath=org/repo.git\n\n");
                assert_eq!(
                    github_request(request.as_bytes()).unwrap(),
                    host == "github.com" && protocol == "https"
                );
            }
        }
        assert!(!github_request(&b"\n"[..]).unwrap());
        assert!(github_request(&b"protocol=https\nhost=github.com\n"[..]).unwrap());
        assert!(github_request(&b"protocol=https\r\nhost=github.com\r\n\r\n"[..]).unwrap());
    }

    #[test]
    fn malformed_ambiguous_and_unbounded_input_is_rejected() {
        for request in [
            "protocol=https\nhost=github.com\nhost=evil\n\n",
            "protocol=https\nprotocol=http\nhost=github.com\n\n",
            "url=https://github.com\n\n",
            "host\n\n",
            "host=github.com\0\n\n",
            "protocol=https\nhost=github.com",
        ] {
            assert!(github_request(request.as_bytes()).is_err());
        }
        assert!(github_request(&b"host=\xff\n\n"[..]).is_err());
        assert!(github_request(vec![b'x'; MAX_INPUT + 1].as_slice()).is_err());
    }

    #[test]
    fn response_is_git_protocol_and_injection_never_emits_bytes() {
        let mut output = Vec::new();
        write_credential(&mut output, "synthetic-fixture").unwrap();
        assert_eq!(
            output,
            b"username=x-access-token\npassword=synthetic-fixture\n\n"
        );
        for value in ["", "fake\npassword=injected", "fake\r", "fake\0"] {
            let mut output = Vec::new();
            assert!(write_credential(&mut output, value).is_err());
            assert!(output.is_empty());
        }
    }

    #[test]
    fn write_errors_are_value_free() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("synthetic-sensitive-error"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let error = write_credential(Broken, "synthetic-fixture")
            .unwrap_err()
            .to_string();
        assert_eq!(error, "Failed to write Git credential response");
    }
}
