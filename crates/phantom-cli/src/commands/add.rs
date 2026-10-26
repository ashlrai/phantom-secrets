use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::error::PhantomError;
use phantom_core::token::TokenMap;
use phantom_vault::{InitFile, InitSecret, VaultBackend};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

struct AddPlan {
    mutation: InitSecret,
    files: Vec<InitFile>,
    env_path: PathBuf,
}

/// Add one secret through a single exact-before project transaction.
/// How `phantom add --stdin` treats input with more than one line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdinLines {
    /// Default: a single line is stored; more than one line is refused.
    SingleOnly,
    /// `--multiline`: store the whole value, inner line breaks kept.
    Multiline,
    /// `--first-line`: store only line 1 (pass/gopass put metadata after it).
    FirstLine,
}

pub fn run(
    name: &str,
    value_arg: Option<String>,
    from_stdin: bool,
    lines: StdinLines,
) -> Result<()> {
    if let Some(mut value) = value_arg {
        value.zeroize();
        anyhow::bail!(
            "Positional secret values are disabled because command-line arguments can be exposed by process inspection. Omit the value for a hidden terminal prompt, or use --stdin."
        );
    }
    validate_secret_name(name)?;

    let project_dir = crate::util::project_dir()?
        .canonicalize()
        .context("Failed to resolve the current project directory")?;
    let config_path = project_dir.join(".phantom.toml");
    let (config, config_before) = load_config_exact(&config_path).map_err(|error| {
        if error.downcast_ref::<NotInitialized>().is_some() {
            anyhow::anyhow!(
                "Project is not initialized. Run `phantom init --empty` first; `phantom add` will not create config, gitignore, or vault state outside its secret transaction."
            )
        } else {
            error
        }
    })?;
    validate_managed_dotenv_preflight(&project_dir, &config)?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    ensure_secret_absent(vault.as_ref(), config.local_project_id(), name)?;

    // Existing-name authority is resolved from value-blind vault metadata
    // before stdin or the hidden prompt is touched. A second check in
    // `prepare_add_plan` closes the race between this preflight and commit.
    let value = read_secret_value(name, from_stdin, lines)?;
    let plan = prepare_add_plan(
        &project_dir,
        &config_path,
        config,
        config_before,
        vault.as_ref(),
        name,
        value.as_str(),
    )?;

    phantom_vault::commit_init(
        &project_dir,
        vault.as_ref(),
        vec![plan.mutation],
        plan.files,
    )
    .context(
        "Add transaction failed; exact transaction-owned state was rolled back where verifiable. Inspect the vault and managed dotenv before retrying.",
    )?;

    println!(
        "{} Stored {} in vault ({}) and updated {} (value never printed)",
        "ok".green().bold(),
        name.bold(),
        vault.backend_name().dimmed(),
        plan.env_path
            .file_name()
            .and_then(|part| part.to_str())
            .unwrap_or("managed dotenv")
            .cyan()
    );
    Ok(())
}

pub(super) fn validate_managed_dotenv_preflight(
    project_dir: &Path,
    config: &PhantomConfig,
) -> Result<()> {
    let resolved = phantom_core::managed_dotenv::resolve_dotenv(project_dir, config, &[])
        .context("Failed to resolve the managed dotenv before vault access or secret input")?;
    if let Some(dotenv) = resolved.file.as_ref() {
        dotenv.validate_for_mutation().context(
            "Managed dotenv is malformed; add stopped before vault access or secret input",
        )?;
    }
    Ok(())
}

/// Refuse a name the vault already holds, before any value is read. Beside an
/// encrypted-file vault this process cannot open, the listing covers only the
/// OS keychain, so absence cannot be established: the name may be in that
/// file, and storing it would split the project's secrets across two vaults.
fn ensure_secret_absent(vault: &dyn VaultBackend, project_id: &str, name: &str) -> Result<()> {
    let vault_names = vault.list().context("Failed to list protected secrets")?;
    crate::util::require_complete_inventory(vault, project_id, vault_names.len(), "add a secret")?;
    if vault_names.iter().any(|existing| existing == name) {
        anyhow::bail!(
            "Secret '{name}' is already protected. `phantom add` creates new names only and refuses replacement before reading a value. Use the trusted-terminal `phantom remove {name}` ceremony first if you explicitly intend a separate, non-atomic remove-and-add sequence."
        );
    }
    Ok(())
}

/// Upper bound on a value piped through `phantom add --stdin`. Generous for
/// any real credential (a 4096-bit PEM private key or a cloud service-account
/// JSON document is a few KiB) while keeping a runaway producer such as
/// `/dev/zero` from growing memory without limit.
const MAX_STDIN_VALUE_BYTES: usize = 64 * 1024;

fn read_secret_value(name: &str, from_stdin: bool, lines: StdinLines) -> Result<Zeroizing<String>> {
    if from_stdin {
        if stdin_is_tty() {
            anyhow::bail!(
                "--stdin reads from a pipe, but stdin is a terminal, where typed input would echo. Omit {} for the hidden prompt.",
                "--stdin".cyan().bold()
            );
        }
        return read_stdin_value(std::io::stdin().lock(), lines);
    }
    if !stdin_is_tty() {
        anyhow::bail!(
            "stdin is not a terminal. Omit the value for a hidden prompt, or use {} to read it from a pipe.",
            "--stdin".cyan().bold()
        );
    }
    let secret = rpassword::prompt_password(format!("Value for {name}: "))
        .context("Failed to read secret interactively")?;
    if secret.is_empty() {
        anyhow::bail!("Empty value — aborting.");
    }
    Ok(Zeroizing::new(secret))
}

/// Read one value from a piped producer, up to EOF.
///
/// Trailing line endings are dropped first, so `echo "$VALUE" |` is one line.
/// Input that still spans more than one line is refused unless the caller
/// said what to store: `--multiline` keeps every line exactly (a PEM key or
/// service-account JSON, as `phantom init` stores quoted multi-line values),
/// `--first-line` keeps only line 1 (pass/gopass metadata follows it).
/// Guessing either way would silently store a broken credential, and `add`
/// is create-only, so it cannot be redone in place. Oversized, multi-line
/// and non-UTF-8 input is refused before any vault write, and no refusal
/// contains input bytes.
fn read_stdin_value(reader: impl std::io::Read, lines: StdinLines) -> Result<Zeroizing<String>> {
    use std::io::Read;

    // Sized once so the buffer never regrows and leaves unwiped copies.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_STDIN_VALUE_BYTES + 1));
    reader
        .take(MAX_STDIN_VALUE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("Failed to read value from stdin")?;
    if bytes.len() > MAX_STDIN_VALUE_BYTES {
        anyhow::bail!(
            "Value on stdin exceeds {} KiB; nothing was stored.",
            MAX_STDIN_VALUE_BYTES / 1024
        );
    }
    while bytes.ends_with(b"\n") || bytes.ends_with(b"\r") {
        bytes.pop();
    }
    let line_count = count_lines(&bytes);
    if line_count > 1 {
        match lines {
            StdinLines::Multiline => {}
            StdinLines::FirstLine => {
                let end = bytes
                    .iter()
                    .position(|byte| *byte == b'\n' || *byte == b'\r')
                    .unwrap_or(bytes.len());
                // Truncate in place: the dropped tail stays inside the
                // zeroizing allocation and is wiped with it.
                bytes.truncate(end);
            }
            StdinLines::SingleOnly => anyhow::bail!(
                "Input on stdin has {line_count} lines; pass --multiline to store all of it or --first-line to store only the first; nothing was stored."
            ),
        }
    }
    if bytes.is_empty() {
        anyhow::bail!("Received empty value on stdin — aborting.");
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("Value on stdin is not valid UTF-8; nothing was stored."))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Count lines, treating `\n`, `\r\n` and a lone `\r` as one break each.
fn count_lines(bytes: &[u8]) -> usize {
    let mut breaks = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\n' => breaks += 1,
            b'\r' => {
                breaks += 1;
                if bytes.get(index + 1) == Some(&b'\n') {
                    index += 1;
                }
            }
            _ => {}
        }
        index += 1;
    }
    breaks + 1
}

#[allow(clippy::too_many_arguments)]
fn prepare_add_plan(
    project_dir: &Path,
    config_path: &Path,
    mut config: PhantomConfig,
    config_before: Vec<u8>,
    vault: &dyn VaultBackend,
    name: &str,
    value: &str,
) -> Result<AddPlan> {
    let vault_names = vault.list().context("Failed to list protected secrets")?;
    if vault_names.iter().any(|existing| existing == name) {
        anyhow::bail!(
            "Secret '{name}' became protected during add preflight; refusing replacement"
        );
    }
    let resolved =
        phantom_core::managed_dotenv::resolve_dotenv(project_dir, &config, &vault_names)?;
    let env_path = resolved.path;
    let env_before = snapshot_regular_file(&env_path)?;
    let env_after = rewrite_dotenv(env_before.as_deref(), name)?;
    let before = snapshot_secret(vault, name)?;
    if before.is_some() {
        anyhow::bail!(
            "Secret '{name}' became protected during add preflight; refusing replacement"
        );
    }

    let mutation = InitSecret::replace_if_unchanged(name, None::<String>, value);
    let config_after = if config.phantom.dotenv_path.is_none() && vault_names.is_empty() {
        config.phantom.dotenv_path = Some(
            phantom_core::managed_dotenv::dotenv_basename(project_dir, &env_path)
                .context("Failed to persist the managed dotenv mapping")?,
        );
        toml::to_string_pretty(&config)
            .context("Failed to serialize managed dotenv configuration")?
            .into_bytes()
    } else {
        config_before.clone()
    };
    // Even when no config field changes, the exact no-op replacement keeps
    // config identity/lifecycle policy inside the same transaction boundary.
    let mut files = vec![InitFile::replace_if_unchanged(
        config_path,
        Some(config_before),
        config_after,
    )];
    files.push(InitFile::replace_if_unchanged(&env_path, env_before, env_after).commit_last());
    Ok(AddPlan {
        mutation,
        files,
        env_path,
    })
}

pub(super) fn validate_secret_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    if !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        anyhow::bail!(
            "Invalid secret name: expected an environment key matching [A-Za-z_][A-Za-z0-9_]*"
        );
    }
    Ok(())
}

/// No `.phantom.toml` exists at the path [`load_config_exact`] was given.
#[derive(Debug)]
struct NotInitialized;

impl std::fmt::Display for NotInitialized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Project is not initialized. Run `phantom init --empty` first.")
    }
}

impl std::error::Error for NotInitialized {}

/// The config at `path` and its exact bytes, read only as a regular,
/// non-symlink file (see [`crate::util::load_config_if_present`]).
pub(super) fn load_config_exact(path: &Path) -> Result<(PhantomConfig, Vec<u8>)> {
    let before = crate::util::read_config_if_present(path)
        .context("Failed to load .phantom.toml")?
        .ok_or(NotInitialized)?;
    let config =
        PhantomConfig::load_from_bytes(path, &before).context("Failed to load .phantom.toml")?;
    if crate::util::read_config_if_present(path)
        .context("Failed to recheck .phantom.toml")?
        .as_deref()
        != Some(before.as_slice())
    {
        anyhow::bail!(".phantom.toml changed during preflight; no secret was read or stored");
    }
    Ok((config, before))
}

pub(super) fn snapshot_secret(
    vault: &dyn VaultBackend,
    name: &str,
) -> Result<Option<Zeroizing<String>>> {
    match vault.retrieve(name) {
        Ok(value) => Ok(Some(value)),
        Err(PhantomError::SecretNotFound(_)) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "Failed to snapshot destination secret '{name}': {error}"
        )),
    }
}

pub(super) fn snapshot_regular_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            anyhow::bail!(
                "Refusing {}: target must be a regular, non-symlink file or absent",
                path.display()
            )
        }
        Ok(_) => Ok(Some(std::fs::read(path).with_context(|| {
            format!("Failed to snapshot {}", path.display())
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

pub(super) fn rewrite_dotenv(before: Option<&[u8]>, name: &str) -> Result<Vec<u8>> {
    let content = Zeroizing::new(match before {
        Some(bytes) => String::from_utf8(bytes.to_vec())
            .context("Managed dotenv is not valid UTF-8; refusing to rewrite it")?,
        None => String::new(),
    });
    let dotenv = DotenvFile::parse_str(content.as_str());
    dotenv
        .validate_for_mutation()
        .context("Managed dotenv is malformed; no vault, config, or file mutation was prepared")?;
    let mut tokens = TokenMap::new();
    tokens.insert(name.to_string());
    let (rewritten, mut originals) = dotenv
        .upsert_with_phantoms(&tokens)
        .context("Managed dotenv cannot be rewritten safely")?;
    for original in originals.values_mut() {
        original.zeroize();
    }
    originals.clear();
    let mut after = Zeroizing::new(rewritten);
    Ok(std::mem::take(&mut *after).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::error::Result as PhantomResult;
    use phantom_vault::file::FileVault;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    struct AmbiguousCasVault {
        inner: FileVault,
        calls: AtomicUsize,
    }

    impl VaultBackend for AmbiguousCasVault {
        fn store(&self, name: &str, value: &str) -> PhantomResult<()> {
            self.inner.store(name, value)
        }
        fn retrieve(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            self.inner.retrieve(name)
        }
        fn delete(&self, name: &str) -> PhantomResult<()> {
            self.inner.delete(name)
        }
        fn compare_and_swap(
            &self,
            name: &str,
            expected: Option<&str>,
            replacement: Option<&str>,
        ) -> PhantomResult<bool> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                let _ = self.inner.compare_and_swap(name, expected, replacement)?;
                return Err(PhantomError::VaultError(
                    "injected ambiguous CAS failure".to_string(),
                ));
            }
            self.inner.compare_and_swap(name, expected, replacement)
        }
        fn list(&self) -> PhantomResult<Vec<String>> {
            self.inner.list()
        }
        fn backend_name(&self) -> &str {
            "ambiguous-cas"
        }
    }

    fn initialized(dir: &TempDir) -> (PathBuf, PhantomConfig, Vec<u8>, FileVault) {
        let project = dir.path().canonicalize().unwrap();
        let config_path = project.join(".phantom.toml");
        PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(&project))
            .save(&config_path)
            .unwrap();
        let (config, before) = load_config_exact(&config_path).unwrap();
        let vault = FileVault::new(
            &crate::test_support::canonical_tempdir_path(dir),
            "add-test",
            "passphrase".to_string(),
        )
        .unwrap();
        (config_path, config, before, vault)
    }

    /// Beside an encrypted-file vault this process cannot open, the vault is
    /// the OS keychain: add read the name as absent and would store it there,
    /// beside the copy in the locked file.
    #[cfg(unix)]
    #[test]
    fn add_beside_a_locked_file_vault_refuses_before_reading_a_value() {
        use crate::util::test_seam::{empty_keychain, keychain_with_one, LockedProject};
        for (make, lead) in [
            (
                empty_keychain as crate::util::test_seam::MakeVault,
                "Vault locked:",
            ),
            (
                keychain_with_one,
                "Refusing to add a secret from a partial inventory",
            ),
        ] {
            let project = LockedProject::new(make);
            let vault = crate::util::open_vault(&project.project_id).unwrap();

            let outcome = ensure_secret_absent(vault.as_ref(), &project.project_id, "NEW_KEY");

            assert!(outcome.is_err(), "absence cannot be established");
            let message = outcome.err().unwrap().to_string();
            assert!(message.starts_with(lead));
            assert!(message.contains("PHANTOM_VAULT_PASSPHRASE"));
        }
    }

    #[test]
    fn stdin_tty_check_does_not_panic() {
        let _ = stdin_is_tty();
    }

    /// Runtime-generated, credential-free fixture text so no secret-shaped
    /// literal lands in history.
    fn fixture_line(label: &str) -> String {
        format!("{label}-{:016x}", std::process::id() as u64 ^ 0x5eed_5eed)
    }

    #[test]
    fn stdin_value_keeps_every_line_of_a_multi_line_value() {
        let first = fixture_line("first");
        let middle = fixture_line("middle");
        let last = fixture_line("last");
        let piped = format!("{first}\n{middle}\r\n{last}\n");

        let value = read_stdin_value(
            std::io::Cursor::new(piped.into_bytes()),
            StdinLines::Multiline,
        )
        .unwrap();

        assert_eq!(value.as_str(), format!("{first}\n{middle}\r\n{last}"));
    }

    #[test]
    fn multi_line_stdin_value_without_a_flag_is_refused_without_echoing_input() {
        let first = fixture_line("alpha");
        let second = fixture_line("bravo");
        for piped in [
            format!("{first}\n{second}\n"),
            format!("{first}\r\n{second}"),
            format!("{first}\r{second}\r\n"),
        ] {
            let error = read_stdin_value(
                std::io::Cursor::new(piped.into_bytes()),
                StdinLines::SingleOnly,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("has 2 lines"), "{error}");
            assert!(error.contains("--multiline"), "{error}");
            assert!(error.contains("--first-line"), "{error}");
            assert!(error.contains("nothing was stored"), "{error}");
            assert!(!error.contains("alpha-"), "refusal must not echo input");
            assert!(!error.contains("bravo-"), "refusal must not echo input");
        }
    }

    #[test]
    fn first_line_flag_stores_only_the_first_line() {
        let first = fixture_line("first");
        let metadata = fixture_line("login");
        for piped in [
            format!("{first}\n{metadata}\nurl: {metadata}\n"),
            format!("{first}\r\n{metadata}\r\n"),
        ] {
            let value = read_stdin_value(
                std::io::Cursor::new(piped.into_bytes()),
                StdinLines::FirstLine,
            )
            .unwrap();
            assert_eq!(value.as_str(), first);
        }
        // A single line is unaffected by either flag.
        for lines in [StdinLines::FirstLine, StdinLines::Multiline] {
            let value = read_stdin_value(
                std::io::Cursor::new(format!("{first}\n").into_bytes()),
                lines,
            )
            .unwrap();
            assert_eq!(value.as_str(), first);
        }
    }

    /// `std::io::repeat` that panics if asked for bytes past the cap, so the
    /// test fails (instead of hanging) if the reader is not bounded.
    struct EndlessProducer {
        inner: std::io::Repeat,
        served: usize,
    }

    impl std::io::Read for EndlessProducer {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                self.served <= MAX_STDIN_VALUE_BYTES,
                "stdin was read past the {MAX_STDIN_VALUE_BYTES}-byte cap"
            );
            let read = self.inner.read(buf)?;
            self.served += read;
            Ok(read)
        }
    }

    #[test]
    fn endless_stdin_producer_is_cut_off_at_the_cap() {
        let producer = EndlessProducer {
            inner: std::io::repeat(b'a'),
            served: 0,
        };

        let error = read_stdin_value(producer, StdinLines::Multiline)
            .unwrap_err()
            .to_string();

        assert!(error.contains("exceeds 64 KiB"), "{error}");
    }

    #[test]
    fn stdin_value_drops_only_trailing_line_endings() {
        let line = fixture_line("single");
        for piped in [
            line.clone(),
            format!("{line}\n"),
            format!("{line}\r\n"),
            format!("{line}\n\n"),
        ] {
            let value = read_stdin_value(
                std::io::Cursor::new(piped.into_bytes()),
                StdinLines::SingleOnly,
            )
            .unwrap();
            assert_eq!(value.as_str(), line);
        }
        for piped in ["", "\n", "\r\n\n"] {
            let error = read_stdin_value(
                std::io::Cursor::new(piped.as_bytes().to_vec()),
                StdinLines::SingleOnly,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("empty value"), "{error}");
        }
    }

    #[test]
    fn stdin_value_over_the_cap_is_refused_without_echoing_input() {
        let marker = b'q';
        let oversized = vec![marker; MAX_STDIN_VALUE_BYTES + 1];

        let error = read_stdin_value(std::io::Cursor::new(oversized), StdinLines::SingleOnly)
            .unwrap_err()
            .to_string();

        assert!(error.contains("exceeds 64 KiB"), "{error}");
        assert!(!error.contains("qqqq"), "refusal must not echo input");

        let at_cap = vec![marker; MAX_STDIN_VALUE_BYTES];
        let value = read_stdin_value(std::io::Cursor::new(at_cap), StdinLines::SingleOnly).unwrap();
        assert_eq!(value.len(), MAX_STDIN_VALUE_BYTES);
    }

    #[test]
    fn stdin_value_that_is_not_utf8_is_refused_without_echoing_input() {
        let mut piped = fixture_line("prefix").into_bytes();
        piped.extend_from_slice(&[0xff, 0xfe, b'\n']);

        let error = read_stdin_value(std::io::Cursor::new(piped), StdinLines::SingleOnly)
            .unwrap_err()
            .to_string();

        assert!(error.contains("not valid UTF-8"), "{error}");
        assert!(!error.contains("prefix-"), "refusal must not echo input");
    }

    #[test]
    fn rejects_names_that_can_inject_dotenv_lines() {
        for name in ["", "A=B", "A\nB", "../A", "1KEY"] {
            assert!(validate_secret_name(name).is_err());
        }
        assert!(validate_secret_name("API_KEY_2").is_ok());
    }

    #[test]
    fn malformed_dotenv_refuses_append_and_rewrite_plans() {
        for source in [
            b"API_KEY=plaintext\nBROKEN_RECORD\n".as_slice(),
            b"OTHER=plaintext\nBROKEN_RECORD\n".as_slice(),
        ] {
            let error = rewrite_dotenv(Some(source), "API_KEY").unwrap_err();
            assert!(error.to_string().contains("malformed"));
        }
    }

    #[test]
    fn add_validates_dotenv_before_vault_access_and_secret_input() {
        let source = include_str!("add.rs");
        let validate = source
            .find("validate_managed_dotenv_preflight(&project_dir, &config)?")
            .unwrap();
        let vault = source
            .find("phantom_vault::try_create_vault(config.local_project_id())?")
            .unwrap();
        let input = source
            .find("let value = read_secret_value(name, from_stdin, lines)?")
            .unwrap();
        assert!(validate < vault);
        assert!(validate < input);
    }

    #[test]
    fn ambiguous_first_cas_rolls_back_config_and_new_dotenv() {
        let dir = TempDir::new().unwrap();
        let (config_path, config, before, inner) = initialized(&dir);
        let project = dir.path().canonicalize().unwrap();
        let original_config = std::fs::read(&config_path).unwrap();
        let vault = AmbiguousCasVault {
            inner,
            calls: AtomicUsize::new(0),
        };
        let plan = prepare_add_plan(
            &project,
            &config_path,
            config,
            before,
            &vault,
            "API_KEY",
            "secret-value",
        )
        .unwrap();

        assert!(
            phantom_vault::commit_init(&project, &vault, vec![plan.mutation], plan.files).is_err()
        );
        assert!(matches!(
            vault.retrieve("API_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
        assert_eq!(std::fs::read(&config_path).unwrap(), original_config);
        assert!(!project.join(".env").exists());
    }

    #[test]
    fn dotenv_create_race_is_detected_before_vault_cas() {
        let dir = TempDir::new().unwrap();
        let (config_path, config, before, vault) = initialized(&dir);
        let project = dir.path().canonicalize().unwrap();
        let plan = prepare_add_plan(
            &project,
            &config_path,
            config,
            before,
            &vault,
            "API_KEY",
            "secret-value",
        )
        .unwrap();
        std::fs::write(project.join(".env"), "FOREIGN=owner\n").unwrap();

        assert!(
            phantom_vault::commit_init(&project, &vault, vec![plan.mutation], plan.files).is_err()
        );
        assert_eq!(
            std::fs::read_to_string(project.join(".env")).unwrap(),
            "FOREIGN=owner\n"
        );
        assert!(matches!(
            vault.retrieve("API_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
    }

    #[test]
    fn config_drift_aborts_before_vault_or_dotenv_mutation() {
        let dir = TempDir::new().unwrap();
        let (config_path, config, before, vault) = initialized(&dir);
        let project = dir.path().canonicalize().unwrap();
        let plan = prepare_add_plan(
            &project,
            &config_path,
            config,
            before,
            &vault,
            "API_KEY",
            "secret-value",
        )
        .unwrap();
        let mut concurrent_config = std::fs::read(&config_path).unwrap();
        concurrent_config.extend_from_slice(b"\n# concurrent owner\n");
        std::fs::write(&config_path, &concurrent_config).unwrap();

        assert!(
            phantom_vault::commit_init(&project, &vault, vec![plan.mutation], plan.files).is_err()
        );
        assert_eq!(std::fs::read(&config_path).unwrap(), concurrent_config);
        assert!(!project.join(".env").exists());
        assert!(matches!(
            vault.retrieve("API_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
    }

    #[test]
    fn plan_refuses_existing_name_without_rewriting_project_state() {
        let dir = TempDir::new().unwrap();
        let (config_path, config, before, vault) = initialized(&dir);
        let project = dir.path().canonicalize().unwrap();
        vault.store("API_KEY", "original-value").unwrap();
        let original_config = std::fs::read(&config_path).unwrap();

        let error = prepare_add_plan(
            &project,
            &config_path,
            config,
            before,
            &vault,
            "API_KEY",
            "unapproved-replacement",
        )
        .err()
        .expect("existing names must be denied");

        assert!(error.to_string().contains("refusing replacement"));
        assert_eq!(
            vault.retrieve("API_KEY").unwrap().as_str(),
            "original-value"
        );
        assert_eq!(std::fs::read(&config_path).unwrap(), original_config);
        assert!(!project.join(".env").exists());
    }
}
