use colored::Colorize;
use phantom_vault::VaultBackend;
use std::path::PathBuf;

/// Render a "Docs: https://phm.dev/docs/<slug>" suffix in a consistent style.
/// Use as the trailing line of a user-visible error so people can self-serve
/// the fix without context-switching to search.
pub fn docs_url(slug: &str) -> String {
    format!(
        "Docs: {}",
        format!("https://phm.dev/docs/{slug}").cyan().underline()
    )
}

/// The project directory a command works on: the current directory. Tests
/// install their own with [`test_seam::TestProject`].
pub fn project_dir() -> anyhow::Result<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = test_seam::PROJECT.with(|project| project.borrow().clone()) {
        return Ok(dir);
    }
    Ok(std::env::current_dir()?)
}

/// The error for a command that needs `.phantom.toml` in `project_dir`.
///
/// Commands work on the current directory only. When an ancestor directory
/// holds a `.phantom.toml`, the error names it so a run from a project
/// subdirectory is not told to `phantom init` a second project.
pub fn missing_config_error(project_dir: &std::path::Path) -> anyhow::Error {
    let root = project_dir
        .ancestors()
        .skip(1)
        .find(|dir| config_presence(&dir.join(".phantom.toml")) == ConfigPresence::Regular);
    match root {
        Some(root) => anyhow::anyhow!(
            "No .phantom.toml in {}. Phantom commands run from the project root; this directory is inside the project at {}. Run {} first.",
            project_dir.display(),
            root.display(),
            format!("cd {}", root.display()).cyan().bold()
        ),
        None => anyhow::anyhow!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        ),
    }
}

/// What is at a `.phantom.toml` path, judged as [`read_config_if_present`]
/// judges it, without reading it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPresence {
    /// Nothing is there.
    Absent,
    /// A regular, non-symlink file.
    Regular,
    /// Something that is refused: a symlink (dangling or not), directory,
    /// FIFO or device, or a path whose metadata cannot be read.
    NotRegular,
}

/// Classify the `.phantom.toml` at `path` without following a symlink.
///
/// Only [`ConfigPresence::Absent`] means "not initialized"; anything else
/// that exists and is not a regular file is refused by
/// [`load_project_config`], so callers must not treat it as either a
/// project or a missing config.
pub fn config_presence(path: &std::path::Path) -> ConfigPresence {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_file() => {
            ConfigPresence::Regular
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ConfigPresence::Absent,
        _ => ConfigPresence::NotRegular,
    }
}

/// Refusal for a `.phantom.toml` that is not a readable regular file. It
/// names no path: a symlink target may lie outside the project.
pub const CONFIG_NOT_REGULAR: &str =
    "Refusing .phantom.toml that is not a readable regular, non-symlink file";

/// The project's `.phantom.toml` at `path`, or `None` only when nothing
/// exists there.
///
/// A config that exists but cannot be read or parsed is an error. Callers
/// that report readiness or derive repairs from the config must not read it
/// as "not initialized": that silently swaps the managed dotenv for `./.env`
/// and drops every config-derived check.
///
/// The file is read only as a regular, non-symlink file (as `phantom check`
/// does). A symlink, dangling or not, is refused rather than followed or
/// read as absent: its target may lie outside the project and would choose
/// the managed dotenv and routes. A FIFO or device is refused before it is
/// opened, so it cannot block the command.
pub fn load_config_if_present(
    path: &std::path::Path,
) -> phantom_core::error::Result<Option<phantom_core::config::PhantomConfig>> {
    read_config_if_present(path)?
        .map(|bytes| phantom_core::config::PhantomConfig::load_from_bytes(path, &bytes))
        .transpose()
}

/// The exact bytes of the project's `.phantom.toml` at `path`, or `None`
/// only when nothing exists there. Read as [`load_config_if_present`] reads
/// it, for callers that bind a later write to this before-image.
pub fn read_config_if_present(
    path: &std::path::Path,
) -> phantom_core::error::Result<Option<Vec<u8>>> {
    phantom_core::fs::read_regular_file(path).map_err(|_| {
        phantom_core::error::PhantomError::Io(std::io::Error::other(CONFIG_NOT_REGULAR))
    })
}

/// The `.phantom.toml` in `project_dir` for a command that needs one.
///
/// Absent is [`missing_config_error`]. A config that is not a readable
/// regular, non-symlink file, or that does not parse, is an error too, never
/// "not initialized" and never followed (see [`load_config_if_present`]).
pub fn load_project_config(
    project_dir: &std::path::Path,
) -> anyhow::Result<phantom_core::config::PhantomConfig> {
    use anyhow::Context;
    load_config_if_present(&project_dir.join(".phantom.toml"))
        .context("Failed to load .phantom.toml")?
        .ok_or_else(|| missing_config_error(project_dir))
}

/// Open the vault for `project_id`. Tests install a stub backend with
/// [`test_seam::TestProject`].
pub fn open_vault(project_id: &str) -> anyhow::Result<Box<dyn VaultBackend>> {
    #[cfg(test)]
    if let Some(make) = test_seam::VAULT.with(std::cell::Cell::get) {
        return Ok(make());
    }
    Ok(phantom_vault::try_create_vault(project_id)?)
}

/// Judge an answer built from the opened vault's inventory (`listed` names).
///
/// When this process could not open the project's encrypted-file vault (no
/// `PHANTOM_VAULT_PASSPHRASE` here) it selects the OS keychain instead. An
/// empty keychain listing would then read as "no secrets", "nothing expires"
/// or "nothing to validate", so it is refused with the unlock step. A
/// non-empty keychain listing covers only the keychain; the returned note says
/// so. `Ok(None)` when the listing is the whole inventory.
pub fn inventory_guard(
    vault: &dyn VaultBackend,
    project_id: &str,
    listed: usize,
) -> anyhow::Result<Option<String>> {
    let Some(notice) = locked_vault_notice(vault, project_id) else {
        return Ok(None);
    };
    if listed == 0 {
        anyhow::bail!("{VAULT_LOCKED}, so an empty answer here would be wrong. {notice}");
    }
    Ok(Some(format!(
        "This covers only the OS keychain ({listed} secret(s)); secrets in the encrypted-file \
         vault are not included. {notice}"
    )))
}

/// Lead of every refusal caused by a locked encrypted-file vault.
pub const VAULT_LOCKED: &str =
    "Vault locked: this project's secrets are in an encrypted-file vault this process cannot open";

/// The locked-vault notice (with its unlock step) when `vault` is the OS
/// keychain this process selected beside an encrypted-file vault for
/// `project_id` that it cannot open. `None` when `vault` is that file vault
/// or no such file exists.
pub fn locked_vault_notice(vault: &dyn VaultBackend, project_id: &str) -> Option<String> {
    if vault.backend_name() == "encrypted-file" {
        return None;
    }
    phantom_vault::locked_file_vault_notice(project_id)
}

/// The error for a protected key the opened vault does not hold. Beside a
/// locked encrypted-file vault the key is most likely in that file, so the
/// error names the locked vault and the unlock step instead of claiming the
/// key has no entry. Either way the caller refuses: `missing` is the message
/// for a vault that really lacks the key, and `refusal` ends both messages.
/// `default_env` adds the `phantom add` next step, which stores the key for
/// the default environment only.
pub fn missing_protected_entry(
    vault: &dyn VaultBackend,
    project_id: &str,
    key: &str,
    missing: String,
    refusal: &str,
    default_env: bool,
) -> anyhow::Error {
    match locked_vault_notice(vault, project_id) {
        Some(notice) => anyhow::anyhow!(
            "{VAULT_LOCKED}, so protected dotenv key '{key}' cannot be read from it; {refusal}. {notice}"
        ),
        None if default_env => anyhow::anyhow!(
            "{missing}; {refusal}. Next step: store it from a trusted terminal with `phantom add {key}`, or remove {key} from the dotenv if the project no longer uses it."
        ),
        None => anyhow::anyhow!("{missing}; {refusal}"),
    }
}

/// Require that the opened vault lists `name`, judged from names only (no
/// value is read). When it does not, `missing` is the error, except beside a
/// locked encrypted-file vault: the name is most likely in that file, so the
/// error names the locked vault and the unlock step instead of claiming the
/// secret does not exist.
pub fn require_listed_secret(
    vault: &dyn VaultBackend,
    project_id: &str,
    name: &str,
    missing: impl FnOnce() -> String,
) -> anyhow::Result<()> {
    if vault.exists(name)? {
        return Ok(());
    }
    Err(missing_secret_error(vault, project_id, name, missing()))
}

/// Retrieve `name`. A name the opened vault lacks is `missing`, except beside
/// a locked encrypted-file vault, where the error names the locked vault and
/// the unlock step (see [`missing_secret_error`]). Other read errors keep
/// their cause under `missing` as context.
pub fn retrieve_secret(
    vault: &dyn VaultBackend,
    project_id: &str,
    name: &str,
    missing: impl FnOnce() -> String,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    match vault.retrieve(name) {
        Ok(value) => Ok(value),
        Err(phantom_core::error::PhantomError::SecretNotFound(_)) => {
            Err(missing_secret_error(vault, project_id, name, missing()))
        }
        Err(error) => Err(anyhow::Error::new(error).context(missing())),
    }
}

/// The error for a secret `name` the opened vault does not hold: `missing`,
/// or the locked-vault refusal when this process selected the OS keychain
/// beside an encrypted-file vault it cannot open.
pub fn missing_secret_error(
    vault: &dyn VaultBackend,
    project_id: &str,
    name: &str,
    missing: String,
) -> anyhow::Error {
    match locked_vault_notice(vault, project_id) {
        Some(notice) => anyhow::anyhow!(
            "{VAULT_LOCKED}, so secret '{name}' could not be looked up there (the OS keychain does not hold it). {notice}"
        ),
        None => anyhow::anyhow!(missing),
    }
}

/// [`inventory_guard`] for a use that must see every secret: a push that
/// replaces a remote copy with the local inventory (which would drop every
/// secret in the locked file vault), or a gate such as `expiry enforce` (which
/// would pass without judging them). A keychain-only listing is refused too.
/// `what` names the use, e.g. "push to the cloud vault".
pub fn require_complete_inventory(
    vault: &dyn VaultBackend,
    project_id: &str,
    listed: usize,
    what: &str,
) -> anyhow::Result<()> {
    if let Some(note) = inventory_guard(vault, project_id, listed)? {
        anyhow::bail!("Refusing to {what} from a partial inventory. {note}");
    }
    Ok(())
}

/// Print an [`inventory_guard`] note as a warning on stderr.
pub fn warn_inventory_note(note: Option<&str>) {
    if let Some(note) = note {
        eprintln!("{} {note}", "warn".yellow().bold());
    }
}

#[cfg(test)]
pub(crate) mod test_seam {
    use phantom_vault::VaultBackend;
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;

    pub(crate) type MakeVault = fn() -> Box<dyn VaultBackend>;

    thread_local! {
        pub(crate) static PROJECT: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
        pub(crate) static VAULT: Cell<Option<MakeVault>> = const { Cell::new(None) };
    }

    /// Point `project_dir()` and `open_vault()` at a test project and stub
    /// vault on this thread until dropped.
    pub(crate) struct TestProject;

    impl TestProject {
        pub(crate) fn install(dir: PathBuf, vault: MakeVault) -> Self {
            PROJECT.with(|project| *project.borrow_mut() = Some(dir));
            VAULT.with(|slot| slot.set(Some(vault)));
            TestProject
        }
    }

    impl Drop for TestProject {
        fn drop(&mut self) {
            PROJECT.with(|project| *project.borrow_mut() = None);
            VAULT.with(|slot| slot.set(None));
        }
    }

    /// The OS keychain this process selects when it cannot open the file
    /// vault, with nothing in it.
    pub(crate) struct EmptyKeychain;

    impl VaultBackend for EmptyKeychain {
        fn store(&self, _: &str, _: &str) -> phantom_core::error::Result<()> {
            unreachable!("inventory reads never store")
        }
        fn retrieve(&self, name: &str) -> phantom_core::error::Result<zeroize::Zeroizing<String>> {
            Err(phantom_core::error::PhantomError::SecretNotFound(
                name.to_string(),
            ))
        }
        fn delete(&self, _: &str) -> phantom_core::error::Result<()> {
            unreachable!("inventory reads never delete")
        }
        fn list(&self) -> phantom_core::error::Result<Vec<String>> {
            Ok(Vec::new())
        }
        fn backend_name(&self) -> &str {
            "keychain"
        }
    }

    /// The OS keychain holding one secret of its own.
    #[cfg(unix)]
    pub(crate) struct KeychainWithOne;

    #[cfg(unix)]
    impl VaultBackend for KeychainWithOne {
        fn store(&self, _: &str, _: &str) -> phantom_core::error::Result<()> {
            unreachable!("inventory reads never store")
        }
        fn retrieve(&self, _: &str) -> phantom_core::error::Result<zeroize::Zeroizing<String>> {
            panic!("a value was read from a keychain-only view")
        }
        fn delete(&self, _: &str) -> phantom_core::error::Result<()> {
            unreachable!("inventory reads never delete")
        }
        fn list(&self) -> phantom_core::error::Result<Vec<String>> {
            Ok(vec!["KEYCHAIN_ONLY_KEY".to_string()])
        }
        fn backend_name(&self) -> &str {
            "keychain"
        }
    }

    pub(crate) fn empty_keychain() -> Box<dyn VaultBackend> {
        Box::new(EmptyKeychain)
    }

    /// An opened encrypted-file vault holding one entry, `DEMOTED_KEY`, whose
    /// lifecycle metadata is read-only (`demoted: true`) or cannot be read
    /// (`demoted: false`). A plain `retrieve` panics: a path that propagates
    /// values must refuse from metadata alone.
    pub(crate) struct LifecycleBlockedVault {
        demoted: bool,
    }

    impl VaultBackend for LifecycleBlockedVault {
        fn store(&self, _: &str, _: &str) -> phantom_core::error::Result<()> {
            unreachable!("a refused push never stores")
        }
        fn retrieve(&self, _: &str) -> phantom_core::error::Result<zeroize::Zeroizing<String>> {
            panic!("a value was read from a lifecycle-blocked entry")
        }
        fn delete(&self, _: &str) -> phantom_core::error::Result<()> {
            unreachable!("a refused push never deletes")
        }
        fn list(&self) -> phantom_core::error::Result<Vec<String>> {
            Ok(vec!["DEMOTED_KEY".to_string()])
        }
        fn backend_name(&self) -> &str {
            "encrypted-file"
        }
        fn get_metadata(
            &self,
            _: &str,
        ) -> phantom_core::error::Result<Option<phantom_vault::SecretMetadata>> {
            if !self.demoted {
                return Err(phantom_core::error::PhantomError::VaultError(
                    "metadata unavailable".to_string(),
                ));
            }
            Ok(Some(phantom_vault::SecretMetadata {
                created_at: Some(1_800_000_000),
                vault_mode: phantom_vault::metadata::VaultMode::ReadOnly,
                ..phantom_vault::SecretMetadata::default()
            }))
        }
    }

    pub(crate) fn demoted_vault() -> Box<dyn VaultBackend> {
        Box::new(LifecycleBlockedVault { demoted: true })
    }

    pub(crate) fn metadata_unreadable_vault() -> Box<dyn VaultBackend> {
        Box::new(LifecycleBlockedVault { demoted: false })
    }

    /// An initialized project (default `.phantom.toml`) with `vault` standing
    /// in for the opened vault on this thread until dropped.
    pub(crate) struct SeamProject {
        pub(crate) dir: PathBuf,
        _project: tempfile::TempDir,
        _seam: TestProject,
    }

    impl SeamProject {
        pub(crate) fn new(vault: MakeVault) -> Self {
            let project = tempfile::tempdir().unwrap();
            let dir = project.path().canonicalize().unwrap();
            phantom_core::config::PhantomConfig::new_with_defaults(
                phantom_core::config::PhantomConfig::project_id_from_path(&dir),
            )
            .save(&dir.join(".phantom.toml"))
            .unwrap();
            let seam = TestProject::install(dir.clone(), vault);
            SeamProject {
                dir,
                _project: project,
                _seam: seam,
            }
        }
    }

    #[cfg(unix)]
    pub(crate) fn keychain_with_one() -> Box<dyn VaultBackend> {
        Box::new(KeychainWithOne)
    }

    /// An initialized project whose secret is in an encrypted-file vault this
    /// process cannot open (no `PHANTOM_VAULT_PASSPHRASE`), with `vault`
    /// standing in for the OS keychain. Holds the process environment lock
    /// and restores `HOME`, `XDG_DATA_HOME` and the passphrase on drop.
    /// Unix only: the file vault lives under `HOME` there.
    #[cfg(unix)]
    pub(crate) struct LockedProject {
        pub(crate) dir: PathBuf,
        pub(crate) project_id: String,
        _project: tempfile::TempDir,
        _home: tempfile::TempDir,
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
        _seam: TestProject,
        _guard: phantom_core::ProcessEnvGuard,
    }

    #[cfg(unix)]
    impl LockedProject {
        pub(crate) fn new(vault: MakeVault) -> Self {
            let guard = crate::test_support::ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = ["HOME", "XDG_DATA_HOME", "PHANTOM_VAULT_PASSPHRASE"]
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect();
            let home = tempfile::tempdir().unwrap();
            let project = tempfile::tempdir().unwrap();
            unsafe {
                std::env::set_var("HOME", home.path());
                std::env::remove_var("XDG_DATA_HOME");
                std::env::set_var(
                    "PHANTOM_VAULT_PASSPHRASE",
                    format!(
                        "fixture-{}",
                        phantom_core::token::PhantomToken::generate().as_str()
                    ),
                );
            }
            let dir = project.path().canonicalize().unwrap();
            let config = phantom_core::config::PhantomConfig::new_with_defaults(
                phantom_core::config::PhantomConfig::project_id_from_path(&dir),
            );
            config.save(&dir.join(".phantom.toml")).unwrap();
            let value = format!(
                "stored-{}",
                phantom_core::token::PhantomToken::generate().as_str()
            );
            phantom_vault::try_create_vault(config.local_project_id())
                .unwrap()
                .store("OPENAI_API_KEY", &value)
                .unwrap();
            unsafe { std::env::remove_var("PHANTOM_VAULT_PASSPHRASE") };
            assert!(
                phantom_vault::locked_file_vault_notice(config.local_project_id()).is_some(),
                "fixture: the file vault must read as locked"
            );
            let project_id = config.local_project_id().to_string();
            let seam = TestProject::install(dir.clone(), vault);
            LockedProject {
                dir,
                project_id,
                _project: project,
                _home: home,
                previous,
                _seam: seam,
                _guard: guard,
            }
        }
    }

    #[cfg(unix)]
    impl Drop for LockedProject {
        fn drop(&mut self) {
            for (key, value) in &self.previous {
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::test_seam::{empty_keychain, keychain_with_one, LockedProject};
    use super::*;

    /// Run `load_config_if_present` on `project/.phantom.toml` in a thread
    /// and fail instead of hanging if it blocks (a FIFO opened for reading
    /// waits for a writer).
    fn load_with_deadline(
        project: &std::path::Path,
    ) -> Result<Option<phantom_core::config::PhantomConfig>, String> {
        let path = project.join(".phantom.toml");
        let (send, receive) = std::sync::mpsc::channel();
        let target = path.clone();
        std::thread::spawn(move || {
            let outcome = load_config_if_present(&target).map_err(|error| error.to_string());
            let _ = send.send(outcome);
        });
        match receive.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(outcome) => outcome,
            Err(_) => {
                // Release the blocked reader so the test process can finish.
                drop(std::fs::OpenOptions::new().write(true).open(&path));
                panic!("load_config_if_present blocked on .phantom.toml");
            }
        }
    }

    #[test]
    fn config_loads_when_regular_and_is_none_only_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_with_deadline(dir.path()).unwrap().is_none());
        phantom_core::config::PhantomConfig::new_with_defaults("util-regular".to_string())
            .save(&dir.path().join(".phantom.toml"))
            .unwrap();
        assert!(load_with_deadline(dir.path()).unwrap().is_some());
    }

    /// A dangling `.phantom.toml` symlink used to read as "not initialized",
    /// so doctor judged `./.env` and exec/sync said "run phantom init".
    #[test]
    fn dangling_config_symlink_is_an_error_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("missing.toml", dir.path().join(".phantom.toml")).unwrap();
        let message = load_with_deadline(dir.path()).unwrap_err();
        assert!(message.contains(".phantom.toml"), "unexpected refusal text");
        assert!(message.contains("non-symlink"), "unexpected refusal text");
    }

    /// A `.phantom.toml` symlink to a file outside the project used to be
    /// followed: that file's `dotenv_path` and routes chose what exec
    /// protected, what doctor --fix repaired, and what sync pushed.
    #[test]
    fn config_symlink_outside_the_project_is_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        let mut config =
            phantom_core::config::PhantomConfig::new_with_defaults("util-outside".to_string());
        config.phantom.dotenv_path = Some("prod.env".to_string());
        config.save(&outside.path().join(".phantom.toml")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            outside.path().join(".phantom.toml"),
            dir.path().join(".phantom.toml"),
        )
        .unwrap();
        let message = load_with_deadline(dir.path()).unwrap_err();
        assert!(message.contains(".phantom.toml"), "unexpected refusal text");
        assert!(
            !message.contains(&outside.path().display().to_string()),
            "refusal names the outside path"
        );
        assert!(
            !message.contains(&dir.path().display().to_string()),
            "refusal names an absolute path"
        );
    }

    #[test]
    fn config_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(dir.path().join(".phantom.toml"))
            .status()
            .unwrap();
        assert!(status.success(), "mkfifo failed");
        let message = load_with_deadline(dir.path()).unwrap_err();
        assert!(message.contains(".phantom.toml"), "unexpected refusal text");
    }

    #[test]
    fn config_directory_is_an_error_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".phantom.toml")).unwrap();
        let message = load_with_deadline(dir.path()).unwrap_err();
        assert!(message.contains(".phantom.toml"), "unexpected refusal text");
    }

    #[test]
    fn an_empty_keychain_beside_a_locked_file_vault_is_refused() {
        let project = LockedProject::new(empty_keychain);
        let vault = open_vault("unused").unwrap();
        let config =
            phantom_core::config::PhantomConfig::load(&project.dir.join(".phantom.toml")).unwrap();
        let error = inventory_guard(vault.as_ref(), config.local_project_id(), 0).unwrap_err();
        let message = error.to_string();
        assert!(message.starts_with("Vault locked:"), "{message}");
        assert!(message.contains("PHANTOM_VAULT_PASSPHRASE"), "{message}");
    }

    #[test]
    fn a_keychain_only_listing_is_noted_and_refused_for_a_push() {
        let project = LockedProject::new(keychain_with_one);
        let vault = open_vault("unused").unwrap();
        let config =
            phantom_core::config::PhantomConfig::load(&project.dir.join(".phantom.toml")).unwrap();
        let id = config.local_project_id();
        let note = inventory_guard(vault.as_ref(), id, 1).unwrap().unwrap();
        assert!(
            note.contains("covers only the OS keychain (1 secret(s))"),
            "{note}"
        );
        let error = require_complete_inventory(vault.as_ref(), id, 1, "push to the cloud vault")
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("Refusing to push to the cloud vault from a partial inventory"),
            "{error}"
        );
    }

    /// With `PHANTOM_REQUIRE_KEYCHAIN=1` the vault is the OS keychain even
    /// when `PHANTOM_VAULT_PASSPHRASE` is set, so the file vault is never
    /// read. The passphrase used to silence the notice, and an empty keychain
    /// listing read as "no secrets".
    #[test]
    fn a_required_keychain_beside_a_file_vault_is_refused_with_a_passphrase_set() {
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(value) => unsafe { std::env::set_var("PHANTOM_REQUIRE_KEYCHAIN", value) },
                    None => unsafe { std::env::remove_var("PHANTOM_REQUIRE_KEYCHAIN") },
                }
            }
        }

        let project = LockedProject::new(empty_keychain);
        let _restore = Restore(std::env::var_os("PHANTOM_REQUIRE_KEYCHAIN"));
        unsafe {
            std::env::set_var("PHANTOM_REQUIRE_KEYCHAIN", "1");
            // Restored by `LockedProject` on drop.
            std::env::set_var(
                "PHANTOM_VAULT_PASSPHRASE",
                format!(
                    "fixture-{}",
                    phantom_core::token::PhantomToken::generate().as_str()
                ),
            );
        }
        let vault = open_vault("unused").unwrap();
        let message = inventory_guard(vault.as_ref(), &project.project_id, 0)
            .unwrap_err()
            .to_string();
        assert!(message.starts_with("Vault locked:"), "{message}");
        assert!(
            message.contains("PHANTOM_REQUIRE_KEYCHAIN is set"),
            "{message}"
        );
    }

    #[test]
    fn an_unlocked_project_passes_the_guard() {
        let _project = LockedProject::new(empty_keychain);
        let vault = open_vault("unused").unwrap();
        // Another project id has no file vault: nothing is locked for it.
        assert!(inventory_guard(vault.as_ref(), "another-project", 0)
            .unwrap()
            .is_none());
    }

    /// The ancestor search names a project root only when that root holds a
    /// regular, non-symlink `.phantom.toml`, the same file `load_project_config`
    /// would accept there. Fails on main, where `is_file()` followed an
    /// ancestor symlink and sent the user to a root whose config is refused.
    #[cfg(unix)]
    #[test]
    fn missing_config_error_ignores_a_symlinked_ancestor_config() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("phantom.toml");
        std::fs::write(&target, "[phantom]\n").unwrap();
        std::os::unix::fs::symlink(&target, root.path().join(".phantom.toml")).unwrap();
        let sub = root.path().join("sub");
        std::fs::create_dir(&sub).unwrap();

        let rendered = missing_config_error(&sub).to_string();
        assert!(!rendered.contains("inside the project"));
    }

    /// A directory named `.phantom.toml` in an ancestor is not a project root.
    #[test]
    fn missing_config_error_ignores_a_directory_ancestor_config() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".phantom.toml")).unwrap();
        let sub = root.path().join("sub");
        std::fs::create_dir(&sub).unwrap();

        let rendered = missing_config_error(&sub).to_string();
        assert!(!rendered.contains("inside the project"));
    }

    /// A regular ancestor `.phantom.toml` is still named as the project root.
    #[test]
    fn missing_config_error_names_a_regular_ancestor_config() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".phantom.toml"), "[phantom]\n").unwrap();
        let sub = root.path().join("sub");
        std::fs::create_dir(&sub).unwrap();

        let rendered = missing_config_error(&sub).to_string();
        assert!(rendered.contains("inside the project"));
    }

    /// `config_presence` agrees with `read_config_if_present`: absent is
    /// absent, a regular file is present, and anything else that exists
    /// (directory, symlink, dangling symlink) is a refusal, never absent.
    #[cfg(unix)]
    #[test]
    fn config_presence_matches_the_regular_file_reader() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".phantom.toml");
        assert_eq!(config_presence(&path), ConfigPresence::Absent);
        assert!(matches!(read_config_if_present(&path), Ok(None)));

        std::os::unix::fs::symlink(dir.path().join("absent.toml"), &path).unwrap();
        assert_eq!(config_presence(&path), ConfigPresence::NotRegular);
        assert!(read_config_if_present(&path).is_err());
        std::fs::remove_file(&path).unwrap();

        std::fs::create_dir(&path).unwrap();
        assert_eq!(config_presence(&path), ConfigPresence::NotRegular);
        assert!(read_config_if_present(&path).is_err());
        std::fs::remove_dir(&path).unwrap();

        std::fs::write(&path, "[phantom]\n").unwrap();
        assert_eq!(config_presence(&path), ConfigPresence::Regular);
        assert!(matches!(read_config_if_present(&path), Ok(Some(_))));
    }
}

/// Every command that needs the project config reads `.phantom.toml` only as
/// a regular, non-symlink file, through [`load_config_if_present`].
#[cfg(all(test, unix))]
mod config_gate_tests {
    use super::test_seam::TestProject;
    use super::CONFIG_NOT_REGULAR;
    use phantom_vault::VaultBackend;
    use std::path::{Path, PathBuf};

    /// A vault that fails the test if a command reaches it: every command
    /// here must refuse the config before it opens the vault.
    struct UnreachableVault;

    impl VaultBackend for UnreachableVault {
        fn store(&self, _: &str, _: &str) -> phantom_core::error::Result<()> {
            panic!("vault reached past a refused .phantom.toml")
        }
        fn retrieve(&self, _: &str) -> phantom_core::error::Result<zeroize::Zeroizing<String>> {
            panic!("vault reached past a refused .phantom.toml")
        }
        fn delete(&self, _: &str) -> phantom_core::error::Result<()> {
            panic!("vault reached past a refused .phantom.toml")
        }
        fn list(&self) -> phantom_core::error::Result<Vec<String>> {
            panic!("vault reached past a refused .phantom.toml")
        }
        fn backend_name(&self) -> &str {
            panic!("vault reached past a refused .phantom.toml")
        }
    }

    fn unreachable_vault() -> Box<dyn VaultBackend> {
        Box::new(UnreachableVault)
    }

    type Command = (&'static str, fn() -> anyhow::Result<()>);

    /// The commands under test, each run with `project_dir()` pointing at a
    /// project whose `.phantom.toml` is not a regular file.
    fn commands() -> Vec<Command> {
        use crate::commands::*;
        vec![
            ("list", || list::run_with_expiry(false, false, None)),
            ("reveal", || reveal::run("FIXTURE_NAME", false, false)),
            ("status --oneline", || status::run(true, false)),
            ("watch", || watch::run_with_rotate(false, false)),
            ("add", || {
                add::run(
                    "FIXTURE_NAME",
                    None,
                    true,
                    add::StdinLines::SingleOnly,
                    false,
                )
            }),
            ("expiry", || expiry::run(30, false, false, false)),
            ("expiry set", || expiry::run_set("FIXTURE_NAME", 30)),
            ("expiry enforce", || expiry::run_enforce(false, false)),
            ("expiry rotate", || expiry::run_rotate("FIXTURE_NAME")),
            ("rotate --all", || rotate::run_batch(30, false, false)),
            ("env list", env_scope::run_list),
            ("env new", || env_scope::run_new("staging")),
            ("validate", || validate::run(false, None, false)),
            ("validate schedule --status", || {
                validation_scheduler::run_schedule(None, true, false, false)
            }),
            ("validate history", || {
                validation_scheduler::run_history(None, false)
            }),
            ("grant list", || grant::list::run_list(false)),
            ("grant status", || grant::status::run_status(None, false)),
            ("grant revoke", || {
                grant::revoke::run_revoke("openai", false)
            }),
            ("leaks plan", || leaks::run_plan(0.0, false)),
        ]
    }

    /// Run `command` against `project` on a fresh thread and judge it: it
    /// must fail with the non-regular refusal, without blocking (a FIFO
    /// opened for reading waits for a writer) and without reaching the vault.
    /// `Err` names what went wrong.
    fn judge(project: &Path, command: fn() -> anyhow::Result<()>) -> Result<(), &'static str> {
        let (send, receive) = std::sync::mpsc::channel();
        let dir = project.to_path_buf();
        std::thread::spawn(move || {
            let _seam = TestProject::install(dir, unreachable_vault);
            let outcome = command().map_err(|error| format!("{error:#}"));
            let _ = send.send(outcome);
        });
        match receive.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(())) => Err("accepted it"),
            Ok(Err(message)) if message.contains(CONFIG_NOT_REGULAR) => Ok(()),
            Ok(Err(_)) => Err("failed without the non-regular refusal"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Release the blocked reader so the thread can finish.
                drop(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(project.join(".phantom.toml")),
                );
                Err("blocked on it")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err("panicked (reached the vault)")
            }
        }
    }

    fn assert_every_command_refuses(project: &Path, case: &str) {
        let failures: Vec<String> = commands()
            .into_iter()
            .filter_map(|(label, command)| {
                judge(project, command)
                    .err()
                    .map(|what| format!("{label}: {what}"))
            })
            .collect();
        assert!(
            failures.is_empty(),
            ".phantom.toml as a {case}, commands that did not refuse it:\n  {}",
            failures.join("\n  ")
        );
    }

    fn project() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap();
        (dir, path)
    }

    /// A symlink to a config outside the project used to be followed: its
    /// `dotenv_path`, services and project id chose which dotenv, vault and
    /// policy the command used.
    #[test]
    fn config_symlink_outside_the_project_is_refused_by_every_command() {
        let outside = tempfile::tempdir().unwrap();
        let mut config =
            phantom_core::config::PhantomConfig::new_with_defaults("gate-outside".to_string());
        config.phantom.dotenv_path = Some("prod.env".to_string());
        config.save(&outside.path().join(".phantom.toml")).unwrap();
        let (_dir, project) = project();
        std::os::unix::fs::symlink(
            outside.path().join(".phantom.toml"),
            project.join(".phantom.toml"),
        )
        .unwrap();
        assert_every_command_refuses(&project, "outside symlink");
    }

    /// A dangling symlink used to read as "not initialized" (or, for
    /// `leaks plan`, as the default policy).
    #[test]
    fn dangling_config_symlink_is_refused_by_every_command() {
        let (_dir, project) = project();
        std::os::unix::fs::symlink("missing.toml", project.join(".phantom.toml")).unwrap();
        assert_every_command_refuses(&project, "dangling symlink");
    }

    #[test]
    fn config_fifo_is_refused_by_every_command_without_blocking() {
        let (_dir, project) = project();
        let status = std::process::Command::new("mkfifo")
            .arg(project.join(".phantom.toml"))
            .status()
            .unwrap();
        assert!(status.success(), "mkfifo failed");
        assert_every_command_refuses(&project, "fifo");
    }

    #[test]
    fn config_directory_is_refused_by_every_command() {
        let (_dir, project) = project();
        std::fs::create_dir(project.join(".phantom.toml")).unwrap();
        assert_every_command_refuses(&project, "directory");
    }
}
