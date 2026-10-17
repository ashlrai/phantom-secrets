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
}
