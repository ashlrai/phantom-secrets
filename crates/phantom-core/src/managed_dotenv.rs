use crate::config::PhantomConfig;
use crate::dotenv::DotenvFile;
use crate::token::PhantomToken;
use anyhow::{Context, Result};
use std::path::{Component, Path, PathBuf};

const KNOWN_DOTENV_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.development.local",
];

#[derive(Debug)]
pub struct ResolvedDotenv {
    pub path: PathBuf,
    pub file: Option<DotenvFile>,
}

impl ResolvedDotenv {
    pub fn protected_keys(&self) -> Vec<String> {
        self.file
            .iter()
            .flat_map(DotenvFile::entries)
            .filter(|entry| PhantomToken::is_phantom_token(&entry.value))
            .map(|entry| entry.key.clone())
            .collect()
    }
}

/// Convert an init target into one repository-safe filename beside config.
pub fn dotenv_basename(project_dir: &Path, env_path: &Path) -> Result<String> {
    let parent = env_path
        .parent()
        .context("dotenv target has no parent directory")?
        .canonicalize()
        .context("Failed to resolve dotenv parent directory")?;
    let project = project_dir
        .canonicalize()
        .context("Failed to resolve Phantom project directory")?;
    if parent != project {
        anyhow::bail!("dotenv must be stored beside .phantom.toml");
    }
    validate_dotenv_basename(
        env_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("dotenv filename must be valid UTF-8")?,
    )
}

pub fn validate_dotenv_basename(name: &str) -> Result<String> {
    let mut components = Path::new(name).components();
    let single =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if !single
        || name.is_empty()
        || name.len() > 255
        || matches!(name, "." | ".." | ".phantom.toml")
        || !(name == ".env" || name.starts_with(".env.") || name.ends_with(".env"))
    {
        anyhow::bail!(
            "invalid phantom.dotenv_path: expected one safe filename beside .phantom.toml"
        );
    }
    Ok(name.to_string())
}

/// Parse the dotenv `name` in `project_dir` when it is a regular file.
/// `Ok(None)` when it does not exist; a symlink or any other non-regular file
/// is refused without being read. Messages name the file by `name`, relative to
/// the project, never by its absolute path.
///
/// The check and the read cover the same file: it is opened without following
/// a final symlink, then judged on the opened handle, so a file swapped for a
/// symlink between a separate check and open cannot be followed.
pub fn parse_regular_dotenv(project_dir: &Path, name: &str) -> Result<Option<DotenvFile>> {
    let Some(file) = open_regular_file(&project_dir.join(name), name)? else {
        return Ok(None);
    };
    read_dotenv_handle(file, name).map(Some)
}

fn refuse_non_regular(shown: &str) -> anyhow::Error {
    anyhow::anyhow!("Refusing dotenv path that is not a regular, non-symlink file: {shown}")
}

/// Open `path` read-only without following a final symlink, then confirm on
/// the opened handle (fstat, not a second path lookup) that it is a regular
/// file. `Ok(None)` when nothing is there. `shown` is the name used in errors.
fn open_regular_file(path: &Path, shown: &str) -> Result<Option<std::fs::File>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK: a FIFO swapped in must be refused, not waited on. It has
        // no effect on reading a regular file. O_NOCTTY: a terminal device
        // swapped in must not become this process's controlling terminal
        // before the handle check refuses it.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open a reparse point (symlink, junction) itself instead of its
        // target; the handle check below then refuses it.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // O_NOFOLLOW on a symlink: ELOOP on Linux and macOS, EMLINK on FreeBSD.
        #[cfg(unix)]
        Err(error) if matches!(error.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK)) => {
            return Err(refuse_non_regular(shown))
        }
        Err(error) => return Err(error).with_context(|| format!("Failed to open {shown}")),
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to inspect {shown}"))?;
    // On Windows `is_symlink()` covers every name-surrogate reparse point:
    // symlinks and junctions.
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(refuse_non_regular(shown));
    }
    #[cfg(windows)]
    if is_reparse_point(&metadata) {
        return windows_reopen_contents(&file, shown).map(Some);
    }
    Ok(Some(file))
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// A non-name-surrogate reparse file: a OneDrive/Cloud Files file (hydrated
/// files keep the tag, so a project under a synced folder is full of them), a
/// deduplicated file, an app execution alias. Opened with
/// FILE_FLAG_OPEN_REPARSE_POINT it reads as its stub, which could judge stub
/// data as clean. ReOpenFile without that flag re-opens the same file object,
/// with no new path lookup, so the filter serves the real contents. That
/// handle must still be a regular file; a failed reopen is a refusal.
#[cfg(windows)]
fn windows_reopen_contents(file: &std::fs::File, shown: &str) -> Result<std::fs::File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        ReOpenFile, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let before = crate::fs::anchored::std_file_identity(file)
        .with_context(|| format!("Failed to inspect {shown}"))?;
    // SAFETY: the handle is owned by `file` and valid for the call; the
    // returned handle, when valid, is owned by the File built from it.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(refuse_non_regular(shown)).with_context(|| {
            format!(
                "Windows could not reopen the reparse point {shown} for its contents: {}",
                std::io::Error::last_os_error()
            )
        });
    }
    let reopened = unsafe { std::fs::File::from_raw_handle(handle) };
    // The reopen must be the same file object the checks judged, as
    // fs/anchored.rs requires of its own reopens.
    let after = crate::fs::anchored::std_file_identity(&reopened)
        .with_context(|| format!("Failed to inspect {shown}"))?;
    if after != before {
        return Err(refuse_non_regular(shown))
            .with_context(|| format!("Windows reopened a different file object for {shown}"));
    }
    let metadata = reopened
        .metadata()
        .with_context(|| format!("Failed to inspect {shown}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(refuse_non_regular(shown));
    }
    Ok(reopened)
}

/// Read and parse an already-checked handle. The plaintext buffer is zeroized.
fn read_dotenv_handle(mut file: std::fs::File, shown: &str) -> Result<DotenvFile> {
    use std::io::Read;
    use zeroize::Zeroize;
    #[cfg(test)]
    tests::DOTENV_READS.with(|reads| reads.set(reads.get() + 1));
    let mut content = String::new();
    let read = file.read_to_string(&mut content);
    let parsed = read
        .map(|_| DotenvFile::parse_str(&content))
        .with_context(|| format!("Failed to read {shown}"));
    content.zeroize();
    parsed
}

/// Every dotenv name a plaintext scan judges, beyond the configured
/// `dotenv_path`. Wider than [`KNOWN_DOTENV_NAMES`], which is the set
/// `resolve_dotenv` may select a managed file from: a scan must also see the
/// files frameworks load for production and test. `phantom check` and the MCP
/// compliance `env_clean` check both scan exactly this list, so one cannot pass
/// a file the other fails.
pub const SCANNED_DOTENV_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.development.local",
    ".env.production",
    ".env.production.local",
    ".env.test",
    ".env.test.local",
];

/// The names a plaintext scan judges, whether or not they exist: each of
/// [`SCANNED_DOTENV_NAMES`], then the configured `dotenv_path` when one is set
/// and is not already among them. An invalid configured name is an error.
/// For a caller that must report each file on its own; others use
/// [`scanned_dotenv_paths`].
pub fn scanned_dotenv_names(configured: Option<&str>) -> Result<Vec<String>> {
    let mut names: Vec<String> = SCANNED_DOTENV_NAMES.iter().map(|n| n.to_string()).collect();
    if let Some(configured) = configured {
        let configured = validate_dotenv_basename(configured)?;
        if !names.contains(&configured) {
            names.push(configured);
        }
    }
    Ok(names)
}

/// The scan targets that exist: each of [`SCANNED_DOTENV_NAMES`], then the
/// configured `dotenv_path` when one is set and is not already among them. A
/// symlink, a non-regular file or an invalid configured name is an error,
/// never "absent".
pub fn scanned_dotenv_paths(project_dir: &Path, configured: Option<&str>) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for name in scanned_dotenv_names(configured)? {
        let path = project_dir.join(&name);
        // A listing only; whoever reads a listed file reads it with
        // `parse_regular_dotenv`, which re-checks on the opened handle.
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                anyhow::bail!(
                    "Refusing dotenv scan target that is not a regular, non-symlink file: {name}"
                )
            }
            Ok(_) => paths.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("Failed to inspect {name}")),
        }
    }
    Ok(paths)
}

/// The files of [`scanned_dotenv_names`] that exist, parsed. For checks that
/// must judge every file plaintext could sit in, not only the one that is
/// managed. Reads no vault.
pub fn known_regular_dotenvs(
    project_dir: &Path,
    configured: Option<&str>,
) -> Result<Vec<(PathBuf, DotenvFile)>> {
    let mut found = Vec::new();
    for name in scanned_dotenv_names(configured)? {
        if let Some(file) = parse_regular_dotenv(project_dir, &name)? {
            found.push((project_dir.join(&name), file));
        }
    }
    Ok(found)
}

fn has_tokens(dotenv: &DotenvFile) -> bool {
    dotenv
        .entries()
        .iter()
        .any(|entry| PhantomToken::is_phantom_token(&entry.value))
}

/// Resolve a managed dotenv. Repository config cannot escape the config
/// directory. Legacy configs may select exactly one token-bearing conventional
/// dotenv; protected state with no such file fails closed.
pub fn resolve_dotenv(
    project_dir: &Path,
    config: &PhantomConfig,
    vault_names: &[String],
) -> Result<ResolvedDotenv> {
    let protected_state = !vault_names.is_empty() || !config.phantom.secrets.is_empty();

    if let Some(configured) = config.phantom.dotenv_path.as_deref() {
        let name = validate_dotenv_basename(configured)?;
        let path = project_dir.join(&name);
        let file = parse_regular_dotenv(project_dir, &name)?
            .ok_or_else(|| anyhow::anyhow!("Configured protected dotenv does not exist: {name}"))?;
        if protected_state && !has_tokens(&file) {
            anyhow::bail!(
                "Protected vault/config state exists, but {name} contains no phantom tokens; refusing an unprotected direct launch"
            );
        }
        return Ok(ResolvedDotenv {
            path,
            file: Some(file),
        });
    }

    let mut existing = Vec::new();
    let mut token_bearing = Vec::new();
    for name in KNOWN_DOTENV_NAMES {
        let path = project_dir.join(name);
        if let Some(file) = parse_regular_dotenv(project_dir, name)? {
            if has_tokens(&file) {
                token_bearing.push(existing.len());
            }
            existing.push((path, file));
        }
    }
    match token_bearing.len() {
        1 => {
            // Reuse the copy already read and judged; a second read could see
            // a different file.
            let (path, file) = existing.swap_remove(token_bearing[0]);
            return Ok(ResolvedDotenv {
                path,
                file: Some(file),
            });
        }
        count if count > 1 => anyhow::bail!(
            "Legacy config has {count} token-bearing dotenv files; rerun `phantom init --from <file>` to persist one explicit filename"
        ),
        _ => {}
    }
    if protected_state {
        anyhow::bail!(
            "Protected vault/config state exists, but no token-bearing dotenv file could be resolved; refusing an unprotected direct launch. Rerun `phantom init --from <file>` to persist the protected filename"
        );
    }
    let (path, file) = existing
        .into_iter()
        .next()
        .map(|(path, file)| (path, Some(file)))
        .unwrap_or_else(|| (project_dir.join(".env"), None));
    Ok(ResolvedDotenv { path, file })
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// Dotenv handles read on this thread; tests count reads with it.
        pub(super) static DOTENV_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    #[test]
    fn rejects_repository_controlled_path_traversal() {
        for bad in [
            "../.env",
            "nested/.env",
            "/tmp/.env",
            ".phantom.toml",
            "README.md",
        ] {
            assert!(validate_dotenv_basename(bad).is_err(), "accepted {bad}");
        }
        assert_eq!(
            validate_dotenv_basename("custom.env").unwrap(),
            "custom.env"
        );
    }

    #[test]
    fn protected_state_without_tokens_never_selects_direct_launch() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "OPENAI_API_KEY=plaintext\n").unwrap();
        let config = PhantomConfig::new_with_defaults("a".repeat(64));
        let error = resolve_dotenv(dir.path(), &config, &["default/OPENAI_API_KEY".into()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing an unprotected direct launch"));
    }

    #[test]
    fn known_regular_dotenvs_lists_every_conventional_and_configured_file() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            ".env.local",
            ".env.production",
            ".env.test.local",
            "custom.env",
            ".env.example",
        ] {
            std::fs::write(dir.path().join(name), "PORT=3000\n").unwrap();
        }
        let names = |configured| {
            known_regular_dotenvs(dir.path(), configured)
                .unwrap()
                .into_iter()
                .map(|(path, _)| path.file_name().unwrap().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        // Templates are not dotenvs a process loads; only the configured file
        // joins the scanned names.
        let scanned = vec![".env.local", ".env.production", ".env.test.local"];
        assert_eq!(names(None), scanned);
        let mut with_custom = scanned.clone();
        with_custom.push("custom.env");
        assert_eq!(names(Some("custom.env")), with_custom);
        assert_eq!(names(Some(".env.local")), scanned);
        // The scan list is wider than what resolve_dotenv may select from.
        for name in KNOWN_DOTENV_NAMES {
            assert!(SCANNED_DOTENV_NAMES.contains(name), "{name}");
        }
        assert!(known_regular_dotenvs(dir.path(), Some("../.env")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn known_regular_dotenvs_refuses_a_symlink_rather_than_skipping_it() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target"), "A=1\n").unwrap();
        symlink("target", dir.path().join(".env.development")).unwrap();
        assert!(known_regular_dotenvs(dir.path(), None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_dotenv() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target"), "A=1\n").unwrap();
        symlink("target", dir.path().join(".env")).unwrap();
        let message = format!(
            "{:#}",
            parse_regular_dotenv(dir.path(), ".env").unwrap_err()
        );
        assert!(message.contains("non-symlink"), "{message}");
        // Named relative to the project, never by absolute path.
        assert!(message.ends_with(": .env"), "{message}");
        assert!(
            !message.contains(&*dir.path().to_string_lossy()),
            "{message}"
        );
    }

    /// The refusal comes from the open itself (O_NOFOLLOW), not from a
    /// separate path lookup that a swap could slip past.
    #[cfg(unix)]
    #[test]
    fn open_refuses_a_symlink_without_a_prior_lookup() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target"), "A=1\n").unwrap();
        symlink("target", dir.path().join(".env")).unwrap();
        let error = open_regular_file(&dir.path().join(".env"), ".env").unwrap_err();
        assert!(error.to_string().contains("non-symlink"), "{error:#}");
    }

    /// A FIFO is refused on the opened handle (fstat), without blocking for a
    /// writer.
    #[cfg(unix)]
    #[test]
    fn open_refuses_a_fifo_on_the_handle_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join(".env");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: c_path is a valid NUL-terminated path for the call's duration.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let error = open_regular_file(&fifo, ".env").unwrap_err();
        assert!(error.to_string().contains("non-symlink"), "{error:#}");
    }

    /// Once checked, the handle is what is read: replacing the path with a
    /// symlink afterwards cannot redirect the read to the symlink's target.
    #[cfg(unix)]
    #[test]
    fn a_swap_after_the_check_does_not_change_what_is_read() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "CHECKED=1\n").unwrap();
        std::fs::write(dir.path().join("elsewhere"), "SWAPPED_IN=1\n").unwrap();
        let file = open_regular_file(&path, ".env").unwrap().unwrap();
        std::fs::remove_file(&path).unwrap();
        symlink("elsewhere", &path).unwrap();
        let parsed = read_dotenv_handle(file, ".env").unwrap();
        let keys: Vec<&str> = parsed.entries().iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, vec!["CHECKED"]);
    }

    /// Windows: a reparse point opened as itself is caught by the attribute
    /// check, not only by `is_symlink()`, and a plain file is not.
    #[cfg(windows)]
    #[test]
    fn windows_reparse_attribute_is_refused_and_plain_files_are_not() {
        use std::io::Read;
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join(".env.local");
        std::fs::write(&plain, "A=1\n").unwrap();
        let plain_meta = std::fs::File::open(&plain).unwrap().metadata().unwrap();
        assert!(!is_reparse_point(&plain_meta));
        assert!(parse_regular_dotenv(dir.path(), ".env.local")
            .unwrap()
            .is_some());

        // The reopen path: ReOpenFile on a handle opened with
        // FILE_FLAG_OPEN_REPARSE_POINT gives a regular-file handle that reads
        // the real contents. A non-name-surrogate reparse file (a Cloud Files
        // placeholder) cannot be created on a CI runner without a sync
        // provider, so the reopen itself is driven on a plain file here.
        let flagged = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(&plain)
            .unwrap();
        let mut reopened = windows_reopen_contents(&flagged, ".env.local").unwrap();
        let mut content = String::new();
        reopened.read_to_string(&mut content).unwrap();
        assert_eq!(content, "A=1\n");

        std::fs::write(dir.path().join("target"), "A=1\n").unwrap();
        // File symlinks need the create-symlink privilege (admin or Developer
        // Mode). CI runners have it; skip rather than fail where it is absent.
        if std::os::windows::fs::symlink_file("target", dir.path().join(".env")).is_err() {
            eprintln!("skipping: cannot create a file symlink here");
            return;
        }
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let link_meta = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir.path().join(".env"))
            .unwrap()
            .metadata()
            .unwrap();
        assert!(is_reparse_point(&link_meta));
        let message = format!(
            "{:#}",
            parse_regular_dotenv(dir.path(), ".env").unwrap_err()
        );
        assert!(message.contains("non-symlink file: .env"), "{message}");
    }

    #[test]
    fn resolve_reuses_the_single_token_bearing_read() {
        let dir = tempfile::tempdir().unwrap();
        let token = PhantomToken::generate();
        std::fs::write(dir.path().join(".env"), "PORT=1\n").unwrap();
        std::fs::write(
            dir.path().join(".env.local"),
            format!("OPENAI_API_KEY={}\n", token.as_str()),
        )
        .unwrap();
        let config = PhantomConfig::new_with_defaults("resolve-reuse".to_string());
        DOTENV_READS.with(|reads| reads.set(0));
        let resolved = resolve_dotenv(dir.path(), &config, &[]).unwrap();
        // One read per existing file; a second read of the token-bearing
        // file would make this 3.
        assert_eq!(DOTENV_READS.with(|reads| reads.get()), 2);
        assert_eq!(resolved.path, dir.path().join(".env.local"));
        assert_eq!(
            resolved.protected_keys(),
            vec!["OPENAI_API_KEY".to_string()]
        );
    }

    #[test]
    fn resolve_messages_name_the_configured_file_relatively() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = PhantomConfig::new_with_defaults("resolve-rel".to_string());
        config.phantom.dotenv_path = Some("custom.env".to_string());
        let missing = format!(
            "{:#}",
            resolve_dotenv(dir.path(), &config, &[]).unwrap_err()
        );
        assert!(missing.ends_with("does not exist: custom.env"), "{missing}");

        std::fs::write(dir.path().join("custom.env"), "PORT=1\n").unwrap();
        let names = vec!["OPENAI_API_KEY".to_string()];
        let unprotected = format!(
            "{:#}",
            resolve_dotenv(dir.path(), &config, &names).unwrap_err()
        );
        assert!(
            unprotected.contains("but custom.env contains"),
            "{unprotected}"
        );
        assert!(
            !unprotected.contains(&*dir.path().to_string_lossy()),
            "{unprotected}"
        );
    }

    #[test]
    fn parse_regular_dotenv_reads_a_regular_file_and_reports_absence() {
        let dir = tempfile::tempdir().unwrap();
        assert!(parse_regular_dotenv(dir.path(), ".env").unwrap().is_none());
        std::fs::write(dir.path().join(".env"), "A=1\n").unwrap();
        let parsed = parse_regular_dotenv(dir.path(), ".env").unwrap().unwrap();
        assert_eq!(parsed.entries().len(), 1);
    }
}
