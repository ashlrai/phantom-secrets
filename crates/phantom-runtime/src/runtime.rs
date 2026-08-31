use crate::{CancellationToken, EngineeringAction, RelativeCwd, RevocationHandle};
use phantom_authority::{
    canonical_json_v1, ByteLimit, ExactScope, Operation, Sha256Digest, WorkspaceId,
};
use phantom_broker::{DurableReplayStore, ExecutionPermit};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

#[cfg(test)]
use std::time::Duration;

const MAX_DURATION_MS: u64 = 3_600_000;
const MAX_OUTPUT: u64 = 64 * 1024 * 1024;
const MAX_MEMORY: u64 = 16 * 1024 * 1024 * 1024;
const MAX_FILE: u64 = 4 * 1024 * 1024 * 1024;
const MAX_FILES: u64 = 1_024;
const MAX_PROCESSES: u64 = 256;

/// Opaque identity for an allowlisted executable. No production constructor is
/// exposed until executable identity can be bound by descriptor and digest.
pub struct Toolchain {
    cargo: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyV1 {
    version: u16,
    timeout_ms: u64,
    output_bytes: u64,
    memory_bytes: u64,
    file_bytes: u64,
    open_files: u64,
    processes: u64,
}

/// Internally serialized and digested policy. Callers cannot supply a digest
/// independently of the limits it is supposed to bind.
#[derive(Debug, Clone)]
pub struct ExecutionPolicy {
    manifest: PolicyV1,
}

impl ExecutionPolicy {
    pub fn conservative() -> Self {
        Self {
            manifest: PolicyV1 {
                version: 1,
                timeout_ms: 300_000,
                output_bytes: 4 * 1024 * 1024,
                memory_bytes: 2 * 1024 * 1024 * 1024,
                file_bytes: 512 * 1024 * 1024,
                open_files: 256,
                processes: 64,
            },
        }
    }

    fn validate(&self) -> Result<(), ExecutionError> {
        let p = &self.manifest;
        if p.version != 1
            || p.timeout_ms == 0
            || p.timeout_ms > MAX_DURATION_MS
            || p.output_bytes == 0
            || p.output_bytes > MAX_OUTPUT
            || p.memory_bytes == 0
            || p.memory_bytes > MAX_MEMORY
            || p.file_bytes == 0
            || p.file_bytes > MAX_FILE
            || p.open_files == 0
            || p.open_files > MAX_FILES
            || p.processes == 0
            || p.processes > MAX_PROCESSES
        {
            return Err(ExecutionError::InvalidPolicy);
        }
        Ok(())
    }

    fn digest(&self) -> Result<Sha256Digest, ExecutionError> {
        let bytes = canonical_json_v1(&self.manifest).map_err(|_| ExecutionError::InvalidPolicy)?;
        hex::encode(Sha256::digest(bytes))
            .parse()
            .map_err(|_| ExecutionError::InvalidPolicy)
    }
}

/// Opaque descriptor-owning workspace identity. A path, ID, and manifest hash
/// supplied separately are not sufficient, so no public constructor exists.
pub struct WorkspaceHandle {
    #[cfg_attr(not(test), allow(dead_code))]
    root: PathBuf,
    workspace_id: WorkspaceId,
    manifest_sha256: Sha256Digest,
}

pub struct RuntimeBuilder {
    guard: Option<DurableGuard>,
    workspace: Option<WorkspaceHandle>,
    toolchain: Option<Toolchain>,
    backend: Option<Arc<dyn ConfinementBackend>>,
    policy: ExecutionPolicy,
}

impl RuntimeBuilder {
    pub fn new(policy: ExecutionPolicy) -> Self {
        Self {
            guard: None,
            workspace: None,
            toolchain: None,
            backend: None,
            policy,
        }
    }

    pub fn with_execution_permit(
        mut self,
        permit: Box<ExecutionPermit>,
        store: Arc<DurableReplayStore>,
    ) -> Result<Self, ExecutionError> {
        let replacement = DurableGuard::new(store, *permit);
        if self.guard.is_some() {
            // Dropping both guards durably abandons both consumed uses.
            drop(replacement);
            return Err(ExecutionError::DuplicateWitness);
        }
        self.guard = Some(replacement);
        Ok(self)
    }

    pub fn with_workspace_handle(mut self, workspace: WorkspaceHandle) -> Self {
        self.workspace = Some(workspace);
        self
    }

    pub fn with_toolchain(mut self, toolchain: Toolchain) -> Self {
        self.toolchain = Some(toolchain);
        self
    }

    pub fn with_confinement_backend(mut self, backend: Arc<dyn ConfinementBackend>) -> Self {
        self.backend = Some(backend);
        self
    }

    pub fn build(self) -> Result<SupervisedRuntime, ExecutionError> {
        self.policy.validate()?;
        // Every validation error after a permit is attached abandons the
        // consumed durable use through `Drop`.
        let guard = self.guard.ok_or(ExecutionError::MissingWitness)?;
        let workspace = self
            .workspace
            .ok_or(ExecutionError::MissingWorkspaceHandle)?;
        let toolchain = self.toolchain.ok_or(ExecutionError::MissingToolchain)?;
        let backend = self.backend.ok_or(ExecutionError::MissingConfinement)?;
        backend.ensure_available()?;
        let c = guard.permit().constraints();
        if c.read_only
            || !matches!(c.network.schemes, ExactScope::Denied)
            || !matches!(c.network.hosts, ExactScope::Denied)
            || !matches!(c.network.ports, ExactScope::Denied)
            || !matches!(c.network.methods, ExactScope::Denied)
            || !matches!(c.network.path_prefixes, ExactScope::Denied)
            || !c.spend.is_forbidden()
        {
            return Err(ExecutionError::WitnessMismatch);
        }
        let response_limit = match c.uses.max_response_bytes {
            ByteLimit::Bounded { bytes } if bytes > 0 => bytes,
            _ => return Err(ExecutionError::WitnessMismatch),
        };
        let mut policy = self.policy;
        policy.manifest.output_bytes = policy.manifest.output_bytes.min(response_limit);
        if guard.permit().operation() != Operation::RunEngineeringCheck
            || guard.permit().workspace_id() != &workspace.workspace_id
            || guard.permit().workspace_manifest_sha256() != &workspace.manifest_sha256
            || guard.permit().policy_sha256() != &policy.digest()?
        {
            return Err(ExecutionError::WitnessMismatch);
        }
        let authority = RuntimeAuthority {
            action_digest: guard.permit().canonical_args_sha256().as_str().to_owned(),
            not_before: c.time.not_before,
            expires_at: c.time.expires_at,
            request_limit: c.uses.max_request_bytes,
        };
        Ok(SupervisedRuntime {
            authority,
            guard: UseGuard::Durable(Box::new(guard)),
            workspace,
            toolchain,
            backend,
            policy,
            revocation: RevocationHandle::default(),
        })
    }
}

struct RuntimeAuthority {
    action_digest: String,
    not_before: u64,
    expires_at: u64,
    request_limit: ByteLimit,
}

#[cfg_attr(not(test), allow(dead_code))]
pub struct BackendRequest<'a> {
    executable: &'a Path,
    argv: Vec<String>,
    cwd: &'a RelativeCwd,
    workspace: &'a WorkspaceHandle,
    policy: &'a ExecutionPolicy,
    not_before: u64,
    expires_at: u64,
    cancellation: &'a CancellationToken,
    revocation: &'a RevocationHandle,
}

pub type BackendFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ExecutionOutcome, ExecutionError>> + Send + 'a>>;

mod private {
    use super::*;
    pub trait Backend {
        fn ensure_available(&self) -> Result<(), ExecutionError>;
        fn execute<'a>(&'a self, request: BackendRequest<'a>) -> BackendFuture<'a>;
    }
}

/// Sealed boundary whose implementation must own trusted time, confinement,
/// spawn, cancellation, group termination, bounded drain, and reaping.
pub trait ConfinementBackend: private::Backend + Send + Sync {}
impl<T: private::Backend + Send + Sync> ConfinementBackend for T {}

#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllConfinement;

impl private::Backend for DenyAllConfinement {
    fn ensure_available(&self) -> Result<(), ExecutionError> {
        Err(ExecutionError::ConfinementUnavailable)
    }
    fn execute<'a>(&'a self, _: BackendRequest<'a>) -> BackendFuture<'a> {
        Box::pin(async { Err(ExecutionError::ConfinementUnavailable) })
    }
}

pub struct SupervisedRuntime {
    authority: RuntimeAuthority,
    guard: UseGuard,
    workspace: WorkspaceHandle,
    toolchain: Toolchain,
    backend: Arc<dyn ConfinementBackend>,
    policy: ExecutionPolicy,
    revocation: RevocationHandle,
}

impl SupervisedRuntime {
    pub fn revocation_handle(&self) -> RevocationHandle {
        self.revocation.clone()
    }

    /// A runtime is a single durable operation; execution consumes it.
    pub async fn execute(
        self,
        action: &EngineeringAction,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionOutcome, ExecutionError> {
        let result = self.execute_inner(action, cancellation).await;
        match result {
            Ok(outcome) => {
                self.guard.finish()?;
                Ok(outcome)
            }
            Err(error) => {
                self.guard.abandon()?;
                Err(error)
            }
        }
    }

    async fn execute_inner(
        &self,
        action: &EngineeringAction,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionOutcome, ExecutionError> {
        if action.required_operation() != Operation::RunEngineeringCheck
            || action
                .canonical_digest()
                .map_err(|_| ExecutionError::InvalidAction)?
                != self.authority.action_digest
        {
            return Err(ExecutionError::WitnessMismatch);
        }
        let bytes = canonical_json_v1(action)
            .map_err(|_| ExecutionError::InvalidAction)?
            .len() as u64;
        if !matches!(self.authority.request_limit, ByteLimit::Bounded { bytes: max } if bytes <= max)
        {
            return Err(ExecutionError::WitnessMismatch);
        }
        if self.revocation.is_revoked() {
            return Ok(ExecutionOutcome::empty(OutcomeKind::Revoked));
        }
        if cancellation.is_cancelled() {
            return Ok(ExecutionOutcome::empty(OutcomeKind::Cancelled));
        }
        self.backend
            .execute(BackendRequest {
                executable: &self.toolchain.cargo,
                argv: action.argv(),
                cwd: action.cwd(),
                workspace: &self.workspace,
                policy: &self.policy,
                not_before: self.authority.not_before,
                expires_at: self.authority.expires_at,
                cancellation,
                revocation: &self.revocation,
            })
            .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    Exited { success: bool, code: Option<i32> },
    TimedOut,
    Cancelled,
    Revoked,
    OutputLimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ExecutionOutcome {
    pub kind: OutcomeKind,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}
impl ExecutionOutcome {
    fn empty(kind: OutcomeKind) -> Self {
        Self {
            kind,
            stdout_bytes: 0,
            stderr_bytes: 0,
        }
    }
}

struct DurableGuard {
    store: Arc<DurableReplayStore>,
    permit: Option<ExecutionPermit>,
}
impl DurableGuard {
    fn new(store: Arc<DurableReplayStore>, permit: ExecutionPermit) -> Self {
        Self {
            store,
            permit: Some(permit),
        }
    }
    fn permit(&self) -> &ExecutionPermit {
        self.permit
            .as_ref()
            .expect("durable guard always owns its permit before terminal transition")
    }
    fn finish(mut self) -> Result<(), ExecutionError> {
        self.store
            .finish_use(self.permit.as_ref().ok_or(ExecutionError::RuntimeSetup)?)
            .map_err(|_| ExecutionError::DurableTransition)?;
        self.permit.take();
        Ok(())
    }
    fn abandon(mut self) -> Result<(), ExecutionError> {
        self.store
            .abandon_use(self.permit.as_ref().ok_or(ExecutionError::RuntimeSetup)?)
            .map_err(|_| ExecutionError::DurableTransition)?;
        self.permit.take();
        Ok(())
    }
}
impl Drop for DurableGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.permit {
            let _ = self.store.abandon_use(p);
        }
    }
}
enum UseGuard {
    Durable(Box<DurableGuard>),
    #[cfg(test)]
    Test,
}
impl UseGuard {
    fn finish(self) -> Result<(), ExecutionError> {
        match self {
            Self::Durable(g) => g.finish(),
            #[cfg(test)]
            Self::Test => Ok(()),
        }
    }
    fn abandon(self) -> Result<(), ExecutionError> {
        match self {
            Self::Durable(g) => g.abandon(),
            #[cfg(test)]
            Self::Test => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionError {
    #[error("a non-replayed durable execution permit is required")]
    MissingWitness,
    #[error("a builder cannot hold more than one durable execution permit")]
    DuplicateWitness,
    #[error("a sealed workspace handle is required")]
    MissingWorkspaceHandle,
    #[error("a sealed toolchain handle is required")]
    MissingToolchain,
    #[error("an OS confinement backend is required")]
    MissingConfinement,
    #[error("OS confinement is unavailable")]
    ConfinementUnavailable,
    #[error("permit does not bind this action, workspace, operation, or policy")]
    WitnessMismatch,
    #[error("permit is not yet active")]
    NotYetActive,
    #[error("permit has expired")]
    ExpiredWitness,
    #[error("execution policy is invalid")]
    InvalidPolicy,
    #[error("runtime action is invalid")]
    InvalidAction,
    #[error("workspace is invalid")]
    InvalidWorkspace,
    #[error("working directory escaped the workspace")]
    CwdEscape,
    #[error("runtime clock is unavailable")]
    ClockUnavailable,
    #[error("runtime setup failed")]
    RuntimeSetup,
    #[error("durable terminal state could not be persisted")]
    DurableTransition,
    #[error("child spawn failed: {0:?}")]
    SpawnFailed(std::io::ErrorKind),
    #[error("child output read failed")]
    OutputRead,
    #[error("child reap failed")]
    ReapFailed,
}

#[cfg(all(test, unix))]
mod direct {
    use super::*;
    use std::{
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        },
        process::Stdio,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt},
        process::Command,
        sync::Semaphore,
    };
    const REAP: Duration = Duration::from_secs(2);
    const DRAIN: Duration = Duration::from_millis(250);

    pub(super) struct Direct {
        pub started: Option<Arc<Semaphore>>,
    }
    impl private::Backend for Direct {
        fn ensure_available(&self) -> Result<(), ExecutionError> {
            Ok(())
        }
        fn execute<'a>(&'a self, r: BackendRequest<'a>) -> BackendFuture<'a> {
            Box::pin(async move {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| ExecutionError::ClockUnavailable)?
                    .as_secs();
                if now < r.not_before {
                    return Err(ExecutionError::NotYetActive);
                }
                if now >= r.expires_at {
                    return Err(ExecutionError::ExpiredWitness);
                }
                let timeout = Duration::from_millis(r.policy.manifest.timeout_ms)
                    .min(Duration::from_secs(r.expires_at - now));
                let cwd = open_cwd(&r.workspace.root, r.cwd)?;
                let home = tempfile::Builder::new()
                    .prefix("phantom-runtime-test-")
                    .tempdir()
                    .map_err(|_| ExecutionError::RuntimeSetup)?;
                let mut command = Command::new(r.executable);
                command
                    .args(&r.argv)
                    .env_clear()
                    .env("HOME", home.path())
                    .env("LANG", "C")
                    .env("LC_ALL", "C")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_TERMINAL_PROMPT", "0")
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                configure(&mut command, cwd, r.policy)?;
                let mut child = command
                    .spawn()
                    .map_err(|e| ExecutionError::SpawnFailed(e.kind()))?;
                let pid = child
                    .id()
                    .ok_or(ExecutionError::SpawnFailed(std::io::ErrorKind::Other))?;
                let stdout = child.stdout.take().ok_or(ExecutionError::RuntimeSetup)?;
                let stderr = child.stderr.take().ok_or(ExecutionError::RuntimeSetup)?;
                if let Some(s) = &self.started {
                    s.add_permits(1);
                }
                let total = Arc::new(AtomicU64::new(0));
                let out = Arc::new(AtomicU64::new(0));
                let err = Arc::new(AtomicU64::new(0));
                let overflow = CancellationToken::default();
                let mut ot = tokio::spawn(drain(
                    stdout,
                    out.clone(),
                    total.clone(),
                    r.policy.manifest.output_bytes,
                    overflow.clone(),
                ));
                let mut et = tokio::spawn(drain(
                    stderr,
                    err.clone(),
                    total,
                    r.policy.manifest.output_bytes,
                    overflow.clone(),
                ));
                let kind = tokio::select! { biased;
                    _ = r.revocation.revoked() => { terminate(&mut child, pid).await?; OutcomeKind::Revoked }
                    _ = r.cancellation.cancelled() => { terminate(&mut child, pid).await?; OutcomeKind::Cancelled }
                    _ = overflow.cancelled() => { terminate(&mut child, pid).await?; OutcomeKind::OutputLimitExceeded }
                    _ = tokio::time::sleep(timeout) => { terminate(&mut child, pid).await?; OutcomeKind::TimedOut }
                    status = child.wait() => { let s = status.map_err(|_| ExecutionError::ReapFailed)?; OutcomeKind::Exited { success: s.success(), code: s.code() } }
                };
                kill_group(pid);
                if tokio::time::timeout(DRAIN, async {
                    (&mut ot)
                        .await
                        .map_err(|_| ExecutionError::RuntimeSetup)??;
                    (&mut et)
                        .await
                        .map_err(|_| ExecutionError::RuntimeSetup)??;
                    Ok::<(), ExecutionError>(())
                })
                .await
                .is_err()
                {
                    ot.abort();
                    et.abort();
                    let _ = ot.await;
                    let _ = et.await;
                }
                Ok(ExecutionOutcome {
                    kind,
                    stdout_bytes: out.load(Ordering::Acquire),
                    stderr_bytes: err.load(Ordering::Acquire),
                })
            })
        }
    }

    async fn drain(
        mut reader: impl AsyncRead + Unpin,
        stream: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
        limit: u64,
        overflow: CancellationToken,
    ) -> Result<(), ExecutionError> {
        let mut buf = [0; 8192];
        loop {
            let n = reader
                .read(&mut buf)
                .await
                .map_err(|_| ExecutionError::OutputRead)?;
            if n == 0 {
                return Ok(());
            }
            let n = n as u64;
            stream
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                    Some(v.saturating_add(n))
                })
                .ok();
            let before = total
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                    Some(v.saturating_add(n))
                })
                .unwrap_or(u64::MAX);
            if before.saturating_add(n) > limit {
                overflow.cancel();
            }
        }
    }
    fn open_cwd(root: &Path, cwd: &RelativeCwd) -> Result<std::fs::File, ExecutionError> {
        use std::ffi::CString;
        let mut d = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)
            .map_err(|_| ExecutionError::InvalidWorkspace)?;
        for c in cwd
            .resolve(root)
            .strip_prefix(root)
            .map_err(|_| ExecutionError::CwdEscape)?
            .components()
        {
            let p = match c {
                std::path::Component::Normal(p) => p,
                std::path::Component::CurDir => continue,
                _ => return Err(ExecutionError::CwdEscape),
            };
            let n = CString::new(p.as_bytes()).map_err(|_| ExecutionError::CwdEscape)?;
            let fd = unsafe {
                libc::openat(
                    d.as_raw_fd(),
                    n.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(ExecutionError::CwdEscape);
            }
            d = unsafe { std::fs::File::from_raw_fd(fd) };
        }
        Ok(d)
    }
    fn configure(
        command: &mut Command,
        cwd: std::fs::File,
        p: &ExecutionPolicy,
    ) -> Result<(), ExecutionError> {
        let m = p.manifest.memory_bytes;
        let f = p.manifest.file_bytes;
        let n = p.manifest.open_files;
        let pr = p.manifest.processes;
        let cpu = (p.manifest.timeout_ms / 1000).saturating_add(1);
        unsafe {
            command.pre_exec(move || {
                if libc::fchdir(cwd.as_raw_fd()) != 0 || libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(target_os = "macos")]
                let _ = m;
                #[cfg(not(target_os = "macos"))]
                limit(libc::RLIMIT_AS, m)?;
                limit(libc::RLIMIT_FSIZE, f)?;
                limit(libc::RLIMIT_NOFILE, n)?;
                limit(libc::RLIMIT_NPROC, pr)?;
                limit(libc::RLIMIT_CPU, cpu)?;
                Ok(())
            });
        }
        Ok(())
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    type RlimitResource = libc::__rlimit_resource_t;
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    type RlimitResource = libc::c_int;

    fn limit(resource: RlimitResource, value: u64) -> std::io::Result<()> {
        let mut x = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        if unsafe { libc::getrlimit(resource as _, x.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let x = unsafe { x.assume_init() };
        let l = libc::rlimit {
            rlim_cur: (value as libc::rlim_t).min(x.rlim_max),
            rlim_max: x.rlim_max,
        };
        if unsafe { libc::setrlimit(resource as _, &l) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    fn kill_group(pid: u32) {
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
    async fn terminate(child: &mut tokio::process::Child, pid: u32) -> Result<(), ExecutionError> {
        kill_group(pid);
        let _ = child.start_kill();
        tokio::time::timeout(REAP, child.wait())
            .await
            .map_err(|_| ExecutionError::ReapFailed)?
            .map_err(|_| ExecutionError::ReapFailed)?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{direct::Direct, *};
    use crate::PackageName;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;
    use tokio::sync::Semaphore;
    fn action(cwd: RelativeCwd) -> EngineeringAction {
        EngineeringAction::CargoCheck {
            package: Some(PackageName::parse("fixture").unwrap()),
            cwd,
        }
    }
    fn fixture(body: &str) -> (TempDir, PathBuf, EngineeringAction) {
        let w = TempDir::new().unwrap();
        let p = w.path().join("cargo-fixture");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let a = action(RelativeCwd::workspace_root());
        (w, p, a)
    }
    fn runtime(
        w: &Path,
        p: &Path,
        a: &EngineeringAction,
        timeout: u64,
        output: u64,
        started: Option<Arc<Semaphore>>,
    ) -> SupervisedRuntime {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut policy = ExecutionPolicy::conservative();
        policy.manifest.timeout_ms = timeout;
        policy.manifest.output_bytes = output;
        SupervisedRuntime {
            authority: RuntimeAuthority {
                action_digest: a.canonical_digest().unwrap(),
                not_before: now - 1,
                expires_at: now + 60,
                request_limit: ByteLimit::Bounded { bytes: 16384 },
            },
            guard: UseGuard::Test,
            workspace: WorkspaceHandle {
                root: w.into(),
                workspace_id: format!("wrk_{}", "01".repeat(16)).parse().unwrap(),
                manifest_sha256: "ab".repeat(32).parse().unwrap(),
            },
            toolchain: Toolchain { cargo: p.into() },
            backend: Arc::new(Direct { started }),
            policy,
            revocation: RevocationHandle::default(),
        }
    }
    #[test]
    fn missing_permit_denied() {
        assert!(matches!(
            RuntimeBuilder::new(ExecutionPolicy::conservative()).build(),
            Err(ExecutionError::MissingWitness)
        ))
    }
    #[test]
    fn deny_all_unavailable() {
        use private::Backend;
        assert_eq!(
            DenyAllConfinement.ensure_available(),
            Err(ExecutionError::ConfinementUnavailable)
        )
    }
    #[tokio::test]
    async fn timeout() {
        let (w, p, a) = fixture("sleep 5");
        assert_eq!(
            runtime(w.path(), &p, &a, 50, 4096, None)
                .execute(&a, &CancellationToken::default())
                .await
                .unwrap()
                .kind,
            OutcomeKind::TimedOut
        )
    }
    #[tokio::test]
    async fn flood() {
        let (w, p, a) = fixture("while :; do printf 0123456789; done");
        let o = runtime(w.path(), &p, &a, 3000, 2048, None)
            .execute(&a, &CancellationToken::default())
            .await
            .unwrap();
        assert_eq!(o.kind, OutcomeKind::OutputLimitExceeded);
        assert!(o.stdout_bytes > 2048);
        assert!(!serde_json::to_string(&o).unwrap().contains("0123456789"))
    }
    #[tokio::test]
    async fn env_suppressed() {
        let (w, p, a) = fixture(
            "[ -z \"$CARGO_MANIFEST_DIR$HTTP_PROXY$HTTPS_PROXY$ALL_PROXY$NO_PROXY\" ] || exit 91",
        );
        let o = runtime(w.path(), &p, &a, 2000, 4096, None)
            .execute(&a, &CancellationToken::default())
            .await
            .unwrap();
        assert_eq!(
            o.kind,
            OutcomeKind::Exited {
                success: true,
                code: Some(0)
            }
        )
    }
    #[tokio::test]
    async fn cwd_escape() {
        let w = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), w.path().join("escape")).unwrap();
        let (_, p, _) = fixture("exit 0");
        let a = action(RelativeCwd::parse("escape").unwrap());
        assert!(matches!(
            runtime(w.path(), &p, &a, 2000, 4096, None)
                .execute(&a, &CancellationToken::default())
                .await,
            Err(ExecutionError::CwdEscape)
        ));
        assert!(RelativeCwd::parse("../x").is_err())
    }
    #[tokio::test]
    async fn cancel_deterministic() {
        let (w, p, a) = fixture("sleep 5");
        let s = Arc::new(Semaphore::new(0));
        let r = runtime(w.path(), &p, &a, 10000, 4096, Some(s.clone()));
        let c = CancellationToken::default();
        let cc = c.clone();
        let aa = a.clone();
        let t = tokio::spawn(async move { r.execute(&aa, &cc).await.unwrap() });
        s.acquire().await.unwrap().forget();
        c.cancel();
        assert_eq!(t.await.unwrap().kind, OutcomeKind::Cancelled)
    }
    #[tokio::test]
    async fn revoke_deterministic() {
        let (w, p, a) = fixture("sleep 5");
        let s = Arc::new(Semaphore::new(0));
        let r = runtime(w.path(), &p, &a, 10000, 4096, Some(s.clone()));
        let h = r.revocation_handle();
        let aa = a.clone();
        let t =
            tokio::spawn(
                async move { r.execute(&aa, &CancellationToken::default()).await.unwrap() },
            );
        s.acquire().await.unwrap().forget();
        h.revoke();
        assert_eq!(t.await.unwrap().kind, OutcomeKind::Revoked)
    }
    #[tokio::test]
    async fn descendant_drain_bounded() {
        let (w, p, a) = fixture("sleep 30 & exit 0");
        let cancellation = CancellationToken::default();
        let f = runtime(w.path(), &p, &a, 5000, 4096, None).execute(&a, &cancellation);
        assert!(tokio::time::timeout(Duration::from_secs(1), f)
            .await
            .is_ok())
    }
    #[test]
    fn closed_router() {
        assert_eq!(
            action(RelativeCwd::workspace_root()).required_operation(),
            Operation::RunEngineeringCheck
        );
        assert!(
            serde_json::from_str::<EngineeringAction>(r#"{"action":"shell","command":"x"}"#)
                .is_err()
        )
    }
}
