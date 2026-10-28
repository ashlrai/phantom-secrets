use super::*;
use tempfile::tempdir;
fn mark_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }
}

#[test]
fn standalone_resolution_prefers_path_then_current_exe_sibling() {
    let tmp = tempdir().unwrap();
    let current_exe = tmp
        .path()
        .join(format!("phantom{}", std::env::consts::EXE_SUFFIX));
    let sibling = tmp
        .path()
        .join(format!("phantom-mcp{}", std::env::consts::EXE_SUFFIX));
    let path_match = tmp
        .path()
        .join(format!("path-phantom-mcp{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(&sibling, b"test").unwrap();
    std::fs::write(&path_match, b"test").unwrap();
    mark_executable(&sibling);
    mark_executable(&path_match);

    assert_eq!(
        find_mcp_binary_from(
            Some(&current_exe),
            Some(path_match.clone()),
            Some(tmp.path())
        ),
        Some(path_match)
    );
    assert_eq!(
        find_mcp_binary_from(Some(&current_exe), None, Some(tmp.path())),
        Some(sibling)
    );
}

#[test]
fn standalone_resolution_rejects_non_executable_files() {
    let tmp = tempdir().unwrap();
    let current_exe = tmp
        .path()
        .join(format!("phantom{}", std::env::consts::EXE_SUFFIX));
    let sibling = tmp
        .path()
        .join(format!("phantom-mcp{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(&sibling, b"test").unwrap();

    #[cfg(unix)]
    assert_eq!(find_mcp_binary_from(Some(&current_exe), None, None), None);

    #[cfg(not(unix))]
    assert_eq!(
        find_mcp_binary_from(Some(&current_exe), None, None),
        Some(sibling)
    );
}

#[test]
fn command_resolution_fails_closed_without_a_local_runtime() {
    let error = resolve_mcp_command(None, None).unwrap_err().to_string();
    assert!(error.contains("Phantom MCP runtime not found"));
    assert!(error.contains(&format!("releases/tag/v{}", env!("CARGO_PKG_VERSION"))));
    assert!(error.contains("will not download"));
    assert!(!error.contains("npx"));
}

#[test]
fn command_resolution_prefers_bundled_server_over_standalone() {
    let tmp = tempdir().unwrap();
    let bundled = tmp.path().join("phantom");
    let standalone = tmp.path().join("phantom-mcp");
    for path in [&bundled, &standalone] {
        std::fs::write(path, b"test").unwrap();
        mark_executable(path);
    }
    let command = resolve_mcp_command(Some(&bundled), Some(&standalone)).unwrap();
    assert_eq!(command.command, bundled.to_string_lossy());
    assert_eq!(command.args, ["mcp", "serve"]);
}

#[test]
fn command_resolution_uses_verified_standalone_when_bundled_is_missing() {
    let tmp = tempdir().unwrap();
    let standalone = tmp.path().join("phantom-mcp");
    std::fs::write(&standalone, b"test").unwrap();
    mark_executable(&standalone);
    let command =
        resolve_mcp_command(Some(&tmp.path().join("missing")), Some(&standalone)).unwrap();
    assert_eq!(command.command, standalone.to_string_lossy());
    assert!(command.args.is_empty());
}

#[test]
fn command_resolution_rejects_directories_in_both_positions() {
    let tmp = tempdir().unwrap();
    assert!(resolve_mcp_command(Some(tmp.path()), Some(tmp.path())).is_err());
}
