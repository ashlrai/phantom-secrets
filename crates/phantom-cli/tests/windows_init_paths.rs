mod common;

use phantom_core::config::PhantomConfig;
use phantom_vault::{file::FileVault, VaultBackend};

#[test]
fn empty_and_dotenv_init_use_the_exact_fixture_vault() {
    for empty in [true, false] {
        let root = common::canonical_tempdir();
        let project = tempfile::Builder::new()
            .prefix("profile with spaces-ü-")
            .tempdir_in(root.path())
            .unwrap();
        let passphrase = "windows-init-paths-fixture";
        let mut command = common::phantom(&project, passphrase);
        if empty {
            command.args(["init", "--empty"]);
        } else {
            std::fs::write(
                project.path().join(".env"),
                "FIXTURE_KEY=fake-path-fixture\n",
            )
            .unwrap();
            command.args(["init", "--from", ".env"]);
        }
        command.assert().success();
        let config = PhantomConfig::load(&project.path().join(".phantom.toml")).unwrap();
        let path = common::encrypted_file(&project, config.local_project_id());
        assert!(path.starts_with(common::profile_path(project.path())));
        assert!(path.with_extension("lock").is_file());
        assert_eq!(path.is_file(), !empty);
        let base = path.parent().unwrap().parent().unwrap();
        assert!(base
            .join(format!("vault-{}.lock", config.local_project_id()))
            .is_file());
        let vault = FileVault::new(base, config.local_project_id(), passphrase.into()).unwrap();
        vault
            .store("PARENT_FIXTURE", "fake-parent-path-fixture")
            .unwrap();
        let output = common::phantom(&project, passphrase)
            .args(["list", "--json"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert!(entries
            .iter()
            .any(|entry| entry["name"] == "PARENT_FIXTURE"));
        for stream in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(stream);
            for private in [
                passphrase,
                "fake-parent-path-fixture",
                "fake-path-fixture",
                "phm_",
            ] {
                assert!(!text.contains(private));
            }
        }
        assert!(!project.path().join(".phantom/vaults").exists());
    }
}

#[cfg(windows)]
#[test]
fn profile_paths_preserve_drive_and_unc_roots() {
    use std::path::Path;
    for (verbatim, ordinary) in [
        (r"\\?\C:\profile with spaces\ü", r"C:\profile with spaces\ü"),
        (r"\\?\UNC\server\share\profile", r"\\server\share\profile"),
        (r"C:\profile", r"C:\profile"),
    ] {
        assert_eq!(
            common::profile_path(Path::new(verbatim)),
            Path::new(ordinary)
        );
    }
}
