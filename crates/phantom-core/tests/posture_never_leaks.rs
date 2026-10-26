//! The posture ledger must never persist or emit a secret name, value,
//! project path, remote URL (or its userinfo), or host key material, and its
//! errors must not carry a path.

use phantom_core::posture::{
    project_id, repo_identity, PostureCounts, PostureEntry, PostureLedger,
};

const NAMES: &[&str] = &[
    "STRIPE_SECRET_KEY",
    "OPENAI_API_KEY",
    "zz_unique_marker_name_7f3a",
    "DATABASE_URL",
];
const REMOTE: &str = "https://x-access-token:tok_marker_55d1@github.com/acme/widget-marker.git";
const ROOT: &str = "/home/u/project-marker-a1";

fn entries() -> Vec<PostureEntry> {
    (0..NAMES.len())
        .map(|i| PostureEntry {
            wrapped: i % 2 == 0,
            expiring: i == 1,
            unrotated: i == 3,
        })
        .collect()
}

#[test]
fn ledger_file_json_and_errors_never_contain_names_paths_remotes_or_key() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(dir.path().join("posture"));
    let key = ledger.host_key().unwrap();
    let identity = repo_identity(Some(REMOTE), std::path::Path::new(ROOT));
    assert_eq!(identity, "acme/widget-marker");
    let counts = PostureCounts::from_entries(project_id(&key, &identity), &key, &entries(), 3);
    assert_eq!(
        (
            counts.wrapped,
            counts.unwrapped,
            counts.expiring,
            counts.unrotated,
            counts.plaintext_env
        ),
        (2, 2, 1, 1, 3)
    );
    ledger.record(&counts).unwrap();

    let file = std::fs::read_to_string(ledger.history_path()).unwrap();
    let json = serde_json::to_string(&ledger.load().unwrap()).unwrap();
    let key_hex = hex::encode(std::fs::read(ledger.host_key_path()).unwrap());
    let tmp = dir.path().to_string_lossy().into_owned();

    std::fs::write(ledger.history_path(), "{bad\n").unwrap();
    let err = format!(
        "{} {:?}",
        ledger.load().unwrap_err(),
        ledger.load().unwrap_err()
    );

    let mut forbidden: Vec<String> = NAMES.iter().map(|s| s.to_string()).collect();
    for s in [
        REMOTE,
        ROOT,
        "project-marker-a1",
        "tok_marker_55d1",
        "acme",
        "widget-marker",
        "github.com",
    ] {
        forbidden.push(s.into());
    }
    forbidden.push(key_hex);
    for haystack in [&file, &json] {
        assert!(haystack.contains("recorded_at") && haystack.contains("key_id"));
        for needle in &forbidden {
            assert!(
                !haystack.to_lowercase().contains(&needle.to_lowercase()),
                "leaked {needle}"
            );
        }
        assert!(!haystack.contains(&tmp));
    }
    assert!(
        !err.contains(&tmp) && !err.contains("posture/"),
        "path in error: {err}"
    );
}
