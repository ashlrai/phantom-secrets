//! The posture ledger must never persist or emit a secret name, value,
//! project path, remote URL (or its userinfo), or host key material.

use phantom_core::posture::{
    project_id, repo_identity, HostKey, PostureCounts, PostureEntry, PostureLedger,
};

const NAMES: &[&str] = &[
    "STRIPE_SECRET_KEY",
    "OPENAI_API_KEY",
    "zz_unique_marker_name_7f3a",
    "DATABASE_URL",
];
const VALUES: &[&str] = &[
    "sk_live_value_marker_91c2",
    "postgres://user:pw_marker@h/db",
];
const REMOTE: &str = "https://x-access-token:tok_marker_55d1@github.com/acme/widget-marker.git";
const ROOT: &str = "/home/u/project-marker-a1";

fn entries() -> Vec<PostureEntry<'static>> {
    NAMES
        .iter()
        .enumerate()
        .map(|(i, name)| PostureEntry {
            name,
            value: VALUES.get(i).copied(),
            wrapped: i % 2 == 0,
            expiring: i == 1,
            unrotated: i == 3,
        })
        .collect()
}

#[test]
fn ledger_file_and_json_never_contain_names_values_paths_remotes_or_key() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(dir.path().join("posture"));
    let key = HostKey::load_or_create(&dir.path().join("posture-host.key")).unwrap();
    let identity = repo_identity(Some(REMOTE), std::path::Path::new(ROOT));
    assert_eq!(identity, "acme/widget-marker");
    let id = project_id(&key, &identity);
    let counts = PostureCounts::from_entries(id, &entries(), 3);
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
    let key_hex = key.to_hex_for_test();
    let forbidden: Vec<&str> = NAMES
        .iter()
        .chain(VALUES)
        .chain(&[
            REMOTE,
            ROOT,
            "project-marker-a1",
            "tok_marker_55d1",
            "acme",
            "widget-marker",
            "github.com",
        ])
        .copied()
        .chain([key_hex.as_str()])
        .collect();
    for haystack in [&file, &json] {
        assert!(haystack.contains("recorded_at"));
        for needle in &forbidden {
            assert!(
                !haystack.to_lowercase().contains(&needle.to_lowercase()),
                "leaked {needle}"
            );
        }
    }
}
