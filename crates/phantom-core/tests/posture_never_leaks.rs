//! The posture ledger must never persist or emit a secret name or value.
//! Written before the store itself (red before green).

use phantom_core::posture::{PostureCounts, PostureLedger, PostureEntry};

const NAMES: &[&str] = &[
    "STRIPE_SECRET_KEY",
    "OPENAI_API_KEY",
    "zz_unique_marker_name_7f3a",
    "DATABASE_URL",
];
const VALUES: &[&str] = &["sk_live_value_marker_91c2", "postgres://user:pw_marker@h/db"];

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
fn ledger_file_and_json_never_contain_names_or_values() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(dir.path().join("posture"));
    let counts = PostureCounts::from_entries("/home/u/project-marker-a1", &entries(), true);
    assert_eq!(counts.wrapped, 2);
    assert_eq!(counts.unwrapped, 2);
    assert_eq!(counts.expiring, 1);
    assert_eq!(counts.unrotated, 1);
    assert!(counts.plaintext_env);
    ledger.record(&counts).unwrap();

    let file = std::fs::read_to_string(ledger.history_path()).unwrap();
    let json = serde_json::to_string(&ledger.load().unwrap()).unwrap();
    for haystack in [&file, &json] {
        for needle in NAMES.iter().chain(VALUES).chain(&["project-marker-a1"]) {
            assert!(!haystack.contains(needle), "leaked {needle}");
            assert!(!haystack.to_lowercase().contains(&needle.to_lowercase()));
        }
    }
}
