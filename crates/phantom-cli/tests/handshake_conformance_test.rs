//! Offline conformance against the byte-identical ashlr-stack v1 contract.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, path::Path, process::Command};

const CONTRACT: &str = include_str!("contract/ashlr-handshake.v1.json");
const PIN: &str = "1f6679138a048f6882eb33f84ab2894b54e51898f887a5cb9c19cc9731c5c171";
const KEBAB: &str = "^[a-z0-9]+(-[a-z0-9]+)*$";
const SEMVER: &str = "^[0-9]+\\.[0-9]+\\.[0-9]+([-+][0-9A-Za-z.+-]+)?$";

fn matches(pattern: &str, s: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    match pattern {
        KEBAB => {
            !s.is_empty()
                && s.split('-').all(|p| {
                    !p.is_empty()
                        && p.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                })
        }
        SEMVER => {
            let (core, suffix) = s
                .find(['-', '+'])
                .map_or((s, None), |i| (&s[..i], Some(&s[i + 1..])));
            core.split('.').count() == 3
                && core.split('.').all(digits)
                && suffix.is_none_or(|p| {
                    !p.is_empty()
                        && p.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
                })
        }
        _ => panic!("unrecognized contract pattern"),
    }
}

fn conforms(h: &Value, c: &Value) -> bool {
    let integer = |v: &Value| v.is_i64() || v.is_u64();
    for (key, rule) in c["fields"].as_object().unwrap() {
        for constraint in rule.as_object().unwrap().keys() {
            assert!(
                [
                    "type",
                    "const",
                    "pattern",
                    "values",
                    "required_keys",
                    "items",
                    "unique",
                    "not_prefix"
                ]
                .contains(&constraint.as_str()),
                "unrecognized contract constraint"
            );
        }
        let Some(v) = h.get(key) else { return false };
        let valid_type = match rule["type"].as_str().unwrap() {
            "string" => v.is_string(),
            "integer" => integer(v),
            "object" => v.is_object(),
            "array" => v.is_array(),
            _ => panic!("unrecognized contract type"),
        };
        if !valid_type || rule.get("const").is_some_and(|expected| v != expected) {
            return false;
        }
        if let Some(s) = v.as_str() {
            if rule["pattern"].as_str().is_some_and(|p| !matches(p, s)) {
                return false;
            }
        }
        if let Some(o) = v.as_object() {
            if let Some(kind) = rule.get("values") {
                assert_eq!(kind, "integer", "unrecognized contract value type");
                if !o.values().all(integer) {
                    return false;
                }
            }
            if rule["required_keys"]
                .as_array()
                .is_some_and(|keys| keys.iter().any(|k| !o.contains_key(k.as_str().unwrap())))
            {
                return false;
            }
        }
        if let Some(a) = v.as_array() {
            assert_eq!(rule["items"], "string", "unrecognized contract item type");
            let mut seen = HashSet::new();
            for item in a {
                let Some(s) = item.as_str() else { return false };
                if rule["pattern"].as_str().is_some_and(|p| !matches(p, s))
                    || rule["not_prefix"]
                        .as_str()
                        .is_some_and(|p| s.starts_with(p))
                    || (rule["unique"] == true && !seen.insert(s))
                {
                    return false;
                }
            }
        }
    }
    let health = &h["health"];
    let rules = &c["health"];
    for constraint in rules.as_object().unwrap().keys() {
        assert!(
            [
                "status",
                "check_id_pattern",
                "check_status",
                "missing_means_not_ok"
            ]
            .contains(&constraint.as_str()),
            "unrecognized health constraint"
        );
    }
    let Some(checks) = health["checks"].as_array() else {
        return false;
    };
    rules["status"]
        .as_array()
        .unwrap()
        .contains(&health["status"])
        && checks.iter().all(|check| {
            check["id"]
                .as_str()
                .is_some_and(|s| matches(rules["check_id_pattern"].as_str().unwrap(), s))
                && rules["check_status"]
                    .as_array()
                    .unwrap()
                    .contains(&check["status"])
        })
        && !(rules["missing_means_not_ok"] == true
            && health["status"] == "ok"
            && checks.iter().any(|check| check["status"] == "missing"))
        && h["protocols"]["ashlr.handshake"] == c["schema_version"]
}

fn handshake(home: &Path, cwd: &Path, args: &[&str]) -> Value {
    // Keep coverage instrumentation writes outside the no-side-effects probe.
    let profile = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_phantom"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env(
            "LLVM_PROFILE_FILE",
            profile.path().join("phantom-%p.profraw"),
        )
        .env(
            "HANDSHAKE_TEST_PRIVATE_NAME",
            "handshake-test-private-value",
        )
        .current_dir(cwd)
        .output()
        .unwrap();
    // Do not print captured streams: regressions could contain private data.
    assert!(out.status.success(), "handshake failed");
    assert!(out.stderr.is_empty(), "handshake wrote diagnostics");
    for private in [
        "HANDSHAKE_TEST_PRIVATE_NAME",
        "handshake-test-private-value",
    ] {
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains(private),
            "handshake disclosed private data"
        );
    }
    serde_json::from_slice(&out.stdout).expect("handshake must emit exactly one JSON object")
}

#[test]
fn contract_pin_and_every_handshake_field_conform() {
    assert_eq!(format!("{:x}", Sha256::digest(CONTRACT.as_bytes())), PIN);
    assert_eq!(
        include_str!("contract/ashlr-handshake.v1.json.sha256")
            .split_whitespace()
            .next(),
        Some(PIN)
    );
    let c: Value = serde_json::from_str(CONTRACT).unwrap();
    assert_eq!(c["contract"], "ashlr.handshake");
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let h = handshake(home.path(), cwd.path(), &["--ashlr-handshake"]);
    assert!(conforms(&h, &c));
    assert_eq!(h["name"], "phantom-secrets");
    assert_eq!(h["command"], "phantom");
    assert_eq!(h["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(h["protocols"]["mcp"], 1);
    assert_eq!(h["protocols"]["phantom.agent.preflight"], 1);
    // No advertised capability may opt into unsupported gated behavior.
    for capability in c["gated_capabilities"].as_object().unwrap().keys() {
        assert!(!h["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == capability));
    }
    for args in [
        ["--ashlr-handshake", "--json"],
        ["--json", "--ashlr-handshake"],
        ["--verbose", "--ashlr-handshake"],
    ] {
        assert!(h == handshake(home.path(), cwd.path(), &args));
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(cwd.path()).unwrap().count(), 0);
    // Poison project and vault files: discovery must neither parse nor report them.
    std::fs::create_dir(home.path().join(".phantom")).unwrap();
    let files = [
        cwd.path().join(".env"),
        cwd.path().join(".phantom.toml"),
        home.path().join(".phantom/vault.enc"),
    ];
    for path in &files {
        std::fs::write(
            path,
            "HANDSHAKE_TEST_PRIVATE_NAME=handshake-test-private-value\n",
        )
        .unwrap();
    }
    assert!(h == handshake(home.path(), cwd.path(), &["--ashlr-handshake", "--json"]));
    for path in &files {
        assert!(
            std::fs::read(path).unwrap()
                == b"HANDSHAKE_TEST_PRIVATE_NAME=handshake-test-private-value\n"
        );
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 1);
    assert_eq!(
        std::fs::read_dir(home.path().join(".phantom"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(std::fs::read_dir(cwd.path()).unwrap().count(), 2);
}

#[test]
fn checker_rejects_drift_in_every_field_and_nested_constraint() {
    let c: Value = serde_json::from_str(CONTRACT).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let good = handshake(dir.path(), dir.path(), &["--ashlr-handshake"]);
    for key in c["fields"].as_object().unwrap().keys() {
        let mut h = good.clone();
        h.as_object_mut().unwrap().remove(key);
        assert!(!conforms(&h, &c), "missing required field accepted");
        h[key] = Value::Null;
        assert!(!conforms(&h, &c), "wrong field type accepted");
    }
    for (key, bad) in [
        ("kind", json!("other")),
        ("schema_version", json!(2)),
        ("name", json!("Phantom")),
        ("command", json!("bad--id")),
        ("version", json!("v1")),
        ("protocols", json!({})),
        ("protocols", json!({"ashlr.handshake": "1"})),
        ("protocols", json!({"ashlr.handshake": 2})),
        ("capabilities", json!(["bad_id"])),
        ("capabilities", json!(["a", "a"])),
        ("capabilities", json!([1])),
        ("health", json!({})),
        ("health", json!({"status":"ok","checks":{}})),
        ("health", json!({"status":"bad","checks":[]})),
        (
            "health",
            json!({"status":"ok","checks":[{"id":"bad_id","status":"ok"}]}),
        ),
        (
            "health",
            json!({"status":"ok","checks":[{"id":"a","status":"bad"}]}),
        ),
        (
            "health",
            json!({"status":"ok","checks":[{"id":"a","status":"missing"}]}),
        ),
        ("edits", json!(["/private"])),
        ("edits", json!([1])),
        ("receipts", json!([1])),
    ] {
        let mut h = good.clone();
        h[key] = bad;
        assert!(!conforms(&h, &c), "contract drift accepted in {key}");
    }
}
