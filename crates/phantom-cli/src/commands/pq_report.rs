//! `phantom doctor --pq`: a read-only, value-free post-quantum readiness report.
//!
//! The report lists the cryptographic algorithms Phantom uses per surface and
//! whether each is quantum-vulnerable (broken by Shor's algorithm on a large
//! enough quantum computer) or resistant at its current key size. It reads no
//! vault, key, config, or network state, and prints no key material.
//!
//! The table is static and describes this build. Entries were taken from the
//! code (vault, team key share, audit log, session MAC) and are not probed at
//! runtime, except whether the experimental `pq-hybrid` feature is compiled in
//! and the key exchange groups the proxy's upstream TLS client offers, which
//! are read from the proxy's own provider config. Offering a group is not
//! negotiating it: the upstream server chooses.
//!
//! Background, not a claim about today's hardware: Shor's algorithm breaks
//! X25519 and Ed25519 given a large fault-tolerant quantum computer; Grover's
//! algorithm only gives a quadratic speedup on symmetric keys, so 256-bit keys
//! keep a wide margin. Data captured now and decrypted later is the
//! "harvest now, decrypt later" concern for anything protected only by X25519.

use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumStatus {
    /// Public-key scheme broken by Shor's algorithm (X25519, Ed25519).
    Vulnerable,
    /// Symmetric key or hash at 256 bits: Grover leaves a wide margin.
    Resistant,
}

impl QuantumStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Vulnerable => "quantum-vulnerable",
            Self::Resistant => "resistant at current key size",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Surface {
    pub surface: &'static str,
    pub algorithms: &'static str,
    pub status: QuantumStatus,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct PqHybridState {
    /// Whether the experimental feature is compiled into this build.
    pub compiled_in: bool,
    pub status: &'static str,
    pub scheme: &'static str,
    pub hosted_route: &'static str,
    pub audit_caveat: &'static str,
}

/// Key exchange groups the proxy's upstream TLS client offers, read from the
/// provider config the proxy connects with.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyTlsKeyExchange {
    /// Group names in offer order, most preferred first.
    pub offered_groups: Vec<String>,
    /// IANA code points, same order.
    pub offered_code_points: Vec<u16>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PqReport {
    pub surfaces: Vec<Surface>,
    pub proxy_tls_key_exchange: ProxyTlsKeyExchange,
    pub pq_hybrid: PqHybridState,
    pub not_assessed: Vec<&'static str>,
    pub summary: &'static str,
}

const HYBRID_GROUP: &str = "X25519MLKEM768";

/// Describe the offered groups without claiming more than the proxy tests show:
/// the hybrid group is offered (and preferred when first), and negotiated only
/// with an upstream that supports it.
pub fn proxy_tls_key_exchange(groups: &[phantom_proxy::OfferedKxGroup]) -> ProxyTlsKeyExchange {
    let offered_groups: Vec<String> = groups.iter().map(|g| g.name.clone()).collect();
    let offered_code_points = groups.iter().map(|g| g.code_point).collect();
    let list = offered_groups.join(", ");
    let summary = match offered_groups.iter().position(|g| g == HYBRID_GROUP) {
        Some(0) => format!(
            "offers {HYBRID_GROUP} first (offer order: {list}); negotiated only if the upstream supports it"
        ),
        Some(_) => format!(
            "offers {HYBRID_GROUP}, but not first (offer order: {list}); negotiated only if the upstream supports it and picks it"
        ),
        None if offered_groups.is_empty() => "offers no key exchange groups".to_string(),
        None => format!("does not offer {HYBRID_GROUP} (offer order: {list})"),
    };
    ProxyTlsKeyExchange {
        offered_groups,
        offered_code_points,
        summary,
    }
}

/// One line for `phantom doctor`.
pub fn proxy_tls_doctor_line() -> String {
    format!(
        "Proxy upstream TLS key exchange: {}",
        proxy_tls_key_exchange(&phantom_proxy::upstream_offered_key_exchange_groups()).summary
    )
}

/// Build the report for this build. `pq_hybrid_compiled` is passed in so tests
/// can cover both states.
pub fn build(pq_hybrid_compiled: bool) -> PqReport {
    build_with_groups(
        pq_hybrid_compiled,
        &phantom_proxy::upstream_offered_key_exchange_groups(),
    )
}

fn build_with_groups(
    pq_hybrid_compiled: bool,
    groups: &[phantom_proxy::OfferedKxGroup],
) -> PqReport {
    let surfaces = vec![
        Surface {
            surface: "vault at rest",
            algorithms: "ChaCha20-Poly1305 (256-bit key) with Argon2id key derivation",
            status: QuantumStatus::Resistant,
            note: "Symmetric. Strength of a passphrase-derived key still depends on the passphrase.",
        },
        Surface {
            surface: "team key share (classic)",
            algorithms: "XChaCha20-Poly1305 box over an X25519 agreement (256-bit team key)",
            status: QuantumStatus::Vulnerable,
            note: "A captured share could be opened later if X25519 is broken. The hosted key route accepts classic 32-byte keys only.",
        },
        Surface {
            surface: "audit log signatures",
            algorithms: "Ed25519 on sidecar events",
            status: QuantumStatus::Vulnerable,
            note: "Signatures could be forged if Ed25519 is broken; this threatens integrity, not secrecy.",
        },
        Surface {
            surface: "audit log chain and context",
            algorithms: "HMAC-SHA256 chain, AES-256-GCM encrypted context",
            status: QuantumStatus::Resistant,
            note: "Symmetric and hash based, 256-bit keys.",
        },
        Surface {
            surface: "session state integrity",
            algorithms: "HMAC-SHA256",
            status: QuantumStatus::Resistant,
            note: "Symmetric, 256-bit key.",
        },
    ];

    let pq_hybrid = PqHybridState {
        compiled_in: pq_hybrid_compiled,
        status: "experimental, off by default",
        scheme: "X-Wing (X25519 + ML-KEM-768) wraps the team key under ChaCha20-Poly1305. Confidentiality should hold if either X25519 or ML-KEM-768 holds.",
        hosted_route: "Local only. The hosted key route does not accept hybrid keys by default.",
        audit_caveat: "The x-wing and ml-kem crates have not been independently audited, and X-Wing is a pre-1.0 draft. Do not rely on it alone.",
    };

    PqReport {
        surfaces,
        proxy_tls_key_exchange: proxy_tls_key_exchange(groups),
        pq_hybrid,
        not_assessed: vec![
            "Proxy TLS key exchange group negotiated with each real upstream (the server chooses; not probed here)",
            "Release signatures and package registry signing (outside this binary)",
        ],
        summary: "Symmetric keys and hashes are 256-bit. Public-key parts (X25519, Ed25519) are quantum-vulnerable. No post-quantum signatures are in use. Hybrid key share is experimental and unaudited.",
    }
}

/// Print the report. Value-free: no keys, paths, or config are read.
pub fn run(json: bool) -> Result<()> {
    let report = build(phantom_core::PQ_HYBRID_COMPILED);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("Post-quantum readiness (static report for this build)\n");
    for s in &report.surfaces {
        println!("  {}: {}", s.surface, s.status.label());
        println!("    algorithms: {}", s.algorithms);
        println!("    note: {}", s.note);
    }
    println!(
        "\nproxy upstream TLS key exchange: {}",
        report.proxy_tls_key_exchange.summary
    );
    println!("\npq-hybrid: {}", report.pq_hybrid.status);
    println!(
        "  compiled into this build: {}",
        if report.pq_hybrid.compiled_in {
            "yes"
        } else {
            "no"
        }
    );
    println!("  {}", report.pq_hybrid.scheme);
    println!("  {}", report.pq_hybrid.hosted_route);
    println!("  {}", report.pq_hybrid.audit_caveat);
    println!("\nNot assessed:");
    for n in &report.not_assessed {
        println!("  - {n}");
    }
    println!("\n{}", report.summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_public_key_parts_as_vulnerable() {
        let r = build(false);
        for name in ["team key share (classic)", "audit log signatures"] {
            let s = r.surfaces.iter().find(|s| s.surface == name).unwrap();
            assert_eq!(s.status, QuantumStatus::Vulnerable, "{name}");
        }
        assert!(r
            .surfaces
            .iter()
            .any(|s| s.status == QuantumStatus::Resistant));
    }

    #[test]
    fn hybrid_is_described_as_experimental_and_unaudited() {
        let r = build(true);
        assert!(r.pq_hybrid.compiled_in);
        assert!(r.pq_hybrid.status.contains("experimental"));
        assert!(r
            .pq_hybrid
            .audit_caveat
            .contains("not been independently audited"));
        assert!(!build(false).pq_hybrid.compiled_in);
    }

    fn group(name: &str, code_point: u16) -> phantom_proxy::OfferedKxGroup {
        phantom_proxy::OfferedKxGroup {
            name: name.to_string(),
            code_point,
        }
    }

    #[test]
    fn proxy_tls_summary_comes_from_the_offered_groups() {
        let first =
            proxy_tls_key_exchange(&[group("X25519MLKEM768", 0x11ec), group("X25519", 0x001d)]);
        assert_eq!(
            first.summary,
            "offers X25519MLKEM768 first (offer order: X25519MLKEM768, X25519); negotiated only if the upstream supports it"
        );
        assert_eq!(first.offered_code_points, vec![0x11ec, 0x001d]);
        let later =
            proxy_tls_key_exchange(&[group("X25519", 0x001d), group("X25519MLKEM768", 0x11ec)]);
        assert!(later.summary.contains("but not first"), "{}", later.summary);
        let none = proxy_tls_key_exchange(&[group("X25519", 0x001d)]);
        assert_eq!(
            none.summary,
            "does not offer X25519MLKEM768 (offer order: X25519)"
        );
    }

    #[test]
    fn report_uses_the_real_proxy_provider_config() {
        let report = build(false);
        let real = phantom_proxy::upstream_offered_key_exchange_groups();
        assert_eq!(
            report.proxy_tls_key_exchange.offered_groups,
            real.iter().map(|g| g.name.clone()).collect::<Vec<_>>()
        );
        // This build uses the aws-lc-rs provider with prefer-post-quantum.
        assert_eq!(
            report
                .proxy_tls_key_exchange
                .offered_groups
                .first()
                .map(String::as_str),
            Some("X25519MLKEM768")
        );
        assert!(proxy_tls_doctor_line()
            .starts_with("Proxy upstream TLS key exchange: offers X25519MLKEM768 first"));
        let text = report.proxy_tls_key_exchange.summary.to_lowercase();
        assert!(!text.contains("negotiates x25519mlkem768 with"), "{text}");
    }

    #[test]
    fn report_text_has_no_em_dash_and_no_overclaim() {
        let json = serde_json::to_string(&build(false)).unwrap();
        assert!(!json.contains('\u{2014}'));
        assert!(!json.to_lowercase().contains("quantum-safe"));
        assert!(!json.to_lowercase().contains("unbreakable"));
    }
}
