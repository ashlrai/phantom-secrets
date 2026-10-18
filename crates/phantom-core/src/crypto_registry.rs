//! Crypto-agility registry: one place that names every algorithm and format
//! tag Phantom uses, with its role, status and quantum class.
//!
//! This module is descriptive. It changes no behavior: nothing in the vault,
//! team share, audit, or session code reads it yet. Numeric ids and labels are
//! tied to the real constants (for example [`crate::blob_format`]) by tests, so
//! the table cannot drift from the code. Adding an algorithm later (an HQC KEM,
//! FN-DSA or ML-DSA signatures) means adding one row here, plus a new id in the
//! format that carries it.
//!
//! Quantum class is a statement about the math, not about any current machine:
//! public-key schemes based on elliptic curves fall to Shor's algorithm on a
//! large fault-tolerant quantum computer; 256-bit symmetric keys and hashes keep
//! a wide margin against Grover's quadratic speedup.

/// Role an algorithm plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Aead,
    Kdf,
    Mac,
    Kem,
    Signature,
}

/// Lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Used by default in this build.
    Default,
    /// Supported, chosen by the user or a flag.
    Optional,
    /// Behind a feature flag, unaudited or pre-1.0.
    Experimental,
    /// Still readable but not written by new code.
    Deprecated,
}

/// Quantum class of the underlying math.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantumClass {
    /// Broken by Shor's algorithm (elliptic curves, RSA).
    Vulnerable,
    /// Symmetric or hash based at 256 bits.
    Resistant,
    /// Classical plus post-quantum combined.
    Hybrid,
}

/// One algorithm row.
#[derive(Debug, Clone, Copy)]
pub struct Algorithm {
    /// Stable lowercase name.
    pub name: &'static str,
    pub kind: Kind,
    pub status: Status,
    pub quantum: QuantumClass,
    /// Key size in bits for symmetric algorithms, if fixed.
    pub key_bits: Option<u16>,
    /// One-byte algorithm id in the `PHMB` blob header, if it has one.
    pub blob_alg_id: Option<u8>,
    /// Wire label used in JSON shares, if it has one.
    pub wire_label: Option<&'static str>,
}

/// One format tag row.
#[derive(Debug, Clone, Copy)]
pub struct FormatTag {
    pub name: &'static str,
    /// Version byte or number carried in the format.
    pub version: u8,
    /// Leading magic bytes, if the format has them.
    pub magic: Option<[u8; 4]>,
}

/// Wire label of the experimental X-Wing share. Equal to
/// `team_crypto_pq::ALG` (checked by a test when `pq-hybrid` is enabled).
pub const WIRE_XWING_CHACHA20POLY1305: &str = "xwing-chacha20poly1305";

/// Every algorithm Phantom names today.
pub const ALGORITHMS: &[Algorithm] = &[
    Algorithm {
        name: "chacha20-poly1305",
        kind: Kind::Aead,
        status: Status::Default,
        quantum: QuantumClass::Resistant,
        key_bits: Some(256),
        blob_alg_id: Some(crate::blob_format::ALG_CHACHA20_POLY1305),
        wire_label: None,
    },
    Algorithm {
        name: "aes-256-gcm",
        kind: Kind::Aead,
        status: Status::Default,
        quantum: QuantumClass::Resistant,
        key_bits: Some(256),
        blob_alg_id: None,
        wire_label: None,
    },
    Algorithm {
        name: "argon2id",
        kind: Kind::Kdf,
        status: Status::Default,
        quantum: QuantumClass::Resistant,
        key_bits: Some(256),
        blob_alg_id: None,
        wire_label: None,
    },
    Algorithm {
        name: "hmac-sha256",
        kind: Kind::Mac,
        status: Status::Default,
        quantum: QuantumClass::Resistant,
        key_bits: Some(256),
        blob_alg_id: None,
        wire_label: None,
    },
    Algorithm {
        name: "x25519-xchacha20-poly1305",
        kind: Kind::Kem,
        status: Status::Default,
        quantum: QuantumClass::Vulnerable,
        key_bits: None,
        blob_alg_id: None,
        wire_label: None,
    },
    Algorithm {
        name: "xwing",
        kind: Kind::Kem,
        status: Status::Experimental,
        quantum: QuantumClass::Hybrid,
        key_bits: None,
        blob_alg_id: None,
        wire_label: Some(WIRE_XWING_CHACHA20POLY1305),
    },
    Algorithm {
        name: "ed25519",
        kind: Kind::Signature,
        status: Status::Default,
        quantum: QuantumClass::Vulnerable,
        key_bits: None,
        blob_alg_id: None,
        wire_label: None,
    },
];

/// Every format tag Phantom names today.
pub const FORMAT_TAGS: &[FormatTag] = &[
    FormatTag {
        name: "blob-v2",
        version: crate::blob_format::VERSION_2,
        magic: Some(crate::blob_format::MAGIC),
    },
    FormatTag {
        name: "team-share-classic-max",
        version: crate::team_crypto::SHARE_VERSION_MAX,
        magic: None,
    },
    FormatTag {
        name: "team-share-hybrid",
        version: 3,
        magic: None,
    },
];

/// Look up an algorithm by name.
pub fn by_name(name: &str) -> Option<&'static Algorithm> {
    ALGORITHMS.iter().find(|a| a.name == name)
}

/// Look up an algorithm by its `PHMB` header algorithm id.
pub fn by_blob_alg_id(id: u8) -> Option<&'static Algorithm> {
    ALGORITHMS.iter().find(|a| a.blob_alg_id == Some(id))
}

/// Look up an algorithm by its JSON wire label.
pub fn by_wire_label(label: &str) -> Option<&'static Algorithm> {
    ALGORITHMS.iter().find(|a| a.wire_label == Some(label))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn names_ids_and_labels_are_unique() {
        let names: HashSet<_> = ALGORITHMS.iter().map(|a| a.name).collect();
        assert_eq!(names.len(), ALGORITHMS.len());
        let ids: Vec<_> = ALGORITHMS.iter().filter_map(|a| a.blob_alg_id).collect();
        assert_eq!(ids.len(), ids.iter().collect::<HashSet<_>>().len());
        let labels: Vec<_> = ALGORITHMS.iter().filter_map(|a| a.wire_label).collect();
        assert_eq!(labels.len(), labels.iter().collect::<HashSet<_>>().len());
        let tags: HashSet<_> = FORMAT_TAGS.iter().map(|t| t.name).collect();
        assert_eq!(tags.len(), FORMAT_TAGS.len());
    }

    #[test]
    fn blob_header_matches_the_registry() {
        let header = crate::blob_format::header();
        let alg = by_blob_alg_id(header[5]).expect("header alg id is registered");
        assert_eq!(alg.name, "chacha20-poly1305");
        let tag = FORMAT_TAGS.iter().find(|t| t.name == "blob-v2").unwrap();
        assert_eq!(tag.version, header[4]);
        assert_eq!(
            tag.magic,
            Some([header[0], header[1], header[2], header[3]])
        );
        assert!(by_blob_alg_id(0).is_none());
        assert!(by_blob_alg_id(0xff).is_none());
    }

    #[test]
    fn symmetric_algorithms_declare_256_bit_keys() {
        for a in ALGORITHMS
            .iter()
            .filter(|a| matches!(a.kind, Kind::Aead | Kind::Mac | Kind::Kdf))
        {
            assert_eq!(a.key_bits, Some(256), "{}", a.name);
            assert_eq!(a.quantum, QuantumClass::Resistant, "{}", a.name);
        }
    }

    #[test]
    fn elliptic_curve_schemes_are_marked_vulnerable() {
        for name in ["x25519-xchacha20-poly1305", "ed25519"] {
            assert_eq!(by_name(name).unwrap().quantum, QuantumClass::Vulnerable);
        }
    }

    #[test]
    fn hybrid_is_experimental_and_not_default() {
        let a = by_name("xwing").unwrap();
        assert_eq!(a.status, Status::Experimental);
        assert_eq!(a.quantum, QuantumClass::Hybrid);
        assert!(ALGORITHMS
            .iter()
            .filter(|a| a.quantum == QuantumClass::Hybrid)
            .all(|a| a.status == Status::Experimental));
        assert_eq!(
            by_wire_label(WIRE_XWING_CHACHA20POLY1305).unwrap().name,
            "xwing"
        );
    }

    #[test]
    fn registry_text_has_no_em_dash() {
        let s = format!("{ALGORITHMS:?}{FORMAT_TAGS:?}");
        assert!(!s.contains('\u{2014}'));
    }

    #[cfg(feature = "pq-hybrid")]
    #[test]
    fn hybrid_constants_match_the_implementation() {
        assert_eq!(WIRE_XWING_CHACHA20POLY1305, crate::team_crypto_pq::ALG);
        let tag = FORMAT_TAGS
            .iter()
            .find(|t| t.name == "team-share-hybrid")
            .unwrap();
        assert_eq!(tag.version, crate::team_crypto_pq::HYBRID_SHARE_VERSION);
    }
}
