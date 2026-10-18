//! `phantom crypto inventory`: a value-free list of every algorithm and format
//! tag Phantom names, taken from `phantom_core::crypto_registry`.
//!
//! It reads no vault, key, or config and needs no project. The JSON shape is
//! Phantom's own (`"kind": "phantom-crypto-inventory"`); it is not a CycloneDX
//! CBOM document.

use clap::ValueEnum;
use phantom_core::crypto_registry::{ALGORITHMS, FORMAT_TAGS};
use serde_json::{json, Value};

/// Output format for `phantom crypto inventory`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum InventoryFormat {
    Text,
    Json,
}

/// Version of the JSON shape below. Bump on a breaking change.
pub const INVENTORY_SCHEMA_VERSION: u32 = 1;

/// Format magic bytes as ASCII when every byte is a printable character,
/// otherwise as lowercase hex.
fn magic_label(magic: [u8; 4]) -> String {
    if magic.iter().all(|b| b.is_ascii_graphic()) {
        magic.iter().map(|&b| b as char).collect()
    } else {
        magic.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// The inventory as JSON.
pub fn inventory_json() -> Value {
    let algorithms: Vec<Value> = ALGORITHMS
        .iter()
        .map(|a| {
            json!({
                "name": a.name,
                "kind": a.kind.as_str(),
                "status": a.status.as_str(),
                "quantum": a.quantum.as_str(),
                "key_bits": a.key_bits,
                "blob_alg_id": a.blob_alg_id,
                "wire_label": a.wire_label,
            })
        })
        .collect();
    let formats: Vec<Value> = FORMAT_TAGS
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "version": t.version,
                "magic": t.magic.map(magic_label),
            })
        })
        .collect();
    json!({
        "kind": "phantom-crypto-inventory",
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "phantom_version": env!("CARGO_PKG_VERSION"),
        "algorithms": algorithms,
        "formats": formats,
    })
}

/// The inventory as a plain-text table.
pub fn inventory_text() -> String {
    let mut out = String::from("Algorithms\n");
    out.push_str(&format!(
        "  {:<28} {:<10} {:<13} {:<11} {}\n",
        "name", "kind", "status", "quantum", "key bits"
    ));
    for a in ALGORITHMS {
        let bits = a
            .key_bits
            .map(|b| b.to_string())
            .unwrap_or_else(|| "-".into());
        out.push_str(&format!(
            "  {:<28} {:<10} {:<13} {:<11} {}\n",
            a.name,
            a.kind.as_str(),
            a.status.as_str(),
            a.quantum.as_str(),
            bits
        ));
    }
    out.push_str("\nFormat tags\n");
    out.push_str(&format!("  {:<28} {:<8} {}\n", "name", "version", "magic"));
    for t in FORMAT_TAGS {
        let magic = t.magic.map(magic_label).unwrap_or_else(|| "-".into());
        out.push_str(&format!("  {:<28} {:<8} {}\n", t.name, t.version, magic));
    }
    out.push_str(
        "\nQuantum class describes the math: vulnerable means broken by Shor's algorithm on a large\n\
         fault-tolerant quantum computer; resistant means symmetric or hash based at 256 bits.\n",
    );
    out
}

pub fn run_inventory(format: InventoryFormat) -> anyhow::Result<()> {
    match format {
        InventoryFormat::Json => println!("{}", serde_json::to_string_pretty(&inventory_json())?),
        InventoryFormat::Text => print!("{}", inventory_text()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_lists_every_registry_row() {
        let v = inventory_json();
        assert_eq!(v["kind"], "phantom-crypto-inventory");
        assert_eq!(v["schema_version"], INVENTORY_SCHEMA_VERSION);
        assert_eq!(v["algorithms"].as_array().unwrap().len(), ALGORITHMS.len());
        assert_eq!(v["formats"].as_array().unwrap().len(), FORMAT_TAGS.len());
        let chacha = v["algorithms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["name"] == "chacha20-poly1305")
            .unwrap();
        assert_eq!(chacha["kind"], "aead");
        assert_eq!(chacha["quantum"], "resistant");
        assert_eq!(chacha["key_bits"], 256);
        assert_eq!(
            chacha["blob_alg_id"],
            phantom_core::blob_format::ALG_CHACHA20_POLY1305
        );
    }

    #[test]
    fn blob_magic_prints_as_ascii() {
        let v = inventory_json();
        let blob = v["formats"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "blob-v2")
            .unwrap();
        assert_eq!(blob["magic"], "PHMB");
        assert_eq!(magic_label([0, 1, 0xab, 0xff]), "0001abff");
    }

    #[test]
    fn text_names_every_algorithm_and_has_no_em_dash() {
        let text = inventory_text();
        for a in ALGORITHMS {
            assert!(text.contains(a.name), "{}", a.name);
        }
        for t in FORMAT_TAGS {
            assert!(text.contains(t.name), "{}", t.name);
        }
        assert!(!text.contains('\u{2014}'));
        assert!(!inventory_json().to_string().contains('\u{2014}'));
    }
}
