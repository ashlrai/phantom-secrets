use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

const ID_HEX_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind}: expected {prefix} followed by {hex_len} lowercase hex characters")]
pub struct IdParseError {
    kind: &'static str,
    prefix: &'static str,
    hex_len: usize,
}

fn valid_prefixed_hex(value: &str, prefix: &str, hex_len: usize) -> bool {
    value.len() == prefix.len() + hex_len
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

macro_rules! opaque_id {
    ($name:ident, $kind:literal, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;
            pub const HEX_LEN: usize = ID_HEX_LEN;

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if valid_prefixed_hex(value, Self::PREFIX, Self::HEX_LEN) {
                    Ok(Self(value.to_owned()))
                } else {
                    Err(IdParseError {
                        kind: $kind,
                        prefix: Self::PREFIX,
                        hex_len: Self::HEX_LEN,
                    })
                }
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdParseError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                value.parse()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

opaque_id!(WorkspaceId, "workspace id", "wrk_");
opaque_id!(BindingId, "binding id", "bnd_");
opaque_id!(PlaceId, "place id", "plc_");
opaque_id!(VaultNamespaceId, "vault namespace id", "vlt_");
opaque_id!(InstallationId, "installation id", "ins_");
opaque_id!(SessionId, "session id", "ses_");
opaque_id!(ActionId, "action id", "act_");
opaque_id!(GrantId, "grant id", "grt_");
opaque_id!(LeaseId, "lease id", "lea_");

/// A lowercase hexadecimal SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub const HEX_LEN: usize = 64;

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Sha256Digest {
    type Err = IdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if valid_prefixed_hex(value, "", Self::HEX_LEN) {
            Ok(Self(value.to_owned()))
        } else {
            Err(IdParseError {
                kind: "sha256 digest",
                prefix: "",
                hex_len: Self::HEX_LEN,
            })
        }
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_id_parsers_accept_only_exact_lowercase_hex() {
        let good = format!("wrk_{}", "a1".repeat(16));
        assert_eq!(good.parse::<WorkspaceId>().unwrap().as_str(), good);

        for bad in [
            format!("wrk_{}", "A1".repeat(16)),
            format!("wrk_{}", "a1".repeat(15)),
            format!("bnd_{}", "a1".repeat(16)),
            format!("wrk_{}g", "a1".repeat(15)),
        ] {
            assert!(bad.parse::<WorkspaceId>().is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn every_public_id_has_the_same_fixed_entropy_width() {
        macro_rules! assert_id {
            ($ty:ty, $prefix:literal) => {{
                let raw = format!("{}{}", $prefix, "01".repeat(16));
                let parsed = raw.parse::<$ty>().unwrap();
                assert_eq!(parsed.to_string(), raw);
            }};
        }

        assert_id!(WorkspaceId, "wrk_");
        assert_id!(BindingId, "bnd_");
        assert_id!(PlaceId, "plc_");
        assert_id!(VaultNamespaceId, "vlt_");
        assert_id!(InstallationId, "ins_");
        assert_id!(SessionId, "ses_");
        assert_id!(ActionId, "act_");
        assert_id!(GrantId, "grt_");
        assert_id!(LeaseId, "lea_");
    }

    #[test]
    fn digest_is_exact_lowercase_sha256_shape() {
        assert!("ab".repeat(32).parse::<Sha256Digest>().is_ok());
        assert!("AB".repeat(32).parse::<Sha256Digest>().is_err());
        assert!("ab".repeat(31).parse::<Sha256Digest>().is_err());
    }
}
