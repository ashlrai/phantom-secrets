use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum EngineeringAction {
    CargoCheck {
        #[serde(skip_serializing_if = "Option::is_none")]
        package: Option<PackageName>,
        cwd: RelativeCwd,
    },
    CargoTest {
        #[serde(skip_serializing_if = "Option::is_none")]
        package: Option<PackageName>,
        #[serde(skip_serializing_if = "Option::is_none")]
        filter: Option<TestFilter>,
        cwd: RelativeCwd,
    },
    CargoClippy {
        #[serde(skip_serializing_if = "Option::is_none")]
        package: Option<PackageName>,
        cwd: RelativeCwd,
    },
    CargoFmtCheck {
        cwd: RelativeCwd,
    },
}

impl EngineeringAction {
    pub const fn required_operation(&self) -> phantom_authority::Operation {
        phantom_authority::Operation::RunEngineeringCheck
    }

    pub(crate) fn argv(&self) -> Vec<String> {
        match self {
            Self::CargoCheck { package, .. } => {
                let mut args = vec!["check".into(), "--locked".into()];
                append_package(&mut args, package);
                args
            }
            Self::CargoTest {
                package, filter, ..
            } => {
                let mut args = vec!["test".into(), "--locked".into()];
                append_package(&mut args, package);
                if let Some(filter) = filter {
                    args.push("--".into());
                    args.push(filter.0.clone());
                }
                args
            }
            Self::CargoClippy { package, .. } => {
                let mut args = vec!["clippy".into(), "--locked".into()];
                append_package(&mut args, package);
                args.extend(["--".into(), "-D".into(), "warnings".into()]);
                args
            }
            Self::CargoFmtCheck { .. } => {
                vec!["fmt".into(), "--all".into(), "--".into(), "--check".into()]
            }
        }
    }

    pub(crate) fn cwd(&self) -> &RelativeCwd {
        match self {
            Self::CargoCheck { cwd, .. }
            | Self::CargoTest { cwd, .. }
            | Self::CargoClippy { cwd, .. }
            | Self::CargoFmtCheck { cwd } => cwd,
        }
    }

    pub fn canonical_digest(&self) -> Result<String, phantom_authority::CanonicalJsonError> {
        Ok(hex::encode(sha2::Sha256::digest(
            phantom_authority::canonical_json_v1(self)?,
        )))
    }
}

fn append_package(args: &mut Vec<String>, package: &Option<PackageName>) {
    if let Some(package) = package {
        args.extend(["--package".into(), package.0.clone()]);
    } else {
        args.push("--workspace".into());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct PackageName(
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    )]
    String,
);

impl PackageName {
    pub fn parse(value: impl Into<String>) -> Result<Self, ActionError> {
        let value = value.into();
        if value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            && valid_bounded(&value, 128, |byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
            })
        {
            Ok(Self(value))
        } else {
            Err(ActionError::InvalidPackage)
        }
    }
}

impl<'de> Deserialize<'de> for PackageName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct TestFilter(
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    )]
    String,
);

impl TestFilter {
    pub fn parse(value: impl Into<String>) -> Result<Self, ActionError> {
        let value = value.into();
        if value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            && valid_bounded(&value, 128, |byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            Ok(Self(value))
        } else {
            Err(ActionError::InvalidFilter)
        }
    }
}

impl<'de> Deserialize<'de> for TestFilter {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct RelativeCwd(#[schemars(length(min = 1, max = 512))] String);

impl RelativeCwd {
    pub fn workspace_root() -> Self {
        Self(".".into())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ActionError> {
        let value = value.into();
        let path = Path::new(&value);
        if value.is_empty()
            || value.len() > 512
            || path.is_absolute()
            || (value != "."
                && path
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_))))
        {
            return Err(ActionError::InvalidCwd);
        }
        Ok(Self(value))
    }

    #[cfg(test)]
    pub(crate) fn resolve(&self, root: &Path) -> std::path::PathBuf {
        if self.0 == "." {
            root.to_path_buf()
        } else {
            root.join(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for RelativeCwd {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn valid_bounded(value: &str, max: usize, allowed: impl Fn(u8) -> bool) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(allowed)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActionError {
    #[error("invalid package name")]
    InvalidPackage,
    #[error("invalid test filter")]
    InvalidFilter,
    #[error("working directory must be a contained relative path")]
    InvalidCwd,
}

use sha2::Digest;
