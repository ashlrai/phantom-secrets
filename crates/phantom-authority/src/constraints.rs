use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Options,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeConstraints {
    pub not_before: u64,
    pub expires_at: u64,
}

impl TimeConstraints {
    /// The upper boundary is exclusive: `now == expires_at` is expired.
    pub fn active_at(&self, now: u64) -> bool {
        self.not_before <= now && now < self.expires_at
    }

    fn validate(&self) -> Result<(), ConstraintError> {
        if self.not_before >= self.expires_at {
            return Err(ConstraintError::InvalidTimeWindow);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UseConstraints {
    pub capacity: UseCapacity,
    pub max_request_bytes: ByteLimit,
    pub max_response_bytes: ByteLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum UseCapacity {
    Denied,
    Bounded {
        max_uses: u32,
        max_concurrent_uses: u16,
    },
}

impl UseCapacity {
    pub fn limits(self) -> Option<(u32, u16)> {
        match self {
            Self::Denied => None,
            Self::Bounded {
                max_uses,
                max_concurrent_uses,
            } => Some((max_uses, max_concurrent_uses)),
        }
    }

    fn validate(self) -> Result<(), ConstraintError> {
        match self {
            Self::Denied => Ok(()),
            Self::Bounded { max_uses: 0, .. }
            | Self::Bounded {
                max_concurrent_uses: 0,
                ..
            } => Err(ConstraintError::InvalidUseCapacity),
            Self::Bounded { .. } => Ok(()),
        }
    }

    fn intersect(self, other: Self) -> Self {
        match (self, other) {
            (
                Self::Bounded {
                    max_uses: left_uses,
                    max_concurrent_uses: left_concurrent,
                },
                Self::Bounded {
                    max_uses: right_uses,
                    max_concurrent_uses: right_concurrent,
                },
            ) => Self::Bounded {
                max_uses: left_uses.min(right_uses),
                max_concurrent_uses: left_concurrent.min(right_concurrent),
            },
            _ => Self::Denied,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ByteLimit {
    Denied,
    Bounded { bytes: u64 },
}

impl ByteLimit {
    fn validate(self) -> Result<(), ConstraintError> {
        if matches!(self, Self::Bounded { bytes: 0 }) {
            return Err(ConstraintError::InvalidByteLimit);
        }
        Ok(())
    }

    fn intersect(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bounded { bytes: left }, Self::Bounded { bytes: right }) => Self::Bounded {
                bytes: left.min(right),
            },
            _ => Self::Denied,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "values", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ExactScope<T> {
    Denied,
    Exact(Vec<T>),
}

impl<T: Ord> ExactScope<T> {
    fn validate(&self) -> Result<(), ConstraintError> {
        match self {
            Self::Denied => Ok(()),
            Self::Exact(values) if values.is_empty() => Err(ConstraintError::EmptyExactScope),
            Self::Exact(values) => {
                let unique = values.iter().collect::<BTreeSet<_>>();
                if unique.len() != values.len() {
                    return Err(ConstraintError::DuplicateExactScope);
                }
                if values.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return Err(ConstraintError::UnsortedExactScope);
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConstraints {
    pub schemes: ExactScope<NetworkScheme>,
    pub hosts: ExactScope<String>,
    pub ports: ExactScope<u16>,
    pub methods: ExactScope<HttpMethod>,
    pub path_prefixes: ExactScope<String>,
    #[serde(default)]
    pub allow_redirects: bool,
}

impl NetworkConstraints {
    fn validate(&self) -> Result<(), ConstraintError> {
        if self.allow_redirects {
            return Err(ConstraintError::RedirectsDenied);
        }
        self.schemes.validate()?;
        self.hosts.validate()?;
        self.ports.validate()?;
        self.methods.validate()?;
        self.path_prefixes.validate()?;
        let hosts = match &self.hosts {
            ExactScope::Denied => &[][..],
            ExactScope::Exact(values) => values.as_slice(),
        };
        if hosts.iter().any(|host| {
            host.is_empty()
                || host.len() > 253
                || host != &host.to_ascii_lowercase()
                || host.contains(['/', ':', '@', '\\'])
                || !host.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                        && label
                            .as_bytes()
                            .first()
                            .is_some_and(u8::is_ascii_alphanumeric)
                        && label
                            .as_bytes()
                            .last()
                            .is_some_and(u8::is_ascii_alphanumeric)
                })
        }) {
            return Err(ConstraintError::InvalidHost);
        }
        let paths = match &self.path_prefixes {
            ExactScope::Denied => &[][..],
            ExactScope::Exact(values) => values.as_slice(),
        };
        if paths.iter().any(|path| {
            !path.starts_with('/')
                || path.len() > 2_048
                || !path.bytes().all(|byte| byte.is_ascii_graphic())
                || path.contains('?')
                || path.contains('#')
                || path.contains('\\')
                || path.contains('%')
                || path.contains("//")
                || path.split('/').any(|segment| matches!(segment, "." | ".."))
        }) {
            return Err(ConstraintError::InvalidPathPrefix);
        }
        Ok(())
    }
}

/// A zero cap with no currency means spending is forbidden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendConstraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    pub max_minor_units: u64,
}

impl SpendConstraints {
    pub fn forbidden() -> Self {
        Self {
            currency: None,
            max_minor_units: 0,
        }
    }

    pub fn is_forbidden(&self) -> bool {
        self.max_minor_units == 0
    }

    fn validate(&self) -> Result<(), ConstraintError> {
        match (&self.currency, self.max_minor_units) {
            (None, 0) => Ok(()),
            (Some(currency), amount)
                if amount > 0
                    && currency.len() == 3
                    && currency.bytes().all(|byte| byte.is_ascii_uppercase()) =>
            {
                Ok(())
            }
            _ => Err(ConstraintError::InvalidSpendCap),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConstraints {
    pub environment: String,
    pub read_only: bool,
    pub time: TimeConstraints,
    pub uses: UseConstraints,
    pub network: NetworkConstraints,
    pub spend: SpendConstraints,
}

impl AuthorityConstraints {
    pub fn validate(&self) -> Result<(), ConstraintError> {
        if self.environment.is_empty()
            || self.environment.len() > 64
            || !self
                .environment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ConstraintError::InvalidEnvironment);
        }
        self.time.validate()?;
        self.uses.capacity.validate()?;
        self.uses.max_request_bytes.validate()?;
        self.uses.max_response_bytes.validate()?;
        self.network.validate()?;
        self.spend.validate()?;
        Ok(())
    }

    /// Compute the deterministic least-authority intersection of two grants.
    ///
    /// Numeric limits take the minimum, time windows narrow, set-valued
    /// network scopes intersect, redirects require both sides, and read-only
    /// wins if either side requires it. The result can never add authority.
    pub fn intersect(&self, other: &Self) -> Result<Self, ConstraintError> {
        self.validate()?;
        other.validate()?;
        if self.environment != other.environment {
            return Err(ConstraintError::EnvironmentMismatch);
        }

        let time = TimeConstraints {
            not_before: self.time.not_before.max(other.time.not_before),
            expires_at: self.time.expires_at.min(other.time.expires_at),
        };
        time.validate()?;

        let spend = match (&self.spend.currency, &other.spend.currency) {
            (Some(left), Some(right)) if left == right => SpendConstraints {
                currency: Some(left.clone()),
                max_minor_units: self.spend.max_minor_units.min(other.spend.max_minor_units),
            },
            _ => SpendConstraints::forbidden(),
        };

        Ok(Self {
            environment: self.environment.clone(),
            read_only: self.read_only || other.read_only,
            time,
            uses: UseConstraints {
                capacity: self.uses.capacity.intersect(other.uses.capacity),
                max_request_bytes: self
                    .uses
                    .max_request_bytes
                    .intersect(other.uses.max_request_bytes),
                max_response_bytes: self
                    .uses
                    .max_response_bytes
                    .intersect(other.uses.max_response_bytes),
            },
            network: NetworkConstraints {
                schemes: exact_scope_intersection(&self.network.schemes, &other.network.schemes),
                hosts: exact_scope_intersection(&self.network.hosts, &other.network.hosts),
                ports: exact_scope_intersection(&self.network.ports, &other.network.ports),
                methods: exact_scope_intersection(&self.network.methods, &other.network.methods),
                path_prefixes: path_scope_intersection(
                    &self.network.path_prefixes,
                    &other.network.path_prefixes,
                ),
                allow_redirects: self.network.allow_redirects && other.network.allow_redirects,
            },
            spend,
        })
    }
}

fn exact_scope_intersection<T: Clone + Ord>(
    left: &ExactScope<T>,
    right: &ExactScope<T>,
) -> ExactScope<T> {
    let (ExactScope::Exact(left), ExactScope::Exact(right)) = (left, right) else {
        return ExactScope::Denied;
    };
    let left = left.iter().cloned().collect::<BTreeSet<_>>();
    let right = right.iter().cloned().collect::<BTreeSet<_>>();
    let values = left.intersection(&right).cloned().collect::<Vec<_>>();
    if values.is_empty() {
        ExactScope::Denied
    } else {
        ExactScope::Exact(values)
    }
}

fn path_scope_intersection(
    left: &ExactScope<String>,
    right: &ExactScope<String>,
) -> ExactScope<String> {
    let (ExactScope::Exact(left), ExactScope::Exact(right)) = (left, right) else {
        return ExactScope::Denied;
    };
    let mut result = BTreeSet::new();
    for left_path in left {
        for right_path in right {
            if path_is_within(left_path, right_path) {
                result.insert(left_path.clone());
            } else if path_is_within(right_path, left_path) {
                result.insert(right_path.clone());
            }
        }
    }
    let values = result.into_iter().collect::<Vec<_>>();
    if values.is_empty() {
        ExactScope::Denied
    } else {
        ExactScope::Exact(values)
    }
}

fn path_is_within(candidate: &str, parent: &str) -> bool {
    candidate == parent
        || (candidate.starts_with(parent)
            && (parent.ends_with('/')
                || candidate.as_bytes().get(parent.len()).copied() == Some(b'/')))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConstraintError {
    #[error("authority time window is empty or inverted")]
    InvalidTimeWindow,
    #[error("authority environments do not match")]
    EnvironmentMismatch,
    #[error("invalid authority environment")]
    InvalidEnvironment,
    #[error("invalid exact authority host")]
    InvalidHost,
    #[error("invalid authority path prefix")]
    InvalidPathPrefix,
    #[error("network redirects are denied by authority schema v1")]
    RedirectsDenied,
    #[error("bounded byte limits must be greater than zero")]
    InvalidByteLimit,
    #[error("exact authority scopes cannot be empty; use denied")]
    EmptyExactScope,
    #[error("exact authority scopes cannot contain duplicate values")]
    DuplicateExactScope,
    #[error("exact authority scopes must be strictly sorted")]
    UnsortedExactScope,
    #[error("bounded use capacity must have nonzero use and concurrency limits")]
    InvalidUseCapacity,
    #[error("invalid authority spend cap")]
    InvalidSpendCap,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constraints() -> AuthorityConstraints {
        AuthorityConstraints {
            environment: "production".into(),
            read_only: false,
            time: TimeConstraints {
                not_before: 100,
                expires_at: 200,
            },
            uses: UseConstraints {
                capacity: UseCapacity::Bounded {
                    max_uses: 10,
                    max_concurrent_uses: 3,
                },
                max_request_bytes: ByteLimit::Bounded { bytes: 1_000 },
                max_response_bytes: ByteLimit::Bounded { bytes: 2_000 },
            },
            network: NetworkConstraints {
                schemes: ExactScope::Exact(vec![NetworkScheme::Http, NetworkScheme::Https]),
                hosts: ExactScope::Exact(vec![
                    "api.example.com".into(),
                    "other.example.com".into(),
                ]),
                ports: ExactScope::Exact(vec![443, 8443]),
                methods: ExactScope::Exact(vec![HttpMethod::Get, HttpMethod::Post]),
                path_prefixes: ExactScope::Exact(vec!["/status".into(), "/v1".into()]),
                allow_redirects: false,
            },
            spend: SpendConstraints {
                currency: Some("USD".into()),
                max_minor_units: 5_000,
            },
        }
    }

    #[test]
    fn intersection_only_narrows() {
        let left = constraints();
        let mut right = constraints();
        right.read_only = true;
        right.time.not_before = 120;
        right.time.expires_at = 180;
        right.uses.capacity = UseCapacity::Bounded {
            max_uses: 1,
            max_concurrent_uses: 3,
        };
        right.network.schemes = ExactScope::Exact(vec![NetworkScheme::Https]);
        right.network.hosts = ExactScope::Exact(vec!["api.example.com".into()]);
        right.network.ports = ExactScope::Exact(vec![443]);
        right.network.methods = ExactScope::Exact(vec![HttpMethod::Post]);
        right.network.path_prefixes = ExactScope::Exact(vec!["/v1/jobs".into()]);
        right.network.allow_redirects = false;
        right.spend.max_minor_units = 500;

        let narrowed = left.intersect(&right).unwrap();
        assert!(narrowed.read_only);
        assert_eq!(narrowed.time.not_before, 120);
        assert_eq!(narrowed.time.expires_at, 180);
        assert_eq!(narrowed.uses.capacity.limits(), Some((1, 3)));
        assert_eq!(
            narrowed.network.schemes,
            ExactScope::Exact(vec![NetworkScheme::Https])
        );
        assert_eq!(
            narrowed.network.hosts,
            ExactScope::Exact(vec!["api.example.com".into()])
        );
        assert_eq!(
            narrowed.network.path_prefixes,
            ExactScope::Exact(vec!["/v1/jobs".into()])
        );
        assert!(!narrowed.network.allow_redirects);
        assert_eq!(narrowed.spend.max_minor_units, 500);
    }

    #[test]
    fn intersection_never_expands_disjoint_network_or_spend() {
        let left = constraints();
        let mut right = constraints();
        right.network.hosts = ExactScope::Exact(vec!["third.example.com".into()]);
        right.spend.currency = Some("EUR".into());

        let narrowed = left.intersect(&right).unwrap();
        assert_eq!(narrowed.network.hosts, ExactScope::Denied);
        assert!(narrowed.spend.is_forbidden());
    }

    #[test]
    fn empty_scopes_and_zero_bounded_limits_are_rejected() {
        let mut invalid = constraints();
        invalid.network.hosts = ExactScope::Exact(Vec::new());
        assert!(matches!(
            invalid.validate(),
            Err(ConstraintError::EmptyExactScope)
        ));

        let mut invalid = constraints();
        invalid.uses.max_request_bytes = ByteLimit::Bounded { bytes: 0 };
        assert!(matches!(
            invalid.validate(),
            Err(ConstraintError::InvalidByteLimit)
        ));
    }

    #[test]
    fn encoded_and_backslash_paths_are_rejected() {
        for path in [
            "/v1/%2e%2e/admin",
            "/v1\\admin",
            "/v1//admin",
            "/v1/./admin",
            "/v1/has space",
        ] {
            let mut invalid = constraints();
            invalid.network.path_prefixes = ExactScope::Exact(vec![path.into()]);
            assert!(matches!(
                invalid.validate(),
                Err(ConstraintError::InvalidPathPrefix)
            ));
        }
    }

    #[test]
    fn malformed_hosts_redirects_unsorted_scopes_and_zero_capacity_are_rejected() {
        for host in [
            ".example.com",
            "example.com.",
            "-api.example.com",
            "api..example.com",
        ] {
            let mut invalid = constraints();
            invalid.network.hosts = ExactScope::Exact(vec![host.into()]);
            assert!(matches!(
                invalid.validate(),
                Err(ConstraintError::InvalidHost)
            ));
        }

        let mut invalid = constraints();
        invalid.network.allow_redirects = true;
        assert!(matches!(
            invalid.validate(),
            Err(ConstraintError::RedirectsDenied)
        ));

        let mut invalid = constraints();
        invalid.network.hosts =
            ExactScope::Exact(vec!["z.example.com".into(), "a.example.com".into()]);
        assert!(matches!(
            invalid.validate(),
            Err(ConstraintError::UnsortedExactScope)
        ));

        let mut invalid = constraints();
        invalid.uses.capacity = UseCapacity::Bounded {
            max_uses: 1,
            max_concurrent_uses: 0,
        };
        assert!(matches!(
            invalid.validate(),
            Err(ConstraintError::InvalidUseCapacity)
        ));
    }

    #[test]
    fn expiry_boundary_is_exclusive() {
        let time = TimeConstraints {
            not_before: 10,
            expires_at: 20,
        };
        assert!(time.active_at(10));
        assert!(time.active_at(19));
        assert!(!time.active_at(20));
    }
}
