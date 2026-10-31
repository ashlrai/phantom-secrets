//! Canonical byte grammars for conservative response-credential detection.
//!
//! Match ranges and static labels are value-free. Callers own their input and
//! remain responsible for erasing temporary buffers containing credentials.

#[derive(Clone, Copy)]
enum ByteClass {
    Alnum,
    AlnumUnderscore,
    AlnumDashUnderscore,
    UpperAlnum,
    AlnumDash,
    HexLower,
}

impl ByteClass {
    fn contains(self, byte: u8) -> bool {
        match self {
            Self::Alnum => byte.is_ascii_alphanumeric(),
            Self::AlnumUnderscore => byte.is_ascii_alphanumeric() || byte == b'_',
            Self::AlnumDashUnderscore => {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
            }
            Self::UpperAlnum => byte.is_ascii_uppercase() || byte.is_ascii_digit(),
            Self::AlnumDash => byte.is_ascii_alphanumeric() || byte == b'-',
            Self::HexLower => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        }
    }
}

#[derive(Clone, Copy)]
enum FormatShape {
    Unbounded { class: ByteClass, min: usize },
    Fixed { class: ByteClass, len: usize },
    SendGrid,
}

/// One response-credential byte grammar, shared by buffered and streaming scans.
///
/// Response matching deliberately accepts embedded prefixes and identifier-like
/// tails: bytes leaving the proxy require conservative scrubbing, unlike source
/// code diagnostics which suppress common identifier false positives.
#[derive(Clone, Copy)]
pub struct FormatSpec {
    /// Value-free identifier used in redaction markers and audit events.
    pub label: &'static str,
    /// Public provider prefix; never contains credential tail bytes.
    pub prefix: &'static [u8],
    shape: FormatShape,
}

impl FormatSpec {
    /// Non-overlapping, left-to-right matches for this format as byte ranges.
    ///
    /// Ranges carry no credential values. Every matched byte is ASCII, so ranges
    /// found in UTF-8 input also lie on character boundaries. Arbitrary byte
    /// input is supported without lossy decoding.
    pub fn match_ranges(self, input: &[u8]) -> Vec<std::ops::Range<usize>> {
        let mut ranges = Vec::new();
        let mut cursor = 0;
        while cursor < input.len() {
            if let Some(len) = self.complete_prefix_len(&input[cursor..]) {
                ranges.push(cursor..cursor + len);
                cursor += len;
            } else {
                cursor += 1;
            }
        }
        ranges
    }

    /// Minimum complete credential length, including its public prefix.
    pub fn minimum_match_len(self) -> usize {
        self.prefix.len()
            + match self.shape {
                FormatShape::Unbounded { min, .. } => min,
                FormatShape::Fixed { len, .. } => len,
                FormatShape::SendGrid => 22 + 1 + 43,
            }
    }

    /// Whether matches may continue beyond the minimum credential length.
    pub fn is_unbounded(self) -> bool {
        matches!(self.shape, FormatShape::Unbounded { .. })
    }

    /// Whether a byte extends an already-matched unbounded credential.
    pub fn continuation_contains(self, byte: u8) -> bool {
        match self.shape {
            FormatShape::Unbounded { class, .. } => class.contains(byte),
            _ => false,
        }
    }

    /// Whether all of `candidate` can still become a match for this format.
    pub fn is_incomplete_prefix(self, candidate: &[u8]) -> bool {
        if candidate.len() <= self.prefix.len() {
            return self.prefix.starts_with(candidate);
        }
        if !candidate.starts_with(self.prefix) {
            return false;
        }
        let suffix = &candidate[self.prefix.len()..];
        match self.shape {
            FormatShape::Unbounded { class, min } => {
                suffix.len() < min && suffix.iter().all(|byte| class.contains(*byte))
            }
            FormatShape::Fixed { class, len } => {
                suffix.len() < len && suffix.iter().all(|byte| class.contains(*byte))
            }
            FormatShape::SendGrid => sendgrid_prefix_is_incomplete(suffix),
        }
    }

    /// Length of a complete match at the beginning of `candidate`.
    pub fn complete_prefix_len(self, candidate: &[u8]) -> Option<usize> {
        if !candidate.starts_with(self.prefix) {
            return None;
        }
        let suffix = &candidate[self.prefix.len()..];
        match self.shape {
            FormatShape::Unbounded { class, min } => {
                let run = suffix
                    .iter()
                    .take_while(|byte| class.contains(**byte))
                    .count();
                (run >= min).then_some(self.prefix.len() + run)
            }
            FormatShape::Fixed { class, len } => (suffix.len() >= len
                && suffix[..len].iter().all(|byte| class.contains(*byte)))
            .then_some(self.prefix.len() + len),
            FormatShape::SendGrid => {
                let total = 22 + 1 + 43;
                (suffix.len() >= total
                    && suffix[..22]
                        .iter()
                        .all(|byte| ByteClass::AlnumDashUnderscore.contains(*byte))
                    && suffix[22] == b'.'
                    && suffix[23..total]
                        .iter()
                        .all(|byte| ByteClass::AlnumDashUnderscore.contains(*byte)))
                .then_some(self.prefix.len() + total)
            }
        }
    }
}

fn sendgrid_prefix_is_incomplete(suffix: &[u8]) -> bool {
    if suffix.len() <= 22 {
        return suffix
            .iter()
            .all(|byte| ByteClass::AlnumDashUnderscore.contains(*byte));
    }
    if suffix[22] != b'.' {
        return false;
    }
    let tail = &suffix[23..];
    tail.len() < 43
        && tail
            .iter()
            .all(|byte| ByteClass::AlnumDashUnderscore.contains(*byte))
}

/// FORMAT_SPECS grouped by first prefix byte, so a scan position only tests
/// the shapes that can begin there. Bucket contents preserve catalog order.
pub(crate) fn specs_by_first_byte() -> &'static [Vec<&'static FormatSpec>; 256] {
    static INDEX: std::sync::OnceLock<[Vec<&'static FormatSpec>; 256]> = std::sync::OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index: [Vec<&'static FormatSpec>; 256] = std::array::from_fn(|_| Vec::new());
        for spec in FORMAT_SPECS {
            index[spec.prefix[0] as usize].push(spec);
        }
        index
    })
}

/// Canonical response-format catalog, ordered for stable audit and replacement
/// behavior. Both buffered and bounded streaming consumers use these grammars.
pub const FORMAT_SPECS: &[FormatSpec] = &[
    FormatSpec {
        label: "sk_*",
        prefix: b"sk-",
        shape: FormatShape::Unbounded {
            class: ByteClass::AlnumDashUnderscore,
            min: 20,
        },
    },
    FormatSpec {
        label: "sk_live_*",
        prefix: b"sk_live_",
        shape: FormatShape::Unbounded {
            class: ByteClass::Alnum,
            min: 20,
        },
    },
    FormatSpec {
        label: "sk_test_*",
        prefix: b"sk_test_",
        shape: FormatShape::Unbounded {
            class: ByteClass::Alnum,
            min: 20,
        },
    },
    FormatSpec {
        label: "ghp_*",
        prefix: b"ghp_",
        shape: FormatShape::Unbounded {
            class: ByteClass::Alnum,
            min: 36,
        },
    },
    FormatSpec {
        label: "github_pat_*",
        prefix: b"github_pat_",
        shape: FormatShape::Unbounded {
            class: ByteClass::AlnumUnderscore,
            min: 80,
        },
    },
    FormatSpec {
        label: "AKIA*",
        prefix: b"AKIA",
        shape: FormatShape::Fixed {
            class: ByteClass::UpperAlnum,
            len: 16,
        },
    },
    FormatSpec {
        label: "AIza*",
        prefix: b"AIza",
        shape: FormatShape::Fixed {
            class: ByteClass::AlnumDashUnderscore,
            len: 35,
        },
    },
    FormatSpec {
        label: "xoxb-*",
        prefix: b"xoxb-",
        shape: FormatShape::Unbounded {
            class: ByteClass::AlnumDash,
            min: 40,
        },
    },
    FormatSpec {
        label: "xoxp-*",
        prefix: b"xoxp-",
        shape: FormatShape::Unbounded {
            class: ByteClass::AlnumDash,
            min: 40,
        },
    },
    FormatSpec {
        label: "SG.*",
        prefix: b"SG.",
        shape: FormatShape::SendGrid,
    },
    FormatSpec {
        label: "AC*",
        prefix: b"AC",
        shape: FormatShape::Fixed {
            class: ByteClass::HexLower,
            len: 32,
        },
    },
    FormatSpec {
        label: "phm_*",
        prefix: b"phm_",
        shape: FormatShape::Fixed {
            class: ByteClass::HexLower,
            len: 64,
        },
    },
];
