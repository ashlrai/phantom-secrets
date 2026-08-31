use crate::protocol::{BrokerEnvelopeV1, ValidatedBrokerEnvelope};
use phantom_authority::{canonical_json_v1, decode_closed_json_v1, CanonicalJsonError};
use std::io::{Read, Write};

pub const MAX_BROKER_MESSAGE_BYTES: usize = 64 * 1024;

pub fn encode_frame(
    message: &ValidatedBrokerEnvelope,
    writer: &mut impl Write,
) -> Result<(), BrokerCodecError> {
    let payload = canonical_json_v1(message.as_inner())?;
    if payload.is_empty() || payload.len() > MAX_BROKER_MESSAGE_BYTES {
        return Err(BrokerCodecError::InvalidLength(payload.len()));
    }
    let length =
        u32::try_from(payload.len()).map_err(|_| BrokerCodecError::InvalidLength(payload.len()))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    Ok(())
}

pub fn decode_frame(reader: &mut impl Read) -> Result<ValidatedBrokerEnvelope, BrokerCodecError> {
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|error| map_truncation(error, BrokerCodecError::TruncatedPrefix))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_BROKER_MESSAGE_BYTES {
        return Err(BrokerCodecError::InvalidLength(length));
    }

    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).map_err(|error| {
        map_truncation(
            error,
            BrokerCodecError::TruncatedPayload { expected: length },
        )
    })?;
    let envelope: BrokerEnvelopeV1 = match decode_closed_json_v1(&payload) {
        Err(CanonicalJsonError::NonCanonicalInput) => {
            return Err(BrokerCodecError::NonCanonicalPayload)
        }
        result => result?,
    };
    let validated = ValidatedBrokerEnvelope::try_from(envelope)?;
    if canonical_json_v1(validated.as_inner())? != payload {
        return Err(BrokerCodecError::NonCanonicalPayload);
    }
    Ok(validated)
}

fn map_truncation(error: std::io::Error, truncated: BrokerCodecError) -> BrokerCodecError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        truncated
    } else {
        BrokerCodecError::Io(error)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerCodecError {
    #[error("broker frame length {0} is outside 1..={MAX_BROKER_MESSAGE_BYTES}")]
    InvalidLength(usize),
    #[error("broker frame ended before the 4-byte length prefix")]
    TruncatedPrefix,
    #[error("broker frame ended before its {expected}-byte payload")]
    TruncatedPayload { expected: usize },
    #[error("broker payload is not canonical JSON")]
    NonCanonicalPayload,
    #[error(transparent)]
    InvalidMessage(#[from] crate::protocol::ProtocolValidationError),
    #[error(transparent)]
    Canonical(#[from] CanonicalJsonError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{BrokerMessageV1, HelloV1, BROKER_PROTOCOL_VERSION};

    fn envelope() -> ValidatedBrokerEnvelope {
        let id = "01".repeat(16);
        let digest = "ab".repeat(32);
        ValidatedBrokerEnvelope::try_new(BrokerMessageV1::Hello(HelloV1 {
            installation_id: format!("ins_{id}").parse().unwrap(),
            broker_epoch_sha256: digest.parse().unwrap(),
            executable_sha256: "cd".repeat(32).parse().unwrap(),
            supported_versions: vec![BROKER_PROTOCOL_VERSION],
        }))
        .unwrap()
    }

    #[test]
    fn length_prefixed_round_trip() {
        let expected = envelope();
        let mut frame = Vec::new();
        encode_frame(&expected, &mut frame).unwrap();
        assert_eq!(
            u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
        assert_eq!(decode_frame(&mut frame.as_slice()).unwrap(), expected);
    }

    #[test]
    fn partial_prefix_and_payload_are_rejected() {
        assert!(matches!(
            decode_frame(&mut [0, 0, 0].as_slice()),
            Err(BrokerCodecError::TruncatedPrefix)
        ));
        let mut partial = vec![0, 0, 0, 10];
        partial.extend_from_slice(b"short");
        assert!(matches!(
            decode_frame(&mut partial.as_slice()),
            Err(BrokerCodecError::TruncatedPayload { expected: 10 })
        ));
    }

    #[test]
    fn oversized_claim_is_rejected_before_allocation() {
        let length = (MAX_BROKER_MESSAGE_BYTES as u32 + 1).to_be_bytes();
        assert!(matches!(
            decode_frame(&mut length.as_slice()),
            Err(BrokerCodecError::InvalidLength(size)) if size == MAX_BROKER_MESSAGE_BYTES + 1
        ));
    }

    #[test]
    fn oversized_encode_is_rejected() {
        let mut hello = match envelope().message().clone() {
            BrokerMessageV1::Hello(hello) => hello,
            _ => unreachable!(),
        };
        hello.supported_versions = vec![BROKER_PROTOCOL_VERSION; MAX_BROKER_MESSAGE_BYTES];
        let message = ValidatedBrokerEnvelope::try_new(BrokerMessageV1::Hello(hello)).unwrap();
        assert!(matches!(
            encode_frame(&message, &mut Vec::new()),
            Err(BrokerCodecError::InvalidLength(_))
        ));
    }

    #[test]
    fn unsupported_version_fails_closed() {
        let payload = canonical_json_v1(envelope().as_inner())
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        let payload = String::from_utf8(payload)
            .unwrap()
            .replace("\"protocol_version\":1", "\"protocol_version\":2")
            .into_bytes();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        assert!(matches!(
            decode_frame(&mut frame.as_slice()),
            Err(BrokerCodecError::InvalidMessage(
                crate::protocol::ProtocolValidationError::UnsupportedVersion(2)
            ))
        ));
    }

    #[test]
    fn duplicate_keys_and_noncanonical_json_are_rejected() {
        let canonical =
            String::from_utf8(canonical_json_v1(envelope().as_inner()).unwrap()).unwrap();
        let payloads = [
            format!(" {canonical}"),
            canonical.replacen(
                "\"protocol_version\":1",
                "\"protocol_version\":1,\"protocol_version\":1",
                1,
            ),
        ];
        for payload in payloads {
            let mut frame = Vec::new();
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(payload.as_bytes());
            assert!(matches!(
                decode_frame(&mut frame.as_slice()),
                Err(BrokerCodecError::NonCanonicalPayload)
            ));
        }
    }
}
