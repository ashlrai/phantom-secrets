use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

/// Serialize a value with recursively sorted object keys and no floats.
///
/// This is Phantom's local deterministic `canonical_json_v1` format. It is
/// intentionally **not** named or represented as RFC 8785 JCS and must not be
/// used as the future Phantom-Locus signature wire contract. That contract
/// requires shared cross-repository vectors and an independently reviewed JCS
/// implementation.
pub fn canonical_json_v1<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalJsonError> {
    let value = serde_json::to_value(value)?;
    let mut output = Vec::new();
    write_canonical(&value, &mut output)?;
    Ok(output)
}

/// Decode a closed serde schema after rejecting floating-point numbers.
///
/// Unknown-field rejection is supplied by the target contract's
/// `#[serde(deny_unknown_fields)]` annotation.
pub fn decode_closed_json_v1<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, CanonicalJsonError> {
    let value: Value = serde_json::from_slice(bytes)?;
    reject_floats(&value)?;
    let decoded = serde_json::from_value(value)?;
    if canonical_json_v1(&decoded)? != bytes {
        return Err(CanonicalJsonError::NonCanonicalInput);
    }
    Ok(decoded)
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if number.is_f64() {
                return Err(CanonicalJsonError::FloatForbidden);
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(string) => {
            output.extend_from_slice(serde_json::to_string(string)?.as_bytes())
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                output.push(b':');
                write_canonical(&object[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn reject_floats(value: &Value) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Number(number) if number.is_f64() => Err(CanonicalJsonError::FloatForbidden),
        Value::Array(values) => {
            for value in values {
                reject_floats(value)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for value in values.values() {
                reject_floats(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CanonicalJsonError {
    #[error("floating-point values are forbidden in authority contracts")]
    FloatForbidden,
    #[error("authority JSON is not canonical or contains duplicate keys")]
    NonCanonicalInput,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_serialization_sorts_recursively_and_is_stable() {
        let first: Value = serde_json::from_str(r#"{"z":1,"a":{"y":2,"b":3}}"#).unwrap();
        let second: Value = serde_json::from_str(r#"{"a":{"b":3,"y":2},"z":1}"#).unwrap();

        let expected = br#"{"a":{"b":3,"y":2},"z":1}"#.to_vec();
        assert_eq!(canonical_json_v1(&first).unwrap(), expected);
        assert_eq!(canonical_json_v1(&second).unwrap(), expected);
    }

    #[test]
    fn canonical_helpers_reject_floats() {
        let value = serde_json::json!({"nested": [1, 1.5]});
        assert!(matches!(
            canonical_json_v1(&value),
            Err(CanonicalJsonError::FloatForbidden)
        ));
        assert!(matches!(
            decode_closed_json_v1::<Value>(br#"{"value":1.5}"#),
            Err(CanonicalJsonError::FloatForbidden)
        ));
    }
}
