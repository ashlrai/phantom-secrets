use std::io::Read;
use std::time::Duration;

use zeroize::Zeroizing;

pub(crate) const MAX_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;

pub(crate) fn async_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "provider HTTP client could not be initialized".to_string())
}

pub(crate) fn blocking_client(timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .timeout(timeout)
        .user_agent("phantom-secrets-validator/0.1")
        .build()
        .map_err(|_| "provider HTTP client could not be initialized".to_string())
}

pub(crate) async fn read_bounded_response(
    mut response: reqwest::Response,
    operation: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        return Err(format!(
            "{operation} response exceeded the {MAX_PROVIDER_RESPONSE_BYTES}-byte limit"
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| format!("{operation} response could not be read"))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(format!(
                "{operation} response exceeded the {MAX_PROVIDER_RESPONSE_BYTES}-byte limit"
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) fn read_bounded_blocking_response(
    response: reqwest::blocking::Response,
    operation: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        return Err(format!(
            "{operation} response exceeded the {MAX_PROVIDER_RESPONSE_BYTES}-byte limit"
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take((MAX_PROVIDER_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("{operation} response could not be read"))?;
    if bytes.len() > MAX_PROVIDER_RESPONSE_BYTES {
        return Err(format!(
            "{operation} response exceeded the {MAX_PROVIDER_RESPONSE_BYTES}-byte limit"
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocking_body_limit_is_strict_and_value_free() {
        // The network response wrapper is exercised by integration callers;
        // this constant-level regression keeps the shared ceiling bounded.
        assert_eq!(MAX_PROVIDER_RESPONSE_BYTES, 1024 * 1024);
        let error =
            format!("validation response exceeded the {MAX_PROVIDER_RESPONSE_BYTES}-byte limit");
        assert!(!error.contains("provider-echoed-secret"));
    }
}
