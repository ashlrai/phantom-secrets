use crate::error::{PhantomError, Result};
use serde::de::DeserializeOwned;
use std::time::Duration;
use zeroize::Zeroizing;

pub(crate) const MAX_PHANTOM_CLOUD_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| PhantomError::CloudError {
            status: 0,
            message: "Failed to initialize the Phantom Cloud HTTP client".to_string(),
        })
}

pub(crate) async fn read_bounded_response(
    mut response: reqwest::Response,
    operation: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let status = response.status().as_u16();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PHANTOM_CLOUD_RESPONSE_BYTES as u64)
    {
        return Err(response_error(
            status,
            operation,
            "response exceeded the size limit",
        ));
    }

    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| response_error(status, operation, "response body could not be read"))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_PHANTOM_CLOUD_RESPONSE_BYTES {
            return Err(response_error(
                status,
                operation,
                "response exceeded the size limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) fn parse_json<T: DeserializeOwned>(
    bytes: &[u8],
    status: u16,
    operation: &str,
) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|_| response_error(status, operation, "response was invalid JSON"))
}

pub(crate) fn response_error(status: u16, operation: &str, reason: &str) -> PhantomError {
    PhantomError::CloudError {
        status,
        message: format!("{operation}: {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[tokio::test]
    async fn rejects_oversized_content_length_without_reading_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_PHANTOM_CLOUD_RESPONSE_BYTES + 1
            )
            .unwrap();
        });
        let response = reqwest::get(format!("http://{address}")).await.unwrap();
        let error = read_bounded_response(response, "mock cloud read")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("size limit"));
        server.join().unwrap();
    }

    #[test]
    fn parse_errors_never_echo_response_body() {
        let echoed = b"provider-echoed-secret-value";
        let error = parse_json::<serde_json::Value>(echoed, 502, "mock cloud read").unwrap_err();
        assert!(error.to_string().contains("invalid JSON"));
        assert!(!error.to_string().contains("provider-echoed-secret-value"));
    }
}
