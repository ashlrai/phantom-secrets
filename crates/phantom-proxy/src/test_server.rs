//! A simple mock HTTP server for integration tests.
//! Records incoming requests so tests can assert on what was received.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::watch;

/// A recorded request from the mock server.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// A mock HTTP server that records all incoming requests.
pub struct MockServer {
    pub port: u16,
    pub requests: Arc<Mutex<Vec<RecordedRequest>>>,
    shutdown_tx: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl MockServer {
    /// Start a mock server on an ephemeral port.
    /// Responds to all requests with 200 OK and a JSON body.
    pub async fn start() -> Self {
        Self::start_inner(None).await
    }

    /// Start a mock server that echoes the value of the request header
    /// `header` back in a `x-echo` response header and in the JSON body,
    /// served with `content_type`. Models a careless or hostile upstream that
    /// reflects the credential it received.
    pub async fn start_echoing(header: &str, content_type: &str) -> Self {
        Self::start_inner(Some(Echo {
            header: header.to_ascii_lowercase(),
            content_type: content_type.to_string(),
        }))
        .await
    }

    async fn start_inner(echo: Option<Echo>) -> Self {
        let echo = Arc::new(echo);
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let requests: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let reqs = requests.clone();
        let handle = tokio::spawn(async move {
            run_mock(listener, reqs, echo, shutdown_rx).await;
        });

        Self {
            port,
            requests,
            shutdown_tx,
            handle,
        }
    }

    /// Get all recorded requests.
    pub fn get_requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// Shut down the mock server.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.handle.await;
    }
}

/// Echo configuration for [`MockServer::start_echoing`].
struct Echo {
    header: String,
    content_type: String,
}

async fn run_mock(
    listener: TcpListener,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    echo: Arc<Option<Echo>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let reqs = requests.clone();
                        let echo = echo.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let _ = http1::Builder::new()
                                .serve_connection(
                                    io,
                                    service_fn(move |req| {
                                        let reqs = reqs.clone();
                                        let echo = echo.clone();
                                        async move {
                                            handle_mock_request(req, reqs, echo).await
                                        }
                                    }),
                                )
                                .await;
                        });
                    }
                    Err(_) => break,
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}

async fn handle_mock_request(
    req: Request<Incoming>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    echo: Arc<Option<Echo>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    use http_body_util::BodyExt;

    let method = req.method().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_default();

    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.to_string(), v.to_string());
        }
    }

    let echoed = echo
        .as_ref()
        .as_ref()
        .map(|echo| (headers.get(&echo.header).cloned().unwrap_or_default(), echo));
    let body = req.collect().await?.to_bytes().to_vec();

    requests.lock().unwrap().push(RecordedRequest {
        method,
        path,
        headers,
        body,
    });

    if let Some((value, echo)) = echoed {
        let body = serde_json::json!({ "error": "unauthorized", "received": value }).to_string();
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", echo.content_type.as_str())
            .header("x-echo", value)
            .body(Full::new(Bytes::from(body)))
            .unwrap());
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(r#"{"status":"ok","mock":true}"#)))
        .unwrap())
}
