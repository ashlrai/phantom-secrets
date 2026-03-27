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
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let requests: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let reqs = requests.clone();
        let handle = tokio::spawn(async move {
            run_mock(listener, reqs, shutdown_rx).await;
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

async fn run_mock(
    listener: TcpListener,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let reqs = requests.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let _ = http1::Builder::new()
                                .serve_connection(
                                    io,
                                    service_fn(move |req| {
                                        let reqs = reqs.clone();
                                        async move {
                                            handle_mock_request(req, reqs).await
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

    let body = req.collect().await?.to_bytes().to_vec();

    requests.lock().unwrap().push(RecordedRequest {
        method,
        path,
        headers,
        body,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(r#"{"status":"ok","mock":true}"#)))
        .unwrap())
}
