//! End-to-end latency/throughput benchmark: client -> phantom proxy -> local mock upstream,
//! compared with client -> mock upstream directly. Loopback only, synthetic.
//! Run: cargo run --release -p phantom-secrets-proxy --example e2e_bench
use phantom_proxy::test_server::MockServer;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry, ServiceRoute};
use std::collections::HashMap;
use std::time::Instant;

async fn run(client: &reqwest::Client, url: String, total: usize, conc: usize) -> (Vec<f64>, f64) {
    let t0 = Instant::now();
    let per = total / conc;
    let mut hs = Vec::new();
    for _ in 0..conc {
        let c = client.clone();
        let u = url.clone();
        hs.push(tokio::spawn(async move {
            let mut v = Vec::with_capacity(per);
            for _ in 0..per {
                let s = Instant::now();
                let r = c
                    .post(&u)
                    .header("content-type", "application/json")
                    .body(r#"{"model":"m","messages":[]}"#)
                    .send()
                    .await
                    .unwrap();
                let _ = r.bytes().await.unwrap();
                v.push(s.elapsed().as_secs_f64());
            }
            v
        }));
    }
    let mut all = Vec::new();
    for h in hs {
        all.extend(h.await.unwrap());
    }
    let el = t0.elapsed().as_secs_f64();
    all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (all, el)
}

fn pct(v: &[f64], p: f64) -> f64 {
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)] * 1e6
}

#[tokio::main]
async fn main() {
    let mock = MockServer::start().await;
    let secret = "sk-live-0123456789abcdefSECRETVALUExxxxxxxx";
    let phantom = "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
    let mut named = HashMap::new();
    named.insert("OPENAI_API_KEY".to_string(), secret.to_string());
    let mut tm = HashMap::new();
    tm.insert(phantom.to_string(), secret.to_string());
    let mut reg = ServiceRegistry::new();
    reg.add_route(ServiceRoute {
        name: "openai".into(),
        target_base: format!("http://127.0.0.1:{}", mock.port),
        secret_key: "OPENAI_API_KEY".into(),
        header: "Authorization".into(),
        header_format: "Bearer {secret}".into(),
        credential_profile: phantom_proxy::services::CredentialProfile::Standard,
        sdk_base_path: None,
    });
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: String::new(),
            ..ProxyConfig::default()
        },
        reg,
        Interceptor::new_with_named(tm, named),
    )
    .await
    .unwrap();
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(64)
        .build()
        .unwrap();
    let direct = format!("http://127.0.0.1:{}/v1/chat", mock.port);
    let via = format!("http://127.0.0.1:{}/openai/v1/chat", proxy.port());
    println!("cores={}", std::thread::available_parallelism().unwrap());
    for &conc in &[1usize, 16, 64] {
        let total = if conc == 1 { 3000 } else { 12000 };
        let _ = run(&client, direct.clone(), 200, conc.min(8)).await;
        let _ = run(&client, via.clone(), 200, conc.min(8)).await;
        let (d, de) = run(&client, direct.clone(), total, conc).await;
        let (p, pe) = run(&client, via.clone(), total, conc).await;
        println!("conc={conc:>2} direct: p50 {:.0}us p99 {:.0}us {:.0} req/s | proxy: p50 {:.0}us p99 {:.0}us {:.0} req/s | added p50 {:.0}us",
            pct(&d,0.5), pct(&d,0.99), d.len() as f64/de, pct(&p,0.5), pct(&p,0.99), p.len() as f64/pe, pct(&p,0.5)-pct(&d,0.5));
    }
}
