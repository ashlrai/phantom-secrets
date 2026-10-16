//! Micro-benchmark for the buffered response scrubber hot path.
//! Run: cargo run --release -p phantom-secrets-proxy --example scrub_bench
use phantom_proxy::ResponseScrubber;
use std::collections::HashMap;
use std::time::Instant;

fn body(size: usize, with_secret: bool) -> Vec<u8> {
    let mut s = String::from("{\"items\":[");
    let mut i = 0;
    while s.len() < size {
        if i > 0 { s.push(','); }
        s.push_str(&format!("{{\"id\":{i},\"name\":\"item-{i}\",\"note\":\"lorem ipsum dolor sit amet\"}}"));
        i += 1;
    }
    if with_secret { s.push_str(",{\"k\":\"sk-live-0123456789abcdefSECRETVALUE\"}"); }
    s.push_str("]}");
    s.into_bytes()
}

fn main() {
    let mut m = HashMap::new();
    for n in 0..5 { m.insert(format!("KEY{n}"), format!("sk-live-0123456789abcdefSECRETVALUE{}{}", n, "x".repeat(8))); }
    let sc = ResponseScrubber::from_named_map(&m);
    for &(label, size, sec) in &[("1KB clean", 1<<10, false), ("64KB clean", 64<<10, false), ("1MB clean", 1<<20, false), ("1MB with format-pattern secret", 1<<20, true)] {
        let b = body(size, sec);
        for _ in 0..3 { let _ = sc.scrub_buffered(Some("application/json"), &b); }
        let iters = if size >= 1<<20 { 30 } else { 500 };
        let mut t = Vec::new();
        for _ in 0..iters { let s = Instant::now(); let _ = sc.scrub_buffered(Some("application/json"), &b); t.push(s.elapsed().as_secs_f64()); }
        t.sort_by(|a,b| a.partial_cmp(b).unwrap());
        let med = t[t.len()/2];
        println!("{label}: {} bytes, median {:.1} us, p95 {:.1} us, {:.1} MB/s", b.len(), med*1e6, t[t.len()*95/100]*1e6, b.len() as f64/med/1e6);
    }
}
