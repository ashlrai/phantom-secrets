//! Micro-benchmark: classic X25519 team key share vs hybrid X-Wing share.
//! Run: cargo run --release -p phantom-secrets-core --features pq-hybrid --example crypto_bench
//! The hybrid crate is unaudited; numbers are for sizing and cost only.
#[cfg(not(feature = "pq-hybrid"))]
fn main() {
    eprintln!("Build with --features pq-hybrid");
}

#[cfg(feature = "pq-hybrid")]
fn main() {
    use phantom_core::team_crypto::{generate_sym_key, open_sym_key, seal_sym_key, MemberKeypair};
    use phantom_core::team_crypto_pq::{open_sym_key_hybrid, seal_sym_key_hybrid, HybridKeypair};
    use std::time::Instant;

    fn stats(label: &str, mut t: Vec<f64>) {
        t.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "{label}: n={}, median {:.1} us, p95 {:.1} us",
            t.len(),
            t[t.len() / 2] * 1e6,
            t[t.len() * 95 / 100] * 1e6
        );
    }
    fn run<F: FnMut()>(mut f: F, iters: usize) -> Vec<f64> {
        for _ in 0..10 {
            f();
        }
        (0..iters)
            .map(|_| {
                let s = Instant::now();
                f();
                s.elapsed().as_secs_f64()
            })
            .collect()
    }

    let n = 1000;
    let key = generate_sym_key();

    stats("classic keygen", run(|| drop(MemberKeypair::generate()), n));
    stats("hybrid  keygen", run(|| drop(HybridKeypair::generate()), n));

    let cm = MemberKeypair::generate();
    let hm = HybridKeypair::generate();
    let cpub = cm.public_b64();
    let hpub = hm.public_b64();
    stats(
        "classic seal  ",
        run(|| drop(seal_sym_key(&key, &cpub).unwrap()), n),
    );
    stats(
        "hybrid  seal  ",
        run(|| drop(seal_sym_key_hybrid(&key, &hpub).unwrap()), n),
    );

    let cs = seal_sym_key(&key, &cpub).unwrap();
    let hs = seal_sym_key_hybrid(&key, &hpub).unwrap();
    stats(
        "classic open  ",
        run(|| drop(open_sym_key(&cs, &cm).unwrap()), n),
    );
    stats(
        "hybrid  open  ",
        run(|| drop(open_sym_key_hybrid(&hs, &hm).unwrap()), n),
    );

    let csz = serde_json::to_string(&cs).unwrap().len();
    let hsz = serde_json::to_string(&hs).unwrap().len();
    println!("share JSON bytes: classic {csz}, hybrid {hsz}");
    println!(
        "public key base64 bytes: classic {}, hybrid {}",
        cpub.len(),
        hpub.len()
    );
}
