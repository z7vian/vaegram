use std::time::{Duration, Instant};

const WARM_UP: Duration = Duration::from_millis(50);
const MEASURE: Duration = Duration::from_millis(300);

pub fn header() {
    println!("{:<40} {:>12} {:>10}", "case", "ns/op", "MB/s");
}

pub fn bench(name: &str, f: impl FnMut()) {
    let ns = measure(f);
    println!("{name:<40} {ns:>12.1}");
}

/// Also prints the throughput of `bytes` per call, in MB/s of 10^6 bytes as Go's benchmarks count them.
pub fn bench_bytes(name: &str, bytes: usize, f: impl FnMut()) {
    let ns = measure(f);
    let mb_per_s = bytes as f64 * 1e3 / ns;
    println!("{name:<40} {ns:>12.1} {mb_per_s:>10.1}");
}

fn measure(mut f: impl FnMut()) -> f64 {
    let warm = Instant::now();
    let mut batch = 0u64;
    while warm.elapsed() < WARM_UP {
        f();
        batch += 1;
    }
    let batch = batch.max(1);

    let mut iters = 0u64;
    let start = Instant::now();
    while start.elapsed() < MEASURE {
        for _ in 0..batch {
            f();
        }
        iters += batch;
    }
    start.elapsed().as_nanos() as f64 / iters as f64
}
