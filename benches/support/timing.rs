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
    throughput(name, bytes, measure(f));
}

/// Like [`bench_bytes`], for inputs that run out: `warm_up` untimed calls, then exactly `count` timed ones.
pub fn bench_bytes_counted(name: &str, bytes: usize, warm_up: usize, count: usize, mut f: impl FnMut()) {
    for _ in 0..warm_up {
        f();
    }
    let start = Instant::now();
    for _ in 0..count {
        f();
    }
    throughput(name, bytes, start.elapsed().as_nanos() as f64 / count as f64);
}

fn throughput(name: &str, bytes: usize, ns: f64) {
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
