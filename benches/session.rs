//! The full client against a loopback DC (`support/mockdc.rs`) at 0/10/40 ms of added latency.
//! `cargo bench --bench session` prints one JSON line per result. The `cpu_ms_per_mib_*` rows (Linux only) count
//! the whole process, so the in-process mock DC's own work is in them too: compare them only against the same
//! mock DC on the same kind of runner. They come from per-thread schedstat nanoseconds; the `*_ticks` rows
//! repeat them from /proc/self/stat's 10 ms ticks as a diagnostic, never as the number to compare.

#[path = "support/cpu.rs"]
mod cpu;
#[path = "support/mockdc.rs"]
mod mockdc;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use mockdc::{MockDc, get_file};
use vaegram::raw::{base, functions};
use vaegram::{Client, filters};

const LATENCIES_MS: [u64; 3] = [0, 10, 40];
const WINDOW: Duration = Duration::from_secs(2);
const PART: usize = 512 * 1024;
const TRANSFER_PARTS: usize = 256;
const TRANSFER_DEPTH: usize = 8;
// Each transfer runs this many times and reports its median, so one noisy round can't move a row.
const TRANSFER_ROUNDS: usize = 5;
const UPDATES: u64 = 20_000;
const ECHOES: u64 = 10_000;
// Pushes stay this far ahead of the handler, so the client's update channel never overflows.
const PUSH_AHEAD: u64 = 500;
const PUSH_BATCH: u64 = 100;
const PUSH_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_EVERY: Duration = Duration::from_millis(1);

fn report(case: &str, latency_ms: u64, value: f64, unit: &str) {
    println!("{{\"case\":\"{case}\",\"latency_ms\":{latency_ms},\"value\":{value:.1},\"unit\":\"{unit}\"}}");
}

/// Prints VmRSS and VmHWM in KiB; Linux only.
fn report_rss(when: &str) {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else { return };
    let field = |name: &str| {
        status.lines().find_map(|l| l.strip_prefix(name)?.trim().strip_suffix("kB")?.trim().parse::<u64>().ok())
    };
    if let (Some(rss), Some(hwm)) = (field("VmRSS:"), field("VmHWM:")) {
        println!("{{\"case\":\"rss_{when}\",\"rss_kib\":{rss},\"hwm_kib\":{hwm}}}");
    }
}

/// The median, min and max of `values`.
fn spread(mut values: Vec<f64>) -> (f64, f64, f64) {
    values.sort_by(f64::total_cmp);
    (values[values.len() / 2], values[0], values[values.len() - 1])
}

fn report_cpu(case: &str, latency_ms: u64, ms_per_mib: Vec<f64>) {
    let (median, min, max) = spread(ms_per_mib);
    println!(
        "{{\"case\":\"{case}\",\"latency_ms\":{latency_ms},\"value\":{median:.2},\"min\":{min:.2},\"max\":{max:.2},\
         \"rounds\":{TRANSFER_ROUNDS},\"unit\":\"cpu ms/MiB\"}}"
    );
}

/// The transfer's median MiB/s over its rounds, then (Linux only) the CPU milliseconds the process spent per MiB
/// moved: median, min and max.
async fn measured_transfer(client: &Client, upload: bool, latency_ms: u64) {
    let direction = if upload { "upload" } else { "download" };
    let mib = (TRANSFER_PARTS * PART) as f64 / (1 << 20) as f64;
    let (mut rates, mut on_cpu, mut ticks) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..TRANSFER_ROUNDS {
        let before = cpu::sample();
        rates.push(transfer(client, upload).await);
        let (Some((ns_before, ticks_before)), Some((ns_after, ticks_after))) = (before, cpu::sample()) else {
            continue;
        };
        // Saturating: a thread that ended mid-round takes its time with it.
        on_cpu.push(ns_after.saturating_sub(ns_before) as f64 / 1e6 / mib);
        if let (Some(before), Some(after)) = (ticks_before, ticks_after) {
            ticks.push(after.saturating_sub(before) as f64 / mib);
        }
    }
    report(direction, latency_ms, spread(rates).0, "MiB/s");
    if on_cpu.len() == TRANSFER_ROUNDS {
        report_cpu(&format!("cpu_ms_per_mib_{direction}"), latency_ms, on_cpu);
    }
    if ticks.len() == TRANSFER_ROUNDS {
        report_cpu(&format!("cpu_ms_per_mib_{direction}_ticks"), latency_ms, ticks);
    }
}

async fn requests(client: &Client, depth: usize, ping: bool) -> f64 {
    let done = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let workers: Vec<_> = (0..depth)
        .map(|_| {
            let (client, done) = (client.clone(), done.clone());
            tokio::spawn(async move {
                while start.elapsed() < WINDOW {
                    if ping {
                        client.invoke(&functions::Ping { ping_id: 1 }).await.unwrap();
                    } else {
                        client.invoke(&functions::updates::GetState {}).await.unwrap();
                    }
                    done.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for w in workers {
        w.await.unwrap();
    }
    done.load(Ordering::Relaxed) as f64 / start.elapsed().as_secs_f64()
}

async fn pushed(mock: &MockDc, seen: impl Fn() -> u64, total: u64) -> f64 {
    let base = seen();
    let start = Instant::now();
    let mut sent = 0;
    while seen() - base < total {
        while sent < total && sent - (seen() - base) < PUSH_AHEAD {
            mock.push(PUSH_BATCH as u32);
            sent += PUSH_BATCH;
        }
        assert!(start.elapsed() < PUSH_TIMEOUT, "{} of {total} pushes never arrived", total - (seen() - base));
        tokio::time::sleep(POLL_EVERY).await;
    }
    total as f64 / start.elapsed().as_secs_f64()
}

async fn transfer(client: &Client, upload: bool) -> f64 {
    let next = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let workers: Vec<_> = (0..TRANSFER_DEPTH)
        .map(|_| {
            let (client, next) = (client.clone(), next.clone());
            tokio::spawn(async move {
                let mut save = functions::upload::SaveBigFilePart {
                    file_id: 1,
                    file_part: 0,
                    file_total_parts: TRANSFER_PARTS as i32,
                    bytes: vec![1; PART],
                };
                loop {
                    let part = next.fetch_add(1, Ordering::Relaxed) as usize;
                    if part >= TRANSFER_PARTS {
                        break;
                    }
                    if upload {
                        save.file_part = part as i32;
                        assert!(client.invoke(&save).await.unwrap());
                    } else {
                        let get = get_file((part * PART) as i64, PART as i32);
                        let base::upload::File::File(f) = client.invoke(&get).await.unwrap() else {
                            panic!("expected upload.file");
                        };
                        assert_eq!(f.bytes.len(), PART);
                    }
                }
            })
        })
        .collect();
    for w in workers {
        w.await.unwrap();
    }
    (TRANSFER_PARTS * PART) as f64 / (1 << 20) as f64 / start.elapsed().as_secs_f64()
}

async fn bench(latency_ms: u64) {
    let mock = MockDc::start(Duration::from_millis(latency_ms));
    let client = Client::builder("bench", 1, "bench").session_string(mock.session_string()).connect().await.unwrap();

    for depth in [1, 16, 256] {
        report(&format!("rpc_get_state_d{depth}"), latency_ms, requests(&client, depth, false).await, "req/s");
    }
    report("ping_d16", latency_ms, requests(&client, 16, true).await, "req/s");

    let seen = Arc::new(AtomicU64::new(0));
    let echo = Arc::new(AtomicBool::new(false));
    let (s, e) = (seen.clone(), echo.clone());
    client.on_message(filters::all(), move |m| {
        s.fetch_add(1, Ordering::Relaxed);
        let echo = e.load(Ordering::Relaxed);
        async move {
            if echo {
                m.reply("pong").await?;
            }
            Ok(())
        }
    });
    let states = mock.stats.states.load(Ordering::Relaxed);
    let runner = tokio::spawn({
        let client = client.clone();
        async move { client.run().await }
    });
    // run() is ready once get_me and getState are answered; updates pushed before that are
    // older than the state and get skipped.
    while mock.stats.states.load(Ordering::Relaxed) == states {
        assert!(!runner.is_finished(), "run() failed");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    tokio::time::sleep(Duration::from_millis(2 * latency_ms + 10)).await;
    pushed(&mock, || seen.load(Ordering::Relaxed), PUSH_BATCH).await;

    report("updates", latency_ms, pushed(&mock, || seen.load(Ordering::Relaxed), UPDATES).await, "updates/s");
    echo.store(true, Ordering::Relaxed);
    let stats = mock.stats.clone();
    report("echo", latency_ms, pushed(&mock, || stats.sent.load(Ordering::Relaxed), ECHOES).await, "round trips/s");
    echo.store(false, Ordering::Relaxed);

    measured_transfer(&client, true, latency_ms).await;
    measured_transfer(&client, false, latency_ms).await;
    assert_eq!(mock.stats.parts_saved.load(Ordering::Relaxed), (TRANSFER_PARTS * TRANSFER_ROUNDS) as u64);
    runner.abort();
    report_rss(&format!("after_{latency_ms}ms"));
}

fn main() {
    report_rss("start");
    let rt = tokio::runtime::Runtime::new().unwrap();
    for latency in LATENCIES_MS {
        rt.block_on(bench(latency));
    }
}
