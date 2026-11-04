//! CPU time of the whole bench process, for the `cpu_ms_per_mib_*` rows; Linux only.

/// One reading of the process's CPU time: the nanoseconds its threads spent on a CPU, summed over every thread's
/// schedstat (the clock the gating rows use), and the user plus system milliseconds from /proc/self/stat at its
/// 10 ms resolution (for a diagnostic row only). `None` off Linux. On Linux it panics when the per-thread
/// schedstat can't be read, so the gating rows never come from a coarser clock.
pub fn sample() -> Option<(u64, Option<u64>)> {
    #[cfg(target_os = "linux")]
    {
        let ns = schedstat_ns().unwrap_or_else(|e| panic!("cpu_ms_per_mib needs /proc/self/task/*/schedstat: {e}"));
        Some((ns, stat_ticks_ms()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn schedstat_ns() -> Result<u64, String> {
    let mut total = 0;
    let threads = std::fs::read_dir("/proc/self/task").map_err(|e| format!("/proc/self/task: {e}"))?;
    for thread in threads {
        let dir = thread.map_err(|e| format!("/proc/self/task: {e}"))?.path();
        let path = dir.join("schedstat");
        let stat = match std::fs::read_to_string(&path) {
            Ok(stat) => stat,
            // A thread that ended after the listing has no time left to count.
            Err(_) if !dir.exists() => continue,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let ns = stat.split_whitespace().next().and_then(|ns| ns.parse::<u64>().ok());
        total += ns.ok_or_else(|| format!("{}: no time on CPU in {stat:?}", path.display()))?;
    }
    Ok(total)
}

#[cfg(target_os = "linux")]
fn stat_ticks_ms() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // utime and stime are fields 14 and 15; the command name before ')' may hold spaces.
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace().skip(11);
    let ticks = fields.next()?.parse::<u64>().ok()? + fields.next()?.parse::<u64>().ok()?;
    // Clock ticks of USER_HZ, which Linux fixes at 100 for everything it exports to user space.
    Some(ticks * 10)
}
