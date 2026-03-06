#[cfg(target_os = "linux")]
use std::collections::HashSet;

#[cfg(target_os = "linux")]
fn parse_cpu_list(spec: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for token in spec.trim().split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((start, end)) = token.split_once('-') {
            let Ok(start) = start.trim().parse::<usize>() else {
                continue;
            };
            let Ok(end) = end.trim().parse::<usize>() else {
                continue;
            };
            if start <= end {
                for cpu in start..=end {
                    cpus.push(cpu);
                }
            } else {
                for cpu in end..=start {
                    cpus.push(cpu);
                }
            }
        } else if let Ok(cpu) = token.parse::<usize>() {
            cpus.push(cpu);
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    cpus
}

#[cfg(target_os = "linux")]
pub fn read_cpu_list_from_status(status: &str) -> Option<Vec<usize>> {
    let line = status
        .lines()
        .find(|line| line.starts_with("Cpus_allowed_list:"))?;
    let (_, list) = line.split_once(':')?;
    let parsed = parse_cpu_list(list);
    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

#[cfg(target_os = "linux")]
pub fn collect_cpu_ids_from_status_blobs<'a, I>(statuses: I) -> Vec<usize>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut union = HashSet::new();
    for status in statuses {
        let Some(cpus) = read_cpu_list_from_status(status) else {
            continue;
        };
        for cpu in cpus {
            union.insert(cpu);
        }
    }
    let mut cpus: Vec<usize> = union.into_iter().collect();
    cpus.sort_unstable();
    cpus
}

#[cfg(target_os = "linux")]
fn process_allowed_cpu_ids() -> Vec<usize> {
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    let mut statuses = Vec::new();
    for entry in tasks.flatten() {
        let status_path = entry.path().join("status");
        let Ok(status) = std::fs::read_to_string(status_path) else {
            continue;
        };
        statuses.push(status);
    }
    collect_cpu_ids_from_status_blobs(statuses.iter().map(String::as_str))
}

#[cfg(target_os = "linux")]
fn allowed_cpu_ids(max_workers: usize) -> Vec<usize> {
    let process_allowed = process_allowed_cpu_ids();
    if !process_allowed.is_empty() {
        return process_allowed;
    }
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        if let Some(parsed) = read_cpu_list_from_status(&status) {
            return parsed;
        }
    }
    (0..max_workers.max(1)).collect()
}

#[cfg(target_os = "linux")]
fn thread_siblings(cpu: usize) -> Vec<usize> {
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
    if let Ok(raw) = std::fs::read_to_string(path) {
        let parsed = parse_cpu_list(&raw);
        if !parsed.is_empty() {
            return parsed;
        }
    }
    vec![cpu]
}

#[cfg(target_os = "linux")]
pub fn choose_dpdk_worker_core_ids(requested_workers: usize, max_workers: usize) -> Vec<usize> {
    let allowed = allowed_cpu_ids(max_workers);
    if allowed.is_empty() {
        return vec![0];
    }
    let allowed_set: HashSet<usize> = allowed.iter().copied().collect();
    let mut seen = HashSet::new();
    let mut slots: Vec<Vec<usize>> = Vec::new();
    for cpu in &allowed {
        if seen.contains(cpu) {
            continue;
        }
        let mut siblings = thread_siblings(*cpu);
        siblings.retain(|id| allowed_set.contains(id));
        siblings.sort_unstable();
        siblings.dedup();
        if siblings.is_empty() {
            siblings.push(*cpu);
        }
        for id in &siblings {
            seen.insert(*id);
        }
        slots.push(siblings);
    }
    if slots.is_empty() {
        return vec![allowed[0]];
    }

    let target = requested_workers.max(1).min(allowed.len());
    let mut selected = Vec::with_capacity(target);
    let mut selected_set = HashSet::new();

    for slot in &slots {
        let cpu = slot[0];
        if selected_set.insert(cpu) {
            selected.push(cpu);
            if selected.len() == target {
                return selected;
            }
        }
    }

    let mut level = 1usize;
    while selected.len() < target {
        let mut added = false;
        for slot in &slots {
            if level < slot.len() {
                let cpu = slot[level];
                if selected_set.insert(cpu) {
                    selected.push(cpu);
                    added = true;
                    if selected.len() == target {
                        return selected;
                    }
                }
            }
        }
        if !added {
            break;
        }
        level += 1;
    }

    for cpu in allowed {
        if selected_set.insert(cpu) {
            selected.push(cpu);
            if selected.len() == target {
                break;
            }
        }
    }

    if selected.is_empty() {
        selected.push(0);
    }
    selected
}

#[cfg(not(target_os = "linux"))]
pub fn choose_dpdk_worker_core_ids(requested_workers: usize, max_workers: usize) -> Vec<usize> {
    let target = requested_workers.max(1).min(max_workers.max(1));
    (0..target).collect()
}

#[cfg(target_os = "linux")]
pub fn cpu_core_count() -> usize {
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if count > 0 {
        return count as usize;
    }
    std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1)
}

#[cfg(not(target_os = "linux"))]
pub fn cpu_core_count() -> usize {
    std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1)
}

#[cfg(target_os = "linux")]
pub fn pin_thread_to_core(core_id: usize) -> Result<(), String> {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core_id, &mut set);
        let rc = libc::pthread_setaffinity_np(
            libc::pthread_self(),
            std::mem::size_of::<libc::cpu_set_t>(),
            &set,
        );
        if rc != 0 {
            return Err(format!("pthread_setaffinity_np failed: {rc}"));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn pin_thread_to_core(_core_id: usize) -> Result<(), String> {
    Ok(())
}
