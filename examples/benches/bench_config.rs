pub const DEFAULT_LOG_TRACE_HEIGHTS: &[usize] = &[16, 17, 18];

pub fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_list_usize(name: &str) -> Option<Vec<usize>> {
    match std::env::var(name) {
        Ok(raw) => {
            Some(raw.split(',').filter_map(|val| val.trim().parse::<usize>().ok()).collect())
        },
        Err(_) => None,
    }
}

pub fn trace_sizes() -> Vec<usize> {
    if let Some(logs) = env_list_usize("WINTERFELL_LOG_TRACE_HEIGHTS") {
        return logs.into_iter().map(|log_n| 1usize << log_n).collect();
    }
    if let Some(sizes) = env_list_usize("WINTERFELL_TRACE_SIZES") {
        return sizes;
    }
    DEFAULT_LOG_TRACE_HEIGHTS.iter().map(|log_n| 1usize << log_n).collect()
}
