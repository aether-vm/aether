//! Small latency-distribution helper (nearest-rank percentiles).

use std::time::Duration;

use serde::Serialize;

/// Summary of a set of latency samples, in microseconds.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Dist {
    /// Sample count.
    pub n: usize,
    /// Minimum.
    pub min_us: f64,
    /// Median.
    pub p50_us: f64,
    /// 90th percentile.
    pub p90_us: f64,
    /// 99th percentile.
    pub p99_us: f64,
    /// Maximum.
    pub max_us: f64,
    /// Arithmetic mean.
    pub mean_us: f64,
}

/// Nearest-rank percentile of an already **sorted** slice (`p` in `0..=100`).
#[must_use]
pub fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

impl Dist {
    /// Build from microsecond samples.
    #[must_use]
    pub fn from_us(mut v: Vec<f64>) -> Self {
        if v.is_empty() {
            return Self::default();
        }
        v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN latencies"));
        let n = v.len();
        let sum: f64 = v.iter().sum();
        Self {
            n,
            min_us: v[0],
            p50_us: percentile_sorted(&v, 50.0),
            p90_us: percentile_sorted(&v, 90.0),
            p99_us: percentile_sorted(&v, 99.0),
            max_us: v[n - 1],
            mean_us: sum / n as f64,
        }
    }

    /// Build from durations.
    #[must_use]
    pub fn from_durations(v: &[Duration]) -> Self {
        Self::from_us(v.iter().map(|d| d.as_secs_f64() * 1e6).collect())
    }

    /// Compact `p50/p99/max` string in milliseconds.
    #[must_use]
    pub fn ms_summary(&self) -> String {
        format!(
            "{:.3} / {:.3} / {:.3}",
            self.p50_us / 1e3,
            self.p99_us / 1e3,
            self.max_us / 1e3
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_percentiles() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        let d = Dist::from_us(v);
        assert_eq!(d.n, 100);
        assert_eq!(d.min_us, 1.0);
        assert_eq!(d.p50_us, 50.0);
        assert_eq!(d.p90_us, 90.0);
        assert_eq!(d.p99_us, 99.0);
        assert_eq!(d.max_us, 100.0);
        assert!((d.mean_us - 50.5).abs() < 1e-9);
    }

    #[test]
    fn small_and_empty_inputs() {
        let d = Dist::from_us(vec![7.0]);
        assert_eq!((d.p50_us, d.p99_us, d.max_us), (7.0, 7.0, 7.0));
        assert_eq!(Dist::from_us(vec![]).n, 0);
        let d = Dist::from_durations(&[Duration::from_millis(2), Duration::from_millis(1)]);
        assert_eq!(d.min_us, 1000.0);
        assert_eq!(d.max_us, 2000.0);
    }
}
