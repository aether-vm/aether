//! Markdown + JSON report writing.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::env::EnvHeader;
use crate::stats::Dist;
use crate::util::fmt_ms;

/// Output of one experiment.
#[derive(Debug, Clone)]
pub struct ExpOutput {
    /// Experiment id, e.g. `F0-1`.
    pub id: &'static str,
    /// File stem, e.g. `f0-1-btrfs-snap`.
    pub slug: &'static str,
    /// Machine readable result.
    pub json: Value,
    /// Markdown body (experiment specific; the env header is prepended by [`write_report`]).
    pub md: String,
}

/// Write `<slug>.json` and `<slug>.md` into `out_dir`.
pub fn write_report(out_dir: &Path, out: &ExpOutput, env: &EnvHeader) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    let jp = out_dir.join(format!("{}.json", out.slug));
    let mp = out_dir.join(format!("{}.md", out.slug));
    let doc = json!({ "experiment": out.id, "env": env, "result": out.json });
    std::fs::write(&jp, serde_json::to_string_pretty(&doc)? + "\n")?;
    let md = format!("# {}\n\n{}\n{}", out.id, env.to_markdown(), out.md);
    std::fs::write(&mp, md)?;
    Ok((jp, mp))
}

/// Markdown table row `| label | n | p50 | p90 | p99 | max | mean |` in milliseconds.
#[must_use]
pub fn dist_row(label: &str, d: &Dist) -> String {
    format!(
        "| {label} | {} | {} | {} | {} | {} | {} |\n",
        d.n,
        fmt_ms(d.p50_us),
        fmt_ms(d.p90_us),
        fmt_ms(d.p99_us),
        fmt_ms(d.max_us),
        fmt_ms(d.mean_us)
    )
}

/// Header matching [`dist_row`].
pub const DIST_HEADER: &str =
    "| Series | n | p50 (ms) | p90 (ms) | p99 (ms) | max (ms) | mean (ms) |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dist_row_matches_header_columns() {
        let d = Dist::from_us(vec![1000.0, 2000.0, 3000.0]);
        let row = dist_row("x", &d);
        assert_eq!(row.matches('|').count(), DIST_HEADER.lines().next().unwrap().matches('|').count());
        assert!(row.contains("2.000"));
    }

    #[test]
    fn write_report_creates_both_files() {
        let dir = std::env::temp_dir().join(format!("p0-report-{}", std::process::id()));
        let env = EnvHeader::collect(Path::new("/tmp"), vec![]);
        let out = ExpOutput { id: "F0-X", slug: "f0-x", json: json!({"a": 1}), md: "body\n".into() };
        let (j, m) = write_report(&dir, &out, &env).unwrap();
        assert!(std::fs::read_to_string(j).unwrap().contains("\"experiment\": \"F0-X\""));
        assert!(std::fs::read_to_string(m).unwrap().contains("body"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
