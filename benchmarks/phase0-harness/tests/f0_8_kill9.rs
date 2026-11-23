//! End-to-end multi-process `F0-8` crash-injection integration test.
//!
//! Spawns the real compiled `phase0-harness f0-8-worker` binary against a real `meta/`, `pool/`,
//! and `tmpfs/` layout, randomly kills it (`SIGKILL` on Linux, `TerminateProcess` via `Child::kill`
//! on Windows), runs `MetaEngine::open_and_recover`, and asserts zero leaks and zero lost frames.

use std::path::PathBuf;

use phase0_harness::env::EnvHeader;
use phase0_harness::exp_f0_8::{self, Args};
use phase0_harness::report::write_report;
use phase0_harness::Ctx;

#[test]
fn f0_8_multiprocess_kill9_recovery_zero_orphans_zero_lost_frames() {
    let base = std::env::temp_dir().join(format!(
        "forkloom-f08-integ-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    let out_dir = base.join("reports");

    let ctx = Ctx {
        root: base.clone(),
        out: out_dir.clone(),
        max_pool_gib: 1,
        seed: 0xF008_CAFE,
    };
    let args = Args {
        rounds: 15,
        meta_dir: base.join("meta"),
        pool_dir: base.join("pool"),
        tmpfs_dir: base.join("tmpfs"),
        max_kill_delay_ms: 25,
        reboot_every: 5,
        allow_same_fs: true,
        cgroup_root: None,
        worker_exe: Some(PathBuf::from(env!("CARGO_BIN_EXE_phase0-harness"))),
    };

    let out = exp_f0_8::run(&ctx, &args).expect("F0-8 run should succeed");
    assert_eq!(out.id, "F0-8");
    assert_eq!(out.slug, "f0-8-kill9-recovery");
    assert_eq!(
        out.json["passed"],
        true,
        "F0-8 failed: {:?}",
        out.json["failures"]
    );
    assert_eq!(out.json["rounds_completed"], 15);
    assert_eq!(out.json["leaked_processes"], 0);
    assert_eq!(out.json["leaked_netns"], 0);
    assert_eq!(out.json["unrecorded_orphans"], 0);
    assert_eq!(out.json["lost_committed_frames"], 0);
    assert_eq!(out.json["non_committed_survivors"], 0);
    assert_eq!(out.json["running_worlds_after_recovery"], 0);
    assert_eq!(out.json["missing_committed_objects"], 0);
    assert_eq!(out.json["breaker_probe"]["breaker_tripped"], true);
    assert_eq!(out.json["breaker_probe"]["objects_untouched"], true);
    assert!(
        out.json["total_reboots"].as_u64().unwrap() >= 3,
        "expected >= 3 simulated reboots"
    );

    // Verify JSON + Markdown report writing works end-to-end.
    let env = EnvHeader::collect(&base, vec!["phase0-harness".into(), "f0-8-kill9-recovery".into()]);
    let (jpath, mpath) = write_report(&out_dir, &out, &env).expect("write_report");
    let json_text = std::fs::read_to_string(&jpath).unwrap();
    let md_text = std::fs::read_to_string(&mpath).unwrap();
    assert!(json_text.contains("\"experiment\": \"F0-8\""));
    assert!(md_text.contains("Zero-Leak Invariants"));
    assert!(md_text.contains("Verdict: **PASS**"));

    let _ = std::fs::remove_dir_all(&base);
}
