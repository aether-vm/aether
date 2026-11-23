# F0-8

## Environment header

> **Authority: `AdvisoryWsl2`** - WSL2 = nested virtualisation + loop devices on ext4-on-VHDX + host page cache beneath. Valid for functional/crash-semantics conclusions; latency/throughput numbers MUST NOT be published as baselines (docs/PHASE0_FALSIFICATION.md section 1).

| Field | Value |
| --- | --- |
| Collected at (UTC) | 2026-11-23T11:13:10Z |
| Declared host hardware | Surface Pro 8, i5-1135G7, 16 GiB RAM (as declared in docs/PHASE0_FALSIFICATION.md section 1.1; not verifiable from inside WSL2) |
| CPU (as seen by guest) | 8 x AMD Ryzen 7 5800H with Radeon Graphics |
| Memory | 15995 MiB total, 15294 MiB available |
| Page cache at start | Cached 1246 MiB, Dirty 51544 KiB |
| Kernel | 6.18.58.1-microsoft-standard-WSL2 (WSL2: true) |
| Kernel version line | Linux version 6.18.58.1-microsoft-standard-WSL2 (root@6869314ecc53) (gcc (GCC) 13.2.0, GNU ld (GNU Binutils) 2.41) #1 SMP PREEMPT_DYNAMIC Tue Oct 27 00:24:11 UTC 2026 |
| boot_id | 7b1c3663-5615-4fc4-8c36-3e39119c4bfb |
| euid / /dev/kvm | 0 / true |
| Pool root | /var/lib/forkloom/phase0 (fs: ext2/3/4) |
| Power state | BAT1: status=Not charging online=unknown; AC1: status=unknown online=1 |
| rustc | unavailable |
| btrfs-progs | btrfs-progs v6.6.3 |
| xfsprogs (mkfs.xfs) | mkfs.xfs version 6.6.0 |
| e2fsprogs (mkfs.ext4) | mke2fs 1.47.0 (5-Feb-2023) |
| git | git version 2.43.0 |
| losetup | losetup from util-linux 2.39.3 |
| firecracker | Firecracker v1.10.1 |
| Command | ./target/release/phase0-harness --root /var/lib/forkloom/phase0 --out benchmarks/reports/wsl2-ryzen5800h f0-8-kill9-recovery --rounds 100 --meta-dir /var/lib/forkloom/phase0/f0-8-meta --pool-dir /var/lib/forkloom/phase0/f0-8-btrfs-mnt/pool --tmpfs-dir /var/lib/forkloom/phase0/f0-8-tmpfs-mnt/volatile --allow-same-fs false --cgroup-root /sys/fs/cgroup/forkloom-f08 --max-kill-delay-ms 180 --reboot-every 20 |


## F0-8: `kill -9` Fault Injection & Zero-Orphan Recovery (`aos-meta` R0~R6)

- Verdict: **PASS** (100 rounds completed, cgroup_v2_active=true, live_orphans_killed_by_r2=100, allow_same_fs=false)
- Recovery activity: preparing_rolled_back=**193**, deleting_completed=**37**, worlds_marked_lost=**106**, orphans_quarantined=**10**, simulated_reboots=**5**, final_committed=**26**
- R6 circuit-breaker probe (8 injected wild orphans): tripped=**true**, objects_untouched=**true**

### Zero-Leak Invariants

| Invariant | Observed | Required |
| --- | ---: | ---: |
| Leaked child processes | 0 | 0 |
| Leaked netns/veth | 0 | 0 |
| Unrecorded orphan objects | 0 | 0 |
| Lost committed frames | 0 | 0 |
| Non-committed survivors | 0 | 0 |
| Running worlds after recovery | 0 | 0 |
| Missing committed objects | 0 | 0 |

### `MetaEngine::open_and_recover` Latency

| Series | n | p50 (ms) | p90 (ms) | p99 (ms) | max (ms) | mean (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| open_and_recover (R0~R6) | 100 | 32.9 | 47.7 | 68.5 | 70.9 | 36.1 |

