# ENV

## Environment header

> **Authority: `AdvisoryWsl2`** - WSL2 = nested virtualisation + loop devices on ext4-on-VHDX + host page cache beneath. Valid for functional/crash-semantics conclusions; latency/throughput numbers MUST NOT be published as baselines (docs/PHASE0_FALSIFICATION.md section 1).

| Field | Value |
| --- | --- |
| Collected at (UTC) | 2026-11-16T08:59:52Z |
| Declared host hardware | Surface Pro 8, i5-1135G7, 16 GiB RAM (as declared in docs/PHASE0_FALSIFICATION.md section 1.1; not verifiable from inside WSL2) |
| CPU (as seen by guest) | 8 x 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz |
| Memory | 7942 MiB total, 7438 MiB available |
| Page cache at start | Cached 856 MiB, Dirty 19392 KiB |
| Kernel | 6.6.87.2-microsoft-standard-WSL2 (WSL2: true) |
| Kernel version line | Linux version 6.6.87.2-microsoft-standard-WSL2 (root@439a258ad544) (gcc (GCC) 11.2.0, GNU ld (GNU Binutils) 2.37) #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 |
| boot_id | 463b5974-ab7f-4309-843d-6f0dc4d057de |
| euid / /dev/kvm | 0 / true |
| Pool root | /var/lib/aether/phase0 (fs: ext2/3/4) |
| Power state | BAT1: status=Discharging online=unknown; AC1: status=unknown online=1 |
| rustc | unavailable |
| btrfs-progs | btrfs-progs v5.16.2 |
| xfsprogs (mkfs.xfs) | mkfs.xfs version 5.13.0 |
| e2fsprogs (mkfs.ext4) | mke2fs 1.46.5 (30-Dec-2021) |
| git | git version 2.34.1 |
| losetup | losetup from util-linux 2.37.2 |
| firecracker | Firecracker v1.10.1 |
| Command | ./target/release/phase0-harness env |


Environment header only (no experiment run).
