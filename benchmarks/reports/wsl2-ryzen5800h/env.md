# ENV

## Environment header

> **Authority: `AdvisoryWsl2`** - WSL2 = nested virtualisation + loop devices on ext4-on-VHDX + host page cache beneath. Valid for functional/crash-semantics conclusions; latency/throughput numbers MUST NOT be published as baselines (docs/PHASE0_FALSIFICATION.md section 1).

| Field | Value |
| --- | --- |
| Collected at (UTC) | 2026-11-23T11:12:35Z |
| Declared host hardware | Surface Pro 8, i5-1135G7, 16 GiB RAM (as declared in docs/PHASE0_FALSIFICATION.md section 1.1; not verifiable from inside WSL2) |
| CPU (as seen by guest) | 8 x AMD Ryzen 7 5800H with Radeon Graphics |
| Memory | 15995 MiB total, 15295 MiB available |
| Page cache at start | Cached 1040 MiB, Dirty 121332 KiB |
| Kernel | 6.18.58.1-microsoft-standard-WSL2 (WSL2: true) |
| Kernel version line | Linux version 6.18.58.1-microsoft-standard-WSL2 (root@6869314ecc53) (gcc (GCC) 13.2.0, GNU ld (GNU Binutils) 2.41) #1 SMP PREEMPT_DYNAMIC Tue Oct 27 00:24:11 UTC 2026 |
| boot_id | 7b1c3663-5615-4fc4-8c36-3e39119c4bfb |
| euid / /dev/kvm | 0 / true |
| Pool root | /var/lib/forkloom/phase0 (fs: ext2/3/4) |
| Power state | BAT1: status=Not charging online=unknown; AC1: status=unknown online=1 |
| rustc | rustc 1.100.0 (0ef1bc386 2026-11-09) |
| btrfs-progs | btrfs-progs v6.6.3 |
| xfsprogs (mkfs.xfs) | mkfs.xfs version 6.6.0 |
| e2fsprogs (mkfs.ext4) | mke2fs 1.47.0 (5-Feb-2023) |
| git | git version 2.43.0 |
| losetup | losetup from util-linux 2.39.3 |
| firecracker | Firecracker v1.10.1 |
| Command | ./target/release/phase0-harness --root /var/lib/forkloom/phase0 --out benchmarks/reports/wsl2-ryzen5800h env |


Environment header only (no experiment run).
