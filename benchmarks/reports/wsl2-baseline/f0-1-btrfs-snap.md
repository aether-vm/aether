# F0-1

## Environment header

> **Authority: `AdvisoryWsl2`** - WSL2 = nested virtualisation + loop devices on ext4-on-VHDX + host page cache beneath. Valid for functional/crash-semantics conclusions; latency/throughput numbers MUST NOT be published as baselines (docs/PHASE0_FALSIFICATION.md section 1).

| Field | Value |
| --- | --- |
| Collected at (UTC) | 2026-11-16T08:59:52Z |
| Declared host hardware | Surface Pro 8, i5-1135G7, 16 GiB RAM (as declared in docs/PHASE0_FALSIFICATION.md section 1.1; not verifiable from inside WSL2) |
| CPU (as seen by guest) | 8 x 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz |
| Memory | 7942 MiB total, 7437 MiB available |
| Page cache at start | Cached 856 MiB, Dirty 19588 KiB |
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
| Command | ./target/release/phase0-harness f0-1-btrfs-snap --subvols 500 --baseline-secs 3 |


# F0-1 - Btrfs concurrent snapshot / destroy vs same-pool `redb` commits

## Parameters

- pool: Btrfs on loop (`direct_io=true`), 3072 MiB; subvolumes: 500 (alternating read-only/writable); template subvol: 200 x 16 KiB files
- background load: 4 KiB random `pwrite` into a 256 MiB file with `fdatasync` every 64 writes (84608 writes total)
- redb: one commit per 2 ms per DB (128 B value, `Durability::Immediate`); DB#1 on the Btrfs pool, DB#2 on host ext4 (control)
- qgroups disabled: **true** (`btrfs qgroup show`: `ERROR: can't list qgroups: quotas not enabled`)
- Btrfs FS_INFO: nodesize 16384, sectorsize 4096, clone_alignment 4096, devices 1, generation 0
- destroy API used: V2

## Snapshot / destroy call latency

| Series | n | p50 (ms) | p90 (ms) | p99 (ms) | max (ms) | mean (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SNAP_CREATE_V2 (all) | 500 | 25.9 | 48.5 | 67.6 | 1512 | 33.0 |
| SNAP_CREATE_V2 (read-only) | 250 | 25.8 | 49.6 | 70.8 | 1512 | 36.2 |
| SNAP_CREATE_V2 (writable) | 250 | 26.0 | 48.1 | 61.1 | 75.2 | 29.8 |
| SNAP_DESTROY_V2 | 500 | 0.014 | 0.020 | 0.042 | 0.118 | 0.015 |

- total create wall time: 16.51 s (30 snaps/s); total destroy wall time: 0.01 s (63762 destroys/s)
- async cleaner drain (`btrfs subvolume sync`): 13.02 s
- free space: before 2499 MiB, after create 2413 MiB, after drain 2357 MiB

## `redb` commit latency by phase

| Series | n | p50 (ms) | p90 (ms) | p99 (ms) | max (ms) | mean (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| redb on **pool** (btrfs) / baseline | 170 | 14.2 | 20.4 | 28.6 | 32.9 | 15.4 |
| redb on host (ext4 control) / baseline | 729 | 1.570 | 2.851 | 8.952 | 18.0 | 1.996 |
| redb on **pool** (btrfs) / create | 518 | 23.5 | 44.1 | 55.2 | 1520 | 29.7 |
| redb on host (ext4 control) / create | 3275 | 1.849 | 3.965 | 10.6 | 1480 | 2.912 |
| redb on **pool** (btrfs) / destroy | 1 | 12.4 | 12.4 | 12.4 | 12.4 | 12.4 |
| redb on host (ext4 control) / destroy | 2 | 1.827 | 1.871 | 1.871 | 1.871 | 1.849 |
| redb on **pool** (btrfs) / settle | 631 | 13.0 | 23.6 | 46.6 | 1401 | 20.1 |
| redb on host (ext4 control) / settle | 2698 | 1.686 | 2.893 | 9.313 | 724 | 3.076 |

## Verdict

**PIVOT TRIGGERED (advisory, WSL2)**: same-pool redb commit P99 reached 55.2 ms (> 50 ms) during snapshot churn -> `meta/aether.redb` must live outside the Btrfs data pool.
