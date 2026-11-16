# F0-2

## Environment header

> **Authority: `AdvisoryWsl2`** - WSL2 = nested virtualisation + loop devices on ext4-on-VHDX + host page cache beneath. Valid for functional/crash-semantics conclusions; latency/throughput numbers MUST NOT be published as baselines (docs/PHASE0_FALSIFICATION.md section 1).

| Field | Value |
| --- | --- |
| Collected at (UTC) | 2026-11-16T09:00:27Z |
| Declared host hardware | Surface Pro 8, i5-1135G7, 16 GiB RAM (as declared in docs/PHASE0_FALSIFICATION.md section 1.1; not verifiable from inside WSL2) |
| CPU (as seen by guest) | 8 x 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz |
| Memory | 7942 MiB total, 7449 MiB available |
| Page cache at start | Cached 860 MiB, Dirty 248 KiB |
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
| Command | ./target/release/phase0-harness f0-2-ficlone-matrix --extents 1000,10000,50000 --dirty-mib 0,128 --reps 3 |


# F0-2 - `FICLONE + fsync` pause on fragmented block images

## Parameters

- pools: Btrfs and XFS (`reflink=1`, crc=1), 3072 MiB each, loop `direct_io` = true
- source image: `N` extents = N x 4 KiB random-order writes at 8 KiB stride (holes prevent merging); extents verified by `BTRFS_IOC_TREE_SEARCH` (key 108) / `fsx_nextents` and cross-checked with FIEMAP
- dirty page cache: the last `D` MiB of the source image rewritten (not synced) before every clone; system `Dirty:` sampled right before the clone
- repetitions per cell: 3; extents [1000, 10000, 50000]; dirty MiB [0, 128]
- `btrfs-nocow`: `FS_IOC_SETFLAGS(+FS_NOCOW_FL)` applied to the empty source *and* destination before any data (Btrfs refuses clone between NOCOW and COW inodes)
- not measured here: ext4 *inside* the image (irrelevant to extent layout), 100k extents and 1 GiB dirty (pool-size / laptop safety), XFS `cowextsize` hint (default used)

## Results (milliseconds)

| Backend | extents req. | exact extents (before / after) | FIEMAP before | dirty MiB | Dirty KiB max | reps ok | FICLONE p50 | fsync p50 | **total p50** | total p99 | total max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| btrfs-cow | 1000 | 1000 / 1000 | 1000 | 0 | 700 | 3 | 8.158 | 36.0 | **44.1** | 54.0 | 54.0 |
| btrfs-cow | 1000 | 1000 / 1001 | 1000 | 128 | 131768 | 3 | 106 | 14.1 | **120** | 141 | 141 |
| btrfs-cow | 10000 | 10000 / 10000 | 10000 | 0 | 1680 | 3 | 42.8 | 51.8 | **87.5** | 142 | 142 |
| btrfs-cow | 10000 | 10000 / 10001 | 10000 | 128 | 132556 | 3 | 149 | 54.7 | **191** | 312 | 312 |
| btrfs-cow | 50000 | 50000 / 50000 | 50000 | 0 | 11572 | 3 | 179 | 223 | **405** | 429 | 429 |
| btrfs-cow | 50000 | 50000 / 50001 | 50000 | 128 | 142684 | 3 | 275 | 183 | **477** | 490 | 490 |
| btrfs-nocow | 1000 | 1000 / 1000 | 1000 | 0 | 580 | 3 | 2.889 | 10.9 | **13.8** | 20.9 | 20.9 |
| btrfs-nocow | 1000 | 1000 / 1001 | 1000 | 128 | 131508 | 3 | 89.0 | 14.8 | **104** | 140 | 140 |
| btrfs-nocow | 10000 | 10000 / 10000 | 10000 | 0 | 2560 | 3 | 31.5 | 55.4 | **86.9** | 131 | 131 |
| btrfs-nocow | 10000 | 10000 / 10001 | 10000 | 128 | 133480 | 3 | 122 | 42.9 | **164** | 260 | 260 |
| btrfs-nocow | 50000 | 50000 / 50000 | 50000 | 0 | 10400 | 3 | 172 | 269 | **434** | 452 | 452 |
| btrfs-nocow | 50000 | 50000 / 50001 | 50000 | 128 | 141104 | 3 | 290 | 219 | **516** | 519 | 519 |
| xfs-reflink | 1000 | 1000 / 1000 | 1000 | 0 | 380 | 3 | 7.927 | 6.313 | **12.9** | 26.7 | 26.7 |
| xfs-reflink | 1000 | 1000 / 1002 | 1000 | 128 | 131396 | 3 | 106 | 18.2 | **121** | 131 | 131 |
| xfs-reflink | 10000 | 10000 / 10000 | 10000 | 0 | 16 | 3 | 115 | 21.6 | **136** | 554 | 554 |
| xfs-reflink | 10000 | 10000 / 10002 | 10000 | 128 | 131088 | 3 | 173 | 24.7 | **195** | 207 | 207 |
| xfs-reflink | 50000 | 50000 / 50000 | 50000 | 0 | 8 | 3 | 412 | 43.2 | **455** | 2369 | 2369 |
| xfs-reflink | 50000 | 50000 / 50002 | 50000 | 128 | 131100 | 3 | 1601 | 18.9 | **1620** | 1628 | 1628 |

## Verdict

Gate cell: 50000 extents, dirty 0 MiB: Btrfs-CoW p50 405.1 ms vs XFS p50 455.2 ms (threshold: Btrfs > 100 ms AND XFS significantly lower, i.e. < 50 % of Btrfs). => **no pivot triggered** (advisory, WSL2 loop-on-ext4-on-VHDX; re-verify on bare metal).
