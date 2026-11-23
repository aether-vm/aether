# F0-5

## Environment header

> **Authority: `AdvisoryWsl2`** - WSL2 = nested virtualisation + loop devices on ext4-on-VHDX + host page cache beneath. Valid for functional/crash-semantics conclusions; latency/throughput numbers MUST NOT be published as baselines (docs/PHASE0_FALSIFICATION.md section 1).

| Field | Value |
| --- | --- |
| Collected at (UTC) | 2026-11-23T11:26:22Z |
| Declared host hardware | Surface Pro 8, i5-1135G7, 16 GiB RAM (as declared in docs/PHASE0_FALSIFICATION.md section 1.1; not verifiable from inside WSL2) |
| CPU (as seen by guest) | 8 x AMD Ryzen 7 5800H with Radeon Graphics |
| Memory | 15995 MiB total, 15071 MiB available |
| Page cache at start | Cached 1152 MiB, Dirty 3484 KiB |
| Kernel | 6.18.58.1-microsoft-standard-WSL2 (WSL2: true) |
| Kernel version line | Linux version 6.18.58.1-microsoft-standard-WSL2 (root@6869314ecc53) (gcc (GCC) 13.2.0, GNU ld (GNU Binutils) 2.41) #1 SMP PREEMPT_DYNAMIC Tue Oct 27 00:24:11 UTC 2026 |
| boot_id | b871cc91-4480-40a8-a01f-02468bae95b4 |
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
| Command | ./target/release/phase0-harness --root /var/lib/forkloom/phase0 --out benchmarks/reports/wsl2-ryzen5800h f0-5-fc-restore --firecracker-bin /usr/local/bin/firecracker --snapshot-path /var/lib/forkloom/phase0/snaps/f05_f06/vmstate --mem-file-path /var/lib/forkloom/phase0/snaps/f05_f06/mem.img --vsock-uds ./v.sock --vsock-port 5000 --probe-argv /bin/uname,-r --vm-mem-mib 512 --reps 5 |


## F0-5: Firecracker Restore -> First `aos-guest` vsock Command Latency

- VM memory: **512 MiB**, repetitions/tier: **5**
- Cold-restore `mincore` working set: **18596 / 131072** pages (14.2%, 4 extents, 72.64 MiB)
- Cold vs Hot page-fault penalty (p50): **2.12x**
- `mincore + fadvise(WILLNEED)` honest total speedup including prewarm (p50): **1.09x**
- `mincore + fadvise(WILLNEED)` restore-only speedup excluding prewarm (p50): **1.27x**

### Honest Total Cold-to-Ready Latency (`fadvise_prewarm + restore -> first vsock reply`)

| Series | n | p50 (ms) | p90 (ms) | p99 (ms) | max (ms) | mean (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cold_cache (drop_caches) | 5 | 90.8 | 93.7 | 93.7 | 93.7 | 91.6 |
| hot_cache (warm page cache) | 5 | 42.9 | 43.7 | 43.7 | 43.7 | 42.7 |
| mincore + fadvise(WILLNEED) | 5 | 83.4 | 96.0 | 96.0 | 96.0 | 86.4 |

### Post-Prewarm Restore -> First vsock Reply Latency (`PUT /snapshot/load -> reply`)

| Series | n | p50 (ms) | p90 (ms) | p99 (ms) | max (ms) | mean (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cold_cache (drop_caches) | 5 | 90.8 | 93.7 | 93.7 | 93.7 | 91.6 |
| hot_cache (warm page cache) | 5 | 42.9 | 43.7 | 43.7 | 43.7 | 42.7 |
| mincore + fadvise(WILLNEED) | 5 | 71.6 | 80.8 | 80.8 | 80.8 | 74.2 |

### VMM `PUT /snapshot/load` API Return Time (NOT guest readiness)

| Series | n | p50 (ms) | p90 (ms) | p99 (ms) | max (ms) | mean (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cold_cache (drop_caches) | 5 | 22.4 | 23.0 | 23.0 | 23.0 | 22.4 |
| hot_cache (warm page cache) | 5 | 2.320 | 2.487 | 2.487 | 2.487 | 2.334 |
| mincore + fadvise(WILLNEED) | 5 | 10.8 | 11.8 | 11.8 | 11.8 | 11.1 |

