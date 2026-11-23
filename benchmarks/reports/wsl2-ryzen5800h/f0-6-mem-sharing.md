# F0-6

## Environment header

> **Authority: `AdvisoryWsl2`** - WSL2 = nested virtualisation + loop devices on ext4-on-VHDX + host page cache beneath. Valid for functional/crash-semantics conclusions; latency/throughput numbers MUST NOT be published as baselines (docs/PHASE0_FALSIFICATION.md section 1).

| Field | Value |
| --- | --- |
| Collected at (UTC) | 2026-11-23T11:26:20Z |
| Declared host hardware | Surface Pro 8, i5-1135G7, 16 GiB RAM (as declared in docs/PHASE0_FALSIFICATION.md section 1.1; not verifiable from inside WSL2) |
| CPU (as seen by guest) | 8 x AMD Ryzen 7 5800H with Radeon Graphics |
| Memory | 15995 MiB total, 15190 MiB available |
| Page cache at start | Cached 1151 MiB, Dirty 3360 KiB |
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
| Command | ./target/release/phase0-harness --root /var/lib/forkloom/phase0 --out benchmarks/reports/wsl2-ryzen5800h f0-6-mem-sharing --firecracker-bin /usr/local/bin/firecracker --snapshot-path /var/lib/forkloom/phase0/snaps/f05_f06/vmstate --mem-file-path /var/lib/forkloom/phase0/snaps/f05_f06/mem.img --mother-api-sock /var/lib/forkloom/phase0/snaps/f05_f06/mother.api.sock --vm-mem-mib 512 --clones 4 --volatile-tmpfs-mib 640 --tmpfs-quota-mib 256 --capture-reps 3 --vsock-uds ./v.sock --vsock-port 5000 |


## F0-6: Snapshot Capture Latency & MAP_PRIVATE Physical Sharing

- Verdict: **PASS** (VM memory: **512 MiB**, clones: **4**)
- Aggregate memory: Sum RSS = **62.7 MiB**, Sum PSS = **19.3 MiB**, Shared_Clean = **57.5 MiB**, Private_Dirty = **5.2 MiB**
- Physical sharing: dedup factor = **3.25x**, physical RAM saved = **69.2%**
- `tmpfs` quota probe (256 MiB quota, 288 MiB attempted): graceful_enospc=true, oom_kill_delta=0 (hit ENOSPC cleanly after 256 MiB)

### Snapshot Capture Latency

| Series | n | p50 (ms) | p90 (ms) | p99 (ms) | max (ms) | mean (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Durable (disk pool + fsync) | 3 | 194 | 324 | 324 | 324 | 235 |
| Volatile (quota tmpfs) | 3 | 208 | 213 | 213 | 213 | 209 |

### Per-Clone `/proc/<pid>/smaps_rollup`

| Clone | PID | Load (ms) | RSS (KiB) | PSS (KiB) | Shared_Clean (KiB) | Private_Dirty (KiB) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 432 | 3.15 | 16108 | 4973 | 14764 | 1344 |
| 1 | 437 | 2.93 | 16108 | 4963 | 14764 | 1344 |
| 2 | 441 | 3.00 | 16108 | 4952 | 14764 | 1344 |
| 3 | 445 | 2.98 | 15908 | 4864 | 14588 | 1260 |

