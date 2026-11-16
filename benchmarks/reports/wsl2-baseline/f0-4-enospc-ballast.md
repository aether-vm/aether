# F0-4

## Environment header

> **Authority: `AdvisoryWsl2`** - WSL2 = nested virtualisation + loop devices on ext4-on-VHDX + host page cache beneath. Valid for functional/crash-semantics conclusions; latency/throughput numbers MUST NOT be published as baselines (docs/PHASE0_FALSIFICATION.md section 1).

| Field | Value |
| --- | --- |
| Collected at (UTC) | 2026-11-16T09:02:41Z |
| Declared host hardware | Surface Pro 8, i5-1135G7, 16 GiB RAM (as declared in docs/PHASE0_FALSIFICATION.md section 1.1; not verifiable from inside WSL2) |
| CPU (as seen by guest) | 8 x 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz |
| Memory | 7942 MiB total, 7458 MiB available |
| Page cache at start | Cached 133 MiB, Dirty 224 KiB |
| Kernel | 6.6.87.2-microsoft-standard-WSL2 (WSL2: true) |
| Kernel version line | Linux version 6.6.87.2-microsoft-standard-WSL2 (root@439a258ad544) (gcc (GCC) 11.2.0, GNU ld (GNU Binutils) 2.37) #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 |
| boot_id | 463b5974-ab7f-4309-843d-6f0dc4d057de |
| euid / /dev/kvm | 0 / true |
| Pool root | /var/lib/aether/phase0 (fs: ext2/3/4) |
| Power state | BAT1: status=Full online=unknown; AC1: status=unknown online=1 |
| rustc | unavailable |
| btrfs-progs | btrfs-progs v5.16.2 |
| xfsprogs (mkfs.xfs) | mkfs.xfs version 5.13.0 |
| e2fsprogs (mkfs.ext4) | mke2fs 1.46.5 (30-Dec-2021) |
| git | git version 2.34.1 |
| losetup | losetup from util-linux 2.37.2 |
| firecracker | Firecracker v1.10.1 |
| Command | ./target/release/phase0-harness f0-4-enospc-ballast |


# F0-4 - pool-full (`ENOSPC`) and ballast recovery drill (Btrfs)

## Parameters

- pool: Btrfs on loop (`direct_io=true`), 2048 MiB; ballast 64 MiB (`posix_fallocate`); 2 victim subvolumes (128 MiB total); `redb` in `meta/` on the same pool
- fill: 1 MiB writes into 64 MiB files, then 4 KiB writes, then up to 400k tiny (900 B, inline) files until the first failure

## Space accounting (MiB available per `statvfs`)

| moment | avail MiB |
| --- | ---: |
| pristine (after mount) | 1826 |
| after victims + ballast | 1632 |
| pool full | 0 |
| full, just before ballast release | 0 |
| after ballast release (+sync) | 64 |
| after victim subvolumes destroyed + cleaner drained | 127 |
| after filler removed (final) | 1824 |

Final free space = **99.91 %** of pristine (cleaner drain: destroy 30.0s, final 0.0s; redb file + `post-recovery*` objects account for the remainder).

## Fill outcome

```json
{
  "fill_seconds": 2.506607612,
  "stage1_bulk": {
    "bytes": 1711931392,
    "ended_with": "No space left on device (os error 28)",
    "enospc": true,
    "files": 26
  },
  "stage2_4k": {
    "bytes": 106496,
    "ended_with": "No space left on device (os error 28)",
    "enospc": true
  },
  "stage3_tiny": {
    "ended_with": "No space left on device (os error 28)",
    "enospc": true,
    "files": 0
  }
}
```

`btrfs filesystem df -b` at ENOSPC:

```
Data, single: total=1914961920, used=1914961920
System, DUP: total=8388608, used=16384
Metadata, DUP: total=107347968, used=2277376
GlobalReserve, single: total=5767168, used=0
```

## Probes while the pool is full (ballast still present)

| probe | result | detail |
| --- | :---: | --- |
| redb tombstone txns (64 B values) x20 at ENOSPC | FAIL | 0 committed, 20 failed; first error: I/O error: No space left on device (os error 28) |
| redb growth txns (2 MiB values) x5 at ENOSPC | FAIL | 0 committed, 5 failed; first error: Previous I/O error occurred. Please close and re-open the database. |
| create a second redb file at ENOSPC | FAIL | I/O error: No space left on device (os error 28) |
| destroy subvolume victim-a at ENOSPC (before releasing ballast) | OK | ok via V2 |
| unlink a tiny file at ENOSPC | OK | ok |
| create+write a new 900 B file at ENOSPC (control: expected to fail) | FAIL | No space left on device (os error 28) |

## Recovery after releasing the ballast

| probe | result | detail |
| --- | :---: | --- |
| BTRFS_IOC_SYNC after unlinking ballast | OK | None; avail +64 MiB after 0.00s (ballast 64 MiB) |
| redb reopen + integrity check after the failed-commit episode | OK | integrity=true, 2000 keys |
| redb tombstone txns x20 after ballast release | OK | 20 committed, 0 failed |
| destroy subvolume victim-b after ballast release | OK | ok via V2 |
| remove the filler tree | OK | 0.2s |
| post-recovery: create subvolume / redb commit / write 1 MiB | OK | subvol=true redb=true file=true |

## Verdict

**PIVOT TRIGGERED**: a tombstone-sized redb transaction failed at ENOSPC on the same pool -> `meta/` MUST live on a separate disk/filesystem from the data pool.

Recovery after ballast release fully functional: **true**.
