# F0-3

## Environment header

> **Authority: `AdvisoryWsl2`** - WSL2 = nested virtualisation + loop devices on ext4-on-VHDX + host page cache beneath. Valid for functional/crash-semantics conclusions; latency/throughput numbers MUST NOT be published as baselines (docs/PHASE0_FALSIFICATION.md section 1).

| Field | Value |
| --- | --- |
| Collected at (UTC) | 2026-11-16T09:01:32Z |
| Declared host hardware | Surface Pro 8, i5-1135G7, 16 GiB RAM (as declared in docs/PHASE0_FALSIFICATION.md section 1.1; not verifiable from inside WSL2) |
| CPU (as seen by guest) | 8 x 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz |
| Memory | 7942 MiB total, 7445 MiB available |
| Page cache at start | Cached 860 MiB, Dirty 168 KiB |
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
| Command | ./target/release/phase0-harness f0-3-mkfs-git --files 10000,50000 |


# F0-3 - small-file import, mount-free `mkfs.ext4 -d` materialisation, `git status` after fork

## Parameters

- pool: Btrfs on loop (`direct_io=true`), 4096 MiB; file counts [10000, 50000]
- tree: `node_modules/pkg-NNNNN/lib/fNN.js`, 20 files/pkg, sizes 256 B - 8 KiB, owners cycle through uid:gid 0, 1000, 1234, 65534 per package; every 10th file 0755; plus a real Git repository (`git add -A && git commit`)
- "unpack" = `tar -xpf --numeric-owner` of the tree into a fresh subvolume as root; materialisation = `mkfs.ext4 -d` of that tree (no mount of the image); UID/GID/mode verified via `debugfs stat` on sampled files
- fork = `BTRFS_IOC_SNAP_CREATE_V2` of the Git subvolume; stat-compat checked with `git ls-files --debug` vs real `lstat`

## Results

| files | dirs | data (MiB) | populate (ms) | git add+commit (ms) | tar unpack (ms) | **mkfs.ext4 -d (ms)** | image (MiB) | e2fsck | uid/gid/mode mismatches |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10000 | 1271 | 40.4 | 625 | 1774 | 1103 | **1211** | 217 | 0 | 0/64 |
| 50000 | 5271 | 202.5 | 3337 | 6837 | 6390 | **6402** | 824 | 0 | 0/64 |

### Linear cost coefficients (largest vs smallest run)

- `mkfs.ext4 -d`: 129.8 us/file; tar unpack: 132.2 us/file; tree generation: 67.8 us/file

### `git status` after a subvolume fork

| files | warm status in original (ms) | **first status in fork (ms)** | second (ms) | cold (drop_caches) (ms) | index rewritten by 1st fork status | porcelain dirty | snapshot (ms) |
| ---: | ---: | ---: | ---: | ---: | :---: | :---: | ---: |
| 10000 | 34.0 | **37.0** | 26.9 | 81.0 | true | false | 6.412 |
| 50000 | 115 | **223** | 142 | 217 | true | false | 9.852 |

### Index-cached stat vs real stat in the fork (sampled entries; mismatch counts)

| files | samples | dev | ino | ctime | mtime | uid | gid | size |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10000 | 2000 | 2000 | 0 | 0 | 0 | 0 | 0 | 0 |
| 50000 | 2000 | 2000 | 0 | 0 | 0 | 0 | 0 | 0 |

## Findings

- UID/GID/mode fidelity of `mkfs.ext4 -d` from a root-unpacked tree: **OK (0 mismatches)** (zero offset expected when the unpack preserves numeric owners).
- Btrfs fork changes `st_dev` of every file: **true** (git ignores `st_dev` on Linux unless `core.checkStat`/`USE_STDEV` says otherwise); other stat fields (`ino`/`ctime`/`mtime`/`uid`/`gid`/`size`) preserved by the snapshot: **true**.
- First `git status` in the fork triggers a full re-hash / index rewrite: **true**. Engineering countermeasure: pre-refresh the Git index (`git update-index --refresh` / `git status`) at import time and again right after fork materialisation.

