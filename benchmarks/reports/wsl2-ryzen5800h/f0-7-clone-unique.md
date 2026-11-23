# F0-7

## Environment header

> **Authority: `AdvisoryWsl2`** - WSL2 = nested virtualisation + loop devices on ext4-on-VHDX + host page cache beneath. Valid for functional/crash-semantics conclusions; latency/throughput numbers MUST NOT be published as baselines (docs/PHASE0_FALSIFICATION.md section 1).

| Field | Value |
| --- | --- |
| Collected at (UTC) | 2026-11-23T11:27:41Z |
| Declared host hardware | Surface Pro 8, i5-1135G7, 16 GiB RAM (as declared in docs/PHASE0_FALSIFICATION.md section 1.1; not verifiable from inside WSL2) |
| CPU (as seen by guest) | 8 x AMD Ryzen 7 5800H with Radeon Graphics |
| Memory | 15995 MiB total, 15295 MiB available |
| Page cache at start | Cached 847 MiB, Dirty 3648 KiB |
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
| Command | ./target/release/phase0-harness --root /var/lib/forkloom/phase0 --out benchmarks/reports/wsl2-ryzen5800h f0-7-clone-unique --firecracker-bin /usr/local/bin/firecracker --snapshot-path /var/lib/forkloom/phase0/snaps/f07/vmstate --mem-file-path /var/lib/forkloom/phase0/snaps/f07/mem.img --vsock-uds ./v.sock --vsock-port 5000 --clones 2 --entropy-bytes 64 --max-sever-ms 100 --socket-probe-argv /bin/f07-workload,probe --netns-tap tap-f07 |


## F0-7: Clone Uniqueness & Loopback Connection Survival

- Verdict: **PASS**
- Entropy divergence: **2/2** unique 64B samples, min pairwise Hamming distance = **251 bits** (pass=true)
- External TCP severed (`SOCK_DESTROY` / `ss -K`, <= 100 ms): **true**
- Loopback (`127.0.0.1` / `[::1]`) pool survived: **true**
- Kernel ABI: `RNDADDENTROPY=0x40085203`, `RNDRESEEDCRNG=0x5207`, filter=`state connected ( not dst 127.0.0.0/8 and not dst [::1] and not dst [::ffff:127.0.0.0/104] )`

| Clone | Killed Ext TCP | Kept Loopback | External Severed | Sever (ms) | Loopback Survived | Detail |
| ---: | ---: | ---: | :---: | ---: | :---: | :--- |
| 0 | 1 | 2 | true | 0.04 | true | ext_errno=103 lo_echo=ok |
| 1 | 1 | 2 | true | 0.04 | true | ext_errno=103 lo_echo=ok |

