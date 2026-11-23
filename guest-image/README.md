# Guest Kernel & Inspector Initramfs Build System

This directory holds reproducible build scripts, kernel configuration fragments, and Kconfig verification assertions (Linux `>= 5.18`, target **6.6 LTS**) for:

1. **`vmlinux`**: Minimal, moduleless (`CONFIG_MODULES=n`) Firecracker `x86_64` guest kernel built with `virtio-mmio` (`CONFIG_VIRTIO_PCI=n`, keeping `CONFIG_PCI=y` solely to satisfy Linux 6.6 `x86_64` `CONFIG_ACPI=y` -> `CONFIG_VMGENID=y`), `virtio-rng`, `cgroup v2` + freezer, `virtio-vsock`, `virtio-blk` + `ext4`, `zstd` initramfs support, and `NETLINK_SOCK_DIAG` + `INET_TCP_DIAG` + `INET_DIAG_DESTROY` for post-fork external TCP teardown.
2. **`inspector.cpio.zst`**: Deterministic, networkless, read-only initramfs used by ephemeral `Inspector VM` instances to mount untrusted block snapshots (`/dev/vda`, `/dev/vdb`) with `ro,noload,nosuid,nodev,noexec` completely off the host kernel.

---

## Directory Layout

| File | Purpose |
| :--- | :--- |
| `firecracker-6.6-x86_64.config.fragment` | Minimal Linux 6.6 LTS Kconfig fragment pinning all required features **and** their hidden Kconfig parent dependencies. |
| `required-kconfig.txt` | Mandatory Kconfig assertions checked by `build-kernel.sh` after `make olddefconfig` so no required symbol can be silently dropped. |
| `build-kernel.sh` | Reproducible `vmlinux` builder with `SOURCE_DATE_EPOCH` determinism, `olddefconfig` verification, and GPL-2.0-only compliance manifest generation. |
| `build-inspector-initramfs.sh` | Reproducible `inspector.cpio.zst` builder (`cpio --reproducible -R 0:0` + `zstd`) with zero network tools and license/checksum manifest generation. |

---

## Critical Kconfig Dependencies (Linux 6.6 LTS)

`make olddefconfig` silently drops symbols whose parent dependencies are disabled. `firecracker-6.6-x86_64.config.fragment` and `required-kconfig.txt` explicitly pin and verify every chain:

| Capability | Required Symbol(s) | Mandatory Parent Dependencies |
| :--- | :--- | :--- |
| Firecracker MMIO devices | `CONFIG_VIRTIO_MMIO=y`, `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y`, `CONFIG_VIRTIO_PCI=n` | `CONFIG_VIRTIO=y`, `CONFIG_VIRTIO_MENU=y` |
| Snapshot clone entropy (`VMGenID`) | `CONFIG_VMGENID=y` | `CONFIG_PCI=y` (required by Linux 6.6 x86_64 `ACPI`), `CONFIG_ACPI=y`, `CONFIG_VIRT_DRIVERS=y` |
| Host entropy injection (`virtio-rng`) | `CONFIG_HW_RANDOM_VIRTIO=y` | `CONFIG_HW_RANDOM=y`, `CONFIG_VIRTIO=y` |
| Root block image (`virtio-blk` + `ext4`) | `CONFIG_VIRTIO_BLK=y`, `CONFIG_EXT4_FS=y` | `CONFIG_BLOCK=y`, `CONFIG_VIRTIO=y` |
| Workload freeze & per-exec `cgroup.kill` | `CONFIG_CGROUPS=y`, `CONFIG_CGROUP_FREEZER=y`, `CONFIG_CGROUP_PIDS=y`, `CONFIG_MEMCG=y` | `CONFIG_CGROUPS=y` (v2 `cgroup.freeze` is built into core `CGROUPS` since 5.2) |
| Host↔Guest `aos-guest` channel | `CONFIG_VSOCKETS=y`, `CONFIG_VIRTIO_VSOCKETS=y` | `CONFIG_NET=y`, `CONFIG_VIRTIO=y` |
| Post-fork external TCP teardown (`SOCK_DESTROY` / `ss -K`) | `CONFIG_INET_DIAG=y`, **`CONFIG_INET_TCP_DIAG=y`**, `CONFIG_INET_DIAG_DESTROY=y` | `CONFIG_NET=y`, `CONFIG_INET=y`, `CONFIG_IPV6=y` (`INET_TCP_DIAG=y` is mandatory in moduleless `vmlinux`, otherwise `SOCK_DIAG` fails with `ENOENT`) |
| Ephemeral Inspector initramfs | `CONFIG_BLK_DEV_INITRD=y`, `CONFIG_RD_ZSTD=y`, `CONFIG_DEVTMPFS_MOUNT=y` | `CONFIG_TMPFS=y`, `CONFIG_PROC_FS=y`, `CONFIG_SYSFS=y` |

---

## Reproducible Build Usage (Native Linux / WSL2 Native FS Only)

> **Important (`AGENTS.md` Red Line 1)**: Always run builds on a native Linux filesystem (e.g., `~/work/forkloom-vm/forkloom`), never under `/mnt/c` (WSL 9p). Both build scripts actively reject `/mnt/<drive>` paths.

### 1. Build `vmlinux` (Linux 6.6 LTS)

```bash
# Install prerequisites (Ubuntu 22.04 / 24.04)
sudo apt-get update && sudo apt-get install -y \
  build-essential bc flex bison libssl-dev libelf-dev curl xz-utils

# Build reproducible vmlinux + GPL-2.0-only manifest
cd guest-image
KERNEL_VERSION=6.6.87 ./build-kernel.sh

# Optional: pin exact upstream tarball SHA-256 and Firecracker upstream base config
KERNEL_VERSION=6.6.87 \
KERNEL_SHA256="<expected-tarball-sha256>" \
BASE_CONFIG="/path/to/microvm-kernel-ci-x86_64-6.1.config" \
  ./build-kernel.sh
```

Outputs are written to `guest-image/dist/kernel/`:
- `vmlinux`
- `vmlinux.config`
- `manifest.json`
- `GPL-2.0-NOTICE.txt`
- `LICENSE.GPL-2.0`
- `SHA256SUMS`

### 2. Build `inspector.cpio.zst`

```bash
sudo apt-get install -y busybox-static cpio zstd file

cd guest-image
./build-inspector-initramfs.sh

# Optional: embed a static musl aos-inspector binary (required unless booting with
# kernel cmdline `forkloom.inspector_allow_fallback=1` for dev/bringup)
INSPECTOR_BIN="../target/x86_64-unknown-linux-musl/release/aos-inspector" \
  ./build-inspector-initramfs.sh
```

Outputs are written to `guest-image/dist/inspector/`:
- `inspector.cpio.zst`
- `inspector-manifest.json`
- `GPL-2.0-NOTICE.txt`
- `SHA256SUMS`

### 3. Build Static `aos-guest` PID-1 Binary (`x86_64-unknown-linux-musl`)

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl -p aos-guest --bin aos-guest
```

---

## GPL-2.0-only Compliance Notice

While all Forkloom userspace code (including `crates/aos-guest`) is licensed under **Apache-2.0**, any distributed `vmlinux` binary (and any `inspector.cpio.zst` bundling `busybox-static`) is governed by **GPL-2.0-only**. Release pipelines **MUST** publish alongside every binary bundle:

1. The exact upstream kernel tarball URL and SHA-256 digest (`manifest.json`),
2. Any applied patch series and their SHA-256 digests (`manifest.json`),
3. The exact resolved kernel `.config` (`vmlinux.config`),
4. `GPL-2.0-NOTICE.txt` and `SHA256SUMS`.
