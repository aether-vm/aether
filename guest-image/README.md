# Guest Kernel & Inspector Initramfs Build System

This directory holds reproducible build scripts and kernel configurations (`.config`, Linux >= 5.18) for:
1. **`vmlinux`**: Minimal Firecracker guest kernel with `CONFIG_VMGENID=y`, `CONFIG_HW_RANDOM_VIRTIO=y`, `CONFIG_INET_DIAG_DESTROY=y`, `CONFIG_CGROUPS=y`, `CONFIG_CGROUP_FREEZER=y`, and `CONFIG_VSOCKETS=y`.
2. **`inspector.cpio.zst`**: Networkless read-only initramfs used by ephemeral `Inspector VM` instances to compute untrusted block-image diffs safely off the host kernel.

## GPL-2.0 Compliance Notice
While all Aether userspace code is licensed under Apache-2.0, any distributed `vmlinux` binary is governed by **GPL-2.0-only**. Release pipelines MUST publish the exact upstream kernel tarball digest, patch series (if any), and `.config` alongside every binary bundle.
