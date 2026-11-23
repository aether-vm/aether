#!/usr/bin/env bash
# Reproducible networkless read-only Inspector VM initramfs builder (`inspector.cpio.zst`).
#
# Per `docs/ARCHITECTURE_V2.md` §3.4 & `AGENTS.md` Red Line 3:
#   - Host kernel MUST NEVER mount any untrusted guest block image.
#   - Ephemeral Inspector VM boots this networkless, read-only initramfs to mount
#     base (/dev/vda) and target (/dev/vdb) ext4 snapshots read-only (`ro,noload`)
#     and emit patch/diff output before powering off immediately.
#
# Outputs:
#   <OUT_DIR>/inspector.cpio.zst
#   <OUT_DIR>/inspector-manifest.json   (reproducibility + GPL/Apache license manifest)
#   <OUT_DIR>/GPL-2.0-NOTICE.txt        (GPL-2.0-only notice for bundled busybox-static)
#   <OUT_DIR>/SHA256SUMS
#
# Usage:
#   ./build-inspector-initramfs.sh
#   BUSYBOX_BIN=/bin/busybox-static INSPECTOR_BIN=/path/to/aos-inspector ./build-inspector-initramfs.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

BUSYBOX_BIN="${BUSYBOX_BIN:-$(command -v busybox || true)}"
INSPECTOR_BIN="${INSPECTOR_BIN:-}"
OUT_DIR="${OUT_DIR:-${SCRIPT_DIR}/dist/inspector}"
WORK_DIR="${WORK_DIR:-${SCRIPT_DIR}/.build-inspector}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1735689600}"
ZSTD_LEVEL="${ZSTD_LEVEL:-19}"
export LC_ALL="C"

# Guard against WSL2 9p mounts (/mnt/c etc.) on all build paths per AGENTS.md Red Line 1.
check_native_linux_path() {
  local label="$1"
  local path="$2"
  case "${path}" in
    /mnt/[a-zA-Z]/*|/mnt/[a-zA-Z])
      echo "ERROR: Refusing to use WSL 9p mount for ${label} (${path})." >&2
      echo "Use native Linux storage (e.g. ~/work/forkloom-vm/forkloom)." >&2
      exit 1
      ;;
  esac
}
check_native_linux_path "SCRIPT_DIR" "${SCRIPT_DIR}"
check_native_linux_path "WORK_DIR" "${WORK_DIR}"
check_native_linux_path "OUT_DIR" "${OUT_DIR}"

for tool in cpio zstd find sort sha256sum awk file; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "ERROR: required tool '${tool}' not found in PATH." >&2
    exit 1
  fi
done

if [[ -z "${BUSYBOX_BIN}" || ! -x "${BUSYBOX_BIN}" ]]; then
  echo "ERROR: static busybox binary not found. Install 'busybox-static' or set BUSYBOX_BIN." >&2
  exit 1
fi

if file "${BUSYBOX_BIN}" | grep -qi "dynamically linked"; then
  echo "ERROR: BUSYBOX_BIN (${BUSYBOX_BIN}) is dynamically linked; a static binary is required for initramfs." >&2
  echo "Install Debian/Ubuntu package 'busybox-static' or point BUSYBOX_BIN to a static build." >&2
  exit 1
fi

if [[ -n "${INSPECTOR_BIN}" ]]; then
  if [[ ! -x "${INSPECTOR_BIN}" ]]; then
    echo "ERROR: INSPECTOR_BIN (${INSPECTOR_BIN}) is not executable." >&2
    exit 1
  fi
  if file "${INSPECTOR_BIN}" | grep -qi "dynamically linked"; then
    echo "ERROR: INSPECTOR_BIN (${INSPECTOR_BIN}) must be statically linked (e.g. x86_64-unknown-linux-musl)." >&2
    exit 1
  fi
fi

ROOTFS="${WORK_DIR}/rootfs"
rm -rf "${ROOTFS}"
mkdir -p "${OUT_DIR}" "${ROOTFS}"/{bin,dev,mnt/base,mnt/target,proc,sys,tmp}

# ---------------------------------------------------------------------------
# 1. Populate Minimal Read-Only Userspace (Zero Network Tools)
# ---------------------------------------------------------------------------
cp "${BUSYBOX_BIN}" "${ROOTFS}/bin/busybox"
chmod 0755 "${ROOTFS}/bin/busybox"

# Explicitly install only minimal non-network applets needed for RO diff extraction.
APPLETS=(
  sh mount umount mkdir rmdir ls cat cp diff tar find sort stat readlink basename
  grep head tail wc cut tr sed awk sha256sum poweroff sleep echo true false
)
for app in "${APPLETS[@]}"; do
  ln -s busybox "${ROOTFS}/bin/${app}"
done

INSPECTOR_SHA256="null"
if [[ -n "${INSPECTOR_BIN}" ]]; then
  cp "${INSPECTOR_BIN}" "${ROOTFS}/bin/aos-inspector"
  chmod 0755 "${ROOTFS}/bin/aos-inspector"
  INSPECTOR_SHA256="\"$(sha256sum "${ROOTFS}/bin/aos-inspector" | awk '{print $1}')\""
fi

# ---------------------------------------------------------------------------
# 2. Write Deterministic Networkless /init
# ---------------------------------------------------------------------------
cat > "${ROOTFS}/init" <<'INIT_EOF'
#!/bin/sh
# Forkloom ephemeral Inspector VM PID-1 init (networkless, strictly read-only mounts).
set -eu

export PATH=/bin

mount -t proc -o nosuid,nodev,noexec proc /proc
mount -t sysfs -o nosuid,nodev,noexec sysfs /sys
mount -t devtmpfs -o nosuid devtmpfs /dev 2>/dev/null || true

cleanup_and_halt() {
  rc=$?
  umount /mnt/target 2>/dev/null || true
  umount /mnt/base 2>/dev/null || true
  if [ "${rc}" -ne 0 ]; then
    echo "FORKLOOM_INSPECTOR_ERROR exit_code=${rc}"
  fi
  poweroff -f
}
trap cleanup_and_halt EXIT

# Refuse to run if any external network interface is present (defense-in-depth).
for iface in /sys/class/net/*; do
  [ -e "${iface}" ] || continue
  name="${iface##*/}"
  if [ "${name}" != "lo" ]; then
    echo "FORKLOOM_INSPECTOR_ERROR unexpected_net_iface=${name}"
    exit 2
  fi
done

if [ ! -b /dev/vda ] || [ ! -b /dev/vdb ]; then
  echo "FORKLOOM_INSPECTOR_ERROR missing_virtio_blk_devices"
  exit 3
fi

# Strictly read-only mounts (`noload` avoids replaying untrusted ext4 journals).
mount -t ext4 -o ro,noload,nosuid,nodev,noexec /dev/vda /mnt/base
mount -t ext4 -o ro,noload,nosuid,nodev,noexec /dev/vdb /mnt/target

if [ -x /bin/aos-inspector ]; then
  /bin/aos-inspector --base /mnt/base --target /mnt/target
else
  # Fail closed by default unless explicitly opted in via kernel cmdline for dev/bringup.
  if ! grep -qw "forkloom.inspector_allow_fallback=1" /proc/cmdline; then
    echo "FORKLOOM_INSPECTOR_ERROR missing_aos_inspector"
    exit 4
  fi

  # Safe regular-file-only dev fallback: never follows symlinks, never opens FIFOs
  # or device nodes, and propagates diff I/O errors (rc >= 2).
  echo "FORKLOOM_INSPECTOR_BEGIN"
  (
    cd /mnt/base && find . -type f | LC_ALL=C sort > /tmp/base_files.txt
    cd /mnt/target && find . -type f | LC_ALL=C sort > /tmp/target_files.txt
    cat /tmp/base_files.txt /tmp/target_files.txt | LC_ALL=C sort -u | while IFS= read -r rel; do
      b="/mnt/base/${rel#./}"
      t="/mnt/target/${rel#./}"
      if [ -f "${b}" ] && [ ! -L "${b}" ] && [ -f "${t}" ] && [ ! -L "${t}" ]; then
        set +e
        diff -u "${b}" "${t}"
        rc=$?
        set -e
        if [ "${rc}" -ge 2 ]; then
          exit "${rc}"
        fi
      elif [ ! -e "${b}" ] && [ -f "${t}" ] && [ ! -L "${t}" ]; then
        set +e
        diff -u /dev/null "${t}"
        rc=$?
        set -e
        if [ "${rc}" -ge 2 ]; then
          exit "${rc}"
        fi
      elif [ -f "${b}" ] && [ ! -L "${b}" ] && [ ! -e "${t}" ]; then
        set +e
        diff -u "${b}" /dev/null
        rc=$?
        set -e
        if [ "${rc}" -ge 2 ]; then
          exit "${rc}"
        fi
      fi
    done
  )
  echo "FORKLOOM_INSPECTOR_END"
fi
INIT_EOF
chmod 0755 "${ROOTFS}/init"

# ---------------------------------------------------------------------------
# 3. Deterministic CPIO + ZSTD Archive Creation
# ---------------------------------------------------------------------------
# Normalize mtimes to SOURCE_DATE_EPOCH for bit-for-bit reproducible output.
find "${ROOTFS}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

ARCHIVE="${OUT_DIR}/inspector.cpio.zst"
(
  cd "${ROOTFS}"
  find . -print0 \
    | LC_ALL=C sort -z \
    | cpio --null -o -H newc --reproducible -R 0:0 --quiet \
    | zstd -"${ZSTD_LEVEL}" -T0 --quiet -f -o "${ARCHIVE}"
)

# ---------------------------------------------------------------------------
# 4. Emit License & Reproducibility Manifest
# ---------------------------------------------------------------------------
BUSYBOX_SHA256="$(sha256sum "${ROOTFS}/bin/busybox" | awk '{print $1}')"
BUSYBOX_VERSION="$("${BUSYBOX_BIN}" --help 2>&1 | head -n1 | sed 's/"/\\"/g')"
ARCHIVE_SHA256="$(sha256sum "${ARCHIVE}" | awk '{print $1}')"
ARCHIVE_SIZE="$(stat -c%s "${ARCHIVE}")"

cat > "${OUT_DIR}/inspector-manifest.json" <<EOF
{
  "schema_version": 1,
  "artifact": "inspector.cpio.zst",
  "arch": "x86_64",
  "networkless": true,
  "read_only_mounts": ["ro", "noload", "nosuid", "nodev", "noexec"],
  "archive_sha256": "${ARCHIVE_SHA256}",
  "archive_size_bytes": ${ARCHIVE_SIZE},
  "reproducibility": {
    "source_date_epoch": ${SOURCE_DATE_EPOCH},
    "zstd_level": ${ZSTD_LEVEL}
  },
  "components": [
    {
      "name": "busybox-static",
      "version": "${BUSYBOX_VERSION}",
      "license": "GPL-2.0-only",
      "sha256": "${BUSYBOX_SHA256}"
    },
    {
      "name": "forkloom-inspector-init",
      "license": "Apache-2.0",
      "aos_inspector_sha256": ${INSPECTOR_SHA256}
    }
  ]
}
EOF

cat > "${OUT_DIR}/GPL-2.0-NOTICE.txt" <<EOF
Forkloom Inspector Initramfs — GPL-2.0-only Component Notice
============================================================

Artifact:        inspector.cpio.zst (x86_64)
Archive SHA-256: ${ARCHIVE_SHA256}
GPL Component:   busybox-static (${BUSYBOX_VERSION})
BusyBox SHA-256: ${BUSYBOX_SHA256}
License:         GNU General Public License v2.0 only (GPL-2.0-only)

Forkloom's /init script and aos-inspector userspace binary are licensed under
Apache-2.0. The bundled busybox-static binary is licensed under GPL-2.0-only;
any redistribution of inspector.cpio.zst MUST comply with GPL-2.0-only by
providing corresponding BusyBox source code for the exact version recorded in
inspector-manifest.json.
EOF

(
  cd "${OUT_DIR}"
  sha256sum inspector.cpio.zst inspector-manifest.json GPL-2.0-NOTICE.txt > SHA256SUMS
)

echo "Done! Reproducible Inspector initramfs written to ${OUT_DIR}:"
ls -lh "${ARCHIVE}" "${OUT_DIR}/inspector-manifest.json" "${OUT_DIR}/GPL-2.0-NOTICE.txt" "${OUT_DIR}/SHA256SUMS"
