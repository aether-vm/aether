#!/usr/bin/env bash
# Reproducible minimal Firecracker x86_64 Linux 6.6 LTS kernel builder.
#
# Produces:
#   <OUT_DIR>/vmlinux
#   <OUT_DIR>/vmlinux.config          (exact resolved .config)
#   <OUT_DIR>/manifest.json           (GPL-2.0-only compliance & reproducibility manifest)
#   <OUT_DIR>/GPL-2.0-NOTICE.txt      (human-readable GPL-2.0-only distribution notice)
#   <OUT_DIR>/LICENSE.GPL-2.0         (verbatim Linux kernel COPYING license text)
#   <OUT_DIR>/SHA256SUMS              (artifact checksums)
#
# Usage:
#   ./build-kernel.sh
#   KERNEL_VERSION=6.6.87 KERNEL_SHA256=<sha256> ./build-kernel.sh
#   KERNEL_TARBALL=/path/to/linux-6.6.87.tar.xz BASE_CONFIG=/path/to/fc.config ./build-kernel.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

KERNEL_VERSION="${KERNEL_VERSION:-6.6.87}"
KERNEL_MAJOR="${KERNEL_VERSION%%.*}"
KERNEL_TARBALL_URL="${KERNEL_TARBALL_URL:-https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz}"
KERNEL_TARBALL="${KERNEL_TARBALL:-}"
KERNEL_SHA256="${KERNEL_SHA256:-}"
BASE_CONFIG="${BASE_CONFIG:-}"
PATCH_DIR="${PATCH_DIR:-}"
FRAGMENT_PATH="${FRAGMENT_PATH:-${SCRIPT_DIR}/firecracker-6.6-x86_64.config.fragment}"
REQUIRED_KCONFIG="${REQUIRED_KCONFIG:-${SCRIPT_DIR}/required-kconfig.txt}"
WORK_DIR="${WORK_DIR:-${SCRIPT_DIR}/.build-kernel}"
OUT_DIR="${OUT_DIR:-${SCRIPT_DIR}/dist/kernel}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

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

# Reproducible build metadata (Linux kbuild respects these environment variables).
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1735689600}"
export KBUILD_BUILD_TIMESTAMP="${KBUILD_BUILD_TIMESTAMP:-$(date -u -d "@${SOURCE_DATE_EPOCH}" '+%a %b %d %H:%M:%S UTC %Y' 2>/dev/null || echo 'Wed Jan 01 00:00:00 UTC 2025')}"
export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-forkloom}"
export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-reproducible}"
export ARCH="x86_64"
export LC_ALL="C"

for tool in make gcc bc flex bison tar xz sha256sum awk sed grep; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "ERROR: required build tool '${tool}' not found in PATH." >&2
    exit 1
  fi
done

if [[ -z "${KERNEL_TARBALL}" ]] && ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: 'curl' is required to download upstream kernel tarball (or pass KERNEL_TARBALL)." >&2
  exit 1
fi
if [[ -n "${PATCH_DIR}" && -d "${PATCH_DIR}" ]] && ! command -v patch >/dev/null 2>&1; then
  echo "ERROR: 'patch' is required when PATCH_DIR is specified." >&2
  exit 1
fi

if [[ ! -f "${FRAGMENT_PATH}" ]]; then
  echo "ERROR: kernel config fragment not found: ${FRAGMENT_PATH}" >&2
  exit 1
fi
if [[ ! -f "${REQUIRED_KCONFIG}" ]]; then
  echo "ERROR: required-kconfig assertion file not found: ${REQUIRED_KCONFIG}" >&2
  exit 1
fi

mkdir -p "${WORK_DIR}" "${OUT_DIR}"

# ---------------------------------------------------------------------------
# 1. Fetch & Verify Upstream Kernel Tarball
# ---------------------------------------------------------------------------
if [[ -z "${KERNEL_TARBALL}" ]]; then
  KERNEL_TARBALL="${WORK_DIR}/linux-${KERNEL_VERSION}.tar.xz"
  if [[ ! -f "${KERNEL_TARBALL}" ]]; then
    echo "[1/5] Downloading ${KERNEL_TARBALL_URL} ..."
    curl -fsSL --retry 3 -o "${KERNEL_TARBALL}.tmp" "${KERNEL_TARBALL_URL}"
    mv "${KERNEL_TARBALL}.tmp" "${KERNEL_TARBALL}"
  fi
fi

ACTUAL_TARBALL_SHA256="$(sha256sum "${KERNEL_TARBALL}" | awk '{print $1}')"
if [[ -n "${KERNEL_SHA256}" ]]; then
  if [[ "${ACTUAL_TARBALL_SHA256}" != "${KERNEL_SHA256}" ]]; then
    echo "ERROR: Tarball SHA-256 mismatch!" >&2
    echo "  expected: ${KERNEL_SHA256}" >&2
    echo "  actual:   ${ACTUAL_TARBALL_SHA256}" >&2
    exit 1
  fi
  echo "[1/5] Verified kernel tarball SHA-256: ${ACTUAL_TARBALL_SHA256}"
else
  echo "[1/5] Recorded kernel tarball SHA-256: ${ACTUAL_TARBALL_SHA256} (set KERNEL_SHA256 to pin strictly)"
fi

# ---------------------------------------------------------------------------
# 2. Extract Source & Apply Optional Patch Series
# ---------------------------------------------------------------------------
SRC_DIR="${WORK_DIR}/linux-${KERNEL_VERSION}"
rm -rf "${SRC_DIR}"
echo "[2/5] Extracting $(basename "${KERNEL_TARBALL}") ..."
tar -xJf "${KERNEL_TARBALL}" -C "${WORK_DIR}"

PATCH_RECORDS_JSON="[]"
if [[ -n "${PATCH_DIR}" && -d "${PATCH_DIR}" ]]; then
  echo "[2/5] Applying patches from ${PATCH_DIR} ..."
  PATCH_RECORDS=()
  while IFS= read -r -d '' patch_file; do
    patch_name="$(basename "${patch_file}")"
    patch_sha="$(sha256sum "${patch_file}" | awk '{print $1}')"
    patch -d "${SRC_DIR}" -p1 --batch --forward < "${patch_file}"
    PATCH_RECORDS+=("{\"name\":\"${patch_name}\",\"sha256\":\"${patch_sha}\"}")
  done < <(find "${PATCH_DIR}" -maxdepth 1 -type f -name '*.patch' -print0 | LC_ALL=C sort -z)
  if (( ${#PATCH_RECORDS[@]} > 0 )); then
    PATCH_RECORDS_JSON="[$(IFS=,; echo "${PATCH_RECORDS[*]}")]"
  fi
fi

# ---------------------------------------------------------------------------
# 3. Compose .config & Strictly Assert Required Kconfig Symbols
# ---------------------------------------------------------------------------
echo "[3/5] Generating .config and verifying mandatory Kconfig symbols ..."
pushd "${SRC_DIR}" >/dev/null

if [[ -n "${BASE_CONFIG}" ]]; then
  cp "${BASE_CONFIG}" .config
else
  make x86_64_defconfig >/dev/null
fi

if [[ -x scripts/kconfig/merge_config.sh ]]; then
  scripts/kconfig/merge_config.sh -m .config "${FRAGMENT_PATH}" >/dev/null
else
  cat "${FRAGMENT_PATH}" >> .config
fi

make olddefconfig >/dev/null

# Verify EVERY required symbol survived `make olddefconfig` (catches silent drops).
MISSING_SYMBOLS=()
while IFS= read -r line; do
  line="${line%%#*}"
  line="$(echo "${line}" | xargs)"
  [[ -z "${line}" ]] && continue

  sym="${line%%=*}"
  expected="${line#*=}"

  if [[ "${expected}" == "n" ]]; then
    if grep -qE "^${sym}=(y|m)$" .config; then
      MISSING_SYMBOLS+=("${sym}=n (was enabled)")
    fi
  else
    if ! grep -qE "^${sym}=${expected}$" .config; then
      actual="$(grep -E "^(# )?${sym}[= ]" .config || echo "<absent>")"
      MISSING_SYMBOLS+=("${sym}=${expected} (actual: ${actual})")
    fi
  fi
done < "${REQUIRED_KCONFIG}"

if (( ${#MISSING_SYMBOLS[@]} > 0 )); then
  echo "ERROR: One or more mandatory Kconfig symbols were dropped or mismatched after olddefconfig:" >&2
  for item in "${MISSING_SYMBOLS[@]}"; do
    echo "  - ${item}" >&2
  done
  exit 1
fi
echo "[3/5] All mandatory Kconfig assertions passed."

# ---------------------------------------------------------------------------
# 4. Compile Static Uncompressed vmlinux for Firecracker
# ---------------------------------------------------------------------------
echo "[4/5] Building vmlinux with -j${JOBS} ..."
make -j"${JOBS}" vmlinux

cp vmlinux "${OUT_DIR}/vmlinux"
cp .config "${OUT_DIR}/vmlinux.config"
if [[ -f COPYING ]]; then
  cp COPYING "${OUT_DIR}/LICENSE.GPL-2.0"
elif [[ -f LICENSES/preferred/GPL-2.0 ]]; then
  cp LICENSES/preferred/GPL-2.0 "${OUT_DIR}/LICENSE.GPL-2.0"
else
  echo "ERROR: upstream kernel GPL-2.0 license text (COPYING) not found in ${SRC_DIR}" >&2
  exit 1
fi
KERNEL_RELEASE="$(make -s kernelrelease)"
popd >/dev/null

# ---------------------------------------------------------------------------
# 5. Emit GPL-2.0-only Compliance Manifest & Checksums
# ---------------------------------------------------------------------------
echo "[5/5] Writing GPL-2.0-only compliance manifest to ${OUT_DIR} ..."

VMLINUX_SHA256="$(sha256sum "${OUT_DIR}/vmlinux" | awk '{print $1}')"
CONFIG_SHA256="$(sha256sum "${OUT_DIR}/vmlinux.config" | awk '{print $1}')"
FRAGMENT_SHA256="$(sha256sum "${FRAGMENT_PATH}" | awk '{print $1}')"
LICENSE_SHA256="$(sha256sum "${OUT_DIR}/LICENSE.GPL-2.0" | awk '{print $1}')"
GCC_VERSION="$(gcc --version | head -n1 | sed 's/"/\\"/g')"
LD_VERSION="$(ld --version | head -n1 | sed 's/"/\\"/g')"
BASE_CONFIG_LABEL="${BASE_CONFIG:-x86_64_defconfig}"

cat > "${OUT_DIR}/manifest.json" <<EOF
{
  "schema_version": 1,
  "artifact": "vmlinux",
  "license": "GPL-2.0-only",
  "license_file": "LICENSE.GPL-2.0",
  "license_file_sha256": "${LICENSE_SHA256}",
  "arch": "x86_64",
  "kernel_version": "${KERNEL_VERSION}",
  "kernel_release": "${KERNEL_RELEASE}",
  "upstream_tarball_url": "${KERNEL_TARBALL_URL}",
  "upstream_tarball_sha256": "${ACTUAL_TARBALL_SHA256}",
  "base_config": "${BASE_CONFIG_LABEL}",
  "config_fragment_sha256": "${FRAGMENT_SHA256}",
  "resolved_config_sha256": "${CONFIG_SHA256}",
  "vmlinux_sha256": "${VMLINUX_SHA256}",
  "patches": ${PATCH_RECORDS_JSON},
  "reproducibility": {
    "source_date_epoch": ${SOURCE_DATE_EPOCH},
    "kbuild_build_timestamp": "${KBUILD_BUILD_TIMESTAMP}",
    "kbuild_build_user": "${KBUILD_BUILD_USER}",
    "kbuild_build_host": "${KBUILD_BUILD_HOST}",
    "gcc_version": "${GCC_VERSION}",
    "ld_version": "${LD_VERSION}"
  },
  "verified_kconfig_file": "required-kconfig.txt"
}
EOF

cat > "${OUT_DIR}/GPL-2.0-NOTICE.txt" <<EOF
Forkloom Guest Kernel Binary — GPL-2.0-only Compliance Notice
=============================================================

Artifact:        vmlinux (${KERNEL_RELEASE}, x86_64)
License:         GNU General Public License v2.0 only (GPL-2.0-only; see LICENSE.GPL-2.0)
Upstream Source: ${KERNEL_TARBALL_URL}
Tarball SHA-256: ${ACTUAL_TARBALL_SHA256}
Config SHA-256:  ${CONFIG_SHA256} (see bundled vmlinux.config)
vmlinux SHA-256: ${VMLINUX_SHA256}

All Forkloom userspace code is licensed under Apache-2.0. This vmlinux binary is
derived from the upstream Linux kernel and is distributed strictly under the
terms of GPL-2.0-only. Complete corresponding source code consists of the exact
upstream tarball listed above, any patches recorded in manifest.json, and the
bundled vmlinux.config file.
EOF

(
  cd "${OUT_DIR}"
  sha256sum vmlinux vmlinux.config manifest.json GPL-2.0-NOTICE.txt LICENSE.GPL-2.0 > SHA256SUMS
)

echo "Done! Outputs written to ${OUT_DIR}:"
ls -lh "${OUT_DIR}/vmlinux" "${OUT_DIR}/vmlinux.config" "${OUT_DIR}/manifest.json" "${OUT_DIR}/GPL-2.0-NOTICE.txt" "${OUT_DIR}/LICENSE.GPL-2.0" "${OUT_DIR}/SHA256SUMS"
