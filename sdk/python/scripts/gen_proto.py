#!/usr/bin/env python3
"""Reproducibly generate Python protobuf & gRPC stubs from ../../proto/forkloom/v1/runtime.proto.

Usage:
    python scripts/gen_proto.py           # regenerate stubs into src/forkloom_vm/_proto/
    python scripts/gen_proto.py --check   # verify committed stubs match runtime.proto
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

from grpc_tools import protoc

SDK_PYTHON_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SDK_PYTHON_DIR.parent.parent
PROTO_ROOT = REPO_ROOT / "proto"
PROTO_REL = Path("forkloom") / "v1" / "runtime.proto"
OUT_ROOT = SDK_PYTHON_DIR / "src" / "forkloom_vm" / "_proto"

_RELATIVE_IMPORT_RE = re.compile(
    r"^from forkloom\.v1 import runtime_pb2 as (\w+)$",
    re.MULTILINE,
)


def _generate_into(dest_root: Path) -> None:
    proto_file = PROTO_ROOT / PROTO_REL
    if not proto_file.is_file():
        raise FileNotFoundError(f"Proto definition not found: {proto_file}")

    dest_root.mkdir(parents=True, exist_ok=True)
    args = [
        "grpc_tools.protoc",
        f"-I{PROTO_ROOT}",
        f"--python_out={dest_root}",
        f"--pyi_out={dest_root}",
        f"--grpc_python_out={dest_root}",
        str(PROTO_REL.as_posix()),
    ]
    rc = protoc.main(args)
    if rc != 0:
        raise RuntimeError(f"grpc_tools.protoc failed with exit code {rc}")

    # Rewrite absolute `from forkloom.v1 import runtime_pb2` to a package-local
    # relative import so `forkloom_vm._proto` never depends on top-level sys.path.
    grpc_py = dest_root / "forkloom" / "v1" / "runtime_pb2_grpc.py"
    original = grpc_py.read_text(encoding="utf-8")
    rewritten, count = _RELATIVE_IMPORT_RE.subn(
        r"from . import runtime_pb2 as \1",
        original,
    )
    if count != 1:
        raise RuntimeError(
            f"Expected 1 runtime_pb2 import to rewrite in {grpc_py}, found {count}"
        )
    grpc_py.write_text(rewritten, encoding="utf-8", newline="\n")

    # Normalize line endings across generated files for cross-OS determinism.
    for path in (
        dest_root / "forkloom" / "v1" / "runtime_pb2.py",
        dest_root / "forkloom" / "v1" / "runtime_pb2.pyi",
        grpc_py,
    ):
        text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        path.write_text(text, encoding="utf-8", newline="\n")

    # Ensure package markers exist at every level.
    for pkg_dir in (
        dest_root,
        dest_root / "forkloom",
        dest_root / "forkloom" / "v1",
    ):
        init_file = pkg_dir / "__init__.py"
        init_file.write_text(
            '"""Generated Forkloom protobuf/gRPC stubs. Do not edit by hand."""\n',
            encoding="utf-8",
            newline="\n",
        )


def _check_sync(dest_root: Path) -> int:
    with tempfile.TemporaryDirectory(prefix="forkloom-proto-check-") as tmp:
        tmp_root = Path(tmp)
        _generate_into(tmp_root)
        expected_files = sorted(
            p.relative_to(tmp_root) for p in tmp_root.rglob("*") if p.is_file()
        )
        mismatches: list[str] = []
        for rel in expected_files:
            actual = dest_root / rel
            if not actual.is_file():
                mismatches.append(f"missing: {rel}")
                continue
            if actual.read_bytes() != (tmp_root / rel).read_bytes():
                mismatches.append(f"differs: {rel}")
        if mismatches:
            print("Generated Python protobuf stubs are out of date:", file=sys.stderr)
            for item in mismatches:
                print(f"  - {item}", file=sys.stderr)
            print("Run: python scripts/gen_proto.py", file=sys.stderr)
            return 1
    print("Python protobuf stubs are up to date.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify committed stubs match ../../proto/forkloom/v1/runtime.proto",
    )
    args = parser.parse_args(argv)

    if args.check:
        return _check_sync(OUT_ROOT)

    if OUT_ROOT.exists():
        shutil.rmtree(OUT_ROOT)
    _generate_into(OUT_ROOT)
    print(f"Generated Forkloom Python gRPC stubs in {OUT_ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
