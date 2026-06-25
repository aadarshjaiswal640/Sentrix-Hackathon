#!/usr/bin/env python3
"""Safely remove generated and runtime artifacts from the repository.

By default, the script performs a dry run and prints the files/directories it would remove.
Pass --apply to actually delete them.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]

TARGET_DIR_NAMES = {
    "__pycache__",
    "build",
    "dist",
    "logs",
    "tmp",
    "temp",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".pytype",
    ".cache",
    ".upm",
}

TARGET_FILE_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".toc",
    ".pyz",
    ".zip",
    ".log",
    ".tmp",
    ".temp",
    ".bak",
    ".old",
}

PROTECTED_DIR_NAMES = {".git", ".github", "docs", "rules", "connectors", "libs", "agent", "tests"}


def iter_targets(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.exists():
            continue
        if path.is_dir():
            if path.name in TARGET_DIR_NAMES:
                yield path
            elif any(part in TARGET_DIR_NAMES for part in path.parts):
                continue
            continue

        if path.is_file() and (
            path.name.endswith(tuple(TARGET_FILE_SUFFIXES))
            or path.suffix in TARGET_FILE_SUFFIXES
        ):
            yield path


def should_remove(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    parts = set(rel.parts)

    if not parts:
        return False

    if parts & {".git"}:
        return False

    if path.is_dir() and path.name in PROTECTED_DIR_NAMES:
        return False

    if path.is_dir() and path.name in TARGET_DIR_NAMES:
        return True

    if path.is_dir() and any(part in TARGET_DIR_NAMES for part in path.parts):
        return False

    if path.is_file() and path.name.endswith(tuple(TARGET_FILE_SUFFIXES)):
        return True

    return False


def collect_targets(root: Path) -> list[Path]:
    targets = []
    for path in root.rglob("*"):
        if not path.exists():
            continue
        if should_remove(path):
            targets.append(path)
    return sorted(targets, key=lambda item: (item.is_file(), item.as_posix()))


def remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="actually delete the matched artifacts")
    args = parser.parse_args()

    targets = collect_targets(ROOT)

    if not targets:
        print("No generated artifacts found.")
        return 0

    print("Generated artifacts detected:")
    for target in targets:
        rel = target.relative_to(ROOT).as_posix()
        print(f"- {rel}")

    if not args.apply:
        print("\nDry run only. Re-run with --apply to remove these files and directories.")
        return 0

    for target in targets:
        rel = target.relative_to(ROOT).as_posix()
        try:
            remove_path(target)
            print(f"Removed: {rel}")
        except Exception as exc:  # pragma: no cover - defensive
            print(f"Failed to remove {rel}: {exc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
