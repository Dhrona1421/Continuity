#!/usr/bin/env python3
"""Build reproducible source and easy-install archives from tracked files."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path


def git_output(root: Path, *arguments: str, text: bool = True):
    executable = shutil.which("git")
    if executable is None:
        raise SystemExit("git is required to package a release")
    result = subprocess.run(  # noqa: S603 - fixed git executable and internal arguments only
        [executable, *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=text,
    )
    return result.stdout.strip() if text else result.stdout


def tracked_files(root: Path) -> list[Path]:
    output = git_output(root, "ls-files", "-z", text=False)
    return [Path(item.decode()) for item in output.split(b"\0") if item]


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("release"))
    parser.add_argument("--name", default="GhostSOC")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if git_output(root, "status", "--short"):
        raise SystemExit("Refusing to package a dirty Git worktree")
    commit = git_output(root, "rev-parse", "HEAD")
    short = commit[:7]
    files = tracked_files(root)
    args.output.mkdir(parents=True, exist_ok=True)
    source_zip = args.output / f"{args.name}-source-{short}.zip"
    easy_zip = args.output / f"{args.name}-easy-install-{short}.zip"
    easy_tar = args.output / f"{args.name}-easy-install-{short}.tar.gz"
    generated = datetime.now(UTC).replace(microsecond=0).isoformat()

    def manifest(kind: str) -> bytes:
        return json.dumps(
            {
                "product": "GhostSOC",
                "bundle": kind,
                "git_commit": commit,
                "generated_at": generated,
                "tracked_files": len(files),
                "contains_secrets": False,
                "quick_start_linux_macos": "./install.sh",
                "quick_start_windows": ".\\install.ps1",
            },
            indent=2,
        ).encode()

    with zipfile.ZipFile(source_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative in files:
            archive.write(root / relative, Path(f"{args.name}-source") / relative)
        archive.writestr(f"{args.name}-source/RELEASE-MANIFEST.json", manifest("source"))

    prefix = f"{args.name}-Easy-Install"
    quick = (
        b"GHOSTSOC EASY INSTALL\n\n"
        b"Linux/macOS: chmod +x install.sh start.sh stop.sh && ./install.sh\n"
        b"Windows:     Set-ExecutionPolicy -Scope Process Bypass; .\\install.ps1\n\n"
        b"Full instructions: INSTALL.md\n"
    )
    with zipfile.ZipFile(easy_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative in files:
            archive.write(root / relative, Path(prefix) / relative)
        archive.writestr(f"{prefix}/INSTALL-NOW.txt", quick)
        archive.writestr(f"{prefix}/RELEASE-MANIFEST.json", manifest("easy-install"))
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory) / prefix
        temp.mkdir()
        for relative in files:
            destination = temp / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / relative, destination)
        (temp / "INSTALL-NOW.txt").write_bytes(quick)
        (temp / "RELEASE-MANIFEST.json").write_bytes(manifest("easy-install"))
        with tarfile.open(easy_tar, "w:gz") as archive:
            archive.add(temp, arcname=prefix)

    checksums = args.output / f"{args.name}-{short}-SHA256SUMS.txt"
    checksums.write_text("".join(f"{digest(path)}  {path.name}\n" for path in (source_zip, easy_zip, easy_tar)))
    print(source_zip)
    print(easy_zip)
    print(easy_tar)
    print(checksums)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
