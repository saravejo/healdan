#!/usr/bin/env python3
"""Audit every reachable Git blob and distribution archive without printing content."""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tomllib
import zipfile

BAD_PATHS = re.compile(r"(^|/)(wiki-1\.4\.md|\.local-tools|\.verification|config/local\.json|\.env|transcripts)(/|$)", re.I)
PRIVATE = re.compile(rb"(?m)^-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----\r?$|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|sk-ant-api[0-9]+-[A-Za-z0-9_-]{30,}")
CONVERSATION = re.compile(r"(^|/)(?:S-[0-9]+\.jsonl|[^/]+\.age|[^/]+\.key|[^/]+\.pem)$", re.I)


def check(name, data, failures, reference_hash):
    if BAD_PATHS.search(name) or CONVERSATION.search(name):
        failures.append("Forbidden publication path: " + name)
    if PRIVATE.search(data):
        failures.append("Possible credential in: " + name)
    if reference_hash and hashlib.sha256(data).hexdigest() == reference_hash:
        failures.append("Local reference content found under: " + name)


def safe_archive_path(name):
    return (bool(name) and not name.startswith("/") and not any(char in name for char in ("\\", "\0")) and
            not re.match(r"^[A-Za-z]:", name) and ".." not in PurePosixPath(name).parts)


def audit_zip(file, failures, reference_hash):
    with zipfile.ZipFile(file) as archive:
        entries = archive.infolist()
        invalid = [entry.orig_filename for entry in entries
                   if not safe_archive_path(entry.orig_filename) or
                   stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG)]
        if invalid:
            failures.extend(f"Unsafe ZIP entry: {name!r}" for name in invalid)
            return 0
        for entry in entries:
            check(entry.filename, b"" if entry.is_dir() else archive.read(entry), failures, reference_hash)
        return len(entries)


def audit_tar(file, failures, reference_hash):
    with tarfile.open(fileobj=file, mode="r:gz") as archive:
        entries = archive.getmembers()
        invalid = [entry.name for entry in entries if not safe_archive_path(entry.name) or
                   entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)]
        if invalid:
            failures.extend(f"Unsafe tar entry: {name!r}" for name in invalid)
            return 0
        for entry in entries:
            if entry.isdir():
                data = b""
            else:
                with archive.extractfile(entry) as content:
                    data = content.read()
            check(entry.name, data, failures, reference_hash)
        return len(entries)


def expected_distributions(names, root, required, failures):
    unsupported = [name for name in names if not name.endswith((".whl", ".tar.gz") if required else (".whl", ".zip", ".tar.gz"))]
    failures.extend(f"Unexpected distribution entry: {name!r}" for name in unsupported)
    if unsupported:
        return False
    if not required:
        return True
    metadata = root / "pyproject.toml"
    if metadata.is_symlink():
        failures.append("Expected project metadata to be a regular file")
        return False
    with metadata.open("rb") as config:
        project = tomllib.load(config)["project"]
    name = re.sub(r"[-_.]+", "_", project["name"]).lower()
    stem = f"{name}-{project['version']}"
    wheel = re.compile(rf"{re.escape(stem)}(?:-[0-9][A-Za-z0-9_]*)?(?:-[A-Za-z0-9_.]+){{3}}\.whl")
    if len(names) == 2 and f"{stem}.tar.gz" in names and sum(wheel.fullmatch(name) is not None for name in names) == 1:
        return True
    failures.append("Expected exactly one wheel and one source distribution for the project name and version")
    return False


def audit_distribution(name, file, failures, reference_hash):
    inspect = audit_tar if name.endswith(".tar.gz") else audit_zip
    return inspect(file, failures, reference_hash)


def audit_packages(packages, root, required, failures, reference_hash):
    count = 0
    if packages.is_dir() and not packages.is_symlink():
        entries = list(packages.iterdir())
        invalid = [entry.name for entry in entries if entry.is_symlink() or not entry.is_file()]
        if invalid:
            failures.extend(f"Unexpected distribution entry: {name!r}" for name in invalid)
            return 0
        if expected_distributions([entry.name for entry in entries], root, required, failures):
            for entry in entries:
                with entry.open("rb") as file:
                    count += audit_distribution(entry.name, file, failures, reference_hash)
        return count
    if not packages.is_file() or packages.is_symlink():
        failures.append("Expected a distribution directory or builder output archive")
        return 0
    # Docker emits a tar stream. Inspect its top-level files without extracting it.
    with tarfile.open(packages, "r:") as output:
        entries = [entry for entry in output.getmembers() if not (entry.isdir() and entry.name in (".", "./"))]
        invalid = [entry.name for entry in entries if not safe_archive_path(entry.name) or
                   len(PurePosixPath(entry.name).parts) != 1 or entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)]
        if invalid:
            failures.extend(f"Unsafe builder output entry: {name!r}" for name in invalid)
            return 0
        names = [PurePosixPath(entry.name).name for entry in entries]
        if expected_distributions(names, root, required, failures):
            for name, entry in zip(names, entries):
                with output.extractfile(entry) as file:
                    count += audit_distribution(name, file, failures, reference_hash)
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--packages", type=Path, help="Distribution directory or uncompressed tar stream from the builder")
    parser.add_argument("--require-distributions", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    git = shutil.which("git")
    if git is None:
        parser.error("git is required")
    reference = root / "wiki-1.4.md"
    reference_hash = hashlib.sha256(reference.read_bytes()).hexdigest() if reference.is_file() and not reference.is_symlink() else None
    failures, count = [], 0
    command = [git, "-C", str(root)]
    tracked = subprocess.run(command + ["ls-files", "-z"], capture_output=True, check=True).stdout
    for raw in tracked.split(b"\0"):
        if raw:
            name = raw.decode("utf-8")
            tracked_file = root / name
            data = str(tracked_file.readlink()).encode() if tracked_file.is_symlink() else tracked_file.read_bytes()
            check(name, data, failures, reference_hash)
            count += 1
    objects = subprocess.run(command + ["rev-list", "--objects", "--all"], capture_output=True, check=True).stdout
    seen = set()
    for line in objects.decode("utf-8").splitlines():
        oid, _, name = line.partition(" ")
        if not name or oid in seen:
            continue
        seen.add(oid)
        kind = subprocess.run(command + ["cat-file", "-t", oid], capture_output=True, check=True).stdout.strip()
        if kind == b"blob":
            data = subprocess.run(command + ["cat-file", "blob", oid], capture_output=True, check=True).stdout
            check(name, data, failures, reference_hash)
            count += 1
    for registry in ("wiki/claims.jsonl", "resources/sources/index.jsonl", "wiki/control/query-cases.jsonl",
                     "wiki/control/decisions.jsonl", "wiki/control/lessons.jsonl", "control/approvals/packages.jsonl"):
        if (root / registry).exists() and (root / registry).stat().st_size:
            failures.append("Distribution knowledge registry must start empty: " + registry)
    if args.packages:
        try:
            count += audit_packages(args.packages, root, args.require_distributions, failures, reference_hash)
        except (OSError, KeyError, TypeError, ValueError, tarfile.TarError, zipfile.BadZipFile):
            failures.append("Could not read the expected distributions or project metadata")
    elif args.require_distributions:
        failures.append("Expected a distribution directory")
    for failure in sorted(set(failures)):
        print(failure)
    print(f"Audited {count} tracked/archive/historical entries; {len(failures)} findings")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
