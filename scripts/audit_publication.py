#!/usr/bin/env python3
"""Audit every reachable Git blob and distribution archive without printing content."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from healdan.core import executable

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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packages", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    git = executable("git")
    reference = root / "wiki-1.4.md"
    reference_hash = hashlib.sha256(reference.read_bytes()).hexdigest() if reference.exists() else None
    failures, count = [], 0
    command = [git, "-C", str(root)]
    tracked = subprocess.run(command + ["ls-files", "-z"], capture_output=True, check=True).stdout
    for raw in tracked.split(b"\0"):
        if raw:
            name = raw.decode("utf-8")
            check(name, (root / name).read_bytes(), failures, reference_hash)
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
        for package in args.packages.iterdir():
            if package.suffix in {"whl", ".zip"} or package.suffix == ".whl":
                with zipfile.ZipFile(package) as archive:
                    for entry in archive.infolist():
                        if not entry.is_dir():
                            check(entry.filename, archive.read(entry), failures, reference_hash)
                            count += 1
            elif package.name.endswith(".tar.gz"):
                with tarfile.open(package) as archive:
                    for entry in archive.getmembers():
                        if entry.isfile():
                            check(entry.name, archive.extractfile(entry).read(), failures, reference_hash)
                            count += 1
    for failure in sorted(set(failures)):
        print(failure)
    print(f"Audited {count} tracked/archive/historical entries; {len(failures)} findings")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
