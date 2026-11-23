#!/usr/bin/env python3
"""Audit every reachable Git blob and distribution archive without printing content."""
import argparse
import hashlib
import os
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


def check_path(name, failures):
    if BAD_PATHS.search(name) or CONVERSATION.search(name):
        failures.append("Forbidden publication path: " + name)


def check_content(name, sha256, private, failures, reference_hashes):
    if private:
        failures.append("Possible credential in: " + name)
    if sha256 in reference_hashes:
        failures.append("Local reference content found under: " + name)


def check(name, data, failures, reference_hashes):
    check_path(name, failures)
    check_content(name, hashlib.sha256(data).hexdigest(), PRIVATE.search(data), failures, reference_hashes)


class AuditError(Exception):
    pass


class GitHistory:
    def __init__(self, executable, root):
        self.command = [executable, "-C", str(root)]
        self.env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        self.env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")

    def git(self, *args, check=True):
        return subprocess.run(self.command + list(args), env=self.env, capture_output=True, check=check).stdout

    def head(self):
        return self.git("rev-parse", "--verify", "--quiet", "HEAD", check=False).decode("ascii").strip()

    def verify_complete(self, root):
        if Path(os.fsdecode(self.git("rev-parse", "--show-toplevel").rstrip(b"\r\n"))).resolve() != root:
            raise AuditError("Select the root of the repository to audit")
        if self.git("rev-parse", "--is-shallow-repository").strip() != b"false":
            raise AuditError("Complete Git history is required. The repository is shallow")
        promisor = self.git("config", "--type=bool", "--get-regexp", r"^remote\..*\.promisor$", check=False)
        if (self.git("config", "--get", "extensions.partialclone", check=False) or
                any(line.rsplit(b" ", 1)[-1] == b"true" for line in promisor.splitlines())):
            raise AuditError("Complete Git history is required. The repository uses a partial clone")

    def occurrences(self, head, failures):
        """Deduplicate identical trees and keep every distinct path of a reachable blob."""
        trees = set(self.git("log", "--all", "--format=%T", *([head] if head else [])).decode("ascii").splitlines())
        result = set()
        refs = self.git("for-each-ref", "--format=%(objectname) %(objecttype) %(refname)")
        for line in refs.decode("utf-8").splitlines():
            oid, kind, name = line.split(" ", 2)
            if kind == "tag":
                oid = self.git("rev-parse", "--verify", oid + "^{}").decode("ascii").strip()
                kind = self.git("cat-file", "-t", oid).decode("ascii").strip()
            if kind == "tree":
                trees.add(oid)
            elif kind == "blob":
                result.add((name, oid))
        checked = set()
        for tree in sorted(trees):
            for entry in self.git("ls-tree", "-r", "-t", "-z", "--full-tree", tree).split(b"\0")[:-1]:
                info, raw = entry.split(b"\t", 1)
                _, kind, oid = info.decode("ascii").split()
                name = raw.decode("utf-8")
                if kind != "blob" and entry not in checked:
                    check_path(name, failures)
                    checked.add(entry)
                if kind == "blob":
                    result.add((name, oid))
                elif kind != "tree":
                    failures.append("Cannot audit the history of a Git link: " + name)
        return result

    def contents(self, objects):
        result = {}
        if not objects:
            return result
        with subprocess.Popen(self.command + ["cat-file", "--batch"], env=self.env, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            try:
                for oid in sorted(objects):
                    process.stdin.write(oid.encode("ascii") + b"\n")
                    process.stdin.flush()
                    header = process.stdout.readline().split()
                    if len(header) != 3 or header[0].decode("ascii") != oid or header[1] != b"blob":
                        raise AuditError("A reachable Git blob is unavailable")
                    size = int(header[2])
                    data = process.stdout.read(size)
                    if len(data) != size or process.stdout.read(1) != b"\n":
                        raise AuditError("A reachable Git blob is incomplete")
                    result[oid] = (hashlib.sha256(data).hexdigest(), PRIVATE.search(data) is not None)
            finally:
                process.stdin.close()
            if process.wait() != 0:
                raise AuditError("Git could not read historical objects")
        return result


def audit_repository(git, root, expected_commit, failures, reference_hashes):
    history = GitHistory(git, root)
    history.verify_complete(root)
    head = history.head()
    if expected_commit is not None and expected_commit != head:
        raise AuditError("Publication target HEAD differs from the selected commit")
    occurrences = history.occurrences(head, failures)
    contents = history.contents({oid for _, oid in occurrences})
    reference_hashes.update(contents[oid][0] for name, oid in occurrences
                            if PurePosixPath(name).name.lower() == "wiki-1.4.md")
    for name, oid in sorted(occurrences):
        check_path(name, failures)
        check_content(name, *contents[oid], failures, reference_hashes)
    tracked = history.git("ls-files", "-z")
    count = len(occurrences)
    for raw in tracked.split(b"\0")[:-1]:
        name = raw.decode("utf-8")
        tracked_file = root / name
        data = str(tracked_file.readlink()).encode() if tracked_file.is_symlink() else tracked_file.read_bytes()
        check(name, data, failures, reference_hashes)
        count += 1
    if history.head() != head:
        raise AuditError("Publication target HEAD changed during the audit")
    return count


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
    parser.add_argument("--expected-commit", help="Require the selected repository HEAD")
    parser.add_argument("--packages", type=Path, help="Distribution directory or uncompressed tar stream from the builder")
    parser.add_argument("--require-distributions", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    git = shutil.which("git")
    if git is None and os.name == "nt":
        candidate = Path("C:/Program Files/Git/cmd/git.exe")
        git = str(candidate) if candidate.is_file() else None
    if git is None:
        parser.error("git is required")
    reference = root / "wiki-1.4.md"
    reference_hashes = {hashlib.sha256(reference.read_bytes()).hexdigest()} if reference.is_file() and not reference.is_symlink() else set()
    failures, count = [], 0
    try:
        count = audit_repository(git, root, args.expected_commit, failures, reference_hashes)
    except AuditError as exc:
        failures.append(str(exc))
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError):
        failures.append("Could not audit the selected repository and its complete Git history")
    for registry in ("wiki/claims.jsonl", "resources/sources/index.jsonl", "wiki/control/query-cases.jsonl",
                     "wiki/control/decisions.jsonl", "wiki/control/lessons.jsonl", "control/approvals/packages.jsonl"):
        if (root / registry).exists() and (root / registry).stat().st_size:
            failures.append("Distribution knowledge registry must start empty: " + registry)
    if args.packages:
        try:
            count += audit_packages(args.packages, root, args.require_distributions, failures, reference_hashes)
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
