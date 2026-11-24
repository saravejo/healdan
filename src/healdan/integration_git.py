"""Git plumbing for integration at one worktree and one direct ref."""
from pathlib import Path
import re
import subprocess
import tempfile

from .binding import Repository
from .core import Blocked, git_bytes, git_process, require, safe_path, stamp, utc


REGULAR = {"100644", "100755"}
INPUT_DIRECTORIES = ("wiki", "resources/sources", "templates", "config", "control/approvals")


def oid(value):
    return isinstance(value, str) and re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", value)


def raw(root, *args, **kwargs):
    return git_bytes(root, "--no-replace-objects", *args, **kwargs)


def line(root, *args, **kwargs):
    return raw(root, *args, **kwargs).decode("utf-8").strip()


def admin_dir(root):
    return Path(line(root, "rev-parse", "--absolute-git-dir")).resolve()


def file_identity(path):
    stat = path.stat()
    require(stat.st_ino != 0, "Cannot identify integration directory: " + str(path), 5)
    return [stat.st_dev, stat.st_ino]


def symbolic(root, name):
    return line(root, "symbolic-ref", "--quiet", "--no-recurse", name, check=False)


def destination(vault):
    vault._check_binding()
    root = vault.root
    repository = Repository.open(root)
    require(repository == vault.repository, "Integration repository changed", 5)
    admin = admin_dir(root)
    if root != repository.primary:
        require((admin, root / ".git") in repository.linked_worktrees(),
                "Integration worktree metadata is not reciprocal", 5)
    ref = symbolic(root, "HEAD")
    require(not ref or ref.startswith("refs/heads/") and not symbolic(root, ref),
            "Integration requires a direct branch ref or a detached HEAD", 5)
    return {"vault": vault.identity, "binding": vault.binding["location"], "worktree": str(root),
            "git_dir": str(admin), "worktree_identity": file_identity(root), "git_identity": file_identity(admin),
            "mode": "branch" if ref else "detached", "ref": ref or "HEAD"}


def verify_destination(vault, frozen):
    actual = destination(vault)
    if actual == frozen:
        return
    if frozen["binding"] in vault.binding["previous"]:
        rebound = {**frozen, "binding": vault.binding["location"],
                   **{key: str(vault.relocated_path(frozen[key])) for key in ("worktree", "git_dir")}}
        if actual == rebound:
            return
    raise Blocked("Integration destination differs from recorded worktree, binding or HEAD", 5)


def ref_value(vault, frozen):
    verify_destination(vault, frozen)
    return line(vault.root, "rev-parse", "--verify", "--end-of-options", frozen["ref"], check=False)


def publish(vault, frozen, base, commit, operation):
    """Prepare the Git transaction before inspecting the now-locked HEAD."""
    argv, env = git_process(vault.root, "--no-replace-objects", "update-ref", "--create-reflog",
                            "-m", "Healdan integration " + operation, "--stdin")
    with subprocess.Popen(argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as process:
        def request(command, response):
            try:
                process.stdin.write(command)
                process.stdin.flush()
            except BrokenPipeError as exc:
                raise Blocked("Integration CAS refused by Git", 5) from exc
            require(process.stdout.readline() == response, "Integration CAS refused by Git", 5)

        try:
            request(b"start\n", b"start: ok\n")
            request(f"update HEAD {commit} {base}\nprepare\n".encode("ascii"), b"prepare: ok\n")
            verify_destination(vault, frozen)
            request(b"commit\n", b"commit: ok\n")
        finally:
            process.stdin.close()  # EOF aborts a prepared, uncommitted transaction.
        require(process.wait() == 0, "Integration CAS did not finish", 5)


def was_published(root, ref, operation, commit):
    expected = f"{commit} Healdan integration {operation}"
    report = line(root, "reflog", "show", "--format=%H %gs", ref, check=False)
    return expected in report.splitlines()


def entries(root, tree, *, scopes=(), recurse=False):
    args = ["ls-tree", "-z", "--full-tree", "-r" if recurse else "-t", tree]
    if scopes:
        args.extend(("--", *scopes))
    result = {}
    for item in raw(root, "--literal-pathspecs", *args).split(b"\0")[:-1]:
        info, name = item.split(b"\t", 1)
        result[name.decode("utf-8")] = tuple(info.decode("ascii").split())
    return result


def overlay_modes(root, base, files):
    modes = {}
    for name in files:
        parents = Path(name).parents
        scopes = [name, *(p.as_posix() for p in parents if p != Path("."))]
        before = entries(root, base, scopes=scopes)
        for ancestor in scopes[1:]:
            require(ancestor not in before or before[ancestor][1] == "tree",
                    "Integration path has a non-directory Git ancestor: " + ancestor)
        entry = before.get(name)
        require(entry is None or entry[0] in REGULAR and entry[1] == "blob",
                "Integration destination is not a regular Git file: " + name)
        modes[name] = [entry[0], entry[2]] if entry else None
    return modes


def blob(root, object_id):
    return raw(root, "cat-file", "blob", object_id)


def index_settings(path):
    return {"GIT_INDEX_FILE": str(path), "GIT_OPTIONAL_LOCKS": "0"}


def index_entries(root, files, *, settings=None):
    # Compare stage and persistent flags, ignoring the stat cache and fsmonitor bits.
    report = raw(root, "--literal-pathspecs", "ls-files", "--stage", "--debug", "-z", "--", *files,
                 settings=settings)
    result = {name: [] for name in files}
    while report:
        row, report = report.split(b"\0", 1)
        info, name = row.split(b"\t", 1)
        flags = re.match(rb"(?:[^\n]*\n){4}[^\n]*flags: ([0-9a-f]+)\n", report)
        require(flags, "Git index entry flags could not be read", 5)
        mode, object_id, stage = info.decode("ascii").split()
        result[name.decode("utf-8")].append([mode, object_id, int(stage), int(flags[1], 16) & 0x60008000])
        report = report[flags.end():]
    return result


def update_index(root, files, settings):
    rows = b"".join(f"{mode} {object_id}\t{name}\0".encode("utf-8")
                    for name, (mode, object_id) in files.items())
    raw(root, "-c", "core.splitIndex=false", "update-index", "-z", "--index-info", data=rows,
        settings=settings)


def prepare_tree(vault, base, modes, files):
    proposed = {name: [(modes[name] or ["100644"])[0],
                       raw(vault.root, "hash-object", "-w", "--no-filters", "--stdin",
                           data=body).decode("ascii").strip()] for name, body in files.items()}
    with tempfile.TemporaryDirectory(prefix="git-integration-", dir=vault.state) as temp:
        settings = index_settings(Path(temp) / "index")
        raw(vault.root, "-c", "core.sparseCheckout=false", "read-tree", base, settings=settings)
        update_index(vault.root, proposed, settings)
        return line(vault.root, "write-tree", settings=settings), proposed


def commit_identity(root):
    return {"author": identity_fields(root, "GIT_AUTHOR_IDENT"), "committer": identity_fields(root, "GIT_COMMITTER_IDENT"),
            "at": stamp()}


def identity_fields(root, variable):
    identity = line(root, "var", variable)
    match = re.fullmatch(r"(.+) <([^<>]*)> \d+ [+-]\d{4}", identity)
    require(match, "Git integration identity is unavailable", 5)
    return list(match.groups())


def make_commit(root, base, tree, package, identity):
    settings = {}
    when = f"@{int(utc(identity['at']).timestamp())} +0000"
    for role in ("author", "committer"):
        prefix = "GIT_" + role.upper()
        settings.update({prefix + "_NAME": identity[role][0], prefix + "_EMAIL": identity[role][1],
                         prefix + "_DATE": when})
    message = f"Healdan integration\n\nHealdan-Package: {package}\n".encode("ascii")
    return raw(root, "-c", "i18n.commitEncoding=UTF-8", "commit-tree", tree, "-p", base, "--no-gpg-sign",
               settings=settings, data=message).decode("ascii").strip()


def verify_commit(root, commit, base, tree, overlay, bodies):
    require(line(root, "cat-file", "-t", commit, check=False) == "commit", "Integration commit is missing", 5)
    header = raw(root, "cat-file", "commit", commit).split(b"\n\n", 1)[0].splitlines()
    require([row for row in header if row.startswith(b"parent ")] == [f"parent {base}".encode("ascii")] and
            header[0] == f"tree {tree}".encode("ascii"), "Integration commit parent or tree differs", 5)
    actual = entries(root, tree, scopes=overlay)
    for name, (mode, object_id) in overlay.items():
        require(actual.get(name) == (mode, "blob", object_id) and blob(root, object_id) == bodies[name],
                "Integration commit blob differs: " + name)


def materialize_inputs(root, tree, destination_root):
    from .backup_snapshot import paths_compatible
    inputs = entries(root, tree, scopes=INPUT_DIRECTORIES, recurse=True)
    paths_compatible(inputs)
    for name, (mode, kind, object_id) in inputs.items():
        require(mode in REGULAR and kind == "blob", "Candidate input is not a regular Git file: " + name)
        target = safe_path(destination_root, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob(root, object_id))
