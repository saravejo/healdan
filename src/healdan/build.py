"""Verify the wheel, installed controller and per-vault selection."""
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from hashlib import file_digest
from io import BytesIO
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

from . import __version__
from .core import Blocked, atomic, decode, digest, read_json, require, safe_path

BUILD_FORMAT = "healdan-controller-build-v1"
SELECTION_FORMAT = "healdan-controller-selection-v1"
BUILD_RECEIPT = "build.json"
SELECTION = "controller-build.json"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CAPABILITY_KEYS = {"binding", "config", "policy", "case", "package", "csp", "journal", "archive"}
WHEEL_NAME = re.compile(r"healdan-[A-Za-z0-9_.+!-]+\.whl\Z")


def store_path():
    return Path.home() / ".local/share/healdan/controller-builds"


def external(prefix, repository, state):
    resolved = Path(prefix).resolve()
    require(all(not resolved.is_relative_to(path) and not path.is_relative_to(resolved)
                for path in {*repository.worktree_roots(), repository.common, Path(state).resolve()}),
            "Controller installations must stay outside all vault worktrees and external state", 5)


def validate_store(store, root, state):
    from .binding import Repository, marker

    root = Path(root).resolve()
    repository = Repository.open(root) if (root / ".git").exists() else Repository(root, root, root / ".git")
    existing = marker(repository.control)
    selected = existing["location"]["state"] if existing else repository.default_state
    external(store, repository, selected)
    if state is not None and Path(state).resolve() != Path(selected):
        external(store, repository, state)


def program(prefix, command):
    prefix = Path(prefix)
    return prefix / ("Scripts" if os.name == "nt" else "bin") / (command + (".exe" if os.name == "nt" else ""))


def wheel_details(filename, body):
    require(WHEEL_NAME.fullmatch(filename), "Expected a Healdan wheel", 2)
    try:
        return _wheel_details(filename, body)
    except (KeyError, ValueError, zipfile.BadZipFile) as exc:
        raise Blocked("Invalid controller wheel metadata", 5) from exc


def _wheel_details(filename, body):
    files = {}
    metadata = {}
    with zipfile.ZipFile(BytesIO(body)) as wheel:
        for entry in wheel.infolist():
            name = entry.orig_filename
            p = PurePosixPath(name)
            require(not p.is_absolute() and len(p.parts) > 1 and p.as_posix() == name and ".." not in p.parts and
                    not any(c in name for c in ("\\", ":", "\0")) and not entry.is_dir() and
                    stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG) and name not in files,
                    "Wheel has an unsafe or duplicate entry")
            data = wheel.read(entry)
            files[name] = digest(data)
            if name in {"healdan/controller_formats.json", "healdan/defaults.json"} or p.name in {"METADATA", "WHEEL", "entry_points.txt"}:
                metadata[name] = data
    dist_infos = {PurePosixPath(name).parts[0] for name in files if not name.startswith("healdan/")}
    require(len(dist_infos) == 1, "Expected one distribution metadata directory")
    dist = dist_infos.pop()
    require(dist.startswith("healdan-") and dist.endswith(".dist-info"), "Unexpected wheel distribution")
    meta = BytesParser(policy=policy.default).parsebytes(metadata[dist + "/METADATA"])
    version = meta["Version"]
    require(meta["Name"] == "healdan" and version and dist == f"healdan-{version}.dist-info" and
            filename.startswith(f"healdan-{version}-"), "Wheel name and version disagree")
    require(meta.get("Requires-Dist") is None, "Controller wheel dependencies must be prepared explicitly", 5)
    require(metadata[dist + "/WHEEL"] and b"healdan = healdan.cli:main" in metadata[dist + "/entry_points.txt"] and
            "healdan/__init__.py" in files and "healdan/__main__.py" in files and dist + "/RECORD" in files,
            "Missing controller package or entry point")
    caps = decode(metadata["healdan/controller_formats.json"])
    require(isinstance(caps, dict) and set(caps) == CAPABILITY_KEYS and
            all(isinstance(items, list) and all(item is None or type(item) in {int, str} for item in items)
                for items in caps.values()), "Invalid controller format capabilities")
    defaults = decode(metadata["healdan/defaults.json"])
    require(defaults.get("schema_version") in caps["policy"], "Controller policy and capabilities disagree")
    del files[dist + "/RECORD"]  # pip writes a new installation-specific RECORD.
    return {"format": BUILD_FORMAT, "sha256": digest(body), "version": str(version), "wheel": filename,
            "capabilities": caps, "files": files}


def _binary_identity(path):
    path = Path(path).resolve()
    require(path.is_file() and (os.name == "nt" or os.access(path, os.X_OK)),
            "Controller interpreter is unavailable", 5)
    with path.open("rb") as stream:
        return {"path": str(path), "sha256": file_digest(stream, "sha256").hexdigest()}


def _base_runtime(path):
    base = _binary_identity(path)
    runtime = {"base": base}
    if os.name == "nt":
        runtime["windows_runtime"] = {p.name: _binary_identity(p)
                                      for p in sorted(Path(base["path"]).parent.glob("python3*.dll"))}
    return runtime


def _startup_files(prefix, site_packages, python):
    files = {}
    for path in sorted(site_packages.iterdir()):
        name = path.name.lower()
        if name.endswith(".pth") or name.split(".", 1)[0] in {"sitecustomize", "usercustomize"}:
            require(path.is_file(), "Unexpected Python startup directory: " + path.name, 5)
            relative = path.relative_to(prefix)
            files[relative.as_posix()] = digest(safe_path(prefix, relative, exists=True).read_bytes())
    for directory in {prefix, python.parent}:
        for path in sorted(directory.iterdir()):
            name = path.name.lower()
            if name.endswith("._pth") or (directory != prefix and name == "pyvenv.cfg"):
                relative = path.relative_to(prefix)
                files[relative.as_posix()] = digest(safe_path(prefix, relative, exists=True).read_bytes())
    return files


def installed_layout(prefix, details, base_executable, *, base_runtime=None):
    candidates = ([prefix / "Lib/site-packages"] if os.name == "nt" else
                  list((prefix / "lib").glob("python*/site-packages")))
    candidates = [p for p in candidates if p.is_dir()]
    require(len(candidates) == 1, "Controller build has no unique installed package directory", 5)
    site_packages = safe_path(prefix, candidates[0].relative_to(prefix))
    for name, sha256 in details["files"].items():
        actual = safe_path(site_packages, name, exists=True)
        require(digest(actual.read_bytes()) == sha256, "Installed file differs from the wheel: " + name, 5)
    installed_package = {p.relative_to(site_packages).as_posix() for p in (site_packages / "healdan").rglob("*")
                         if (p.is_file() or p.is_symlink()) and "__pycache__" not in p.parts}
    require(installed_package == {name for name in details["files"] if name.startswith("healdan/")},
            "Installed controller has unexpected files", 5)
    cfg = safe_path(prefix, "pyvenv.cfg", exists=True)
    entry = program(prefix, "healdan")
    require(os.access(entry, os.X_OK), "Controller entry point is unavailable", 5)
    python = program(prefix, "python")
    safe_path(prefix, python.parent.relative_to(prefix))
    runtime = base_runtime if base_runtime is not None else _base_runtime(base_executable)
    binaries = {"program": _binary_identity(python), **runtime}
    return {"site_packages": site_packages.relative_to(prefix).as_posix(),
            "venv_config_sha256": digest(cfg.read_bytes()),
            "entry_point_sha256": digest(safe_path(prefix, entry.relative_to(prefix), exists=True).read_bytes()),
            "python": binaries, "startup_files": _startup_files(prefix, site_packages, python)}


@dataclass(frozen=True)
class Build:
    prefix: Path
    manifest: dict

    @property
    def identity(self):
        return {"version": self.manifest["version"], "sha256": self.manifest["sha256"]}

    @property
    def python(self):
        return program(self.prefix, "python")

    @property
    def entry_point(self):
        return program(self.prefix, "healdan")

    def running(self):
        return (Path(sys.prefix).resolve() == self.prefix and
                Path(__file__).resolve().parent == self.prefix / self.manifest["layout"]["site_packages"] / "healdan" and
                __version__ == self.manifest["version"])


def verify_build(prefix):
    prefix = Path(prefix).resolve()
    manifest = read_json(safe_path(prefix, BUILD_RECEIPT, exists=True))
    require(isinstance(manifest, dict) and manifest.get("format") == BUILD_FORMAT and
            manifest.get("sha256") == prefix.name and SHA256.fullmatch(prefix.name) and
            isinstance(manifest.get("wheel"), str) and WHEEL_NAME.fullmatch(manifest["wheel"]),
            "Invalid controller build manifest", 5)
    wheel = safe_path(prefix, "artifact/" + manifest["wheel"], exists=True)
    data = wheel.read_bytes()
    require(digest(data) == prefix.name, "Saved wheel digest differs from the selected controller", 5)
    details = wheel_details(wheel.name, data)
    recorded_python = manifest.get("layout", {}).get("python", {})
    base_executable = recorded_python.get("base", {}).get("path")
    require(isinstance(base_executable, str) and Path(base_executable).is_absolute(),
            "Controller build manifest has no verified base interpreter", 5)
    recovery = ("The recorded base Python is unavailable or changed. Prepare the same wheel and activate it "
                "from a new store using scripts/setup.py --wheel WHEEL --store NEW_STORE.")
    try:
        current = _base_runtime(base_executable)
    except (Blocked, OSError) as exc:
        raise Blocked(recovery, 5) from exc
    require(current == {key: value for key, value in recorded_python.items() if key != "program"}, recovery, 5)
    require(dict(details, layout=installed_layout(prefix, details, base_executable, base_runtime=current)) == manifest,
            "Controller build manifest does not match the verified wheel and environment", 5)
    return Build(prefix, manifest)


def running_build():
    build = verify_build(sys.prefix)
    require(build.running(), "Running controller does not come from its verified wheel", 5)
    return build


def read_selection(control, vault_id):
    path = safe_path(control, SELECTION)
    if not path.exists():
        return None
    value = read_json(path)
    require(isinstance(value, dict) and set(value) == {"format", "vault_id", "prefix", "sha256", "version"} and
            value["format"] == SELECTION_FORMAT and value["vault_id"] == vault_id and
            isinstance(value["sha256"], str) and SHA256.fullmatch(value["sha256"]) and
            isinstance(value["prefix"], str) and Path(value["prefix"]).is_absolute() and
            Path(value["prefix"]).name == value["sha256"] and isinstance(value["version"], str),
            "Controller selection is invalid or belongs to another vault", 5)
    return value


def selected_build(repository, binding, selection):
    external(selection["prefix"], repository, binding["location"]["state"])
    build = verify_build(selection["prefix"])
    require(build.prefix == Path(selection["prefix"]) and build.identity ==
            {key: selection[key] for key in ("sha256", "version")}, "Selected controller identity changed", 5)
    return build


def active(vault):
    with vault.reading():
        selection = read_selection(vault.control, vault.identity)
        require(selection, "Activate a verified controller build for this vault", 5)
        return selected_build(vault.repository, vault.binding, selection)


def require_active(vault):
    build = active(vault)
    require(build.running(), "Use the installed controller command selected for this vault", 5)
    return build


def activate(vault, sha256, store=None):
    from .compatibility import check
    from .launchd import legacy_jobs, require_removed

    require(SHA256.fullmatch(sha256), "Expected the prepared controller SHA-256", 2)
    prefix = Path(store if store is not None else store_path()).resolve() / sha256
    with vault.locked():
        require_removed(legacy_jobs(vault.binding["location"], vault.binding["previous"]), "build activation")
        external(prefix, vault.repository, vault.state)
        build = verify_build(prefix)
        previous = read_selection(vault.control, vault.identity)
        check(vault, build.manifest["capabilities"])
        selection = {"format": SELECTION_FORMAT, "vault_id": vault.identity, "prefix": str(build.prefix),
                     **build.identity}
        if selection != previous:
            atomic(vault.control / SELECTION, selection)
    return {"build": build.identity, "vault_id": vault.identity, "controller": str(build.entry_point),
            "command": [str(build.entry_point), "--vault", str(vault.repository.primary)]}
