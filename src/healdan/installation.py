"""Prepare an immutable controller environment at its final executable path."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import venv

from .build import BUILD_RECEIPT, Build, installed_layout, program, store_path, verify_build, wheel_details
from .core import atomic, lock, read_json, require, run, safe_path

PENDING = "build-pending.json"


def isolated_environment():
    variables = {k: v for k, v in os.environ.items() if not k.upper().startswith("PYTHON")}
    variables.update(PYTHONDONTWRITEBYTECODE="1", PYTHONSAFEPATH="1")
    return variables


def _install(prefix, wheel):
    venv.EnvBuilder(with_pip=True).create(prefix)
    run([program(prefix, "python"), "-I", "-B", "-m", "pip", "--isolated", "--disable-pip-version-check", "install",
         "--no-index", "--no-deps", "--no-compile", wheel], cwd=prefix, env=isolated_environment())


def _smoke(prefix, details):
    command = program(prefix, "healdan")
    env = isolated_environment()
    actual = run([command, "--version"], cwd=prefix, env=env).stdout.decode().strip()
    require(actual == details["version"], "Prepared controller entry point reports a different version", 5)
    check = "import healdan, sys; print(sys.prefix); print(healdan.__file__); print(sys._base_executable)"
    lines = run([program(prefix, "python"), "-I", "-B", "-c", check], cwd=prefix, env=env).stdout.decode().splitlines()
    require(len(lines) == 3 and Path(lines[0]).resolve() == prefix and
            Path(lines[1]).resolve().is_relative_to(prefix) and
            Path(lines[2]).resolve() == Path(sys._base_executable).resolve(),
            "Prepared controller did not load from the final venv with its recorded base interpreter", 5)


def prepare(wheel, store=None):
    wheel = Path(wheel).resolve()
    data = wheel.read_bytes()
    details = wheel_details(wheel.name, data)
    store = Path(store if store is not None else store_path()).resolve()
    store.mkdir(parents=True, exist_ok=True)
    store = store.resolve()
    (store / ".locks").mkdir(exist_ok=True)
    key = details["sha256"]
    with lock(safe_path(store, ".locks/" + key + ".lock"), timeout=120):
        prefix = safe_path(store, key)
        manifest_path = safe_path(prefix, BUILD_RECEIPT)
        if manifest_path.exists():
            build = verify_build(prefix)
            require({k: build.manifest[k] for k in details} == details, "Prepared build does not match the requested wheel", 5)
            return build
        intent = {"sha256": key, "wheel": wheel.name, "version": details["version"]}
        pending = safe_path(prefix, PENDING)
        if prefix.exists() and any(prefix.iterdir()):
            require(read_json(pending) == intent, "Unexpected files at the final installation path", 5)
            shutil.rmtree(prefix)
        prefix.mkdir(mode=0o700, parents=True, exist_ok=True)
        atomic(pending, intent)
        copied = prefix / "artifact" / wheel.name
        atomic(copied, data)
        _install(prefix, copied)
        layout = installed_layout(prefix, details, sys._base_executable)
        _smoke(prefix, details)
        require(installed_layout(prefix, details, sys._base_executable) == layout,
                "Controller environment changed during the smoke test", 5)
        manifest = dict(details, layout=layout)
        atomic(manifest_path, manifest)
        pending.unlink()
        return Build(prefix, manifest)


def run_installed(build, args):
    # With -I, an editor's checkout and PYTHONPATH cannot override the prepared wheel.
    command = [str(build.python), "-I", "-B", "-m", "healdan", *map(str, args)]
    return subprocess.run(command, env=isolated_environment()).returncode
