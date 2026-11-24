#!/usr/bin/env python3
"""Prepare a wheel outside the vault and activate its verified controller."""
import argparse
from pathlib import Path
import sys
import tempfile

if sys.version_info < (3, 12):
    raise SystemExit("Python 3.12+ is required")

SOURCE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOURCE / "src"))
from healdan.build import store_path, validate_store
from healdan.core import Blocked, canonical, require, run
from healdan.installation import prepare, run_installed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vault", type=Path, default=SOURCE)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--store", type=Path, default=store_path())
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--interactive", action=argparse.BooleanOptionalAction, default=sys.stdin.isatty())
    args = parser.parse_args()
    try:
        validate_store(args.store, args.vault, args.state)
        if args.wheel:
            build = prepare(args.wheel, args.store)
        else:
            with tempfile.TemporaryDirectory(prefix="healdan-wheel-") as directory:
                run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", directory, SOURCE], timeout=300)
                wheels = list(Path(directory).glob("*.whl"))
                require(len(wheels) == 1, "Expected one controller wheel")
                build = prepare(wheels[0], args.store)
        if args.prepare_only:
            print(canonical({"build": build.identity, "controller": str(build.entry_point)}).decode("utf-8"))
            return 0
        selection = ["--vault", str(args.vault)]
        if args.state is not None:
            selection.extend(("--state", str(args.state)))
        result = run_installed(build, [*selection, "setup", *(["--interactive"] if args.interactive else [])])
        if result:
            return result
        return run_installed(build, [*selection, "build", "activate", build.identity["sha256"], "--store", args.store])
    except (Blocked, OSError, ValueError) as exc:
        print(canonical({"error": str(exc)}).decode("utf-8"))
        return exc.code if isinstance(exc, Blocked) else 1


if __name__ == "__main__":
    raise SystemExit(main())
