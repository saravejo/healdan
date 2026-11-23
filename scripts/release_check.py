#!/usr/bin/env python3
"""Verify the selected vault, controller, Actions attempt and native release evidence."""
import argparse
from pathlib import Path
import subprocess
import sys
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


def assess(vault, build, run_id, attempt):
    from healdan.build import require_active
    from healdan.core import Blocked, git, run
    from healdan.maintenance import trial_status
    from scripts.ci_evidence import GitHub, verify

    commit = vault.head()
    clean = bool(commit) and not git(vault.root, "status", "--porcelain")
    ci = {"verified": False, "reason": "A successful Actions attempt with structured results is required"}
    if build is None:
        ci["reason"] = "The selected vault needs an active verified wheel"
    elif run_id is not None:
        try:
            ci = verify(GitHub(), run_id, attempt, commit, build)
        except (Blocked, OSError, KeyError, TypeError, ValueError, zipfile.BadZipFile) as exc:
            ci["reason"] = str(exc)
    audit = run([sys.executable, "-I", HERE / "audit_publication.py", "--root", vault.root,
                 "--expected-commit", commit or ""], check=False, timeout=300)
    with vault.locked():
        trials = trial_status(vault)
        ready = clean and ci["verified"] and audit.returncode == 0 and all(row["passed"] for row in trials)
        if ready:
            ready = require_active(vault).identity == build.identity and vault.head() == commit
            clean = clean and not git(vault.root, "status", "--porcelain")
    return {"commit": commit, "clean": clean, "build": build.identity if build else None, "trials": trials,
            "ci": ci, "publication_audit": audit.returncode == 0, "stable_release_allowed": ready and clean}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vault", default=".")
    parser.add_argument("--state")
    parser.add_argument("--ci-run", type=int)
    parser.add_argument("--ci-attempt", type=int)
    parser.add_argument("--installed", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.installed and not sys.flags.isolated:
        parser.error("The verified release process requires an isolated Python environment")
    if not args.installed:
        sys.path.insert(0, str(HERE.parent / "src"))
    from healdan.build import active, require_active
    from healdan.core import Blocked, Vault, canonical
    from healdan.installation import isolated_environment
    from healdan.maintenance import TRIALS

    try:
        vault = Vault(args.vault, args.state)
        build = None
        if args.installed:
            build = require_active(vault)
        else:
            try:
                build = active(vault)
            except (Blocked, OSError, KeyError, TypeError, ValueError):
                pass
            if build:
                command = [build.python, "-I", "-B", Path(__file__).resolve(), *argv, "--installed"]
                return subprocess.run(command, env=isolated_environment()).returncode
        result = assess(vault, build, args.ci_run, args.ci_attempt)
    except (Blocked, OSError, KeyError, TypeError, ValueError) as exc:
        result = {"commit": None, "clean": False, "build": None,
                  "trials": [{"name": name, "passed": False, "reason": "Personal macOS trial is pending"} for name in TRIALS],
                  "ci": {"verified": False, "reason": str(exc)}, "publication_audit": False, "stable_release_allowed": False}
    sys.stdout.buffer.write(canonical(result) + b"\n")
    return 0 if result["stable_release_allowed"] else 5


if __name__ == "__main__":
    raise SystemExit(main())
