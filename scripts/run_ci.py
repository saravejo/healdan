#!/usr/bin/env python3
"""Execute the identified wheel and record each required test's outcome."""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def discover():
    loader = unittest.TestLoader()
    tests = unittest.TestSuite((loader.discover(str(ROOT / "tests")), loader.loadTestsFromName("scripts.test_sprint_gate")))

    def cases(suite):
        for member in suite:
            if isinstance(member, unittest.TestSuite):
                yield from cases(member)
            else:
                yield member

    return list(cases(tests)), list(loader.errors)


class Records(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []
        self.current = {}

    def startTest(self, test):
        super().startTest(test)
        entry = {"id": test.id(), "outcome": "started"}
        self.current[test] = entry
        self.records.append(entry)

    def outcome(self, test, value):
        if test not in self.current:
            self.current[test] = {"id": test.id()}
            self.records.append(self.current[test])
        self.current[test]["outcome"] = value

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcome(test, "passed")

    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.outcome(test, "failed")

    def addError(self, test, error):
        super().addError(test, error)
        self.outcome(test, "error")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcome(getattr(test, "test_case", test), "skipped")

    def addExpectedFailure(self, test, error):
        super().addExpectedFailure(test, error)
        self.outcome(test, "expected_failure")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.outcome(test, "unexpected_success")

    def addSubTest(self, test, subtest, error):
        super().addSubTest(test, subtest, error)
        if error is not None:
            self.outcome(test, "failed" if issubclass(error[0], test.failureException) else "error")


def dependencies(profile):
    from healdan.core import executable, require, run

    commands = {"git": "--version", "ssh": "-V", "age": "--version"}
    if profile == "macos":
        commands.update(node="--version", srt="--version")
    details = {"python": platform.python_version()}
    for dependency, flag in commands.items():
        result = run([executable(dependency), flag])
        details[dependency] = (result.stdout or result.stderr).decode("utf-8").strip()
    require(details["git"].startswith("git version ") and "OpenSSH" in details["ssh"], "Git and OpenSSH are required", 5)
    for name in ("age-keygen", "ssh-keygen"):
        details[name] = str(Path(executable(name)).resolve())
    return details


def run_tests(args, wheel):
    from healdan.build import running_build
    from healdan.core import atomic, digest, git, require
    from scripts.ci_evidence import PROFILES, REPOSITORY, RESULT_FORMAT, WORKFLOW, catalog, expected_tests, validate_results

    build = running_build()
    require(digest(wheel.read_bytes()) == build.identity["sha256"] and build.manifest["wheel"] == wheel.name,
            "Installed wheel differs from the CI artifact", 5)
    require(args.repository == REPOSITORY and args.workflow == WORKFLOW and args.commit == git(ROOT, "rev-parse", "HEAD") and
            args.run > 0 and args.attempt > 0 and args.artifact_id > 0, "CI context differs from the tested checkout", 5)
    profile = args.profile
    require(profile in PROFILES and PROFILES[profile] == platform.system(), "CI profile does not match the runner platform", 5)
    os.environ["HEALDAN_INSTALLED_TESTS"] = "1"
    index = catalog()
    required = expected_tests(profile, index)
    all_expected = set().union(*(expected_tests(name, index) for name in PROFILES))
    tests, errors = discover()
    ids = [test.id() for test in tests]
    if set(ids) != all_expected or len(ids) != len(set(ids)):
        errors.append("Discovered tests differ from the checked-in catalog")
    expected = {"repository": args.repository, "workflow": args.workflow, "run_id": args.run, "attempt": args.attempt,
                "commit": args.commit, "profile": profile, "build": build.identity, "wheel": wheel.name,
                "wheel_artifact_id": args.artifact_id}
    evidence = {"format": RESULT_FORMAT, **expected, "platform": platform.system(), "discovery_errors": errors,
                "tests": [], "tools": {}}
    try:
        evidence["tools"] = dependencies(profile)
        suite = unittest.TestSuite(test for test in tests if test.id() in required)
        result = unittest.TextTestRunner(verbosity=2, resultclass=Records).run(suite)
        evidence["tests"] = result.records
        running_build()  # Recheck that discovery and tests retained the installed controller.
        validate_results(evidence, expected, index)
    finally:
        atomic(args.work_dir / "results.json", evidence)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--profile", choices=("windows", "linux", "macos"), required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "saravejo/healdan"))
    parser.add_argument("--workflow", default=os.environ.get("GITHUB_WORKFLOW", "Verify controller"))
    parser.add_argument("--run", type=int, default=os.environ.get("GITHUB_RUN_ID"))
    parser.add_argument("--attempt", type=int, default=os.environ.get("GITHUB_RUN_ATTEMPT"))
    parser.add_argument("--installed", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    wheels = list(args.wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        parser.error("Expected the single wheel downloaded from the package job")
    if args.run is None or args.attempt is None or args.commit is None:
        parser.error("The CI run, attempt and commit are required")
    if args.installed:
        if not sys.flags.isolated:
            parser.error("The installed suite requires an isolated Python environment")
        return run_tests(args, wheels[0])
    sys.path.insert(0, str(ROOT / "src"))
    from healdan.installation import isolated_environment, prepare

    build = prepare(wheels[0], args.work_dir / "builds")
    command = [build.python, "-I", "-B", Path(__file__).resolve(), *sys.argv[1:], "--installed"]
    return subprocess.run(command, env=isolated_environment(), cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
