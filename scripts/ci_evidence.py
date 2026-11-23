"""Structured controller test evidence and verification against the Actions attempt."""
from io import BytesIO
from pathlib import Path
import stat
import zipfile

from healdan.core import Blocked, decode, digest, executable, read_json, require, run

REPOSITORY = "saravejo/healdan"
REPOSITORY_ID = 1465945296
REPO = "/repos/" + REPOSITORY
WORKFLOW = "Verify controller"
WORKFLOW_PATH = ".github/workflows/ci.yml"
RESULT_FORMAT = "healdan-ci-results-v1"
PROFILES = {"windows": "Windows", "linux": "Linux", "macos": "Darwin"}
SETUP_STEPS = {"package": {"Audit wheel, source distribution and full history", "Upload tested wheel"},
               "test": {"Require all installed controller profiles"}}
PROFILE_STEPS = {"Run installed controller tests", "Upload structured profile results"}


def catalog():
    return read_json(Path(__file__).with_name("ci_catalog.json"))


def expected_tests(profile, index):
    require(profile in PROFILES, "Unknown CI profile", 5)
    tests = index["all"] + index.get(profile, [])
    require(tests and all(isinstance(test, str) and test for test in tests) and len(tests) == len(set(tests)),
            "Invalid required CI test catalog", 5)
    return set(tests)


def wheel_name(attempt):
    return f"healdan-wheel-{attempt}"


def results_name(profile, attempt):
    return f"healdan-results-{profile}-{attempt}"


def validate_results(value, expected, index):
    profile = expected["profile"]
    require(isinstance(value, dict) and value.get("format") == RESULT_FORMAT and
            all(type(value.get(key)) is type(item) and value[key] == item for key, item in expected.items()),
            "CI result does not match the selected commit, profile, attempt and wheel", 5)
    require(value.get("platform") == PROFILES[profile] and value.get("discovery_errors") == [],
            "CI test discovery did not complete on the required platform", 5)
    tools = value.get("tools", {})
    required_tools = {"python", "git", "ssh", "ssh-keygen", "age", "age-keygen"}
    if profile == "macos":
        required_tools |= {"node", "srt"}
    require(isinstance(tools, dict) and set(tools) == required_tools and
            all(isinstance(version, str) and version.strip() for version in tools.values()),
            "CI did not record the required real dependencies", 5)
    tests = value.get("tests")
    require(isinstance(tests, list), "Missing individual CI test results", 5)
    by_id = {}
    for test in tests:
        require(isinstance(test, dict) and isinstance(test.get("id"), str) and test["id"] not in by_id,
                "Duplicate or malformed CI test result", 5)
        by_id[test["id"]] = test.get("outcome")
    required = expected_tests(profile, index)
    require(set(by_id) == required, "CI test results differ from the required profile catalog", 5)
    require(all(by_id[test] == "passed" for test in required), "A required CI test did not pass", 5)


class GitHub:
    def raw(self, path):
        return run([executable("gh"), "api", "--hostname", "github.com", path]).stdout

    def get(self, path):
        return decode(self.raw(path))


def _positive(value):
    return type(value) is int and value > 0


def _jobs(api, path, run_id, attempt, head):
    values = api.get(path + "/jobs?per_page=100")
    rows = values["jobs"]
    require(values["total_count"] == len(rows), "CI jobs list is incomplete", 5)
    required = {**SETUP_STEPS, **{"test-" + profile: PROFILE_STEPS for profile in PROFILES}}
    for name, steps in required.items():
        matches = [row for row in rows if row["name"] == name]
        require(len(matches) == 1, "Required CI job is unavailable or duplicated: " + name, 5)
        job = matches[0]
        require(job.get("run_id") == run_id and job.get("run_attempt", attempt) == attempt and job.get("head_sha") == head and
                job.get("status") == "completed" and job.get("conclusion") == "success",
                "Required CI job did not succeed in the selected attempt: " + name, 5)
        for step in steps:
            ran = [row for row in job.get("steps", []) if row["name"] == step]
            require(len(ran) == 1 and ran[0].get("status") == "completed" and ran[0].get("conclusion") == "success",
                    "Required CI step did not succeed: " + name + " / " + step, 5)


def _artifacts(api, path):
    rows = []
    page = 1
    while True:
        result = api.get(f"{path}/artifacts?per_page=100&page={page}")
        batch = result["artifacts"]
        rows.extend(batch)
        if len(batch) < 100:
            require(len(rows) == result["total_count"], "CI artifacts list changed or is incomplete", 5)
            return rows
        page += 1


def _artifact(api, artifacts, name, filename, run_id, head):
    matches = [row for row in artifacts if row["name"] == name]
    require(len(matches) == 1, "CI artifact is unavailable or duplicated: " + name, 5)
    value = matches[0]
    origin = value.get("workflow_run") or {}
    identifier = value.get("id")
    require(_positive(identifier) and value.get("expired") is False and
            origin.get("id") == run_id and origin.get("head_sha") == head and
            origin.get("repository_id") == REPOSITORY_ID and origin.get("head_repository_id") == REPOSITORY_ID,
            "CI artifact belongs to another run or commit: " + name, 5)
    archive = api.raw(f"{REPO}/actions/artifacts/{identifier}/zip")
    require(value.get("size_in_bytes") == len(archive) and value.get("digest") == "sha256:" + digest(archive),
            "CI artifact archive does not match GitHub's digest: " + name, 5)
    with zipfile.ZipFile(BytesIO(archive)) as zipped:
        entries = zipped.infolist()
        require(len(entries) == 1 and entries[0].orig_filename == filename and not entries[0].is_dir() and
                stat.S_IFMT(entries[0].external_attr >> 16) in (0, stat.S_IFREG),
                "Unexpected contents of CI artifact: " + name, 5)
        return identifier, zipped.read(entries[0])


def verify(api, run_id, requested_attempt, head, build, index=None):
    require(_positive(run_id), "Expected a GitHub Actions run ID", 5)
    index = index if index is not None else catalog()
    path = f"{REPO}/actions/runs/{run_id}"
    workflow = api.get(f"{REPO}/actions/workflows/ci.yml")
    current = api.get(path)
    attempt = current.get("run_attempt")
    require(_positive(attempt) and (requested_attempt is None or requested_attempt == attempt),
            "Select the current CI attempt for this run", 5)
    attempt_path = f"{path}/attempts/{attempt}"
    recorded = api.get(attempt_path)
    require(_positive(workflow.get("id")) and workflow.get("path") == WORKFLOW_PATH and
            workflow.get("name") == WORKFLOW and workflow.get("state") == "active", "Unexpected CI workflow", 5)
    for value in (current, recorded):
        require(value.get("id") == run_id and value.get("workflow_id") == workflow["id"] and
                value.get("path") in {WORKFLOW_PATH, WORKFLOW_PATH + "@refs/heads/main"} and value.get("name") == WORKFLOW and
                value.get("status") == "completed" and value.get("conclusion") == "success" and value.get("head_sha") == head and
                value.get("run_attempt") == attempt and value.get("head_branch") == "main" and
                value.get("event") in {"push", "workflow_dispatch"} and
                value["repository"]["full_name"] == REPOSITORY and value["repository"]["id"] == REPOSITORY_ID and
                value["head_repository"]["id"] == REPOSITORY_ID,
                "CI workflow run does not identify a successful attempt on the selected commit", 5)
    _jobs(api, attempt_path, run_id, attempt, head)
    artifacts = _artifacts(api, path)
    wheel = build.manifest["wheel"]
    wheel_id, data = _artifact(api, artifacts, wheel_name(attempt), wheel, run_id, head)
    require(digest(data) == build.identity["sha256"], "Tested wheel differs from the selected controller build", 5)
    results = {}
    for profile in PROFILES:
        artifact_id, data = _artifact(api, artifacts, results_name(profile, attempt), "results.json", run_id, head)
        expected = {"repository": REPOSITORY, "workflow": WORKFLOW, "run_id": run_id, "attempt": attempt,
                    "commit": head, "profile": profile, "build": build.identity, "wheel": wheel,
                    "wheel_artifact_id": wheel_id}
        validate_results(decode(data), expected, index)
        results[profile] = artifact_id
    return {"verified": True, "attempt": attempt, "run": run_id, "url": current.get("html_url"),
            "wheel_sha256": build.identity["sha256"], "wheel_artifact_id": wheel_id, "profiles": results}
