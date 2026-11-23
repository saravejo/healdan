#!/usr/bin/env python3
"""Verify a sprint pull request with metadata from GitHub and protected main."""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


REPOSITORY = "saravejo/healdan"
REPOSITORY_ID = 1465945296
REPO = "/repos/" + REPOSITORY
WEB = "https://github.com/" + REPOSITORY
BASE = "main"
WORKFLOW = ".github/workflows/sprint-b00.yml"
BOOTSTRAP_BRANCH = "sprint-gate-bootstrap"
BOOTSTRAP_WORKFLOW = ".github/workflows/ci.yml"
CHECK = "sprint/b00"
ACTIONS_APP = 15368
MATRIX = "docs/sprint-autonoma/matriz.json"
B00_CONTRACT = "docs/sprint-autonoma/B00.md"


class Blocked(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Blocked(message)


def sha(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value), "Expected a full commit SHA")
    return value


def number(value):
    require(type(value) in (str, int) and re.fullmatch(r"[1-9][0-9]{0,19}", str(value)), "Expected a GitHub ID")
    return int(value)


def digest(data):
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token):
        require(bool(token), "A GitHub token is required")
        self.opener = build_opener(NoRedirect())
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "healdan-sprint-gate",
        }

    def request(self, route, method="GET", payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request("https://api.github.com" + route, data, self.headers, method=method)
        try:
            with self.opener.open(request, timeout=30) as response:
                return json.load(response), response.headers.get("Link", "")
        except URLError as exc:
            raise Blocked(f"GitHub API request failed ({method} {route.split('?')[0]}, HTTP {getattr(exc, 'code', 'unavailable')})") from None

    def get(self, route):
        return self.request(route)[0]

    def text_at(self, path, commit):
        blob = self.get(f"{REPO}/contents/{path}?ref={commit}")
        require(blob["type"] == "file" and blob["encoding"] == "base64", "Protected policy file is unavailable")
        return base64.b64decode(blob["content"]).decode("utf-8").replace("\r\n", "\n")

    def job_log(self, job_id):
        request = Request(f"https://api.github.com{REPO}/actions/jobs/{job_id}/logs", headers=self.headers)
        try:
            with self.opener.open(request, timeout=30) as response:
                return self.read_log(response)
        except HTTPError as exc:
            require(exc.code == 302 and exc.headers.get("Location"), "Actions job logs are unavailable")
            location = urlsplit(exc.headers["Location"])
            require(location.scheme == "https" and location.hostname and not location.username, "Invalid job logs redirect")
            # The signed storage URL receives no GitHub Authorization header.
            with self.opener.open(location.geturl(), timeout=30) as response:
                return self.read_log(response)

    @staticmethod
    def read_log(response):
        limit = 4 * 1024 * 1024
        body = response.read(limit + 1)
        require(len(body) <= limit, "Actions gate log exceeded its verification limit")
        return body.decode("utf-8-sig")

    def pages(self, route, key=None, **params):
        for page in range(1, 1001):
            query = urlencode(params | {"page": page, "per_page": 100})
            response, links = self.request(f"{route}?{query}")
            rows = response[key] if key else response
            require(isinstance(rows, list), "GitHub returned an invalid page")
            yield from rows
            if 'rel="next"' not in links:
                return
        raise Blocked("GitHub pagination could not be completed")

    def edits(self, node, kind):
        typename = {"issue": "IssueComment", "inline": "PullRequestReviewComment", "review": "PullRequestReview"}[kind]
        query = """
          query($id: ID!, $after: String) {
            node(id: $id) {
              ... on TYPE {
                lastEditedAt
                userContentEdits(first: 100, after: $after) {
                  nodes { id diff deletedAt }
                  pageInfo { hasNextPage endCursor }
                }
              }
            }
          }
        """.replace("TYPE", typename)
        cursor = None
        for _ in range(1000):
            response, _ = self.request("/graphql", "POST", {"query": query, "variables": {"id": node, "after": cursor}})
            require(not response.get("errors"), "Could not retrieve Qodo edit history")
            content = response["data"]["node"]
            require(content and "lastEditedAt" in content, "Qodo record disappeared during verification")
            if content["lastEditedAt"] is None:
                return
            edits = content["userContentEdits"]
            require(edits and edits["nodes"], "Qodo edit history is unavailable")
            for edit in edits["nodes"]:
                require(edit and isinstance(edit["diff"], str) and not edit["deletedAt"], "Qodo edit content is unavailable")
                yield edit
            page = edits["pageInfo"]
            if not page["hasNextPage"]:
                return
            require(page["endCursor"] and page["endCursor"] != cursor, "Qodo edit history could not be paginated")
            cursor = page["endCursor"]
        raise Blocked("Qodo edit history could not be completed")

    def deleted_qodo_comment(self, pull, bot_id):
        query = """
          query($pull: Int!, $after: String) {
            repository(owner: "saravejo", name: "healdan") {
              pullRequest(number: $pull) {
                timelineItems(itemTypes: [COMMENT_DELETED_EVENT], first: 100, after: $after) {
                  nodes { ... on CommentDeletedEvent { deletedCommentAuthor { ... on Bot { databaseId } } } }
                  pageInfo { hasNextPage endCursor }
                }
              }
            }
          }
        """
        cursor = None
        for _ in range(1000):
            response, _ = self.request("/graphql", "POST", {"query": query, "variables": {"pull": pull, "after": cursor}})
            require(not response.get("errors"), "Could not inspect deleted review history")
            timeline = response["data"]["repository"]["pullRequest"]["timelineItems"]
            for row in timeline["nodes"]:
                author = row["deletedCommentAuthor"]
                require(author is not None, "An unavailable PR comment has an unknown author")
                if author.get("databaseId") == bot_id:
                    return True
            page = timeline["pageInfo"]
            if not page["hasNextPage"]:
                return False
            require(page["endCursor"] and page["endCursor"] != cursor, "Review timeline could not be paginated")
            cursor = page["endCursor"]
        raise Blocked("Review timeline could not be completed")


@dataclass(frozen=True)
class Scope:
    pull: int
    head: str
    base: str
    merge: str
    lot: str


@dataclass(frozen=True)
class Policy:
    branch: str
    path: str
    commit: str


def policy_for(api, scope, bootstrap):
    if not bootstrap:
        return Policy(BASE, WORKFLOW, scope.base)
    require(scope.pull == 1 and scope.lot == "B00", "The bootstrap policy is limited to the first B00 pull request")
    pinned = sha(os.environ.get("SPRINT_BOOTSTRAP_SHA"))
    branch = api.get(f"{REPO}/branches/{BOOTSTRAP_BRANCH}")
    require(branch["protected"] is True and branch["commit"]["sha"] == pinned, "The protected bootstrap ref changed")
    main_workflows = api.get(f"{REPO}/contents/.github/workflows?ref={scope.base}")
    require(all(row["path"] != WORKFLOW for row in main_workflows), "Bootstrap ended when the permanent workflow reached main")
    return Policy(BOOTSTRAP_BRANCH, BOOTSTRAP_WORKFLOW, pinned)


def pr_scope(api, pull, head, base):
    repository = api.get(REPO)
    require(repository["id"] == REPOSITORY_ID and repository["full_name"] == REPOSITORY and repository["default_branch"] == BASE and
            repository["private"] is False, "Unexpected repository or default branch")
    branch = api.get(f"{REPO}/branches/{BASE}")
    require(branch["protected"] is True and branch["commit"]["sha"] == base, "Protected main has changed or is unavailable")
    pr_route = f"{REPO}/pulls/{pull}"
    pr = api.get(pr_route)
    for _ in range(3):
        if pr["mergeable"] is not None:
            break
        time.sleep(2)
        pr = api.get(pr_route)
    require(pr["number"] == pull and pr["state"] == "open" and pr["draft"] is False, "Expected an open, ready pull request")
    for side in ("base", "head"):
        repo = pr[side]["repo"]
        require(repo and repo["id"] == repository["id"] and repo["full_name"] == REPOSITORY, "Unexpected pull request repository")
    require(pr["base"]["ref"] == BASE and pr["base"]["sha"] == base and pr["head"]["sha"] == head,
            "Pull request base or head SHA has changed")
    lot = re.fullmatch(r"sprint/(b[0-9]{2})(?:-[a-z0-9-]+)?", pr["head"]["ref"])
    require(lot is not None, "Pull request branch must identify a sprint lot")
    compare = api.get(f"{REPO}/compare/{base}...{head}?per_page=1")
    require(compare["status"] == "ahead" and compare["merge_base_commit"]["sha"] == base, "Pull request head must include the current base")
    require(pr["mergeable"] is True, "GitHub has not resolved a mergeable test commit")
    merge = sha(pr["merge_commit_sha"])
    commit = api.get(f"{REPO}/git/commits/{merge}")
    require(commit["sha"] == merge and [parent["sha"] for parent in commit["parents"]] == [base, head],
            "The test merge commit does not have the expected parents")
    return Scope(pull, head, base, merge, lot[1].upper())


def verify_protection(api):
    protection = api.get(f"{REPO}/branches/{BASE}/protection")
    checks = protection["required_status_checks"]
    reviews = protection["required_pull_request_reviews"]
    require(protection["enforce_admins"]["enabled"] is True and
            protection["allow_force_pushes"]["enabled"] is False and
            protection["allow_deletions"]["enabled"] is False and
            protection["required_conversation_resolution"]["enabled"] is True and
            reviews is not None and not any(reviews.get("bypass_pull_request_allowances", {}).values()),
            "Main must require pull requests and resolved conversations without bypass, force-pushes or deletion")
    require(checks and checks["strict"] is True and
            {(CHECK, ACTIONS_APP), ("test", ACTIONS_APP), ("package", ACTIONS_APP)} <=
            {(row["context"], row["app_id"]) for row in checks["checks"]},
            "Main must require the sprint and CI checks from GitHub Actions and an up-to-date head")
    rules = api.get(f"{REPO}/rules/branches/{BASE}")
    restriction_ids = {row["ruleset_id"] for row in rules if row["type"] == "update" and row["ruleset_source_type"] == "Repository"}
    require(restriction_ids, "Main must restrict updates to the coordinator's pull-request merges")
    for ruleset_id in restriction_ids:
        ruleset = api.get(f"{REPO}/rulesets/{number(ruleset_id)}")
        bypass = ruleset["bypass_actors"]
        if (ruleset["enforcement"] == "active" and len(bypass) == 1 and bypass[0]["actor_type"] == "RepositoryRole" and
                bypass[0]["actor_id"] == 5 and bypass[0]["bypass_mode"] == "pull_request"):
            return
    raise Blocked("Main updates must allow only repository admins through pull requests")


def verify_run(api, policy, run_id, attempt, coordinator):
    workflow = api.get(f"{REPO}/actions/workflows/{policy.path.rsplit('/', 1)[1]}")
    run = api.get(f"{REPO}/actions/runs/{run_id}")
    require(workflow["path"] == policy.path and run["id"] == run_id and run["workflow_id"] == workflow["id"] and
            run["path"] in (policy.path, policy.path + f"@refs/heads/{policy.branch}") and run["event"] == "workflow_dispatch" and
            run["head_branch"] == policy.branch and run["head_sha"] == policy.commit and run["run_attempt"] == attempt and
            run["repository"]["full_name"] == REPOSITORY and run["repository"]["id"] == REPOSITORY_ID and
            run["head_repository"]["id"] == REPOSITORY_ID and
            run["actor"]["id"] == coordinator and run["triggering_actor"]["id"] == coordinator,
            "CI must run through the protected workflow dispatched by the coordinator")
    return run


def verify_jobs(api, policy, run_id, attempt, include_gate=False):
    jobs = list(api.pages(f"{REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs"))
    names = ["sprint-b00 test", "sprint-b00 package"]
    if include_gate:
        names.append("sprint-b00 gate")
    for name in names:
        matches = [row for row in jobs if row["name"] == name]
        require(len(matches) == 1 and matches[0]["run_id"] == run_id and matches[0]["head_sha"] == policy.commit and
                matches[0]["status"] == "completed" and matches[0]["conclusion"] == "success",
                f"The trusted CI job {name} did not pass in this attempt")
    return matches[0]


def qodo_review_comment(body):
    group = re.match(r"\s*<h3>(Incremental )?Code Review by Qodo</h3>[ \t]*\n([^\n]+)", body or "")
    if not group:
        return None
    counts = re.findall(r"<code>[^<>]*?([A-Za-z][A-Za-z -]+) \(([0-9]+)\)</code>", group[2])
    labels = {label for label, _ in counts}
    if len(labels) != len(counts) or not {"Bugs", "Rule violations", "Requirement gaps"} <= labels:
        return None
    markers = re.findall(rf"(?m)^<!--[ \t]+{re.escape(WEB)}/commit/([0-9a-f]{{40}})[ \t]+-->[ \t]*$", body)
    completed_head = markers[0] if len(markers) == 1 and not group[1] else None
    return completed_head, sum(int(count) for _, count in counts)


def qodo_snapshot(api, scope, bot_id, app_id):
    prefix = f"{REPO}/pulls/{scope.pull}"
    routes = {"issue": f"{REPO}/issues/{scope.pull}/comments", "review": prefix + "/reviews", "inline": prefix + "/comments"}
    records, completions = {}, []
    for kind, route in routes.items():
        for row in api.pages(route):
            user = row.get("user") or {}
            if user.get("id") != bot_id:
                continue
            app = row.get("performed_via_github_app")
            require(user.get("type") == "Bot" and (app is None or app["id"] == app_id), "Unexpected Qodo author identity")
            record_key = f"{kind}:{number(row['id'])}"
            require(record_key not in records, "Qodo history changed during pagination")
            records[record_key] = {field: row.get(field) for field in (
                "body", "html_url", "state", "commit_id", "original_commit_id", "updated_at", "submitted_at", "in_reply_to_id"
            )}
            if kind == "issue":
                review = qodo_review_comment(row["body"])
                if review is not None:
                    review_head, total = review
                    records[record_key]["minimum_findings"] = total
                    if review_head == scope.head and app is not None:
                        completions.append(record_key)
            for edit in api.edits(row["node_id"], kind):
                key = f"{record_key}/edit:{edit['id']}"
                require(key not in records, "Qodo edit history changed during pagination")
                records[key] = {"body": edit["diff"], "html_url": row["html_url"]}
    require(records, "No authenticated Qodo history is available")
    require(not api.deleted_qodo_comment(scope.pull, bot_id), "A Qodo comment was deleted and its history is unavailable")
    require(completions, "No authenticated Qodo completion is bound to the current head")
    return records, sorted(completions)


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def criteria(matrix, lot, b00_contract=""):
    require(isinstance(matrix, list), "The matrix must be an array")
    accepted, seen = {}, set()
    for row in matrix:
        require(isinstance(row, dict) and type(row.get("id")) is int and re.fullmatch(r"B[0-9]{2}", row.get("lote", "")),
                "Invalid matrix item")
        item, acceptance = str(row["id"]), row.get("aceite")
        require(item not in seen, "Duplicate matrix item")
        seen.add(item)
        require(nonempty(acceptance) or (isinstance(acceptance, list) and acceptance and all(map(nonempty, acceptance))),
                "Matrix item is missing acceptance criteria")
        if row["lote"] == lot:
            accepted[item] = acceptance
    require(seen == {str(item) for item in range(1, 68) if item not in (40, 41)}, "The original sprint matrix is incomplete")
    if lot == "B00":
        table = re.search(r"(?m)^\| Entrega \| Aceite e contraprova \|\n\| --- \| --- \|\n((?:\|[^\n]+\|\n)+)", b00_contract)
        require(table, "The B00 acceptance table is missing on protected main")
        for line in table[1].splitlines():
            label, acceptance = (part.strip() for part in line.strip("|").split("|"))
            require(nonempty(label) and nonempty(acceptance) and f"B00:{label}" not in accepted, "Invalid B00 acceptance item")
            accepted[f"B00:{label}"] = acceptance
    require(accepted, "The sprint lot has no acceptance criteria on protected main")
    return accepted


def valid_evidence(evidence):
    if not isinstance(evidence, list) or not evidence:
        return False
    for row in evidence:
        if not isinstance(row, dict) or not nonempty(row.get("detail")) or not nonempty(row.get("url")):
            return False
        url = urlsplit(row["url"])
        if url.scheme != "https" or url.netloc != "github.com" or not url.path.startswith("/" + REPOSITORY + "/"):
            return False
    return True


def unique_keys(pairs):
    data = dict(pairs)
    require(len(data) == len(pairs), "Evidence contains duplicate JSON keys")
    return data


def read_manifest(api, scope, comment_id, coordinator):
    comment = api.get(f"{REPO}/issues/comments/{comment_id}")
    require(comment["id"] == comment_id and comment["issue_url"] == f"https://api.github.com{REPO}/issues/{scope.pull}" and
            comment["user"]["id"] == coordinator and comment["user"]["type"] == "User" and
            not comment.get("performed_via_github_app"), "Evidence must be a GitHub comment from the configured coordinator on this PR")
    body = re.fullmatch(r"```json\r?\n(.+)\r?\n```", comment["body"].strip(), re.DOTALL)
    require(body is not None, "Expected a single fenced JSON evidence manifest")
    manifest = json.loads(body[1], object_pairs_hook=unique_keys)
    return manifest, digest({"id": comment_id, "body": comment["body"], "updated_at": comment["updated_at"]})


def verify_manifest(scope, expected, manifest, records, completions):
    require(isinstance(manifest, dict) and type(manifest.get("version")) is int and manifest["version"] == 1 and
            manifest.get("repository") == REPOSITORY and type(manifest.get("pull")) is int and
            all(manifest.get(key) == value for key, value in asdict(scope).items()), "Evidence manifest is for a different pull request snapshot")
    implementers = manifest.get("implementers")
    require(isinstance(implementers, list) and implementers and all(map(nonempty, implementers)), "Implementer identities are required")
    audit = manifest["audit"]
    require(nonempty(audit.get("agent")) and audit["agent"].strip().casefold() not in {item.strip().casefold() for item in implementers} and
            audit.get("result") == "pass" and audit.get("history_complete") is True and valid_evidence(audit.get("evidence")),
            "The coordinator must attest an independent passing audit with a complete Qodo review")
    items = manifest["items"]
    require(isinstance(items, dict) and items.keys() == expected.keys(), "Evidence must cover every acceptance item in the lot")
    for item, acceptance in expected.items():
        row = items[item]
        require(row.get("acceptance_sha256") == digest(acceptance) and row.get("result") == "pass" and valid_evidence(row.get("evidence")),
                "A matrix item is missing passing evidence for the current acceptance criteria")
    qodo = manifest["qodo"]
    require(qodo.get("completion") in completions, "Qodo completion evidence does not match the current head")
    attested = qodo["records"]
    require(isinstance(attested, dict) and attested.keys() == records.keys(), "Evidence must cover every Qodo summary, review, comment and edit")
    for key, record in records.items():
        row = attested[key]
        findings = row.get("findings")
        require(row.get("sha256") == digest(record) and isinstance(findings, list), "Qodo evidence is stale or incomplete")
        require(len(findings) >= record.get("minimum_findings", 0), "Qodo review has unaccounted findings")
        if not findings:
            require(nonempty(row.get("no_findings")), "A Qodo record needs findings or an explanation for their absence")
        quotes = set()
        for finding in findings:
            quote = finding.get("quote")
            require(nonempty(quote) and quote in (record["body"] or "") and quote not in quotes and
                    finding.get("resolution") in ("fixed", "dismissed-with-reason") and valid_evidence(finding.get("evidence")),
                    "A Qodo finding is missing its source text, resolution or evidence")
            quotes.add(quote)


def sprint_check(api, scope):
    rows = api.pages(f"{REPO}/commits/{scope.head}/check-runs", "check_runs", check_name=CHECK, filter="all")
    existing = [row for row in rows if row["name"] == CHECK]
    require(len(existing) <= 1, "The pull request head has competing sprint checks")
    if not existing:
        return {}
    check = existing[0]
    require(check["external_id"] == f"sprint-b00:{scope.pull}:{scope.base}:{scope.head}:{scope.merge}" and
            check["app"]["id"] == ACTIONS_APP and check["head_sha"] == scope.head, "Unexpected sprint check issuer or pull request")
    return check


def publish(api, scope, conclusion, summary, run_id):
    existing = sprint_check(api, scope)
    output = {"title": f"Sprint {scope.lot} / PR #{scope.pull}", "summary": summary}
    run_url = f"{WEB}/actions/runs/{run_id}"
    if (existing.get("status") == "completed" and existing.get("conclusion") == conclusion and
            existing.get("details_url") == run_url and all(existing["output"].get(key) == value for key, value in output.items())):
        return existing["id"]
    payload = {
        "name": CHECK, "status": "completed", "conclusion": conclusion, "output": output,
        "details_url": run_url, "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if existing:
        result, _ = api.request(f"{REPO}/check-runs/{number(existing['id'])}", "PATCH", payload)
    else:
        external_id = f"sprint-b00:{scope.pull}:{scope.base}:{scope.head}:{scope.merge}"
        result, _ = api.request(f"{REPO}/check-runs", "POST", payload | {"head_sha": scope.head, "external_id": external_id})
    require(result["app"]["id"] == ACTIONS_APP and result["head_sha"] == scope.head, "GitHub did not confirm the expected check publisher and SHA")
    return number(result["id"])


def verify_evidence(api, scope, args, coordinator, expected):
    manifest, fingerprint = read_manifest(api, scope, args.comment, coordinator)
    records, completions = qodo_snapshot(api, scope, args.bot_id, args.qodo_app_id)
    verify_manifest(scope, expected, manifest, records, completions)
    _, current_fingerprint = read_manifest(api, scope, args.comment, coordinator)
    require(current_fingerprint == fingerprint, "The coordinator's evidence changed during verification")
    require(qodo_snapshot(api, scope, args.bot_id, args.qodo_app_id) == (records, completions),
            "Qodo history changed during verification")
    return fingerprint


def verify_published(api, scope, summary, run_id, gate_job):
    log = api.job_log(number(gate_job["id"]))
    published = re.findall(r"(?m)^(?:[0-9T:.+\-Z]+ )?Published sprint check run ([0-9]+)\r?$", log)
    check = sprint_check(api, scope)
    require(len(published) == 1 and check.get("id") == number(published[0]) and
            check["status"] == "completed" and check["conclusion"] == "success" and
            check["details_url"] == f"{WEB}/actions/runs/{run_id}" and check["output"]["summary"] == summary,
            "The sprint check does not match the protected job's published result")
    return check["id"]


def snapshot_report(scope, criteria, records, completions, template):
    inputs = {"repository": REPOSITORY, **asdict(scope)}
    if template:
        return inputs | {
            "version": 1, "implementers": [],
            "audit": {"agent": "", "result": None, "history_complete": False, "evidence": []},
            "items": {key: {"acceptance_sha256": digest(value), "result": None, "evidence": []} for key, value in criteria.items()},
            "qodo": {"completion": completions[-1], "records": {
                key: {"sha256": digest(value), "no_findings": "", "findings": []} for key, value in records.items()
            }},
        }
    return inputs | {
        "completion": completions, "items": {key: digest(value) for key, value in criteria.items()},
        "records": {key: {"sha256": digest(value), **value} for key, value in records.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "snapshot", "evaluate", "preflight"))
    parser.add_argument("--pull", default=os.environ.get("SPRINT_PULL"))
    parser.add_argument("--head", default=os.environ.get("SPRINT_HEAD"))
    parser.add_argument("--base", default=os.environ.get("SPRINT_BASE") or os.environ.get("GITHUB_SHA"))
    parser.add_argument("--bootstrap", action="store_true", default=os.environ.get("GITHUB_REF") == f"refs/heads/{BOOTSTRAP_BRANCH}")
    parser.add_argument("--run", default=os.environ.get("GITHUB_RUN_ID"))
    parser.add_argument("--attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT"))
    parser.add_argument("--attestation", dest="comment", default=os.environ.get("SPRINT_ATTESTATION"))
    parser.add_argument("--template", action="store_true", help="Generate an incomplete evidence manifest in snapshot mode")
    args = parser.parse_args()
    try:
        api = GitHub(os.environ.get("GH_TOKEN"))
        scope = pr_scope(api, number(args.pull), sha(args.head), sha(args.base))
        policy = policy_for(api, scope, args.bootstrap)
        if args.mode in ("prepare", "evaluate"):
            require(os.environ.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{policy.path}@refs/heads/{policy.branch}" and
                    os.environ.get("GITHUB_WORKFLOW_SHA") == policy.commit == os.environ.get("GITHUB_SHA") and
                    os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
                    "Evaluation must use the pinned protected workflow dispatch")
        if args.mode == "prepare":
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                output.write(f"pull={scope.pull}\nhead={scope.head}\nbase={scope.base}\n")
            return 0
        matrix = json.loads(api.text_at(MATRIX, policy.commit), object_pairs_hook=unique_keys)
        expected = criteria(matrix, scope.lot, api.text_at(B00_CONTRACT, policy.commit) if scope.lot == "B00" else "")
        args.bot_id = number(os.environ.get("SPRINT_QODO_BOT_ID"))
        args.qodo_app_id = number(os.environ.get("SPRINT_QODO_APP_ID"))
        if args.mode == "snapshot":
            records, completions = qodo_snapshot(api, scope, args.bot_id, args.qodo_app_id)
            print(json.dumps(snapshot_report(scope, expected, records, completions, args.template), indent=2, ensure_ascii=True))
            return 0
        run_id, attempt = number(args.run), number(args.attempt)
        coordinator = number(os.environ.get("SPRINT_COORDINATOR_ID"))
        args.comment = number(args.comment)
        run = verify_run(api, policy, run_id, attempt, coordinator)
        preflight = args.mode == "preflight"
        publishing = args.mode == "evaluate" and os.environ.get("SPRINT_PUBLISH") == "true"
        if preflight:
            require(api.get("/user")["id"] == coordinator, "The configured coordinator must run the merge preflight")
            require(run["status"] == "completed" and run["conclusion"] == "success", "The protected workflow attempt has not passed")
            verify_protection(api)
        try:
            gate_job = verify_jobs(api, policy, run_id, attempt, include_gate=preflight)
            fingerprint = verify_evidence(api, scope, args, coordinator, expected)
        except (Blocked, KeyError, AttributeError, IndexError, OSError, TypeError, ValueError):
            if publishing and pr_scope(api, scope.pull, scope.head, scope.base) == scope:
                publish(api, scope, "failure", "CI or evidence verification blocked this pull request.", run_id)
            raise
        require(pr_scope(api, scope.pull, scope.head, scope.base) == scope, "Pull request changed during verification")
        require(policy_for(api, scope, args.bootstrap) == policy, "Policy ref changed during verification")
        summary = (f"PR #{scope.pull}\nHead `{scope.head}`\nBase `{scope.base}`\nTest merge `{scope.merge}`\nWorkflow attempt {attempt}\n"
                   f"Evidence comment {args.comment}, SHA-256 `{fingerprint}`\n"
                   "Test, package, independent audit, matrix acceptance and Qodo passed.")
        if publishing:
            print(f"Published sprint check run {publish(api, scope, 'success', summary, run_id)}")
        if preflight:
            check_id = verify_published(api, scope, summary, run_id, gate_job)
            print(f"Verified sprint check run {check_id}")
        print(summary)
        return 0
    except (Blocked, KeyError, AttributeError, IndexError, OSError, TypeError, ValueError) as exc:
        print(f"Sprint blocked: {exc if isinstance(exc, Blocked) else 'Malformed or unavailable evidence'}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
