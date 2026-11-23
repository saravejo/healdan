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
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlencode, urlsplit
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
                  totalCount
                  nodes { id diff deletedAt editedAt editor { ... on Bot { databaseId } } }
                  pageInfo { hasNextPage endCursor }
                }
              }
            }
          }
        """.replace("TYPE", typename)
        cursor, count = None, 0
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
                count += 1
                yield edit
            page = edits["pageInfo"]
            if not page["hasNextPage"]:
                require(count == edits["totalCount"] and count != 100, "Qodo edit history may be truncated and requires archived evidence")
                return
            require(page["endCursor"] and page["endCursor"] != cursor, "Qodo edit history could not be paginated")
            cursor = page["endCursor"]
        raise Blocked("Qodo edit history could not be completed")

    def deleted_qodo_comments(self, pull, bot_id):
        query = """
          query($pull: Int!, $after: String) {
            repository(owner: "saravejo", name: "healdan") {
              pullRequest(number: $pull) {
                timelineItems(itemTypes: [COMMENT_DELETED_EVENT], first: 100, after: $after) {
                  nodes { ... on CommentDeletedEvent { id createdAt deletedCommentAuthor { ... on Bot { databaseId } } } }
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
                    yield row
            page = timeline["pageInfo"]
            if not page["hasNextPage"]:
                return
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


def sprint_lot(ref):
    match = re.fullmatch(r"sprint/(b[0-9]{2})(?:-[a-z0-9-]+)?", ref)
    return match[1].upper() if match else None


def same_repository(repo):
    return repo and repo["id"] == REPOSITORY_ID and repo["full_name"] == REPOSITORY


def precedes(api, ancestor, descendant):
    if ancestor == descendant:
        return True
    compare = api.get(f"{REPO}/compare/{ancestor}...{descendant}?per_page=1")
    return compare["status"] == "ahead" and compare["merge_base_commit"]["sha"] == ancestor


def pr_scope(api, pull, head, base):
    repository = api.get(REPO)
    require(same_repository(repository) and repository["default_branch"] == BASE and
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
        require(same_repository(repo), "Unexpected pull request repository")
    require(pr["base"]["ref"] == BASE and pr["base"]["sha"] == base and pr["head"]["sha"] == head,
            "Pull request base or head SHA has changed")
    lot = sprint_lot(pr["head"]["ref"])
    require(lot is not None, "Pull request branch must identify a sprint lot")
    require(base != head and precedes(api, base, head), "Pull request head must include the current base")
    require(pr["mergeable"] is True, "GitHub has not resolved a mergeable test commit")
    merge = sha(pr["merge_commit_sha"])
    commit = api.get(f"{REPO}/git/commits/{merge}")
    require(commit["sha"] == merge and [parent["sha"] for parent in commit["parents"]] == [base, head],
            "The test merge commit does not have the expected parents")
    return Scope(pull, head, base, merge, lot)


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
    group = re.match(r"\s*<h3>(Incremental )?Code Review by Qodo</h3>\s*([^\r\n]+)", body or "")
    if not group:
        return None
    counts = re.findall(r"<code>[^<>]*?([A-Za-z][A-Za-z -]+) \(([0-9]+)\)</code>", group[2])
    labels = {label for label, _ in counts}
    if len(labels) != len(counts) or not {"Bugs", "Rule violations"} <= labels:
        return None
    markers = re.findall(rf"(?m)^<!--[ \t]+{re.escape(WEB)}/commit/([0-9a-f]{{40}})[ \t]+-->[ \t]*$", body)
    completed_head = markers[0] if len(markers) == 1 and not group[1] else None
    return completed_head, sum(int(count) for _, count in counts)


def qodo_titles(body):
    pattern = r"(?m)^[+\-]?[ \t]*(?:<summary>[ \t]*)?[0-9]+\\?\.[ \t]+([^\n<]+?)[ \t]*(?:<code>|</summary>)"
    return list(dict.fromkeys(re.findall(pattern, body or "")))


def qodo_record(row, kind):
    record = {field: row.get(field) for field in (
        "body", "html_url", "state", "commit_id", "original_commit_id", "updated_at", "submitted_at", "in_reply_to_id"
    )}
    titles = qodo_titles(record["body"])
    if titles:
        record["finding_titles"] = titles
    review = qodo_review_comment(row["body"]) if kind == "issue" else None
    if review is not None:
        record["minimum_findings"] = review[1]
    if kind == "inline" and nonempty(record["body"]) and not row.get("in_reply_to_id"):
        record["minimum_findings"] = 1
    return record, review


def qodo_anchor_hashes(body, bot_id, app_id):
    if f"bot GitHub {bot_id}, App {app_id}" not in (body or ""):
        return set()
    pattern = r"(?m)^\|[ \t]*([0-9]+)[ \t]*\|[^|\r\n]*\|[ \t]*([0-9a-f]{64})[ \t]*\|[ \t]*$"
    return {(number(item), fingerprint) for item, fingerprint in re.findall(pattern, body)}


def qodo_archive(api, scope, archive, bot_id, app_id, coordinator):
    kind, row = archive["kind"], archive["record"]
    require(kind in ("issue", "review", "inline") and row["user"]["id"] == bot_id and row["user"]["type"] == "Bot" and
            (row.get("performed_via_github_app") or {}).get("id") == app_id, "Archived Qodo record has an unexpected identity")
    item = number(row["id"])
    anchor_types = {"issue": "issuecomment-", "review": "pullrequestreview-", "inline": "discussion_r"}
    require(row["html_url"] == f"{WEB}/pull/{scope.pull}#{anchor_types[kind]}{item}", "Archived Qodo record is from another PR")
    body_hash = hashlib.sha256(row["body"].encode("utf-8")).hexdigest()
    anchor_id = number(archive["anchor"])
    anchor = coordinator_comment(api, scope, anchor_id, coordinator)
    require((item, body_hash) in qodo_anchor_hashes(anchor["body"], bot_id, app_id),
            "The archived Qodo body must match a durable, unedited GitHub hash record")
    record, _ = qodo_record(row, kind)
    record["archive"] = {"anchor": anchor_id, "sha256": body_hash, "event": archive.get("event")}
    return f"{kind}:{item}", body_hash, record, anchor["created_at"]


def qodo_snapshot(api, scope, bot_id, app_id, archives=(), coordinator=None):
    prefix = f"{REPO}/pulls/{scope.pull}"
    routes = {"issue": f"{REPO}/issues/{scope.pull}/comments", "review": prefix + "/reviews", "inline": prefix + "/comments"}
    records, completions = {}, []
    observed, reconciled = set(), set()
    for kind, route in routes.items():
        for row in api.pages(route):
            user = row.get("user") or {}
            if kind == "issue" and coordinator is not None and user.get("id") == coordinator:
                hashes = qodo_anchor_hashes(row.get("body"), bot_id, app_id)
                if hashes:
                    anchor = coordinator_comment(api, scope, number(row["id"]), coordinator)
                    require(anchor["body"] == row["body"], "The Qodo hash anchor changed during collection")
                    observed.update(hashes)
            if user.get("id") != bot_id:
                continue
            app = row.get("performed_via_github_app")
            require(user.get("type") == "Bot" and (app is None or app["id"] == app_id), "Unexpected Qodo author identity")
            record_key = f"{kind}:{number(row['id'])}"
            require(record_key not in records, "Qodo history changed during pagination")
            records[record_key], review = qodo_record(row, kind)
            if isinstance(row["body"], str):
                reconciled.add((number(row["id"]), hashlib.sha256(row["body"].encode("utf-8")).hexdigest()))
            edits = list(api.edits(row["node_id"], kind))
            for edit in edits:
                key = f"{record_key}/edit:{edit['id']}"
                require(key not in records, "Qodo edit history changed during pagination")
                records[key] = {"body": edit["diff"], "html_url": row["html_url"], "editor": (edit["editor"] or {}).get("databaseId"),
                                "finding_titles": qodo_titles(edit["diff"])}
            last_edit = max((edit["editedAt"] for edit in edits), default=None)
            from_bot = all((edit["editor"] or {}).get("databaseId") == bot_id for edit in edits if edit["editedAt"] == last_edit)
            if review and review[0] == scope.head and app is not None and from_bot:
                completions.append(record_key)
    events = {row["id"]: row["createdAt"] for row in api.deleted_qodo_comments(scope.pull, bot_id)}
    for archive in archives:
        key, body_hash, record, anchored_at = qodo_archive(api, scope, archive, bot_id, app_id, coordinator)
        event = archive.get("event")
        if event is not None:
            require(event in events and anchored_at <= events[event], "Archived Qodo body is not anchored before its deletion event")
            del events[event]
        archived_key = f"{key}/snapshot:{body_hash}"
        require(archived_key not in records, "Duplicate archived Qodo record")
        records[archived_key] = record
        reconciled.add((number(archive["record"]["id"]), body_hash))
    require(records, "No authenticated Qodo history is available")
    require(not events, "A Qodo comment was deleted and its history is unavailable")
    require(observed <= reconciled, "A previously recorded Qodo snapshot is missing from the reconciled history")
    require(completions, "No authenticated Qodo completion is bound to the current head")
    return records, sorted(completions)


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def matrix_items(matrix):
    require(isinstance(matrix, list), "The matrix must be an array")
    items = {}
    for row in matrix:
        require(isinstance(row, dict) and type(row.get("id")) is int and re.fullmatch(r"B[0-9]{2}", row.get("lote", "")),
                "Invalid matrix item")
        item, acceptance = str(row["id"]), row.get("aceite")
        require(item not in items, "Duplicate matrix item")
        require(nonempty(acceptance) or (isinstance(acceptance, list) and acceptance and all(map(nonempty, acceptance))),
                f"Matrix item {item} is missing acceptance criteria")
        items[item] = row
    require(items.keys() == {str(item) for item in range(1, 68) if item not in (40, 41)}, "The original sprint matrix is incomplete")
    return items


def criteria(items, lot, b00_contract=""):
    accepted = {item: row["aceite"] for item, row in items.items() if row["lote"] == lot}
    if lot == "B00":
        table = re.search(r"(?m)^\| Entrega \| Aceite e contraprova \|\n\| --- \| --- \|\n((?:\|[^\n]+\|\n)+)", b00_contract)
        require(table, "The B00 acceptance table is missing on protected main")
        for line in table[1].splitlines():
            label, acceptance = (part.strip() for part in line.strip("|").split("|"))
            require(nonempty(label) and nonempty(acceptance) and f"B00:{label}" not in accepted, "Invalid B00 acceptance item")
            accepted[f"B00:{label}"] = acceptance
    require(accepted, "The sprint lot has no acceptance criteria on protected main")
    return accepted


def merged_lot(api, scope, pull):
    pr = api.get(f"{REPO}/pulls/{pull}")
    require(pr["number"] == pull and pull != scope.pull and pr["state"] == "closed" and
            pr["merged"] is True and nonempty(pr["merged_at"]) and pr["base"]["ref"] == BASE and
            same_repository(pr["base"]["repo"]) and same_repository(pr["head"]["repo"]),
            f"Matrix completion refers to PR #{pull} without an integration in this repository")
    merge = sha(pr["merge_commit_sha"])
    require(precedes(api, merge, scope.base), f"PR #{pull} is outside the protected base history")
    return Scope(pull, sha(pr["head"]["sha"]), scope.base, merge, sprint_lot(pr["head"]["ref"]))


def verify_candidate_matrix(api, scope, protected, candidate):
    integrations = {}
    for item, reference in protected.items():
        row = candidate[item]
        require(all(row.get(field) == reference[field] for field in ("lote", "aceite", "dependencias")),
                f"Matrix item {item} changes the protected lot, acceptance or dependencies")
        state = row.get("estado")
        require(state in ("pendente", "concluido"), f"Matrix item {item} has an invalid state")
        require(all(isinstance(row.get(field), list) for field in ("commits", "testes", "pareceres")),
                f"Matrix item {item} has invalid traceability fields")
        if state == "pendente":
            require(reference["estado"] == "pendente" and row.get("pr") is None,
                    f"Matrix item {item} loses or misstates a verified integration")
            continue
        require(scope.lot != "B00", "Matrix items must remain pending in B00")
        if row == reference:
            continue
        pull = row.get("pr")
        match = re.fullmatch(rf"{re.escape(WEB)}/pull/([0-9]+)", str(pull))
        pull = number(match[1] if match else pull)
        if pull not in integrations:
            integration = merged_lot(api, scope, pull)
            commits = {sha(commit["sha"]) for commit in api.pages(f"{REPO}/pulls/{pull}/commits")}
            integrations[pull] = integration, commits | {integration.merge}, Evidence(api, integration)
        integration, commits, evidence = integrations[pull]
        require(integration.lot == row["lote"], f"Matrix item {item} refers to an integrated PR from another lot")
        require(row["commits"] and all(sha(commit) in commits for commit in row["commits"]),
                f"Matrix item {item} has a commit outside its integrated PR")
        for field in ("testes", "pareceres"):
            require(row[field], f"Matrix item {item} lacks {field} for its integration")
            for reference_url in row[field]:
                evidence.resolve(reference_url["url"] if isinstance(reference_url, dict) else reference_url)


def verify_dependencies(api, scope, items):
    dependencies = {dependency for row in items.values() if row["lote"] == scope.lot for dependency in row["dependencias"]}
    for dependency in sorted(dependencies):
        if dependency == "B00":
            require(merged_lot(api, scope, 1).lot == "B00", "The B00 prerequisite is not integrated")
            continue
        records = [row for row in items.values() if row["lote"] == dependency]
        require(records and all(row["estado"] == "concluido" for row in records), f"Sprint prerequisite {dependency} is not fully integrated")


@dataclass(frozen=True)
class Acceptance:
    items: dict
    contract_sha256: str
    scenarios: dict


def load_acceptance(api, scope, policy):
    protected = matrix_items(json.loads(api.text_at(MATRIX, policy.commit), object_pairs_hook=unique_keys))
    candidate = matrix_items(json.loads(api.text_at(MATRIX, scope.head), object_pairs_hook=unique_keys))
    verify_candidate_matrix(api, scope, protected, candidate)
    verify_dependencies(api, scope, candidate)
    path = f"docs/sprint-autonoma/{scope.lot}.md"
    contract = api.text_at(path, policy.commit)
    require(api.text_at(path, scope.head) == contract, "Proposal changes the applicable protected lot contract")
    items = criteria(protected, scope.lot, contract)
    if scope.lot == "B00":
        scenarios = {key: {"acceptance": value} for key, value in items.items()}
    else:
        blocks = re.findall(r"(?ms)^```json[ \t]*\n(.*?)^```[ \t]*$", contract)
        require(len(blocks) == 1, "The protected lot contract must list its scenarios in one JSON block")
        scenarios = json.loads(blocks[0], object_pairs_hook=unique_keys)["scenarios"]
        require(isinstance(scenarios, dict) and scenarios.keys() == items.keys(), "The protected contract must list scenarios for every lot item")
        for item, rows in scenarios.items():
            require(isinstance(rows, dict) and rows and all(nonempty(key) and nonempty(value) for key, value in rows.items()),
                    f"The protected contract is missing a scenario description for item {item}")
    return Acceptance(items, hashlib.sha256(contract.encode("utf-8")).hexdigest(), scenarios)


@dataclass(frozen=True)
class Proof:
    kind: str
    body: str = ""
    author: int | None = None
    commit: str | None = None
    job: int | None = None


class Evidence:
    def __init__(self, api, scope, coordinator=None, excluded_comments=(), include_base=False):
        self.api = api
        self.scope = scope
        self.coordinator = coordinator
        self.excluded_comments = excluded_comments
        self.allowed_shas = {scope.head, scope.merge} | ({scope.base} if include_base else set())
        self.cache = {}
        self.logs = {}

    def resolve(self, url):
        require(nonempty(url) and not any(char.isspace() or char == "\\" for char in url), "Invalid evidence URL")
        if url not in self.cache:
            self.cache[url] = self.fetch(url)
        return self.cache[url]

    def fetch(self, url):
        parsed = urlsplit(url)
        prefix = f"/{REPOSITORY}/"
        require(parsed.scheme == "https" and parsed.netloc == "github.com" and parsed.path.startswith(prefix) and not parsed.query,
                "Evidence must reference this GitHub repository")
        path = parsed.path.removeprefix(prefix)
        if path == f"pull/{self.scope.pull}":
            return self.comment(parsed.fragment)
        run = re.fullmatch(r"actions/runs/([0-9]+)(?:/job/([0-9]+))?", path)
        if run and not parsed.fragment:
            return self.action(number(run[1]), number(run[2]) if run[2] else None)
        commit = re.fullmatch(r"commit/([0-9a-f]{40})", path)
        if commit and not parsed.fragment:
            self.commit(commit[1])
            return Proof("commit", commit=commit[1])
        blob = re.fullmatch(r"blob/([0-9a-f]{40})/([^?]+)", path)
        if blob:
            decoded_path = unquote(blob[2])
            require(not any(part in ("", ".", "..") for part in decoded_path.split("/")) and
                    not any(char in decoded_path for char in "\\?#\r\n"), "Invalid file evidence path")
            self.commit(blob[1])
            self.api.text_at(blob[2], blob[1])
            return Proof("blob", commit=blob[1])
        raise Blocked("Evidence URL does not identify a supported GitHub record for this pull request")

    def comment(self, fragment):
        match = re.fullmatch(r"(issuecomment-|pullrequestreview-|discussion_r)([0-9]+)", fragment)
        require(match, "Pull request evidence must identify a comment or a review")
        kind, item = match[1], number(match[2])
        routes = {"issuecomment-": f"issues/comments/{item}", "pullrequestreview-": f"pulls/{self.scope.pull}/reviews/{item}",
                  "discussion_r": f"pulls/comments/{item}"}
        require(kind != "issuecomment-" or item not in self.excluded_comments, "An attestation or audit cannot be its own evidence")
        data = self.api.get(f"{REPO}/{routes[kind]}")
        url = f"{WEB}/pull/{self.scope.pull}#{fragment}"
        require(data["id"] == item and data["html_url"] == url and nonempty(data["body"]), "GitHub evidence is unavailable on this pull request")
        author = data.get("user") or {}
        original = kind == "issuecomment-" and nonempty(data.get("created_at")) and data["created_at"] == data.get("updated_at")
        identity = author.get("id") if original and author.get("type") == "User" and not data.get("performed_via_github_app") else None
        if identity is not None and identity == self.coordinator and any(self.api.edits(data["node_id"], "issue")):
            identity = None
        return Proof("comment", data["body"], author=identity)

    def action(self, run_id, job_id):
        run = self.api.get(f"{REPO}/actions/runs/{run_id}")
        commit = run["head_sha"]
        require(run["id"] == run_id and same_repository(run["repository"]) and commit in self.allowed_shas and
                run["status"] == "completed", "CI evidence is not a completed run for the expected SHA")
        if job_id is None:
            return Proof("run", commit=commit)
        job = self.api.get(f"{REPO}/actions/jobs/{job_id}")
        require(job["id"] == job_id and job["run_id"] == run_id and job["head_sha"] == commit and job["status"] == "completed",
                "CI job evidence is not part of the expected completed run")
        return Proof("job", commit=commit, job=job_id)

    def commit(self, commit, fix=False):
        bookmark = (commit, fix)
        if bookmark not in self.cache:
            require(self.api.get(f"{REPO}/git/commits/{commit}")["sha"] == commit, "Evidence commit did not resolve on GitHub")
            if fix:
                require(precedes(self.api, commit, self.scope.head) and not precedes(self.api, commit, self.scope.base),
                        "A Qodo fix must be a commit introduced by the reviewed pull request")
            else:
                require(commit in self.allowed_shas or precedes(self.api, commit, self.scope.head),
                        "Evidence commit is outside the expected pull request history")
            self.cache[bookmark] = True

    def verify(self, rows):
        require(isinstance(rows, list) and rows, "Evidence references are required")
        for row in rows:
            require(isinstance(row, dict) and nonempty(row.get("detail")), "Evidence needs a description of what it proves")
        return [self.resolve(row.get("url")) for row in rows]

    def test(self, test):
        require(isinstance(test, dict) and nonempty(test.get("command")) and nonempty(test.get("result")),
                "A Qodo finding needs a reproducible command and result")
        for proof in self.verify(test.get("evidence")):
            if proof.kind == "job" and proof.commit in {self.scope.head, self.scope.merge}:
                if proof.job not in self.logs:
                    self.logs[proof.job] = self.api.job_log(proof.job)
                body = self.logs[proof.job]
            elif proof.kind == "comment" and proof.author == self.coordinator and self.scope.head in proof.body:
                body = proof.body
            else:
                continue
            if test["command"] in body and test["result"] in body:
                return
        raise Blocked("The Qodo test command and result were not found in evidence bound to the reviewed SHA")


def unique_keys(pairs):
    data = dict(pairs)
    require(len(data) == len(pairs), "Evidence contains duplicate JSON keys")
    return data


def coordinator_comment(api, scope, comment_id, coordinator):
    comment = api.get(f"{REPO}/issues/comments/{comment_id}")
    require(comment["id"] == comment_id and comment["issue_url"] == f"https://api.github.com{REPO}/issues/{scope.pull}" and
            comment["user"]["id"] == coordinator and comment["user"]["type"] == "User" and
            not comment.get("performed_via_github_app"), "Evidence must be a GitHub comment from the configured coordinator on this PR")
    require(nonempty(comment.get("created_at")) and comment["created_at"] == comment["updated_at"],
            "Coordinator evidence must stay in an unedited GitHub comment")
    require(not any(api.edits(comment["node_id"], "issue")), "Coordinator evidence has an edited GitHub version")
    return comment


def read_manifest(api, scope, comment_id, coordinator):
    comment = coordinator_comment(api, scope, comment_id, coordinator)
    body = re.fullmatch(r"```json\r?\n(.+)\r?\n```", comment["body"].strip(), re.DOTALL)
    require(body is not None, "Expected a single fenced JSON evidence manifest")
    manifest = json.loads(body[1], object_pairs_hook=unique_keys)
    return manifest, digest({"id": comment_id, "body": comment["body"], "updated_at": comment["updated_at"]})


def verify_scope(data, scope):
    require(isinstance(data, dict) and type(data.get("version")) is int and data["version"] == 1 and
            data.get("repository") == REPOSITORY and type(data.get("pull")) is int and
            all(data.get(key) == value for key, value in asdict(scope).items()), "Evidence is for a different pull request snapshot")


def verify_manifest(scope, expected, manifest, audit, records, completions, evidence):
    verify_scope(manifest, scope)
    verify_scope(audit, scope)
    implementers = manifest.get("implementers")
    require(isinstance(implementers, list) and implementers and all(map(nonempty, implementers)), "Implementer identities are required")
    require(audit.get("kind") == "independent-audit" and nonempty(audit.get("agent")) and
            audit["agent"].strip().casefold() not in {item.strip().casefold() for item in implementers} and
            audit.get("result") == "pass" and audit.get("history_complete") is True,
            "A separate independent audit must pass and verify the complete Qodo history")
    require(manifest.get("contract_sha256") == audit.get("contract_sha256") == expected.contract_sha256,
            "Audit and evidence must bind the detailed protected lot contract")
    evidence.verify(audit.get("evidence"))
    items = manifest["items"]
    audit_items = audit["items"]
    require(isinstance(items, dict) and isinstance(audit_items, dict) and items.keys() == audit_items.keys() == expected.items.keys(),
            "Audit and evidence must cover every acceptance item in the lot")
    for item, acceptance in expected.items.items():
        row = items[item]
        opinion = audit_items[item]
        require(row.get("acceptance_sha256") == digest(acceptance) and row.get("result") == "pass" and
                opinion.get("result") == "pass" and opinion.get("sha256") == digest(row),
                "A matrix item is missing passing evidence and an audit opinion for the current acceptance criteria")
        evidence.verify(row.get("evidence"))
        scenarios = row["scenarios"]
        require(isinstance(scenarios, dict) and scenarios.keys() == expected.scenarios[item].keys(),
                f"Matrix item {item} is missing a scenario from the protected contract")
        for name, criteria_text in expected.scenarios[item].items():
            outcome = scenarios[name]
            require(outcome.get("sha256") == digest(criteria_text) and outcome.get("result") == "pass",
                    f"A scenario for matrix item {item} is missing passing evidence")
            evidence.verify(outcome.get("evidence"))
    qodo = manifest["qodo"]
    require(qodo.get("completion") in completions, "Qodo completion evidence does not match the current head")
    attested = qodo["records"]
    qodo_audit = audit["qodo"]
    require(isinstance(attested, dict) and isinstance(qodo_audit, dict) and attested.keys() == qodo_audit.keys() == records.keys(),
            "Audit and evidence must cover every Qodo summary, review, comment and edit")
    for key, record in records.items():
        row = attested[key]
        findings = row.get("findings")
        require(row.get("sha256") == digest(record) and isinstance(findings, list), "Qodo evidence is stale or incomplete")
        require(len(findings) >= record.get("minimum_findings", 0), "Qodo review has unaccounted findings")
        opinion = qodo_audit[key]
        require(opinion.get("sha256") == digest(row) and isinstance(opinion.get("findings"), dict), "The Qodo audit does not match the submitted resolutions")
        if not findings:
            require(nonempty(row.get("no_findings")), "A Qodo record needs findings or an explanation for their absence")
        quotes, identities, matched_titles = set(), set(), set()
        titles = set(record.get("finding_titles", ()))
        if key.startswith("issue:") and qodo_review_comment(record["body"]):
            require(len(titles) >= record.get("minimum_findings", 0), "Qodo did not expose a source title for every reported finding")
        for finding in findings:
            identity, quote, resolution = finding.get("id"), finding.get("quote"), finding.get("resolution")
            require(nonempty(identity) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", identity) and identity not in identities,
                    "Every Qodo finding needs an individual ID within its source record")
            require(nonempty(quote) and quote in (record["body"] or "") and quote not in quotes and
                    resolution in ("fixed", "dismissed-with-reason"), "A Qodo finding is missing its source text or resolution")
            if titles:
                matched = {title for title in titles if title in quote}
                require(len(matched) == 1 and not matched & matched_titles, "A Qodo resolution must identify one distinct finding title")
                matched_titles.update(matched)
            decision = opinion["findings"].get(identity, {})
            require(decision.get("approved") is True and decision.get("resolution") == resolution and nonempty(decision.get("detail")),
                    "A Qodo finding lacks explicit approval from the independent auditor")
            if resolution == "fixed":
                evidence.commit(sha(finding.get("commit")), fix=True)
            else:
                require(nonempty(finding.get("reason")), "A dismissed Qodo finding needs the reason supported by its counterexample")
            evidence.test(finding.get("test"))
            identities.add(identity)
            quotes.add(quote)
        require(identities == opinion["findings"].keys(), "Audit decisions must match every individual Qodo finding")
        require(matched_titles == titles, "A Qodo finding title lacks separate resolution evidence")


def sprint_check(api, scope, allow_previous_merge=False):
    rows = api.pages(f"{REPO}/commits/{scope.head}/check-runs", "check_runs", check_name=CHECK, filter="all")
    existing = [row for row in rows if row["name"] == CHECK]
    require(len(existing) <= 1, "The pull request head has competing sprint checks")
    if not existing:
        return {}
    check = existing[0]
    identity = f"sprint-b00:{scope.pull}:{scope.base}:{scope.head}:"
    external = check["external_id"] or ""
    matches = external == identity + scope.merge or (allow_previous_merge and re.fullmatch(rf"{identity}[0-9a-f]{{40}}", external))
    require(matches and
            check["app"]["id"] == ACTIONS_APP and check["head_sha"] == scope.head, "Unexpected sprint check issuer or pull request")
    return check


def publish(api, scope, conclusion, summary, run_id):
    existing = sprint_check(api, scope, allow_previous_merge=True)
    external_id = f"sprint-b00:{scope.pull}:{scope.base}:{scope.head}:{scope.merge}"
    output = {"title": f"Sprint {scope.lot} / PR #{scope.pull}", "summary": summary}
    run_url = f"{WEB}/actions/runs/{run_id}"
    if (existing.get("status") == "completed" and existing.get("conclusion") == conclusion and
            existing.get("details_url") == run_url and existing.get("external_id") == external_id and
            all(existing["output"].get(key) == value for key, value in output.items())):
        return existing["id"]
    payload = {
        "name": CHECK, "status": "completed", "conclusion": conclusion, "output": output, "external_id": external_id,
        "details_url": run_url, "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if existing:
        result, _ = api.request(f"{REPO}/check-runs/{number(existing['id'])}", "PATCH", payload)
    else:
        result, _ = api.request(f"{REPO}/check-runs", "POST", payload | {"head_sha": scope.head})
    require(result["app"]["id"] == ACTIONS_APP and result["head_sha"] == scope.head and result["external_id"] == external_id,
            "GitHub did not confirm the expected check publisher and SHA")
    return number(result["id"])


def verify_evidence(api, scope, args, coordinator, expected):
    manifest, fingerprint = read_manifest(api, scope, args.comment, coordinator)
    pointer = manifest["audit"]
    audit_id = number(pointer.get("comment"))
    require(audit_id != args.comment, "The independent audit must be in a separate comment")
    audit, audit_fingerprint = read_manifest(api, scope, audit_id, coordinator)
    require(pointer.get("sha256") == audit_fingerprint, "The independent audit comment hash does not match")
    archives = manifest["qodo"].get("archives", [])
    require(isinstance(archives, list), "The Qodo archive inventory must be a list")
    records, completions = qodo_snapshot(api, scope, args.bot_id, args.qodo_app_id, archives, coordinator)
    evidence = Evidence(api, scope, coordinator, {args.comment, audit_id}, include_base=True)
    verify_manifest(scope, expected, manifest, audit, records, completions, evidence)
    for comment, expected_fingerprint in ((args.comment, fingerprint), (audit_id, audit_fingerprint)):
        _, current = read_manifest(api, scope, comment, coordinator)
        require(current == expected_fingerprint, "The coordinator's evidence changed during verification")
    require(qodo_snapshot(api, scope, args.bot_id, args.qodo_app_id, archives, coordinator) == (records, completions),
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


def snapshot_report(scope, expected, records, completions, template, archives=(), audit_pointer=None):
    inputs = {"repository": REPOSITORY, **asdict(scope), "contract_sha256": expected.contract_sha256}
    items = {key: {"acceptance_sha256": digest(value), "scenarios": {
        name: {"sha256": digest(description)} for name, description in expected.scenarios[key].items()
    }} for key, value in expected.items.items()}
    if template:
        for row in items.values():
            row.update(result=None, evidence=[])
            for scenario in row["scenarios"].values():
                scenario.update(result=None, evidence=[])
        return inputs | {
            "version": 1, "implementers": [],
            "audit": audit_pointer or {"comment": None, "sha256": ""},
            "items": items,
            "qodo": {"completion": completions[-1], "archives": list(archives), "records": {
                key: {"sha256": digest(value), "no_findings": "", "findings": []} for key, value in records.items()
            }},
        }
    return inputs | {
        "completion": completions, "items": items,
        "records": {key: {"sha256": digest(value), **value} for key, value in records.items()},
    } | ({"audit": audit_pointer} if audit_pointer else {})


def audit_template(manifest):
    report = {key: manifest[key] for key in ("version", "repository", "pull", "head", "base", "merge", "lot", "contract_sha256")}
    report.update(kind="independent-audit", agent="", result=None, history_complete=False, evidence=[])
    report["items"] = {key: {"sha256": digest(row), "result": None} for key, row in manifest["items"].items()}
    report["qodo"] = {key: {"sha256": digest(row), "findings": {
        item["id"]: {"approved": False, "resolution": item["resolution"], "detail": ""} for item in row["findings"]
    }} for key, row in manifest["qodo"]["records"].items()}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "snapshot", "audit-template", "evaluate", "preflight"))
    parser.add_argument("--pull", default=os.environ.get("SPRINT_PULL"))
    parser.add_argument("--head", default=os.environ.get("SPRINT_HEAD"))
    parser.add_argument("--base", default=os.environ.get("SPRINT_BASE") or os.environ.get("GITHUB_SHA"))
    parser.add_argument("--bootstrap", action="store_true", default=os.environ.get("GITHUB_REF") == f"refs/heads/{BOOTSTRAP_BRANCH}")
    parser.add_argument("--run", default=os.environ.get("GITHUB_RUN_ID"))
    parser.add_argument("--attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT"))
    parser.add_argument("--attestation", dest="comment", default=os.environ.get("SPRINT_ATTESTATION"))
    parser.add_argument("--template", action="store_true", help="Generate an incomplete evidence manifest in snapshot mode")
    parser.add_argument("--archives", type=Path, help="Read anchored Qodo snapshots from this JSON file in snapshot mode")
    parser.add_argument("--audit-comment", help="Include the authenticated audit comment digest in snapshot mode")
    parser.add_argument("--manifest", type=Path, help="Read the draft attestation in audit-template mode")
    args = parser.parse_args()
    try:
        if args.mode == "audit-template":
            require(args.manifest, "An attestation JSON file is required to generate an audit template")
            manifest = json.loads(args.manifest.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_keys)
            print(json.dumps(audit_template(manifest), indent=2, ensure_ascii=True))
            return 0
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
        args.bot_id = number(os.environ.get("SPRINT_QODO_BOT_ID"))
        args.qodo_app_id = number(os.environ.get("SPRINT_QODO_APP_ID"))
        coordinator = number(os.environ.get("SPRINT_COORDINATOR_ID"))
        if args.mode == "snapshot":
            expected = load_acceptance(api, scope, policy)
            archives = json.loads(args.archives.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_keys) if args.archives else []
            require(isinstance(archives, list), "The Qodo archive inventory must be a list")
            records, completions = qodo_snapshot(api, scope, args.bot_id, args.qodo_app_id, archives, coordinator)
            pointer = None
            if args.audit_comment:
                audit_id = number(args.audit_comment)
                audit, fingerprint = read_manifest(api, scope, audit_id, coordinator)
                verify_scope(audit, scope)
                require(audit.get("kind") == "independent-audit", "The selected comment is not an independent audit report")
                pointer = {"comment": audit_id, "sha256": fingerprint}
            print(json.dumps(snapshot_report(scope, expected, records, completions, args.template, archives, pointer), indent=2, ensure_ascii=True))
            return 0
        run_id, attempt = number(args.run), number(args.attempt)
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
            expected = load_acceptance(api, scope, policy)
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
