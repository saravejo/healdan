"""Source revisions and dependencies of captured wiki output."""
import base64
from collections import defaultdict
import re

from .core import Blocked, digest, git, git_bytes, parse_jsonl, require, safe_path
from .ids import aliases, registry_records
from .originals import REGISTRY, git_blob, verify_body
from .signing import trusted_signers, verify

ORIGIN = "healdan-source-origin-v1"
CLAIMS = "wiki/claims.jsonl"
LEDGER = "control/approvals/packages.jsonl"
ANCHOR = re.compile(rb'<a id="(C-[0-9]+)"')
PAGE_MARK = re.compile(rb'<!-- healdan:(?:current|history):')


class UnknownPageOrigin(Blocked):
    pass


def sha256(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def references(value):
    require(isinstance(value, list) and value, "Lineage requires source revision references", 5)
    for ref in value:
        require(isinstance(ref, dict) and set(ref) == {"id", "revision"} and
                isinstance(ref["id"], str) and sha256(ref["revision"]),
                "Invalid source revision reference", 5)
    return value


def wiki_path(path):
    return isinstance(path, str) and path.startswith("wiki/") and path.endswith(".md")


def page_revision(path, body, claims, sources, source_aliases=None):
    uses = []
    source_aliases = source_aliases or {}
    current = body.split(b"<!-- healdan:current:end -->", 1)[0]
    for identifier in dict.fromkeys(match.decode("ascii") for match in ANCHOR.findall(current)):
        claim = claims.get(identifier)
        if claim is None:
            continue
        support = []
        for locator in claim["sources"]:
            source_id = locator.get("id")
            source = sources.get(source_id) or sources.get(source_aliases.get(source_id))
            if source:
                support.append({"id": source["id"], "revision": digest(source)})
        uses.append({"id": identifier, "revision": digest(claim), "sources": support})
    return {"path": path, "revision": digest(body), "claims": uses}


def package_pages(payload):
    pages = payload.get("page_revisions", [])
    require(isinstance(pages, list), "Invalid signed page revisions", 5)
    files = payload.get("files", {})
    seen = set()
    for page in pages:
        require(isinstance(page, dict) and set(page) == {"path", "revision", "claims"} and
                sha256(page["revision"]) and isinstance(page["claims"], list), "Invalid signed page revision", 5)
        path = page["path"]
        require(wiki_path(path) and path not in seen and isinstance(files, dict) and path in files,
                "Signed page revision lacks a unique published file", 5)
        seen.add(path)
        try:
            body = base64.b64decode(files[path], validate=True)
        except (TypeError, ValueError) as exc:
            raise Blocked("Invalid signed page bytes: " + path, 5) from exc
        require(digest(body) == page["revision"], "Signed page revision differs from its bytes", 5)
        for claim in page["claims"]:
            require(isinstance(claim, dict) and set(claim) == {"id", "revision", "sources"} and
                    sha256(claim["revision"]) and isinstance(claim["sources"], list), "Invalid signed page claim", 5)
            if claim["sources"]:
                references(claim["sources"])
                for ref in claim["sources"]:
                    registry_records(REGISTRY, [ref])
        registry_records(CLAIMS, page["claims"])
    return pages


class PageHistory:
    def __init__(self, vault, approvals=None):
        self.vault = vault
        self.approvals = approvals
        self.signed = None
        self.current = None
        self.historical = {}
        self.history_trees = None

    def _signed_pages(self):
        if self.signed is not None:
            return self.signed
        self.signed = {}
        if self.approvals is None:
            self.approvals = [verify(row, "package", trusted_signers(self.vault)) for row in self.vault.rows(LEDGER)]
        for payload in self.approvals:
            for page in package_pages(payload):
                entries = self.signed.setdefault(page["revision"], [])
                if page not in entries:
                    entries.append(page)
        return self.signed

    def _current_pages(self):
        if self.current is None:
            self.current = {}
            for path in sorted((self.vault.root / "wiki").rglob("*.md")):
                if path.is_file() or path.is_symlink():
                    name = path.relative_to(self.vault.root).as_posix()
                    revision = digest(safe_path(self.vault.root, name, exists=True).read_bytes())
                    self.current.setdefault(revision, []).append(name)
        return self.current

    def _historical_pages(self, body):
        revision = digest(body)
        if revision in self.historical:
            return self.historical[revision]
        root, head = self.vault.repository.root, self.vault.head()
        pages = self.historical[revision] = []
        if not head:
            return pages
        oid = git_bytes(root, "hash-object", "--no-filters", "--stdin", data=body).strip()
        if self.history_trees is None:
            commits = git(root, "log", "--reverse", "--full-history", "--format=%H", head, "--", "wiki").splitlines()
            self.history_trees = [(commit, git_bytes(root, "ls-tree", "-rz", commit, "--", "wiki").split(b"\0")[:-1])
                                  for commit in commits]
        seen = set()
        for commit, entries in self.history_trees:
            matches = []
            for entry in entries:
                meta, name = entry.split(b"\t", 1)
                if meta.split()[-1] == oid:
                    path = name.decode("utf-8")
                    if wiki_path(path) and path not in seen:
                        matches.append(path)
                        seen.add(path)
            if matches:
                claims = registry_records(CLAIMS, parse_jsonl(git_blob(root, commit, CLAIMS), f"{commit}:{CLAIMS}"))
                sources = registry_records(REGISTRY, parse_jsonl(git_blob(root, commit, REGISTRY),
                                                                  f"{commit}:{REGISTRY}"))
                pages.extend(page_revision(path, body, claims, sources) for path in matches)
        return pages

    def pages(self, body):
        revision = digest(body)
        pages = self._signed_pages().get(revision, [])
        if pages:
            return pages
        paths = self._current_pages().get(revision, [])
        if paths or PAGE_MARK.search(body):
            pages = self._historical_pages(body)
            if pages:
                return pages
            return [{"path": path, "revision": revision, "claims": []} for path in paths]
        return []

    def origin(self, body, path, derived=None):
        pages = self.pages(body)
        if pages or PAGE_MARK.search(body):
            require(derived is None, "Wiki output already has a page origin", 5)
            return {"format": ORIGIN, "kind": "wiki", "path": path,
                    "pages": [{"path": page["path"], "revision": page["revision"]} for page in pages]}
        if derived is not None:
            require(isinstance(derived, dict) and set(derived) == {"method", "sources"},
                    "A conversion requires a method and source revisions", 2)
            return {"format": ORIGIN, "kind": "derived", "path": path, **derived}
        return {"format": ORIGIN, "kind": "observation", "path": path}


class Lineage:
    def __init__(self, vault, sources, page_history, bodies=None, *, verify_original=None):
        self.vault = vault
        self.sources = sources
        self.page_history = page_history
        self.bodies = bodies or {}
        self.verify_original = verify_original
        self.aliases = None
        self.by_digest = defaultdict(list)
        self.conversions = {}
        for identifier, row in sources.items():
            self.by_digest[row["sha256"]].append(identifier)

    def source_id(self, identifier):
        if identifier in self.sources:
            return identifier
        if self.aliases is None:
            self.aliases = aliases(self.vault)
        return self.aliases.get(identifier, identifier)

    def body(self, identifier):
        row = self.sources[identifier]
        if self.verify_original:
            self.verify_original(identifier)
        if identifier not in self.bodies:
            body = safe_path(self.vault.root, row["path"], exists=True).read_bytes()
            self.bodies[identifier] = verify_body(row, body)
        return self.bodies[identifier]

    def known_conversion(self, sha):
        if sha not in self.conversions:
            established = None
            expected = None
            observations = set()
            for identifier in self.by_digest.get(sha, []):
                origin = self.sources[identifier].get("origin")
                if not isinstance(origin, dict):
                    continue
                if origin.get("kind") == "observation":
                    self.body(identifier)
                    observations.add(identifier)
                    continue
                if origin.get("kind") != "derived":
                    continue
                self.body(identifier)
                require(origin.get("format") == ORIGIN and isinstance(origin.get("method"), str) and
                        origin["method"].strip(), f"{identifier}: invalid conversion origin", 5)
                if "path" in origin:
                    safe_path(self.vault.root, origin["path"])
                parents = {(self.source_id(ref["id"]), ref["revision"]) for ref in references(origin.get("sources"))}
                if established is None:
                    established, expected = origin, parents
                require(parents == expected, f"{identifier}: identical source bytes have conflicting conversion parents", 5)
            if established and observations:
                require(all(parent in observations for parent, _ in expected),
                        "Identical source bytes conflict with their established observation", 5)
                established = None
            self.conversions[sha] = established
        return self.conversions[sha]

    def parents(self, identifier):
        row = self.sources[identifier]
        body = self.body(identifier)
        origin = row.get("origin")
        pages = self.page_history.pages(body)
        if origin is not None:
            require(isinstance(origin, dict) and origin.get("format") == ORIGIN,
                    f"{identifier}: unknown source origin format", 5)
        kind = origin.get("kind") if origin else None
        if pages or PAGE_MARK.search(body) or kind == "wiki":
            if kind == "wiki":
                expected = origin.get("pages")
                require(isinstance(expected, list) and all(isinstance(ref, dict) and
                        set(ref) == {"path", "revision"} and wiki_path(ref["path"]) and sha256(ref["revision"])
                        for ref in expected), f"{identifier}: invalid wiki page revision references", 5)
                missing = [ref for ref in expected if not any(all(page[key] == ref[key] for key in ref) for page in pages)]
                require(not missing, f"{identifier}: missing wiki page revision {missing}", 5)
            if not pages or not all(page["claims"] for page in pages):
                raise UnknownPageOrigin(f"{identifier}: wiki page revision lacks verified claim lineage", 5)
            uses = [claim for page in pages for claim in page["claims"]]
            return "wiki", [ref for claim in uses for ref in claim["sources"]], uses
        require(kind in {None, "derived", "observation"} and (kind is not None or origin is None),
                f"{identifier}: unknown source origin kind", 5)
        conversion = self.known_conversion(row["sha256"])
        if conversion:
            return "derived", conversion["sources"], []
        if kind == "derived":
            return kind, references(origin.get("sources")), []
        if kind == "observation":
            path = origin.get("path")
            require(isinstance(path, str) and path.strip(), f"{identifier}: missing capture origin", 5)
            safe_path(self.vault.root, path)
            return kind, [], []
        return "legacy", [], []

    def parent_id(self, ref):
        identifier = self.source_id(ref["id"])
        require(identifier in self.sources, f"missing source {ref['id']} revision {ref['revision']}", 5)
        require(digest(self.sources[identifier]) == ref["revision"],
                f"{identifier}: source revision differs from {ref['revision']}", 5)
        return identifier

    def restriction_hashes(self, identifier, stack=()):
        require(identifier not in stack, "Source lineage cycle: " + " -> ".join((*stack, identifier)), 5)
        row = self.sources[identifier]
        try:
            _, refs, _ = self.parents(identifier)
        except UnknownPageOrigin:
            return {row["sha256"]}
        hashes = {row["sha256"]}
        for ref in refs:
            parent = self.source_id(ref["id"])
            require(parent in self.sources, f"missing source {ref['id']} revision {ref['revision']}", 5)
            hashes.update(self.restriction_hashes(parent, (*stack, identifier)))
            self.parent_id(ref)
        return hashes
