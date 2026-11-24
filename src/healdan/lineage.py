"""Source revisions and dependencies of captured wiki output."""
import base64
import re

from .core import Blocked, digest, git, git_bytes, parse_jsonl, require, safe_path
from .ids import aliases, registry_records
from .originals import REGISTRY, git_blob
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


class PageHistory:
    def __init__(self, vault, approvals=None):
        self.vault = vault
        self.approvals = approvals
        self.signed = None
        self.current = None
        self.historical = {}

    def _signed_pages(self):
        if self.signed is not None:
            return self.signed
        self.signed = {}
        if self.approvals is None:
            self.approvals = [verify(row, "package", trusted_signers(self.vault)) for row in self.vault.rows(LEDGER)]
        for payload in self.approvals:
            revisions = payload.get("page_revisions", [])
            require(isinstance(revisions, list), "Invalid signed page revisions", 5)
            for page in revisions:
                path = page.get("path")
                require(wiki_path(path) and path in payload.get("files", {}),
                        "Signed page revision lacks its published file", 5)
                body = base64.b64decode(payload["files"][path], validate=True)
                require(digest(body) == page.get("revision"), "Signed page revision differs from its bytes", 5)
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
        commits = git(root, "log", "--reverse", "--full-history", "--format=%H", "--all", head, "--", "wiki").splitlines()
        seen = set()
        for commit in commits:
            matches = []
            for entry in git_bytes(root, "ls-tree", "-rz", commit, "--", "wiki").split(b"\0")[:-1]:
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
    def __init__(self, vault, sources, page_history, bodies=None):
        self.vault = vault
        self.sources = sources
        self.page_history = page_history
        self.bodies = bodies or {}
        self.aliases = None

    def source_id(self, identifier):
        if identifier in self.sources:
            return identifier
        if self.aliases is None:
            self.aliases = aliases(self.vault)
        return self.aliases.get(identifier, identifier)

    def parents(self, identifier):
        row = self.sources[identifier]
        body = self.bodies.get(identifier)
        if body is None:
            body = self.bodies[identifier] = safe_path(self.vault.root, row["path"], exists=True).read_bytes()
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
        if kind == "derived":
            require(isinstance(origin.get("method"), str) and origin["method"].strip(),
                    f"{identifier}: missing conversion method", 5)
            if "path" in origin:
                safe_path(self.vault.root, origin["path"])
            return kind, references(origin.get("sources")), []
        if kind == "observation":
            path = origin.get("path")
            require(isinstance(path, str) and path.strip(), f"{identifier}: missing capture origin", 5)
            safe_path(self.vault.root, path)
            return kind, [], []
        require(origin is None, f"{identifier}: unknown source origin kind", 5)
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
            kind, refs, _ = self.parents(identifier)
        except UnknownPageOrigin:
            return {row["sha256"]}
        hashes = {row["sha256"]}
        for ref in refs:
            parent = self.source_id(ref["id"])
            require(parent in self.sources, f"missing source {ref['id']} revision {ref['revision']}", 5)
            hashes.update(self.restriction_hashes(parent, (*stack, identifier)))
            self.parent_id(ref)
        for other_id, other in self.sources.items():
            if (other_id != identifier and other_id not in stack and other["sha256"] == row["sha256"] and
                    (other.get("origin") or {}).get("kind") == "derived" and kind != "derived"):
                hashes.update(self.restriction_hashes(other_id, (*stack, identifier)))
        return hashes
