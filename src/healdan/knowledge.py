"""Evidence validation and the deterministic resolver shared by query and P5."""
from __future__ import annotations

import math

from .core import Blocked, digest, require, safe_path, stamp, utc
from .ids import identity, registry_records
from . import admission, originals
from .lineage import Lineage, PageHistory
from .signing import trusted_signers, verify

LIVE = {"accepted", "hypothesis", "disputed"}
STATES = LIVE | {"superseded", "rejected"}
QUERY_FILTERS = {"entity", "property", "environment", "modality", "topic", "term"}


def typed(value):
    require(isinstance(value, dict) and set(value) == {"type", "value", "unit"}, "Invalid typed value")
    types = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "null": type(None)}
    kind, raw = value["type"], value["value"]
    require(kind in types, "Unknown value type")
    allowed = types[kind] if isinstance(types[kind], tuple) else (types[kind],)
    require(type(raw) in allowed, "Value does not match its declared type")
    require(not isinstance(raw, float) or math.isfinite(raw), "Non-finite value")
    require(value["unit"] is None or isinstance(value["unit"], str), "Invalid unit")
    return value


def claim_key(claim):
    return tuple(claim.get(k) for k in ("entity", "property", "environment", "modality"))


class Knowledge:
    def __init__(self, vault, *, proposed=(), diagnostic=False):
        self.vault = vault
        claims = "wiki/claims.jsonl"
        self.claims = registry_records(claims, vault.rows(claims))
        self.by_identity = {identity(k): k for k in self.claims}
        self.sources = {}
        sources = originals.REGISTRY
        root, revision = vault.repository.root, vault.head()
        originals.verify_committed(root, revision, originals.committed_sources(root, revision).values())
        for row in registry_records(sources, vault.rows(sources)).values():
            require(row.get("provenance") and row.get("classification"), "Missing source provenance/class")
            require(row["classification"] != "secret", "Secrets cannot be promoted as canonical sources")
            if row["classification"] != "common":
                from .custody import validate_purpose
                validate_purpose(row)
            captured_at = row.get("captured_at")
            message = f"Source {row['id']} captured_at requires an ISO timestamp with a UTC offset"
            require(isinstance(captured_at, str), message)
            try:
                utc(captured_at)
            except (Blocked, OverflowError, ValueError) as exc:
                raise Blocked(message) from exc
            require(originals.source_path(row["path"]), "Source path outside source tree")
            body = safe_path(vault.root, row["path"], exists=True).read_bytes()
            originals.verify_body(row, body)
            self.sources[row["id"]] = (row, body)
        self.membership = {}
        for row in vault.rows("wiki/control/topic-map.jsonl"):
            key = self.resolve_id(row["id"])
            require(key not in self.membership, "Duplicate topic map identity")
            require(type(row.get("replace_primary_topic", False)) is bool, "Invalid replacement flag")
            require(isinstance(row.get("topics"), list) and
                    all(isinstance(t, str) and t.strip() for t in row["topics"]), "Invalid topics")
            topics = set(row["topics"])
            if not row.get("replace_primary_topic", False):
                topics.add(self.claims[key].get("primary_topic"))
            self.membership[key] = topics - {None, ""}
        approved = set(proposed)
        approvals = []
        for entry in vault.rows("control/approvals/packages.jsonl"):
            payload = verify(entry, "package", trusted_signers(vault))
            approvals.append(payload)
            approved.update(payload.get("claim_digests", {}).values())
        self.lineage = Lineage(vault, {identifier: row for identifier, (row, _) in self.sources.items()},
                               PageHistory(vault, approvals),
                               {identifier: body for identifier, (_, body) in self.sources.items()})
        self.locators = {}
        for row in self.claims.values():
            require(row.get("state") in STATES, "Unknown claim state")
            required = ("statement",) if diagnostic else ("statement", "entity", "property", "environment")
            require(all(isinstance(row.get(k), str) and row[k].strip() for k in required), "Missing claim fields")
            typed(row["value"])
            require(row.get("polarity") in {"positive", "negative"}, "Invalid polarity")
            if row.get("valid_from"):
                utc(row["valid_from"])
            if row.get("valid_to"):
                utc(row["valid_to"])
            if row.get("valid_from") and row.get("valid_to"):
                require(utc(row["valid_from"]) < utc(row["valid_to"]), "Empty validity interval")
            require(isinstance(row.get("sources"), list) and row["sources"], "Claim lacks source locators")
            minimum = row.get("minimum_observations", 1)
            require(type(minimum) is int and minimum > 0, "Invalid minimum source observations")
            self.locators[row["id"]] = []
            for locator in row["sources"]:
                source_id = self.lineage.source_id(locator.get("id"))
                require(source_id in self.sources, "Unknown source locator")
                body = self.sources[source_id][1]
                start, end = locator.get("start"), locator.get("end")
                require(type(start) is int and type(end) is int and 0 <= start < end <= len(body),
                        "Invalid byte locator")
                require(digest(body[start:end]) == locator.get("sha256"), "Locator hash mismatch")
                self.locators[row["id"]].append((source_id, locator.get("revision")))
            if row["state"] == "accepted":
                require(digest(row) in approved, "Accepted claim lacks a matching signed promotion")
            if row["state"] == "superseded":
                require(row.get("successor"), "Superseded claim lacks successor")
            self.successor(row["id"])
        self.classification = admission.Classification(vault, self.lineage.sources)

    def resolve_id(self, value):
        key = identity(value)
        require(key in self.by_identity, "Missing claim: " + value)
        # Nonoriginal spellings require an explicitly signed alias.
        original = self.by_identity[key]
        if value != original:
            from .ids import aliases
            require(aliases(self.vault).get(value) == original, "Unapproved legacy alias")
        return original

    def successor(self, value):
        seen = set()
        current = self.resolve_id(value)
        while self.claims[current].get("successor"):
            require(current not in seen, "Successor cycle")
            seen.add(current)
            current = self.resolve_id(self.claims[current]["successor"])
        return current

    def topics(self, value):
        key = self.resolve_id(value)
        return self.membership.get(key, {self.claims[key].get("primary_topic")} - {None, ""})

    def active(self, row, cutoff):
        return (row["state"] in LIVE and
                (not row.get("valid_from") or utc(row["valid_from"]) <= cutoff) and
                (not row.get("valid_to") or cutoff < utc(row["valid_to"])))

    def source_support(self, identifier, cutoff, chain, revision=None):
        label = " -> ".join((*chain, identifier))
        require(identifier not in chain, "Source lineage cycle: " + label, 5)
        source = self.lineage.sources[identifier]
        require(revision is None or digest(source) == revision, label + ": source revision differs", 5)
        kind, refs, claims = self.lineage.parents(identifier)
        self.classification.require_use(source, self.lineage.restriction_hashes(identifier))
        if kind in {"observation", "legacy"}:
            return ({source["sha256"]}, False) if kind == "observation" else (set(), True)
        roots, unknown = set(), False
        if claims:
            for use in claims:
                claim_id = use["id"]
                claim = self.claims.get(claim_id)
                use_label = label + " -> " + claim_id
                require(claim and claim["state"] == "accepted" and self.active(claim, cutoff),
                        use_label + ": referenced claim is missing, rejected, or not current", 5)
                require(digest(claim) == use["revision"] and use["sources"], use_label + ": claim revision differs", 5)
                require(claim_id not in chain, "Claim lineage cycle: " + use_label, 5)
                verified = [(self.lineage.parent_id(ref), ref["revision"]) for ref in use["sources"]]
                require({source_id for source_id, _ in verified} ==
                        {source_id for source_id, _ in self.locators[claim_id]},
                        use_label + ": source references differ from the claim revision", 5)
                supported, observed, messages = self.support(claim, cutoff, (*chain, identifier))
                require(supported, use_label + ": " + "; ".join(messages), 5)
                roots.update(observed)
                unknown |= not observed
        else:
            for ref in refs:
                parent = self.lineage.parent_id(ref)
                observed, uncertain = self.source_support(parent, cutoff, (*chain, identifier), ref["revision"])
                roots.update(observed)
                unknown |= uncertain
        return roots, unknown

    def support(self, row, cutoff, chain=()):
        chain = (*chain, row["id"])
        roots, legacy, problems = set(), False, []
        for identifier, revision in self.locators[row["id"]]:
            try:
                observed, uncertain = self.source_support(identifier, cutoff, chain, revision)
                roots.update(observed)
                legacy |= uncertain
            except Blocked as exc:
                message = str(exc)
                problems.append(message if message.startswith(" -> ".join(chain)) else
                                " -> ".join((*chain, identifier)) + ": " + message)
        minimum = row.get("minimum_observations")
        supported = len(roots) >= (minimum or 1) or (legacy and minimum is None)
        if not supported and minimum is not None:
            problems.append(f"{row['id']}: {len(roots)} verified observations, {minimum} required")
            if legacy:
                problems.append(f"{row['id']}: legacy source independence is pending")
        return supported, roots, problems

    def resolve(self, filters, cutoff, *, max_records=None):
        require(set(filters) <= QUERY_FILTERS and all(isinstance(v, str) for v in filters.values()),
                "Unsupported query filter", 2)
        if max_records is not None and len(self.claims) > max_records:
            return {"code": 5, "outcome": "blocked", "ids": [], "value": None,
                    "polarity": None, "conflicts": [], "research": "incomplete"}
        cutoff = utc(cutoff)
        keys = set()
        for row in self.claims.values():
            if any(row.get(k) != v for k, v in filters.items() if k not in {"topic", "term"}):
                continue
            if filters.get("topic") and filters["topic"] not in self.topics(row["id"]):
                continue
            if filters.get("term") and filters["term"].casefold() not in row["statement"].casefold():
                continue
            keys.add(claim_key(self.claims[self.successor(row["id"])]))
        candidates = [c for c in self.claims.values() if claim_key(c) in keys and self.active(c, cutoff)]
        candidates.sort(key=lambda c: identity(c["id"]))
        support = {row["id"]: self.support(row, cutoff) for row in candidates}
        supported = [c for c in candidates if support[c["id"]][0]]
        eligible = [c for c in supported if c["state"] == "accepted"]
        conflicts = set()
        for a in supported:
            for b in supported:
                if (a["id"] != b["id"] and claim_key(a) == claim_key(b) and
                    a["state"] != "hypothesis" and b["state"] != "hypothesis" and
                    (a["value"] != b["value"] or a["polarity"] != b["polarity"])):
                    conflicts.update((a["id"], b["id"]))
        result = {"ids": [c["id"] for c in eligible], "value": None, "polarity": None,
                  "conflicts": sorted(conflicts, key=identity), "research": "complete",
                  "observations": sorted({root for _, roots, _ in support.values() for root in roots})}
        problems = [message for ok, _, messages in support.values() if not ok for message in messages]
        if problems:
            result["diagnostics"] = problems
        if conflicts:
            result.update(code=3, outcome="conflict")
        elif not eligible:
            result.update(code=20, outcome="abstention")
        elif len({claim_key(c) for c in eligible}) != 1:
            result.update(code=2, outcome="invalid", diagnostics=["Narrow the structured query"])
        elif any(c["state"] == "disputed" for c in supported):
            result.update(code=5, outcome="blocked", research="blocked")
        else:
            result.update(code=0, outcome="answer", value=eligible[0]["value"], polarity=eligible[0]["polarity"])
        return result


def query(vault, filters, cutoff=None, *, proposed=(), max_records=None):
    try:
        cutoff = stamp(cutoff)
        before = vault.fingerprint()
        classification = admission.classification_token(vault)
        result = Knowledge(vault, proposed=proposed).resolve(filters, cutoff, max_records=max_records)
        require(vault.fingerprint() == before and admission.classification_token(vault) == classification,
                "Query inputs changed during research", 5)
        return dict(result, cutoff=cutoff, commit=vault.head(), fingerprint=before)
    except Blocked as exc:
        return {"code": exc.code, "outcome": "invalid", "ids": [], "value": None,
                "polarity": None, "conflicts": [], "cutoff": cutoff,
                "commit": vault.head(), "research": "blocked", "diagnostics": [str(exc)]}
    except (ValueError, KeyError, TypeError, OSError) as exc:
        code = 1 if isinstance(exc, OSError) else 4
        return {"code": code, "outcome": "invalid", "ids": [], "value": None,
                "polarity": None, "conflicts": [], "cutoff": cutoff, "commit": vault.head(),
                "research": "blocked", "diagnostics": ["Incomplete or unreadable input: " + str(exc)]}
