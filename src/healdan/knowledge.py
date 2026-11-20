"""Evidence validation and the deterministic resolver shared by query and P5."""
from __future__ import annotations

import math
from pathlib import Path

from .core import Blocked, digest, require, safe_path, stamp, utc
from .ids import identity, inventory
from .signing import trusted_signers, verify

LIVE = {"accepted", "hypothesis", "disputed"}
STATES = LIVE | {"superseded", "rejected"}


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
        rows = vault.rows("wiki/claims.jsonl")
        require(not inventory(rows)["collisions"], "Claim identity collision")
        self.claims = {r["id"]: r for r in rows}
        self.by_identity = {identity(k): k for k in self.claims}
        self.sources = {}
        source_rows = vault.rows("resources/sources/index.jsonl")
        require(not inventory(source_rows)["collisions"], "Source identity collision")
        for row in source_rows:
            require(identity(row["id"])[0] == "F", "Source needs an F- ID")
            require(row.get("provenance") and row.get("classification"), "Missing source provenance/class")
            utc(row["captured_at"])
            require(row["path"].startswith("resources/sources/"), "Source path outside source tree")
            body = safe_path(vault.root, row["path"], exists=True).read_bytes()
            require(len(body) == row["size"] and digest(body) == row["sha256"], "Source hash/size mismatch")
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
        for entry in vault.rows("control/approvals/packages.jsonl"):
            payload = verify(entry, "package", trusted_signers(vault))
            approved.update(payload.get("claim_digests", {}).values())
        for row in rows:
            require(identity(row["id"])[0] == "C", "Claim needs a C- ID")
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
            for locator in row["sources"]:
                require(locator.get("id") in self.sources, "Unknown source locator")
                body = self.sources[locator["id"]][1]
                start, end = locator.get("start"), locator.get("end")
                require(type(start) is int and type(end) is int and 0 <= start < end <= len(body),
                        "Invalid byte locator")
                require(digest(body[start:end]) == locator.get("sha256"), "Locator hash mismatch")
            if row["state"] == "accepted":
                require(digest(row) in approved, "Accepted claim lacks a matching signed promotion")
            if row["state"] == "superseded":
                require(row.get("successor"), "Superseded claim lacks successor")
            self.successor(row["id"])

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

    def resolve(self, filters, cutoff, *, max_records=None):
        allowed = {"entity", "property", "environment", "modality", "topic", "term"}
        require(set(filters) <= allowed and all(isinstance(v, str) for v in filters.values()),
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
        eligible = [c for c in candidates if c["state"] == "accepted"]
        conflicts = set()
        for a in candidates:
            for b in candidates:
                if (a["id"] != b["id"] and claim_key(a) == claim_key(b) and
                    a["state"] != "hypothesis" and b["state"] != "hypothesis" and
                    (a["value"] != b["value"] or a["polarity"] != b["polarity"])):
                    conflicts.update((a["id"], b["id"]))
        result = {"ids": [c["id"] for c in eligible], "value": None, "polarity": None,
                  "conflicts": sorted(conflicts, key=identity), "research": "complete"}
        if conflicts:
            result.update(code=3, outcome="conflict")
        elif not eligible:
            result.update(code=20, outcome="abstention")
        elif len({claim_key(c) for c in eligible}) != 1:
            result.update(code=2, outcome="invalid", diagnostics=["Narrow the structured query"])
        elif any(c["state"] == "disputed" for c in candidates):
            result.update(code=5, outcome="blocked", research="blocked")
        else:
            result.update(code=0, outcome="answer", value=eligible[0]["value"], polarity=eligible[0]["polarity"])
        return result


def query(vault, filters, cutoff=None, *, proposed=(), max_records=None):
    try:
        cutoff = stamp(cutoff)
        before = vault.fingerprint()
        result = Knowledge(vault, proposed=proposed).resolve(filters, cutoff, max_records=max_records)
        require(vault.fingerprint() == before, "Query inputs changed during research", 5)
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
