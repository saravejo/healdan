"""Admission policy for preserved originals and their registered copies."""
from pathlib import Path
from uuid import uuid4

from .core import Blocked, atomic, digest, extend_jsonl, read_json, require, safe_path, stamp
from .custody import materials, retention_deadline, validate_purpose
from .ids import next_ids, registry_records, reserve
from .lineage import Lineage, PageHistory, sha256
from .originals import REGISTRY, committed_sources, source_path, verify_body, verify_committed, verify_storage
from .signing import human_sign, trusted_signers, verify

POLICY = "healdan-source-admission-v1"
RECLASSIFICATION = "healdan-source-classification-v1"
DECISIONS = "source-classification.json"
CLASSES = {"common", "personal", "sensitive", "mixed", "unknown", "secret"}
PUBLISHABLE = {"common", "personal", "sensitive"}


class AdmissionBlocked(Blocked):
    pass


def source_rows(vault):
    return registry_records(REGISTRY, vault.rows(REGISTRY))


def published_rows(vault):
    transaction = read_json(vault.control / "transaction.json", {})
    if transaction.get("status") == "writing" and vault.head() == transaction["base"]:
        return committed_sources(vault.root, transaction["base"])
    return source_rows(vault)


def classification_token(vault):
    return digest([read_json(vault.control / name, {}) for name in ("inbox.json", "materials.json", DECISIONS)])


def append_sources(vault, rows):
    before = safe_path(vault.root, REGISTRY, exists=True).read_bytes()
    return extend_jsonl(before, rows)


def receipt(vault, identifier, kind):
    value = read_json(safe_path(vault.control, f"receipts/{identifier}.json"))
    require(value and digest(value) == identifier and value["kind"] == kind,
            "Invalid source custody receipt: " + identifier, 5)
    return value["payload"]


def material_hashes(vault, material):
    hashes = {material.get("source_sha256")}
    if material.get("kind") == "export":
        hashes.update(c.get("sha256") for c in material.get("copies", []) if c["kind"] == "export")
    quarantine = material.get("quarantine_receipt")
    if quarantine:
        incident = receipt(vault, quarantine, "quarantine")
        require(incident.get("id") == material["id"], "Quarantine receipt belongs to another material", 5)
        hashes.add(incident.get("sha256"))
    return {sha for sha in hashes if sha256(sha)}


class Classification:
    def __init__(self, vault, sources):
        self.vault = vault
        self.sources = sources
        self.items = read_json(vault.control / "inbox.json", {})
        self.materials = materials(vault)
        self.history = read_json(vault.control / DECISIONS, {})
        self.links = {}
        for record in self.materials.values():
            for sha in material_hashes(vault, record):
                self.links.setdefault(sha, []).append(record)
        self.by_hash = {}
        for row in sources.values():
            self.by_hash.setdefault(row["sha256"], []).append(row)
        self.effective = {}

    def facts(self, sha):
        facts = {}
        item = self.items.get(sha)
        if item and (item.get("classification") != "unknown" or item.get("decision")):
            facts["inbox"] = {"classification": item["classification"], "purpose": item.get("purpose"),
                              "revision": item.get("decided_at"), "receipt": item.get("decision_receipt")}
        for row in self.by_hash.get(sha, []):
            facts["source:" + row["id"]] = {"classification": row["classification"],
                                           "purpose": row.get("purpose"), "revision": digest(row)}
        for record in self.links.get(sha, []):
            facts["custody:" + record["id"]] = {"classification": record["classification"],
                                              "purpose": record.get("purpose"), "revision": record.get("captured_at"),
                                              "receipt": record.get("decision_receipt") or record.get("quarantine_receipt")}
        return facts

    def policy(self):
        authorities = self.vault.config.get("source_classification_authorities", [])
        require(isinstance(authorities, list) and all(isinstance(a, str) and a.strip() for a in authorities),
                "Invalid source classification authorities", 5)
        signers = trusted_signers(self.vault)
        return {"version": POLICY, "authorities": sorted(set(authorities)), "allowed_signers": digest(signers.read_bytes())}

    def signature(self, envelope):
        policy = self.policy()
        value = verify(envelope, "decision", trusted_signers(self.vault))
        require(value.get("format") == RECLASSIFICATION and value.get("vault") == self.vault.identity,
                "Decision belongs to another format or vault", 5)
        require(value.get("actor") == envelope["identity"] and value["actor"] in policy["authorities"],
                "No verifiable source-classification authority for the operator", 5)
        require(value.get("policy") == policy, "Source classification policy changed", 5)
        return value

    def revision(self, sha, facts):
        history = self.history.get(sha, [])
        previous = history[-1]["approval"]["digest"] if history else None
        return digest({"sha256": sha, "evidence": facts, "previous": previous})

    def prior_classes(self, sha, facts):
        classes = {fact["classification"] for fact in facts.values()}
        history = self.history.get(sha, [])
        if history:
            classes.add(history[-1]["approval"]["payload"]["to"])
        return sorted(classes)

    def copies(self, sha):
        inbox = [{"path": path, "sha256": sha, "kind": "inbox"}
                 for path in self.items.get(sha, {}).get("paths", [])]
        sources = [{"path": row["path"], "sha256": sha, "kind": "source", "revision": digest(row)}
                   for row in self.by_hash.get(sha, [])]
        custody = [{"material": record["id"], **copy} for record in self.links.get(sha, [])
                   for copy in record.get("copies", [])]
        return sorted([*inbox, *sources, *custody], key=digest)

    def current(self, sha):
        if sha in self.effective:
            return self.effective[sha]
        facts = self.facts(sha)
        classes = {fact["classification"] for fact in facts.values()}
        require(classes <= CLASSES, "Unknown recorded source classification: " + sha, 5)
        require("secret" not in classes, "Known secret must remain in quarantine: " + sha, 5)
        history = self.history.get(sha, [])
        if history:
            previous = None
            for event in history:
                envelope = event["approval"]
                payload = envelope["payload"]
                require(digest(payload) == envelope["digest"] and payload.get("previous") == previous and
                        payload.get("revision") == digest({"sha256": sha, "evidence": payload["evidence"], "previous": previous}),
                        "Source classification decision history is inconsistent: " + sha, 5)
                previous = envelope["digest"]
            event = history[-1]
            decision = self.signature(event["approval"])
            require(decision["sha256"] == sha and
                    receipt(self.vault, event["receipt"], "source-reclassification") == event["approval"],
                    "Reclassification receipt does not match the material revision", 5)
            different = [key for key, fact in facts.items()
                         if fact != decision["evidence"].get(key) and fact["classification"] != decision["to"]]
            require(not different, f"Source classification changed after the decision for {sha}: {', '.join(different)}", 5)
            result = decision["to"], event["receipt"]
        else:
            require(len(classes) <= 1, f"Conflicting source classifications for {sha}: {', '.join(sorted(classes))}", 5)
            result = next(iter(classes), None), None
        self.effective[sha] = result
        return result

    def require_use(self, row, origins):
        current, authorised = self.current(row["sha256"])
        require(current in PUBLISHABLE and (current == row["classification"] or authorised),
                f"{row['id']}: current source classification is {current}; admission recorded {row['classification']}", 5)
        for sha in origins - {row["sha256"]}:
            parent_class, _ = self.current(sha)
            require(parent_class in {"common", current}, f"{row['id']}: inherits {parent_class} restriction from {sha}", 5)
        if current != "common":
            return self.custody_link(dict(row, classification=current), origins, legacy=not row.get("origin"))
        return None

    def custody_link(self, row, origins, *, legacy=False):
        validate_purpose(row)
        purpose = row["purpose"]
        link = purpose["link"]
        record = self.materials.get(link)
        if record is None and legacy:
            matching = {record["id"]: record for sha in origins for record in self.links.get(sha, [])
                        if record.get("classification") == row["classification"] and record.get("purpose") == purpose}
            if len(matching) == 1:
                record = next(iter(matching.values()))
        require(record and record.get("classification") == row["classification"] and record.get("purpose") == purpose,
                f"{row['id']}: purpose and custody link must match the current material", 5)
        expected = material_hashes(self.vault, record) & origins
        require(expected and retention_deadline(record) is not None,
                f"{row['id']}: custody link has no applicable capture or deadline", 5)
        require(all(not fact.get("purpose") or fact["purpose"] == purpose for sha in expected
                    for fact in self.facts(sha).values() if fact["classification"] == row["classification"]),
                f"{row['id']}: purpose conflicts with the source history", 5)
        for copy in record.get("copies", []):
            if copy.get("sha256") not in expected or copy.get("status") != "present":
                continue
            root = self.vault.relocated_path(copy["root"])
            path = safe_path(root, copy["path"])
            if path.is_file() and digest(path.read_bytes()) == copy["sha256"]:
                return record["id"]
        raise Blocked(f"{row['id']}: custody link has no verified copy of the material", 5)


def sign_reclassification(vault, sha, request):
    with vault.locked():
        require(sha256(sha) and isinstance(request, dict) and set(request) == {"classification", "reason"},
                "Specify the source hash, target classification and justification", 2)
        policy = Classification(vault, published_rows(vault))
        facts = policy.facts(sha)
        classes = policy.prior_classes(sha, facts)
        require(classes and "secret" not in classes and request["classification"] in PUBLISHABLE and
                classes != [request["classification"]] and isinstance(request["reason"], str) and request["reason"].strip(),
                "Reclassification needs known nonsecret material, a different class and a justification", 5)
        actor = vault.config.get("signing_identity")
        authority = policy.policy()
        require(actor in authority["authorities"], "No verifiable source-classification authority for the operator", 5)
        history = policy.history.get(sha, [])
        previous = history[-1]["approval"]["digest"] if history else None
        decision = {"format": RECLASSIFICATION, "vault": vault.identity, "sha256": sha,
                    "revision": policy.revision(sha, facts), "evidence": facts, "from": classes,
                    "to": request["classification"], "actor": actor, "reason": request["reason"],
                    "at": stamp(), "policy": authority, "copies": policy.copies(sha), "previous": previous}
        return human_sign(vault, decision, "decision")


def reclassify(vault, envelope):
    with vault.locked():
        policy = Classification(vault, published_rows(vault))
        decision = policy.signature(envelope)
        sha = decision["sha256"]
        require(sha256(sha), "Invalid reclassification hash", 2)
        history = policy.history.setdefault(sha, [])
        if history and envelope == history[-1]["approval"]:
            policy.current(sha)
            return history[-1]
        facts = policy.facts(sha)
        classes = policy.prior_classes(sha, facts)
        require(classes and "secret" not in classes and decision["from"] == classes and
                decision["evidence"] == facts and decision["revision"] == policy.revision(sha, facts) and
                decision.get("previous") == (history[-1]["approval"]["digest"] if history else None) and
                decision.get("copies") == policy.copies(sha),
                "Reclassification refers to a stale material revision", 5)
        require(decision["to"] in PUBLISHABLE and classes != [decision["to"]] and
                isinstance(decision["reason"], str) and decision["reason"].strip(), "Invalid reclassification decision", 5)
        event = {"approval": envelope, "receipt": vault.receipt("source-reclassification", envelope, at=decision["at"])}
        history.append(event)
        atomic(vault.control / DECISIONS, policy.history)
        return event


def require_triage(vault, sha, classification):
    current, _ = Classification(vault, published_rows(vault)).current(sha)
    require(current is None or current == classification,
            f"Source {sha} is {current}; an authorized reclassification to {classification} is required", 5)


def plan(vault, candidate, baseline, *, reviewed, check_storage=True):
    """Check new source rows before any copy or manifest becomes visible."""
    sources = source_rows(candidate)
    additions = [row for key, row in sources.items() if key not in baseline]
    result = []
    try:
        original_paths = {name for name in candidate.proposed_paths if source_path(name)}
        require(original_paths <= {row["path"] for row in sources.values()},
                "New preserved source file lacks a manifest record", 5)
        if not additions:
            return result
        policy = Classification(vault, baseline)
        lineage = Lineage(candidate, sources, PageHistory(candidate))
        paths = [row["path"] for row in sources.values()]
        require(len(paths) == len(set(paths)), "Canonical sources must have distinct paths", 5)
        declared_classes = {}
        for row in additions:
            name = row["path"]
            require(source_path(name), "Invalid canonical source path: " + name, 5)
            body = safe_path(candidate.root, name, exists=True).read_bytes()
            verify_body(row, body)
            if check_storage:
                verify_storage(vault.root, name, body)
            classification = row.get("classification")
            require(classification in PUBLISHABLE, f"{row['id']}: classification is pending, mixed or quarantined", 5)
            sha = row["sha256"]
            require(declared_classes.setdefault(sha, classification) == classification,
                    f"{row['id']}: proposal declares conflicting classifications for {sha}", 5)
            current, decision = policy.current(sha)
            require(current in (None, classification),
                    f"{row['id']}: recorded classification is {current}; cannot admit as {classification}", 5)
            origins = lineage.restriction_hashes(row["id"])
            for parent in origins - {sha}:
                parent_class, _ = policy.current(parent)
                # A parent first admitted in this package still carries its own declaration.
                declared = {s["classification"] for s in sources.values() if s["sha256"] == parent}
                inherited = {parent_class} if parent_class else declared
                require(inherited <= {"common", classification},
                        f"{row['id']}: derivative inherits {', '.join(sorted(inherited))} restriction from {parent}", 5)
            material = None
            if classification != "common":
                require(reviewed, "Personal/sensitive originals require a reviewed minimal-source proposal and retention linkage", 5)
                material = policy.custody_link(row, origins)
                if current is None:
                    require(origins - {sha}, f"{row['id']}: restricted source lacks a current classification decision", 5)
            elif decision and policy.links.get(sha):
                links = [record["id"] for record in policy.links[sha] if record.get("kind") == "export"]
                require(len(links) <= 1, "Source reclassification has ambiguous custody links", 5)
                material = next(iter(links), None)
            result.append({"source": row["id"], "revision": digest(row), "path": name, "sha256": sha,
                           "classification": classification, "decision": decision, "material": material,
                           "origin": row.get("origin"), "state": "initial" if current is None else "confirmed",
                           "size": row["size"], "captured_at": stamp(row["captured_at"]), "provenance": row["provenance"]})
    except Blocked as exc:
        raise AdmissionBlocked(str(exc), exc.code) from exc
    return result


def existing_sources(vault):
    sources = source_rows(vault)
    policy = Classification(vault, sources)
    lineage = Lineage(vault, sources, PageHistory(vault))
    for row in sources.values():
        try:
            sha = row["sha256"]
            verify_body(row, safe_path(vault.root, row["path"], exists=True).read_bytes())
            linked = policy.require_use(row, lineage.restriction_hashes(row["id"]))
            classification, decision = policy.current(sha)
            yield {"status": "valid", "path": row["path"], "source": row["id"], "sha256": sha,
                   "revision": digest(row), "classification": classification, "decision": decision, "material": linked,
                   "origin": row.get("origin"), "state": "legacy" if not row.get("origin") else "confirmed",
                   "size": row["size"], "captured_at": stamp(row["captured_at"]), "provenance": row["provenance"]}
        except (Blocked, TypeError, ValueError, KeyError) as exc:
            yield {"status": "pending", "path": row.get("path"), "source": row["id"], "reason": str(exc)}


def reconcile_sources(vault):
    with vault.locked():
        vault.no_transaction()
        revision = vault.head()
        verify_committed(vault.root, revision, committed_sources(vault.root, revision).values())
        entries = list(existing_sources(vault))
        for entry in entries:
            if entry["status"] == "valid" and entry["state"] == "legacy":
                publication(vault, [entry], "present", at=entry["captured_at"])
        return {"status": "pending" if any(entry["status"] == "pending" for entry in entries) else "complete",
                "sources": entries}


def publication(vault, admissions, status, *, at):
    if not admissions:
        return
    records = materials(vault)
    inbox_path = vault.control / "inbox.json"
    inbox = read_json(inbox_path, {})
    changed = False
    inbox_changed = False
    for entry in admissions:
        identifier = entry["material"]
        source = entry["source"]
        sha = entry["sha256"]
        if identifier:
            record = records[identifier]
            existing = next((c for c in record["copies"] if c.get("source") == source and
                             c["sha256"] == sha and c["status"] != "deleted"), None)
            if existing is None and status != "withdrawn":
                existing = {"root": str(vault.root), "path": entry["path"], "sha256": entry["sha256"],
                            "source": source, "kind": "source", "status": "planned"}
                record["copies"].append(existing)
                changed = True
            if existing and status == "withdrawn":
                existing.update(status="deleted", deleted_at=at, disposition="publication withdrawn")
                changed = True
            elif existing and status in {"present", "committed"}:
                body = safe_path(vault.root, entry["path"], exists=True).read_bytes()
                require(digest(body) == entry["sha256"], "Canonical copy changed during publication", 5)
                if existing["status"] != "present":
                    existing.update(status="present")
                    existing.pop("deleted_at", None)
                    existing.pop("disposition", None)
                    changed = True
        if status == "present":
            receipt_id = vault.receipt("source-admission", entry, at=at)
            item = inbox.get(sha)
            if item is None:
                item = {"sha256": sha, "size": entry["size"], "paths": [], "versions_of": [],
                        "entered_at": entry["captured_at"], "entry_origin": entry["provenance"],
                        "classification": "unknown", "decision": None, "owner": None,
                        "inventoried_at": at, "receipts": []}
                inbox[sha] = item
                inbox_changed = True
            origin_path = (entry["origin"] or {}).get("path")
            if origin_path and origin_path.startswith("inbox/") and origin_path not in item["paths"]:
                item["paths"].append(origin_path)
                inbox_changed = True
            if not item.get("decision") and item["classification"] == "unknown":
                item.update(classification=entry["classification"], decision="ingest", destination=entry["path"],
                            decided_at=at, decision_receipt=receipt_id)
                if not item.get("entered_at"):
                    item.update(entered_at=entry["captured_at"], entry_origin=entry["provenance"])
                inbox_changed = True
            if receipt_id not in item["receipts"]:
                item["receipts"].append(receipt_id)
                inbox_changed = True
            if identifier:
                for path in item["paths"]:
                    origin = safe_path(vault.root, path)
                    if path.startswith("inbox/") and origin.is_file() and digest(origin.read_bytes()) == sha:
                        copy = {"root": str(vault.root / "inbox"), "path": path.removeprefix("inbox/"),
                                "sha256": sha, "kind": "export", "status": "present"}
                        if not any(vault.relocated_path(other["root"]) == vault.root / "inbox" and
                                   other["path"] == copy["path"] and other["sha256"] == sha and
                                   other["status"] == "present" for other in record["copies"]):
                            record["copies"].append(copy)
                            changed = True
    if changed:
        atomic(vault.control / "materials.json", records)
    if inbox_changed:
        atomic(inbox_path, inbox)


def ingest(vault, path, *, provenance, captured_at, classification, derived=None):
    from .inbox import ordinary

    require(ordinary(path), "Ingest expects an ordinary Inbox path", 2)
    require(isinstance(provenance, str) and provenance.strip(), "Ingest requires source provenance", 2)
    with vault.locked():
        vault.no_transaction()
        data = safe_path(vault.root, path, exists=True).read_bytes()
        baseline = source_rows(vault)
        verify_committed(vault.root, vault.head(), committed_sources(vault.root, vault.head()).values())
        identifier, = next_ids(vault, "F", 1)
        target = f"resources/sources/{identifier}/original{Path(path).suffix}"
        history = PageHistory(vault)
        origin = history.origin(data, path, derived)
        # A byte-for-byte copy of an earlier conversion keeps its source references.
        if origin["kind"] == "observation" and derived is None:
            known = [s for s in baseline.values() if s["sha256"] == digest(data) and
                     (s.get("origin") or {}).get("kind") == "derived"]
            if known:
                first = known[0]["origin"]
                require(all(s["origin"]["sources"] == first["sources"] for s in known), "Copy has ambiguous conversion origins", 5)
                origin = dict(first, path=path)
        record = {"id": identifier, "path": target, "sha256": digest(data), "size": len(data),
                  "captured_at": stamp(captured_at), "provenance": provenance,
                  "classification": classification, "origin": origin}
        from .transactions import Candidate
        import base64
        manifest = append_sources(vault, [record])
        with Candidate(vault, {target: base64.b64encode(data).decode(),
                               REGISTRY: base64.b64encode(manifest).decode()}) as candidate:
            admissions = plan(vault, candidate, baseline, reviewed=False)
        destination = safe_path(vault.root, target)
        require(not destination.exists(), "Source destination already exists: " + target, 5)
        require(reserve(vault, "F", 1, str(uuid4()), locked=True) == [identifier], "Source reservation changed", 5)
        atomic(destination, data)
        atomic(vault.root / REGISTRY, manifest)
        publication(vault, admissions, "present", at=stamp())
        vault.receipt("source-ingest", record)
        return record
