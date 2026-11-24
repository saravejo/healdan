"""Pure complete-segment rendering and deterministic splitting previews."""
from collections import defaultdict
import re
from urllib.parse import quote, unquote

from . import admission
from .core import digest, read_json, require, safe_path, stamp, utc
from .ids import identity
from .knowledge import Knowledge, LIVE, claim_key

CAPS = (6000, 12000, 20000)


def escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")


def render_current(knowledge, ids, title, cutoff):
    require(isinstance(title, str) and title.strip() and "\n" not in title, "Invalid page title")
    selected = sorted({knowledge.resolve_id(i) for i in ids}, key=identity)
    current, pending = [], []
    for identifier in selected:
        row = knowledge.claims[identifier]
        require(row["state"] in LIVE, "Terminal claim in a current selector")
        filters = {k: row[k] for k in ("entity", "property", "environment") if row.get(k)}
        if row.get("modality"):
            filters["modality"] = row["modality"]
        answer = knowledge.resolve(filters, cutoff)
        factual = answer["code"] == 0 and identifier in answer["ids"]
        citations = "; ".join(f"{s['id']} bytes {s['start']}:{s['end']} sha256:{s['sha256']}" for s in row["sources"])
        line = (f"<a id=\"{identifier}\"></a>\n- **{identifier}** [{row['state']}] "
                f"{escape(row['statement'])}\n  Value: {escape(row['value'])}; "
                f"polarity: {row['polarity']}; environment: {escape(row.get('environment'))}.\n"
                f"  Sources: {citations}.\n  Validity: {escape(row.get('valid_from'))} to {escape(row.get('valid_to'))}.\n"
                f"  Qualifiers: {escape(row.get('qualifiers', {}))}.\n")
        if not factual:
            line += f"  Pending: {answer['outcome']}; conflicts: {', '.join(answer['conflicts'])}.\n"
            supported, _, reasons = knowledge.support(row, utc(cutoff))
            if not supported and reasons:
                line += "  Evidence: " + escape("; ".join(reasons)) + ".\n"
        (current if factual else pending).append(line)
    return ("<!-- healdan:current:start -->\n# " + escape(title) + "\n\nCutoff: " + stamp(cutoff) +
            "\n\n## Knowledge\n\n" + "\n".join(current) + "\n## Pending\n\n" + "\n".join(pending) +
            "\n<!-- healdan:current:end -->\n")


def split_preview(rows, renderer, caps=CAPS):
    require(bool(caps) and len(set(caps)) == len(caps) and all(type(n) is int and n > 0 for n in caps),
            "Invalid preview caps", 2)
    groups, missing = defaultdict(list), []
    seen = set()
    for row in sorted(rows, key=lambda c: identity(c["id"])):
        require(identity(row["id"]) not in seen, "Numeric collision in preview")
        seen.add(identity(row["id"]))
        if row["state"] not in LIVE:
            continue
        if not row.get("entity") or row["entity"] == "unknown":
            missing.append({"id": row["id"], "reason": "Missing entity"})
        else:
            groups[row["entity"]].append(row)
    output = []
    for cap in caps:
        parts, pending = [], list(missing)
        if renderer is None:
            output.append({"cap": cap, "parts": None, "bytes": None,
                           "status": "Renderer unavailable", "pending": pending})
            continue

        def measure(title, members):
            text = renderer(title, [c["id"] for c in members])
            require(isinstance(text, str), "Renderer must return a complete text segment")
            return len(text.encode("utf-8"))

        def emit(title, members):
            size = measure(title, members)
            require(size <= cap, "Preview segment exceeds cap")
            parts.append({"name": title, "ids": [c["id"] for c in members],
                          "purpose": "current_at_cutoff", "bytes": size})

        for entity, members in sorted(groups.items()):
            base = quote(entity, safe="")
            if measure(base, members) <= cap:
                emit(base, members)
                continue
            subgroups = defaultdict(list)
            for c in members:
                fields = (c.get("property"), c.get("environment"))
                if any(not f or f == "unknown" for f in fields):
                    pending.append({"id": c["id"], "reason": "Missing subdivision fields"})
                else:
                    subgroups[fields].append(c)
            for fields, subset in sorted(subgroups.items()):
                name = base + "/" + "/".join(quote(f, safe="") for f in fields)
                if measure(name, subset) <= cap:
                    emit(name, subset)
                    continue
                part, batch = 1, []
                for c in subset:
                    title = f"{name}/part-{part}"
                    if batch and measure(title, batch + [c]) > cap:
                        emit(title, batch)
                        part, batch = part + 1, []
                        title = f"{name}/part-{part}"
                    if measure(title, [c]) > cap:
                        pending.append({"id": c["id"], "reason": "Indivisible unit exceeds cap",
                                        "bytes": measure(title, [c])})
                    else:
                        batch.append(c)
                if batch:
                    emit(f"{name}/part-{part}", batch)
        output.append({"cap": cap, "parts": parts, "bytes": sum(p["bytes"] for p in parts),
                       "pending": pending, "status": "pending" if pending else "ready"})
    return output


def preview(vault, cutoff=None, *, proposed=()):
    before = vault.fingerprint()
    classification = admission.classification_token(vault)
    knowledge = Knowledge(vault, proposed=proposed, diagnostic=True)
    cutoff = stamp(cutoff)
    result = split_preview(list(knowledge.claims.values()),
                           lambda title, ids: render_current(knowledge, ids, title, cutoff))
    pending = []
    for row in knowledge.claims.values():
        if row["state"] in LIVE:
            supported, _, reasons = knowledge.support(row, utc(cutoff))
            if not supported:
                pending.append({"id": row["id"], "reasons": reasons})
    require(before == vault.fingerprint() and admission.classification_token(vault) == classification,
            "Concurrent change invalidated preview", 5)
    return {"fingerprint": before, "cutoff": cutoff, "comparisons": result, "pending_evidence": pending}


def generated_pages(vault, *, proposed=()):
    knowledge = Knowledge(vault, proposed=proposed)
    selectors = vault.rows("wiki/control/selectors.jsonl")
    policy = read_json(vault.root / "wiki/control/page-policy.json", {})
    pages, coverage = {}, set()
    for selector in selectors:
        require(selector.get("purpose") == "current_at_cutoff", "Invalid selector purpose")
        path = selector["path"]
        require(path.startswith("wiki/topics/") and path.endswith(".md") and path not in pages,
                "Invalid or duplicate page destination")
        safe_path(vault.root, path)
        require(type(policy.get("cap")) is int and policy["cap"] in CAPS and policy.get("decision"),
                "Human page cap and naming decision required", 5)
        for identifier in selector["ids"]:
            require(selector["topic"] in knowledge.topics(identifier), "Selector is outside claim membership")
            coverage.add(knowledge.resolve_id(identifier))
        body = render_current(knowledge, selector["ids"], selector["title"], selector["cutoff"]).encode("utf-8")
        require(len(body) <= policy["cap"], "Complete current page exceeds approved byte cap")
        pages[path] = body
    live = {k for k, c in knowledge.claims.items() if c["state"] in LIVE}
    require(live <= coverage, "Live claims lack topic page coverage: " + ", ".join(sorted(live - coverage)))
    return pages


def validate_pages(vault, *, proposed=()):
    for path, expected in generated_pages(vault, proposed=proposed).items():
        body = safe_path(vault.root, path, exists=True).read_bytes()
        require(body.startswith(expected), "P5 segment does not match the shared resolver: " + path)
        tail = body[len(expected):]
        require(not tail or (tail.startswith(b"<!-- healdan:history:start -->") and
                            tail.rstrip().endswith(b"<!-- healdan:history:end -->")), "Undelimited page history")
    validate_links(vault)


def validate_links(vault):
    for path in (vault.root / "wiki").rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
            if "://" in target or target.startswith("mailto:"):
                continue
            dest, _, anchor = target.partition("#")
            rel = (path.parent / unquote(dest)).resolve() if dest else path
            require(rel.is_relative_to(vault.root) and rel.is_file(), "Broken internal link")
            safe_path(vault.root, rel.relative_to(vault.root), exists=True)
            if anchor:
                content = rel.read_text(encoding="utf-8")
                headings = {re.sub(r"[^\w -]", "", h.strip().lower()).replace(" ", "-")
                            for h in re.findall(r"^#+ (.+)$", content, re.MULTILINE)}
                require(anchor in headings or f'id="{anchor}"' in content or f"^{anchor}" in content,
                        "Broken internal anchor")
