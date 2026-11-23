# Compatibility and migration

Healdan is a new implementation of the supplied requirements. Definitions P1
through P5, CLI, schemas, context-role mapping, and query codes are explicit
Healdan contracts. Unavailable Wiki 1.1–1.3 mechanisms are not claimed as reused.
The old 1,200-line ceiling is replaced by modular, tested implementation.
The local reference document is excluded from Git history and all packages.

`migration inventory` is read-only. It reports ID spellings and numeric
collisions, regex/width assumptions, paths, anchors, links, source locators,
decisions, lessons, signed payloads, and snapshots. It never repairs spelling
or renumbers. No historical questions are invented; the 37-question inventory
remains unavailable until supplied by the owner.

`migration preview` verifies each case and package in its original SSH
namespace. A compatible projection includes the original JSONL row bytes in
Base64, the row and payload SHA-256 digests, and the signature envelope.
`review regression` evaluates the same case projection. Unknown formats,
fields, and inspection regimes remain pending.

The preview preserves each claim's recorded modality and marks authority as
undetermined. For signed CSP-1 packages it reports the inspected units and the
units outside the sample, along with the recorded sequence. A different
inspection regime requires its own human decision and new sequence.

Preview measures complete P5 segments at 6,000, 12,000 and 20,000 UTF-8 bytes.
Group by existing entity, then property/environment if needed, then numeric-ID
parts preserving complete claims. Render each attempt with title, delimiters,
cutoff, sources, qualifiers, states and pending content. Missing fields and
oversize indivisible units remain pending. Without a renderer, size is null.
Concurrent input changes invalidate preview. There is no approved default cap.

A signed migration package must bind preview fingerprint, human cap/names,
selectors and all rendered pages. Keep old paths/anchors as explicit forwarding
pages. Validate internal links and source locators. D-/L- records, approvals,
signed snapshots and historical payloads retain exact bytes and identity.
Regenerate before approval and revalidate under the integration lock.

Historical purge is separate from setup and normal migration. Any extra Git
worktree (including detached, locked or stale), live process, pending operation,
or unresolved backup inventory blocks purge. `worktree prune` alone proves
nothing. `migration purge-check` inventories guards; it does not rewrite Git.
Exceptional execution requires inventory, compatible preservation, reviewed
filter in a disposable no-local clone, signed old/new map, preserved old
signature receipts, approval, and verification of refs, reachable/unreachable
objects, reflogs, packs, backups and external copies. Do not infer authorization
to purge an existing vault from setup or repository publication.

Runtime references: [sandbox runtime v0.0.83](https://github.com/anthropics/sandbox-runtime/tree/v0.0.83),
[Claude CLI](https://code.claude.com/docs/en/cli-reference),
[Claude sandbox environments](https://code.claude.com/docs/en/sandbox-environments).
The outer runtime wraps the complete Claude process tree; Claude's own Bash
sandbox alone is not the controller's isolation boundary.
