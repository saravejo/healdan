# Data model

All distributed names, messages, fields, and configuration are English.
JSON is UTF-8, finite, and rejects duplicate keys. JSONL starts empty.
Timestamps must have an offset and are normalized to UTC.

Setup initializes the nine required JSONL registries. An empty registry is
valid. A missing or malformed registry produces integrity error 4 during
operational use. A read failure produces technical error 1.

Identifiers use F/C/D/L/Q/M/S followed by ASCII digits. New fields require
four digits or a larger integer without extra leading zeros. Identity and
order are `(prefix, numeric_suffix)`; reservation starts at one, never zero.
Diagnostic legacy reads retain original spelling. Ambiguous numeric collisions
block affected reservations/migrations. Signed aliases identify the same
numeric identity and do not create another record. Reservations live under
the common Git directory, use a cross-process lock and operation UUID, include
all published/reserved identifiers, and never reclaim an abandoned number.

`resources/sources/index.jsonl` records F- ID, path, SHA-256, size, capture time,
provenance, and classification. Paths stay below `resources/sources/`.
Locators use byte offsets and a SHA-256 of the exact byte range; no inferred
page offset is accepted. Original bytes are never rewritten by promotion.
The controller checks the effective Git attributes and the blob stored for each
new original, including originals submitted in a source proposal. Original
files use `-text`; the JSONL registry retains its text format. BOMs, mixed line
endings, binary bytes and empty files retain their exact digests. Empty files
have no valid nonempty evidence interval. A mismatch in a historical blob
identifies the source and revision and requires verified raw bytes for an
explicit reconciliation; reading or diagnosing it does not rewrite history.

New lineage uses `origin.format = healdan-source-origin-v1`, records the capture origin and identifies parent source
revisions. A wiki-derived source records page revisions and their supporting
claims and sources. References are checked against current records rather than
accepted from an index. Rejected supporting claims, missing revisions and
cycles cannot supply independent evidence. Known copies share their observation
roots. A claim can require `minimum_observations`; the query reports the unique
roots in `observations`. Legacy lineage remains undetermined where independence
cannot be established, without rewriting the old row or signature.

Admission reconciles the source bytes and revision with existing Inbox,
canonical-source and custody records. An explicit first classification may
classify previously unknown material. Changing an existing classification
requires a signed `healdan-source-classification-v1` decision by an authorized identity. Restricted derivatives
retain their parents' restrictions. Custody records keep their existing holds,
deadlines and copy history when a canonical copy is added.

`wiki/claims.jsonl` contains C- ID, statement, entity, property, environment,
primary_topic, state, typed value `{type,value,unit}`, polarity, sources,
valid_from/valid_to, optional successor, and qualifiers. Allowed states:
accepted, hypothesis, disputed, superseded, rejected. Hypotheses and disputes
remain visible as pending and cannot support factual answers. Acceptance also
requires a matching signed promotion receipt. Types distinguish booleans from
integers. Successor chains must exist and be acyclic.

`wiki/control/topic-map.jsonl` contains id, topics, and
replace_primary_topic (default false). False means union; true replaces the
principal membership without changing the claim. Selectors contain explicit
IDs, a title, path, cutoff, and purpose `current_at_cutoff`.
Decisions D- and lessons L- have their own registries and signed payloads;
they are never converted into claims during navigation changes.

Query accepts structured entity/property/environment/topic/term filters and a
cutoff. It follows successors and searches counterevidence across topics.
JSON returns IDs, typed value, polarity, conflicts, cutoff, commit, research
state, and diagnostics. Exit codes: 0 answer; 1 technical failure; 2 invalid
input; 3 conflict; 4 integrity failure; 5 incomplete/blocked research;
20 abstention. A failure never counts as abstention.

Cases in `wiki/control/query-cases.jsonl` contain an ID, question, filters,
cutoff or temporal policy, reason, and a human decision with an individual
SSH signature. Cases with `format` set to `healdan-query-case-v2` group the
expected IDs, value, polarity, outcome, and conflicts in `expectation`.
The controller verifies legacy cases with flat expectation fields before
projecting their fields into this shape for regression. Signatures use
separate namespaces for cases, packages, aliases, and trial evidence.
Previous signed decisions remain in immutable receipt history.

Tasks and sessions are controller state. A session has S-, UUID, task/action,
role, profile, consumption and launch history. A new action uses a new S-;
resume keeps the same linkage and cumulative usage. Custody manifests contain
hashes and metadata, never conversation bodies. Controller commands accept
JSON files for complex inputs; see `healdan <command> --help`.
