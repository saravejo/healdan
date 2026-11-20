# Operations

Ordinary Inbox triage excludes agent-activities-today.md,
manual-activities-today.md, agent-dashboard.html, and tasks/** below inbox/.
control/tasks/** is separate. Security and retention still apply to excluded
paths. Inventory records paths, hashes, sizes, entry time and its provenance,
classification, owner, decisions, and receipts. Unknown entry time stays
unknown. Content changes create versions; copies/renames preserve the original
deadline. Decisions or dated deferrals are due at seven days. A deferral
preserves original overdue status and retention, and warns on its date.
Only exactly zero-byte ordinary files may be automatically archived.

Lint is read-only with respect to knowledge and Inbox. It writes only run
receipts, logs, and deduplicated follow-up tasks (one open per category).
Findings distinguish new, persistent, and resolved. Partial/failed runs never
renew last_complete_lint_at. No complete lint, or age strictly greater than
eight days, produces an alert. Weekly regression invokes the actual query.

All retention days mean 24 hours UTC. Common conversations expire 30 days after
reconciled closure; personal/sensitive/mixed/unknown conversations after seven.
Sensitive exports expire seven days after recorded capture. Unknown capture or
closure blocks deletion. Personal material requires purpose, necessity, owner,
and linkage. Dependencies and holds prevent deletion without changing the
original deadline. Released, overdue holds are handled next daily round.

Secrets require immediate restricted quarantine. Separate receipts record
quarantine, authorized rotation/revocation confirmation, and deletion decision.
No receipt repeats the secret. A human incident owner performs rotation.
Source dependencies must be resolved before removing their only evidence.

The daily job persists its deletion plan, then rechecks hashes, allowed roots,
symlinks, dependencies, holds, and copy availability under lock. Results are
per copy and resumable. A failure leaves deletion pending and prevents a normal
complete backup round. Only after retention does backup run.

Long generations contain conversation manifests only. Short generations have
an immutable expiry strictly earlier than every included body's deadline.
Holds never extend an existing generation. Separate encrypted preservation
needs its own reviewed plan. Offline destinations remain pending, never absent.
Logical deletion does not promise physical SSD overwrite or deletion of
uninventoried copies. Git bundles are audited for historical conversations
before inclusion. Backup receipts and manifests survive body deletion.

Native Claude copies require verified encrypted capture, artifact inventory,
reconstructed native format, and a successful resume with the same UUID/action
and cumulative consumption before removal. A decryptable archive alone is
insufficient. Missing proof creates a hold. Keep cleanupPeriodDays=30; the
vendor's cleanup is separately tested in an isolated profile and is not assumed
to obey controller guards. Native copies must be inventoried before launch.
