# Workflow

P1 (evidence integrity) preserves originals, hashes, provenance, and exact
locators. P2 (knowledge promotion) requires blind extraction, complete
independent review, CSP inspection, and a verifiable human signature.
P3 (custody and recovery) keeps encrypted conversations outside Git, with
retention and proven recovery. P4 (controlled execution) lets agents propose
and the controller validate/apply. P5 (deterministic pages) shares the query
resolver with topic rendering. These are explicit Healdan definitions.

Preserve sources with `inbox ingest`, review them, and commit the source registry
and originals locally before `task create`. A task requires clean, tracked
canonical inputs, ensuring its base can be recovered from Git. Only one active
writer is allowed by default.
Its detached worktree records creation in UTC. At 12 hours status warns;
at 24 hours new actions and integration stop. The launcher terminates its
process group at that deadline. Reconciliation preserves proposals, sources,
and checkpoints before worktree removal. Preservation failure retains capacity.
Resuming never resets the worktree clock or accumulated session consumption.

Roles have independent UTF-8 context budgets: reader/editor 8,000 bytes,
extractor/reviewer 12,000. Preparation measures the complete assembled context.
Excess fails without truncation. Retrieved evidence contributes to usage,
but not to this initial context ceiling. Page budgets are separate.

Create distinct extractor and reviewer sessions. The reviewer independently
extracts from the same source snapshot before seeing the extractor output.
`review freeze` records both immutable outputs; comparison comes afterwards.
The comparison must account for every unit and report all defects. Human
approval authenticates the package and the review evidence; a boolean supplied
by an agent is never a substitute for an approval.

CSP-1 uses i=111 and f=10%. Freeze numeric unit order and content before
generating the random seed. Store every selection and inspection receipt.
Inspect all units until 111 consecutive conforming units; then draw each unit
independently with probability 0.1. A defect immediately restores full
inspection. Resume the existing package/seed; never redraw to change selection.
Every package still requires a human SSH signature, even with zero sampled units.

Prepare a candidate in the task proposal directory. `review package` validates
sources, pages, independent review, cases, and base, then freezes the package.
Regenerate pages before signing. `approve` verifies human inspection and uses
the external key. Cases have their own signatures and decision history.
`apply` locks the common Git directory, verifies signature/base/content and
regression again, then journals each write. An interrupted apply blocks other
operations until `apply --recover` finishes the same transaction.

Human waiting starts only with a delivery receipt from `task present`.
Reminders at D+3 and D+5 are idempotent; D+7 begins closure for timeout.
Silence is never approval. Worktree expiration and human waiting are separate.
Capacity releases only after preservation, process reconciliation, and closure.
Late responses require a new explicit decision linked to the prior task.
Task closure and integration are local; no automatic PR or issue is created.
