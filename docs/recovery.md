# Recovery

Stop launches and integrations before restoration. Preserve current receipts
and the failed operation journal. Run `backup verify` on the selected manifest
and every available destination. Restore into a new empty directory using
`restore`; it rejects absolute paths, traversal, symlinks and mismatched hashes.
Do not overwrite a live vault. Compare the recovered manifest and Git history,
then run doctor, lint, query regression, and source locator validation.

For conversations, `session capture` creates an age archive outside Git and
immediately decrypts it in memory to verify its digest. Inventory the native
profile's transcript, attachments, tool artifacts and settings, recording the
Claude version and working directory. `session restore` reconstructs this
archive under a fresh external recovery root and verifies each artifact.
`session launch OPERATION --resume --recovery-material MATERIAL` must resume the original UUID and action, record
native result/session identifiers, and add to existing consumption. Restore the
profile under the external controller state directory. Recovery launches allow
only recovery output writes and a short verification prompt; they do not reopen
expired task integration. Sign the matching reconstruction and resume receipt
with `session approve-recovery` before native-copy removal becomes eligible.

Deletion of native copies remains blocked until the signed recovery trial
links capture digest, reconstruction digest, UUID/action and successful native
resume receipt. An unavailable format or authentication leaves a hold.
The offline age recipient must also be tested, separately from the operational
identity; record both outcomes without copying keys into the repository.

An interrupted integration is resumed with `apply --recover`; never clear its
journal by hand. An interrupted deletion retries the same persisted plan.
Already missing copies are reconciled only on accessible inventoried roots.
If preservation fails, leave the task capacity occupied and diagnose it.
The initial installation has no recovery proof; schedules cannot be activated
until actual recovery evidence exists.
