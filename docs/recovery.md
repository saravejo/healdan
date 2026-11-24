# Recovery

Keep the `.age` file and its `.manifest.json` sidecar together. The same pair
can be moved to another location. Use an external SSH allowed-signers file for
the backup signer, an external age identity for either recipient, and the
external human signing policy for any approvals in the snapshot.

The signed manifest records the expected number of replica slots and a digest
for each slot's original publication destination and filenames. Local paths
and replica availability are recorded in the controller's inventory.

```text
healdan backup verify ID --manifest COPY.manifest.json --replica COPY.age --age-identity /path/to/offline.agekey --backup-allowed-signers /path/to/backup-signers --allowed-signers /path/to/human-signers
healdan --state /path/to/new-state restore ID /path/to/new-vault --manifest COPY.manifest.json --replica COPY.age --age-identity /path/to/offline.agekey --backup-allowed-signers /path/to/backup-signers --allowed-signers /path/to/human-signers
```

Point restore at a new or empty vault directory. The new controller gets a
reciprocal binding that preserves the backed-up vault identity. The restore
journal in the external state identifies the verified snapshot, any staged
reconstruction, and the completion receipt. Repeat the same restore after an
interruption. Before completing a resumed restore, the controller verifies the
staged vault and recovered files in the external state. A changed file is
preserved and reported as a pending recovery. For a restore by ID from a working controller, use
`restore ID DESTINATION --recovery-state NEW_STATE`.

On POSIX, restored Git files use the regular or executable mode recorded in
the backed-up commit, filtered by the restoring process's umask.

Each recovered task or session that needs attention reports reconciliation
and preserves origin paths and launch evidence in its history. The recovered
controller starts with recovery trust settings and needs its own runtime
configuration. Open custody copies from the old controller are reported as
unavailable. Add `--remap FILE.json` to supply verified external copies by
material ID and original zero-based copy index, for example
`{"inbox-MATERIAL":{"0":"/path/to/preserved-file"}}`. Restored copies are
inventoried in the new state under the original material ID.

To close a restored task and release its reserved writing capacity, run
`healdan --vault NEW_VAULT --state NEW_STATE task reconcile-restored ID --confirm`.
The controller verifies linked conversation captures in local custody before
closing the task. If a long backup omitted a required body, supply the verified
encrypted copy with `--remap` when restoring. Repeat the command after an
interruption to finish recording the same closure. The closure receipt links
the original task record to the recovered controller. Sessions remain inactive,
and origin worktree and process identities stay in the task's history.

Backups created on a recovered controller carry forward the historical
manifests, receipts and origin records. A new recovery keeps distinct versions
of those records by generation. Earlier storage relocation evidence can
verify deletion receipts while the origin paths remain inactive.

A legacy generation can still be verified or restored by ID with its original
catalog and signing policy. Its restore reports which operational records
the old format omitted. Eligible encrypted bodies from a legacy short backup
are recovered under `custody/` in the destination or explicit recovery state.
To adopt a legacy vault restored without
`--recovery-state`, use `healdan --vault RESTORED --state NEW_STATE state adopt`
and confirm the recovery provenance with `--confirm DIGEST`.

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
