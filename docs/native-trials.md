# Native macOS acceptance trials

These trials need the owner's authenticated Mac. They are deliberately not
represented by the disposable controller fixtures in `tests/`. Keep all logs
and native artifacts outside Git, with restrictive permissions and retention.
Never run a cleanup experiment against the normal `~/.claude` directory.

Use a disposable macOS account or VM and a fresh clone/ZIP of the exact commit.
Install the controller outside the vault. Configure distinct human and backup
SSH signers, operational and offline age recipients, and disposable backup
destinations. Record OS, Python, Git, SSH, age, Claude, Node and srt versions.
Run the automated suite including `MacSandbox`, then the procedures below.

## Authentication and independent roles

1. Preserve one harmless real source and commit the initial vault locally.
2. Create a task and extractor/reviewer sessions with distinct actions and
   measured context files. Record each S-, UUID and profile path.
3. Authenticate each printed dedicated profile with the owner's Claude account.
4. Launch the extractor and reviewer separately. Check that the reviewer cannot
   read the extractor's proposal, the canonical wiki, Git, signing key/socket,
   custody, controller policy or unrelated profiles. Use native file tools and
   a subprocess attempt as well as Bash; retain denial output hashes.
5. Freeze both independent extractions, then run comparison in the reviewer
   session. Verify that access to the extractor's frozen output opens only
   after `review freeze`. Record a full review result for every unit.

## Native reconstruction and resume

1. Record the successful native session UUID, action and token consumption.
2. Capture it with `session capture`, supplying specific purpose/necessity/owner/
   linkage for personal or unknown content. Check ciphertext and plaintext hashes.
3. Restore into a new directory below external controller state; compare every
   transcript, attachment and tool artifact against the capture inventory.
4. Resume with `session launch OPERATION --resume --recovery-material MATERIAL`.
   The result must identify the original UUID/action and cumulative usage must
   not decrease. A new conversation with the same visible title does not pass.
5. Sign recovery evidence containing cipher_sha256, plain_sha256,
   reconstruction_sha256, uuid, action, launch_receipt and the exact usage
   object. Use `session approve-recovery MATERIAL EVIDENCE.json`.
6. Corrupt a disposable copy, omit one attachment, and test an unsupported
   native layout. Each must fail recovery or preserve a deletion hold. The
   ciphertext-only success case must never authorize native-copy deletion.

## Vendor cleanup isolation

In a separate disposable account/profile, create two harmless projects with
old and recent native sessions. Keep cleanupPeriodDays=30. Inventory all files
and timestamps before invoking the installed native CLI. Record which files
the vendor cleanup actually touches, including attachments and other project
directories. Test the controller's own removal independently. Reconstruct and
resume every retained test session. Record absence checks and unexplained
changes; do not claim that an OS/controller test demonstrates vendor behavior.

## Offline recovery and backup

Disconnect operational decryption credentials. Decrypt a capture and a backup
using the offline identity alone in the authorized recovery environment.
Restore a fresh vault and compare Git refs, source bytes, locators, reservations,
session linkage/usage and signed approvals. Run query regression and page lint.
An inaccessible destination must leave deletion pending. Verify that holds do
not change an existing generation expiry. Do not copy recovery keys into logs.

## launchd

Use disposable fixture jobs first to establish calendar behavior, including
sleep/wake, logout/login and timezone changes. Record actual start/end UTC
times, not merely the plist installation. Then validate the generated Monday
09:00 lint and daily 02:00 maintenance plists. Confirm one daily sequence runs
retention before backup, failures prevent a complete round, and an interrupted
round resumes its existing plan. Verify exactly eight days does not warn and
eight days plus one tick does. Do not change the Mac clock on a production host.

## Evidence and release gate

Each trial JSON contains platform `Darwin`, exact commit, passed=true only on
success, versions, procedure, started_at, completed_at, and artifacts (external
path plus SHA-256). Sign each with `maintenance attest TRIAL EVIDENCE.json` for
claude-auth, native-resume, native-cleanup, offline-recovery and launchd.
Failed/incomplete trials remain pending and cannot be signed as passed.

Run `python scripts/release_check.py --vault . --ci-run RUN_ID`. It checks the
exact commit's successful CI, public-content audit and native signatures.
Only then create the stable v1.0.0 tag/release at that validated commit.
The public development repository is usable for inspection and these trials;
it is not proof that authenticated native acceptance has completed.
