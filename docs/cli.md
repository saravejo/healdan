# Command reference

Run commands from a human shell using the external installed controller.
Global options precede the command: `healdan --vault '/path with spaces'`.
`--state` selects external controller state at setup. Subsequent commands
resolve the bound state from the common Git directory. All commands return
JSON. `--help` lists exact arguments.

| Command | Input and effect |
|---|---|
| `setup [--interactive]` | Preserve files/history; initialize missing empty registries; external configuration |
| `state adopt [--confirm DIGEST]` | Preview and confirm the binding for an existing state or a restored vault |
| `state rebind [--confirm DIGEST]` | Preview and confirm new paths for the bound vault or state |
| `build prepare WHEEL` | Verify and install a wheel at its digest-specific path |
| `build activate DIGEST`, `build identity` | Check compatibility before selecting a build or report the active identity |
| `doctor`, `status` | Dependency/configuration/trial health and operational clocks |
| `inbox inventory` | Record content identity, paths, versions; never infer capture time |
| `inbox decide HASH DECISION` | Owner, class, known entry provenance, destination or explicit deferral |
| `inbox ingest inbox/FILE --provenance TEXT --captured-at UTC --classification common` | Reserve F-, preserve original, record hash/locator basis |
| `inbox archive-empty HASH` | Archive only classified ordinary zero-byte copies with receipts |
| `inbox quarantine inbox/FILE --owner OWNER` | Encrypt and restrict an incident copy before removing exposure |
| `task create TITLE`, `task list` | Create a recorded detached worktree; report capacity |
| `task reserve-id C --operation UUID [--count N]` | Idempotent common-Git reservation |
| `task present ID --question TEXT --receipt TEXT` | Record successful human presentation and start waiting clock |
| `task close ID` | Verified encrypted preservation, worktree removal, reconciled closure |
| `task reconcile ID` | Preserve and dismantle an expired worktree while keeping the task/waiting clock |
| `task answer ID DECISION.json` | Sign a timely human response without resetting worktree age |
| `task reopen ID DECISION.json` | Explicitly link a new task to a reconciled closed task and carry prior consumption |
| `session create TASK --role ROLE --action-name ACTION --context FILE` | Measure context; allocate S-/UUID and external profile identity |
| `session profile OPERATION` | Print isolated profile for the owner's native authentication |
| `session probe` | Real macOS runtime denial tests |
| `session launch OPERATION [--resume]` | Mandatory probe, deadline supervision, native result/usage receipt |
| `session capture OPERATION` | age archive and artifact inventory; sensitive classes need purpose JSON |
| `session restore MATERIAL DESTINATION` | Verify/decrypt and reconstruct to an empty external directory |
| `session approve-recovery MATERIAL EVIDENCE.json` | Human signature on matching capture/reconstruction/native resume |
| `review freeze TASK --extractor OP --reviewer OP` | Freeze independent extractions before comparison access |
| `review sign-case INPUT.json --output SIGNED.json` | Sign an individual human-decided case; preserve prior receipts |
| `review regression` | Invoke actual query for each signed expectation |
| `review package TASK` | Validate candidate, render pages, run regression, freeze content/order/CSP seed |
| `review inspect PACKAGE RESULTS.json` | Record the next selected units in order, mapping ID to conform/defect |
| `approve PACKAGE` | Revalidate and sign the frozen complete package from the human shell |
| `apply PACKAGE`, `apply --recover` | Verify signature, lock, revalidate, journal writes, commit locally |
| `query --entity ENTITY --property PROPERTY` | Deterministic structured query; optional cutoff/environment/topic/term |
| `preview` | Pure complete-page comparison at 6,000/12,000/20,000 UTF-8 bytes |
| `lint` | Observational checks, receipts and deduplicated follow-up tasks |
| `maintenance plan`, `maintenance execute PLAN` | Durable retention plan and per-copy guarded execution |
| `maintenance daily` | Reconcile clocks, retention, then verified backup |
| `maintenance hold`, `maintenance release-hold` | Recorded suspension and dependency resolution |
| `maintenance incident MATERIAL rotation|deletion DECISION.json` | Separate signed incident decisions |
| `maintenance trial-environment TRIAL [--profile PATH]` | Record the measured environment for a native trial |
| `maintenance attest TRIAL EVIDENCE.json` | Sign native acceptance evidence for the vault, controller build, and trial environment |
| `maintenance schedule [--activate]` | Generate/activate local-calendar launchd jobs after readiness |
| `backup create --kind long --expires-at UTC` | Encrypted generation to all configured destinations |
| `backup verify ID`, `restore ID DESTINATION` | Verify every copy and restore to a fresh directory |
| `migration inventory`, `migration purge-check` | Read-only legacy/width inventory and purge prerequisites |
| `migration preview` | Verify signed cases and inspection records, then report compatible projections and pending fields |
| `migration sign-alias INPUT.json --output SIGNED.json` | Same-identity alias with a human signed decision |

Task agents receive only their session's proposal directory, source snapshot,
measured context, and temporary/native directory. Authenticate each required
profile with `CLAUDE_CONFIG_DIR='printed path' claude auth login` before launch.
`extraction.json` holds each independent extraction; `comparison.json` maps
every proposed claim ID to an object with status `conform` and the exact claim's
SHA-256, and binds both frozen extraction hashes.
The editor proposal mirrors authorized `wiki/` and `resources/sources/` paths.
The controller writes generated pages into the frozen candidate before signing.

Templates deliberately contain null placeholders and are never operational
records. Allocate real IDs, inspect real evidence and fill them before use.
Follow `docs/acceptance.md` for required native evidence; configuring a field
or writing a template never establishes an approval or recovery proof.
