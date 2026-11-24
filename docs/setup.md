# Setup

Install Python 3.12+, Git, OpenSSH, age, Node.js 22.12+, Claude Code, and
Obsidian from their official distributions. Homebrew is optional.
Install the exact sandbox runtime with
`npm install -g @anthropic-ai/sandbox-runtime@0.0.83`.
The runtime is version checked before use; changing it requires new trials.

Clone the repository or extract a ZIP, then run `python3 scripts/setup.py`.
The bootstrap builds a wheel, installs it in an external virtualenv identified
by its SHA-256 digest, and checks the installed files and entry point. It
initializes Git for ZIPs and selects the verified build for the vault. Use
`--wheel PATH` to select an existing wheel. Setup prints the absolute
`controller` path and the `command` for the vault. Add that executable's
directory to `PATH` or use its absolute path. Quote paths containing spaces.
Setup is repeatable and does not overwrite an existing configuration.
It removes only remotes whose URL identifies `saravejo/healdan`.
Setup does not rewrite history or remove other remotes.
For a ZIP installation, configure Git identity, review the initialized files,
and make the initial local commit before creating a task. Setup never commits
unreviewed files from an existing folder automatically.

The Git common directory and external state identify the same vault. Worktrees
share the binding. Specify `--state PATH` when first choosing a custom state
directory. Subsequent commands discover the bound state when `--state` is
omitted.

For an existing installation, first prepare the new controller with
`python3 scripts/setup.py --prepare-only` and use the printed controller path
to run `healdan --vault PATH --state STATE state adopt`. Review the reported
paths and evidence of ownership. On macOS, use the `legacy_launchagents` preview
to identify the vault's old jobs. For each loaded job, run
`launchctl bootout "gui/$(id -u)/LABEL"`. Remove the corresponding installed
plist shown in the preview so the job cannot reload at login. Repeat the
command with `--confirm DIGEST` using the preview's `confirmation` value,
then run setup. Build activation also checks for legacy jobs on already
bound vaults.
For a vault or state that has moved, use `state rebind` at the new location
with the same preview and confirmation steps. Supply `--state` if the state
directory moved. Preserve both original binding markers during the move. On
macOS, unload the vault's installed LaunchAgents and remove their installed
plist files before reassociation. Recheck readiness at the new paths before
activating the schedules again.

Use `healdan --vault PATH build identity` to see the active version and digest.
To switch builds, run `healdan build prepare WHEEL`, then use the reported digest
with `healdan --vault PATH build activate DIGEST`. Use the previous prepared
digest to return to an earlier build. Activation verifies the target and its
compatibility with the vault's persisted formats before changing the selection.

Configure the external JSON file printed by setup, or use interactive setup.
Provide Git name/email, a human signing identity and public/private SSH key,
operational and offline recovery age recipients, an external age identity,
authorized storage roots, and backup destinations and interval. Configure a
separate backup SSH key, identity and allowed-signers file for scheduled receipts.
Keys must stay outside the vault, task proposals, and native Claude profiles.
The SSH allowed-signers file is external controller policy.

Authenticate the dedicated profile as instructed by setup:
`CLAUDE_CONFIG_DIR='<external profile>' claude auth login`.
The profile keeps `cleanupPeriodDays=30`. Never test native cleanup on your
ordinary Claude profile. Task profiles are separate from the authentication
profile and from one another; the controller stages only required credentials.

Run `healdan doctor`. It reports missing dependencies, incomplete configuration,
recovery evidence, runtime version, and platform gates. A healthy Python test
suite does not establish authenticated Claude or native recovery capability.
Use `healdan session probe` on macOS for OS denial checks, then perform the
trials in `docs/acceptance.md`. Record evidence with signed trial receipts.

Open the repository directory in Obsidian. No community plugin is required.
Use an external shell for controller commands, not the sandboxed agent shell.
Only activate schedules after configuration and verified recovery using
`healdan maintenance schedule --activate`. Each scheduled run checks the
readiness of the active build. Schedules use local calendar time. Deadlines use
elapsed UTC time. The daily job runs retention before backup.
Use the disposable procedure in [native trials](native-trials.md#launchd) to
collect launchd evidence before activating a production schedule.

Troubleshooting: check `healdan status`, `healdan doctor`, the external state
path, executable PATH, and the run receipt. An inaccessible backup destination
is pending work. A failed sandbox probe blocks launch. Never disable a gate
to make setup appear complete. Development tests can run on Windows/Linux;
the supported production launcher is macOS.
