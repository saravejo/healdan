# Setup

Install Python 3.12+, Git, OpenSSH, age, Node.js 22.12+, Claude Code, and
Obsidian from their official distributions. Homebrew is optional.
Install the exact sandbox runtime with
`npm install -g @anthropic-ai/sandbox-runtime@0.0.83`.
The runtime is version checked before use; changing it requires new trials.

Clone the repository or extract a ZIP, then run `python3 scripts/setup.py`.
The bootstrap installs a non-editable controller in an external virtualenv,
prints its executable path, initializes Git for ZIPs, and invokes setup.
Add the printed executable directory to PATH. Paths containing spaces work.
Setup is repeatable and does not overwrite an existing configuration.
It removes only remotes whose URL identifies `saravejo/healdan`.
Setup does not rewrite history or remove other remotes.
For a ZIP installation, configure Git identity, review the initialized files,
and make the initial local commit before creating a task. Setup never commits
unreviewed files from an existing folder automatically.

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
`healdan maintenance schedule`. Schedules use local calendar time; deadlines
use elapsed UTC time. The daily job runs retention before backup.

Troubleshooting: check `healdan status`, `healdan doctor`, the external state
path, executable PATH, and the run receipt. An inaccessible backup destination
is pending work. A failed sandbox probe blocks launch. Never disable a gate
to make setup appear complete. Development tests can run on Windows/Linux;
the supported production launcher is macOS.
