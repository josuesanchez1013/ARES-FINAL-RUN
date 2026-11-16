# Changelog — ARES

All notable changes to ARES are recorded here. This is a **living document**: every change, fix,
new feature, refactor, doc update, or decision gets an entry. Newest first.

Format: loosely based on [Keep a Changelog](https://keepachangelog.com/). Categories:
**Added / Changed / Fixed / Removed / Deprecated / Security / Docs / Infra**.
Dates are YYYY-MM-DD. (Development is AI-assisted; see README.)

---

## [Unreleased]

### Changed
- **Repository cleaned for sharing (2026-11-16):** personal names, organisation names, internal host
  names, account names and program details were removed from the docs, code comments, defaults and
  sample scan files. Internal hosts are now `*.example.internal` placeholders. **Effect on use:** real
  (non-mock) runs must set `GENESIS_API_URL` and `MCP_SERVER_URL` in `.env`; there is no built-in host.
- `README.md` rewritten for the current feature set (UI v2, STIG import, multi-platform targets).

### Security
- **`sudo` no longer hides a state-changing command (2026-11-15, D-032).** Found in the first real VM
  test: `security/command_validator.py` only matched a blocked command at the start of the line or after
  `|`, `;`, `&`, so `sudo systemctl stop sshd` and `sudo rm -rf ...` passed and ran. The match now also
  covers any chain of wrappers (`sudo`, `env`, `nohup`, `timeout`, `xargs`, ...), absolute paths
  (`/bin/rm`), `sh -c '...'`, `$( )`, backticks, subshells, new lines and `find -exec`. Read-only checks
  such as `sudo grep rm /etc/x` still pass. A second lab pass found more forms, also closed: leading
  `VAR=value`, redirections in front of the command, `eval`, `then` / `do` / `else`, quoted names
  (`"rm"`, `r\\m`) and command names built from a variable or substitution (`$cmd x`). 78 new tests in
  `tests/test_platforms.py`.

### Fixed
- **Windows host (2026-11-15):** scan state file replace retried when Windows has the file open; state
  files read and written as UTF-8; tests that need a POSIX shell are skipped where there is none.
- `mount | grep nodev` (a listing) is no longer refused; only `mount` with options or a path is.
- Read-only checks taken from the real OL9 and Ubuntu 22.04 STIG text that were wrongly refused now pass:
  `sudo fdisk -l`, and redirections written with a space (`2> /dev/null`).

### Tested
- **First lab validation (2026-11-15, I-013 partly closed):** on a Windows 11 PC with an Oracle Linux
  8.10 VirtualBox VM. The October 2026 DISA SRG/STIG Library Compilation imported cleanly (399 documents,
  5 s, no errors) plus the OL8 and RHEL 8 SCAP 1.3 benchmarks; discovery suggested Oracle Linux 8 STIG
  V2R10; an `oscap` scan (160 fail / 110 pass / 25 n/a) converted to a checklist with matching counts;
  read-only checks ran over SSH with sudo. Not yet run: the AI agents (needs a Genesis token), RHEL 9,
  Ubuntu, Windows over WinRM, Solaris, network devices.
- **Second lab pass (2026-11-15):** Oracle Linux 9.8 and Ubuntu 22.04.5 VMs. Discovery suggested Oracle
  Linux 9 STIG V1R7 and Canonical Ubuntu 22.04 LTS STIG V2R10; `oscap` scans with the DISA SCAP
  benchmarks (OL9 137 pass / 240 fail / 21 n/a; Ubuntu 44 / 115 / 2) converted with matching counts.
- **Third lab pass (2026-11-15):** Windows Server 2022 Datacenter Evaluation VM over WinRM HTTPS with a
  validated self-signed certificate and NTLM. Connection test and discovery worked and suggested
  Microsoft Windows Server 2022 STIG V2R11; six read-only PowerShell checks ran; seven state-changing
  commands were refused by the PowerShell rules. Lab note: a local administrator needs
  `LocalAccountTokenFilterPolicy=1` and membership of Remote Management Users for WinRM.
- **Still not run:** the AI agents against any of these hosts (needs a Genesis token), Solaris, AIX,
  HP-UX, macOS, ESXi, live network devices.

### Added
- **Multi-platform targets (2026-11-14, D-028..D-031):** ARES can run its read-only checks on Linux
  (any distribution), Solaris, AIX, HP-UX, macOS, ESXi, Windows and network devices, not only the one
  RHEL 8 host. Runs on the default target are unchanged.
  - `stig_library/platforms.py`: platform profiles (shell, connection types, sudo) and a classifier that
    maps any imported STIG to a platform. The STIG library page shows the platform.
  - `cli_executor/backends.py`: connection types `ssh` (existing Fabric path, now for any UNIX),
    `local` (the ARES host itself), `winrm` (Windows PowerShell, optional `pywinrm`, certificate always
    verified) and `config` (a saved network-device configuration answered with `show running-config`
    filters). `cli_executor/target_context.py` is the single path that validates, runs and audit-logs.
  - `security/platform_validators.py`: the POSIX blocklist extended for Solaris/AIX/HP-UX/macOS/ESXi and
    more Linux tooling; an **allowlist** validator for PowerShell (read-only verbs and tools, script
    blocks and sub-expressions checked, method calls allowlisted); an allowlist for network CLIs (show
    commands and output filters only).
  - `ares_api/targets.py` + **Targets** page: save targets (no passwords stored, only the name of an
    environment variable or an SSH key path), test the connection, upload a device configuration, and
    **find matching STIGs** (reads the OS and common software from the target and lists the imported
    STIGs that apply). The Run form has a **Target** picker; the choice is recorded on the run and
    written into CKL/CKLB exports.
  - `ares_api/prompts.py`: runs on a saved target give the agents a platform-aware copy of the prompt
    and tool definition (written to the run folder). `genesis_agents/*.txt` and
    `ui/orchestrator_runner.py` are not edited.
  - **More scan inputs:** CKLB checklists and SCC / OpenSCAP XCCDF results (`.xml`) are accepted on
    the Run form and converted to CKL (`stig_library/convert.py`); rules the SCAP content does not
    cover are listed as Not_Reviewed from the imported manual STIG.
  - **OpenSCAP scans** (`ares_api/scap.py`, on the Targets page): run an imported SCAP benchmark with
    `oscap` on the ARES host or `oscap-ssh` against an SSH target, keep the results, download them as
    CKL or use them directly as a scan file in a run. OpenSCAP is not bundled.
  - Tests: `tests/test_platforms.py` (106) and `tests/test_targets.py` (50). Offline suite: 439 passed /
    4 skipped / 18 deselected.
- **STIG import (2026-11-14, D-025..D-027):** import the latest STIGs from DoD Cyber Exchange and assess
  against any of them. Nothing about how ARES is built, started or shipped changed.
  - New `stig_library/` package: parses DISA XCCDF "Manual" benchmarks and SCAP 1.2/1.3 data streams
    (standard library only, DOCTYPE/entity documents refused), walks uploads in memory including the
    STIG Library compilation zip and the zips nested inside it (size, count and depth limits), and keeps
    every release under `data/stig_library/` (git-ignored) with a change report between releases.
  - API: `GET /api/stigs`, `POST /api/stigs/import`, `GET /api/stigs/{id}` (rules + changes since the
    previous release), `DELETE /api/stigs/{id}`. `POST /api/runs` takes an optional `stig` field
    (`auto` by default, `builtin`, or a library entry id); the choice is recorded on the run.
  - `auto` reads the STIG id and release from the scan files (CKL `STIG_INFO`, CKLB, CSV
    `Benchmark ID`) and uses the matching imported release; with no match the run uses the built-in
    RHEL 8 content exactly as before and shows a note saying so.
  - The pipeline gets the chosen content through `get_stig_loader()` (new
    `set_stig_loader_override` in `genesis_integration/stig_loader.py`); `ui/orchestrator_runner.py`
    is not edited. CKL/CKLB exports name the run's STIG and release.
  - UI v2: new **STIG library** page (upload, search, release details and changes, remove) and a
    **STIG content** picker on the Run form; the run header shows the STIG used. Rebuilt `frontend/dist`.
  - `tests/test_stig_library.py` (27 offline tests). Offline suite at that point: 283 passed / 4 skipped / 18 deselected.
- **UI v2 (2026-11-13):** FastAPI service `ares_api/` and React app `frontend/` (built app committed in
  `frontend/dist`), running alongside the Streamlit UI, which is unchanged. Reuses the existing pipeline
  through `ui/orchestrator_runner.execute_next_step`; `ui/orchestrator_runner.py` is not edited. Adds
  `tests/test_api.py` (24 offline tests), `scripts/verify_rhel.sh`, `scripts/smoke.py`,
  `scripts/check_contrast.py`, `docs/UI_VISUAL_STANDARD.md`, `requirements-api.txt`,
  `requirements-dev.txt`, `README_UI_V2.md`. Offline suite: 256 passed / 4 skipped / 18 deselected.
- UI v2 integration fixes made while merging:
  - `.gitignore`: exception `!frontend/dist/` (the general `dist/` rule hid the built UI, so a fresh
    clone served 404); ignore `frontend/node_modules/` and `.venv-verify-*/`.
  - `ares_api/main.py` loads `.env` like the Streamlit app does (the service previously saw no token,
    agent IDs or `MCP_SERVER_URL` from `.env`).
  - `scripts/verify_rhel.sh` installs `requirements.txt` as well, since it runs the whole `tests/` folder.
  - `.env.example` documents `MCP_SERVER_URL` and the `ARES_*` UI v2 settings.

### Security
- **UI v2 will not send scans to a default MCP server (D-021):** a production run with no
  `MCP_SERVER_URL` now fails at the model check. Before, the orchestrator's built-in default (the retired
  OpenShift server, D-004) would have received the uploaded scan files. Regression test added.

### Added (earlier)
- Knowledge base under `docs/` (MASTER_CONTEXT, ARCHITECTURE, ROADMAP, DECISIONS, TESTING,
  PACKAGING_AND_NETWORKING, DEVELOPMENT) and rewritten README for the post-competition product.
- `pytest.ini` scoping collection to `tests/` and registering `live`/`integration` markers
  (deselected by default).
- `tests/test_stig_loader.py` (real offline tests) and an awk-regex regression class in
  `tests/test_cli_executor.py` (preserving the intent of the old ad-hoc root scripts).
- `pytest-timeout` dev dependency.
- This `CHANGELOG.md` as a live doc; rules/skills now mandate updating ROADMAP + CHANGELOG + DECISIONS
  every batch (self-tracking loop, minimal human input).

### Fixed
- **pytest collection hang (I-003):** bare `pytest` no longer hangs; suite runs offline in ~6s
  (232 passed / 4 skipped / 18 deselected). Root cause: ad-hoc root `test_*.py` scripts ran code at
  import during full-rootdir discovery.
- **Stale tests** referencing the removed `strict_mode`/whitelist validator API updated to the current
  blacklist-only API (deprecated strict-mode test class marked skipped).

### Security
- **CommandValidator gap (I-005):** `iptables -F` and `firewall-cmd --add-port=...` (and similar) were
  silently allowed. Patterns were compiled in original case but matched against a lower-cased command,
  and the trailing boundary broke patterns ending in `-`. Fixed with case-insensitive patterns + boundary
  fix + regression tests. Validator remains blacklist-only by design (no whitelist).

### Removed
- Archived-and-superseded docs deleted from the tree (all preserved in git-ignored `docs/history/` +
  backup branches): root status docs (`DEMO_DEPLOYMENT_SUMMARY`, `DETERMINATION_AGENT_READY`,
  `JUDGE_DEMO_INSTRUCTIONS`, `REPORTING_AGENT_STATUS`, `STEPS_1_AND_2_COMPLETE`, `DEPLOYMENT_GUIDE_V2`,
  `TESTING_AND_FIXES_COMPLETE`), the deprecated `ARES-PROJECT-CONTEXT.md` and `team-design-doc.md`,
  several point-in-time `docs/*` docs, and the dead `genesis_integration/stig_check_text_loader.py`.

### Changed
- Untracked `.streamlit/` (now git-ignored; config kept locally). Renamed `docs/architecture.md` ->
  `docs/ARCHITECTURE.md` (casing) via `git mv`.

### Docs
- Established that public docs stay broad about AI-assisted development; the detailed AI operating model
  lives only in the git-ignored `.clinerules/` and skills (D-019).
- Added mandatory living-doc maintenance + self-tracking loop to rules/skills (D-020): every batch
  updates ROADMAP + CHANGELOG + DECISIONS + affected docs.

### Infra
- Backup refs before Phase 1 cleanup: `backup/pre-phase1-cleanup-20260817` (+tag) and
  `backup/full-snapshot-20260817` (full tracked+untracked snapshot).
- Preserved the pre-existing `stash@{0}` (competition-era UI experiments) as branch
  `archive/stash-ui-improvements-20260817`, then cleared the stash.
- Recreated + populated `docs/history/` (20 archived files) as the local-only reference archive.

---

> Older history (competition era, July 2026) is captured in git history and the archived docs under
> `docs/history/` (git-ignored, local only).
