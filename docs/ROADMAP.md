# ARES — Roadmap, Tasks & Status

> **Status:** Living planning doc. Kept current as work proceeds: mark tasks in-progress/done, note next
> steps, flag blockers. The project lead reviews to steer priorities. Last updated: 2026-11-13.
> Timeline target: development "done" by ~**November 2026**; the project lead ~<=8 hrs/week (review/test only).

---

## Current status snapshot

- **Phase:** Phase 0 (Knowledge capture + rules/skills) — IN PROGRESS.
- **Branch:** `feature/initial-agent-flow` (to be reconciled with `dev` in Phase 1).
- **Biggest known issues:** comparison disagreement-count bug (~25 vs ~40); Reporting agent is faked;
  pytest collection hangs; messy repo/branches; no observability.
- **Pending inputs from the project lead:** (a) OS/software priority after RHEL 8; (b) classified-lab
  packaging/networking constraints. (Ask AI-lab manager.)

---

### Multi-platform targets  [BUILT 2026-11-14 — pending the project lead review, NOT yet run on real systems]
- [x] Platform profiles, connection backends (ssh / local / winrm / saved config), per-platform safety rules.
- [x] Targets page + API, target picker on the Run form, platform-aware prompts, discovery of matching STIGs.
- [x] CKLB and SCC/OpenSCAP results accepted as scan inputs; OpenSCAP scans from imported SCAP content.
- [x] 2026-11-15 first lab validation on an Oracle Linux 8.10 VM: real DISA library import (399 documents),
      discovery, OpenSCAP results as input, read-only checks over SSH. Found and fixed the `sudo` bypass (D-032).
- [x] 2026-11-15 also validated: Oracle Linux 9.8, Ubuntu 22.04 (SSH, OpenSCAP) and Windows Server 2022
      (WinRM HTTPS). Remaining for I-013: real agent runs with a Genesis token, Solaris, a live network device.
- [ ] POSIX command allowlist to replace the blocklist (follow-up to D-032).
- [ ] Lab validation on real systems, one platform at a time (I-013): RHEL 9 / Ubuntu, Windows Server over
      WinRM, Solaris, a Cisco configuration, and an OpenSCAP scan. Record per-platform accuracy.
- [ ] Windows security-policy rules that need `secedit` (I-014).
- [ ] Per-STIG exports for multi-STIG scans; target and STIG pickers in the Streamlit UI (I-012, I-015).

### STIG import  [BUILT 2026-11-14 — pending the project lead review]
- [x] Import DISA STIG zips, SCAP benchmark zips, the full STIG Library compilation zip, or one XCCDF .xml
      (`stig_library/`, `/api/stigs*`, STIG library page). Every release kept; change report per release.
- [x] Runs match the STIG named in the scan files to the library, or use an explicit choice; built-in
      RHEL 8 content stays the fallback (D-025..D-027).
- [ ] Import the real current DISA library zip on a lab host and spot-check a few STIGs in the UI.
- [x] Run imported SCAP content with OpenSCAP (I-011): see Multi-platform targets.
- [ ] Per-STIG CKL/CKLB export for multi-STIG scans; STIG picker in the Streamlit UI (I-012).
- [x] Platform-aware agent prompts and execution backends beyond Linux/SSH (I-010).

### UI v2 (React + FastAPI)  [MERGED 2026-11-13 — pending the project lead review]
- [x] `ares_api/` + `frontend/` added alongside the Streamlit UI; pipeline reused via a bridge.
- [x] Integration tested on the combined tree: offline suite 256 passed / 4 skipped / 18 deselected
      (Python 3.11 and 3.12), mock-mode smoke test, frontend rebuild, contrast check, fresh-clone start.
- [x] Integration fixes: `.gitignore` exception for `frontend/dist`, `.env` loading in the service,
      `verify_rhel.sh` dependencies, explicit `MCP_SERVER_URL` required (D-021).
- [ ] Run `scripts/verify_rhel.sh` on the RHEL 8 / RHEL 9 lab hosts.
- [ ] Live run against a real MCP server, LLM and target (not possible offline).
- [ ] Open items I-006..I-009 (see DECISIONS): orchestrator default MCP URL + `verify=False`, sign-in,
      CSV masking, frontend component tests, CKLB check in STIG Viewer 3.
- [ ] The project lead to confirm D-022 (mock mode kept for UI v2 tests until Phase 2).

---

## Phase plan (foundation-first)

### Phase 0 — Knowledge capture & AI operating setup  [COMPLETE — pending the project lead final review]
- [x] `.clinerules/` (00-project-context … 06-autonomous-operation) — git-ignored.
- [x] Knowledge base docs: MASTER_CONTEXT, ARCHITECTURE, ROADMAP, DECISIONS, TESTING,
  PACKAGING_AND_NETWORKING, DEVELOPMENT + rewritten README.
- [x] Skills files under the agent skills dir (9 `ares-*` skills).
- [x] Archive old/dated docs to `docs/history/` (copies made; originals deleted in Phase 1).
- [x] Applied the project lead's corrections: RHEL-8 stats (41 disagreements / 20 gaps), 1,000-2,000+ systems,
  automated-vs-manual in Compare Scans, "completed scan may have Not_Reviewed," secondary-LLM validation,
  privacy of AI-operating details, git-ignore of `.clinerules`/`docs/history`/`.streamlit`.
- **Exit criteria:** the project lead reviews & approves the knowledge base + rules + skills.

### Phase 1 — Repo cleanup & branch reconciliation  [IN PROGRESS]
- [x] Backup: `backup/pre-phase1-cleanup-20260817` (+tag) at original HEAD, and
      `backup/full-snapshot-20260817` (full tracked+untracked snapshot). Nothing lost.
- [x] Investigate duplicates/dead files; record keep/defer decisions (see DECISIONS D-P1a..e).
- [x] Convert ad-hoc root tests into real offline tests: `tests/test_stig_loader.py` (new) +
      awk-regex regression class in `tests/test_cli_executor.py`; deleted root `test_stig_loader.py`,
      `test_validator.py` (backed up in snapshot).
- [x] Fix pytest collection hang (I-003): add `pytest.ini` scoping to `tests/`, register `live`/
      `integration` markers, deselect them by default. Bare `pytest` now runs fast + offline.
- [x] Fix stale tests referencing removed `strict_mode` API (validator/executor blacklist-only).
- [x] Fix real validator security bug (I-005): case-insensitive + boundary fix so `iptables -F` /
      `firewall-cmd --add-port=...` are blocked. Offline suite: 232 passed, 4 skipped, 18 deselected.
- [x] Add `pytest-timeout` to requirements.
- [x] Per-item keep/drop review of all uncommitted/stashed items (see CHANGELOG + this list).
- [x] Recreated + populated `docs/history/` archive (20 files) before any deletion; also preserved
      the `stash@{0}` UI work as branch `archive/stash-ui-improvements-20260817`, then dropped the stash.
- [x] Deleted archived-and-superseded docs (root status docs + `ARES-PROJECT-CONTEXT.md`,
      `team-design-doc.md`, `TESTING_AND_FIXES_COMPLETE.md`, several `docs/*` point-in-time docs) and the
      dead `stig_check_text_loader.py`. All recoverable from `docs/history/` + backup branches.
- [x] `git rm --cached .streamlit` (untracked, file kept on disk); `git mv` casing fix
      `docs/architecture.md` -> `docs/ARCHITECTURE.md`. Offline suite still green (232/4/18).
- [ ] Untangle remaining working tree + the `cline checkpoint` commit `39d105c`.  ← needs approval (commits)
- [x] Diff `dev` / `feature/live-pipeline-ui` UI vs current branch (see DECISIONS D-P1f):
      current branch WINS. My orchestrator is 1409 lines (live logs, exec lock, real determination/
      reporting); `origin/dev`'s live-pipeline-ui is an earlier/simpler 844-line version w/o live_logs.
      Discard dev's divergent UI; optionally re-apply dev's minor export.py CKLGenerator refactor later.
- [ ] Commit cleaned baseline; reconcile with `dev`; delete stale branches (`cli-mcp-tool`,
      `streamlit-ui-complete`, `cli-executor`, `live-pipeline-ui`) after diff-confirm.  ← needs approval
- DEFERRED to Phase 2 (code-entangled; see DECISIONS): remove mock mode/data; delete
  `workflow_orchestrator.py` stub; consolidate gap-coverage prompt variants; remove OpenShift-era
  `scripts/deploy_mcp_v2.ps1`, `scripts/test_execute_command_mcp.py`, `mcp_server/MCP_DEPLOYMENT.md`.
- DEFERRED to Phase 3: consolidate `comparison_script.py` vs `_enhanced.py` (tied to the count bug).
- **Exit criteria:** clean tree, offline `pytest` passes fast, branches sane. Then merge cleaned branch ->
  `dev` as the baseline, and sync `dev` -> `main` so the repo is shareable/followable.

### Phase 2 — Local-first architecture refactor  [NOT STARTED]
- [ ] LLM Provider abstraction (Genesis dev / lab prod via config).
- [ ] Convert all 4 agents to local Python agents (incl. Parser).
- [ ] Local packaged MCP server (retire OpenShift path).
- [ ] Execution Backend abstraction (local + ssh now; winrm/container stubs).
- [ ] STIG Content Provider abstraction.
- [ ] Central config module (LLM endpoint/model, target/transport, STIG source, classification).
- **Exit criteria:** end-to-end Compare Scans runs fully locally with no Genesis-built agents.

### Phase 3 — Complete & trust "Compare Scans"  [NOT STARTED]
- [ ] Root-cause & fix comparison disagreement-count bug (+ regression test on golden data).
- [ ] Build the Reporting Agent for real (metrics, review queue, real generated CKL).
- [ ] Polish Gap Coverage + Determination (multi-command Check Text, confidence, error/review paths).
- [ ] Observability: run artifacts, LLM traces, golden dataset, eval harness.
- [ ] Reproducible end-to-end test on RHEL 8 golden files.

### Phase 4 — Multi-target / multi-STIG support  [NOT STARTED]
- [ ] Generalize STIG content ingestion (any DISA STIG XML -> normalized content).
- [ ] Sub-system/software discovery on a target.
- [ ] Prioritized additional OS/software (per AI-lab manager guidance).
- **Exit criteria:** ARES handles >1 STIG/OS and discovers sub-systems.

### Phase 5 — New modes  [NOT STARTED]
- [ ] Full Spot Check mode.
- [ ] Version Delta mode.
- [ ] Mode selector in UI + shared pipeline components.
- **Exit criteria:** all three modes work end-to-end.

### Phase 6 — Extended features (prioritized subset)  [NOT STARTED]
- [ ] POA&M comment generation (+ remediation guidance folded in).
- [ ] Windows (WinRM) support.
- [ ] OpenSCAP / container scanning.
- [ ] STIG Explainer chatbot (COULD).
- **Exit criteria:** SHOULD features that fit the window are in.

### Phase 7 — Packaging & lab deployment  [NOT STARTED]
- [ ] Self-contained installable app (bundled venv / executable).
- [ ] Security hardening (SSL verify on, secrets, audit completeness, read-only enforcement).
- [ ] Lab install runbook + metrics capture for the director.
- **Exit criteria:** installable, secure build ready for classified-lab testing.

---

## Feature prioritization

**MUST:** local refactor; complete Compare Scans (real reporting + bug fix); observability;
multi-target/STIG + sub-system discovery; Full Spot Check; Version Delta; packaging.

**SHOULD:** POA&M generation (incl. remediation); Windows (WinRM); OpenSCAP/container scanning.

**COULD:** STIG Explainer chatbot.

**LATER/ROADMAP:** CKLB parsing; Nessus parsing; fleet-level intelligence; STIG-to-SPA risk mapper;
multi-system parallel processing; distributed CLI execution; automated scheduling; pattern learning;
compliance tracking over time.

**Combined/dropped:** standalone Spot Check Agent -> Full Spot Check mode; Fixing Agent -> POA&M
generation; STIG version migration detector -> Version Delta mode.

---

## Timeline reality (tracking)

- ~11-12 weeks to November at <=8 hrs/week of the project lead's review/test time.
- Realistic: Phases 0-3 (foundation + truly-working Compare Scans) achievable by Nov.
- Phases 4-5 achievable if scoped (RHEL 8 + one more OS; both new modes for RHEL first).
- Phase 6-7 breadth likely extends past Nov unless narrowed. Keep this section honest for the
  director's metrics.

---

## Open questions / blockers

- [ ] The project lead -> AI-lab manager: which OS/software to prioritize after RHEL 8?
- [ ] The project lead -> AI-lab manager: classified-lab packaging/networking constraints (outbound access,
      allowed transports, install method)?
- [ ] Confirm the lab's LLM API shape + available models (for the LLM Provider `lab` config).

- **Exit criteria:** Compare Scans is correct, reproducible, observable, and truly complete.
