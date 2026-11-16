# ARES — Decision Log

> **Status:** Living log of material decisions (what + why). Append new entries at the top.
> Last updated: 2026-11-14.

---

## 2026-11-15 — Lab testing fixes (Josue)

- **D-032 — The shared command validator was changed, not only wrapped.** `sudo <blocked command>` passed
  the original blocklist and ran on the test VM. The fix is in `security/command_validator.py` itself so
  the default RHEL 8 path is protected too. *Why:* this is the one place a "keep everything the same"
  rule loses to safety; checks on hosts must be read-only. *Still true:* it is a blocklist, so a command
  nobody listed can pass. An allowlist for POSIX (like the PowerShell one) is the stronger follow-up.

---

## 2026-11-14 — Multi-platform targets (Josue)

- **D-028 — Targets are saved records; the default target is the old behaviour.** A run with no target
  chosen uses `ARES_SSH_*` and the shipped prompts exactly as before. *Why:* nothing existing may change.
- **D-029 — No secrets at rest.** A target stores an SSH key path or the *name* of an environment
  variable holding the password, never the password. *Why:* `data/targets/targets.json` is a plain file.
- **D-030 — Allowlists for PowerShell and network CLIs.** New platforms get allowlist validators; the
  POSIX blocklist is kept (and extended) because the existing RHEL flow depends on it. *Why:* a blocklist
  cannot keep up with PowerShell; moving POSIX to an allowlist is a separate, riskier change.
- **D-031 — Network devices are assessed from a saved configuration first.** Live SSH to a device is
  possible (`ssh` backend) but the config file is the default. *Why:* no credentials or change risk, and
  most network STIG checks read the configuration.

### Known issues logged with multi-platform targets (not yet decisions)
- **I-013 —** WinRM, SSH to Solaris/AIX/HP-UX/macOS/ESXi, live network devices and real OpenSCAP runs
  are covered by offline tests with stand-ins only; none has been run against a real system yet.
- **I-014 —** Windows security policy that is not in the registry (user rights, some account policy)
  needs `secedit /export`, which writes a file and is blocked; those rules go to manual review.
- **I-015 —** The mock pipeline does not contact the target. The Streamlit UI has no target picker.
- **I-016 —** Discovery recognises the OS and a short list of common software; it is a suggestion, not
  an inventory.
- I-010 (RHEL-only prompts) and I-011 (SCAP not executed) are resolved by this change.

---

## 2026-11-14 — Import the latest STIGs (Josue)

- **D-025 — Add STIG import without changing anything else.** How ARES is built, started and shipped
  stays the same; the import is additive. Runs that do not use it behave exactly as before.
  *Why:* Josue's direction: "everything the same, but add the ability to import the latest STIGs".
- **D-026 — Import DISA XCCDF directly into a versioned library; keep the built-in RHEL 8 content as the
  fallback.** Every release is kept under `data/stig_library/` (git-ignored, like `data/runs/`). A run
  picks content by matching the STIG named in its scan files (default), or by an explicit choice.
  *Why:* every DISA STIG uses the same XCCDF format, so one parser covers all of them; the Markdown
  conversion (`scripts/convert_stig_to_markdown.py`) was lossy and one-STIG-at-a-time.
- **D-027 — STIGs are downloaded by a person and uploaded; ARES does not fetch from DoD Cyber Exchange.**
  *Why:* lab networks are offline and parts of Cyber Exchange need a CAC; there is no supported API.

### Known issues logged with STIG import (not yet decisions)
- **I-010 —** Agent prompts still describe a RHEL 8 target over SSH. Any imported STIG can be matched and
  its Check Text is passed to the agents, but automated validation is only meaningful for Linux targets
  reachable over SSH until other execution backends exist.
- **I-011 —** SCAP content is imported and flagged ("automated" rules) but not executed; running it with
  OpenSCAP (allowed in the lab) is the next step.
- **I-012 —** A run whose scans name more than one STIG uses all matched releases, but CKL/CKLB exports
  still write one `iSTIG` block. The Streamlit UI does not offer the STIG picker (it uses the built-in
  content), and the orchestrator's own step-6 CKL still names `RHEL_8_STIG`.

---

## 2026-11-13 — UI v2 merged alongside the Streamlit UI

- **D-021 — UI v2 requires an explicit `MCP_SERVER_URL`.** A UI v2 production run with the variable
  unset fails at the model check. *Why:* the orchestrator's built-in default is the retired OpenShift
  server (D-004); scans must not be sent there by accident. The orchestrator's own default is left as is
  until the Phase 2 refactor (I-006).
- **D-022 — Mock mode stays for now, for UI v2 only as a test/demo path.** `ARES_USE_MOCK=true` is what
  lets `tests/test_api.py`, `scripts/smoke.py` and `scripts/verify_rhel.sh` run offline. *Why:* D-007
  (remove mock mode) is deferred to Phase 2 (D-P1e); when it lands, UI v2's `MockPipeline` should be
  replaced with recorded-response fixtures per `docs/TESTING.md`. **Needs the project lead's confirmation.**
- **D-023 — The built frontend (`frontend/dist`) is committed.** *Why:* the lab server host has no
  Node.js; `.gitignore` carries an exception for it. Rebuild and commit after any frontend change.
- **D-024 — UI v2 and the Streamlit UI coexist.** `ui/` is unchanged; UI v2 calls the same orchestrator
  through a bridge. Retiring Streamlit is a later decision.

### Known issues logged with UI v2 (not yet decisions)
- **I-006 —** `ui/orchestrator_runner.py` still defaults `MCP_SERVER_URL` to the retired OpenShift host
  and calls it with `verify=False` (see also I-004). The Streamlit UI is still exposed to this.
- **I-007 —** UI v2 has no sign-in; review decisions are not attributed to a person.
- **I-008 —** UI v2 masks CKL uploads (host, IP, MAC, FQDN) but passes CSV uploads through unchanged.
- **I-009 —** No frontend component tests; CKLB export not yet opened in STIG Viewer 3; exports are not
  byte-identical to the Streamlit exports (see `README_UI_V2.md`).

---

## 2026-08-16 — Post-competition direction set (this session)

- **D-001 — ARES continues as a funded internal product.** Competition over (top-10/50+, not 1st).
  Now targeting classified-AI-lab testing, ~Nov 2026, to augment PreSTIGe. *Why:* strong reception +
  funded hours from an AI-lab manager.
- **D-002 — AI-assisted development model.** Windsurf assisted during the competition; the project lead switched to
  Cline to accelerate delivery and free time for other priorities. The project lead ~<=8 hrs/week (review/test).
  *Why:* the project lead's time goes to higher-priority projects. (Operating specifics kept in the
  git-ignored `.clinerules/`.)
- **D-003 — Move from Genesis-built agents to LOCAL Python agents (all 4, incl. Parser).** *Why:* the
  lab uses its own GPU infra, not Genesis; we'd have to rebuild anyway. Swap LLM base URL/model IDs by config.
- **D-004 — MCP server runs LOCALLY, packaged with the app.** Retire OpenShift deployment.
  *Why:* removes the biggest competition blocker; needed for packaged lab install.
- **D-005 — STIG content via a local STIG Content Provider, not Genesis RAG.** *Why:* local-first;
  already loading RHEL 8 STIG text from markdown.
- **D-006 — Introduce 3 abstractions: LLM Provider, Execution Backend, STIG Content Provider.** *Why:*
  provider/transport/content agnosticism for lab portability + multi-OS + local/remote execution.
- **D-007 — Remove mock mode/data entirely.** *Why:* never used; only real agents/data going forward.
- **D-008 — Three product modes:** `compare_scans` (display "Compare Scans"), `full_spot_check`
  ("Full Spot Check"), `version_delta` ("Version Delta"). *Why:* reconciling two tool outputs alone is
  not enough to augment PreSTIGe.
- **D-009 — Mode naming:** chose "Compare Scans" (over "Dual-Scan Reconcile"), "Full Spot Check",
  "Version Delta" (over "Update STIG"). *Why:* clarity/brevity per the project lead.
- **D-010 — Support BOTH local-on-target execution AND remote (SSH/WinRM/container)** behind the
  Execution Backend. *Why:* packaged lab install may run on-box (no SSH) or scan remote targets.
- **D-011 — Feature scope:** MUST/SHOULD/COULD/LATER set (see ROADMAP). CKLB + Nessus -> LATER (not
  worth early time). *Why:* focus on highest-value augmentation first.
- **D-012 — Combine/drop:** standalone Spot Check Agent -> Full Spot Check mode; Fixing Agent -> POA&M
  generation; version-migration detector -> Version Delta mode.
- **D-013 — Branching:** `main` = production (reviewed merges only), `dev` = integration, short-lived
  `feature/*` branches per work item. *Why:* clean, reviewable async checkpoints for solo dev.
- **D-014 — Docs strategy:** lean living set in `docs/` (MASTER_CONTEXT, ARCHITECTURE, ROADMAP,
  DECISIONS, TESTING, PACKAGING_AND_NETWORKING, DEVELOPMENT) + rewritten README; archive old/dated docs
  to git-ignored `docs/history/`; deprecate `ARES-PROJECT-CONTEXT.md`; restructure `team-design-doc.md`.
- **D-015 — Cline rules in `.clinerules/` (full set); `.windsurf/` left untouched** so the project lead's Windsurf
  agent keeps working. Skills live under the agent skills dir.
- **D-016 — Observability is foundational** (run artifacts + LLM traces + golden dataset + eval harness).
  *Why:* enables reproducible, reviewable, well-tested development given AI-assisted code generation.
- **D-018 — All modes support a secondary-LLM validation** for Not_Reviewed / net-new / uncertain rules
  (Full Spot Check and Version Delta especially), so every rule gets multiple independent findings;
  disagreements are resolved. *Why:* maximize coverage + confidence per rule.
- **D-019 — Privacy of AI-operating details:** `.clinerules/`, skills, `docs/history/`, and `.streamlit/`
  are git-ignored. Public docs mention only that development is AI-assisted (Windsurf -> Cline); they do
  NOT detail the autonomous operating model. *Why:* keep the operating model internal to the AI tooling.
- **D-020 — Living-doc maintenance is mandatory + self-tracking.** `docs/ROADMAP.md` is the authoritative
  progress tracker and `CHANGELOG.md` records every change; rules/skills require updating ROADMAP +
  CHANGELOG + DECISIONS (+ affected docs) in the SAME batch as any change. *Why:* the project must be
  trackable and self-driving with minimal human input; a reviewer reading ROADMAP+CHANGELOG+DECISIONS
  should always know what changed and what's next.
- **D-017 — Phase order is foundation-first** (0: knowledge/rules; 1: cleanup; 2: local refactor;
  3: complete Compare Scans; 4: multi-target; 5: modes; 6: extended; 7: packaging).

### Phase 1 consolidation investigation (2026-08-17)
Investigated the duplicate/dead files before deleting. Findings + decisions:
- **`stig_check_text_loader.py` (XML) vs `stig_loader.py` (markdown):** KEEP `stig_loader.py`. The XML
  loader was explicitly `# REMOVED` per the old TESTING doc and is imported nowhere in live code; the
  markdown loader is what `ui/orchestrator_runner.py` actually imports/uses. -> delete XML loader (D-P1a).
- **`comparison_script.py` vs `comparison_script_enhanced.py`:** BOTH are imported by the live orchestrator
  (`compare_findings` at ~line 37; `run_comparison` at ~line 955). This pair is entangled with the
  25-vs-41 comparison bug (I-001). DEFER consolidation to Phase 3 (bug fix) so we don't destroy diagnostic
  evidence. Keep both for now; pick the winner while fixing the bug (D-P1b).
- **Gap-coverage prompt variants:** the ACTIVE prompt is `gap_coverage_agent_prompt_NO_RAG.txt` (used at
  orchestrator ~line 669), NOT the base file. `_BALANCED`/`_SIMPLE`/base are experiments. DEFER prompt
  consolidation to Phase 2 (agent rebuild) — archive experiments then, choosing the canonical prompt as we
  rebuild agents local-first (D-P1c).
- **`workflow_orchestrator.py` (stub):** imported by `genesis_integration/__init__.py` and
  `scripts/run_full_workflow.py`, so it can't be deleted without editing those. It's a dead TODO stub;
  DEFER removal to Phase 2 when the orchestration layer is rebuilt (D-P1d).
- **Mock mode/data (`ui/mock_data.py`, `use_mock`):** deeply wired into the 1,457-line orchestrator.
  Removing it safely = editing live orchestrator code + verifying. DEFER to Phase 2 refactor (D-P1e).
- **Rationale:** Phase 1 does only SAFE, non-code-breaking cleanup (archive+delete stale docs, move/annotate
  ad-hoc tests, gitignore hygiene, casing). Code-entangled consolidations move to the phase that already
  rewrites that code, so the repo never breaks and diagnostic evidence is preserved. All originals are in
  `docs/history/` and/or the `backup/full-snapshot-20260817` branch before any deletion.
- **D-P1f — Branch reconciliation, "current branch wins":** compared `feature/initial-agent-flow`
  (now committed) against `origin/dev` + `feature/live-pipeline-ui`. Current branch is the newer, fuller
  demo-ready app (orchestrator 1409 lines w/ live logs, execution lock, real determination/reporting);
  `origin/dev`'s live-pipeline-ui is an earlier 844-line version without `live_logs.py`. DECISION: reconcile
  by making `dev` match the current cleaned branch (discard dev's divergent/older UI). The only notable
  dev-side improvement is `export.py` using the shared `CKLGenerator` — optionally re-apply later. Stale
  branches (`cli-mcp-tool`, `streamlit-ui-complete`, `cli-executor`, `feature/live-pipeline-ui`) are fully
  superseded and safe to delete after the merge (all preserved on the remote until then).

---

## Known issues logged (not yet decisions — see ROADMAP)

- **I-001 — Comparison disagreement-count bug:** 25 vs 41 hand-counted on the RHEL 8 test files. Undiagnosed.
- **I-002 — Reporting agent output is hard-coded/fake.** Must be built for real.
- **I-003 — pytest collection hangs** (import-time side effect). FIXED 2026-08-17: added `pytest.ini`
  scoping collection to `tests/` + registered `live`/`integration` markers (deselected by default);
  converted the two ad-hoc root `test_*.py` scripts (which ran code at import) into real offline tests.
- **I-004 — SSL verification disabled by default** when no cert set. Make secure-by-default in prod.
- **I-005 — CommandValidator missed dangerous commands** (`iptables -F`, `firewall-cmd --add-port=...`):
  patterns compiled in original case but matched against a lower-cased command, and the trailing boundary
  broke patterns ending in `-`. FIXED 2026-08-17 (case-insensitive patterns + boundary fix + regression
  tests). Also fixed stale tests referencing the removed `strict_mode`/whitelist API.

---

## Pending decisions (need the project lead / AI-lab manager input)

- **P-001 — OS/software priority after RHEL 8** (ask AI-lab manager).
- **P-002 — Classified-lab packaging/networking constraints** (outbound access, transports, install method).
- **P-003 — Lab LLM API shape + available models** (for LLM Provider `lab` config).
- **P-004 — Final target package layout** (to be proposed in Phase 2).
