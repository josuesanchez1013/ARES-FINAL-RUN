# ARES — Master Context

> **Status:** Living document. This is the durable "everything about ARES" record and the
> single source of truth for project context, history, and vision. Supersedes the deprecated
> `docs/history/ARES-PROJECT-CONTEXT.md`. Last updated: 2026-08-16.

---

## 1. What ARES is

**ARES = Automated Reconciliation and Evidence for STIGs.**

An AI-powered STIG compliance meta-validation system. It ingests STIG scan outputs, autonomously
runs STIG "Check Text" validation commands on target systems, uses LLM agents to determine ground
truth, and produces a more complete and accurate reconciled STIG checklist (CKL) than any single
scanner produces on its own.

**Key differentiator:** Unlike other AI STIG tools that only analyze reports, ARES *actively
validates* findings by executing read-only CLI commands on the actual systems being assessed.

**STIG = Security Technical Implementation Guide** (DISA) — a standardized set of security rules for
a given OS/software/service. Compliance is checked rule-by-rule; each rule has "Check Text"
(how to verify) and "Fix Text" (how to remediate). Findings statuses: Open, NotAFinding,
Not_Applicable, Not_Reviewed.

---

## 2. The problem & business case

During STIG validation on program systems, the team used two automated
scanners (PreSTIGe and evaluate-STIG). Findings on the **RHEL 8** target (366 rules) — the current
demo scope:
- **41 disagreements** between the two tools. *(The competition demo/presentation understated this as
  25 due to the comparison bug — see section 8 / known issues.)*
- **20 "Not Reviewed" gaps** (rules neither tool automated).
- **CAT I false negatives** in both tools (critical issues missed).
- **3-4 hours of manual reconciliation per system** (SSH in, run commands, compare).
- Neither tool exports POA&M comments (required, manually drafted).

*(Note: earlier combined figures of "72 disagreements / 46 gaps" were RHEL 8 **plus** a Windows 11 VM
together. The RHEL-8-only numbers above are what the current app/demo covers.)*

**Scale:** a single program can have **1,000+ systems/endpoints**, each needing its own full STIG.
Manual reconciliation consumes a large engineering effort every year. Documented per-system impact:
3-4 hrs -> <30 min.

Severity categories: CAT I (high), CAT II (medium), CAT III (low).


---

## 3. History & how we got here

- **Origin:** an entry in a 2026 internal AI intern challenge, built by a small team in a ~2-3 week
  window and aligned with real STIG validation work.
- **Competition constraints (no longer binding):**
  - Agents had to be built IN Genesis (the internal LLM/agent platform) and called via API — NOT
    custom-coded agents.
  - Had to use on-prem Genesis models (not cloud-hosted).
  - Had to use agents in the internal chatbot unless granted a custom-UI exception —
    ARES got the exception (its workflow doesn't fit a chatbot).
- **What actually got built for the demo:**
  - **Parser Agent:** fully built in Genesis, used `parse_ckl`/`parse_csv` MCP tools, connected to a
    Streamlit frontend, accepted files, called tools, returned standardized JSON. Worked well
    (JSON output still needs polish).
  - **MCP server:** custom server with 4 tools, deployed to **OpenShift** (the only place
    Genesis could see custom MCP servers). Getting Panel/OpenShift access + deploying was the single
    biggest time sink of the competition.
  - **Gap Identifier (script):** worked well.
  - **Gap Coverage + Determination Agents:** had to be moved to **local** agents (Genesis model via
    API + local MCP `execute_command` tool using Fabric SSH), because the project lead's RHEL 8 VM ran locally
    in VirtualBox with only a host-only adapter (corporate limitation — no bridged adapter), so the
    OpenShift-hosted MCP could not SSH into it. This technically deviated from competition MCP rules
    but was permitted for the demo (and may have contributed to not winning first place).
  - **Comparison (script):** ran between gap coverage and determination.
  - **Reporting Agent:** NOT built. Output was **hard-coded/faked** to look like it generated a final
    CKL, with no time left before submission.
- **Result:** Submitted on time, mostly working. Placed **top-10 of 50+**. Did not win first place
  (unfinished/rough areas were visible).
- **After the competition:** ARES was presented to the cyber team and received a strong positive
  reception; clear perceived value in time/cost savings.


---

## 4. Current situation (as of Aug 2026)

- Competition is OVER. ARES continues as a product effort with a small team.
- **AI-assisted development** is used to speed up delivery.
- **Timeline:** target is development "done" by ~November 2026, then lab testing to produce metrics
  on time/cost savings.
- **Testing implication:** because development is heavily AI-assisted, **thorough end-to-end, unit, and
  security testing is REQUIRED** before anything is trusted or shipped (see `TESTING.md`).


---

## 5. The big architectural shift: Genesis -> Local

The classified AI lab does **NOT** use Genesis; it has its own separate GPU/LLM infrastructure.
Therefore:
- **All agents become LOCAL Python agents** that only call an LLM API. To move from dev (Genesis) to
  prod (lab), we swap the LLM base URL + model IDs + auth. If we kept Genesis-built agents, we'd have
  to rebuild them anyway — so we rebuild them as local agents now.
- **MCP server runs LOCALLY**, packaged with the app (no OpenShift).
- **STIG content comes from a local provider**, not Genesis RAG (the app already loads RHEL 8 STIG
  text from a local markdown file).

This removes both historical blockers (custom MCP on OpenShift; the local<->Genesis<->OpenShift<->VM
networking maze). New challenge: getting networking secure/reliable once packaged and installed in the
lab (see `PACKAGING_AND_NETWORKING.md`).

**About Genesis (for reference):** an internal LLM + agent-building platform. Agents can use on-prem
or internal-cloud models, and be customized with prompts, RAG knowledge bases, datasets, MCP tools,
and advanced settings. Agents are usable in a chatbot or via API. Beyond calling
Genesis-built agents, you can also call the **Genesis model catalog directly via API** and build
agents in local Python with more customization — which is exactly what ARES will do (and what the lab
requires). On-prem models typically cover more data classifications (for example CUI); cloud
models fewer. Genesis API docs are archived in `docs/history/` (originally `docs/Genesis API Docs.txt`).

---

## 6. Product vision: augment PreSTIGe

The AI-lab manager ultimately wants ARES **packaged with PreSTIGe** (one of the two STIG scanners ARES
was built to augment). PreSTIGe already gets more coverage and higher accuracy than evaluate-STIG, but
it still doesn't review all items and sometimes gets some wrong. ARES augments it by ensuring more
coverage and higher accuracy — saving time/money and shortening the window that vulnerabilities stay open.

To be worthy of packaging with PreSTIGe, ARES must:
- Do more than reconcile two tool outputs (that was a great demo of "AI runs Check Text commands," but
  it's not the strongest use case on its own).
- **Support (much of) the same systems/software PreSTIGe supports, plus more** — many OSes, services,
  software; and **discover and scan sub-systems/software within a target** in one run.
- **Scan entire systems and output complete STIG files** like PreSTIGe does — but better (AI ground-truth
  validation), comparing to any completed STIG CKL/CSV and covering Not_Reviewed items.
- **Compare an older STIG scan to a newer STIG version** and determine what changed (see Version Delta mode).
- Add capabilities PreSTIGe LACKS: AI ground-truth validation, POA&M comment generation, container scanning.

**Note:** By lab-testing time, ARES need not match PreSTIGe exactly — but it must be much more than a
single RHEL 8 reconciliation. The project lead will ask the lab manager which OS/software to prioritize.

---

## 7. The three operating MODES

**Applies to all modes:** a "completed scan" (from any tool OR a manual scan) can still contain
**Not_Reviewed** rules — ARES always covers those. Modes may share agents, scripts, prompts, tools,
and building blocks as needed, but they are **distinct modes that run separately** and can have their
own custom features.

1. **Compare Scans** (`compare_scans`) — CURRENT/ORIGINAL MODE.
   Reconcile two completed scans of the **same STIG (same version)**, produced by different tools OR
   methods — e.g. two automated tools (PreSTIGe CKL vs evaluate-STIG CSV), or an **automated scan vs a
   manual scan**. Pipeline: parse both -> identify Not_Reviewed (in either/both) -> validate gaps via
   CLI -> compare all sources -> resolve disagreements via CLI -> generate reconciled CKL.
   *UI copy: "Upload two completed scans of the same STIG (same version), produced by different tools or methods (including manual). ARES also covers any Not_Reviewed rules."*

2. **Full Spot Check** (`full_spot_check`) — NEW.
   ARES independently re-validates **every** rule of the same STIG via a full AI deep-scan (runs all
   Check Text commands itself), then compares its findings to a completed scan (usually PreSTIGe, but any
   tool or manual scan) to determine ground truth and cover Not_Reviewed. "AI performs a full STIG scan +
   validation," not just diffing tool outputs.
   **Secondary validation:** any rule left Not_Reviewed (or otherwise uncertain) gets a **secondary
   validation using a different LLM**, so every rule receives multiple independent investigations;
   disagreements between the LLMs are then resolved.
   *UI copy: "Same STIG, independently validated with a full AI deep-scan re-check, then compared to a completed scan."*

3. **Version Delta** (`version_delta`) — NEW.
   Compare an **older** STIG scan to a **newer STIG version** of the same system/software (regardless of
   scanning tool/method). Determine per rule: dropped (not in new), resolved (Open->NotAFinding),
   still-open, regressed (NotAFinding->Open), net-new (in new, absent in old), other important comparisons;
   and resolve any Not_Reviewed via CLI.
   **Secondary validation:** any **net-new** rule in the newer STIG, and any Not_Reviewed/uncertain rule,
   gets a **secondary validation using a different LLM** (multiple independent findings per rule;
   disagreements resolved).
   *UI copy: "Compare an older scan to a newer STIG version: what dropped, resolved, still open, regressed, or new."*

Modes share common building blocks (parse, content lookup, CLI validate, compare, resolve, report) via
mode strategies — not three forked pipelines — while remaining clearly separate, independently runnable
modes.


---

## 8. Current app state (honest)

| Component | State |
|---|---|
| Parser Agent | Worked (Genesis-built + OpenShift MCP). Must be rebuilt as a local agent. JSON output needs polish. |
| Gap Identifier (script) | Works. |
| Gap Coverage Agent | Worked locally (Genesis model + local MCP execute_command). Needs polish; possibly partial gaps. |
| Comparison (script) | Works but BUGGY — reports 25 disagreements vs **41** hand-counted (RHEL 8 test files). Undiagnosed. |
| Determination Agent | Worked locally but incomplete; downstream of the comparison count bug. |
| Reporting Agent | Does NOT exist — hard-coded fake output for the demo. Must be built for real. |
| MCP server + 4 tools | Deployed to OpenShift for competition. Moving to local. Tools likely need rebuild/fix for new structure. |
| Streamlit UI | Mostly built and working on `feature/initial-agent-flow` (current branch). Needs improvement + new features. `dev`/`feature/live-pipeline-ui` may contain extra UI work by Matthew/Miguel that the project lead never reviewed — diff and decide keep-vs-discard, building off the current branch. |
| Mock mode | Present in code but NEVER used. To be removed entirely. |
| RHEL 8 support | Only OS/software supported. No sub-system/software discovery. Only runs commands from the uploaded STIG. |
| Observability | None. No saved runs, logs, or traces. To be built (foundational). |
| Repo hygiene | Messy: rushed build left dead code, duplicate files, one-off tests, scattered/outdated docs, out-of-sync branches. |

---

## 9. Feature roadmap summary (see `ROADMAP.md` for detail & status)

**MUST:** local refactor; complete Compare Scans (real Reporting + fix comparison bug); observability;
multi-target/STIG + sub-system discovery; Full Spot Check mode; Version Delta mode; packaging for lab.

**SHOULD:** POA&M comment generation (fold in remediation-script "fixing" capability); Windows (WinRM)
support; OpenSCAP/container scanning (replaces separate OpenSCAP use — high ROI).

**COULD:** STIG Explainer chatbot; (version-migration detector is subsumed by Version Delta mode).

**LATER/ROADMAP:** CKLB parsing; Nessus parsing; fleet-level intelligence; STIG-to-SPA risk mapper;
multi-system parallel processing; distributed CLI execution; automated scheduling; pattern learning;
compliance tracking over time.

**Combined/dropped:** standalone "Spot Check Agent" -> replaced by Full Spot Check mode. "Fixing Agent"
-> folded into POA&M generation. "STIG version migration detector" -> folded into Version Delta mode.

---

## 10. Key people & roles

- **Project lead** — product owner and reviewer/tester.
- **AI-lab manager** (other program) — sponsor of funded hours + classified lab; wants Nov results + metrics.
- Development is AI-assisted (Windsurf during the competition; now Cline). Operating specifics are kept
  in the git-ignored `.clinerules/` and skills, not in shareable docs.


---

## 11. Glossary

- **STIG** — Security Technical Implementation Guide (DISA security ruleset).
- **CKL** — STIG Viewer "Checklist" XML output. **CKLB** — newer STIG Viewer 3 binary/JSON checklist
  (different parsing; roadmap/later).
- **CSV** — comma-separated scan output (tool-dependent columns).
- **PreSTIGe** — STIG scanning tool (higher coverage/accuracy; ARES augments it).
- **evaluate-STIG** — another STIG scanner (the second tool in Compare Scans).
- **OpenSCAP** — open-source SCAP scanner; team uses it to scan containers (ARES aims to replace that need).
- **Nessus** — vulnerability scanner (roadmap parsing support).
- **CAT I/II/III** — STIG severity (high/medium/low).
- **POA&M** — Plan of Action & Milestones (remediation plan; required for Open findings).
- **Check Text / Fix Text** — STIG rule instructions to verify / remediate.
- **Genesis** — internal LLM + agent platform.
- **OpenShift / Panel** — infra used to host custom MCP for Genesis during the competition (being retired).
- **MCP** — Model Context Protocol (tool interface for agents).
- **Fabric** — Python SSH automation library used by the CLI executor.
- **Classifications** — for example CUI (data sensitivity levels affecting model choice).

single RHEL 8 reconciliation. The project lead will ask the lab manager which OS/software to prioritize.
