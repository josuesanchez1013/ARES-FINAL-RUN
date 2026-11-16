# ARES — Automated Reconciliation and Evidence for STIGs

> **AI-powered STIG compliance meta-validation.** ARES ingests STIG scan outputs, autonomously runs
> STIG "Check Text" validation commands on target systems, uses LLM agents to determine ground truth,
> and produces a more complete and accurate reconciled STIG checklist (CKL) than any single scanner
> produces on its own.

**Status (Nov 2026):** Active development. Being rebuilt **local-first**
to run without Genesis-built agents and to eventually **augment PreSTIGe** (an existing STIG scanner).
Development is AI-assisted to accelerate delivery. Because the codebase is AI-assisted, **thorough end-to-end,
unit, and security testing is required** before anything is trusted or shipped.

**New since August (all pending review, see `CHANGELOG.md`):**

| Feature | What it adds | Where |
|---|---|---|
| **UI v2** | React + FastAPI interface that runs alongside the Streamlit UI | `ares_api/`, `frontend/`, `README_UI_V2.md` |
| **STIG import** | Import any DISA STIG or SCAP benchmark, or the whole STIG Library zip, and assess against it. ARES picks the matching STIG for an uploaded scan | `stig_library/`, STIG library page |
| **Multi-platform targets** | Saved targets for Linux (any distribution), Solaris, AIX, HP-UX, macOS, ESXi, Windows (WinRM) and network devices (saved configuration) | `ares_api/targets.py`, `cli_executor/backends.py`, Targets page |
| **Per-platform safety rules** | Read-only command rules for POSIX shells, PowerShell and network CLIs | `security/` |
| **More scan formats** | CKL, CSV, CKLB and XCCDF results from SCC or OpenSCAP as scan inputs | `stig_library/convert.py` |
| **OpenSCAP scans** | Run `oscap` with imported SCAP content and use the result as a scan | `ares_api/scap.py` |

**What has been proven and what has not (2026-11-15 lab pass):** on VirtualBox VMs running Oracle
Linux 8.10, Oracle Linux 9.8, Ubuntu 22.04 and Windows Server 2022, with the October 2026 DISA library
imported (403 entries): connection, discovery of the matching STIG, OpenSCAP results as input (Linux),
and read-only checks all worked. **Not yet run:** the AI agents against those hosts (needs a Genesis
token), Solaris, AIX, HP-UX, macOS, ESXi, and live network devices. The offline suite has 525 tests.

---

## What ARES does

When two STIG scanners disagree, or leave rules "Not Reviewed," a cyber engineer spends 3-4 hours per
system manually SSHing in and running commands. ARES automates that:

1. Parse scan output(s) into a normalized finding schema.
2. Identify gaps (Not_Reviewed rules).
3. Validate findings by running each rule's Check Text command on the target (read-only) and
   interpreting the output with an LLM agent.
4. Reconcile disagreements to determine ground truth.
5. Generate a reconciled CKL + metrics (and, on the roadmap, POA&M comments).

**Differentiator:** unlike other AI STIG tools that only analyze reports, ARES *actively validates*
findings by executing read-only commands on the actual systems.

---

## The three modes

| Mode | Id | What it does |
|---|---|---|
| **Compare Scans** | `compare_scans` | Reconcile two completed scans of the **same STIG (same version)** produced by different tools/methods (e.g. PreSTIGe vs evaluate-STIG). *(Current mode.)* |
| **Full Spot Check** | `full_spot_check` | ARES independently re-validates **every** rule via a full AI deep-scan, then compares to a completed scan to determine ground truth. *(New.)* |
| **Version Delta** | `version_delta` | Compare an **older** scan to a **newer STIG version**: dropped / resolved / still-open / regressed / net-new, plus CLI resolution of Not_Reviewed. *(New.)* |

---

## Architecture (target: local-first)

- **All agents are local Python agents** calling an LLM via a provider abstraction (Genesis in dev,
  the classified lab's GPU infra in prod — swapped by config).
- **Local packaged MCP server** with tools: `parse_ckl`, `parse_csv`, `execute_command`, `generate_ckl`.
- **Execution backends (built):** `ssh` (Fabric, any UNIX), `local` (the ARES host), `winrm`
  (Windows PowerShell, optional `pywinrm`, certificate always verified) and `config` (a saved
  network-device configuration). `container` remains future work.
- **STIG content (built):** the bundled RHEL 8 V2R7 content, or any imported STIG from the library.
  The existing pipeline is served through an override, so `ui/orchestrator_runner.py` is unchanged.
- **Deterministic scripts** (parse, gap identify, compare, delta, CKL gen) stay in Python; LLM agents
  only do reasoning that needs an LLM.

See `docs/ARCHITECTURE.md` for diagrams, the pipeline, and the exact per-step data flow.

---

## Documentation (start here)

| Doc | Purpose |
|---|---|
| `docs/MASTER_CONTEXT.md` | The durable "everything about ARES" record: what/why, history, vision, glossary. |
| `docs/ARCHITECTURE.md` | Target architecture, the 3 abstractions, pipeline, DATAFLOW, observability. |
| `docs/ROADMAP.md` | Phased plan, prioritized features, task status, timeline, open questions. |
| `docs/DECISIONS.md` | Decision log (what + why). |
| `docs/TESTING.md` | Testing + observability strategy. |
| `docs/DEVELOPMENT.md` | Run locally, configure providers/targets, dev -> lab. |
| `README_UI_V2.md` | UI v2 (React + FastAPI): layout, how to run, configuration, status and known gaps. |
| `docs/UI_VISUAL_STANDARD.md` | UI v2 colours, type and contrast rules. |
| `docs/PACKAGING_AND_NETWORKING.md` | Packaging + execution-backend/networking design for the lab. |

Historical/competition-era docs are archived (locally, git-ignored) in `docs/history/`.

---

## Branching & contribution

- **`main`** — always-releasable / production line. Only receives reviewed merges from `dev`.
- **`dev`** — active integration + development branch (the baseline to follow along with).
- **`feature/<name>`** — short-lived branches per work item, branched from `dev`, reviewed before merge.
- Never commit directly to `main`; avoid half-finished work on `dev`. See `docs/DEVELOPMENT.md`.

Because development is AI-assisted, every change is expected to carry tests, and end-to-end + security
testing is required before promotion to `main`.

---

## Quick start (dev)

```bash
python -m venv venv
venv\Scripts\activate          # Windows (Linux/macOS: source venv/bin/activate)
pip install -r requirements.txt
cp .env.example .env           # fill in real values; never commit .env

python -m streamlit run ui/streamlit_app.py
./restart.ps1                  # standardized restart after code/UI changes
```

UI v2 (React + FastAPI, runs alongside the Streamlit UI; see `README_UI_V2.md`):
```bash
pip install -r requirements.txt -r requirements-api.txt
pip install -r requirements-windows.txt                 # only if you will scan Windows targets
uvicorn ares_api.main:app --host 0.0.0.0 --port 8080    # open http://<host>:8080
```
Set `ARES_USE_MOCK=true` to try the UI without calling any model. Then, in the UI: import STIGs on the
**STIG library** page, add hosts on the **Targets** page, and start an assessment on the **Run** page.

Testing:
```bash
pytest            # fast, offline (default) — must never hang
pytest -m live    # opt-in: real LLM + real target (VM/SSH)
```

See `docs/DEVELOPMENT.md` for full configuration and the dev -> lab switch.

---

## Security

- All validation commands are **read-only**; ARES determines state, never remediates.
- Multi-layer safety: restricted target user + sudoers blacklist, application-level command validator
  (`security/command_validator.py`, `security/platform_validators.py`), read-only filesystem posture.
  The POSIX validator is a blocklist; it was hardened in November 2026 after lab testing showed that
  `sudo <blocked command>` passed (DECISIONS D-032). An allowlist is on the roadmap.
- Saved targets never store a password or key: only an SSH key path or the name of an environment variable.
- Every executed command is audit-logged. Secrets come from env/config and are never committed.
- TLS verification ON in production; classification-aware LLM provider selection.

