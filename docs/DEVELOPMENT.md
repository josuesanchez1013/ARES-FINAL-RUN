# ARES — Development & Environment Guide

> **Status:** Living guide for running ARES locally end-to-end and configuring providers/targets.
> Reflects target-state (local-first). Some paths/vars will change during the Phase 2 refactor — keep
> this current. Last updated: 2026-08-16.

---

## 1. Prerequisites

- Python 3.10+ (dev machine runs 3.13). Windows dev; RHEL 8 target VM (VirtualBox, host-only network).
- A reachable **LLM provider**: Genesis (dev) or the lab GPU infra (prod).
- For remote execution: SSH access to the target (Fabric). For on-target mode: run ARES on the target.
- STIG content source (today: `data/input/RHEL_8_STIG_V2R7.md`).

---

## 2. Setup

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env   # then fill in real values (never commit .env)
```

---

## 3. Configuration (.env)

Key variables (see `.env.example` for the full list; names may be refined in Phase 2):

- **LLM provider:** `GENESIS_API_TOKEN`, `GENESIS_API_URL` (dev). Prod will add a `lab` profile with
  its own base URL / model IDs / auth. Model example used historically: `nemotron-3-ultra-550b-a55b`.
- **Agent IDs (legacy Genesis-built):** `ARES_PARSER_AGENT_ID`, `GAP_COVERAGE_AGENT_ID`,
  `DETERMINATION_AGENT_ID`, `REPORTING_AGENT_ID`. These go away as agents become local.
- **SSL:** `SSL_CERT_FILE` (corporate CA bundle). Prod: verification ON.
- **SSH (remote execution):** `SSH_HOST` (e.g. 10.0.2.15), `SSH_USER`, `SSH_KEY_PATH`, `SSH_PORT`.
- **Mode/target/classification:** to be added — active mode, execution backend, STIG source, data classification.
- `ARES_USE_MOCK` — being REMOVED (mock mode is deprecated). Do not rely on it.

---

## 4. Running the app

```bash
python -m streamlit run ui/streamlit_app.py
# After UI/code changes, use the standardized restart (clears caches):
./restart.ps1
```

Then in the UI: choose a mode, upload the required scan(s), start the workflow, watch live progress,
review results, download the reconciled CKL. Every run also writes `data/runs/<run_id>/` for review.

---

## 5. Running tests

```bash
# Fast, offline (default) — MUST pass and never hang:
pytest

# With coverage:
pytest --cov=mcp_server --cov=cli_executor --cov-report=html

# Live end-to-end (opt-in; needs real LLM + VM):
pytest -m live
```

> If `pytest` hangs on collection, a module has an import-time side effect (network/SSH/LLM). This is a
> known issue (I-003) to be fixed in Phase 1; do not add such side effects.

---

## 6. Moving from Genesis (dev) to the lab (prod)

1. Add a `lab` LLM Provider config (base URL, model IDs, auth, classification) — see `ARCHITECTURE.md` 3.1.
2. Select the appropriate **execution backend** (`local` if ARES runs on the target; `ssh`/`winrm`/
   `container` for remote).
3. Point the **STIG Content Provider** at the correct STIG(s).
4. Turn TLS verification ON; supply the lab CA bundle.
5. Run the offline suite, then a `@live` smoke test in the lab.

---

## 7. Repo map (current; evolving in Phase 2)

- `mcp_server/` — MCP tools (`parse_ckl`, `parse_csv`, `generate_ckl`, `execute_command`), parsers,
  `generators/ckl_generator.py`, `schemas/finding_schema.py`.
- `cli_executor/` — Fabric SSH client, executor, MCP tool wrapper, audit logger, config.
- `security/` — `command_validator.py`, audit log viewer.
- `genesis_integration/` — agent client, local agent executor, scripts (`gap_identifier.py`,
  `comparison_script.py`), STIG loader. (Will be reorganized into clear `agents/` + providers.)
- `ui/` — Streamlit app, orchestrator runner, components.
- `data/` — `input/` (scans, STIG markdown), `output/` (latest artifacts), `logs/` (audit),
  `runs/` (per-run artifacts; to be added; git-ignored).
- `tests/` — test suite. `docs/` — living docs (public). `docs/history/` — archived docs (git-ignored).
- `.clinerules/` — AI operating rules (git-ignored, local only). `.windsurf/` — Windsurf rules (left intact).
- `.streamlit/` — local Streamlit config (git-ignored).

## 8. Branch & git strategy (detail)

- **`main`** — always-releasable / production line. Only reviewed merges from `dev`. Never commit directly.
- **`dev`** — active integration + development branch; the shareable baseline others follow.
- **`feature/<kebab-name>`** — short-lived, branched from `dev`, one coherent work item each
  (e.g. `feature/local-agents`, `feature/reporting-agent`, `feature/mode-version-delta`). Reviewed before merge.
- **Commits:** small, focused; prefix `feat:`/`fix:`/`refactor:`/`docs:`/`test:`/`chore:`; explain WHAT + WHY.
- **Milestones:** promote `dev` -> `main` after review; keep `dev` and `main` in sync at release points so
  the repo is always in a shareable state.
- **Never without asking:** force-push / history rewrite on `dev`/`main`, deleting remote branches, or
  deleting files with unique work (archive to `docs/history/` first).
- **AI-assisted code => tests required:** each feature branch should carry unit tests; end-to-end +
  security testing gate promotion to `main`.
