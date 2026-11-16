# ARES UI v2: React + FastAPI

A FastAPI service (`ares_api/`) and a React app (`frontend/`) that replace the
Streamlit UI. Python stays in the backend and the existing pipeline is reused,
not forked. The Streamlit app in `ui/` is untouched and still runs.

## Where the folders go

Copy these into the project root, next to `ui/`, `genesis_integration/` and
`mcp_server/`:

    ares_api/        FastAPI service
    frontend/        React source, plus the built app in frontend/dist
    tests/test_api.py    (keep the project's own tests/conftest.py)
    scripts/         verify_rhel.sh, smoke.py, check_contrast.py
    docs/UI_VISUAL_STANDARD.md
    requirements-api.txt, requirements-dev.txt

## Run it

    pip install -r requirements.txt -r requirements-api.txt
    uvicorn ares_api.main:app --host 0.0.0.0 --port 8080
    # open http://<host>:8080

`requirements.txt` is needed for real runs: the service imports the existing
pipeline (`ui/orchestrator_runner.py`), which needs Streamlit, requests and
Fabric. `requirements-api.txt` alone is enough only for mock mode.

Real runs also need `MCP_SERVER_URL` set (in `.env` or the environment). If it
is missing the run stops at the model check with a clear message, instead of
sending the uploaded scans to the orchestrator's built-in default, the retired
OpenShift server (DECISIONS D-004).

`frontend/dist` is already built and is committed (`.gitignore` has an
exception for it), so the server host needs no Node.js. To
rebuild after a frontend change: `cd frontend && npm ci && npm run build`.

Try it without Genesis, the MCP server or a target: `ARES_USE_MOCK=true`.

## Verify on RHEL 8 / RHEL 9

    ./scripts/verify_rhel.sh

Needs Python 3.11 or 3.12 (`dnf install python3.11`). The RHEL 9 default,
Python 3.9, cannot import `ui/orchestrator_runner.py`. The script installs into
a throwaway venv, runs the full offline test suite (pipeline and API) and the contrast check, then starts
the service in mock mode and drives a full run over HTTP.

## Importing the latest STIGs

1. On a machine with internet access, download STIGs from DoD Cyber Exchange: the STIG Library
   compilation zip (every STIG at once), single STIG zips, or SCAP benchmark zips.
2. Bring the zip to the ARES host the same way other files get there.
3. Open **STIG library** in the UI and upload it. ARES opens the zips inside the zip, imports every
   STIG it finds, keeps each release, and reports what changed against releases already imported.
4. On the Run form, **STIG content** defaults to *Match the scan files*: ARES reads the STIG and release
   named in the uploaded CKL/CKLB/CSV and uses that release from the library. If the library does not
   have it, the run uses the built-in RHEL 8 content as before and says so. You can also pick a
   specific release or the built-in content.

Nothing is downloaded by ARES itself. The library lives in `data/stig_library/` and is not committed.

## Checking other systems (Windows, Solaris, other Linux, network devices)

Open **Targets** and add the system:

| Platform | Connect by | What you need |
|---|---|---|
| Linux (RHEL, Oracle, Ubuntu, SLES), Solaris, AIX, HP-UX, macOS, ESXi | SSH | An audit account and an SSH key file on the ARES host (or a password in an environment variable) |
| Windows Server / Windows 10 / 11 | WinRM | `pip install -r requirements-windows.txt` on the ARES host; WinRM over HTTPS enabled on the target; an audit account whose password is in an environment variable |
| Cisco, Juniper and other network devices | Saved configuration | Upload the device's running configuration on the target |
| The ARES host itself | This machine | Nothing |

Passwords are never stored. Put the password in an environment variable of the ARES service (for
example `ARES_PW_WEB01=...` in `.env`) and enter the variable's name on the target.

Then: **Test connection**, **Find matching STIGs** (lists the imported STIGs that apply to what the
target reports), and choose the target on the Run form. Only read-only commands are sent, and every
command is written to the audit log in `data/logs/`.

Scan files can be CKL, CKLB, CSV, or the XCCDF results `.xml` that DISA SCC and OpenSCAP write.
With OpenSCAP installed on the ARES host (`openscap-scanner`, and `openscap-utils` for scans over
SSH), the Targets page can also run an imported SCAP benchmark and feed its result into a run.

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `ARES_USE_MOCK` | `false` | `true` serves sample results, fully offline |
| `ARES_LLM_MODELS` | `nemotron-3-ultra-550b-a55b` | Comma-separated models offered in the pickers |
| `ARES_SENSITIVITY_CATEGORIES` | `PII,Proprietary,Export controlled,Other` | Sensitivity choices on the start form |
| `ARES_DATA_DIR` | `data/runs` | Where runs, events, outputs and masked uploads are kept |
| `ARES_RUN_RETENTION` | `50` | Finished runs kept; kept (pinned) runs are never pruned |
| `ARES_TARGET_HOST`, `ARES_TARGET_IP` | `rhel8-stig-lab`, `10.0.2.15` | Asset written into CKL / CKLB |
| `ARES_STIG_TITLE`, `ARES_STIG_VERSION`, `ARES_STIG_SOURCE` | RHEL 8 STIG, V2R7 | The built-in STIG: shown in Settings and written into exports of runs that use it |
| `ARES_STIG_LIBRARY_DIR` | `data/stig_library` | Where imported STIG releases are kept |
| `ARES_STIG_IMPORT_MAX_MB` | `2048` | Largest STIG upload accepted |
| `ARES_TARGETS_DIR` | `data/targets` | Saved targets and uploaded device configurations |
| `ARES_SCAP_DIR` | `data/scap_scans` | OpenSCAP scan results |

Existing pipeline variables (`MCP_SERVER_URL`, agent IDs, SSL) are read by the
orchestrator as before. The service loads `.env` from the directory it is
started in, the same way the Streamlit app does.

## How it fits together

    Browser (React)  --HTTP + Server-Sent Events-->  ares_api (FastAPI)
                                                        |
                                    BridgePipeline  or  MockPipeline
                                           |
                              ui/orchestrator_runner.execute_next_step

- `ares_api/pipeline.py` `BridgePipeline` calls the existing orchestrator one
  step at a time. The orchestrator reads and writes `st.session_state`; the
  bridge passes it a plain state object, so it runs without Streamlit and its
  status messages become live events. `ui/orchestrator_runner.py` is not edited.
  When the CORE service layer exists, swap this one class for a CORE adapter.
- `ares_api/runs.py` keeps each run on disk (metadata, event history, step
  outputs, masked uploads) and enforces the run lock.
- `ares_api/findings.py` builds one record per rule from the step outputs. This
  is what makes production runs show a findings table: the production report
  holds only counts, so the Streamlit Results tab had nothing to list.
- API schema: `/api/docs` and `/api/openapi.json`.

## Status against the feature list

| Item | Status |
|---|---|
| Run / Pause / Resume / End | Done. Pause and End take effect at the next status message from the pipeline, in practice after the rule in progress |
| Resume an unfinished run | Done. Restarts at the first unfinished step; a step interrupted midway reruns from its start |
| Run lock | Done. Second start returns 409 |
| Refresh-proof shared run; Start new run is the only reset | Done |
| Data-handling form | Done. Nothing preselected, None exclusive, Classified refused before anything is stored. The category list is a placeholder: set `ARES_SENSITIVITY_CATEGORIES` |
| Model dropdowns from `ARES_LLM_MODELS` | Done. Unlisted models refused. The primary model is passed to the gap and determination agents. The secondary model is recorded but nothing in the pipeline uses it yet |
| Model-check phase | Partial. Shown as its own phase, but it only confirms configuration; it does not ping the model |
| Live activity box, per-rule view | Done |
| Several rules in progress | UI and events support it; the pipeline itself still works one rule at a time |
| Find a rule, Detailed view | Done. Server-side search, filter, sort, paging; tested with 366 rows |
| Review queue with count badge | Done |
| "ARES recommendation X pending", "Confidence now" | Done. Wording still needs the STIG SME review |
| Up to three outcomes, Optional review | Done as: approve the recommendation or pick one of the other two statuses; Optional review lists agent verdicts that were not flagged. Confirm this matches D-121 |
| Approve / override / skip / undo | Done. Saved on the server, shared across tabs, applied to every export |
| CKL / CKLB / CSV / JSON built on click | Done. CKLB has not been opened in STIG Viewer 3 |
| Exports match today's files byte for byte | Not met. CSV has the same columns. CKL now carries the real finding details instead of a fixed sentence, and takes the host from configuration |
| Charts, one status colour map, unscored after scored | Done |
| Red only for real failures | Done as: red marks Open findings and run or agent errors; command output and exit codes are plain |
| No time-saved figure | Done |
| Masked upload path | Partial. CKL host name, IP, MAC and FQDN are masked before the file is stored. CSV files pass through unchanged. Replace `mask_upload` with the I-160 rules |
| Past runs, Keep pin | Done |
| Settings | Done, read-only |
| Light and dark themes, contrast check | Done. `scripts/check_contrast.py` |
| No emoji, one icon set | Done. Lucide icons. Emoji that the orchestrator puts in its status messages are stripped for display |
| Frontend component tests | Not written |

## Known gaps to decide on

- No sign-in. Anyone who can reach the port can start runs and record review
  decisions, and decisions are not attributed to a person.
- `ui/orchestrator_runner.py` calls the MCP server with `verify=False`.
- The pipeline writes `data/output/*.json` and a CKL to shared paths; the run
  lock is what keeps two runs from colliding there.
- Licences to review: React (MIT), lucide-react (ISC), IBM Plex fonts (OFL),
  FastAPI / Starlette / uvicorn (MIT / BSD).
