# ARES — Packaging & Networking Design

> **Status:** Living design doc for how ARES is packaged and how it reaches target systems, especially
> for the classified AI lab. Some items are PENDING confirmation from the AI-lab manager.
> Last updated: 2026-08-16. See also: `ARCHITECTURE.md` (Execution Backend), `.clinerules/05-security.md`.

---

## 1. Goals

- Ship ARES as a **self-contained local app** installable into a target environment (incl. the
  classified lab) with minimal external dependencies.
- Support two operating postures via the **Execution Backend abstraction**:
  1. **On-target (local) execution** — ARES runs ON the system being scanned; commands run locally
     (no SSH). Best for packaging with PreSTIGe and for locked-down/classified environments.
  2. **Remote execution** — ARES scans remote targets over SSH (Linux), WinRM (Windows, future), or
     container exec / OpenSCAP (containers, future).

---

## 2. Execution backends

| Backend | Transport | Status | Use case |
|---|---|---|---|
| `local` | subprocess on the host | built 2026-11-14 | ARES installed on the target itself; no network hop |
| `ssh` | Fabric/Paramiko | exists | Remote Linux (current RHEL 8 VM) |
| `winrm` | pywinrm (optional dependency) | built 2026-11-14, not yet lab-tested | Remote Windows |
| `container` / `openscap` | container exec / SCAP | roadmap | Containers (replaces separate OpenSCAP use) |

All backends share: the security command validator, audit logging, read-only posture, and the same
`run(command, ...)` interface. Adding a backend must not bypass validation/audit.

---

## 3. Packaging options (to evaluate in Phase 7)

**Goal:** ARES ships like PreSTIGe does — a self-contained artifact that gets installed onto (or run
against) target systems, requiring minimal setup and no build tools on the target. The exact PreSTIGe
packaging/distribution mechanism is a reference to match (TODO: The project lead to document how PreSTIGe is
packaged, installed, and invoked, so ARES can mirror or bundle with it).

Candidate packaging approaches:
- **Bundled Python app** (venv + launcher) — simplest; requires a compatible Python on the target.
- **PyInstaller one-folder/one-file executable** — no Python needed on target; larger artifact. Must
  verify Streamlit, Fabric/Paramiko, lxml, and the local MCP server bundle and launch cleanly.
- **Container image** — clean isolation and reproducibility, but classified-lab policy may restrict
  images/registries; may not fit "run on the target itself" mode.
- **Bundle-with-PreSTIGe** — ship ARES as a companion component invoked by/alongside PreSTIGe, sharing
  its install path and target access. Depends on PreSTIGe's packaging (pending).

Design constraints for whatever we choose:
- No hardcoded absolute paths; discover a writable data dir at runtime; work offline except for the LLM
  endpoint. Config-driven (LLM profile, execution backend, STIG source, classification).

## 3a. Install & run models

Two supported postures (selected by config; both use the same Execution Backend interface):
1. **On-target (local backend):** ARES is installed on the system being scanned and runs Check Text
   commands locally (no SSH). Best for locked-down/classified hosts and for bundling with PreSTIGe.
   Needs: the ARES artifact on the host, an LLM endpoint reachable from that host, and the relevant STIG
   content available locally.
2. **Remote (ssh/winrm/container backend):** ARES runs on an operator workstation/box and reaches targets
   by IP over SSH (Linux), WinRM (Windows), or container exec/OpenSCAP (containers). Needs: network path +
   credentials to targets, plus the LLM endpoint.

The UI/config lets the operator pick the mode and target(s). Sub-system/software discovery (Phase 4) runs
under whichever backend is active.


---

## 4. Networking considerations

- **Historical pain (competition):** local Streamlit <-> Genesis <-> OpenShift MCP <-> local VM, plus
  the VirtualBox host-only-adapter limitation (no bridged adapter) meant the OpenShift MCP couldn't SSH
  to the local VM. This drove the move to local MCP + local agents. Do not reintroduce that topology.
- **Local-first target topology:** UI + orchestrator + agents + MCP all run in one local process/host.
  The only outbound dependency is the **LLM provider API** (Genesis in dev; lab GPU infra in prod).
- **Classified lab (PENDING P-002):** confirm allowed outbound access (to the lab LLM endpoint),
  permitted transports to targets, and the install method. If outbound is heavily restricted, prefer
  the `local` backend (ARES on the target) and an in-lab LLM endpoint.
- **Security:** TLS verification ON in prod; support corporate CA bundles; never transmit scan data or
  command output off-box; secrets from env/config only.

---

## 5. Open questions (PENDING)

- **P-002** — Classified-lab constraints: outbound network to LLM endpoint? allowed transports to
  targets (SSH/WinRM/local)? install method (venv / exe / container)? writable data dir?
- **P-003** — Lab LLM API shape + models (drives the LLM Provider `lab` config + which classifications
  are allowed).
- **P-001** — Which OS/software to prioritize (drives which backends/STIGs to build first).
- How does ARES obtain the STIG content for a target in the lab (bundled STIG library vs supplied per run)?
- For on-target `local` mode, how is ARES delivered/updated on each scanned system (esp. with PreSTIGe)?
