# ARES — Testing & Observability Strategy

> **Status:** Living document. How we test ARES and make runs observable so development is reproducible
> and the project lead can review/test with minimal effort. Because ARES is AI-assisted, rigorous testing is required.
> Last updated: 2026-08-16.

---

## 1. Principles

- The project lead reviews asynchronously and rarely drives the UI. So **every run must be reproducible and
  observable from saved artifacts**, and **the default test suite must be fast + offline**.
- Deterministic logic gets thorough unit tests. Non-deterministic LLM behavior gets recorded-response
  regression tests + structural/tolerance evals + opt-in live smoke tests.
- Tests and observability are built alongside features, not after.

---

## 2. Test taxonomy

### Unit (default, offline, fast)
- Targets: parsers (CKL/CSV), gap identifier, comparison, CKL generator, command validator, schema,
  and the provider/backend/content abstractions using fakes.
- No network, SSH, or LLM. Runs in CI on every push. Must never hang.

### Integration (offline)
- Wire the pipeline using **recorded LLM responses** + a **fake execution backend** + a **fake/sample
  STIG content provider**. Assert data flows correctly step-to-step and artifacts match schemas.

### Live (opt-in, marked `@pytest.mark.live`)
- Real LLM provider + real target (VM/SSH). Skipped by default; run explicitly for end-to-end validation.
- Assert **structural correctness + tolerances** (valid statuses, confidence in range, required fields,
  known-answer rules), NOT exact LLM text.

---

## 3. Golden dataset

- The project lead's two RHEL 8 scan files (`data/input/rhel8-prestige-auto.*`,
  `data/input/rhel8-evaluatestig-remote-ansible.*`) + curated known-good expected outputs.
- Used for reproducible end-to-end runs and regression checks (esp. the comparison disagreement-count bug).
- Update goldens deliberately, with a note in the commit + `DECISIONS.md` when behavior intentionally changes.

---

## 4. Eval harness (for agent steps)

- Given a run's `llm/` + `steps/` artifacts, assert:
  - Every finding has a valid status and severity.
  - Confidence values are within range; low-confidence -> flagged for human review.
  - Required fields present; JSON parses; counts reconcile (inputs vs outputs).
  - Known-answer rules resolve as expected (curated subset).
- Produces a pass/fail report per run so the project lead can glance and trust (or investigate).

---

## 5. Observability: run artifacts

Every run writes `data/runs/<run_id>/` (git-ignored):
- `inputs/` — input scans + resolved config (with secrets redacted).
- `steps/<NN>_<step>.json` — each step output (schemas in `ARCHITECTURE.md`).
- `llm/<NN>_<agent>.json` — every prompt + response pair.
- `commands/<rule_id>.json` — command, backend, exit code, stdout, stderr, duration, sudo.
- `run_summary.json` — mode, per-step timings, counts, errors, artifact paths.

A run report (human-readable summary of `run_summary.json` + eval results) is the primary review surface.

---

## 6. CI (roadmap)

- Lightweight GitLab CI on every push to `dev`/feature branches: install, lint (`flake8`), format-check
  (`black --check`), run the **offline** unit + integration suites, and the eval harness against recorded
  fixtures. Keep the existing GitLab vuln scanners.
- Grow to coverage gating + a packaging build. No auto-CD; lab install is a controlled manual step.

---

## 7. Rules of thumb

- New deterministic code => unit tests required.
- New/changed agent step => recorded-response regression test + `@live` smoke test.
- Never introduce import-time network/SSH/LLM calls (that is what hangs pytest today).
- Move any one-off/ad-hoc test scripts into `tests/` as replicable tests, or delete them.
