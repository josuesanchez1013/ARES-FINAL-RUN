import { Check, CirclePause, FileUp, LoaderCircle, Pause, Play, Plus, Square, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Badge, Notice, RunBadge, StatusBadge, bytes, cleanLog, duration, when } from "../ui";
import type { LiveRun } from "../useRun";

const ACTIVE = ["checking", "running", "paused"];

interface Props {
  settings: any; run: any; live: LiveRun; summary: any;
  activeElsewhere: boolean; onChanged: (started?: any) => void; go: (route: string) => void;
}

export default function RunScreen({ settings, run, live, summary, activeElsewhere, onChanged, go }: Props) {
  const [composing, setComposing] = useState(false);
  useEffect(() => { if (run && ACTIVE.includes(run.status)) setComposing(false); }, [run?.id, run?.status]);

  if (!run || composing) {
    return (
      <StartForm settings={settings} canCancel={Boolean(run)} onCancel={() => setComposing(false)}
                 onStarted={(started) => { setComposing(false); onChanged(started); }} />
    );
  }
  return <RunView run={run} live={live} summary={summary} onChanged={onChanged} go={go}
                  onNew={activeElsewhere ? undefined : () => setComposing(true)} />;
}

/* ------------------------------------------------------------------ form */

function FileDrop({ label, hint, file, onFile }: { label: string; hint: string; file: File | null; onFile: (f: File | null) => void }) {
  const [over, setOver] = useState(false);
  return (
    <label className={`drop ${file ? "filled" : ""} ${over ? "over" : ""}`}
           onDragOver={(e) => { e.preventDefault(); setOver(true); }}
           onDragLeave={() => setOver(false)}
           onDrop={(e) => { e.preventDefault(); setOver(false); onFile(e.dataTransfer.files[0] ?? null); }}>
      <input type="file" accept=".ckl,.cklb,.csv,.xml" onChange={(e) => onFile(e.target.files?.[0] ?? null)} />
      <span className="muted small" style={{ display: "flex", gap: 6, alignItems: "center" }}>
        <FileUp className="icon" aria-hidden />{label}
      </span>
      {file
        ? <><span className="name">{file.name}</span><span className="hint num">{bytes(file.size)}. Select to replace.</span></>
        : <><span className="name">Choose a file or drop it here</span><span className="hint">{hint}</span></>}
    </label>
  );
}

function StartForm({ settings, canCancel, onCancel, onStarted }: { settings: any; canCancel: boolean; onCancel: () => void; onStarted: (run: any) => void }) {
  const [tool1, setTool1] = useState<File | null>(null);
  const [tool2, setTool2] = useState<File | null>(null);
  const [classification, setClassification] = useState("");
  const [sensitivity, setSensitivity] = useState<string[]>([]);
  const [primary, setPrimary] = useState("");
  const [secondary, setSecondary] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [stig, setStig] = useState("auto");
  const [target, setTarget] = useState("default");
  const [targetList, setTargetList] = useState<any>(null);
  const [scans, setScans] = useState<any[]>([]);
  const [scan1, setScan1] = useState("");
  const [scan2, setScan2] = useState("");
  useEffect(() => {
    api.targets().then(setTargetList, () => setTargetList(null));
    api.scap().then((body) => setScans(body.scans.filter((s: any) => s.status === "completed")), () => setScans([]));
  }, []);
  const [library, setLibrary] = useState<any>(null);
  useEffect(() => { api.stigs().then(setLibrary, () => setLibrary({ entries: [], builtin: null })); }, []);

  const models: string[] = settings?.models ?? [];
  useEffect(() => { if (models.length === 1) setPrimary(models[0]); }, [models.length]);
  if (!settings) return <p className="muted">Loading settings.</p>;

  const none = settings.sensitivity_none;
  const refused = settings.refused_classifications.includes(classification);
  const toggle = (value: string) =>
    setSensitivity((chosen) => {
      if (value === none) return chosen.includes(none) ? [] : [none];
      const rest = chosen.filter((v) => v !== none);
      return rest.includes(value) ? rest.filter((v) => v !== value) : [...rest, value];
    });

  const missing = [
    !tool1 && !scan1 && "the Tool 1 scan", !tool2 && !scan2 && "the Tool 2 scan",
    !classification && "a classification", sensitivity.length === 0 && "a sensitivity choice",
    !primary && "a primary model",
  ].filter(Boolean) as string[];
  const ready = missing.length === 0 && !refused && !settings.pipeline_error;

  const submit = async () => {
    setBusy(true); setError(null);
    const form = new FormData();
    if (scan1) form.set("tool1_scan", scan1); else form.set("tool1", tool1!);
    if (scan2) form.set("tool2_scan", scan2); else form.set("tool2", tool2!);
    form.set("target", target);
    form.set("classification", classification);
    form.set("sensitivity", sensitivity.join(","));
    form.set("primary_model", primary); form.set("secondary_model", secondary);
    form.set("stig", stig);
    try { onStarted(await api.start(form)); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div className="stack" style={{ maxWidth: 860 }}>
      <div className="page-head">
        <div className="grow">
          <h1>Start a run</h1>
          <p>Upload the same system's results from two scanners. ARES reconciles them, checks open questions on the target, and queues uncertain verdicts for your review.</p>
        </div>
        {canCancel && <button type="button" className="btn" onClick={onCancel}><X className="icon" aria-hidden />Cancel</button>}
      </div>

      {settings.pipeline_error && (
        <Notice tone="critical">The pipeline cannot start: {settings.pipeline_error}</Notice>
      )}
      {settings.mode === "mock" && (
        <Notice tone="warning">Mock data mode is on. Uploaded files are stored but results come from sample data.</Notice>
      )}

      <section className="panel panel-pad stack">
        <h2>Scan files</h2>
        <div className="cols two">
          <FileDrop label="Tool 1" hint="CKL, CKLB, CSV, or SCC / OpenSCAP results (.xml)" file={tool1} onFile={setTool1} />
          <FileDrop label="Tool 2" hint="CKL, CKLB, CSV, or SCC / OpenSCAP results (.xml)" file={tool2} onFile={setTool2} />
        </div>
        {scans.length > 0 && (
          <div className="cols two">
            {[["Tool 1", scan1, setScan1], ["Tool 2", scan2, setScan2]].map(([label, value, setValue]: any) => (
              <label key={label} className="field"><span>Or use an OpenSCAP scan for {label}</span>
                <select value={value} onChange={(e) => setValue(e.target.value)}>
                  <option value="">Use the uploaded file</option>
                  {scans.map((sc: any) => <option key={sc.id} value={sc.id}>{sc.stig_title} {sc.stig_version} on {sc.target_name}, {when(sc.started_at)}</option>)}
                </select>
              </label>
            ))}
          </div>
        )}
        <p className="hint">Host name, IP, MAC and FQDN in a CKL are masked before the file is stored. CKLB and results files are converted to CKL without them.</p>
      </section>

      <StigPicker library={library} settings={settings} value={stig} onChange={setStig} />

      <section className="panel panel-pad stack">
        <h2>Target</h2>
        <label className="field"><span>Run checks on</span>
          <select value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="default">{targetList?.default?.name ?? "Configured target"}</option>
            {(targetList?.targets ?? []).map((t: any) => (
              <option key={t.id} value={t.id} disabled={t.backend === "config" && !t.has_config}>
                {t.name} ({t.platform_label}{t.backend === "config" ? (t.has_config ? ", saved configuration" : ", no configuration uploaded") : ""})
              </option>
            ))}
          </select>
        </label>
        <p className="hint">
          ARES runs read-only checks on this system for rules the scanners left open or disagree on.
          {" "}{(targetList?.targets ?? []).length === 0 && "Add Windows, Solaris, other Linux or network targets on the Targets page."}
        </p>
      </section>

      <section className="panel panel-pad stack">
        <h2>Data handling</h2>
        <fieldset>
          <legend>Classification of these files</legend>
          <div className="choices">
            {settings.classifications.map((c: string) => (
              <label key={c} className="choice">
                <input type="radio" name="classification" checked={classification === c} onChange={() => setClassification(c)} />{c}
              </label>
            ))}
          </div>
        </fieldset>
        {refused && (
          <Notice tone="critical">ARES does not accept classified data. Nothing has been uploaded, and this run cannot start.</Notice>
        )}
        <fieldset>
          <legend>Sensitivity</legend>
          <p className="hint">Select every category that applies, or None.</p>
          <div className="choices">
            {settings.sensitivity_categories.map((c: string) => (
              <label key={c} className="choice">
                <input type="checkbox" checked={sensitivity.includes(c)} onChange={() => toggle(c)} />{c}
              </label>
            ))}
            <span aria-hidden style={{ width: 1, background: "var(--line)", margin: "0 4px" }} />
            <label className="choice">
              <input type="checkbox" checked={sensitivity.includes(none)} onChange={() => toggle(none)} />{none}
            </label>
          </div>
        </fieldset>
      </section>

      <section className="panel panel-pad stack">
        <h2>Models</h2>
        <div className="cols two">
          <label className="field"><span>Primary model</span>
            <select value={primary} onChange={(e) => setPrimary(e.target.value)}>
              <option value="">Choose a model</option>
              {models.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          </label>
          <label className="field"><span>Secondary model (optional)</span>
            <select value={secondary} onChange={(e) => setSecondary(e.target.value)}>
              <option value="">No secondary model</option>
              {models.filter((m) => m !== primary).map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          </label>
        </div>
      </section>

      {error && <Notice tone="critical">{error}</Notice>}
      <div className="actions">
        <button type="button" className="btn primary" disabled={!ready || busy} onClick={submit}>
          <Play className="icon" aria-hidden />{busy ? "Starting" : "Start run"}
        </button>
        {!ready && !refused && missing.length > 0 && (
          <span className="hint">Still needed: {missing.join(", ")}.</span>
        )}
      </div>
    </div>
  );
}

function StigPicker({ library, settings, value, onChange }: { library: any; settings: any; value: string; onChange: (v: string) => void }) {
  const entries: any[] = (library?.entries ?? []).filter((e: any) => e.kind === "manual");
  const builtin = library?.builtin ?? settings.stig;
  return (
    <section className="panel panel-pad stack">
      <h2>STIG content</h2>
      <label className="field"><span>Assess against</span>
        <select value={value} onChange={(e) => onChange(e.target.value)}>
          <option value="auto">Match the scan files (recommended)</option>
          <option value="builtin">Built-in: {builtin?.title} {builtin?.version}</option>
          {entries.length > 0 && (
            <optgroup label="Imported STIG library">
              {entries.map((e) => (
                <option key={e.id} value={e.id}>{e.title} {e.version_label}{e.latest ? "" : " (older release)"}</option>
              ))}
            </optgroup>
          )}
        </select>
      </label>
      <p className="hint">
        {value === "auto"
          ? "ARES reads which STIG and release the scan files are for and uses that release from the STIG library. If the library does not have it, the built-in content is used and the run says so."
          : value === "builtin" ? "Uses the STIG content that ships with ARES, as before."
          : "Every run uses exactly this release, whatever the scan files say."}
        {" "}{entries.length === 0 && "No STIGs are imported yet. Add them on the STIG library page."}
      </p>
    </section>
  );
}

/* --------------------------------------------------------------- run view */

function RunView({ run, live, summary, onChanged, onNew, go }: { run: any; live: LiveRun; summary: any; onChanged: () => void; onNew?: () => void; go: (r: string) => void }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const active = ACTIVE.includes(run.status);
  const paused = run.status === "paused";

  const act = async (call: () => Promise<any>) => {
    setError(null);
    try { await call(); onChanged(); } catch (e: any) { setError(e.message); }
  };

  const runningStep = run.steps.find((s: any) => s.state === "running" || s.state === "failed");
  const fallback = [...run.steps].reverse().find((s: any) => s.state !== "pending") ?? run.steps[0];
  const shown = run.steps.find((s: any) => s.key === selected) ?? runningStep ?? fallback;
  useEffect(() => { setSelected(null); }, [run.id, runningStep?.key]);

  const lines = useMemo(() => {
    const out: { level: string; text: string }[] = [];
    for (const entry of live.logs[shown.key] ?? []) {
      const text = cleanLog(entry.message);
      if (text !== null) out.push({ level: entry.level, text });
    }
    return out;
  }, [live.logs, shown.key]);

  const rules = Object.values(live.rules[shown.key] ?? {});
  const inFlight = rules.filter((r) => r.state === "running");
  const finished = rules.filter((r) => r.state === "done");
  const total = rules[0]?.total ?? 0;
  const check: any[] = run.model_check ?? [];
  const checkState = check.length === 0 ? (run.status === "checking" ? "running" : "pending")
    : check.every((c) => c.ok) ? "done" : "failed";
  const files = run.files.map((f: any) => f.name).join(" and ");

  return (
    <div className="stack">
      <div className="page-head">
        <div className="grow">
          <h1 style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            Run <span className="mono" style={{ fontSize: 16 }}>{run.id}</span><RunBadge status={run.status} />
          </h1>
          <p>
            {files}. {run.declaration.classification}, sensitivity: {run.declaration.sensitivity.join(", ")}.
            {" "}Primary model {run.models.primary}{run.models.secondary ? `, secondary ${run.models.secondary}` : ""}.
            {run.stig && <>{" "}STIG: {run.stig.title} {run.stig.version}{run.stig.mode === "builtin" ? " (built-in)" : ""}.</>}
          </p>
          {run.target && run.target.id !== "default" && <p>Target: {run.target.name} ({run.target.platform_label}).</p>}
          {run.stig?.note && <Notice tone="warning">{run.stig.note}</Notice>}
          {run.target?.note && <Notice tone="warning">{run.target.note}</Notice>}
        </div>
        <div className="actions">
          {(run.status === "running" || run.status === "checking") && (
            <button type="button" className="btn" onClick={() => act(() => api.pause(run.id))}><Pause className="icon" aria-hidden />Pause</button>
          )}
          {paused && (
            <button type="button" className="btn primary" onClick={() => act(() => api.resume(run.id))}><Play className="icon" aria-hidden />Resume</button>
          )}
          {active && (
            <button type="button" className="btn danger" onClick={() => act(() => api.end(run.id))}><Square className="icon" aria-hidden />End</button>
          )}
          {run.resumable && (
            <button type="button" className="btn primary" onClick={() => act(() => api.resume(run.id))}><Play className="icon" aria-hidden />Resume this run</button>
          )}
          {run.has_results && (
            <button type="button" className="btn primary" onClick={() => go(summary?.review_pending ? "review" : "results")}>
              {summary?.review_pending ? `Review ${summary.review_pending} flagged` : "View results"}
            </button>
          )}
          {!active && onNew && (
            <button type="button" className="btn" onClick={onNew}><Plus className="icon" aria-hidden />Start new run</button>
          )}
        </div>
      </div>

      {error && <Notice tone="critical">{error}</Notice>}
      {run.status === "failed" && <Notice tone="critical"><b>The run stopped on an error.</b> {run.error} Completed steps are saved; fix the cause and resume.</Notice>}
      {paused && <Notice tone="warning">Paused. The run holds after the rule in progress and sends nothing new to the model until you resume.</Notice>}
      {run.status === "ended" && <Notice>This run was ended before it finished. Completed steps are saved and it can be resumed.</Notice>}
      {run.status === "interrupted" && <Notice tone="warning">The service restarted while this run was in progress. Completed steps are saved and it can be resumed.</Notice>}
      {run.status === "completed" && summary && (
        <Notice tone="good">
          Finished in {duration(run.duration)}. {summary.total} rules reconciled, {summary.by_status.Open} open
          {summary.review_pending > 0 ? `, ${summary.review_pending} waiting for your review before export.` : ". Nothing is waiting for review."}
        </Notice>
      )}

      <div className="cols run">
        <section className="panel" aria-label="Steps">
          <div className="panel-head"><h2>Steps</h2></div>
          <ol className="timeline">
            <li className={checkState}>
              <span className="tl-dot"><StepMark state={checkState} paused={paused} /></span>
              <div>
                <div className="tl-name">Model check</div>
                <div className="tl-desc">
                  {check.length === 0 ? "Confirms the selected models before any rule is sent"
                    : check.map((c) => `${c.model || c.role}: ${c.ok ? "ready" : c.detail}`).join("; ")}
                </div>
              </div>
            </li>
            {run.steps.map((step: any, i: number) => (
              <li key={step.key} className={`${step.state} ${paused ? "paused" : ""}`}>
                <span className="tl-dot"><StepMark state={step.state} paused={paused} number={i + 1} /></span>
                <div>
                  <button type="button" className="tl-btn"
                          aria-pressed={shown.key === step.key} onClick={() => setSelected(step.key)}>
                    <span className="tl-name">{step.name}</span>
                  </button>
                  <div className="tl-desc">{step.description}</div>
                </div>
                <span className="tl-time num">{step.state === "failed" ? "Failed" : duration(step.duration)}</span>
              </li>
            ))}
          </ol>
        </section>

        <section className="panel" aria-label="Activity">
          <div className="panel-head">
            <h2>{shown.state === "running" ? (paused ? "Paused in" : "Now running") : "Activity"}: {shown.name}</h2>
            <Badge tone="outline">{shown.type === "script" ? "Script" : "Agent"}</Badge>
          </div>
          {total > 0 && (
            <div className="panel-pad stack" style={{ gap: 10 }}>
              <div className="small">
                <b className="num">{finished.length} of {total}</b> rules checked
                {inFlight.length > 0 && <span className="muted">, {inFlight.length} in progress</span>}
              </div>
              <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={total} aria-valuenow={finished.length}>
                <span style={{ width: `${(finished.length / total) * 100}%` }} />
              </div>
              {inFlight.length > 0 && (
                <div className="rules">
                  {inFlight.map((r) => <Badge key={r.vuln_id} tone="info" icon={LoaderCircle}><span className="mono">{r.vuln_id}</span></Badge>)}
                </div>
              )}
              {finished.length > 0 && (
                <div className="rules">
                  {finished.slice(-6).reverse().map((r) => (
                    <span key={r.vuln_id} className="small" style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                      <span className="mono">{r.vuln_id}</span><StatusBadge status={r.verdict} />
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
          <div className="console" aria-live="off" tabIndex={0} aria-label={`Status messages for ${shown.name}`}>
            <div>
              {lines.length === 0 && (
                <div className="log muted">
                  {shown.state === "pending" ? "This step has not started." : shown.state === "running"
                    ? "Waiting for the first status message from this step." : "No status messages were recorded for this step."}
                </div>
              )}
              {lines.map((line, i) => <div key={i} className={`log ${line.level}`}>{line.text}</div>)}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

function StepMark({ state, paused, number }: { state: string; paused: boolean; number?: number }) {
  if (state === "done") return <Check className="icon" aria-label="Done" />;
  if (state === "failed") return <X className="icon" aria-label="Failed" />;
  if (state === "running") {
    return paused ? <CirclePause className="icon" aria-label="Paused" /> : <LoaderCircle className="icon" aria-label="Running" />;
  }
  return <span className="num">{number ?? ""}</span>;
}
