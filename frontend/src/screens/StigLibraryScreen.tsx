import { ChevronDown, ChevronRight, FileUp, Search, Trash2, Upload } from "lucide-react";
import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Badge, Empty, Notice, bytes, when } from "../ui";

const SEVERITY_ORDER = ["CAT I", "CAT II", "CAT III"];

function ImportPanel({ maxMb, onImported }: { maxMb: number; onImported: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<any>(null);

  const submit = async () => {
    if (!file) return;
    setBusy(true); setError(null); setReport(null);
    const form = new FormData();
    form.set("file", file);
    try { setReport(await api.importStigs(form)); setFile(null); onImported(); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  };

  return (
    <section className="panel panel-pad stack">
      <h2>Import STIGs</h2>
      <p className="hint">
        Download STIGs from DoD Cyber Exchange (the STIG Library compilation zip, single STIG zips or SCAP
        benchmark zips) and upload them here. ARES opens the zips inside the zip, imports every STIG it finds and
        keeps each release, so older versions stay available. Up to {maxMb} MB per upload.
      </p>
      <label className={`drop ${file ? "filled" : ""} ${over ? "over" : ""}`}
             onDragOver={(e) => { e.preventDefault(); setOver(true); }}
             onDragLeave={() => setOver(false)}
             onDrop={(e) => { e.preventDefault(); setOver(false); setFile(e.dataTransfer.files[0] ?? null); }}>
        <input type="file" accept=".zip,.xml" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        <span className="muted small" style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <FileUp className="icon" aria-hidden />STIG download
        </span>
        {file
          ? <><span className="name">{file.name}</span><span className="hint num">{bytes(file.size)}. Select to replace.</span></>
          : <><span className="name">Choose a file or drop it here</span><span className="hint">.zip from DoD Cyber Exchange, or an XCCDF .xml</span></>}
      </label>
      <div className="actions">
        <button type="button" className="btn primary" disabled={!file || busy} onClick={submit}>
          <Upload className="icon" aria-hidden />{busy ? "Importing. Large library zips take a minute or two." : "Import"}
        </button>
      </div>
      {error && <Notice tone="critical">{error}</Notice>}
      {report && <ImportReport report={report} />}
    </section>
  );
}

function ImportReport({ report }: { report: any }) {
  const imported = report.imported.length, unchanged = report.unchanged.length;
  return (
    <div className="stack">
      <Notice tone={imported ? "good" : "info"}>
        {imported
          ? `Imported ${imported} STIG release${imported === 1 ? "" : "s"} from ${report.upload}.`
          : `Nothing new in ${report.upload}.`}
        {unchanged > 0 && ` ${unchanged} already in the library were left as they were.`}
      </Notice>
      {report.changes.length > 0 && (
        <div>
          <div className="block-title">New releases of STIGs you already had</div>
          <ul className="small">
            {report.changes.map((c: any) => (
              <li key={`${c.key}-${c.to}`}>
                {c.title}: {c.from} to {c.to}. {c.added_count} rules added, {c.removed_count} removed, {c.changed_count} changed.
              </li>
            ))}
          </ul>
        </div>
      )}
      {report.errors.length > 0 && (
        <Notice tone="warning">
          {report.errors.length} file{report.errors.length === 1 ? " was" : "s were"} skipped:
          <ul className="small">
            {report.errors.slice(0, 10).map((e: any, i: number) => <li key={i}><span className="mono">{e.file.split("/").pop()}</span>: {e.error}</li>)}
          </ul>
          {report.errors.length > 10 && <span className="small">And {report.errors.length - 10} more.</span>}
        </Notice>
      )}
    </div>
  );
}

function Detail({ id }: { id: string }) {
  const [detail, setDetail] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.stig(id).then(setDetail, (e) => setError(e.message)); }, [id]);
  if (error) return <Notice tone="critical">{error}</Notice>;
  if (!detail) return <p className="muted small">Loading.</p>;
  const changes = detail.changes;
  return (
    <div className="stack" style={{ padding: "4px 0 12px" }}>
      <dl className="kv">
        <dt>Benchmark ID</dt><dd className="mono">{detail.benchmark_id}</dd>
        <dt>Release</dt><dd>{detail.release_info || detail.version_label}</dd>
        <dt>Imported from</dt><dd className="mono" style={{ whiteSpace: "normal" }}>{detail.source_file}</dd>
        <dt>SHA-256</dt><dd className="mono small" style={{ wordBreak: "break-all", whiteSpace: "normal" }}>{detail.sha256}</dd>
        {detail.platforms.length > 0 && <><dt>Platforms</dt><dd className="mono">{detail.platforms.join(", ")}</dd></>}
      </dl>
      {changes ? (
        <div>
          <div className="block-title">Changes since {changes.from}</div>
          <p className="small">{changes.added_count} rules added, {changes.removed_count} removed, {changes.changed_count} changed.</p>
          {[["Added", changes.added], ["Removed", changes.removed], ["Changed", changes.changed]].map(([label, rows]: any) =>
            rows.length > 0 && (
              <details key={label}>
                <summary className="small">{label} ({rows.length})</summary>
                <ul className="small">
                  {rows.map((r: any) => (
                    <li key={r.vuln_id}><span className="mono">{r.vuln_id}</span> {r.severity} {r.rule_title}
                      {r.fields && <span className="muted"> ({r.fields.join(", ").replace(/_/g, " ")})</span>}</li>
                  ))}
                </ul>
              </details>
            ))}
        </div>
      ) : <p className="small muted">This is the first release of this STIG in the library.</p>}
    </div>
  );
}

export default function StigLibraryScreen() {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [showOlder, setShowOlder] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);

  const load = useCallback(() => api.stigs().then(setData, (e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);

  const rows = useMemo(() => {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    return (data?.entries ?? []).filter((e: any) =>
      (showOlder || e.latest) &&
      words.every((w) => `${e.title} ${e.key} ${e.version_label} ${e.platform_label}`.toLowerCase().includes(w)));
  }, [data, query, showOlder]);

  const remove = async (id: string) => {
    setConfirming(null); setError(null);
    try { await api.removeStig(id); if (open === id) setOpen(null); await load(); } catch (e: any) { setError(e.message); }
  };

  if (!data) return error ? <Notice tone="critical">{error}</Notice> : <p className="muted">Loading the STIG library.</p>;
  const total = data.entries.length;
  const titles = new Set(data.entries.map((e: any) => e.key)).size;

  return (
    <div className="stack">
      <div className="page-head">
        <div className="grow">
          <h1>STIG library</h1>
          <p>STIG content that runs can be assessed against. When a run starts, ARES reads which STIG the scan files are for and uses the matching release from this library. Without a match it uses the built-in {data.builtin.title} {data.builtin.version}.</p>
        </div>
      </div>
      <ImportPanel maxMb={data.max_upload_mb} onImported={load} />
      {error && <Notice tone="critical">{error}</Notice>}

      {total === 0 ? (
        <Empty title="No STIGs imported yet">Import a download from DoD Cyber Exchange above. Until then, runs use the built-in {data.builtin.title} {data.builtin.version}.</Empty>
      ) : (
        <section className="panel">
          <div className="toolbar">
            <label className="search">
              <Search className="icon" aria-hidden />
              <input type="search" placeholder="Search by name, ID, platform or version" aria-label="Search STIGs"
                     value={query} onChange={(e) => setQuery(e.target.value)} />
            </label>
            <label className="choice">
              <input type="checkbox" checked={showOlder} onChange={(e) => setShowOlder(e.target.checked)} />Show older releases
            </label>
            <span className="hint num" style={{ alignSelf: "center" }}>{titles} STIGs, {total} releases</span>
          </div>
          <div className="table-wrap">
            <table className="grid">
              <thead>
                <tr><th></th><th>STIG</th><th>Platform</th><th>Release</th><th>Type</th><th>Rules</th><th>CAT I / II / III</th><th>Imported</th><th></th></tr>
              </thead>
              <tbody>
                {rows.map((e: any) => (
                  <Fragment key={e.id}>
                    <tr onClick={() => setOpen(open === e.id ? null : e.id)}>
                      <td style={{ width: 28 }}>
                        <button type="button" className="btn quiet sm" aria-expanded={open === e.id}
                                aria-label={`${open === e.id ? "Hide" : "Show"} details for ${e.title}`}
                                onClick={(ev) => { ev.stopPropagation(); setOpen(open === e.id ? null : e.id); }}>
                          {open === e.id ? <ChevronDown className="icon" aria-hidden /> : <ChevronRight className="icon" aria-hidden />}
                        </button>
                      </td>
                      <td className="title">{e.title}<div className="mono muted small">{e.key}</div></td>
                      <td className="small">{e.platform_label}</td>
                      <td>{e.version_label}{!e.latest && <span className="small muted"> (older)</span>}
                        {e.benchmark_date && <div className="small muted">{e.benchmark_date}</div>}</td>
                      <td>{e.kind === "scap"
                        ? <Badge tone="info">SCAP, {e.automated_count} automated</Badge>
                        : <>{"Manual"}{e.scap_available && <div className="small muted">SCAP content also imported</div>}</>}</td>
                      <td className="num">{e.rule_count}</td>
                      <td className="num">{SEVERITY_ORDER.map((s) => e.severity_counts[s] ?? 0).join(" / ")}</td>
                      <td className="small">{when(e.imported_at)}</td>
                      <td onClick={(ev) => ev.stopPropagation()}>
                        <div className="actions" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
                          {confirming === e.id ? (
                            <>
                              <button type="button" className="btn sm danger" onClick={() => remove(e.id)}>Remove release</button>
                              <button type="button" className="btn sm quiet" onClick={() => setConfirming(null)}>Cancel</button>
                            </>
                          ) : (
                            <button type="button" className="btn sm quiet" aria-label={`Remove ${e.title} ${e.version_label}`}
                                    title="Remove this release from the library" onClick={() => setConfirming(e.id)}>
                              <Trash2 className="icon" aria-hidden />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {open === e.id && (
                      <tr style={{ cursor: "default" }}><td></td><td colSpan={8} style={{ whiteSpace: "normal" }}><Detail id={e.id} /></td></tr>
                    )}
                  </Fragment>
                ))}
                {rows.length === 0 && (
                  <tr style={{ cursor: "default" }}><td></td><td colSpan={8} className="muted">No STIGs match this search.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
