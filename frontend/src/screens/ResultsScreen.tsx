import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, Columns3, Download, Search } from "lucide-react";
import { useEffect, useState } from "react";
import { api, downloadExport } from "../api";
import {
  CloseButton, Empty, Evidence, Notice, ScannerDetails, SEVERITIES, SEVERITY_LABEL, SOURCE_LABEL,
  STATUSES, STATUS_LABEL, SeverityBadge, StatusBadge, sourceLabel,
} from "../ui";

const COLUMNS = [
  { id: "vuln_id", label: "Rule", sort: true, fixed: true },
  { id: "rule_title", label: "Title", sort: false },
  { id: "severity", label: "Severity", sort: true },
  { id: "status", label: "Verdict", sort: true },
  { id: "tool1_status", label: "Tool 1", sort: false },
  { id: "tool2_status", label: "Tool 2", sort: false },
  { id: "confidence", label: "Confidence", sort: true },
  { id: "source", label: "How it was decided", sort: true },
];
const EXPORTS = [
  ["ckl", "CKL", "STIG Viewer 2 checklist"], ["cklb", "CKLB", "STIG Viewer 3 checklist"],
  ["csv", "CSV", "One row per rule"], ["json", "JSON", "Full report with evidence"],
];
const PAGE_SIZE = 50;

function storedColumns(): string[] {
  try {
    const saved = JSON.parse(window.localStorage.getItem("ares-columns") ?? "null");
    if (Array.isArray(saved)) return saved;
  } catch { /* fall through to defaults */ }
  return COLUMNS.map((c) => c.id);
}

export default function ResultsScreen({ runId, run, summary, decisionVersion, go }: { runId: string | null; run: any; summary: any; decisionVersion: number; go: (r: string) => void }) {
  if (!run) {
    return <Empty title="No results yet" action={<button type="button" className="btn primary" onClick={() => go("run")}>Start a run</button>}>
      Results appear here when a run finishes.</Empty>;
  }
  if (!run.has_results || !summary || !runId) {
    return <Empty title="Results are not ready" action={<button type="button" className="btn" onClick={() => go("run")}>Go to the run</button>}>
      {run.status === "completed" ? "Loading results." : "This run has not finished. Results appear when the last step completes."}</Empty>;
  }
  return (
    <div className="stack">
      <div className="page-head">
        <div className="grow">
          <h1>Results</h1>
          <p>Reconciled verdict for every rule in run <span className="mono">{run.id}</span>. Human decisions from the Review screen are already applied.</p>
        </div>
      </div>
      <Headline summary={summary} go={go} />
      <Charts summary={summary} />
      <Grid runId={runId} decisionVersion={decisionVersion} />
      <Exports runId={runId} pending={summary.review_pending} />
    </div>
  );
}

function Headline({ summary, go }: { summary: any; go: (r: string) => void }) {
  const tiles = [
    ["Rules", summary.total, `${summary.agreements} where both tools agreed`],
    ["Open", summary.by_status.Open, "Findings to fix"],
    ["Not a finding", summary.by_status.NotAFinding, "Compliant"],
    ["Not applicable", summary.by_status.Not_Applicable, ""],
    ["Not reviewed", summary.by_status.Not_Reviewed, "No verdict reached"],
  ];
  return (
    <div className="tiles">
      {tiles.map(([label, value, sub]) => (
        <div className="tile" key={label}>
          <div className="label">{label}</div><div className="value num">{value}</div><div className="sub">{sub}</div>
        </div>
      ))}
      <div className="tile">
        <div className="label">Waiting for review</div>
        <div className="value num">{summary.review_pending}</div>
        <div className="sub">
          {summary.review_required === 0 ? "Nothing was flagged"
            : <>of {summary.review_required} flagged. <button type="button" className="link" onClick={() => go("review")}>Open review</button></>}
        </div>
      </div>
    </div>
  );
}

function Legend({ counts }: { counts: Record<string, number> }) {
  return (
    <div className="legend">
      {STATUSES.map((s) => <span key={s}><i className={`fill-${s}`} />{STATUS_LABEL[s]} <b className="num">{counts[s]}</b></span>)}
    </div>
  );
}

function SegBar({ counts, thin }: { counts: Record<string, number>; thin?: boolean }) {
  const total = STATUSES.reduce((sum, s) => sum + counts[s], 0);
  if (total === 0) return <div className={`segbar ${thin ? "thin" : ""}`} />;
  return (
    <div className={`segbar ${thin ? "thin" : ""}`} role="img"
         aria-label={STATUSES.map((s) => `${STATUS_LABEL[s]} ${counts[s]}`).join(", ")}>
      {STATUSES.filter((s) => counts[s] > 0).map((s) => (
        <span key={s} className={`fill-${s}`} style={{ flex: counts[s] }} title={`${STATUS_LABEL[s]}: ${counts[s]}`} />
      ))}
    </div>
  );
}

function Charts({ summary }: { summary: any }) {
  const sources = Object.entries(summary.by_source as Record<string, number>).sort((a, b) => b[1] - a[1]);
  const maxSource = Math.max(1, ...sources.map(([, n]) => n));
  const maxSeverity = Math.max(1, ...SEVERITIES.map((sev) => STATUSES.reduce((n, s) => n + summary.by_severity[sev][s], 0)));
  return (
    <div className="cols three">
      <section className="panel panel-pad">
        <div className="chart-title">Verdicts</div>
        <div className="chart-sub">Share of all {summary.total} rules</div>
        <SegBar counts={summary.by_status} />
        <Legend counts={summary.by_status} />
      </section>
      <section className="panel panel-pad">
        <div className="chart-title">Verdicts by severity</div>
        <div className="chart-sub">Same colours as Verdicts</div>
        <div className="bars">
          {SEVERITIES.map((sev) => {
            const row = summary.by_severity[sev];
            const count = STATUSES.reduce((n, s) => n + row[s], 0);
            return (
              <div key={sev} style={{ display: "contents" }}>
                <span>{SEVERITY_LABEL[sev]}</span>
                <div style={{ width: `${Math.max((count / maxSeverity) * 100, count ? 2 : 0)}%` }}><SegBar counts={row} thin /></div>
                <span className="val num">{count}</span>
              </div>
            );
          })}
        </div>
      </section>
      <section className="panel panel-pad">
        <div className="chart-title">How verdicts were decided</div>
        <div className="chart-sub">Rules per source</div>
        <div className="bars">
          {sources.map(([source, count]) => (
            <div key={source} style={{ display: "contents" }}>
              <span>{sourceLabel(source)}</span>
              <div><span className="fill-source" style={{ display: "block", height: 14, width: `${(count / maxSource) * 100}%`, minWidth: 3 }} title={`${sourceLabel(source)}: ${count}`} /></div>
              <span className="val num">{count}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function Grid({ runId, decisionVersion }: { runId: string; decisionVersion: number }) {
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState({ severity: "", status: "", source: "" });
  const [sort, setSort] = useState<{ key: string; dir: string }>({ key: "", dir: "asc" });
  const [page, setPage] = useState(1);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [visible, setVisible] = useState<string[]>(storedColumns);
  const [picker, setPicker] = useState(false);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => { const t = window.setTimeout(() => { setQuery(q); setPage(1); }, 250); return () => window.clearTimeout(t); }, [q]);
  useEffect(() => {
    let stale = false;
    api.findings(runId, { q: query, ...filters, sort: sort.key, dir: sort.dir, page, page_size: PAGE_SIZE })
      .then((body) => { if (!stale) { setData(body); setError(null); } }, (e) => !stale && setError(e.message));
    return () => { stale = true; };
  }, [runId, query, filters, sort, page, decisionVersion]);
  useEffect(() => { try { window.localStorage.setItem("ares-columns", JSON.stringify(visible)); } catch { /* not saved */ } }, [visible]);

  const setFilter = (key: string, value: string) => { setFilters((f) => ({ ...f, [key]: value })); setPage(1); };
  const toggleSort = (key: string) => {
    setSort((s) => s.key !== key ? { key, dir: "asc" } : s.dir === "asc" ? { key, dir: "desc" } : { key: "", dir: "asc" });
    setPage(1);
  };
  const columns = COLUMNS.filter((c) => c.fixed || visible.includes(c.id));
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const first = data && data.total ? (data.page - 1) * PAGE_SIZE + 1 : 0;

  const cell = (row: any, id: string) => {
    switch (id) {
      case "vuln_id": return <span className="mono">{row.vuln_id}</span>;
      case "rule_title": return row.rule_title;
      case "severity": return <SeverityBadge severity={row.severity} />;
      case "status": return <><StatusBadge status={row.status} />{row.decision?.action === "overridden" && <span className="small muted"> overridden</span>}{row.decision?.action === "approved" && <span className="small muted"> approved</span>}</>;
      case "tool1_status": return <StatusBadge status={row.tool1_status} />;
      case "tool2_status": return <StatusBadge status={row.tool2_status} />;
      case "confidence": return <span className="num">{row.confidence_score}%</span>;
      default: return sourceLabel(row.source);
    }
  };

  return (
    <section className="panel" aria-label="Findings">
      <div className="toolbar">
        <label className="field search"><span>Find a rule</span>
          <div style={{ position: "relative" }}>
            <Search className="icon" aria-hidden />
            <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Rule number, rule ID or title" />
          </div>
        </label>
        <label className="field"><span>Severity</span>
          <select value={filters.severity} onChange={(e) => setFilter("severity", e.target.value)}>
            <option value="">All</option>{SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
          </select>
        </label>
        <label className="field"><span>Verdict</span>
          <select value={filters.status} onChange={(e) => setFilter("status", e.target.value)}>
            <option value="">All</option>{STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
          </select>
        </label>
        <label className="field"><span>How it was decided</span>
          <select value={filters.source} onChange={(e) => setFilter("source", e.target.value)}>
            <option value="">All</option>
            {["agreement", "gap_coverage_agent", "determination_agent"].map((s) => <option key={s} value={s}>{SOURCE_LABEL[s]}</option>)}
          </select>
        </label>
        <div className="menu">
          <button type="button" className="btn" aria-expanded={picker} onClick={() => setPicker((p) => !p)}>
            <Columns3 className="icon" aria-hidden />Columns
          </button>
          {picker && (
            <div className="menu-pop">
              {COLUMNS.filter((c) => !c.fixed).map((c) => (
                <label key={c.id}>
                  <input type="checkbox" checked={visible.includes(c.id)}
                         onChange={() => setVisible((v) => v.includes(c.id) ? v.filter((x) => x !== c.id) : [...v, c.id])} />
                  {c.label}
                </label>
              ))}
            </div>
          )}
        </div>
      </div>
      {error && <div className="panel-pad"><Notice tone="critical">{error}</Notice></div>}
      <div className="table-wrap">
        <table className="grid">
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.id} aria-sort={sort.key === c.id ? (sort.dir === "asc" ? "ascending" : "descending") : undefined}>
                  {c.sort
                    ? <button type="button" onClick={() => toggleSort(c.id)}>{c.label}
                        {sort.key === c.id && (sort.dir === "asc" ? <ArrowUp className="icon" aria-hidden /> : <ArrowDown className="icon" aria-hidden />)}
                      </button>
                    : c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data?.rows.map((row: any) => (
              <tr key={row.vuln_id} tabIndex={0} onClick={() => setOpen(row.vuln_id)}
                  onKeyDown={(e) => { if (e.key === "Enter") setOpen(row.vuln_id); }}>
                {columns.map((c) => <td key={c.id} className={c.id === "rule_title" ? "title" : ""}>{cell(row, c.id)}</td>)}
              </tr>
            ))}
            {data && data.rows.length === 0 && (
              <tr><td colSpan={columns.length} className="muted" style={{ cursor: "default", padding: 24 }}>No rules match. Clear the search or filters to see all rules.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="pager">
        <span className="grow num">{data ? `${first} to ${Math.min(first + PAGE_SIZE - 1, data.total)} of ${data.total} rules` : "Loading rules"}
          {!sort.key && data ? ". Scored rules first, then severity." : ""}</span>
        <button type="button" className="btn sm" disabled={page <= 1} onClick={() => setPage(page - 1)} aria-label="Previous page"><ChevronLeft className="icon" aria-hidden /></button>
        <span className="num">Page {page} of {pages}</span>
        <button type="button" className="btn sm" disabled={page >= pages} onClick={() => setPage(page + 1)} aria-label="Next page"><ChevronRight className="icon" aria-hidden /></button>
      </div>
      {open && <Drawer runId={runId} vulnId={open} decisionVersion={decisionVersion} onClose={() => setOpen(null)} />}
    </section>
  );
}

function Drawer({ runId, vulnId, decisionVersion, onClose }: { runId: string; vulnId: string; decisionVersion: number; onClose: () => void }) {
  const [item, setItem] = useState<any>(null);
  useEffect(() => { api.finding(runId, vulnId).then(setItem, () => setItem(null)); }, [runId, vulnId, decisionVersion]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Detailed view of ${vulnId}`}>
        <div className="drawer-head">
          <div className="grow">
            <div className="card-id">{vulnId}</div>
            {item?.rule_title && <p style={{ marginTop: 4 }}>{item.rule_title}</p>}
          </div>
          <CloseButton onClick={onClose} label="Close detailed view" />
        </div>
        {!item ? <p className="muted">Loading rule.</p> : (
          <>
            <dl className="kv">
              <dt>Verdict</dt><dd><StatusBadge status={item.status} /></dd>
              {item.decision?.action === "overridden" && <><dt>ARES recommended</dt><dd><StatusBadge status={item.final_status} /></dd></>}
              {item.decision && item.decision.action !== "skipped" && <><dt>Human decision</dt><dd>{item.decision.action === "approved" ? "Approved" : "Overridden"}</dd></>}
              <dt>Severity</dt><dd><SeverityBadge severity={item.severity} /></dd>
              <dt>Confidence now</dt><dd className="num">{item.confidence_score}%</dd>
              <dt>How it was decided</dt><dd>{sourceLabel(item.source)}</dd>
              <dt>Rule ID</dt><dd className="mono">{item.rule_id || "Not in scan data"}</dd>
              {item.reason && <><dt>Flagged for review</dt><dd>{item.reason}</dd></>}
            </dl>
            <div className="block-title">Evidence</div>
            {item.evidence || item.commands_executed.length ? <Evidence item={item} /> : <p className="muted">No evidence was recorded for this rule.</p>}
            {item.error && <><div className="block-title">Agent error</div><Notice tone="critical">{item.error}</Notice></>}
            <div className="block-title">Scanner details</div>
            <ScannerDetails item={item} />
          </>
        )}
      </aside>
    </>
  );
}

function Exports({ runId, pending }: { runId: string; pending: number }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const build = async (format: string) => {
    setBusy(format); setError(null);
    try { await downloadExport(runId, format); } catch (e: any) { setError(e.message); } finally { setBusy(null); }
  };
  return (
    <section className="panel">
      <div className="panel-head"><h2>Export</h2></div>
      <div className="panel-pad stack">
        {pending > 0 && <Notice tone="warning">{pending} flagged {pending === 1 ? "rule is" : "rules are"} still waiting for review. Exports carry the ARES recommendation for those until you decide.</Notice>}
        {error && <Notice tone="critical">{error}</Notice>}
        <div className="actions">
          {EXPORTS.map(([format, label, hint]) => (
            <button key={format} type="button" className="btn" disabled={busy !== null} onClick={() => build(format)} title={hint}>
              <Download className="icon" aria-hidden />{busy === format ? `Building ${label}` : `Download ${label}`}
            </button>
          ))}
        </div>
        <p className="hint">Each file is built when you click, from the verdicts and decisions as they stand now.</p>
      </div>
    </section>
  );
}
