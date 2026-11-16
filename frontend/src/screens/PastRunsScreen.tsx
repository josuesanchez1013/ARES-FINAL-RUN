import { Pin, Play, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { Empty, Notice, RunBadge, duration, when } from "../ui";

export default function PastRunsScreen({ viewId, onOpen, onChanged }: { viewId: string | null; onOpen: (id: string, route: string) => void; onChanged: () => void }) {
  const [runs, setRuns] = useState<any[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);

  const load = useCallback(() => api.runs().then((body) => setRuns(body.runs), (e) => setError(e.message)), []);
  useEffect(() => { load(); const t = window.setInterval(load, 5000); return () => window.clearInterval(t); }, [load]);

  const act = async (call: () => Promise<any>) => {
    setError(null); setConfirming(null);
    try { await call(); await load(); onChanged(); } catch (e: any) { setError(e.message); }
  };

  if (!runs) return error ? <Notice tone="critical">{error}</Notice> : <p className="muted">Loading runs.</p>;
  return (
    <div className="stack">
      <div className="page-head">
        <div className="grow">
          <h1>Past runs</h1>
          <p>Open a run to see its results and review decisions. Keep a run to protect it from deletion and from the automatic clean-up of old runs.</p>
        </div>
      </div>
      {error && <Notice tone="critical">{error}</Notice>}
      {runs.length === 0 ? <Empty title="No runs yet">Runs are listed here as soon as they start.</Empty> : (
        <section className="panel table-wrap">
          <table className="grid">
            <thead>
              <tr><th>Started</th><th>Status</th><th>Duration</th><th>Files</th><th>Rules</th><th>Open</th><th>To review</th><th>Keep</th><th></th></tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.id} style={{ cursor: "default" }}>
                  <td>{when(run.created_at)}{run.id === viewId && <span className="small muted"> (in view)</span>}
                    <div className="mono muted">{run.id}</div></td>
                  <td><RunBadge status={run.status} /></td>
                  <td className="num">{duration(run.duration) || "Not started"}</td>
                  <td className="title">{run.files.map((f: any) => f.name).join(", ")}</td>
                  <td className="num">{run.counts?.total ?? ""}</td>
                  <td className="num">{run.counts?.open ?? ""}</td>
                  <td className="num">{run.counts?.review_pending ?? ""}</td>
                  <td>
                    <button type="button" className="btn sm pin" aria-pressed={run.keep}
                            aria-label={run.keep ? "Kept. Remove the Keep pin" : "Keep this run"}
                            onClick={() => act(() => api.keep(run.id, !run.keep))}>
                      <Pin className="icon" aria-hidden />{run.keep ? "Kept" : "Keep"}
                    </button>
                  </td>
                  <td>
                    <div className="actions" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
                      {run.resumable && (
                        <button type="button" className="btn sm" onClick={() => act(async () => { await api.resume(run.id); onOpen(run.id, "run"); })}>
                          <Play className="icon" aria-hidden />Resume this run
                        </button>
                      )}
                      <button type="button" className="btn sm" onClick={() => onOpen(run.id, run.has_results ? "results" : "run")}>Open</button>
                      {confirming === run.id ? (
                        <>
                          <button type="button" className="btn sm danger" onClick={() => act(() => api.remove(run.id))}>Delete run</button>
                          <button type="button" className="btn sm quiet" onClick={() => setConfirming(null)}>Cancel</button>
                        </>
                      ) : (
                        <button type="button" className="btn sm quiet" aria-label={`Delete run ${run.id}`}
                                disabled={run.keep || ["checking", "running", "paused"].includes(run.status)}
                                title={run.keep ? "Kept runs cannot be deleted" : "Delete run"}
                                onClick={() => setConfirming(run.id)}>
                          <Trash2 className="icon" aria-hidden />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
