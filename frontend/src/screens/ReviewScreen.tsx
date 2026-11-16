import { Check, Replace, SkipForward, Undo2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Empty, Evidence, Notice, ScannerDetails, SeverityBadge, StatusBadge, sourceLabel, statusLabel } from "../ui";

const OUTCOMES = ["Open", "NotAFinding", "Not_Applicable"];

export default function ReviewScreen({ runId, run, decisionVersion, go }: { runId: string | null; run: any; decisionVersion: number; go: (r: string) => void }) {
  const [review, setReview] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const ready = Boolean(runId && run?.has_results);

  const load = useCallback(() => {
    if (!ready) { setReview(null); return; }
    api.review(runId!).then((body) => { setReview(body); setError(null); }, (e) => setError(e.message));
  }, [runId, ready]);
  useEffect(load, [load, decisionVersion]);

  if (!ready) {
    return <Empty title="Nothing to review yet" action={<button type="button" className="btn" onClick={() => go("run")}>Go to the run</button>}>
      Flagged verdicts appear here when a run finishes.</Empty>;
  }
  if (!review) return error ? <Notice tone="critical">{error}</Notice> : <p className="muted">Loading review items.</p>;

  const act = async (call: () => Promise<any>) => {
    setError(null);
    try { await call(); load(); } catch (e: any) { setError(e.message); }
  };
  const decided = review.required.length - review.pending;

  return (
    <div className="stack">
      <div className="page-head">
        <div className="grow">
          <h1 style={{ display: "flex", gap: 10, alignItems: "center" }}>
            Review {review.pending > 0 && <Badge tone="warning">{review.pending} waiting</Badge>}
          </h1>
          <p>ARES flags a verdict when its confidence is low, a CAT I finding is not near certain, or the agent could not finish. Your decision is saved at once and goes into every export.</p>
        </div>
      </div>
      {error && <Notice tone="critical">{error}</Notice>}
      {review.required.length === 0
        ? <Notice tone="good">No verdict in this run was flagged for review.</Notice>
        : review.pending === 0
          ? <Notice tone="good">All {review.required.length} flagged {review.required.length === 1 ? "verdict has" : "verdicts have"} a decision. Exports now reflect them.</Notice>
          : <Notice>{decided} of {review.required.length} decided.</Notice>}

      {review.required.map((card: any) => (
        <Card key={card.vuln_id} card={card}
              onDecide={(action, status) => act(() => api.decide(runId!, card.vuln_id, action, status))}
              onUndo={() => act(() => api.undo(runId!, card.vuln_id))} />
      ))}

      {review.optional.length > 0 && (
        <details className="section">
          <summary>Optional review ({review.optional.length})</summary>
          <p className="muted" style={{ margin: "4px 0 12px" }}>Verdicts the agents reached with enough confidence. No decision is needed; you can still approve or override any of them.</p>
          <div className="stack">
            {review.optional.map((card: any) => (
              <Card key={card.vuln_id} card={card} optional
                    onDecide={(action, status) => act(() => api.decide(runId!, card.vuln_id, action, status))}
                    onUndo={() => act(() => api.undo(runId!, card.vuln_id))} />
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

function Card({ card, optional, onDecide, onUndo }: { card: any; optional?: boolean; onDecide: (action: string, status?: string) => void; onUndo: () => void }) {
  const action = card.decision?.action;
  const decided = action === "approved" || action === "overridden";
  const recommended = card.final_status;
  // Up to three outcomes: confirm the recommendation, or one of the other two.
  const canApprove = OUTCOMES.includes(recommended);
  const overrides = OUTCOMES.filter((s) => s !== recommended);

  return (
    <article className={`card ${decided ? "decided" : ""}`} aria-label={`Review ${card.vuln_id}`}>
      <div className="card-head">
        <span className="card-id">{card.vuln_id}</span>
        <SeverityBadge severity={card.severity} />
        {action === "skipped" && <Badge tone="neutral">Skipped for now</Badge>}
      </div>
      {card.rule_title && <p style={{ marginTop: 6, maxWidth: "90ch" }}>{card.rule_title}</p>}

      <div className="card-rec">
        {action === "approved" && <>Approved: {statusLabel(recommended)}</>}
        {action === "overridden" && <>Overridden to {statusLabel(card.decision.status)} (ARES recommended {statusLabel(recommended)})</>}
        {!decided && <>ARES recommendation: {statusLabel(recommended)}, pending {optional ? "optional review" : "your decision"}</>}
      </div>
      <div className="card-meta">
        <span>Confidence now: <b className="num">{card.confidence_score}%</b></span>
        <span>{sourceLabel(card.source)}</span>
        {card.conflict_type && <span>Conflict: {card.conflict_type.replace(/_/g, " ")}</span>}
      </div>
      {card.reason && <p style={{ marginTop: 10 }}><b>Why this was flagged:</b> {card.reason}.</p>}
      {card.error && <div style={{ marginTop: 10 }}><Notice tone="critical">{card.error}</Notice></div>}

      <div className="block-title">Evidence</div>
      {card.evidence || card.commands_executed.length
        ? <Evidence item={card} />
        : <p className="muted">No evidence was recorded. Check the rule on the target before deciding.</p>}

      <details className="more">
        <summary>Scanner details and secondary opinion</summary>
        <div className="block-title">What each scanner reported</div>
        <ScannerDetails item={card} />
        <div className="block-title">Secondary opinion</div>
        {card.secondary_opinion
          ? <p>{typeof card.secondary_opinion === "string" ? card.secondary_opinion : JSON.stringify(card.secondary_opinion)}</p>
          : <p className="muted">No secondary opinion was recorded for this rule.</p>}
      </details>

      <div className="actions">
        {decided ? (
          <button type="button" className="btn" onClick={onUndo}><Undo2 className="icon" aria-hidden />Undo decision</button>
        ) : (
          <>
            {canApprove && (
              <button type="button" className="btn primary" onClick={() => onDecide("approve")}>
                <Check className="icon" aria-hidden />Approve {statusLabel(recommended)}
              </button>
            )}
            {overrides.slice(0, canApprove ? 2 : 3).map((status) => (
              <button key={status} type="button" className="btn" onClick={() => onDecide("override", status)}>
                <Replace className="icon" aria-hidden />{canApprove ? "Override to" : "Set to"} {statusLabel(status)}
              </button>
            ))}
            {!optional && action !== "skipped" && (
              <button type="button" className="btn quiet" onClick={() => onDecide("skip")}><SkipForward className="icon" aria-hidden />Skip for now</button>
            )}
            {action === "skipped" && (
              <button type="button" className="btn quiet" onClick={onUndo}><Undo2 className="icon" aria-hidden />Undo skip</button>
            )}
          </>
        )}
      </div>
    </article>
  );
}
