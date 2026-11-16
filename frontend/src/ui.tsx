// Shared vocabulary: one label, one tone and one icon per state, used everywhere.
import {
  AlertTriangle, Check, CircleAlert, CircleDashed, CircleMinus, CirclePause, CircleSlash,
  Info, LoaderCircle, X,
} from "lucide-react";
import type { ReactNode } from "react";

export const STATUSES = ["Open", "NotAFinding", "Not_Applicable", "Not_Reviewed"] as const;
export const STATUS_LABEL: Record<string, string> = {
  Open: "Open", NotAFinding: "Not a finding",
  Not_Applicable: "Not applicable", Not_Reviewed: "Not reviewed",
};
const STATUS_TONE: Record<string, string> = {
  Open: "critical", NotAFinding: "good", Not_Applicable: "neutral", Not_Reviewed: "warning",
};
const STATUS_ICON: Record<string, any> = {
  Open: CircleAlert, NotAFinding: Check, Not_Applicable: CircleMinus, Not_Reviewed: CircleDashed,
};
export const SEVERITIES = ["high", "medium", "low"] as const;
export const SEVERITY_LABEL: Record<string, string> = { high: "CAT I", medium: "CAT II", low: "CAT III" };
export const SOURCE_LABEL: Record<string, string> = {
  agreement: "Tools agreed",
  determination_agent: "Disagreement resolved",
  gap_coverage_agent: "Gap validated",
  determination_agent_error: "Agent error",
  gap_coverage_agent_error: "Agent error",
};
export const sourceLabel = (s: string) => SOURCE_LABEL[s] ?? s.replace(/_/g, " ");
export const statusLabel = (s?: string | null) => (s ? STATUS_LABEL[s] ?? s : "No result");

const RUN_STATE: Record<string, [string, string, any]> = {
  checking: ["Checking models", "info", LoaderCircle],
  running: ["Running", "info", LoaderCircle],
  paused: ["Paused", "warning", CirclePause],
  completed: ["Completed", "good", Check],
  failed: ["Failed", "critical", CircleAlert],
  ended: ["Ended", "neutral", CircleSlash],
  interrupted: ["Interrupted", "warning", AlertTriangle],
};

export function Badge({ tone, icon: Icon, children }: { tone: string; icon?: any; children: ReactNode }) {
  return (
    <span className={`badge ${tone}`}>
      {Icon && <Icon className="icon" aria-hidden />}
      {children}
    </span>
  );
}

export function StatusBadge({ status }: { status?: string | null }) {
  if (!status) return <span className="muted">No result</span>;
  return <Badge tone={STATUS_TONE[status] ?? "neutral"} icon={STATUS_ICON[status]}>{statusLabel(status)}</Badge>;
}

export const SeverityBadge = ({ severity }: { severity: string }) => (
  <span className="badge outline">{SEVERITY_LABEL[severity] ?? severity}</span>
);

export function RunBadge({ status }: { status: string }) {
  const [label, tone, icon] = RUN_STATE[status] ?? [status, "neutral", Info];
  return <Badge tone={tone} icon={icon}>{label}</Badge>;
}

export function Notice({ tone = "info", children, action }: { tone?: string; children: ReactNode; action?: ReactNode }) {
  const Icon = tone === "critical" ? CircleAlert : tone === "warning" ? AlertTriangle : tone === "good" ? Check : Info;
  return (
    <div className={`notice ${tone}`} role={tone === "critical" ? "alert" : "status"}>
      <Icon className="icon" aria-hidden />
      <div className="body">{children}</div>
      {action}
    </div>
  );
}

export function Empty({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <h2>{title}</h2>
      <div>{children}</div>
      {action}
    </div>
  );
}

export function CloseButton({ onClick, label }: { onClick: () => void; label: string }) {
  return (
    <button type="button" className="btn quiet sm" onClick={onClick} aria-label={label}>
      <X className="icon" aria-hidden />
    </button>
  );
}

export function duration(seconds?: number | null): string {
  if (seconds == null) return "";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const total = Math.round(seconds);
  const m = Math.floor(total / 60), s = total % 60;
  if (m < 60) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

export function bytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1048576) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1048576).toFixed(1)} MB`;
}

export const when = (iso?: string | null) =>
  iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "";

// Status messages from the pipeline arrive with decorative pictographs and
// separator rules; the console shows plain text and carries level by colour
// and weight instead.
const PICTO = /^[\s←-⇿⌀-➿⬀-⯿️\u{1f000}-\u{1faff}]+/u;
export function cleanLog(message: string): string | null {
  const text = message.replace(/^\n+/, "").trimEnd();
  if (!text.trim() || /^[=\-_]{8,}$/.test(text.trim())) return null;
  const indent = text.length - text.trimStart().length;
  const body = text.trimStart().replace(PICTO, "");
  return body ? " ".repeat(indent) + body : null;
}

export function Evidence({ item }: { item: any }) {
  const commands: string[] = item.commands_executed ?? [];
  const outputs: string[] = item.command_outputs ?? [];
  return (
    <>
      {item.evidence && <p>{item.evidence}</p>}
      {commands.length > 0 && (
        <>
          <div className="block-title">Commands run on the target</div>
          {commands.map((command, i) => (
            <div key={i}>
              <pre className="cmd in">$ {command}</pre>
              {outputs[i] && <pre className="cmd">{outputs[i]}</pre>}
            </div>
          ))}
        </>
      )}
    </>
  );
}

export function ScannerDetails({ item }: { item: any }) {
  const tools = [["Tool 1", item.tool1_status, item.scanner?.tool1], ["Tool 2", item.tool2_status, item.scanner?.tool2]];
  return (
    <dl className="kv">
      {tools.map(([name, status, detail]) => (
        <div key={name} style={{ display: "contents" }}>
          <dt>{name}</dt>
          <dd>
            <StatusBadge status={status} />
            {detail?.finding_details && <div className="small muted" style={{ marginTop: 4 }}>{detail.finding_details}</div>}
          </dd>
        </div>
      ))}
    </dl>
  );
}
