// Live state of one run, rebuilt from the API event stream. A tab that joins
// late (or refreshes) receives the full history first, then live events, so
// every tab shows the same run.
import { useEffect, useRef, useState } from "react";
import { api } from "./api";

export interface LogLine { level: string; message: string }
export interface RuleState { vuln_id: string; index: number; total: number; state: string; verdict?: string; confidence?: number }
export interface LiveRun {
  run: any | null;
  logs: Record<string, LogLine[]>;
  rules: Record<string, Record<string, RuleState>>;
  decisionVersion: number;
  missing: boolean;
}

const EMPTY: LiveRun = { run: null, logs: {}, rules: {}, decisionVersion: 0, missing: false };

export function useRun(runId: string | null): LiveRun {
  const [state, setState] = useState<LiveRun>(EMPTY);
  const buffer = useRef<any[]>([]);
  const frame = useRef<number | null>(null);

  useEffect(() => {
    setState(EMPTY);
    buffer.current = [];
    if (!runId) return;
    let closed = false;

    const refresh = () =>
      api.run(runId).then(
        (run) => !closed && setState((s) => ({ ...s, run })),
        () => !closed && setState((s) => ({ ...s, missing: true })),
      );

    const flush = () => {
      frame.current = null;
      const events = buffer.current;
      buffer.current = [];
      if (closed || events.length === 0) return;
      const needsRefresh = events.some((e) => !["log", "rule", "decision"].includes(e.type));
      setState((s) => {
        const logs = { ...s.logs };
        const rules = { ...s.rules };
        let decisionVersion = s.decisionVersion;
        for (const e of events) {
          if (e.type === "log") {
            logs[e.step] = [...(logs[e.step] ?? []), { level: e.level, message: e.message }];
          } else if (e.type === "rule") {
            rules[e.step] = { ...(rules[e.step] ?? {}), [e.vuln_id]: e };
          } else if (e.type === "decision") {
            decisionVersion += 1;
          }
        }
        return { ...s, logs, rules, decisionVersion };
      });
      if (needsRefresh) refresh();
    };

    refresh();
    const source = new EventSource(`/api/runs/${runId}/events`);
    source.onmessage = (message) => {
      buffer.current.push(JSON.parse(message.data));
      if (frame.current === null) frame.current = window.setTimeout(flush, 80);
    };
    return () => {
      closed = true;
      source.close();
      if (frame.current !== null) window.clearTimeout(frame.current);
      frame.current = null;
    };
  }, [runId]);

  return state;
}
