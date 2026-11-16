import { ClipboardCheck, History, Library, ListChecks, Play, Server, Settings as SettingsIcon } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import PastRunsScreen from "./screens/PastRunsScreen";
import ResultsScreen from "./screens/ResultsScreen";
import ReviewScreen from "./screens/ReviewScreen";
import RunScreen from "./screens/RunScreen";
import SettingsScreen from "./screens/SettingsScreen";
import StigLibraryScreen from "./screens/StigLibraryScreen";
import TargetsScreen from "./screens/TargetsScreen";
import { Notice, when } from "./ui";
import { useRun } from "./useRun";

const ROUTES = [
  { id: "run", label: "Run", icon: Play },
  { id: "results", label: "Results", icon: ListChecks },
  { id: "review", label: "Review", icon: ClipboardCheck },
  { id: "past-runs", label: "Past runs", icon: History },
  { id: "stig-library", label: "STIG library", icon: Library },
  { id: "targets", label: "Targets", icon: Server },
  { id: "settings", label: "Settings", icon: SettingsIcon },
];
const THEMES = ["system", "light", "dark"];

const readRoute = () => {
  const id = window.location.hash.replace(/^#\/?/, "");
  return ROUTES.some((r) => r.id === id) ? id : "run";
};

function storedTheme(): string {
  try {
    const value = window.localStorage.getItem("ares-theme");
    return value && THEMES.includes(value) ? value : "system";
  } catch {
    return "system";
  }
}

export default function App() {
  const [route, setRoute] = useState(readRoute);
  const [theme, setTheme] = useState(storedTheme);
  const [settings, setSettings] = useState<any>(null);
  const [current, setCurrent] = useState<any>(null);
  const [openedId, setOpenedId] = useState<string | null>(null);
  const [summary, setSummary] = useState<any>(null);
  const [offline, setOffline] = useState<string | null>(null);

  useEffect(() => {
    const onHash = () => setRoute(readRoute());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const go = useCallback((id: string) => { window.location.hash = `/${id}`; }, []);

  useEffect(() => {
    if (theme === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
    try { window.localStorage.setItem("ares-theme", theme); } catch { /* preference not saved */ }
  }, [theme]);

  // The current run is shared by every tab: poll for a run started elsewhere.
  const refreshCurrent = useCallback(() =>
    api.current().then(
      (body) => { setCurrent(body.run); setOffline(null); },
      (error) => setOffline(error.message),
    ), []);
  useEffect(() => {
    api.settings().then(setSettings, (error) => setOffline(error.message));
    refreshCurrent();
    const timer = window.setInterval(refreshCurrent, 4000);
    return () => window.clearInterval(timer);
  }, [refreshCurrent]);

  const viewId = openedId ?? current?.id ?? null;
  const live = useRun(viewId);
  const run = live.run;
  const hasResults = Boolean(run && run.id === viewId && run.has_results);

  useEffect(() => {
    if (!viewId || !hasResults) { setSummary(null); return; }
    let stale = false;
    api.summary(viewId).then((body) => !stale && setSummary(body), () => !stale && setSummary(null));
    return () => { stale = true; };
  }, [viewId, hasResults, live.decisionVersion]);

  useEffect(() => { if (live.missing) setOpenedId(null); }, [live.missing]);

  const viewingPast = openedId !== null && openedId !== current?.id;
  const pending = summary?.review_pending ?? 0;

  return (
    <div className="shell">
      <nav className="nav" aria-label="Main">
        <div className="wordmark">
          <div className="wordmark-name">ARES</div>
          <div className="wordmark-sub">STIG reconciliation and evidence</div>
        </div>
        {ROUTES.map(({ id, label, icon: Icon }) => (
          <button key={id} type="button" className="nav-item" onClick={() => go(id)}
                  aria-current={route === id ? "page" : undefined}>
            <Icon className="icon" aria-hidden />
            {label}
            {id === "review" && pending > 0 && (
              <span className="nav-count num" aria-label={`${pending} awaiting review`}>{pending}</span>
            )}
          </button>
        ))}
        <div className="nav-foot">
          <div className="label">Theme</div>
          <div className="seg" role="group" aria-label="Theme">
            {THEMES.map((t) => (
              <button key={t} type="button" aria-pressed={theme === t} onClick={() => setTheme(t)}>
                {t[0].toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </nav>

      <main className="main">
        {offline && <div style={{ marginBottom: 16 }}><Notice tone="critical">{offline}</Notice></div>}
        {viewingPast && run && route !== "past-runs" && route !== "settings" && route !== "stig-library" && route !== "targets" && (
          <div className="banner">
            <History className="icon" aria-hidden />
            <span className="grow">Viewing a past run from {when(run.created_at)}.</span>
            <button type="button" className="btn" onClick={() => setOpenedId(null)}>Back to current run</button>
          </div>
        )}
        {route === "run" && (
          <RunScreen settings={settings} run={run} live={live} summary={summary}
                     activeElsewhere={viewingPast && current?.status && ["checking", "running", "paused"].includes(current.status)}
                     onChanged={(started) => { if (started) { setCurrent(started); setOpenedId(null); } refreshCurrent(); }}
                     go={go} />
        )}
        {route === "results" && (
          <ResultsScreen runId={viewId} run={run} summary={summary} decisionVersion={live.decisionVersion} go={go} />
        )}
        {route === "review" && (
          <ReviewScreen runId={viewId} run={run} decisionVersion={live.decisionVersion} go={go} />
        )}
        {route === "past-runs" && (
          <PastRunsScreen viewId={viewId}
                          onOpen={(id, target) => { setOpenedId(id); go(target); }}
                          onChanged={refreshCurrent} />
        )}
        {route === "stig-library" && <StigLibraryScreen />}
        {route === "targets" && <TargetsScreen />}
        {route === "settings" && <SettingsScreen settings={settings} />}
      </main>
    </div>
  );
}
