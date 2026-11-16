import { Check, CircleAlert, Download, FileUp, Pencil, Play, Plus, Radar, Search, Trash2, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Empty, Notice, when } from "../ui";

const BACKEND_LABEL: Record<string, string> = {
  ssh: "SSH", winrm: "WinRM (PowerShell)", local: "This machine", config: "Saved configuration file",
};
const BLANK = {
  name: "", family: "linux", backend: "ssh", host: "", port: "", user: "", key_path: "", password_env: "",
  use_sudo: true, winrm_https: true, winrm_transport: "ntlm", ca_bundle: "", timeout: 30, notes: "",
};

function TargetForm({ platforms, initial, onSaved, onCancel }: { platforms: any[]; initial: any | null; onSaved: () => void; onCancel: () => void }) {
  const [form, setForm] = useState<any>(() => initial ? { ...BLANK, ...initial, port: initial.port ?? "" } : BLANK);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const platform = platforms.find((p) => p.family === form.family) ?? platforms[0];
  const set = (key: string, value: any) => setForm((f: any) => ({ ...f, [key]: value }));

  const pickFamily = (family: string) => {
    const next = platforms.find((p) => p.family === family);
    setForm((f: any) => ({
      ...f, family,
      backend: next.backends[0],
      use_sudo: next.sudo,
    }));
  };
  const remote = form.backend === "ssh" || form.backend === "winrm";

  const save = async () => {
    setBusy(true); setError(null);
    const body = { ...form, port: form.port === "" ? null : Number(form.port), timeout: Number(form.timeout) || 30 };
    for (const key of ["id", "shell", "platform_label", "has_config", "created_at"]) delete body[key];
    try {
      if (initial) await api.updateTarget(initial.id, body); else await api.createTarget(body);
      onSaved();
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  };

  return (
    <section className="panel panel-pad stack">
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <h2 className="grow" style={{ flex: 1 }}>{initial ? `Edit ${initial.name}` : "Add a target"}</h2>
        <button type="button" className="btn quiet sm" onClick={onCancel}><X className="icon" aria-hidden />Cancel</button>
      </div>
      <div className="cols two">
        <label className="field"><span>Name</span>
          <input type="text" value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="web01, edge-rtr-01" />
        </label>
        <label className="field"><span>Platform</span>
          <select value={form.family} onChange={(e) => pickFamily(e.target.value)}>
            {platforms.map((p) => <option key={p.family} value={p.family}>{p.label}</option>)}
          </select>
        </label>
        <label className="field"><span>Connect by</span>
          <select value={form.backend} onChange={(e) => set("backend", e.target.value)}>
            {platform.backends.map((b: string) => <option key={b} value={b}>{BACKEND_LABEL[b] ?? b}</option>)}
          </select>
        </label>
        {remote && (
          <label className="field"><span>Host name or IP</span>
            <input type="text" value={form.host} onChange={(e) => set("host", e.target.value)} />
          </label>
        )}
        {remote && (
          <label className="field"><span>Port (blank for the default)</span>
            <input type="text" inputMode="numeric" value={form.port} onChange={(e) => set("port", e.target.value.replace(/\D/g, ""))}
                   placeholder={form.backend === "ssh" ? "22" : form.winrm_https ? "5986" : "5985"} />
          </label>
        )}
        {remote && (
          <label className="field"><span>Account</span>
            <input type="text" value={form.user} onChange={(e) => set("user", e.target.value)} placeholder={form.backend === "winrm" ? "DOMAIN\\auditor" : "auditor"} />
          </label>
        )}
        {form.backend === "ssh" && (
          <label className="field"><span>SSH key file on the ARES host</span>
            <input type="text" value={form.key_path} onChange={(e) => set("key_path", e.target.value)} placeholder="~/.ssh/ares_audit" />
          </label>
        )}
        {remote && (
          <label className="field"><span>Password environment variable{form.backend === "ssh" ? " (if no key)" : ""}</span>
            <input type="text" value={form.password_env} onChange={(e) => set("password_env", e.target.value)} placeholder="ARES_PW_WEB01" />
          </label>
        )}
        {form.backend === "winrm" && (
          <label className="field"><span>Sign-in method</span>
            <select value={form.winrm_transport} onChange={(e) => set("winrm_transport", e.target.value)}>
              <option value="ntlm">NTLM</option><option value="kerberos">Kerberos</option>
              <option value="credssp">CredSSP</option><option value="basic">Basic (HTTPS only)</option>
            </select>
          </label>
        )}
        {form.backend === "winrm" && (
          <label className="field"><span>CA bundle for the WinRM certificate (optional)</span>
            <input type="text" value={form.ca_bundle} onChange={(e) => set("ca_bundle", e.target.value)} placeholder="/etc/pki/tls/certs/lab-ca.pem" />
          </label>
        )}
      </div>
      <div className="choices">
        {form.backend === "winrm" && (
          <label className="choice"><input type="checkbox" checked={form.winrm_https} onChange={(e) => set("winrm_https", e.target.checked)} />Use HTTPS</label>
        )}
        {(form.backend === "ssh" || form.backend === "local") && platform.shell === "posix" && (
          <label className="choice"><input type="checkbox" checked={form.use_sudo} onChange={(e) => set("use_sudo", e.target.checked)} />Account may use sudo</label>
        )}
      </div>
      <p className="hint">
        {remote && "ARES never stores a password. Put it in an environment variable of the ARES service and enter that variable's name here. "}
        {form.backend === "config" && "After saving, upload the device's running configuration. ARES answers show running-config queries from that file and sends checks that need live state to review. "}
        {form.backend === "local" && "Checks run on the machine ARES is installed on. "}
        Only read-only commands are ever sent: {platform.shell === "powershell" ? "an allowlist of PowerShell queries" : platform.shell === "network" ? "show commands" : "commands that pass the read-only rules"}.
      </p>
      {error && <Notice tone="critical">{error}</Notice>}
      <div className="actions">
        <button type="button" className="btn primary" disabled={busy || !form.name.trim()} onClick={save}>
          <Check className="icon" aria-hidden />{busy ? "Saving" : "Save target"}
        </button>
      </div>
    </section>
  );
}

function TargetRow({ target, onEdit, onChanged }: { target: any; onEdit: () => void; onChanged: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [test, setTest] = useState<any>(null);
  const [found, setFound] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  const act = async (name: string, call: () => Promise<any>, then?: (r: any) => void) => {
    setBusy(name); setError(null);
    try { const result = await call(); then?.(result); } catch (e: any) { setError(e.message); } finally { setBusy(null); }
  };
  const upload = (file: File | null) => {
    if (!file) return;
    const form = new FormData(); form.set("file", file);
    act("config", () => api.uploadTargetConfig(target.id, form), onChanged);
  };

  return (
    <section className="panel">
      <div className="panel-head" style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <h2 style={{ flex: 1 }}>{target.name}</h2>
        <Badge tone="info">{target.platform_label}</Badge>
        <span className="badge outline">{BACKEND_LABEL[target.backend] ?? target.backend}</span>
      </div>
      <div className="panel-pad stack">
        <dl className="kv">
          {target.host && <><dt>Host</dt><dd className="mono">{target.user ? `${target.user}@` : ""}{target.host}{target.port ? `:${target.port}` : ""}</dd></>}
          {target.backend === "ssh" && <><dt>Sign-in</dt><dd>{target.key_path ? <>Key <span className="mono">{target.key_path}</span></> : <>Password from <span className="mono">{target.password_env}</span></>}{target.use_sudo ? ", sudo allowed" : ", no sudo"}</dd></>}
          {target.backend === "winrm" && <><dt>Sign-in</dt><dd>{target.winrm_transport.toUpperCase()} over {target.winrm_https ? "HTTPS" : "HTTP"}, password from <span className="mono">{target.password_env || "Kerberos ticket"}</span></dd></>}
          {target.backend === "config" && <><dt>Configuration</dt><dd>{target.has_config ? "Uploaded" : <Badge tone="warning">Not uploaded yet</Badge>}</dd></>}
        </dl>
        <div className="actions">
          {target.backend !== "config" && (
            <button type="button" className="btn sm" disabled={busy !== null} onClick={() => act("test", () => api.testTarget(target.id), setTest)}>
              <Play className="icon" aria-hidden />{busy === "test" ? "Testing" : "Test connection"}
            </button>
          )}
          {target.backend !== "config" && (
            <button type="button" className="btn sm" disabled={busy !== null} onClick={() => act("discover", () => api.discoverTarget(target.id), setFound)}>
              <Radar className="icon" aria-hidden />{busy === "discover" ? "Looking" : "Find matching STIGs"}
            </button>
          )}
          {target.backend === "config" && (
            <label className="btn sm" style={{ cursor: "pointer" }}>
              <FileUp className="icon" aria-hidden />{busy === "config" ? "Uploading" : target.has_config ? "Replace configuration" : "Upload configuration"}
              <input type="file" style={{ display: "none" }} onChange={(e) => upload(e.target.files?.[0] ?? null)} />
            </label>
          )}
          <button type="button" className="btn sm" onClick={onEdit}><Pencil className="icon" aria-hidden />Edit</button>
          {confirming ? (
            <>
              <button type="button" className="btn sm danger" onClick={() => act("delete", () => api.removeTarget(target.id), onChanged)}>Delete target</button>
              <button type="button" className="btn sm quiet" onClick={() => setConfirming(false)}>Cancel</button>
            </>
          ) : (
            <button type="button" className="btn sm quiet" aria-label={`Delete ${target.name}`} onClick={() => setConfirming(true)}><Trash2 className="icon" aria-hidden /></button>
          )}
        </div>
        {error && <Notice tone="critical">{error}</Notice>}
        {test && (
          <Notice tone={test.ok ? "good" : "critical"}>
            {test.ok ? `Connected in ${test.seconds}s. ` : "Could not run a command on the target. "}<span className="mono small">{test.detail}</span>
          </Notice>
        )}
        {found && (
          found.reachable ? (
            <div>
              <div className="block-title">STIGs in the library that apply to this target</div>
              {found.suggestions.length > 0 ? (
                <ul className="small">
                  {found.suggestions.map((s: any) => <li key={s.id}>{s.title} <span className="muted">{s.version_label}</span></li>)}
                </ul>
              ) : (
                <p className="small muted">{found.library_empty ? "The STIG library is empty. Import STIGs first." : "Nothing in the library matched what the target reported."}</p>
              )}
              <details><summary className="small">What the target reported</summary><pre className="cmd">{found.output}</pre></details>
            </div>
          ) : <Notice tone="critical">The target did not answer. {found.errors[0]}</Notice>
        )}
      </div>
    </section>
  );
}

function ScapPanel({ targets }: { targets: any[] }) {
  const [data, setData] = useState<any>(null);
  const [entry, setEntry] = useState("");
  const [target, setTarget] = useState("local");
  const [profile, setProfile] = useState("");
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => api.scap().then(setData, (e) => setError(e.message)), []);
  useEffect(() => { load(); const t = window.setInterval(load, 4000); return () => window.clearInterval(t); }, [load]);
  if (!data) return null;

  const benchmarks: any[] = data.benchmarks;
  const chosen = benchmarks.find((b) => b.id === entry);
  const sshTargets = targets.filter((t) => t.backend === "ssh" && t.shell === "posix");
  const start = async () => {
    setError(null);
    try { await api.startScap({ entry_id: entry, target, profile }); await load(); } catch (e: any) { setError(e.message); }
  };

  return (
    <section className="panel">
      <div className="panel-head"><h2>OpenSCAP scans</h2></div>
      <div className="panel-pad stack">
        <p className="hint">Runs an imported SCAP benchmark with OpenSCAP and keeps the result as a checklist you can use as a scan file in a run. For Windows, run DISA SCC on the machine and upload its XCCDF results on the Run page.</p>
        {!data.oscap && <Notice tone="warning">OpenSCAP is not installed on the ARES host. Install the openscap-scanner package (and openscap-utils for scans over SSH) to use this.</Notice>}
        {benchmarks.length === 0 ? <p className="small muted">No SCAP benchmarks are imported yet. Import SCAP benchmark zips on the STIG library page.</p> : (
          <div className="cols two">
            <label className="field"><span>SCAP benchmark</span>
              <select value={entry} onChange={(e) => { setEntry(e.target.value); setProfile(""); }}>
                <option value="">Choose a benchmark</option>
                {benchmarks.map((b) => <option key={b.id} value={b.id}>{b.title} {b.version_label}</option>)}
              </select>
            </label>
            <label className="field"><span>Scan</span>
              <select value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="local">This machine</option>
                {sshTargets.map((t) => <option key={t.id} value={t.id}>{t.name} (SSH)</option>)}
              </select>
            </label>
            {chosen?.profiles?.length > 0 && (
              <label className="field"><span>Profile</span>
                <select value={profile} onChange={(e) => setProfile(e.target.value)}>
                  <option value="">Benchmark default</option>
                  {chosen.profiles.map((p: any) => <option key={p.id} value={p.id}>{p.title || p.id}</option>)}
                </select>
              </label>
            )}
          </div>
        )}
        {benchmarks.length > 0 && (
          <div className="actions">
            <button type="button" className="btn primary" disabled={!entry} onClick={start}><Search className="icon" aria-hidden />Start scan</button>
          </div>
        )}
        {error && <Notice tone="critical">{error}</Notice>}
      </div>
      {data.scans.length > 0 && (
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th>Started</th><th>Benchmark</th><th>Target</th><th>Status</th><th>Open / Not a finding / Not reviewed</th><th></th></tr></thead>
            <tbody>
              {data.scans.map((s: any) => (
                <tr key={s.id} style={{ cursor: "default" }}>
                  <td>{when(s.started_at)}<div className="mono muted small">{s.id}</div></td>
                  <td className="title">{s.stig_title} {s.stig_version}</td>
                  <td>{s.target_name}</td>
                  <td>{s.status === "completed" ? <Badge tone="good" icon={Check}>Completed</Badge>
                    : s.status === "running" ? <Badge tone="info">Running</Badge>
                    : <><Badge tone="critical" icon={CircleAlert}>Failed</Badge><div className="small muted" style={{ whiteSpace: "normal", maxWidth: 320 }}>{s.error}</div></>}</td>
                  <td className="num">{s.counts ? `${s.counts.Open} / ${s.counts.NotAFinding} / ${s.counts.Not_Reviewed}` : ""}</td>
                  <td>
                    <div className="actions" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
                      {s.status === "completed" && <a className="btn sm" href={`/api/scap/scans/${s.id}/ckl`}><Download className="icon" aria-hidden />CKL</a>}
                      {s.status !== "running" && (
                        <button type="button" className="btn sm quiet" aria-label={`Delete scan ${s.id}`} onClick={() => api.removeScap(s.id).then(load, (e) => setError(e.message))}><Trash2 className="icon" aria-hidden /></button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export default function TargetsScreen() {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<any | "new" | null>(null);
  const load = useCallback(() => api.targets().then(setData, (e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);

  if (!data) return error ? <Notice tone="critical">{error}</Notice> : <p className="muted">Loading targets.</p>;
  return (
    <div className="stack" style={{ maxWidth: 1000 }}>
      <div className="page-head">
        <div className="grow">
          <h1>Targets</h1>
          <p>The systems ARES checks: Linux, Solaris, AIX and other UNIX over SSH, Windows over WinRM, and network devices from a saved configuration. A run uses the target you choose on the Run page; without a choice it uses {data.default.name}, as before.</p>
        </div>
        {editing === null && <button type="button" className="btn primary" onClick={() => setEditing("new")}><Plus className="icon" aria-hidden />Add target</button>}
      </div>
      {error && <Notice tone="critical">{error}</Notice>}
      {editing !== null && (
        <TargetForm platforms={data.platforms} initial={editing === "new" ? null : editing}
                    onCancel={() => setEditing(null)} onSaved={() => { setEditing(null); load(); }} />
      )}
      {data.targets.length === 0 && editing === null && (
        <Empty title="No targets saved yet">Add a target to check a system other than {data.default.name}.</Empty>
      )}
      {data.targets.map((t: any) => (
        <TargetRow key={t.id} target={t} onEdit={() => setEditing(t)} onChanged={load} />
      ))}
      <ScapPanel targets={data.targets} />
    </div>
  );
}
