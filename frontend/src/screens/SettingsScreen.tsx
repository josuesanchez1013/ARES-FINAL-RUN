import { Badge, Notice } from "../ui";
import { Check, CircleAlert } from "lucide-react";

export default function SettingsScreen({ settings }: { settings: any }) {
  if (!settings) return <p className="muted">Loading settings.</p>;
  const check: any[] = settings.model_check ?? [];
  return (
    <div className="stack" style={{ maxWidth: 860 }}>
      <div className="page-head">
        <div className="grow">
          <h1>Settings</h1>
          <p>These values come from the service configuration and are read-only here. Change them in the service environment and restart.</p>
        </div>
      </div>
      {settings.pipeline_error && <Notice tone="critical">The pipeline cannot start: {settings.pipeline_error}</Notice>}

      <section className="panel">
        <div className="panel-head"><h2>Models</h2></div>
        <div className="panel-pad">
          <dl className="kv">
            <dt>Mode</dt>
            <dd>{settings.mode === "mock" ? <Badge tone="warning">Mock data</Badge> : <Badge tone="info">Production</Badge>}</dd>
            <dt>Available models</dt>
            <dd>{settings.models.map((m: string) => <div key={m} className="mono">{m}</div>)}</dd>
            <dt>Last model check</dt>
            <dd>
              {check.length === 0 ? <span className="muted">No run has checked the models since the service started keeping runs.</span>
                : check.map((c, i) => (
                  <div key={i} style={{ marginBottom: 4 }}>
                    <Badge tone={c.ok ? "good" : "critical"} icon={c.ok ? Check : CircleAlert}>{c.ok ? "Ready" : "Failed"}</Badge>{" "}
                    <span className="mono">{c.model || c.role}</span> <span className="muted small">{c.detail}</span>
                  </div>
                ))}
            </dd>
          </dl>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head"><h2>Target and STIG content</h2></div>
        <div className="panel-pad">
          <dl className="kv">
            <dt>Target host</dt><dd className="mono">{settings.target.host_name} ({settings.target.host_ip})</dd>
            <dt>Built-in STIG</dt><dd>{settings.stig.title} {settings.stig.version}</dd>
            <dt>STIG content source</dt><dd>{settings.stig.source}</dd>
            <dt>STIG library</dt>
            <dd>{settings.stig_library?.count ?? 0} imported releases. <a className="link" href="#/stig-library">Manage the STIG library</a>
              <div className="mono small muted">{settings.stig_library?.dir}</div></dd>
            <dt>MCP server</dt><dd className="mono">{settings.mcp_server_url || "Not set (MCP_SERVER_URL)"}</dd>
          </dl>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head"><h2>Data handling and review</h2></div>
        <div className="panel-pad">
          <dl className="kv">
            <dt>Accepted classifications</dt>
            <dd>{settings.classifications.filter((c: string) => !settings.refused_classifications.includes(c)).join(", ")}</dd>
            <dt>Refused</dt><dd>{settings.refused_classifications.join(", ")}</dd>
            <dt>Sensitivity categories</dt><dd>{settings.sensitivity_categories.join(", ")}</dd>
            <dt>Flag for review</dt>
            <dd>CAT I below {settings.review_thresholds.cat_i}% confidence; other rules below {settings.review_thresholds.default}%</dd>
          </dl>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head"><h2>Storage</h2></div>
        <div className="panel-pad">
          <dl className="kv">
            <dt>Run data folder</dt><dd className="mono">{settings.data_dir}</dd>
            <dt>Runs retained</dt><dd>{settings.retention} most recent, plus every kept run</dd>
            <dt>Service version</dt><dd className="mono">{settings.version}</dd>
          </dl>
        </div>
      </section>
    </div>
  );
}
