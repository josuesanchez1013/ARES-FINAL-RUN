// Thin client for the ARES API. Every call is same-origin and relative.

export class ApiError extends Error {
  code: string;
  status: number;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function request(path: string, init?: RequestInit): Promise<any> {
  let response: Response;
  try {
    response = await fetch(`/api${path}`, init);
  } catch {
    throw new ApiError(0, "offline", "The ARES service cannot be reached. Check that it is running.");
  }
  if (response.status === 204) return null;
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = body?.detail;
    if (detail && typeof detail === "object" && !Array.isArray(detail)) {
      throw new ApiError(response.status, detail.code ?? "error", detail.message ?? "Request failed.");
    }
    throw new ApiError(response.status, "error", "The request was not accepted. Check the form and try again.");
  }
  return body;
}

const json = (method: string, body?: unknown): RequestInit => ({
  method,
  headers: body === undefined ? undefined : { "Content-Type": "application/json" },
  body: body === undefined ? undefined : JSON.stringify(body),
});

export const api = {
  settings: () => request("/settings"),
  current: () => request("/runs/current"),
  runs: () => request("/runs"),
  run: (id: string) => request(`/runs/${id}`),
  start: (form: FormData) => request("/runs", { method: "POST", body: form }),
  pause: (id: string) => request(`/runs/${id}/pause`, json("POST")),
  resume: (id: string) => request(`/runs/${id}/resume`, json("POST")),
  end: (id: string) => request(`/runs/${id}/end`, json("POST")),
  keep: (id: string, keep: boolean) => request(`/runs/${id}/keep`, json("PUT", { keep })),
  remove: (id: string) => request(`/runs/${id}`, json("DELETE")),
  summary: (id: string) => request(`/runs/${id}/summary`),
  findings: (id: string, params: Record<string, string | number>) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v !== "" && query.set(k, String(v)));
    return request(`/runs/${id}/findings?${query}`);
  },
  finding: (id: string, vuln: string) => request(`/runs/${id}/findings/${encodeURIComponent(vuln)}`),
  review: (id: string) => request(`/runs/${id}/review`),
  decide: (id: string, vuln: string, action: string, status?: string) =>
    request(`/runs/${id}/decisions/${encodeURIComponent(vuln)}`, json("POST", { action, status })),
  undo: (id: string, vuln: string) =>
    request(`/runs/${id}/decisions/${encodeURIComponent(vuln)}`, json("DELETE")),
  stigs: () => request("/stigs"),
  stig: (id: string) => request(`/stigs/${encodeURIComponent(id)}`),
  importStigs: (form: FormData) => request("/stigs/import", { method: "POST", body: form }),
  removeStig: (id: string) => request(`/stigs/${encodeURIComponent(id)}`, json("DELETE")),
  targets: () => request("/targets"),
  createTarget: (body: unknown) => request("/targets", json("POST", body)),
  updateTarget: (id: string, body: unknown) => request(`/targets/${id}`, json("PUT", body)),
  removeTarget: (id: string) => request(`/targets/${id}`, json("DELETE")),
  testTarget: (id: string) => request(`/targets/${id}/test`, json("POST")),
  discoverTarget: (id: string) => request(`/targets/${id}/discover`, json("POST")),
  uploadTargetConfig: (id: string, form: FormData) => request(`/targets/${id}/config`, { method: "POST", body: form }),
  scap: () => request("/scap"),
  startScap: (body: unknown) => request("/scap/scans", json("POST", body)),
  removeScap: (id: string) => request(`/scap/scans/${id}`, json("DELETE")),
};

// Exports are built by the API only when the button is clicked.
export async function downloadExport(id: string, format: string): Promise<void> {
  const response = await fetch(`/api/runs/${id}/export/${format}`);
  if (!response.ok) throw new ApiError(response.status, "export", "The export could not be built.");
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = `ares_reconciled_${id}.${format}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
