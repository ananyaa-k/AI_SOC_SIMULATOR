import type { Alert, Health, Incident, Metrics, SimulateResult } from "../types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(path, init);
  if (!resp.ok) {
    const detail = await resp.text().catch(() => "");
    throw new Error(`${resp.status} ${resp.statusText}: ${detail.slice(0, 200)}`);
  }
  return (await resp.json()) as T;
}

export const api = {
  health: () => request<Health>("/health"),
  alerts: () => request<Alert[]>("/alerts"),
  alert: (id: string) => request<Alert>(`/alerts/${id}`),
  incidents: () => request<Incident[]>("/incidents"),
  incident: (id: string) => request<Incident>(`/incidents/${id}`),
  report: (id: string, format: "json" | "text" = "json") =>
    request<{ incident_id: string; format: string; content: string }>(
      `/incidents/${id}/report?format=${format}`,
    ),
  metrics: () => request<Metrics>("/metrics"),
  simulate: (scenario?: string) =>
    request<SimulateResult | { scenarios: SimulateResult[] }>(
      scenario ? `/simulate/${scenario}` : "/simulate",
      { method: "POST" },
    ),
};