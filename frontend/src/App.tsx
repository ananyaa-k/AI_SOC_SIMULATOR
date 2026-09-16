import { useCallback, useEffect, useState } from "react";
import AlertFeed from "./components/AlertFeed";
import IncidentDetail from "./components/IncidentDetail";
import SeverityChart from "./components/SeverityChart";
import StatCards from "./components/StatCards";
import { api } from "./services/api";
import type { Alert, Incident, Metrics } from "./types";

const SCENARIOS = [
  "brute_force",
  "suspicious_powershell",
  "malicious_ip",
  "suspicious_command",
];

const EMPTY_METRICS: Metrics = {
  total_logs: 0,
  malicious_logs: 0,
  total_detections: 0,
  detection_rate: null,
  total_alerts: 0,
  alerts_by_severity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
  alerts_by_status: {
    NEW: 0,
    TRIAGED: 0,
    AUTO_RESOLVED: 0,
    ESCALATED: 0,
    CLOSED: 0,
  },
  total_incidents: 0,
  incidents_by_status: {},
  incidents_by_technique: {},
  auto_resolved: 0,
  escalated: 0,
};

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [metrics, setMetrics] = useState<Metrics>(EMPTY_METRICS);
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [alertList, incidentList, metricData] = await Promise.all([
        api.alerts(),
        api.incidents(),
        api.metrics(),
      ]);
      setAlerts(alertList);
      setIncidents(incidentList);
      setMetrics(metricData);
      setError(null);
    } catch (e) {
      setError(`Backend unreachable: ${e instanceof Error ? e.message : String(e)}`);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  const runScenario = async (scenario?: string) => {
    setBusy(scenario ?? "all");
    try {
      await api.simulate(scenario);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const selectedIncident = incidents.find((i) => i.alert_id === selected) ?? null;

  return (
    <div className="app">
      <header className="topbar">
        <h1>AI SOC Simulator</h1>
        <div className="controls">
          <button
            disabled={busy !== null}
            onClick={() => runScenario()}
            className="btn btn-primary"
          >
            {busy === "all" ? "Simulating…" : "Run All Scenarios"}
          </button>
          {SCENARIOS.map((s) => (
            <button
              key={s}
              disabled={busy !== null}
              onClick={() => runScenario(s)}
            >
              {busy === s ? "Running…" : s.replace("_", " ")}
            </button>
          ))}
        </div>
      </header>

      {error && <div className="banner error">{error}</div>}

      <main>
        <StatCards metrics={metrics} />

        <div className="columns">
          <div className="column left">
            <AlertFeed
              alerts={alerts}
              selectedId={selected}
              onSelect={setSelected}
            />
          </div>
          <div className="column right">
            <SeverityChart metrics={metrics} />
            {selectedIncident ? (
              <IncidentDetail incident={selectedIncident} />
            ) : (
              <div className="panel muted">Select an alert to inspect its incident.</div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}