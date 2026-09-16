import type { Alert } from "../types";

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "#e11d48",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
};

interface Props {
  alerts: Alert[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export default function AlertFeed({ alerts, selectedId, onSelect }: Props) {
  return (
    <div className="panel">
      <h3>Alert Feed ({alerts.length})</h3>
      <table className="alert-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Alert</th>
            <th>Timestamp</th>
            <th>Rule</th>
            <th>Source</th>
            <th>MITRE</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr
              key={a.alert_id}
              className={a.alert_id === selectedId ? "row-selected" : ""}
              onClick={() => onSelect(a.alert_id)}
            >
              <td>
                <span
                  className="sev"
                  style={{ background: SEVERITY_COLOR[a.severity] ?? "#64748b" }}
                >
                  {a.severity}
                </span>
              </td>
              <td>{a.alert_id}</td>
              <td>{new Date(a.timestamp).toLocaleTimeString()}</td>
              <td>{a.rule_name}</td>
              <td>{a.source_ip ?? "—"}</td>
              <td>
                {a.mitre_technique_id ?? "—"}
                <span className="mitre-tactic">{a.mitre_tactic}</span>
              </td>
              <td>{a.status}</td>
            </tr>
          ))}
          {alerts.length === 0 && (
            <tr>
              <td colSpan={7} className="empty">
                No alerts. Click a simulate button.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}