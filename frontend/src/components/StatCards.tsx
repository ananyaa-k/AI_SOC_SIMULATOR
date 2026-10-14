import type { Metrics } from "../types";

interface Props {
  metrics: Metrics;
}

type NumericKey = "total_alerts" | "total_incidents" | "total_logs" | "total_detections";

const LABELS: Array<{ key: NumericKey; title: string }> = [
  { key: "total_alerts", title: "Total Alerts" },
  { key: "total_incidents", title: "Incidents" },
  { key: "total_logs", title: "Logs Ingested" },
  { key: "total_detections", title: "Detections" },
];

function StatCard({ title, value }: { title: string; value: string | number }) {
  return (
    <div className="stat-card">
      <div className="stat-value">{value}</div>
      <div className="stat-title">{title}</div>
    </div>
  );
}

export default function StatCards({ metrics }: Props) {
  const rate =
    metrics.detection_rate === null ? "—" : `${(metrics.detection_rate * 100).toFixed(1)}%`;
  return (
    <div className="stat-grid">
      {LABELS.map(({ key, title }) => (
        <StatCard key={key} title={title} value={metrics[key]} />
      ))}
      <StatCard
        title={`Malicious Events Detected (${metrics.detected_malicious_logs}/${metrics.malicious_logs})`}
        value={rate}
      />
      <StatCard title="Auto-resolved" value={metrics.auto_resolved} />
      <StatCard title="Escalated" value={metrics.escalated} />
    </div>
  );
}