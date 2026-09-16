import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { Metrics } from "../types";

const COLORS: Record<string, string> = {
  CRITICAL: "#e11d48",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
};

export default function SeverityChart({ metrics }: { metrics: Metrics }) {
  const data = Object.entries(metrics.alerts_by_severity).map(([name, value]) => ({
    name,
    value,
  }));

  return (
    <div className="chart">
      <h3>Severity Breakdown</h3>
      {data.every((d) => d.value === 0) ? (
        <p className="empty">No alerts yet — run a simulation.</p>
      ) : (
        <ResponsiveContainer width="100%" height={240}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              outerRadius={90}
              label={(entry) => `${entry.name} (${entry.value})`}
            >
              {data.map((entry) => (
                <Cell key={entry.name} fill={COLORS[entry.name] ?? "#64748b"} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}