import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { Incident } from "../types";

interface Props {
  incident: Incident;
}

export default function IncidentDetail({ incident }: Props) {
  const [report, setReport] = useState<string | null>(null);

  useEffect(() => {
    setReport(null);
    api
      .report(incident.incident_id, "text")
      .then((r) => setReport(r.content))
      .catch(() => setReport(null));
  }, [incident.incident_id]);

  return (
    <div className="panel">
      <div className="incident-head">
        <h3>
          {incident.title} <span className="muted">{incident.incident_id}</span>
        </h3>
        <div className="badges">
          <span className="badge badge-sev">{incident.severity}</span>
          <span className="badge">{incident.status}</span>
          <span className="badge badge-mitre">{incident.mitre_technique_id}</span>
        </div>
      </div>

      <section>
        <h4>Detection &amp; ATT&CK</h4>
        <p>
          {incident.description ?? "No description"} ·{" "}
          {incident.mitre_tactic} / {incident.mitre_technique} (
          {incident.mitre_technique_id})
        </p>
      </section>

      <section>
        <h4>Evidence ({incident.evidence.length})</h4>
        <ul className="evidence">
          {incident.evidence.map((e, i) => (
            <li key={i}>
              <code>
                {new Date(e.timestamp).toLocaleTimeString()} {e.event_type} ·{" "}
                {e.raw_message}
              </code>
            </li>
          ))}
          {incident.evidence.length === 0 && <li className="empty">—</li>}
        </ul>
      </section>

      <section>
        <h4>Historical Matches / Confidence</h4>
        {incident.historical_matches.length === 0 && (
          <p className="muted">RAG not yet enabled (Day 4).</p>
        )}
        {incident.historical_matches.map((m, i) => (
          <p key={i} className="muted">
            similarity {String(m.similarity)} · {String(m.title)}
          </p>
        ))}
        <p>
          Confidence:{" "}
          <strong>{incident.confidence === null ? "—" : incident.confidence.toFixed(2)}</strong>
        </p>
      </section>

      <section>
        <h4>Agent / Response</h4>
        <p className="muted">
          Decision: {incident.agent_decision ?? "PENDING (Day 6)"}
          {" · "}Response: {incident.response_action ?? "—"} (
          {incident.response_status ?? "—"})
        </p>
        {incident.escalation_reason && (
          <p className="escalation">Escalation: {incident.escalation_reason}</p>
        )}
      </section>

      <section>
        <h4>Timeline</h4>
        <ol className="timeline">
          {incident.timeline.map((t, i) => (
            <li key={i}>
              <code>{new Date(t.timestamp).toLocaleTimeString()}</code>{" "}
              {t.event}
              {Object.keys(t.detail).length > 0 && (
                <span className="muted"> · {JSON.stringify(t.detail)}</span>
              )}
            </li>
          ))}
        </ol>
      </section>

      {report && (
        <details>
          <summary>Analyst report</summary>
          <pre className="report">{report}</pre>
        </details>
      )}
    </div>
  );
}