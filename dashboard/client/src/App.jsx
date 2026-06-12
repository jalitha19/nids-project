import { useState, useEffect } from "react";

const API_URL = "http://localhost:3001/api/alerts";
const POLL_INTERVAL = 3000;

const SEVERITY_STYLES = {
  critical: {
    badge: "bg-red-900 text-red-300 border border-red-700",
    row: "border-l-2 border-red-600",
  },
  high: {
    badge: "bg-yellow-900 text-yellow-300 border border-yellow-700",
    row: "border-l-2 border-yellow-500",
  },
  medium: {
    badge: "bg-cyan-900 text-cyan-300 border border-cyan-700",
    row: "border-l-2 border-cyan-600",
  },
  low: {
    badge: "bg-gray-800 text-gray-400 border border-gray-600",
    row: "border-l-2 border-gray-600",
  },
};

const ALERT_TYPE_COLORS = {
  PORT_SCAN:       "text-yellow-400",
  SYN_FLOOD:       "text-red-400",
  ICMP_SWEEP:      "text-cyan-400",
  SSH_BRUTE_FORCE: "text-orange-400",
};

function SeverityBadge({ severity }) {
  const styles = SEVERITY_STYLES[severity] || SEVERITY_STYLES.low;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider ${styles.badge}`}>
      {severity}
    </span>
  );
}

function StatCard({ label, count, color }) {
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 flex flex-col gap-1">
      <span className={`text-2xl font-bold ${color}`}>{count}</span>
      <span className="text-xs text-gray-500 uppercase tracking-wider">{label}</span>
    </div>
  );
}

function AlertTable({ alerts }) {
  if (alerts.length === 0) {
    return (
      <div className="text-center text-gray-600 py-16 text-sm">
        No alerts detected. Waiting for traffic...
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 text-xs uppercase tracking-wider border-b border-gray-800">
            <th className="text-left py-3 px-4">Timestamp</th>
            <th className="text-left py-3 px-4">Source IP</th>
            <th className="text-left py-3 px-4">Alert type</th>
            <th className="text-left py-3 px-4">Severity</th>
            <th className="text-left py-3 px-4">Detail</th>
          </tr>
        </thead>
        <tbody>
          {[...alerts].reverse().map((alert, i) => {
            const rowStyle = (SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.low).row;
            const typeColor = ALERT_TYPE_COLORS[alert.alert_type] || "text-gray-300";
            return (
              <tr
                key={i}
                className={`${rowStyle} border-b border-gray-800/50 hover:bg-gray-800/40 transition-colors`}
              >
                <td className="py-3 px-4 text-gray-500 whitespace-nowrap">
                  {alert.timestamp.replace("T", " ").replace("Z", "")}
                </td>
                <td className="py-3 px-4 text-blue-400 font-mono">{alert.src_ip}</td>
                <td className={`py-3 px-4 font-semibold ${typeColor}`}>{alert.alert_type}</td>
                <td className="py-3 px-4">
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td className="py-3 px-4 text-gray-400">{alert.detail}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const res = await fetch(API_URL);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        setAlerts(data);
        setLastUpdated(new Date().toLocaleTimeString());
        setError(null);
      } catch (err) {
        setError("Cannot reach NIDS server. Is it running?");
      }
    };

    fetchAlerts();
    const interval = setInterval(fetchAlerts, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, []);

  const counts = {
    PORT_SCAN:       alerts.filter((a) => a.alert_type === "PORT_SCAN").length,
    SYN_FLOOD:       alerts.filter((a) => a.alert_type === "SYN_FLOOD").length,
    ICMP_SWEEP:      alerts.filter((a) => a.alert_type === "ICMP_SWEEP").length,
    SSH_BRUTE_FORCE: alerts.filter((a) => a.alert_type === "SSH_BRUTE_FORCE").length,
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-200">
      <header className="border-b border-gray-800 px-6 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-green-400 tracking-tight">
            NIDS <span className="text-gray-500 font-normal">/ alert dashboard</span>
          </h1>
          <p className="text-xs text-gray-600 mt-0.5">Lightweight Network Intrusion Detection System</p>
        </div>
        <div className="text-right text-xs text-gray-600">
          {lastUpdated && <div>last updated: {lastUpdated}</div>}
          <div className="flex items-center justify-end gap-1.5 mt-1">
            <span className="w-2 h-2 rounded-full bg-green-500 inline-block animate-pulse"></span>
            <span>polling every 3s</span>
          </div>
        </div>
      </header>

      <main className="px-6 py-6 space-y-6">
        {error && (
          <div className="bg-red-950 border border-red-800 text-red-400 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        )}

        <div>
          <h2 className="text-xs text-gray-500 uppercase tracking-wider mb-3">Alert counts by type</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard label="Port scan"       count={counts.PORT_SCAN}       color="text-yellow-400" />
            <StatCard label="SYN flood"       count={counts.SYN_FLOOD}       color="text-red-400" />
            <StatCard label="ICMP sweep"      count={counts.ICMP_SWEEP}      color="text-cyan-400" />
            <StatCard label="SSH brute force" count={counts.SSH_BRUTE_FORCE} color="text-orange-400" />
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-xs text-gray-500 uppercase tracking-wider">
              Alert log
              <span className="ml-2 text-gray-700">({alerts.length} total)</span>
            </h2>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg">
            <AlertTable alerts={alerts} />
          </div>
        </div>
      </main>
    </div>
  );
}
