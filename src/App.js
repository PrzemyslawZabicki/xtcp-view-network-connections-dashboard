import React, { useEffect, useState, useRef } from "react";
import './App.css';

function logToServer(level, message, details = {}) {
  fetch("http://127.0.0.1:8000/api/frontend-log", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ level, message, details })
  }).catch(() => {});
}

function App() {
  const [connections, setConnections] = useState([]);
  const [securityData, setSecurityData] = useState({});
  const [loadingIPs, setLoadingIPs] = useState({});
  const [loadingConnections, setLoadingConnections] = useState(true); // global loading flag
  const tableRef = useRef(null);
  const [selectedRow, setSelectedRow] = useState(null);


  useEffect(() => {
    const controller = new AbortController();
    logToServer("info", "Started streaming connections");
    setLoadingConnections(true);

    async function fetchStream() {
      const response = await fetch("http://127.0.0.1:8000/api/connections/stream", {
        signal: controller.signal,
      });

      const reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          setLoadingConnections(false); 
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();

        for (const line of lines) {
          if (line.trim()) {
            try {
              const obj = JSON.parse(line);
              setConnections(prev => [...prev, obj]);
              logToServer("info", "New connection received", { ip: obj.remote_ip, pid: obj.pid });

              if (obj.remote_ip && !isLocalhost(obj.remote_ip) && !isPrivateLAN(obj.remote_ip)) {
                if (!securityData[obj.remote_ip]) {
                  setLoadingIPs(prev => ({ ...prev, [obj.remote_ip]: true }));
                  logToServer("debug", "Fetching security data", { ip: obj.remote_ip });
                  fetch(`http://127.0.0.1:8000/api/security-check/${obj.remote_ip}`)
                    .then(res => res.json())
                    .then(data => {
                      setSecurityData(prev => ({ ...prev, [obj.remote_ip]: data }));
                      setLoadingIPs(prev => ({ ...prev, [obj.remote_ip]: false }));
                      logToServer("info", "Security data fetched", { ip: obj.remote_ip });
                    })
                    .catch(err => {
                      setLoadingIPs(prev => ({ ...prev, [obj.remote_ip]: false }));
                      logToServer("error", "Security check failed", { ip: obj.remote_ip, error: err.toString() });
                    });
                }
              }
            } catch (err) {
              logToServer("error", "Bad JSON line", { line });
            }
          }
        }
      }
    }

    fetchStream();
    return () => {
      controller.abort();
      setLoadingConnections(false);
      logToServer("info", "Stopped streaming connections");
    };
  }, [securityData]);

  const thStyle = {
    whiteSpace: "nowrap",
    padding: "6px 12px",
    borderBottom: "1px solid white",
    textAlign: "left"
  };
  const tdStyle = {
    padding: "6px 12px",
    borderBottom: "1px solid #333",
    whiteSpace: "nowrap"
  };

  const isLocalhost = ip => ip === "127.0.0.1" || ip === "localhost";

  const isPrivateLAN = ip => {
    if (!ip) return false;
    if (ip.startsWith("10.")) return true;
    if (ip.startsWith("192.168.")) return true;
    const parts = ip.split(".");
    if (parts.length === 4) {
      const first = parseInt(parts[0], 10);
      const second = parseInt(parts[1], 10);
      if (first === 172 && second >= 16 && second <= 31) return true;
    }
    return false;
  };

  const sortedConnections = [...connections].sort((a, b) => {
    const statusA = (a.status || "").toUpperCase();
    const statusB = (b.status || "").toUpperCase();

    const statusRankA = statusA === "ESTABLISHED" ? 0 : 1;
    const statusRankB = statusB === "ESTABLISHED" ? 0 : 1;
    if (statusRankA !== statusRankB) return statusRankA - statusRankB;
    if (statusRankA === 1 && statusRankB === 1) {
      const cmp = statusA.localeCompare(statusB);
      if (cmp !== 0) return cmp;
    }

    const ipRank = ip => {
      if (isLocalhost(ip)) return 2;
      if (isPrivateLAN(ip)) return 1;
      return 0;
    };
    const ipRankA = ipRank(a.remote_ip);
    const ipRankB = ipRank(b.remote_ip);
    if (ipRankA !== ipRankB) return ipRankA - ipRankB;

    const timeA = a.create_time ? new Date(a.create_time).getTime() : 0;
    const timeB = b.create_time ? new Date(b.create_time).getTime() : 0;
    return timeB - timeA;
  });


  const getSeverityColor = (value, type = "abuse") => {
    if (value == null) return "white";

    if (type === "abuse") {
      if (value >= 80) return "red";
      if (value >= 50) return "orange";
      if (value >= 20) return "yellow";
      return "white";
    }

    if (type === "vt") {
      if (value >= 10) return "red";
      if (value >= 5) return "orange";
      if (value >= 1) return "yellow";
      return "white";
    }

    return "white";
  };

  // -------------------------------
  // Render UI
  // -------------------------------
  return (
    <div style={{ backgroundColor: "black", color: "white", fontFamily: "Consolas", fontSize: "10px", minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <header style={{ padding: "4px", borderBottom: "0px solid white" }}>
        <h1 style={{ marginTop: "4px", fontSize: "14px" }}>
          xTCP View - Network Connections Dashboard
        </h1>
      </header>

      <h2 style={{ fontSize: "12px", marginBottom: "12px", marginLeft: "16px" }}>
        Live Connections{" "}
        {loadingConnections && (
          <span style={{ marginLeft: "10px", fontSize: "12px", color: "white", display: "inline-flex", alignItems: "center" }}>
            Loading network connections
            <div className="spinner"></div>
          </span>
        )}
      </h2>

      <main style={{ flex: 1, padding: "4px" }}>
        <table ref={tableRef} style={{ borderCollapse: "collapse", minWidth: "100%" }}>
          <thead>
            <tr>
              <th style={{ ...thStyle, width: "80px" }}>PID</th>
              <th style={{ ...thStyle, width: "160px" }}>Process Start Time</th>
              <th style={{ ...thStyle, width: "140px" }}>Process</th>
              <th style={{ ...thStyle, width: "200px" }}>Process Path</th>
              <th style={{ ...thStyle, width: "100px" }}>Protocol</th>
              <th style={{ ...thStyle, width: "160px" }}>Local Service</th>
              <th style={{ ...thStyle, width: "100px" }}>Local Port</th>
              <th style={{ ...thStyle, width: "120px" }}>Status</th>
              <th style={{ ...thStyle, width: "120px" }}>Remote Port</th>
              <th style={{ ...thStyle, width: "160px" }}>Remote IP</th>
              <th style={{ ...thStyle, width: "160px" }}>Remote DNS</th>
              <th style={{ ...thStyle, width: "160px" }}>Abuse Confidence</th>
              <th style={{ ...thStyle, width: "140px" }}>Abuse Reports</th>
              <th style={{ ...thStyle, width: "140px" }}>Abuse Country</th>
              <th style={{ ...thStyle, width: "140px" }}>Abuse ISP</th>
              <th style={{ ...thStyle, width: "140px" }}>Abuse Domain</th>
              <th style={{ ...thStyle, width: "160px" }}>Abuse Usage Type</th>
              <th style={{ ...thStyle, width: "180px" }}>Abuse Last Reported</th>
              <th style={{ ...thStyle, width: "140px" }}>VT Reputation</th>
              <th style={{ ...thStyle, width: "140px" }}>VT Country</th>
              <th style={{ ...thStyle, width: "140px" }}>VT Harmless</th>
              <th style={{ ...thStyle, width: "140px" }}>VT Malicious</th>
              <th style={{ ...thStyle, width: "140px" }}>VT Suspicious</th>
              <th style={{ ...thStyle, width: "140px" }}>VT Undetected</th>
              <th style={{ ...thStyle, width: "140px" }}>Local IP</th>
              <th style={{ ...thStyle, width: "220px" }}>Process Command Line</th>
            </tr>
          </thead>
          <tbody>
            {sortedConnections.map((c, idx) => {
              const sec = securityData[c.remote_ip] || {};
              const abuse = sec.abuse || {};
              const vt = sec.vt || {};
              const stats = vt.last_analysis_stats || {};

              return (
                <tr
                  key={idx}
                  onClick={() => setSelectedRow(idx)}
                  style={{
                    backgroundColor: selectedRow === idx ? "black" : "transparent",
                    color: selectedRow === idx ? "cyan" : "inherit",
                    cursor: "pointer",
                    fontSize: "10px",            
                    fontWeight: selectedRow === idx ? "bold" : "normal"
                  }}
                >
                  <td style={tdStyle}>{c.pid || "-"}</td>
                  <td style={tdStyle}>{c.create_time || "-"}</td>
                  <td style={tdStyle}>{c.process || "-"}</td>
                  <td style={tdStyle}>{c.exe || "-"}</td>
                  <td style={tdStyle}>{c.protocol || "-"}</td>
                  <td style={tdStyle}>{c.local_service && c.local_service !== "unknown" ? c.local_service : "-"}</td>
                  <td style={tdStyle}>{c.local_port || "-"}</td>
                  <td style={tdStyle}>{c.status || "-"}</td>
                  <td style={tdStyle}>{c.remote_port || "-"}</td>
                  <td style={tdStyle}>{c.remote_ip || "-"}</td>
                  <td style={tdStyle}>{c.dns && c.dns !== "unknown" ? c.dns : "-"}</td>

                  {/* AbuseIPDB values */}
                  <td style={{ ...tdStyle, color: selectedRow === idx ? "cyan" : getSeverityColor(abuse.abuseConfidenceScore, "abuse"), fontSize: "10px", fontWeight: selectedRow === idx ? "bold" : "normal" }}>
                    {abuse.abuseConfidenceScore ?? "-"}
                  </td>
                  <td style={tdStyle}>{abuse.totalReports || "-"}</td>
                  <td style={tdStyle}>{abuse.countryCode || "-"}</td>
                  <td style={tdStyle}>{abuse.isp || "-"}</td>
                  <td style={tdStyle}>{abuse.domain || "-"}</td>
                  <td style={tdStyle}>{abuse.usageType || "-"}</td>
                  <td style={tdStyle}>{abuse.lastReportedAt || "-"}</td>

                  {/* VirusTotal values */}
                  <td style={{ ...tdStyle, color: selectedRow === idx ? "cyan" : getSeverityColor(vt.reputation, "vt"), fontSize: "10px", fontWeight: selectedRow === idx ? "bold" : "normal" }}>
                    {vt.reputation ?? "-"}
                  </td>
                  <td style={tdStyle}>{vt.country || "-"}</td>
                  <td style={tdStyle}>{stats.harmless ?? "-"}</td>
                  <td style={{ ...tdStyle, color: selectedRow === idx ? "cyan" : getSeverityColor(stats.malicious, "vt"), fontSize: "10px", fontWeight: selectedRow === idx ? "bold" : "normal" }}>
                    {stats.malicious ?? "-"}
                  </td>
                  <td style={{ ...tdStyle, color: selectedRow === idx ? "cyan" : getSeverityColor(stats.suspicious, "vt"), fontSize: "10px", fontWeight: selectedRow === idx ? "bold" : "normal" }}>
                    {stats.suspicious ?? "-"}
                  </td>
                  <td style={tdStyle}>{stats.undetected ?? "-"}</td>
                  <td style={tdStyle}>{c.local_ip || "-"}</td>
                  <td style={tdStyle}>{Array.isArray(c.cmdline) && c.cmdline.length > 0 ? c.cmdline.join(" ") : "-"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </main>

      {/* Footer */}
      <footer style={{ padding: "4px", borderTop: "1px solid white", fontSize: "10px", textAlign: "center" }}>
        © 2026 xTCP View - Network Connections Dashboard [Author: https://github.com/PrzemyslawZabicki]
      </footer>
    </div>
  );
}

export default App;
