const refreshSeconds = window.HNSDOH_UI_REFRESH_SECONDS || 30;

function badgeFor(result) {
  const badgeClass = result.ok ? "badge badge-ok" : "badge badge-bad";
  const label = result.ok ? "UP" : "DOWN";
  const latency = result.latency_ms === null ? "" : ` (${result.latency_ms} ms)`;
  const reason = result.reason || "";

  return `
    <span class="${badgeClass}">${label}${latency}</span>
    <span class="hint">${reason}</span>
  `;
}

function historyDots(history, protocol) {
  if (!history || history.length === 0) {
    return "";
  }

  const recent = history.slice(-10);
  const dots = recent
    .map((entry) => {
      const r = entry[protocol];
      if (!r) return '<span class="dot"></span>';
      return `<span class="dot ${r.ok ? "ok" : "bad"}"></span>`;
    })
    .join("");

  return `<div class="history">${dots}</div>`;
}

function rowForNode(node, history) {
  const udp = node.results.dns_udp;
  const tcp = node.results.dns_tcp;
  const doh = node.results.doh;
  const dot = node.results.dot;

  return `
    <tr>
      <td>${node.ip}</td>
      <td>${badgeFor(udp)}${historyDots(history, "dns_udp")}</td>
      <td>${badgeFor(tcp)}${historyDots(history, "dns_tcp")}</td>
      <td>${badgeFor(doh)}${historyDots(history, "doh")}</td>
      <td>${badgeFor(dot)}${historyDots(history, "dot")}</td>
    </tr>
  `;
}

async function refreshStatus() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    const data = await response.json();
    const tableBody = document.getElementById("status-table-body");
    const lastUpdated = document.getElementById("last-updated");

    if (!data.current) {
      tableBody.innerHTML = '<tr><td colspan="5">No data yet. Waiting for first check.</td></tr>';
      return;
    }

    lastUpdated.textContent = `Last updated: ${data.current.checked_at}`;

    const rows = data.current.nodes
      .map((node) => rowForNode(node, data.history[node.ip] || []))
      .join("");

    tableBody.innerHTML = rows || '<tr><td colspan="5">No nodes discovered.</td></tr>';
  } catch (error) {
    const tableBody = document.getElementById("status-table-body");
    tableBody.innerHTML = `<tr><td colspan="5">Failed to load status: ${error}</td></tr>`;
  }
}

refreshStatus();
setInterval(refreshStatus, refreshSeconds * 1000);
