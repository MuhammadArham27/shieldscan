/**
 * ShieldScan — dashboard.js
 * Loads stats, handles quick scan, and renders scan history.
 */

document.addEventListener("DOMContentLoaded", async () => {

  await loadHistory();

  // ── Quick scan ──────────────────────────────────────────────────────────────

  const quickInput  = document.getElementById("quickInput");
  const quickScanBtn = document.getElementById("quickScanBtn");
  const quickLabel  = document.getElementById("quickBtnLabel");
  const quickSpinner = document.getElementById("quickSpinner");
  const quickResult = document.getElementById("quickResult");

  if (quickScanBtn) {
    quickScanBtn.addEventListener("click", runQuickScan);
    quickInput?.addEventListener("keydown", e => {
      if (e.key === "Enter") runQuickScan();
    });
  }

  async function runQuickScan() {
    const url = quickInput.value.trim();
    if (!url) {
      showToast("Enter a URL first", "warn");
      quickInput.focus();
      return;
    }

    setQuickLoading(true);
    quickResult.innerHTML = "";

    try {
      const result = await API.post("/api/scan", { url });
      renderQuickResult(result);
      await loadHistory();      // refresh history + stats
    } catch (err) {
      quickResult.innerHTML = `<div class="result-error">⚠️ ${err.data?.error || "Scan failed."}</div>`;
    } finally {
      setQuickLoading(false);
    }
  }

  function setQuickLoading(on) {
    quickScanBtn.disabled      = on;
    quickLabel.style.display   = on ? "none" : "inline";
    quickSpinner.style.display = on ? "inline-block" : "none";
  }

  function renderQuickResult(r) {
    const verdictMeta = {
      safe:    { color: "#00e676", icon: "✅", label: "Safe" },
      warning: { color: "#ffd600", icon: "⚠️", label: "Suspicious" },
      danger:  { color: "#ff3d3d", icon: "🚫", label: "Dangerous" },
    };
    const m = verdictMeta[r.verdict] || verdictMeta.warning;

    quickResult.innerHTML = `
      <div style="display:flex;align-items:center;gap:.8rem;padding:.9rem 1rem;
        background:var(--surface);border-radius:10px;border-left:3px solid ${m.color};">
        <span style="font-size:1.5rem">${m.icon}</span>
        <div style="flex:1">
          <strong style="color:${m.color}">${m.label}</strong>
          <span style="color:var(--text-dim);font-family:var(--mono);font-size:.78rem;margin-left:.5rem">
            Score: ${r.score}/100
          </span>
          <div style="color:var(--text-dim);font-size:.75rem;font-family:var(--mono);margin-top:.2rem">
            ${r.verdict_msg}
          </div>
        </div>
        <a href="scanner.html?url=${encodeURIComponent(r.url)}"
           style="font-size:.76rem;color:var(--accent);font-family:var(--mono);white-space:nowrap;">
          Deep scan →
        </a>
      </div>`;
  }

  // ── History & stats ─────────────────────────────────────────────────────────

  async function loadHistory() {
    try {
      const history = await API.get("/api/scan/history");
      renderStats(history);
      renderHistory(history);
    } catch (_) {}
  }

  function renderStats(history) {
    const total  = history.length;
    const safe   = history.filter(r => r.verdict === "safe").length;
    const warn   = history.filter(r => r.verdict === "warning").length;
    const danger = history.filter(r => r.verdict === "danger").length;

    const set = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    set("statTotal",  total);
    set("statSafe",   safe);
    set("statWarn",   warn);
    set("statDanger", danger);
  }

  function renderHistory(history) {
    const tbody = document.getElementById("histBody");
    if (!tbody) return;

    if (!history.length) {
      tbody.innerHTML = `<tr><td colspan="4">
        <div class="empty-state">
          <div class="empty-icon">🔍</div>
          No scans yet — paste a URL above to get started
        </div>
      </td></tr>`;
      return;
    }

    const verdictBadge = {
      safe:    '<span class="badge badge-safe">✅ Safe</span>',
      warning: '<span class="badge badge-warn">⚠️ Suspicious</span>',
      danger:  '<span class="badge badge-danger">🚫 Dangerous</span>',
    };

    tbody.innerHTML = history.slice(0, 20).map(r => {
      const ts   = new Date(r.timestamp * 1000);
      const time = ts.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const date = ts.toLocaleDateString([], { month: "short", day: "numeric" });
      const shortUrl = r.url.length > 55 ? r.url.slice(0, 52) + "…" : r.url;

      return `<tr>
        <td>
          <a href="scanner.html?url=${encodeURIComponent(r.url)}"
             style="color:var(--accent);font-family:var(--mono);font-size:0.78rem;
                    text-decoration:none;word-break:break-all;">
            ${escHtml(shortUrl)}
          </a>
        </td>
        <td>${verdictBadge[r.verdict] || r.verdict}</td>
        <td>
          <span style="font-family:var(--mono);font-weight:700;
            color:${r.score >= 75 ? "#00e676" : r.score >= 45 ? "#ffd600" : "#ff3d3d"}">
            ${r.score}
          </span>
        </td>
        <td style="font-family:var(--mono);font-size:0.75rem;color:var(--text-dim)">
          ${date} ${time}
        </td>
      </tr>`;
    }).join("");
  }

  function escHtml(str) {
    return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  }
});
