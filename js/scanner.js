/**
 * ShieldScan — scanner.js
 * Deep 10-point URL analysis via /api/scan
 */

document.addEventListener("DOMContentLoaded", () => {

  const urlInput  = document.getElementById("urlInput");
  const scanBtn   = document.getElementById("scanBtn");
  const btnLabel  = document.getElementById("btnLabel");
  const spinner   = document.getElementById("scanSpinner");
  const resultWrap = document.getElementById("resultWrap");

  if (!scanBtn) return;

  // Pre-fill from query string e.g. scanner.html?url=https://...
  const params = new URLSearchParams(window.location.search);
  if (params.get("url")) {
    urlInput.value = params.get("url");
    runScan();
  }

  scanBtn.addEventListener("click", runScan);
  urlInput.addEventListener("keydown", e => {
    if (e.key === "Enter") runScan();
  });

  async function runScan() {
    const url = urlInput.value.trim();
    if (!url) {
      showToast("Please enter a URL first", "warn");
      urlInput.focus();
      return;
    }

    setLoading(true);
    resultWrap.innerHTML = "";

    try {
      const result = await API.post("/api/scan", { url });
      renderResult(result);
    } catch (err) {
      resultWrap.innerHTML = `<div class="result-error">⚠️ ${err.data?.error || "Scan failed — please try again."}</div>`;
    } finally {
      setLoading(false);
    }
  }

  function setLoading(on) {
    scanBtn.disabled       = on;
    btnLabel.style.display = on ? "none"   : "inline";
    spinner.style.display  = on ? "inline-block" : "none";
  }

  function renderResult(r) {
    const verdictColors = {
      safe:    { bg: "rgba(0,230,118,.08)", border: "#00e676", icon: "✅", label: "SAFE" },
      warning: { bg: "rgba(255,214,0,.08)",  border: "#ffd600", icon: "⚠️", label: "SUSPICIOUS" },
      danger:  { bg: "rgba(255,61,61,.08)",  border: "#ff3d3d", icon: "🚫", label: "DANGEROUS" },
    };
    const vc = verdictColors[r.verdict] || verdictColors.warning;

    // Summary banner
    const banner = document.createElement("div");
    banner.className = "scan-banner";
    banner.style.cssText = `
      background:${vc.bg};border:1px solid ${vc.border};border-radius:12px;
      padding:1.4rem 1.6rem;margin-bottom:1.2rem;display:flex;
      align-items:center;gap:1.2rem;`;
    banner.innerHTML = `
      <div style="font-size:2.2rem;line-height:1">${vc.icon}</div>
      <div style="flex:1">
        <div style="font-size:1.1rem;font-weight:700;color:${vc.border};letter-spacing:.08em">${vc.label}</div>
        <div style="font-size:0.82rem;color:var(--text-dim);font-family:var(--mono);margin-top:.25rem">${r.verdict_msg}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:2.5rem;font-weight:800;color:${vc.border};line-height:1">${r.score}</div>
        <div style="font-size:0.7rem;color:var(--text-dim);font-family:var(--mono)">/ 100</div>
      </div>`;
    resultWrap.appendChild(banner);

    // Normalized URL
    const urlRow = document.createElement("div");
    urlRow.style.cssText = "font-family:var(--mono);font-size:0.75rem;color:var(--text-dim);margin-bottom:1rem;word-break:break-all;";
    urlRow.textContent = `Analyzed: ${r.normalized_url}`;
    resultWrap.appendChild(urlRow);

    // Check list
    const grid = document.createElement("div");
    grid.style.cssText = "display:grid;gap:.5rem;";

    r.checks.forEach(check => {
      const row = document.createElement("div");
      row.style.cssText = `
        display:flex;align-items:flex-start;gap:.8rem;padding:.8rem 1rem;
        background:var(--surface);border-radius:8px;
        border-left:3px solid ${check.pass ? "#00e676" : severityColor(check.severity)};`;
      row.innerHTML = `
        <div style="font-size:1.2rem;line-height:1.3">${check.icon}</div>
        <div style="flex:1;min-width:0">
          <div style="font-size:.82rem;font-weight:700;color:var(--text-bright)">${check.name}</div>
          <div style="font-size:.75rem;font-family:var(--mono);color:var(--text-dim);margin-top:.2rem">${check.detail}</div>
        </div>
        <div style="font-size:1rem;flex-shrink:0">${check.pass ? "✅" : "❌"}</div>`;
      grid.appendChild(row);
    });
    resultWrap.appendChild(grid);
  }

  function severityColor(sev) {
    return sev === "high" ? "#ff3d3d" : sev === "medium" ? "#ffd600" : "#ff9100";
  }
});
