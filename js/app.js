/**
 * ShieldScan — app.js
 * Shared utilities: API client, auth helpers, toast, navbar init
 */

// ── API client ────────────────────────────────────────────────────────────────

const API = {
  BASE: "",   // Same origin; change to "http://localhost:5000" for dev if needed

  _getToken() {
    return localStorage.getItem("ss_token") || "";
  },

  async _request(method, path, body = null) {
    const headers = { "Content-Type": "application/json" };
    const token = this._getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const opts = { method, headers };
    if (body !== null) opts.body = JSON.stringify(body);

    const res = await fetch(this.BASE + path, opts);
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      throw Object.assign(new Error(data.error || "Request failed"), { status: res.status, data });
    }
    return data;
  },

  get:    (path)        => API._request("GET",    path),
  post:   (path, body)  => API._request("POST",   path, body),
  delete: (path)        => API._request("DELETE", path),
};

// ── Auth helpers ──────────────────────────────────────────────────────────────

const Auth = {
  save(token, name, email) {
    localStorage.setItem("ss_token", token);
    localStorage.setItem("ss_name",  name);
    localStorage.setItem("ss_email", email);
  },

  clear() {
    ["ss_token", "ss_name", "ss_email"].forEach(k => localStorage.removeItem(k));
  },

  isLoggedIn() {
    return !!localStorage.getItem("ss_token");
  },

  getName()  { return localStorage.getItem("ss_name")  || "User"; },
  getEmail() { return localStorage.getItem("ss_email") || ""; },

  requireAuth() {
    if (!this.isLoggedIn()) {
      window.location.href = "login.html";
      return false;
    }
    return true;
  },

  async logout() {
    try { await API.post("/api/auth/logout"); } catch (_) {}
    this.clear();
    window.location.href = "login.html";
  },
};

// ── Navbar init ───────────────────────────────────────────────────────────────

function initNavbar() {
  const name    = Auth.getName();
  const avatarEl = document.getElementById("navAvatar");
  const nameEl   = document.getElementById("navUsername");
  if (avatarEl) avatarEl.textContent = name.charAt(0).toUpperCase();
  if (nameEl)   nameEl.textContent   = name;

  const logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) logoutBtn.addEventListener("click", () => Auth.logout());

  // Highlight active nav link
  const page = document.body.dataset.page ||
    window.location.pathname.split("/").pop().replace(".html", "");
  document.querySelectorAll(".nav-link[data-page]").forEach(el => {
    if (el.dataset.page === page) el.classList.add("active");
  });
}

// ── Toast ─────────────────────────────────────────────────────────────────────

function showToast(msg, type = "info") {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent  = msg;
  el.className    = `toast toast-${type} visible`;
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.remove("visible"), 3400);
}

// ── DOM ready ─────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  // Pages that require login (all except auth pages)
  const publicPages = ["index.html", "signup.html", "home.html", ""];
  const currentPage = window.location.pathname.split("/").pop();
  if (!publicPages.includes(currentPage)) {
    if (!Auth.requireAuth()) return;
    initNavbar();
  }
});
