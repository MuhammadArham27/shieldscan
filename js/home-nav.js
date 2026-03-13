/**
 * ShieldScan — home-nav.js
 * Smart navbar for home.html:
 * - Logged OUT → shows Sign In + Sign Up buttons
 * - Logged IN  → shows username + Dashboard + Sign Out
 */

document.addEventListener("DOMContentLoaded", () => {
  const isLoggedIn = !!localStorage.getItem("ss_token");
  const name       = localStorage.getItem("ss_name") || "User";

  const navRight = document.querySelector(".home-nav-right, .nav-right, #navRight");
  if (!navRight) return;

  if (isLoggedIn) {
    navRight.innerHTML = `
      <div style="display:flex;align-items:center;gap:.8rem;">
        <div style="display:flex;align-items:center;gap:.5rem;">
          <div style="
            width:30px;height:30px;border-radius:50%;
            background:linear-gradient(135deg,#00e5ff 0%,#7c4dff 100%);
            display:flex;align-items:center;justify-content:center;
            font-size:.78rem;font-weight:700;color:#000;">
            ${name.charAt(0).toUpperCase()}
          </div>
          <span style="font-size:.85rem;color:#9ba3b0;">${name}</span>
        </div>
        <a href="dashboard.html" style="
          padding:.4rem .9rem;border-radius:7px;
          background:rgba(0,229,255,.12);border:1px solid rgba(0,229,255,.3);
          color:#00e5ff;font-size:.82rem;font-weight:600;text-decoration:none;">
          Dashboard
        </a>
        <button id="homeSignOut" style="
          padding:.4rem .9rem;border-radius:7px;
          background:transparent;border:1px solid #1e232c;
          color:#5a6278;font-size:.82rem;cursor:pointer;">
          Sign Out
        </button>
      </div>`;

    document.getElementById("homeSignOut").addEventListener("click", async () => {
      try {
        const token = localStorage.getItem("ss_token");
        await fetch("/api/auth/logout", {
          method: "POST",
          headers: { "Authorization": `Bearer ${token}` }
        });
      } catch (_) {}
      localStorage.removeItem("ss_token");
      localStorage.removeItem("ss_name");
      localStorage.removeItem("ss_email");
      window.location.reload();
    });

  } else {
    navRight.innerHTML = `
      <div style="display:flex;align-items:center;gap:.6rem;">
        <a href="index.html" style="
          padding:.45rem 1rem;border-radius:7px;
          background:transparent;border:1px solid #1e232c;
          color:#9ba3b0;font-size:.83rem;font-weight:500;text-decoration:none;">
          Sign In
        </a>
        <a href="signup.html" style="
          padding:.45rem 1rem;border-radius:7px;
          background:#00e5ff;color:#000;
          font-size:.83rem;font-weight:700;text-decoration:none;">
          Sign Up Free
        </a>
      </div>`;
  }
});
