/**
 * ShieldScan — auth.js
 * Handles login and signup form submission.
 */

document.addEventListener("DOMContentLoaded", () => {

  // ── Sign In ────────────────────────────────────────────────────────────────
  const loginForm = document.getElementById("loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = document.getElementById("loginEmail").value.trim();
      const pw    = document.getElementById("loginPass").value;
      const errEl = document.getElementById("loginError");
      errEl.textContent = "";

      if (!email || !pw) {
        errEl.textContent = "Please enter your email and password.";
        return;
      }

      const btn = loginForm.querySelector("button[type=submit]");
      btn.disabled   = true;
      btn.textContent = "Signing in…";

      try {
        const data = await API.post("/api/auth/login", { email, password: pw });
        Auth.save(data.token, data.name, data.email);
        window.location.href = "dashboard.html";
      } catch (err) {
        errEl.textContent = err.data?.error || "Login failed. Please try again.";
        btn.disabled   = false;
        btn.textContent = "Sign In →";
      }
    });
  }

  // ── Sign Up ────────────────────────────────────────────────────────────────
  const signupForm = document.getElementById("signupForm");
  if (signupForm) {
    const passInput = document.getElementById("signupPass");

    // Password strength indicator
    if (passInput) {
      passInput.addEventListener("input", () => {
        const pw  = passInput.value;
        const bars = [
          document.getElementById("pwBar1"),
          document.getElementById("pwBar2"),
          document.getElementById("pwBar3"),
        ];

        let strength = 0;
        if (pw.length >= 8)                        strength++;
        if (/[A-Z]/.test(pw) && /[0-9]/.test(pw)) strength++;
        if (/[^a-zA-Z0-9]/.test(pw))              strength++;

        const colors = ["#e74c3c", "#f39c12", "#00e676"];
        bars.forEach((bar, i) => {
          if (!bar) return;
          bar.style.background = i < strength ? colors[strength - 1] : "";
          bar.style.opacity    = i < strength ? "1" : "0.2";
        });
      });
    }

    signupForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name  = document.getElementById("signupName").value.trim();
      const email = document.getElementById("signupEmail").value.trim();
      const pw    = document.getElementById("signupPass").value;
      const errEl = document.getElementById("signupError");
      errEl.textContent = "";

      if (!name || !email || !pw) {
        errEl.textContent = "All fields are required.";
        return;
      }
      if (pw.length < 8) {
        errEl.textContent = "Password must be at least 8 characters.";
        return;
      }

      const btn = signupForm.querySelector("button[type=submit]");
      btn.disabled   = true;
      btn.textContent = "Creating account…";

      try {
        const data = await API.post("/api/auth/signup", { name, email, password: pw });
        Auth.save(data.token, data.name, data.email);
        window.location.href = "dashboard.html";
      } catch (err) {
        errEl.textContent = err.data?.error || "Signup failed. Please try again.";
        btn.disabled   = false;
        btn.textContent = "Create Account →";
      }
    });
  }

  // Redirect already-logged-in users away from auth pages
  if (Auth.isLoggedIn()) {
    window.location.href = "dashboard.html";
  }
});
