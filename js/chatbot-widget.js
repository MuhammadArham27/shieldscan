/**
 * ShieldScan — chatbot-widget.js
 * Floating AI chat bubble injected on every authenticated page.
 */

(function () {

  // Don't show on the dedicated chatbot page
  if (window.location.pathname.includes("chatbot.html")) return;

  let history = [];
  let isOpen  = false;
  let isTyping = false;

  // ── Inject CSS ──────────────────────────────────────────────────────────────
  const style = document.createElement("style");
  style.textContent = `
    /* ── Floating button ── */
    #cw-btn {
      position: fixed; bottom: 1.5rem; right: 1.5rem; z-index: 8000;
      width: 54px; height: 54px; border-radius: 50%;
      background: linear-gradient(135deg, #00e5ff 0%, #7c4dff 100%);
      border: none; cursor: pointer; box-shadow: 0 4px 20px rgba(0,229,255,.4);
      display: flex; align-items: center; justify-content: center;
      font-size: 1.4rem; transition: transform .2s, box-shadow .2s;
      animation: cw-pulse 3s infinite;
    }
    #cw-btn:hover {
      transform: scale(1.1);
      box-shadow: 0 6px 28px rgba(0,229,255,.6);
    }
    @keyframes cw-pulse {
      0%,100% { box-shadow: 0 4px 20px rgba(0,229,255,.4); }
      50%      { box-shadow: 0 4px 28px rgba(0,229,255,.7); }
    }

    /* ── Badge ── */
    #cw-badge {
      position: fixed; bottom: 3rem; right: 1.3rem; z-index: 8001;
      background: #ff3d3d; color: #fff;
      font-size: .65rem; font-weight: 700;
      width: 18px; height: 18px; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      pointer-events: none; transition: opacity .2s;
    }

    /* ── Chat panel ── */
    #cw-panel {
      position: fixed; bottom: 5rem; right: 1.5rem; z-index: 7999;
      width: 360px; height: 500px;
      background: #111318; border: 1px solid #1e232c;
      border-radius: 16px; box-shadow: 0 8px 40px rgba(0,0,0,.6);
      display: flex; flex-direction: column; overflow: hidden;
      transform: scale(.9) translateY(20px); opacity: 0;
      pointer-events: none;
      transition: transform .25s cubic-bezier(.34,1.56,.64,1), opacity .2s;
    }
    #cw-panel.cw-open {
      transform: scale(1) translateY(0); opacity: 1;
      pointer-events: all;
    }

    /* ── Panel header ── */
    #cw-header {
      display: flex; align-items: center; gap: .7rem;
      padding: .85rem 1rem;
      background: #181c22; border-bottom: 1px solid #1e232c;
      flex-shrink: 0;
    }
    #cw-avatar {
      width: 34px; height: 34px; border-radius: 50%;
      background: rgba(0,229,255,.15);
      border: 1px solid rgba(0,229,255,.3);
      display: flex; align-items: center; justify-content: center;
      font-size: 1.1rem;
    }
    #cw-title { flex: 1; }
    #cw-title strong {
      display: block; font-size: .88rem; font-weight: 700;
      color: #e8eaf0;
    }
    #cw-title span {
      font-size: .7rem; color: #5a6278;
      font-family: monospace;
    }
    .cw-status-dot {
      width: 7px; height: 7px; border-radius: 50%;
      background: #00e676; display: inline-block;
      margin-right: 4px; box-shadow: 0 0 5px #00e676;
      animation: cw-blink 2s infinite;
    }
    @keyframes cw-blink {
      0%,100%{opacity:1} 50%{opacity:.4}
    }
    #cw-close-btn {
      background: transparent; border: none; cursor: pointer;
      color: #5a6278; font-size: 1.1rem; padding: .2rem;
      line-height: 1; transition: color .2s;
    }
    #cw-close-btn:hover { color: #ff3d3d; }

    /* ── Messages ── */
    #cw-messages {
      flex: 1; overflow-y: auto; padding: .9rem;
      display: flex; flex-direction: column; gap: .7rem;
      scroll-behavior: smooth;
    }
    #cw-messages::-webkit-scrollbar { width: 4px; }
    #cw-messages::-webkit-scrollbar-track { background: transparent; }
    #cw-messages::-webkit-scrollbar-thumb { background: #1e232c; border-radius: 2px; }

    .cw-msg { display: flex; gap: .5rem; align-items: flex-end; }
    .cw-msg-user { flex-direction: row-reverse; }

    .cw-msg-av {
      width: 26px; height: 26px; border-radius: 50%; flex-shrink: 0;
      background: rgba(0,229,255,.12);
      border: 1px solid rgba(0,229,255,.2);
      display: flex; align-items: center; justify-content: center;
      font-size: .8rem;
    }

    .cw-bubble {
      max-width: 80%; padding: .6rem .85rem;
      border-radius: 12px; font-size: .8rem; line-height: 1.55;
      word-break: break-word;
    }
    .cw-msg-bot .cw-bubble {
      background: #181c22; border: 1px solid #1e232c;
      color: #9ba3b0; border-bottom-left-radius: 3px;
    }
    .cw-msg-user .cw-bubble {
      background: rgba(0,229,255,.12);
      border: 1px solid rgba(0,229,255,.2);
      color: #e8eaf0; border-bottom-right-radius: 3px;
    }
    .cw-bubble strong { color: #e8eaf0; }
    .cw-bubble code {
      font-family: monospace; font-size: .75rem;
      background: rgba(0,229,255,.08); border-radius: 3px;
      padding: .1em .35em;
    }

    /* typing dots */
    .cw-typing { display: flex; align-items: center; gap: 4px; padding: .5rem .7rem; }
    .cw-dot {
      width: 6px; height: 6px; border-radius: 50%;
      background: #5a6278; animation: cw-bounce .9s infinite;
    }
    .cw-dot:nth-child(2){animation-delay:.15s}
    .cw-dot:nth-child(3){animation-delay:.3s}
    @keyframes cw-bounce{0%,80%,100%{transform:scale(1);opacity:.4}40%{transform:scale(1.3);opacity:1}}

    /* ── Input row ── */
    #cw-input-row {
      display: flex; gap: .5rem; align-items: center;
      padding: .7rem .9rem;
      border-top: 1px solid #1e232c; background: #181c22;
      flex-shrink: 0;
    }
    #cw-input {
      flex: 1; background: #111318; border: 1px solid #1e232c;
      border-radius: 8px; padding: .55rem .8rem;
      color: #e8eaf0; font-size: .82rem; outline: none;
      font-family: inherit; resize: none; line-height: 1.4;
      max-height: 80px; overflow-y: auto;
      transition: border-color .2s;
    }
    #cw-input:focus { border-color: #00e5ff; }
    #cw-input::placeholder { color: #5a6278; }
    #cw-send {
      width: 34px; height: 34px; border-radius: 8px;
      background: #00e5ff; color: #000; border: none;
      cursor: pointer; font-size: .85rem;
      display: flex; align-items: center; justify-content: center;
      flex-shrink: 0; transition: filter .2s;
    }
    #cw-send:hover    { filter: brightness(1.15); }
    #cw-send:disabled { opacity: .4; cursor: not-allowed; }

    /* ── Shortcut link ── */
    #cw-fullpage {
      text-align: center; padding: .4rem;
      font-size: .7rem; color: #5a6278; font-family: monospace;
      border-top: 1px solid #1e232c; background: #181c22;
      flex-shrink: 0;
    }
    #cw-fullpage a { color: #00e5ff; text-decoration: none; }
    #cw-fullpage a:hover { text-decoration: underline; }

    @media (max-width: 480px) {
      #cw-panel { width: calc(100vw - 2rem); right: 1rem; }
    }
  `;
  document.head.appendChild(style);

  // ── Inject HTML ─────────────────────────────────────────────────────────────
  document.body.insertAdjacentHTML("beforeend", `
    <div id="cw-badge">1</div>

    <button id="cw-btn" title="Ask ShieldBot">🤖</button>

    <div id="cw-panel">
      <div id="cw-header">
        <div id="cw-avatar">🤖</div>
        <div id="cw-title">
          <strong>ShieldBot</strong>
          <span><span class="cw-status-dot"></span>AI Security Assistant</span>
        </div>
        <button id="cw-close-btn" title="Close">✕</button>
      </div>

      <div id="cw-messages"></div>

      <div id="cw-input-row">
        <textarea id="cw-input" rows="1" placeholder="Ask about URL safety..."></textarea>
        <button id="cw-send" title="Send">➤</button>
      </div>

      <div id="cw-fullpage">
        <a href="chatbot.html">Open full chatbot →</a>
      </div>
    </div>
  `);

  // ── Elements ────────────────────────────────────────────────────────────────
  const btn      = document.getElementById("cw-btn");
  const panel    = document.getElementById("cw-panel");
  const badge    = document.getElementById("cw-badge");
  const messages = document.getElementById("cw-messages");
  const input    = document.getElementById("cw-input");
  const sendBtn  = document.getElementById("cw-send");
  const closeBtn = document.getElementById("cw-close-btn");

  // ── Welcome message ─────────────────────────────────────────────────────────
  appendMsg("bot", "👋 Hi! I'm ShieldBot. Paste a URL or ask me anything about online security!");

  // ── Toggle panel ────────────────────────────────────────────────────────────
  btn.addEventListener("click", () => {
    isOpen = !isOpen;
    panel.classList.toggle("cw-open", isOpen);
    btn.textContent = isOpen ? "✕" : "🤖";
    badge.style.opacity = "0";
    if (isOpen) input.focus();
  });

  closeBtn.addEventListener("click", () => {
    isOpen = false;
    panel.classList.remove("cw-open");
    btn.textContent = "🤖";
  });

  // ── Send message ─────────────────────────────────────────────────────────────
  sendBtn.addEventListener("click", handleSend);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  });
  input.addEventListener("input", () => {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 80) + "px";
  });

  function handleSend() {
    const text = input.value.trim();
    if (!text || isTyping) return;
    input.value = "";
    input.style.height = "auto";
    sendMessage(text);
  }

  async function sendMessage(text) {
    appendMsg("user", text);
    history.push({ role: "user", content: text });

    isTyping = true;
    sendBtn.disabled = true;
    const typingId = showTyping();

    try {
      const data = await API.post("/api/chat", { messages: history });
      removeTyping(typingId);
      appendMsg("bot", data.reply);
      history.push({ role: "assistant", content: data.reply });

      // Badge pulse if panel closed
      if (!isOpen) {
        badge.style.opacity = "1";
        badge.textContent = "+1";
      }
    } catch (err) {
      removeTyping(typingId);
      const msg = err.status === 503
        ? "⚠️ AI not configured. Set GEMINI_API_KEY."
        : `⚠️ ${err.data?.error || "Something went wrong."}`;
      appendMsg("bot", msg);
    } finally {
      isTyping = false;
      sendBtn.disabled = false;
    }
  }

  // ── Helpers ─────────────────────────────────────────────────────────────────

  function appendMsg(role, text) {
    const wrap = document.createElement("div");
    wrap.className = `cw-msg cw-msg-${role}`;

    const av = document.createElement("div");
    av.className = "cw-msg-av";
    av.textContent = role === "bot" ? "🤖" : "👤";

    const bubble = document.createElement("div");
    bubble.className = "cw-bubble";
    bubble.innerHTML = fmt(text);

    wrap.appendChild(av);
    wrap.appendChild(bubble);
    messages.appendChild(wrap);
    messages.scrollTop = messages.scrollHeight;
  }

  function showTyping() {
    const id = "cwt-" + Date.now();
    const wrap = document.createElement("div");
    wrap.className = "cw-msg cw-msg-bot";
    wrap.id = id;
    wrap.innerHTML = `
      <div class="cw-msg-av">🤖</div>
      <div class="cw-bubble" style="padding:.4rem .7rem">
        <div class="cw-typing">
          <div class="cw-dot"></div>
          <div class="cw-dot"></div>
          <div class="cw-dot"></div>
        </div>
      </div>`;
    messages.appendChild(wrap);
    messages.scrollTop = messages.scrollHeight;
    return id;
  }

  function removeTyping(id) {
    document.getElementById(id)?.remove();
  }

  function fmt(text) {
    return text
      .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\n/g, "<br>");
  }

})();
