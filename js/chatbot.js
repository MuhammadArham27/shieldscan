/**
 * ShieldScan — chatbot.js
 * Powers the ShieldBot AI assistant via the /api/chat backend endpoint.
 */

document.addEventListener("DOMContentLoaded", () => {

  const messagesEl = document.getElementById("chatMessages");
  const inputEl    = document.getElementById("chatInput");
  const sendBtn    = document.getElementById("sendBtn");
  const clearBtn   = document.getElementById("clearBtn");

  // Conversation history kept in-memory for multi-turn context
  let history = [];
  let isTyping = false;

  // ── Welcome message ─────────────────────────────────────────────────────────

  appendMessage("bot", `👋 Hi! I'm **ShieldBot**, your AI security assistant.

I can help you with:
• Analyzing URLs for threats and phishing signals
• Explaining cybersecurity concepts
• Reviewing scan results
• Answering safe-browsing questions

Paste a URL or ask me anything about online safety!`);

  // ── Suggestion buttons ──────────────────────────────────────────────────────

  document.querySelectorAll(".suggestion-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const prompt = btn.dataset.prompt;
      if (prompt) sendMessage(prompt);
    });
  });

  // ── Send on Enter (Shift+Enter = newline) ───────────────────────────────────

  inputEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  });

  // Auto-resize textarea
  inputEl.addEventListener("input", () => {
    inputEl.style.height = "auto";
    inputEl.style.height = Math.min(inputEl.scrollHeight, 160) + "px";
  });

  sendBtn.addEventListener("click", handleSend);
  clearBtn.addEventListener("click", clearChat);

  // ── Core functions ──────────────────────────────────────────────────────────

  function handleSend() {
    const text = inputEl.value.trim();
    if (!text || isTyping) return;
    inputEl.value = "";
    inputEl.style.height = "auto";
    sendMessage(text);
  }

  async function sendMessage(text) {
    appendMessage("user", text);
    history.push({ role: "user", content: text });

    isTyping = true;
    sendBtn.disabled = true;
    const typingId = showTyping();

    try {
      const data = await API.post("/api/chat", { messages: history });
      removeTyping(typingId);

      const reply = data.reply;
      appendMessage("bot", reply);
      history.push({ role: "assistant", content: reply });

    } catch (err) {
      removeTyping(typingId);
      const errMsg = err.status === 503
        ? "⚠️ The AI assistant is not configured yet. Set `ANTHROPIC_API_KEY` in your environment."
        : err.status === 429
        ? "⚠️ Rate limit reached. Please wait a moment before sending another message."
        : `⚠️ Error: ${err.data?.error || "Something went wrong. Please try again."}`;
      appendMessage("bot", errMsg, "error");
    } finally {
      isTyping = false;
      sendBtn.disabled = false;
      inputEl.focus();
    }
  }

  function appendMessage(role, text, variant = "") {
    const wrap = document.createElement("div");
    wrap.className = `msg msg-${role}${variant ? " msg-" + variant : ""}`;

    const bubble = document.createElement("div");
    bubble.className = "msg-bubble";
    bubble.innerHTML = formatMarkdown(text);

    if (role === "bot") {
      const avatar = document.createElement("div");
      avatar.className = "msg-avatar";
      avatar.textContent = "🤖";
      wrap.appendChild(avatar);
    }

    wrap.appendChild(bubble);
    messagesEl.appendChild(wrap);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return wrap;
  }

  function showTyping() {
    const id = "typing-" + Date.now();
    const wrap = document.createElement("div");
    wrap.className = "msg msg-bot";
    wrap.id = id;
    wrap.innerHTML = `
      <div class="msg-avatar">🤖</div>
      <div class="msg-bubble typing-bubble">
        <span class="dot"></span><span class="dot"></span><span class="dot"></span>
      </div>`;
    messagesEl.appendChild(wrap);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return id;
  }

  function removeTyping(id) {
    document.getElementById(id)?.remove();
  }

  function clearChat() {
    history = [];
    messagesEl.innerHTML = "";
    appendMessage("bot", "Chat cleared. How can I help you with URL security today?");
    showToast("Chat cleared", "info");
  }

  // ── Basic markdown renderer ─────────────────────────────────────────────────
  // Supports: **bold**, `code`, bullet lists, line breaks

  function formatMarkdown(text) {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/^[•\-\*] (.+)$/gm, "<li>$1</li>")
      .replace(/(<li>.*<\/li>(\n|$))+/g, m => `<ul>${m}</ul>`)
      .replace(/\n/g, "<br>");
  }
});
