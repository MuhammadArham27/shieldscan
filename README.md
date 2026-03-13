# ShieldScan

A cybersecurity URL analysis web app powered by Flask and the Anthropic API.

## Setup

```bash
pip install -r requirements.txt
```

Set your Anthropic API key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Run the server:

```bash
python app.py
```

Visit `http://localhost:5000`

---

## Run Tests

```bash
pytest tests/ -v
```

With coverage report:

```bash
pytest tests/ -v --cov=app --cov-report=term-missing
```

---

## Project Structure

```
shieldscan/
├── app.py              # Flask backend — auth, scan, chat endpoints
├── requirements.txt
├── tests/
│   └── test_app.py     # 35+ pytest tests for all endpoints + URL logic
├── js/
│   ├── app.js          # Shared API client, auth helpers, toast
│   ├── auth.js         # Login & signup form handlers
│   ├── chatbot.js      # ShieldBot chat UI (calls /api/chat → Anthropic)
│   ├── scanner.js      # Deep URL scan page
│   └── dashboard.js    # Stats, quick scan, history table
├── css/
│   ├── styles.css      # Global design tokens, navbar, cards
│   ├── auth.css        # Login/signup split-panel styles
│   ├── dashboard.css   # Stat cards, checker card, history table
│   └── chatbot.css     # Chat layout, message bubbles, typing indicator
├── index.html          # Sign in
├── signup.html         # Create account
├── home.html           # Landing / marketing page
├── dashboard.html      # User dashboard
├── scanner.html        # Deep URL scanner
└── chatbot.html        # AI chatbot
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/signup` | — | Register new user |
| POST | `/api/auth/login` | — | Login, get token |
| POST | `/api/auth/logout` | ✓ | Invalidate token |
| POST | `/api/scan` | ✓ | Analyze a URL (10-point check) |
| GET | `/api/scan/history` | ✓ | Get user's scan history |
| POST | `/api/chat` | ✓ | Chat with ShieldBot (Anthropic) |

All protected endpoints require `Authorization: Bearer <token>` header.

## URL Analysis Checks

1. **HTTPS Protocol** — insecure HTTP penalizes score
2. **IP Address** — raw IP instead of domain is high risk
3. **TLD Reputation** — flags .xyz, .tk, .ml, .ga, etc.
4. **Phishing Keywords** — detects "login", "verify", "paypal" in domain
5. **URL Shorteners** — bit.ly, tinyurl.com, t.co, etc.
6. **Subdomain Depth** — more than 2 subdomains is suspicious
7. **Punycode / Homograph** — detects xn-- encoding for lookalike domains
8. **URL Length** — URLs over 100 chars are penalized
9. **Special Characters** — unusual chars in hostname
10. **Path Keywords** — suspicious words in the URL path
