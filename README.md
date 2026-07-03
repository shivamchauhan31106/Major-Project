# Inspectr — Fake URL Detector

A heuristic phishing/fake-URL checker with a Python backend and an HTML/CSS/JS frontend styled like a link-inspection report.

## Option A — just open it (no install)
Open `static/index.html` directly in any browser. The page has a built-in
JavaScript copy of the detection logic, so it works fully standalone.

## Option B — run with the Python/Flask backend
```bash
pip install flask
python app.py
```
Then open **http://127.0.0.1:5000**. The page will call the Python backend
(`/api/scan`) for every check instead of using the JS fallback.

## Option C — use detector.py from the command line
```bash
python detector.py https://example.com
# or run with no arguments to paste URLs interactively
```

## What it checks
- HTTPS vs HTTP
- Raw IP addresses used as the host
- The "@" authority-spoofing trick (`http://real-bank.com@evil.io`)
- Punycode / lookalike (homoglyph) characters
- Excessive subdomain depth
- A trusted brand name appearing outside the real domain
  (e.g. `paypal` in the subdomain of a `.xyz` domain)
- Known link shorteners
- Risky top-level domains (`.xyz`, `.top`, `.click`, etc.)
- Hyphen/digit-heavy auto-generated-looking domains
- Unusual length / percent-encoding
- Stacked urgency keywords (`verify`, `suspended`, `confirm`, ...)

Each check contributes a weight to a 0–100 risk score, which maps to a
**SAFE / SUSPICIOUS / DANGEROUS** verdict.

## Honest limits
This is pattern analysis only — it does not check live threat-intel
databases, WHOIS age, certificate details, or page content. A link can
pass every check and still be new and malicious, or fail several and
still be harmless. Treat it as a fast first opinion, not a verdict.
