/* ------------------------------------------------------------------
   Client-side mirror of detector.py's heuristics.
   Used as an instant local fallback if /api/scan isn't reachable
   (e.g. when this file is opened directly without the Flask server).
   ------------------------------------------------------------------ */

const KNOWN_SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
  "rebrand.ly","cutt.ly","shorte.st","adf.ly","bl.ink","tiny.cc",
]);

const SUSPICIOUS_TLDS = [
  ".zip",".mov",".xyz",".top",".club",".work",".click",".loan",
  ".men",".gq",".tk",".ml",".cf",".ga",".icu",".rest",".buzz",
];

const COMMONLY_IMPERSONATED_BRANDS = [
  "paypal","apple","microsoft","google","amazon","netflix","bank",
  "facebook","instagram","whatsapp","irs","dhl","fedex","ups",
  "outlook","office365","chase","wellsfargo","americanexpress",
  "coinbase","binance","metamask",
];

const HOMOGLYPHS = "аеорсхуѕіjԍɡΑΒ";

function signal(id, label, status, detail, weight = 0) {
  return { id, label, status, detail, weight };
}

function tryParseUrl(raw) {
  const hadScheme = /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(raw);
  const testUrl = hadScheme ? raw : `https://${raw}`;
  try {
    const u = new URL(testUrl);
    return { ok: true, hadScheme, parsed: u };
  } catch {
    return { ok: false, hadScheme, parsed: null };
  }
}

function checkScheme(parsed) {
  if (parsed.protocol === "https:") {
    return signal("scheme", "Connection security", "pass",
      "Uses HTTPS, so traffic to this host is encrypted in transit.");
  }
  if (parsed.protocol === "http:") {
    return signal("scheme", "Connection security", "warn",
      "Uses plain HTTP. Login or payment forms on an HTTP page are not encrypted in transit.", 15);
  }
  return signal("scheme", "Connection security", "warn",
    `Unusual scheme '${parsed.protocol.replace(":", "")}'. Most legitimate web links use http/https.`, 10);
}

function checkIpHost(host) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  const ipv6 = host.startsWith("[") && host.endsWith("]");
  if (ipv4 || ipv6) {
    return signal("ip_host", "Domain identity", "fail",
      "The address is a raw IP, not a domain name. Legitimate sites almost always use a named domain rather than exposing a bare IP address.", 30);
  }
  return signal("ip_host", "Domain identity", "pass",
    "The host is a named domain rather than a raw IP address.");
}

function checkAtSymbol(raw) {
  const authority = raw.split("//").pop().split("/")[0];
  if (authority.includes("@")) {
    return signal("at_symbol", "Authority spoofing", "fail",
      "The link contains an '@' before the real host. Browsers ignore everything before '@', so the visible text can show a trusted name while actually navigating elsewhere.", 35);
  }
  return signal("at_symbol", "Authority spoofing", "pass", "No '@' trick found in the address.");
}

function checkPunycode(host) {
  if (host.toLowerCase().includes("xn--")) {
    return signal("punycode", "Lookalike characters", "fail",
      "The domain is internationalized (punycode, 'xn--'), a technique often used to register lookalike domains with non-Latin characters that mimic a trusted brand.", 30);
  }
  const found = [...host].some(ch => HOMOGLYPHS.includes(ch));
  if (found) {
    return signal("punycode", "Lookalike characters", "warn",
      "The domain contains characters that closely resemble ordinary Latin letters, a common lookalike-domain trick.", 20);
  }
  return signal("punycode", "Lookalike characters", "pass",
    "No lookalike or internationalized character tricks detected.");
}

function checkSubdomainDepth(host) {
  const labels = host.split(".");
  const depth = Math.max(labels.length - 2, 0);
  if (depth >= 3) {
    return signal("subdomain_depth", "Subdomain structure", "fail",
      `The host has ${depth} subdomain levels before the real domain. Long chains like 'login.account.secure-update.example.com' are often used to bury a fake brand name in front of an unrelated real domain.`, 25);
  }
  if (depth === 2) {
    return signal("subdomain_depth", "Subdomain structure", "warn",
      "The host has two subdomain levels, which is unusual for most consumer-facing sites.", 10);
  }
  return signal("subdomain_depth", "Subdomain structure", "pass", "Subdomain structure looks ordinary.");
}

function checkBrandSpoof(host, path) {
  const labels = host.split(".");
  const registrable = labels.slice(-2).join(".").toLowerCase();
  const subdomainPart = labels.slice(0, -2).join(".").toLowerCase();
  const area = `${subdomainPart} ${path}`.toLowerCase();

  for (const brand of COMMONLY_IMPERSONATED_BRANDS) {
    if (area.includes(brand) && !registrable.includes(brand)) {
      return signal("brand_spoof", "Brand impersonation", "fail",
        `The text '${brand}' appears in the subdomain or path, but the actual domain being visited is '${registrable}', not '${brand}'. This pattern is frequently used to make a link look like it belongs to a trusted brand.`, 35);
    }
  }
  return signal("brand_spoof", "Brand impersonation", "pass",
    "No known brand name found masquerading outside the real domain.");
}

function checkShortener(host) {
  if (KNOWN_SHORTENERS.has(host.toLowerCase())) {
    return signal("shortener", "Link shortener", "warn",
      "This is a known URL-shortening service. Shorteners hide the real destination until you click, which is also popular with legitimate marketing links, so treat as a caution rather than a verdict on its own.", 15);
  }
  return signal("shortener", "Link shortener", "pass", "Not a recognized link-shortening domain.");
}

function checkTld(host) {
  const lower = host.toLowerCase();
  for (const tld of SUSPICIOUS_TLDS) {
    if (lower.endsWith(tld)) {
      return signal("tld", "Domain extension", "warn",
        `The domain ends in '${tld}', an extension that is cheap and largely unmoderated, so it shows up disproportionately often in phishing campaigns. Many legitimate sites use it too, so this alone is not conclusive.`, 15);
    }
  }
  return signal("tld", "Domain extension", "pass", "Domain extension is not one commonly abused for phishing.");
}

function checkHyphenDigitDensity(host) {
  const labels = host.split(".");
  const main = labels.length >= 2 ? labels[labels.length - 2] : host;
  const hyphens = (main.match(/-/g) || []).length;
  const digits = (main.match(/\d/g) || []).length;
  if (hyphens >= 3 || digits >= 4) {
    return signal("hyphen_digit_density", "Domain composition", "warn",
      "The core domain name contains an unusually high number of hyphens or digits, a pattern common in auto-generated phishing domains (e.g. 'secure-login-987-update.com').", 15);
  }
  return signal("hyphen_digit_density", "Domain composition", "pass",
    "Domain composition looks like an ordinary, human-chosen name.");
}

function checkLength(raw) {
  const length = raw.length;
  if (length <= 90) {
    return signal("length", "Overall length", "pass", "Length is within the normal range for a typical link.");
  }
  let decodedLen = length;
  try { decodedLen = decodeURIComponent(raw).length; } catch { /* ignore malformed escapes */ }
  if (length > 150 || decodedLen > length * 1.3) {
    return signal("length", "Overall length", "warn",
      `The link is unusually long (${length} characters) and/or heavily percent-encoded, which is sometimes used to bury suspicious content or obscure the real destination.`, 10);
  }
  return signal("length", "Overall length", "warn", `The link is longer than typical (${length} characters).`, 5);
}

function checkUrgencyKeywords(raw) {
  const keywords = ["login","verify","secure","account","update","confirm",
    "signin","password","billing","suspended","unlock"];
  const lower = raw.toLowerCase();
  const hits = keywords.filter(k => lower.includes(k));
  if (hits.length >= 3) {
    return signal("urgency_keywords", "Urgency language", "warn",
      `The link contains several words associated with credential-harvesting pages (${hits.slice(0,4).join(", ")}, ...). These words are common on real account pages too, but stacking several together is a recognizable phishing pattern.`, 15);
  }
  if (hits.length) {
    return signal("urgency_keywords", "Urgency language", "pass",
      `Found common account-related wording (${hits.join(", ")}) but not enough to be a strong signal on its own.`);
  }
  return signal("urgency_keywords", "Urgency language", "pass",
    "No suspicious urgency or credential-related keyword stacking found.");
}

function scanUrlLocally(rawInput) {
  const raw = rawInput.trim();
  const { ok, hadScheme, parsed } = tryParseUrl(raw);
  const signals = [];

  if (!ok || !parsed.hostname) {
    signals.push(signal("well_formed", "Address structure", "fail",
      "This does not look like a well-formed URL, so it cannot be reliably analyzed.", 20));
    return finalize(raw, signals);
  }

  signals.push(signal("well_formed", "Address structure", "pass", "The address parses as a well-formed URL."));
  if (!hadScheme) {
    signals.push(signal("no_scheme", "Address structure", "warn",
      "No 'http://' or 'https://' was given; assuming https for analysis. Always check the real scheme before trusting a link.", 5));
  }

  const host = parsed.hostname;
  const path = parsed.pathname || "";

  signals.push(checkScheme(parsed));
  signals.push(checkIpHost(host));
  signals.push(checkAtSymbol(raw));
  signals.push(checkPunycode(host));
  signals.push(checkSubdomainDepth(host));
  signals.push(checkBrandSpoof(host, path));
  signals.push(checkShortener(host));
  signals.push(checkTld(host));
  signals.push(checkHyphenDigitDensity(host));
  signals.push(checkLength(raw));
  signals.push(checkUrgencyKeywords(raw));

  return finalize(raw, signals);
}

function finalize(url, signals) {
  let score = signals.reduce((sum, s) => sum + s.weight, 0);
  score = Math.min(score, 100);
  let verdict = "SAFE";
  if (score >= 50) verdict = "DANGEROUS";
  else if (score >= 20) verdict = "SUSPICIOUS";
  return { url, score, verdict, signals };
}

/* ------------------------------------------------------------------
   UI wiring
   ------------------------------------------------------------------ */

const form = document.getElementById("scan-form");
const input = document.getElementById("url-input");
const sweep = document.getElementById("scan-sweep");
const reportSection = document.getElementById("report-section");
const report = document.getElementById("report");
const button = document.getElementById("scan-button");

async function fetchResult(url) {
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error("api unavailable");
    return await res.json();
  } catch {
    // No server (e.g. static file opened directly) — fall back to the
    // identical logic running locally in the browser.
    return scanUrlLocally(url);
  }
}

function verdictClass(verdict) {
  return verdict === "SAFE" ? "safe" : verdict === "SUSPICIOUS" ? "suspicious" : "dangerous";
}

function iconFor(status) {
  return status === "pass" ? "✓" : status === "warn" ? "⚠" : "✗";
}

function renderReport(result) {
  if (result.error) {
    report.innerHTML = `<div class="report-error">${escapeHtml(result.error)}</div>`;
    reportSection.hidden = false;
    return;
  }

  const cls = verdictClass(result.verdict);
  const verdictCopy = {
    safe: "No major red flags found",
    suspicious: "A few things worth a second look",
    dangerous: "Multiple strong phishing signals",
  }[cls];

  report.innerHTML = `
    <div class="report-head">
      <div>
        <div class="report-url">${escapeHtml(result.url)}</div>
      </div>
      <div class="stamp ${cls}">${result.verdict}</div>
    </div>
    <div class="report-score">
      <span class="score-label">RISK</span>
      <div class="score-track"><div class="score-fill ${cls}" id="score-fill"></div></div>
      <span class="score-number">${result.score}/100</span>
    </div>
    <ul class="signal-list">
      ${result.signals.map(s => `
        <li class="signal-item">
          <span class="signal-icon ${s.status}">${iconFor(s.status)}</span>
          <div class="signal-text">
            <h4>${escapeHtml(s.label)}</h4>
            <p>${escapeHtml(s.detail)}</p>
          </div>
        </li>
      `).join("")}
    </ul>
  `;

  reportSection.hidden = false;
  // animate the score bar in after layout
  requestAnimationFrame(() => {
    const fill = document.getElementById("score-fill");
    if (fill) fill.style.width = `${result.score}%`;
  });

  reportSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

async function runScan(rawUrl) {
  if (!rawUrl || !rawUrl.trim()) return;

  button.disabled = true;
  sweep.classList.remove("run");
  // restart animation
  void sweep.offsetWidth;
  sweep.classList.add("run");

  const result = await fetchResult(rawUrl.trim());

  setTimeout(() => {
    renderReport(result);
    button.disabled = false;
  }, 420); // let the sweep animation read before the report lands
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  runScan(input.value);
});

document.querySelectorAll(".example-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    input.value = chip.dataset.url;
    input.focus();
    runScan(chip.dataset.url);
  });
});
