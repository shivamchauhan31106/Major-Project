from __future__ import annotations

import re
import sys
import math
import json
from dataclasses import dataclass, field
from urllib.parse import urlparse, unquote



KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly", "bl.ink", "tiny.cc",
}

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".xyz", ".top", ".club", ".work", ".click", ".loan",
    ".men", ".gq", ".tk", ".ml", ".cf", ".ga", ".icu", ".rest", ".buzz",
}


COMMONLY_IMPERSONATED_BRANDS = [
    "paypal","paypAl", "apple", "microsoft", "google", "amazon", "netflix", "bank",
    "facebook", "instagram", "whatsapp", "irs", "dhl", "fedex", "ups",
    "outlook", "office365", "chase", "wellsfargo", "americanexpress",
    "coinbase", "binance", "metamask",
]

HOMOGLYPH_LOOKALIKES = {

    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "ԍ": "g", "ɡ": "g", "Α": "A", "Β": "B",
}

URL_SHAPE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", re.IGNORECASE)


@dataclass
class Signal:
    id: str
    label: str
    status: str          
    detail: str
    weight: int = 0     


@dataclass
class ScanResult:
    url: str
    score: int
    verdict: str          
    signals: list[Signal] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "score": self.score,
            "verdict": self.verdict,
            "signals": [s.__dict__ for s in self.signals],
        }




def _check_scheme(parsed) -> Signal:
    if parsed.scheme == "https":
        return Signal("scheme", "Connection security", "pass",
                       "Uses HTTPS, so traffic to this host is encrypted in transit.")
    if parsed.scheme == "http":
        return Signal("scheme", "Connection security", "warn",
                       "Uses plain HTTP. Login or payment forms on an HTTP page "
                       "are not encrypted in transit.", weight=15)
    return Signal("scheme", "Connection security", "warn",
                   f"Unusual scheme '{parsed.scheme}'. Most legitimate web links use http/https.",
                   weight=10)


def _check_ip_host(host: str) -> Signal:
    ipv4 = re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host)
    ipv6 = host.startswith("[") and host.endswith("]")
    if ipv4 or ipv6:
        return Signal("ip_host", "Domain identity", "fail",
                       "The address is a raw IP, not a domain name. Legitimate "
                       "sites almost always use a named domain rather than "
                       "exposing a bare IP address.", weight=30)
    return Signal("ip_host", "Domain identity", "pass",
                   "The host is a named domain rather than a raw IP address.")


def _check_at_symbol(raw_url: str) -> Signal:
    
    authority = raw_url.split("//", 1)[-1].split("/", 1)[0]
    if "@" in authority:
        return Signal("at_symbol", "Authority spoofing", "fail",
                       "The link contains an '@' before the real host. Browsers "
                       "ignore everything before '@', so the visible text can "
                       "show a trusted name while actually navigating elsewhere.",
                       weight=35)
    return Signal("at_symbol", "Authority spoofing", "pass",
                   "No '@' trick found in the address.")


def _check_punycode(host: str) -> Signal:
    if "xn--" in host.lower():
        return Signal("punycode", "Lookalike characters", "fail",
                       "The domain is internationalized (punycode, 'xn--'), a "
                       "technique often used to register lookalike domains with "
                       "non-Latin characters that mimic a trusted brand.",
                       weight=30)
    homoglyphs_found = [ch for ch in host if ch in HOMOGLYPH_LOOKALIKES]
    if homoglyphs_found:
        return Signal("punycode", "Lookalike characters", "warn",
                       "The domain contains characters that closely resemble "
                       "ordinary Latin letters, a common lookalike-domain trick.",
                       weight=20)
    return Signal("punycode", "Lookalike characters", "pass",
                   "No lookalike or internationalized character tricks detected.")


def _check_subdomain_depth(host: str) -> Signal:
    labels = host.split(".")
    
    subdomain_labels = labels[:-2] if len(labels) > 2 else []
    depth = len(subdomain_labels)
    if depth >= 3:
        return Signal("subdomain_depth", "Subdomain structure", "fail",
                       f"The host has {depth} subdomain levels before the real "
                       "domain. Long chains like 'login.account.secure-update."
                       "example.com' are often used to bury a fake brand name "
                       "in front of an unrelated real domain.", weight=25)
    if depth == 2:
        return Signal("subdomain_depth", "Subdomain structure", "warn",
                       "The host has two subdomain levels, which is unusual for "
                       "most consumer-facing sites.", weight=10)
    return Signal("subdomain_depth", "Subdomain structure", "pass",
                   "Subdomain structure looks ordinary.")


def _check_brand_in_subdomain_or_path(host: str, path: str) -> Signal:
    labels = host.split(".")
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
    subdomain_part = ".".join(labels[:-2]).lower()
    full_check_area = f"{subdomain_part} {path}".lower()

    for brand in COMMONLY_IMPERSONATED_BRANDS:
        if brand in full_check_area and brand not in registrable.lower():
            return Signal("brand_spoof", "Brand impersonation", "fail",
                           f"The text '{brand}' appears in the subdomain or path, "
                           f"but the actual domain being visited is "
                           f"'{registrable}', not '{brand}'. This pattern is "
                           "frequently used to make a link look like it belongs "
                           "to a trusted brand.", weight=35)
    return Signal("brand_spoof", "Brand impersonation", "pass",
                   "No known brand name found masquerading outside the real domain.")


def _check_shortener(host: str) -> Signal:
    if host.lower() in KNOWN_SHORTENERS:
        return Signal("shortener", "Link shortener", "warn",
                       "This is a known URL-shortening service. Shorteners hide "
                       "the real destination until you click, which is also "
                       "popular with legitimate marketing links, so treat as a "
                       "caution rather than a verdict on its own.", weight=15)
    return Signal("shortener", "Link shortener", "pass",
                   "Not a recognized link-shortening domain.")


def _check_suspicious_tld(host: str) -> Signal:
    for tld in SUSPICIOUS_TLDS:
        if host.lower().endswith(tld):
            return Signal("tld", "Domain extension", "warn",
                           f"The domain ends in '{tld}', an extension that is "
                           "cheap and largely unmoderated, so it shows up "
                           "disproportionately often in phishing campaigns. "
                           "Many legitimate sites use it too, so this alone "
                           "is not conclusive.", weight=15)
    return Signal("tld", "Domain extension", "pass",
                   "Domain extension is not one commonly abused for phishing.")


def _check_excessive_hyphens_digits(host: str) -> Signal:
    labels = host.split(".")
    main_label = labels[-2] if len(labels) >= 2 else host
    hyphens = main_label.count("-")
    digits = sum(ch.isdigit() for ch in main_label)
    if hyphens >= 3 or digits >= 4:
        return Signal("hyphen_digit_density", "Domain composition", "warn",
                       "The core domain name contains an unusually high number "
                       "of hyphens or digits, a pattern common in auto-generated "
                       "phishing domains (e.g. 'secure-login-987-update.com').",
                       weight=15)
    return Signal("hyphen_digit_density", "Domain composition", "pass",
                   "Domain composition looks like an ordinary, human-chosen name.")


def _check_length_and_entropy(raw_url: str) -> Signal:
    length = len(raw_url)
    if length <= 90:
        return Signal("length", "Overall length", "pass",
                       "Length is within the normal range for a typical link.")
    decoded = unquote(raw_url)
    if length > 150 or len(decoded) > length * 1.3:
        return Signal("length", "Overall length", "warn",
                       f"The link is unusually long ({length} characters) and/or "
                       "heavily percent-encoded, which is sometimes used to "
                       "bury suspicious content or obscure the real destination.",
                       weight=10)
    return Signal("length", "Overall length", "warn",
                   f"The link is longer than typical ({length} characters).",
                   weight=5)


def _check_credential_keywords(raw_url: str) -> Signal:
    keywords = ["login", "verify", "secure", "account", "update", "confirm",
                "signin", "password", "billing", "suspended", "unlock"]
    lower = raw_url.lower()
    hits = [k for k in keywords if k in lower]
    if len(hits) >= 3:
        return Signal("urgency_keywords", "Urgency language", "warn",
                       "The link contains several words associated with "
                       f"credential-harvesting pages ({', '.join(hits[:4])}, ...). "
                       "These words are common on real account pages too, but "
                       "stacking several together is a recognizable phishing "
                       "pattern.", weight=15)
    if hits:
        return Signal("urgency_keywords", "Urgency language", "pass",
                       f"Found common account-related wording ({', '.join(hits)}) "
                       "but not enough to be a strong signal on its own.")
    return Signal("urgency_keywords", "Urgency language", "pass",
                   "No suspicious urgency or credential-related keyword stacking found.")


def _check_well_formed(raw_url: str, parsed) -> Signal:
    if not URL_SHAPE_RE.match(raw_url):
        return Signal("well_formed", "Address structure", "fail",
                       "This does not look like a well-formed URL with a scheme "
                       "(e.g. 'https://'), so it cannot be reliably analyzed.",
                       weight=20)
    if not parsed.hostname:
        return Signal("well_formed", "Address structure", "fail",
                       "No host could be parsed from this address.", weight=20)
    return Signal("well_formed", "Address structure", "pass",
                   "The address parses as a well-formed URL.")


# Orchestration

def scan_url(raw_url: str) -> ScanResult:
    raw_url = raw_url.strip()
    # Be forgiving: if someone pastes "example.com" with no scheme, assume https
    # for parsing purposes, but note it as its own (mild) signal
    had_scheme = bool(URL_SHAPE_RE.match(raw_url))
    test_url = raw_url if had_scheme else f"https://{raw_url}"

    parsed = urlparse(test_url)
    host = parsed.hostname or ""
    path = parsed.path or ""

    signals: list[Signal] = []
    signals.append(_check_well_formed(raw_url, parsed))

    # If it's not parseable at all, short-circuit with just that signal.
    if signals[0].status == "fail" and not host:
        return _finalize(raw_url, signals)

    if not had_scheme:
        signals.append(Signal("no_scheme", "Address structure", "warn",
                               "No 'http://' or 'https://' was given; assuming "
                               "https for analysis. Always check the real scheme "
                               "before trusting a link.", weight=5))

    signals.append(_check_scheme(parsed))
    signals.append(_check_ip_host(host))
    signals.append(_check_at_symbol(raw_url))
    signals.append(_check_punycode(host))
    signals.append(_check_subdomain_depth(host))
    signals.append(_check_brand_in_subdomain_or_path(host, path))
    signals.append(_check_shortener(host))
    signals.append(_check_suspicious_tld(host))
    signals.append(_check_excessive_hyphens_digits(host))
    signals.append(_check_length_and_entropy(raw_url))
    signals.append(_check_credential_keywords(raw_url))

    return _finalize(raw_url, signals)


def _finalize(raw_url: str, signals: list[Signal]) -> ScanResult:
    score = sum(s.weight for s in signals)
    score = min(score, 100)
    if score >= 50:
        verdict = "DANGEROUS"
    elif score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    return ScanResult(url=raw_url, score=score, verdict=verdict, signals=signals)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

STATUS_ICON = {"pass": "✓", "warn": "⚠", "fail": "✗"}


def _print_report(result: ScanResult) -> None:
    print()
    print(f"URL:      {result.url}")
    print(f"Verdict:  {result.verdict}   (risk score: {result.score}/100)")
    print("-" * 60)
    for s in result.signals:
        icon = STATUS_ICON[s.status]
        print(f" {icon} {s.label}")
        print(f"     {s.detail}")
    print("-" * 60)
    print()


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        for url in argv[1:]:
            _print_report(scan_url(url))
        return 0

    print("Fake URL Detector — paste a URL to scan (Ctrl+C to quit).")
    try:
        while True:
            url = input("\n> ").strip()
            if not url:
                continue
            _print_report(scan_url(url))
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
