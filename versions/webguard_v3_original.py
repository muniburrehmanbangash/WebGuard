#!/usr/bin/env python3
"""WebGuard 3.0: user-friendly website security configuration review."""

import html
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

TOOL_NAME = "WebGuard"
REPORT_VERSION = "3.0"
TIMEOUT_SECONDS = 10
IMPORTANT_NOTE = (
    "WebGuard performs passive HTTP response checks and limited, non-destructive "
    "validation requests. Findings describe observed configuration, not proof of "
    "exploitability. The scanner does not submit attack payloads, test authenticated "
    "workflows, or establish that an application is secure. Redirect-chain responses "
    "are recorded where available, but cookie analysis is limited to captured "
    "Set-Cookie headers from responses observed during this scan."
)

HEADER_RULES = {
    "Content-Security-Policy": {
        "purpose": "Controls which resources browsers may load and can restrict framing.",
        "impact": "An enforced policy can reduce the impact of some injection and framing risks.",
        "recommendation": "Review the application's resource requirements and deploy a tested CSP. Start with report-only mode when practical.",
    },
    "Strict-Transport-Security": {
        "purpose": "Instructs browsers to use HTTPS for future connections.",
        "impact": "Can reduce downgrade and insecure-transport exposure after a browser has received the policy over HTTPS.",
        "recommendation": "Serve HSTS on HTTPS responses after confirming HTTPS is consistently supported. Assess includeSubDomains and preload separately.",
    },
    "X-Content-Type-Options": {
        "purpose": "Controls browser MIME-type sniffing when set to nosniff.",
        "impact": "Can reduce risks from content being interpreted as a type different from its declared MIME type.",
        "recommendation": "Use X-Content-Type-Options: nosniff where appropriate and ensure Content-Type values are correct.",
    },
    "X-Frame-Options": {
        "purpose": "Provides legacy browser framing restrictions.",
        "impact": "Can help reduce clickjacking when framing is not intended.",
        "recommendation": "Use an appropriate CSP frame-ancestors directive; X-Frame-Options may be retained for legacy compatibility.",
    },
    "Referrer-Policy": {
        "purpose": "Controls how much referrer information browsers send with navigation and resource requests.",
        "impact": "A suitable policy can reduce unintended URL or origin information disclosure.",
        "recommendation": "Set a policy appropriate for the application, commonly strict-origin-when-cross-origin or a more restrictive option.",
    },
}

SEVERITY_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Unrated": -1}


def validate_url(raw_url):
    url = raw_url.strip()
    if not url:
        raise ValueError("Please enter a website URL.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("Please enter a valid HTTP or HTTPS URL.")
    if any(ch.isspace() for ch in url):
        raise ValueError("URL must not contain whitespace.")
    return url


def make_finding(rule_id, title, classification, severity, confidence, evidence,
                 impact, recommendation, applicability="Applicable", status="OBSERVATION"):
    return {
        "id": rule_id,
        "title": title,
        "classification": classification,
        "severity": severity,
        "confidence": confidence,
        "applicability": applicability,
        "status": status,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
    }


def get_header_values(response, name):
    """Return repeated header values when urllib3 exposes them."""
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        try:
            values = raw_headers.getlist(name)
            if values:
                return [str(v) for v in values]
        except Exception:
            pass
    value = response.headers.get(name)
    return [] if value is None else [str(value)]


def analyze_security_headers(response, report):
    print("\n--- Security Header Analysis ---")
    headers = report["security_headers"]
    findings = report["findings"]
    is_https = urlparse(response.url).scheme.lower() == "https"
    all_values = {key.lower(): value for key, value in response.headers.items()}

    for name, rule in HEADER_RULES.items():
        values = get_header_values(response, name)
        value = response.headers.get(name)
        status = "MISSING" if value is None else ("REVIEW" if not value.strip() else "PRESENT")
        note = ("Header was observed." if status == "PRESENT" else
                "Header was not observed." if status == "MISSING" else
                "Header exists but its value is empty.")
        item_findings = []

        if name == "Strict-Transport-Security" and not is_https:
            status = "NOT_ASSESSED"
            note = "This response used HTTP; HSTS is evaluated on HTTPS responses, so this response cannot establish the site's HTTPS HSTS configuration."
            finding = make_finding(
                "HDR-HSTS-HTTP", "HSTS not assessed on HTTP response",
                "Not assessed", "Unrated", "High",
                {"response_url": response.url, "scheme": "http", "header_values": values},
                "HSTS directives received over HTTP are ignored by browsers; the HTTPS configuration remains unknown.",
                "Check the final HTTPS response separately. Do not infer an HTTPS HSTS weakness from this HTTP response.",
                applicability="Not applicable to this HTTP response", status="NOT_ASSESSED")
            item_findings.append(finding)
            findings.append(finding)

        elif status == "MISSING":
            if name == "Content-Security-Policy" and all_values.get("content-security-policy-report-only"):
                classification, severity = "Informational", "Informational"
                note = "Enforced CSP was not observed; Content-Security-Policy-Report-Only is present and does not enforce restrictions."
            elif name == "X-Frame-Options" and "content-security-policy" in all_values and re.search(
                    r"(?:^|;)\s*frame-ancestors\b", all_values["content-security-policy"], re.I):
                classification, severity = "Informational", "Informational"
                note = "X-Frame-Options is absent, but a CSP frame-ancestors directive was observed as an alternative framing control."
            elif name == "Strict-Transport-Security":
                classification, severity = "Potential issue", "Low"
                note = "HSTS was not observed on this HTTPS response; browser preload, prior policy, and deployment context are not assessed."
            elif name == "Content-Security-Policy":
                classification, severity = "Potential issue", "Low"
            elif name == "X-Frame-Options":
                classification, severity = "Potential issue", "Low"
            elif name == "X-Content-Type-Options":
                classification, severity = "Informational", "Informational"
            else:
                classification, severity = "Informational", "Informational"

            if not item_findings:
                finding = make_finding(
                    "HDR-" + re.sub(r"[^A-Z0-9]+", "-", name.upper()).strip("-"),
                    f"Missing {name}", classification, severity, "High",
                    {"header": name, "observed_values": values, "response_url": response.url},
                    rule["impact"] + " The scan did not establish an exploitable vulnerability.",
                    rule["recommendation"],
                    applicability=("HTTPS response" if name == "Strict-Transport-Security" else "General HTTP response"),
                    status="MISSING")
                item_findings.append(finding)
                findings.append(finding)

        elif status == "REVIEW" and value is not None:
            note = "Header exists but its value is empty."
            finding = make_finding(
                "HDR-EMPTY-" + re.sub(r"[^A-Z0-9]+", "-", name.upper()).strip("-"),
                f"Empty {name} value", "Configuration weakness", "Low", "High",
                {"header": name, "observed_values": values, "response_url": response.url},
                "An empty value is unlikely to provide the intended protection.",
                rule["recommendation"], status="REVIEW")
            item_findings.append(finding)
            findings.append(finding)

        elif name == "X-Content-Type-Options" and value.strip().lower() != "nosniff":
            note = "Value is not nosniff."
            finding = make_finding(
                "HDR-XCTO-VALUE", "Unexpected X-Content-Type-Options value",
                "Configuration weakness", "Low", "High",
                {"header": name, "observed_values": values},
                "The observed value does not provide the expected nosniff behavior.",
                "Set X-Content-Type-Options: nosniff where appropriate.", status="REVIEW")
            item_findings.append(finding)
            findings.append(finding)

        elif name == "Strict-Transport-Security":
            directives = [d.strip() for d in value.split(";") if d.strip()]
            max_age = next((d.split("=", 1)[1].strip() for d in directives
                            if d.lower().startswith("max-age=") and "=" in d), None)
            if max_age is None or not max_age.isdigit():
                note = "HSTS was present, but max-age was absent or malformed."
                finding = make_finding(
                    "HDR-HSTS-MAXAGE", "Malformed HSTS max-age",
                    "Configuration weakness", "Low", "High",
                    {"header": name, "value": value},
                    "Browsers may not apply the intended HSTS policy when max-age is invalid.",
                    "Configure a valid non-negative max-age after confirming HTTPS readiness.", status="REVIEW")
                item_findings.append(finding)
                findings.append(finding)
            else:
                note = "HSTS was observed on HTTPS with a numeric max-age. Other deployment requirements were not assessed."

        elif name == "Content-Security-Policy" and "report-only" in name.lower():
            note = "CSP was observed."

        print(f"\n[{status}] {name}")
        if value is not None:
            print("  Value:", value)
        print("  Note:", note)
        print("  Purpose:", rule["purpose"])

        headers.append({
            "name": name, "status": status, "value": value, "values": values,
            "note": note, "purpose": rule["purpose"], "security_relevance": rule["impact"],
            "recommendation": rule["recommendation"],
            "findings": item_findings,
        })

    # Duplicate values are recorded as an observation, not automatically a vulnerability.
    for name in HEADER_RULES:
        values = get_header_values(response, name)
        if len(values) > 1:
            finding = make_finding(
                "HDR-DUP-" + re.sub(r"[^A-Z0-9]+", "-", name.upper()).strip("-"),
                f"Repeated {name} headers", "Potential issue", "Low", "Medium",
                {"header": name, "values": values},
                "Repeated or conflicting security header values can be interpreted differently by components.",
                "Review the server, reverse proxy, and application configuration to ensure one consistent policy is emitted.",
                status="REVIEW")
            findings.append(finding)


def parse_set_cookie(raw_value):
    """Parse one Set-Cookie header without splitting the Expires date on commas."""
    parts = [part.strip() for part in raw_value.split(";")]
    if not parts or "=" not in parts[0]:
        return None, {}, ["Cookie name/value pair could not be parsed."]
    name, value = parts[0].split("=", 1)
    name = name.strip()
    attributes = {}
    duplicates = []
    for part in parts[1:]:
        if not part:
            continue
        if "=" in part:
            key, attr_value = part.split("=", 1)
            key = key.strip().lower()
            attr_value = attr_value.strip()
        else:
            key, attr_value = part.strip().lower(), True
        if key in attributes:
            duplicates.append(key)
        attributes[key] = attr_value
    return name, attributes, duplicates


def analyze_cookies(response, report):
    print("\n--- Cookie Security Analysis ---")
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        cookie_headers = list(raw_headers.getlist("Set-Cookie"))
    else:
        # Requests' merged header view may collapse repeated Set-Cookie values.
        cookie_headers = []
        report["cookie_scan_note"] = (
            "The response library did not expose separate Set-Cookie header values; "
            "cookie analysis may be incomplete."
        )

    if not cookie_headers:
        report.setdefault("cookie_scan_note", "No Set-Cookie headers were observed in the final response.")
        print(report["cookie_scan_note"])
        return

    for index, raw_cookie in enumerate(cookie_headers, start=1):
        name, attrs, duplicate_attrs = parse_set_cookie(str(raw_cookie))
        if not name:
            finding = make_finding(
                f"COOKIE-PARSE-{index:02d}", "Unparseable Set-Cookie header",
                "Not assessed", "Unrated", "High", {"set_cookie": str(raw_cookie)},
                "The scanner could not reliably evaluate this cookie's attributes.",
                "Review the raw Set-Cookie header manually.", status="NOT_ASSESSED")
            report["findings"].append(finding)
            report["cookies"].append({"name": None, "raw_header": str(raw_cookie), "findings": [finding]})
            continue

        secure = "secure" in attrs
        httponly = "httponly" in attrs
        same_site = attrs.get("samesite")
        cookie_findings = []

        def add_cookie_finding(suffix, title, classification, severity, confidence,
                               impact, recommendation, status="OBSERVATION"):
            finding = make_finding(
                f"COOKIE-{suffix}-{index:02d}", title, classification, severity, confidence,
                {"cookie_name": name, "attributes": {k: v for k, v in attrs.items()},
                 "set_cookie_header": str(raw_cookie)},
                impact, recommendation, applicability="Cookie purpose is unknown unless supplied by application context",
                status=status)
            cookie_findings.append(finding)
            report["findings"].append(finding)

        # Missing Secure/HttpOnly/SameSite are reported as context-dependent observations.
        if not secure:
            add_cookie_finding("SECURE", f"Cookie {name} lacks Secure",
                "Potential issue", "Low", "High",
                "If this cookie is sent over HTTP, it could be exposed on an unencrypted connection. The scanner does not know whether it is a session cookie.",
                "Use Secure for cookies that should only travel over HTTPS; verify that the site does not rely on HTTP.")
        if not httponly:
            add_cookie_finding("HTTPONLY", f"Cookie {name} lacks HttpOnly",
                "Informational", "Informational", "High",
                "Client-side scripts may be able to read the cookie. Impact is more significant for authentication/session cookies; cookie purpose was not established.",
                "Use HttpOnly for cookies that do not need to be read by client-side JavaScript.")
        if same_site is None:
            add_cookie_finding("SAMESITE", f"Cookie {name} lacks SameSite",
                "Informational", "Informational", "High",
                "Cross-site cookie behavior may depend on browser defaults. This observation alone does not prove a CSRF issue.",
                "Choose SameSite=Lax or Strict where compatible; use None only when cross-site use is required and pair it with Secure.")
        elif not isinstance(same_site, str) or same_site.lower() not in ("strict", "lax", "none"):
            add_cookie_finding("SAMESITE-VALUE", f"Cookie {name} has an unrecognized SameSite value",
                "Configuration weakness", "Low", "High",
                "An unrecognized SameSite value may not produce the intended browser behavior.",
                "Use SameSite=Strict, Lax, or None according to the application's cross-site requirements.", "REVIEW")
        elif same_site.lower() == "none" and not secure:
            add_cookie_finding("SAMESITE-NONE-SECURE", f"Cookie {name} uses SameSite=None without Secure",
                "Configuration weakness", "Low", "High",
                "Modern browsers generally require Secure with SameSite=None; the cookie may be rejected or not behave as intended.",
                "Add Secure and verify the intended cross-site cookie behavior.", "REVIEW")

        if not name:
            pass
        if name.startswith("__Secure-") and not secure:
            add_cookie_finding("PREFIX-SECURE", f"Cookie {name} violates __Secure- prefix requirements",
                "Configuration weakness", "Low", "High",
                "Browsers require a __Secure- cookie to be set from a secure context with the Secure attribute.",
                "Set the cookie over HTTPS with Secure, or rename it if the prefix is not intended.", "REVIEW")
        if name.startswith("__Host-"):
            if not secure:
                add_cookie_finding("PREFIX-HOST-SECURE", f"Cookie {name} lacks Secure required by __Host-",
                    "Configuration weakness", "Low", "High",
                    "The __Host- prefix requires Secure and a secure origin.",
                    "Set Secure and issue the cookie from HTTPS.", "REVIEW")
            if attrs.get("path") != "/":
                add_cookie_finding("PREFIX-HOST-PATH", f"Cookie {name} does not have Path=/",
                    "Configuration weakness", "Low", "High",
                    "The __Host- prefix requires Path=/.",
                    "Set Path=/ or remove the __Host- prefix if its guarantees are not intended.", "REVIEW")
            if "domain" in attrs:
                add_cookie_finding("PREFIX-HOST-DOMAIN", f"Cookie {name} has a Domain attribute",
                    "Configuration weakness", "Low", "High",
                    "The __Host- prefix forbids the Domain attribute.",
                    "Remove Domain and issue the cookie as a host-only cookie.", "REVIEW")

        for attr in duplicate_attrs:
            add_cookie_finding("DUP-ATTR", f"Cookie {name} repeats the {attr} attribute",
                "Potential issue", "Low", "Medium",
                "Duplicate cookie attributes can cause ambiguous configuration or inconsistent interpretation.",
                "Emit each cookie attribute at most once.", "REVIEW")

        cookie_report = {
            "name": name, "raw_header": str(raw_cookie),
            "secure": secure, "httponly": httponly,
            "samesite": same_site, "path": attrs.get("path"),
            "domain": attrs.get("domain"), "expires": attrs.get("expires"),
            "max_age": attrs.get("max-age"), "attributes": attrs,
            "findings": cookie_findings,
        }
        report["cookies"].append(cookie_report)
        print(f"\nCookie: {name}")
        print(f"  Secure={secure}; HttpOnly={httponly}; SameSite={same_site or 'not set'}")
        for finding in cookie_findings:
            print(f"  [{finding['severity']}] {finding['title']}")


def collect_response_details(response, report, label):
    detail = {
        "label": label,
        "url": response.url,
        "status_code": response.status_code,
        "headers": dict(response.headers.items()),
        "set_cookie_headers": get_header_values(response, "Set-Cookie"),
    }
    report["responses"].append(detail)


def safe_validation_get(session, url):
    """One bounded GET with redirects; no payloads or state-changing methods."""
    return session.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=True, stream=True)


def perform_scan(url, report):
    session = requests.Session()
    session.headers.update({"User-Agent": "WebGuard/3.0 (passive security configuration review)"})
    try:
        # Main request: normal GET only; no attack payloads.
        response = safe_validation_get(session, url)
        try:
            report["final_url"] = response.url
            report["http_status_code"] = response.status_code
            collect_response_details(response, report, "primary")
            report["response_headers"] = dict(response.headers.items())
            print("\nRequested URL:", url)
            print("Final URL:", response.url)
            print("Status Code:", response.status_code)
            print("\n--- Response Headers ---")
            for header, value in response.headers.items():
                print(f"{header}: {value}")
            analyze_security_headers(response, report)
            analyze_cookies(response, report)
        finally:
            response.close()

        # Non-destructive validation: if the initial URL was HTTP and it did not
        # redirect to HTTPS, make one HTTPS GET to the same host/path for comparison.
        parsed_requested = urlparse(url)
        parsed_final = urlparse(report["final_url"] or url)
        if parsed_requested.scheme == "http" and parsed_final.scheme == "http":
            https_url = parsed_final._replace(scheme="https").geturl()
            try:
                validation_response = safe_validation_get(session, https_url)
                try:
                    collect_response_details(validation_response, report, "https-comparison")
                    report["validation_requests"].append({
                        "type": "https-comparison",
                        "requested_url": https_url,
                        "status_code": validation_response.status_code,
                        "final_url": validation_response.url,
                        "note": "A single ordinary GET compared HTTPS behavior; no payloads were sent."
                    })
                    # Only use comparison to annotate HSTS check; don't silently substitute
                    # a different response as the primary target.
                    hsts = next((h for h in report["security_headers"]
                                 if h["name"] == "Strict-Transport-Security"), None)
                    if hsts:
                        hsts["https_comparison"] = {
                            "url": validation_response.url,
                            "status_code": validation_response.status_code,
                            "hsts_observed": validation_response.headers.get("Strict-Transport-Security") is not None,
                        }
                        if validation_response.headers.get("Strict-Transport-Security"):
                            hsts["note"] += " HSTS was observed on the separate HTTPS comparison response."
                finally:
                    validation_response.close()
            except requests.RequestException as error:
                report["validation_requests"].append({
                    "type": "https-comparison", "requested_url": https_url,
                    "error": str(error),
                    "note": "The optional HTTPS comparison failed; this does not prove HTTPS is unavailable."
                })
    finally:
        session.close()


def calculate_summaries(report):
    headers = report.get("security_headers", [])
    cookies = report.get("cookies", [])
    findings = report.get("findings", [])
    report["header_summary"] = {
        "headers_checked": len(headers),
        "headers_present": sum(h["status"] == "PRESENT" for h in headers),
        "headers_missing": sum(h["status"] == "MISSING" for h in headers),
        "headers_needing_review": sum(h["status"] in ("REVIEW", "NOT_ASSESSED") for h in headers),
    }
    report["cookie_summary"] = {
        "cookie_count": len(cookies),
        "cookies_with_findings": sum(bool(c.get("findings")) for c in cookies),
        "cookie_findings_count": sum(len(c.get("findings", [])) for c in cookies),
    }
    counts = Counter(f["classification"] for f in findings)
    severity_counts = Counter(f["severity"] for f in findings)
    report["finding_summary"] = {
        "total_findings": len(findings),
        "by_classification": dict(counts),
        "by_severity": dict(severity_counts),
    }
    report["scan_summary"] = {**report["header_summary"], **report["cookie_summary"],
                              "total_findings": len(findings)}


def esc(value):
    if value is None:
        return "Not available"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, indent=2, ensure_ascii=False)
    return html.escape(str(value), quote=True)


def render_finding(finding):
    severity = finding.get("severity", "Unrated")
    badge_class = {"High": "high", "Medium": "medium", "Low": "low",
                   "Informational": "info", "Unrated": "neutral"}.get(severity, "neutral")
    classification = finding.get("classification", "Observation")
    return f"""
    <article class="finding">
      <div class="top"><div><p class="eyebrow">{esc(classification)}</p><h3>{esc(finding.get('title'))}</h3></div><span class="badge {badge_class}">{esc(severity)}</span></div>
      <p>{esc(finding.get('impact'))}</p>
      <div class="recommendation"><strong>Recommended action</strong><p>{esc(finding.get('recommendation'))}</p></div>
      <details><summary>Technical details</summary>
        <dl><dt>Evidence</dt><dd><pre>{esc(finding.get('evidence'))}</pre></dd>
        <dt>Confidence</dt><dd>{esc(finding.get('confidence'))}</dd>
        <dt>Applicability</dt><dd>{esc(finding.get('applicability'))}</dd>
        <dt>Rule / status</dt><dd>{esc(finding.get('id'))} · {esc(finding.get('status'))}</dd></dl>
      </details>
    </article>"""


def generate_html_report(report, output_path):
    findings = report.get("findings", [])
    findings_html = "".join(render_finding(f) for f in findings)
    if not findings_html:
        findings_html = '<div class="empty"><h3>No findings recorded</h3><p>The configured checks did not produce findings. This does not prove the website is secure.</p></div>'

    response_rows = ""
    for response in report.get("responses", []):
        response_rows += (
            "<tr><td>" + esc(response.get("label")) + "</td><td>" + esc(response.get("url")) +
            "</td><td>" + esc(response.get("status_code")) + "</td><td><details><summary>View headers</summary><pre>" +
            esc(response.get("headers")) + "</pre></details></td></tr>"
        )
    scan_error = ""
    if report.get("scan_error"):
        scan_error = f'<section class="panel error"><h2>Scan issue</h2><p>WebGuard could not complete every scan step. Review the technical message below.</p><pre>{esc(report["scan_error"])}</pre></section>'

    summary = report.get("finding_summary", {})
    severity_counts = summary.get("by_severity", {})
    top_severity = next((s for s in ("High", "Medium", "Low") if severity_counts.get(s, 0)), None)
    if report.get("scan_error"):
        overall_label, overall_class = "Scan needs review", "neutral"
        overall_text = "Some scan steps did not complete. Check the scan issue section."
    elif top_severity == "High":
        overall_label, overall_class = "High-priority findings", "high"
        overall_text = "One or more high-severity observations need prompt review."
    elif top_severity == "Medium":
        overall_label, overall_class = "Findings need attention", "medium"
        overall_text = "Review the medium-severity observations and apply fixes where appropriate."
    elif top_severity == "Low":
        overall_label, overall_class = "Improvements suggested", "low"
        overall_text = "The scan found configuration improvements worth reviewing."
    else:
        overall_label, overall_class = "No prioritized issues found", "info"
        overall_text = "No high, medium, or low severity findings were recorded by these checks. This is not a guarantee of security."

    validation_items = report.get("validation_requests", [])
    if validation_items:
        validation_html = "".join(f'<li><strong>{esc(item.get("type", "Validation request"))}:</strong> {esc(item.get("note", item.get("error", "Completed")))}' + (f'<pre>{esc(item.get("error"))}</pre>' if item.get("error") else "") + '</li>' for item in validation_items)
        validation_html = f"<ul>{validation_html}</ul>"
    else:
        validation_html = '<p class="muted">No additional validation requests were needed for this scan.</p>'

    cookie_count = report.get("cookie_summary", {}).get("cookie_count", 0)
    header_missing = report.get("header_summary", {}).get("headers_missing", 0)
    status_code = report.get("http_status_code") if report.get("http_status_code") is not None else "Not received"
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebGuard 3.0 Report</title><style>
:root{{--ink:#172033;--muted:#64748b;--line:#dbe3ee;--bg:#f3f6fb;--card:#fff;--navy:#172554;--accent:#2563eb}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
main{{max-width:1080px;margin:auto;padding:24px 16px 48px}}.hero{{background:linear-gradient(135deg,#172554,#1d4ed8);color:#fff;padding:28px;border-radius:18px;overflow-wrap:anywhere;box-shadow:0 10px 30px #17255418}}
.hero-row{{display:flex;align-items:flex-start;justify-content:space-between;gap:18px}}h1{{font-size:clamp(1.8rem,4vw,2.5rem);line-height:1.15;margin:0}}.hero p{{color:#dbeafe;margin:8px 0}}.brandline{{font-weight:700;letter-spacing:.04em;color:#bfdbfe!important;font-size:.82rem;text-transform:uppercase}}
.actions{{display:flex;gap:8px;flex-wrap:wrap}}button{{border:0;border-radius:10px;padding:11px 15px;font-weight:700;font-size:.95rem;cursor:pointer}}.print-btn{{background:#fff;color:#1d4ed8}}.print-btn:hover{{background:#eff6ff}}.report-meta{{margin-top:18px;padding-top:14px;border-top:1px solid #ffffff3d;display:grid;grid-template-columns:1fr 1fr;gap:8px 20px}}.report-meta div{{overflow-wrap:anywhere}}.report-meta strong{{color:#bfdbfe;display:block;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}}
.overview{{margin-top:16px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px}}.statusline{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}.statusline h2{{margin:0;font-size:1.25rem}}.status-pill,.badge{{display:inline-block;border-radius:999px;padding:3px 10px;font-size:.82rem;font-weight:750;white-space:nowrap}}.high{{background:#fee2e2;color:#991b1b}}.medium{{background:#ffedd5;color:#9a3412}}.low{{background:#fef3c7;color:#92400e}}.info{{background:#dbeafe;color:#1e40af}}.neutral{{background:#e2e8f0;color:#334155}}.overview p{{margin:8px 0 0;color:var(--muted)}}
.metrics{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:14px}}.metric,.panel,.finding,.empty{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;min-width:0}}.metric span{{color:var(--muted);font-size:.9rem}}.metric strong{{display:block;font-size:1.8rem;line-height:1.3;margin-top:5px}}section{{margin-top:26px}}section>h2,.panel h2{{font-size:1.35rem;margin:0 0 8px}}.section-intro{{color:var(--muted);margin:0 0 12px}}.finding{{margin:12px 0}}.top{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}}h3{{margin:0;overflow-wrap:anywhere;font-size:1.08rem}}.eyebrow{{font-size:.78rem;font-weight:750;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:0 0 3px}}.finding>p{{margin:12px 0}}.recommendation{{background:#f8fafc;border-left:4px solid var(--accent);padding:12px 14px;border-radius:7px;margin:12px 0}}.recommendation p{{margin:4px 0 0}}details{{margin-top:12px}}summary{{cursor:pointer;font-weight:650;color:#1d4ed8}}dl{{display:grid;grid-template-columns:150px 1fr;gap:8px 12px}}dt{{font-weight:700}}dd{{margin:0;min-width:0;overflow-wrap:anywhere}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f8fafc;border:1px solid var(--line);padding:12px;border-radius:8px;font-size:.85rem;margin:8px 0}}
.tablewrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;background:white}}th,td{{border:1px solid var(--line);padding:10px;text-align:left;vertical-align:top}}th{{background:#f8fafc}}.muted{{color:var(--muted)}}.error{{border-color:#fecaca;background:#fffafa}}.empty{{text-align:center;padding:22px}}footer{{margin-top:30px;border-top:1px solid var(--line);padding-top:16px;color:var(--muted);font-size:.88rem}}
@media(max-width:650px){{main{{padding:12px 10px 28px}}.hero-row{{flex-direction:column}}.report-meta{{grid-template-columns:1fr}}.metrics{{grid-template-columns:1fr 1fr}}dl{{grid-template-columns:1fr;gap:3px}}dd{{margin-bottom:10px}}}}
@media print{{@page{{size:auto;margin:14mm}}body{{background:#fff;font-size:10.5pt}}main{{max-width:none;padding:0}}.hero{{background:#172554!important;color:#fff!important;print-color-adjust:exact;-webkit-print-color-adjust:exact;box-shadow:none}}.actions{{display:none!important}}.metric,.panel,.finding,.overview{{break-inside:avoid;box-shadow:none}}details:not([open])>*:not(summary){{display:block}}a{{color:inherit}}section{{break-inside:auto}}.finding{{break-inside:avoid}}footer{{break-before:auto}}}}
</style></head><body><main>
<header class="hero"><div class="hero-row"><div><p class="brandline">Website security review</p><h1>🛡 WebGuard 3.0</h1><p>Simple, evidence-based checks for common website security settings.</p></div><div class="actions"><button class="print-btn" onclick="window.print()">Print / Save as PDF</button></div></div>
<div class="report-meta"><div><strong>Scanned URL</strong>{esc(report.get('requested_url'))}</div><div><strong>Final URL</strong>{esc(report.get('final_url'))}</div><div><strong>HTTP status</strong>{esc(status_code)}</div><div><strong>Scan time (UTC)</strong>{esc(report.get('scan_time_utc'))}</div></div></header>
<div class="overview"><div class="statusline"><h2>Scan summary</h2><span class="status-pill {overall_class}">{esc(overall_label)}</span></div><p>{esc(overall_text)}</p></div>
<div class="metrics"><div class="metric"><span>Total observations</span><strong>{len(findings)}</strong></div><div class="metric"><span>Security headers missing</span><strong>{header_missing}</strong></div><div class="metric"><span>Cookies observed</span><strong>{cookie_count}</strong></div></div>
<section><h2>Findings and recommendations</h2><p class="section-intro">Start with the highest severity. Each item explains what was observed and what you can review or fix.</p>{findings_html}</section>
<section><h2>Request details</h2><p class="section-intro">Technical response information is available when you need it.</p><div class="panel"><div class="tablewrap"><table><thead><tr><th>Request</th><th>URL</th><th>Status</th><th>Evidence</th></tr></thead><tbody>{response_rows or '<tr><td colspan="4">No HTTP response was received.</td></tr>'}</tbody></table></div></div></section>
<section class="panel"><h2>Additional checks</h2>{validation_html}</section>
{scan_error}
<section class="panel"><h2>About this report</h2><p>{esc(report.get('important_note', IMPORTANT_NOTE))}</p><p class="muted">WebGuard checks selected HTTP security settings only. Findings are observations, not proof of exploitability, and a clean report does not guarantee that a website is secure.</p></section>
<footer>Generated by WebGuard 3.0 · Report format: HTML · Use “Print / Save as PDF” to create a shareable PDF copy.</footer>
</main></body></html>"""
    output_path.write_text(document, encoding="utf-8")

def choose_report_number(directory):
    number = 1
    while True:
        json_path = directory / f"scan_Report_{number:02d}.json"
        html_path = directory / f"scan_Report_{number:02d}.html"
        if not json_path.exists() and not html_path.exists():
            return json_path, html_path
        number += 1


def main():
    print("--- WebGuard 3.0 ---")
    try:
        url = validate_url(input("Enter a website URL: "))
    except ValueError as error:
        print("Error:", error)
        raise SystemExit(1)

    report = {
        "tool": TOOL_NAME, "report_version": REPORT_VERSION,
        "scan_mode": "passive_plus_non_destructive_validation",
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": url, "final_url": None, "http_status_code": None,
        "scan_error": None, "security_headers": [], "cookies": [],
        "findings": [], "responses": [], "validation_requests": [],
        "response_headers": {}, "important_note": IMPORTANT_NOTE,
    }
    try:
        perform_scan(url, report)
    except requests.RequestException as error:
        report["scan_error"] = str(error)
        print("\nRequest failed:", error)
    except Exception as error:
        report["scan_error"] = f"Unexpected scan error: {type(error).__name__}: {error}"
        print("\nScan error:", report["scan_error"])

    calculate_summaries(report)
    reports_directory = Path("reports")
    try:
        reports_directory.mkdir(parents=True, exist_ok=True)
        json_path, html_path = choose_report_number(reports_directory)
        with json_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=2, ensure_ascii=False)
        try:
            generate_html_report(report, html_path)
        except OSError as error:
            print("Could not save HTML report:", error)
        print("\n--- Reports ---")
        print("User-friendly HTML report:", html_path.resolve() if html_path.exists() else "not created")
        print("Optional JSON technical export:", json_path.resolve())
        print("Tip: Open the HTML file in your browser and choose ‘Print / Save as PDF’." )
    except OSError as error:
        print("Could not save reports:", error)


if __name__ == "__main__":
    main()
