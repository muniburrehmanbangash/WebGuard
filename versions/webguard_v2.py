import html
import json
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests


TOOL_NAME = "WebGuard"
IMPORTANT_NOTE = (
    "WebGuard performs limited passive checks of the HTTP response it receives. "
    "A missing header or cookie attribute is an observation, not proof that a "
    "website is vulnerable. Review findings in the context of the application. "
    "This scan is not a complete penetration test."
)


# --------------------------------------------------
# 1. Define the security headers to inspect
# --------------------------------------------------

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "purpose": "Controls which resources browsers can load.",
        "importance": "Helps reduce risks such as cross-site scripting (XSS).",
        "severity": "Medium",
        "recommendation": (
            "Review whether an enforced Content-Security-Policy is needed. "
            "Define a policy appropriate for the site's resources and test it "
            "before enforcement."
        ),
    },
    "Strict-Transport-Security": {
        "purpose": "Tells browsers to use HTTPS for future connections.",
        "importance": "Helps protect against protocol downgrade attacks.",
        "severity": "Medium",
        "recommendation": (
            "If the site is intended to use HTTPS, review whether "
            "Strict-Transport-Security should be configured. Only send HSTS "
            "over HTTPS, and assess includeSubDomains/preload carefully."
        ),
    },
    "X-Content-Type-Options": {
        "purpose": "Controls MIME-type sniffing when set to nosniff.",
        "importance": "Helps prevent content-type interpretation issues.",
        "severity": "Low",
        "recommendation": (
            "Review whether X-Content-Type-Options: nosniff is appropriate "
            "for the application."
        ),
    },
    "X-Frame-Options": {
        "purpose": "Controls whether a page can be embedded in frames.",
        "importance": "Helps protect against clickjacking.",
        "severity": "Medium",
        "recommendation": (
            "Review clickjacking protections. Consider an appropriate "
            "X-Frame-Options policy or CSP frame-ancestors directive."
        ),
    },
    "Referrer-Policy": {
        "purpose": "Controls how much referrer information browsers send.",
        "importance": "Helps limit unintended information disclosure.",
        "severity": "Low",
        "recommendation": (
            "Consider a Referrer-Policy that limits unnecessary disclosure "
            "of URL information, such as strict-origin-when-cross-origin."
        ),
    },
}


def validate_url(raw_url):
    """Normalize and validate an HTTP or HTTPS URL."""
    url = raw_url.strip()

    if not url:
        raise ValueError("Please enter a website URL.")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("Please enter a valid HTTP or HTTPS URL.")

    return url


def analyze_security_headers(response, report):
    """Record observations for the five configured security headers."""
    print("\n--- Security Header Analysis ---")
    is_https = urlparse(response.url).scheme == "https"

    for header, details in SECURITY_HEADERS.items():
        value = response.headers.get(header)

        if header == "Strict-Transport-Security" and not is_https:
            status = "REVIEW"
            note = "HSTS is assessed only on HTTPS responses."
        elif value is None:
            if (
                header == "Content-Security-Policy"
                and "Content-Security-Policy-Report-Only" in response.headers
            ):
                status = "REVIEW"
                note = (
                    "Enforced CSP was not observed; a Report-Only CSP is present."
                )
            else:
                status = "MISSING"
                note = "Header was not found in the response."
        elif not value.strip():
            status = "REVIEW"
            note = "Header is present but empty."
        elif (
            header == "X-Content-Type-Options"
            and value.strip().lower() != "nosniff"
        ):
            status = "REVIEW"
            note = "Value is not nosniff."
        else:
            status = "PRESENT"
            note = "Header was found in the response."

        print(f"\n[{status}] {header}")
        if value is not None:
            print("  Value:", value)
        print("  Note:", note)
        print("  Purpose:", details["purpose"])
        print("  Security relevance:", details["importance"])

        report["security_headers"].append({
            "name": header,
            "status": status,
            "severity": details["severity"],
            "recommendation": details["recommendation"],
            "value": value,
            "note": note,
            "purpose": details["purpose"],
            "security_relevance": details["importance"],
        })


def analyze_cookies(response, report):
    """Inspect cookie attributes in the final response only."""
    print("\n--- Cookie Security Analysis ---")
    raw_headers = response.raw.headers

    if hasattr(raw_headers, "getlist"):
        set_cookie_headers = raw_headers.getlist("Set-Cookie")
    else:
        set_cookie_headers = None

    if set_cookie_headers is None:
        message = "Could not reliably separate Set-Cookie headers."
        print("[REVIEW]", message)
        report["cookie_scan_note"] = message
        return

    if not set_cookie_headers:
        message = "No Set-Cookie headers found in this response."
        print(message)
        report["cookie_scan_note"] = message
        return

    for set_cookie in set_cookie_headers:
        parts = [part.strip() for part in set_cookie.split(";")]
        cookie_pair = parts[0]

        if "=" not in cookie_pair:
            print("\n[REVIEW] Could not parse a cookie name.")
            continue

        cookie_name = cookie_pair.split("=", 1)[0].strip()
        attributes = {}

        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                attributes[key.strip().lower()] = value.strip()
            else:
                attributes[part.strip().lower()] = True

        cookie_report = {
            "name": cookie_name,
            "secure": "secure" in attributes,
            "httponly": "httponly" in attributes,
            "samesite": attributes.get("samesite"),
            "findings": [],
        }

        print(f"\nCookie: {cookie_name}")

        if "secure" in attributes:
            print("  [PRESENT] Secure")
        else:
            message = "Secure attribute is missing."
            print("  [REVIEW]", message)
            cookie_report["findings"].append(message)

        if "httponly" in attributes:
            print("  [PRESENT] HttpOnly")
        else:
            message = "HttpOnly attribute is missing."
            print("  [REVIEW]", message)
            cookie_report["findings"].append(message)

        same_site = attributes.get("samesite")
        if same_site is not None:
            normalized = str(same_site).lower()
            if normalized in ("strict", "lax", "none"):
                print(f"  [PRESENT] SameSite={normalized}")
                cookie_report["samesite"] = normalized

                if normalized == "none" and "secure" not in attributes:
                    message = "SameSite=None should be paired with Secure."
                    print("  [REVIEW]", message)
                    cookie_report["findings"].append(message)
            else:
                message = f"Unrecognized SameSite value: {same_site}"
                print("  [REVIEW]", message)
                cookie_report["findings"].append(message)
        else:
            message = "SameSite attribute is missing."
            print("  [REVIEW]", message)
            cookie_report["findings"].append(message)

        report["cookies"].append(cookie_report)


def calculate_summaries(report):
    """Calculate the summary fields used by both report formats."""
    cookie_count = len(report["cookies"])
    cookies_with_findings = sum(
        1 for cookie in report["cookies"] if cookie["findings"]
    )
    cookie_findings_count = sum(
        len(cookie["findings"]) for cookie in report["cookies"]
    )

    report["cookie_summary"] = {
        "cookie_count": cookie_count,
        "cookies_with_findings": cookies_with_findings,
        "cookie_findings_count": cookie_findings_count,
    }

    header_summary = {
        "headers_checked": len(report["security_headers"]),
        "headers_present": sum(
            1 for item in report["security_headers"]
            if item["status"] == "PRESENT"
        ),
        "headers_missing": sum(
            1 for item in report["security_headers"]
            if item["status"] == "MISSING"
        ),
        "headers_needing_review": sum(
            1 for item in report["security_headers"]
            if item["status"] == "REVIEW"
        ),
    }
    report["header_summary"] = header_summary
    report["scan_summary"] = {**header_summary, **report["cookie_summary"]}


def html_escape(value):
    """Safely escape data before inserting it into HTML."""
    if value is None:
        return "Not available"
    return html.escape(str(value), quote=True)


def status_class(status):
    return {
        "PRESENT": "present",
        "MISSING": "missing",
        "REVIEW": "review",
    }.get(status, "neutral")


def render_header_card(item):
    name = html_escape(item.get("name"))
    status = item.get("status", "REVIEW")
    css_class = status_class(status)
    value = item.get("value")
    value_text = html_escape(value) if value is not None else "No value observed"
    return f"""
      <article class="finding">
        <div class="finding-top">
          <h3>{name}</h3>
          <span class="badge {css_class}">{html_escape(status)}</span>
        </div>
        <p class="plain-note">{html_escape(item.get("note"))}</p>
        <p><strong>What it does:</strong> {html_escape(item.get("purpose"))}</p>
        <p><strong>Why it matters:</strong> {html_escape(item.get("security_relevance"))}</p>
        <p><strong>Suggested next step:</strong> {html_escape(item.get("recommendation"))}</p>
        <details>
          <summary>Technical evidence</summary>
          <dl>
            <dt>Observed value</dt><dd><code>{value_text}</code></dd>
            <dt>Preliminary review priority</dt><dd>{html_escape(item.get("severity", "Informational"))}</dd>
          </dl>
        </details>
      </article>
    """


def render_cookie_card(cookie):
    findings = cookie.get("findings", [])
    if findings:
        finding_list = "".join(f"<li>{html_escape(message)}</li>" for message in findings)
        summary = f"<ul>{finding_list}</ul>"
        badge_text = "Needs review"
        badge_class = "review"
    else:
        summary = "<p>No missing cookie attributes were observed by these checks.</p>"
        badge_text = "No observations"
        badge_class = "present"

    same_site = cookie.get("samesite")
    same_site_text = same_site if same_site is not None else "Not set"
    return f"""
      <article class="finding">
        <div class="finding-top">
          <h3>Cookie: {html_escape(cookie.get("name"))}</h3>
          <span class="badge {badge_class}">{badge_text}</span>
        </div>
        {summary}
        <details>
          <summary>Technical evidence</summary>
          <dl>
            <dt>Secure</dt><dd>{'Present' if cookie.get('secure') else 'Missing'}</dd>
            <dt>HttpOnly</dt><dd>{'Present' if cookie.get('httponly') else 'Missing'}</dd>
            <dt>SameSite</dt><dd>{html_escape(same_site_text)}</dd>
          </dl>
        </details>
      </article>
    """


def generate_html_report(report, output_path):
    """Write a standalone, browser-readable HTML report."""
    headers = report.get("security_headers", [])
    cookies = report.get("cookies", [])
    header_summary = report.get("header_summary", {})
    cookie_summary = report.get("cookie_summary", {})
    scan_summary = report.get("scan_summary", {})

    if report.get("scan_error"):
        overall_label = "Scan incomplete"
        overall_class = "review"
        overview = "WebGuard could not complete the HTTP request. Review the error details below."
    elif scan_summary.get("headers_needing_review", 0) or scan_summary.get("headers_missing", 0) or cookie_summary.get("cookie_findings_count", 0):
        overall_label = "Review observations"
        overall_class = "review"
        overview = (
            "WebGuard recorded configuration observations that may deserve review. "
            "These results do not by themselves confirm vulnerabilities."
        )
    else:
        overall_label = "Checks completed"
        overall_class = "present"
        overview = (
            "The configured checks completed without recording missing-header or cookie-attribute observations. "
            "This does not establish that the website is secure."
        )

    header_cards = "".join(render_header_card(item) for item in headers)
    if not header_cards:
        header_cards = '<p class="empty">No security-header results were collected.</p>'

    cookie_cards = "".join(render_cookie_card(cookie) for cookie in cookies)
    if not cookie_cards:
        cookie_note = html_escape(
            report.get("cookie_scan_note", "No cookie results were collected.")
        )
        cookie_cards = f'<p class="empty">{cookie_note}</p>'

    scan_error_html = ""
    if report.get("scan_error"):
        scan_error_html = f"""
        <section class="section">
          <h2>Scan error</h2>
          <div class="notice error">{html_escape(report["scan_error"])}</div>
        </section>
        """

    raw_headers = report.get("response_headers", {})
    raw_header_rows = "".join(
        f"<tr><th>{html_escape(key)}</th><td><code>{html_escape(value)}</code></td></tr>"
        for key, value in raw_headers.items()
    )
    if raw_header_rows:
        raw_headers_html = f"""
        <section class="section">
          <h2>Response headers</h2>
          <details><summary>Show all response headers</summary>
            <div class="table-wrap"><table>{raw_header_rows}</table></div>
          </details>
        </section>
        """
    else:
        raw_headers_html = ""

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WebGuard Security Report</title>
  <style>
    :root {{ color-scheme: light; --ink:#172033; --muted:#5d687b; --line:#dce3ed; --bg:#f4f7fb; --card:#fff; --navy:#172554; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--ink); font:16px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
    main {{ max-width:1040px; margin:0 auto; padding:28px 18px 48px; }}
    .hero {{ background:linear-gradient(135deg,#172554,#1e40af); color:#fff; padding:28px; border-radius:18px; box-shadow:0 8px 28px #17255420; }}
    .brand {{ display:flex; align-items:center; gap:12px; margin-bottom:18px; }}
    .logo {{ display:grid; place-items:center; width:44px; height:44px; border:1px solid #ffffff55; border-radius:12px; font-size:24px; }}
    h1 {{ margin:0; font-size:clamp(1.7rem,4vw,2.25rem); line-height:1.2; }}
    .subtitle {{ color:#dbeafe; margin:4px 0 0; }}
    .target {{ margin-top:22px; overflow-wrap:anywhere; }}
    .target small {{ display:block; color:#dbeafe; text-transform:uppercase; letter-spacing:.08em; font-size:.75rem; }}
    .target strong {{ font-size:1.08rem; }}
    .hero-meta {{ display:flex; flex-wrap:wrap; gap:10px 22px; margin-top:14px; color:#e0e7ff; font-size:.92rem; }}
    .section {{ margin-top:26px; }}
    h2 {{ font-size:1.35rem; margin:0 0 12px; }}
    h3 {{ font-size:1.05rem; margin:0; overflow-wrap:anywhere; }}
    .summary {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin-top:18px; }}
    .metric,.finding,.notice {{ background:var(--card); border:1px solid var(--line); border-radius:14px; }}
    .metric {{ padding:16px; }}
    .metric-label {{ color:var(--muted); font-size:.85rem; }}
    .metric-value {{ font-size:1.8rem; font-weight:750; line-height:1.3; }}
    .overview {{ margin-top:18px; padding:14px 16px; border-radius:12px; background:#fff; border:1px solid var(--line); }}
    .overview .badge {{ margin-right:8px; }}
    .finding {{ padding:20px; margin:12px 0; }}
    .finding-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:12px; }}
    .badge {{ display:inline-block; flex-shrink:0; padding:3px 10px; border-radius:999px; font-size:.78rem; font-weight:750; letter-spacing:.02em; }}
    .present {{ color:#166534; background:#dcfce7; }}
    .missing {{ color:#9a3412; background:#ffedd5; }}
    .review {{ color:#92400e; background:#fef3c7; }}
    .neutral {{ color:#475569; background:#e2e8f0; }}
    p {{ margin:10px 0; }}
    .plain-note {{ color:var(--muted); }}
    details {{ margin-top:12px; padding-top:10px; border-top:1px solid var(--line); }}
    summary {{ cursor:pointer; color:#1d4ed8; font-weight:650; }}
    dl {{ display:grid; grid-template-columns:minmax(125px,190px) minmax(0,1fr); gap:8px 14px; margin:12px 0 0; }}
    dt {{ color:var(--muted); }} dd {{ margin:0; overflow-wrap:anywhere; }}
    code {{ white-space:pre-wrap; overflow-wrap:anywhere; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:.9em; }}
    .empty,.notice {{ padding:16px; }}
    .notice {{ background:#eff6ff; }}
    .error {{ background:#fff1f2; border-color:#fecdd3; overflow-wrap:anywhere; }}
    ul {{ padding-left:22px; }}
    .table-wrap {{ overflow-x:auto; }}
    table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
    th,td {{ text-align:left; vertical-align:top; padding:10px; border-bottom:1px solid var(--line); }}
    th {{ width:30%; color:var(--muted); }}
    .disclaimer {{ color:var(--muted); font-size:.88rem; }}
    footer {{ margin-top:28px; padding-top:16px; border-top:1px solid var(--line); color:var(--muted); font-size:.85rem; }}
    @media (max-width:760px) {{ .summary {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} .hero {{ padding:22px; }} }}
    @media (max-width:440px) {{ .summary {{ grid-template-columns:1fr 1fr; gap:8px; }} .metric {{ padding:12px; }} .metric-value {{ font-size:1.5rem; }} .finding {{ padding:15px; }} dl {{ grid-template-columns:1fr; gap:2px; }} dd {{ margin-bottom:8px; }} }}
    @media print {{ body {{ background:#fff; }} main {{ max-width:none; padding:0; }} .hero {{ box-shadow:none; print-color-adjust:exact; }} .finding,.metric {{ break-inside:avoid; }} details > * {{ display:block; }} summary {{ list-style:none; }} }}
  </style>
</head>
<body>
<main>
  <header class="hero">
    <div class="brand"><div class="logo" aria-hidden="true">🛡</div><div><h1>WebGuard</h1><p class="subtitle">Website Security Assessment</p></div></div>
    <div class="target"><small>Requested target</small><strong>{html_escape(report.get("requested_url"))}</strong></div>
    <div class="hero-meta">
      <span>Final URL: {html_escape(report.get("final_url"))}</span>
      <span>HTTP status: {html_escape(report.get("http_status_code"))}</span>
      <span>Scan time (UTC): {html_escape(report.get("scan_time_utc"))}</span>
    </div>
  </header>

  <div class="summary" aria-label="Scan summary">
    <div class="metric"><div class="metric-label">Headers checked</div><div class="metric-value">{header_summary.get("headers_checked", 0)}</div></div>
    <div class="metric"><div class="metric-label">Headers present</div><div class="metric-value">{header_summary.get("headers_present", 0)}</div></div>
    <div class="metric"><div class="metric-label">Headers missing</div><div class="metric-value">{header_summary.get("headers_missing", 0)}</div></div>
    <div class="metric"><div class="metric-label">Need review</div><div class="metric-value">{header_summary.get("headers_needing_review", 0)}</div></div>
    <div class="metric"><div class="metric-label">Cookies observed</div><div class="metric-value">{cookie_summary.get("cookie_count", 0)}</div></div>
    <div class="metric"><div class="metric-label">Cookies with observations</div><div class="metric-value">{cookie_summary.get("cookies_with_findings", 0)}</div></div>
    <div class="metric"><div class="metric-label">Cookie observations</div><div class="metric-value">{cookie_summary.get("cookie_findings_count", 0)}</div></div>
    <div class="metric"><div class="metric-label">Scan errors</div><div class="metric-value">{1 if report.get("scan_error") else 0}</div></div>
  </div>

  <div class="overview"><span class="badge {overall_class}">{overall_label}</span>{overview}</div>

  <section class="section">
    <h2>Security header observations</h2>
    <p class="disclaimer">A missing header is not automatically a vulnerability. Review the site's requirements and deployment context before treating an observation as a security issue.</p>
    {header_cards}
  </section>

  <section class="section">
    <h2>Cookie observations</h2>
    <p class="disclaimer">Cookie checks apply to Set-Cookie headers observed in the final response. Redirect responses and application behavior may require separate assessment.</p>
    {cookie_cards}
  </section>

  {raw_headers_html}
  {scan_error_html}

  <section class="section">
    <h2>Important note</h2>
    <div class="notice">{html_escape(report.get("important_note", IMPORTANT_NOTE))}</div>
  </section>

  <footer>Generated by WebGuard · Passive HTTP response checks · This report is not a complete penetration test.</footer>
</main>
</body>
</html>
"""
    output_path.write_text(document, encoding="utf-8")


def choose_report_number(reports_directory):
    """Choose a number unused by either report format."""
    number = 1
    while True:
        json_path = reports_directory / f"scan_Report_{number:02d}.json"
        html_path = reports_directory / f"scan_Report_{number:02d}.html"
        if not json_path.exists() and not html_path.exists():
            return number, json_path, html_path
        number += 1


def main():
    print("--- WebGuard: HTTP Inspector ---")
    try:
        url = validate_url(input("Enter a website URL: "))
    except ValueError as error:
        print("Error:", error)
        raise SystemExit(1)

    report = {
        "tool": TOOL_NAME,
        "report_version": "2.1",
        "scan_mode": "passive",
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": url,
        "final_url": None,
        "http_status_code": None,
        "scan_error": None,
        "security_headers": [],
        "cookies": [],
        "important_note": IMPORTANT_NOTE,
    }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        try:
            print("\nRequested URL:", url)
            print("Final URL:", response.url)
            print("Status Code:", response.status_code)

            report["final_url"] = response.url
            report["http_status_code"] = response.status_code
            report["response_headers"] = dict(response.headers.items())

            print("\n--- Response Headers ---")
            for header, value in response.headers.items():
                print(f"{header}: {value}")

            analyze_security_headers(response, report)
            analyze_cookies(response, report)
        finally:
            response.close()

    except requests.RequestException as error:
        print("\nRequest failed:", error)
        report["scan_error"] = str(error)

    calculate_summaries(report)

    reports_directory = Path("reports")
    try:
        reports_directory.mkdir(parents=True, exist_ok=True)
        report_number, json_path, html_path = choose_report_number(reports_directory)

        # Write JSON first so the original machine-readable output remains available.
        with json_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=4, ensure_ascii=False)

        try:
            generate_html_report(report, html_path)
        except OSError as error:
            print("Could not save the HTML report:", error)
            print("The JSON report was still saved.")

        print("\n--- Reports ---")
        print("JSON report saved to:", json_path.resolve())
        if html_path.exists():
            print("HTML report saved to:", html_path.resolve())
        print("\nTip: Open the HTML report in your browser for the readable version.")

    except OSError as error:
        print("Could not save reports:", error)


if __name__ == "__main__":
    main()
