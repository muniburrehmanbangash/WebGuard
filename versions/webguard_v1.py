import json
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests


IMPORTANT_NOTE = (
    "WebGuard performs automated security checks and reports observed "
    "configuration weaknesses and potential security issues. Findings are "
    "not automatically confirmed vulnerabilities. Interpret each result in "
    "context; potential vulnerabilities may require additional validation. "
    "A clean scan does not guarantee that a website is secure. Only scan "
    "systems you own or have explicit authorization to assess."
)

OWASP_CONFIGURATION_CATEGORY = (
    "Security Misconfiguration (provisional mapping; verify applicability "
    "against the relevant OWASP release and testing guidance)"
)


def create_finding(
    *,
    vulnerability,
    affected_component,
    status,
    severity,
    confidence,
    evidence,
    impact,
    recommendation,
    owasp_category=OWASP_CONFIGURATION_CATEGORY,
    wstg_reference=None,
):
    """Create a consistently shaped finding for the JSON report."""
    return {
        "vulnerability": vulnerability,
        "owasp_category": owasp_category,
        "wstg_reference": wstg_reference,
        "status": status,
        "severity": severity,
        "confidence": confidence,
        "affected_component": affected_component,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
    }


def main():
    # --------------------------------------------------
    # 1. Get and validate the target URL
    # --------------------------------------------------
    url = input("Enter a website URL: ").strip()

    if not url:
        print("Error: Please enter a website URL.")
        raise SystemExit(1)

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed_url = urlparse(url)

    if (
        parsed_url.scheme not in ("http", "https")
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
    ):
        print("Error: Please enter a valid HTTP or HTTPS URL.")
        raise SystemExit(1)

    # --------------------------------------------------
    # 2. Define security headers and review guidance
    # --------------------------------------------------
    security_headers = {
        "Content-Security-Policy": {
            "purpose": "Controls which resources browsers can load.",
            "importance": "Helps reduce risks such as cross-site scripting (XSS).",
            "recommendation": (
                "Review whether an enforced Content-Security-Policy is "
                "appropriate. Define a policy for the application and test "
                "it before enforcement."
            ),
        },
        "Strict-Transport-Security": {
            "purpose": "Tells browsers to use HTTPS for future connections.",
            "importance": "Helps protect against protocol downgrade attacks.",
            "recommendation": (
                "If the site is intended to use HTTPS, review whether "
                "Strict-Transport-Security should be configured. Send HSTS "
                "only over HTTPS and verify the policy before deployment."
            ),
        },
        "X-Content-Type-Options": {
            "purpose": "Controls MIME-type sniffing when set to nosniff.",
            "importance": "Helps prevent content-type interpretation issues.",
            "recommendation": (
                "Review whether X-Content-Type-Options: nosniff is "
                "appropriate for the application."
            ),
        },
        "X-Frame-Options": {
            "purpose": "Controls whether a page can be embedded in frames.",
            "importance": "Can help protect against clickjacking.",
            "recommendation": (
                "Review clickjacking protections. Consider an appropriate "
                "X-Frame-Options policy or the CSP frame-ancestors directive."
            ),
        },
        "Referrer-Policy": {
            "purpose": "Controls how much referrer information browsers send.",
            "importance": "Helps limit unintended information disclosure.",
            "recommendation": (
                "Consider a Referrer-Policy that limits unnecessary disclosure "
                "of URL information, such as strict-origin-when-cross-origin."
            ),
        },
    }

    # --------------------------------------------------
    # 3. Prepare the report
    # --------------------------------------------------
    report = {
        "tool": "WebGuard",
        "report_version": "2.0",
        "scan_mode": "passive",
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": url,
        "final_url": None,
        "http_status_code": None,
        "scan_error": None,
        "important_note": IMPORTANT_NOTE,
        "security_headers": [],
        "cookies": [],
        "findings": [],
    }

    # --------------------------------------------------
    # 4. Send the HTTP request
    # --------------------------------------------------
    response = None
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
        )

        print("\n--- WebGuard: HTTP Inspector ---")
        print("Requested URL:", url)
        print("Final URL:", response.url)
        print("Status Code:", response.status_code)

        final_url = urlparse(response.url)
        is_https = final_url.scheme.lower() == "https"

        report["final_url"] = response.url
        report["http_status_code"] = response.status_code

        print("\n--- Response Headers ---")
        for header, value in response.headers.items():
            print(f"{header}: {value}")

        # --------------------------------------------------
        # 5. Analyze security headers
        # --------------------------------------------------
        print("\n--- Security Header Analysis ---")
        headers = response.headers

        for header, details in security_headers.items():
            value = headers.get(header)

            if header == "Strict-Transport-Security" and not is_https:
                status = "REVIEW"
                note = "HSTS is assessed only on HTTPS responses."
                finding_status = "Not tested"
                severity = "Informational"
                confidence = "High"
                evidence = (
                    "The final response URL uses HTTP, so this response "
                    "cannot establish whether HSTS is correctly configured "
                    "for HTTPS."
                )

            elif value is None:
                if (
                    header == "Content-Security-Policy"
                    and "Content-Security-Policy-Report-Only" in headers
                ):
                    status = "REVIEW"
                    note = (
                        "Enforced CSP is missing; Report-Only CSP is present."
                    )
                else:
                    status = "MISSING"
                    note = "Header was not found in the response."

                finding_status = "Informational/Misconfiguration"
                severity = "Informational"
                confidence = "High"
                evidence = (
                    f"The response did not include the {header} header."
                )

            elif not value.strip():
                status = "REVIEW"
                note = "Header is present but empty."
                finding_status = "Potential"
                severity = "Low"
                confidence = "High"
                evidence = f"The {header} response header is empty."

            elif (
                header == "X-Content-Type-Options"
                and value.strip().lower() != "nosniff"
            ):
                status = "REVIEW"
                note = "Value is not nosniff."
                finding_status = "Potential"
                severity = "Low"
                confidence = "High"
                evidence = (
                    f"The X-Content-Type-Options value is {value!r}, "
                    "rather than nosniff."
                )

            else:
                status = "PRESENT"
                note = "Header was found in the response."
                finding_status = "Not detected"
                severity = "Informational"
                confidence = "High"
                evidence = f"The response included {header}: {value}"

            print(f"\n[{status}] {header}")
            if value is not None:
                print("  Value:", value)
            print("  Note:", note)
            print("  Purpose:", details["purpose"])
            print("  Security relevance:", details["importance"])

            header_record = {
                "name": header,
                "status": status,
                "value": value,
                "note": note,
                "purpose": details["purpose"],
                "security_relevance": details["importance"],
            }
            report["security_headers"].append(header_record)

            finding = create_finding(
                vulnerability=(
                    f"Review {header} configuration"
                    if finding_status != "Not detected"
                    else f"No issue detected by the {header} presence check"
                ),
                affected_component=header,
                status=finding_status,
                severity=severity,
                confidence=confidence,
                evidence=evidence,
                impact=(
                    "The absence or configuration of this header may reduce "
                    "a browser-side protection, depending on the application "
                    "and its other controls. Header absence alone does not "
                    "prove an exploitable vulnerability."
                ),
                recommendation=details["recommendation"],
            )
            report["findings"].append(finding)

            print(
                f"  Finding: {finding['status']} | "
                f"Severity: {finding['severity']}"
            )
            print("  Recommendation:", finding["recommendation"])

        # --------------------------------------------------
        # 6. Analyze cookie security attributes
        # --------------------------------------------------
        print("\n--- Cookie Security Analysis ---")
        raw_headers = response.raw.headers

        if hasattr(raw_headers, "getlist"):
            set_cookie_headers = raw_headers.getlist("Set-Cookie")
        else:
            set_cookie_headers = None

        if set_cookie_headers is None:
            message = "Cannot reliably separate Set-Cookie headers."
            print("[REVIEW]", message)
            report["cookie_scan_note"] = message

        elif not set_cookie_headers:
            message = "No Set-Cookie headers found in this response."
            print(message)
            report["cookie_scan_note"] = message

        else:
            report["cookie_scan_note"] = (
                "Cookie attributes were inspected on Set-Cookie headers "
                "in the final response only."
            )

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
                        key, attr_value = part.split("=", 1)
                        attributes[key.strip().lower()] = attr_value.strip()
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

                def add_cookie_finding(attribute, message, recommendation):
                    cookie_finding = create_finding(
                        vulnerability=message,
                        affected_component=f"Cookie: {cookie_name}",
                        status="Potential",
                        severity="Low",
                        confidence="Medium",
                        evidence=(
                            f"Set-Cookie for {cookie_name!r} does not satisfy "
                            f"the observed {attribute} check: {message}"
                        ),
                        impact=(
                            "Depending on how the cookie is used, missing or "
                            "incorrect attributes may weaken browser-side "
                            "protections. Validate the cookie's purpose and "
                            "application context before assigning final risk."
                        ),
                        recommendation=recommendation,
                    )
                    cookie_report["findings"].append(cookie_finding)
                    report["findings"].append(cookie_finding)
                    print("  [REVIEW]", message)

                if "secure" in attributes:
                    print("  [PRESENT] Secure")
                else:
                    add_cookie_finding(
                        "Secure",
                        "Secure attribute is missing.",
                        "If this cookie is used over HTTPS, consider setting "
                        "Secure so browsers send it only over secure "
                        "connections.",
                    )

                if "httponly" in attributes:
                    print("  [PRESENT] HttpOnly")
                else:
                    add_cookie_finding(
                        "HttpOnly",
                        "HttpOnly attribute is missing.",
                        "If client-side JavaScript does not need to read this "
                        "cookie, consider setting HttpOnly to reduce access "
                        "from scripts.",
                    )

                same_site = attributes.get("samesite")
                if same_site is not None:
                    normalized = str(same_site).lower()
                    if normalized in ("strict", "lax", "none"):
                        cookie_report["samesite"] = normalized
                        print(f"  [PRESENT] SameSite={normalized}")

                        if normalized == "none" and "secure" not in attributes:
                            add_cookie_finding(
                                "SameSite",
                                "SameSite=None is set without Secure.",
                                "Browsers generally require Secure when "
                                "SameSite=None is used; configure both "
                                "attributes when this cross-site behavior "
                                "is required.",
                            )
                    else:
                        add_cookie_finding(
                            "SameSite",
                            f"Unrecognized SameSite value: {same_site}",
                            "Use a supported SameSite value (Strict, Lax, or "
                            "None) appropriate to the application's needs.",
                        )
                else:
                    add_cookie_finding(
                        "SameSite",
                        "SameSite attribute is missing.",
                        "Choose a SameSite policy (Strict, Lax, or None) "
                        "based on required cross-site cookie behavior.",
                    )

                report["cookies"].append(cookie_report)

    except requests.RequestException as error:
        print("\nRequest failed:", error)
        report["scan_error"] = str(error)

    finally:
        if response is not None:
            response.close()

    # --------------------------------------------------
    # 7. Calculate cookie summary counts
    # --------------------------------------------------
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

    # --------------------------------------------------
    # 8. Calculate security header summary
    # --------------------------------------------------
    header_summary = {
        "headers_checked": len(report["security_headers"]),
        "headers_present": sum(
            1 for header in report["security_headers"]
            if header["status"] == "PRESENT"
        ),
        "headers_missing": sum(
            1 for header in report["security_headers"]
            if header["status"] == "MISSING"
        ),
        "headers_needing_review": sum(
            1 for header in report["security_headers"]
            if header["status"] == "REVIEW"
        ),
    }
    report["header_summary"] = header_summary

    # --------------------------------------------------
    # 9. Overall scan and finding summaries
    # --------------------------------------------------
    finding_status_counts = {}
    finding_severity_counts = {}

    for finding in report["findings"]:
        status = finding["status"]
        severity = finding["severity"]
        finding_status_counts[status] = finding_status_counts.get(status, 0) + 1
        finding_severity_counts[severity] = (
            finding_severity_counts.get(severity, 0) + 1
        )

    report["finding_summary"] = {
        "total_findings": len(report["findings"]),
        "by_status": finding_status_counts,
        "by_severity": finding_severity_counts,
    }
    report["scan_summary"] = {
        **header_summary,
        **report["cookie_summary"],
        "total_findings": len(report["findings"]),
    }

    # --------------------------------------------------
    # 10. Display scan limitation notice
    # --------------------------------------------------
    print("\n--- Finding Summary ---")
    print("Total findings:", len(report["findings"]))
    for status, count in finding_status_counts.items():
        print(f"  {status}: {count}")

    print("\n--- Important Security Notice ---")
    print(report["important_note"])

    # --------------------------------------------------
    # 11. Save the JSON report without overwriting reports
    # --------------------------------------------------
    reports_directory = Path("reports")
    reports_directory.mkdir(parents=True, exist_ok=True)

    report_number = 1
    while True:
        report_path = reports_directory / (
            f"scan_Report_{report_number:02d}.json"
        )
        if not report_path.exists():
            break
        report_number += 1

    try:
        with report_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=4, ensure_ascii=False)

        print("\n--- JSON Report ---")
        print("Report saved to:", report_path.resolve())

    except OSError as error:
        print("Could not save the JSON report:", error)


if __name__ == "__main__":
    main()
