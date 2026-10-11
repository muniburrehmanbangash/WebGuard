#!/usr/bin/env python3
# ^ The "shebang" line. On Linux/Mac it tells the system to run this file with
#   Python 3 when you execute it directly. On Windows it is simply ignored.

# ======================================================================
#  HOW TO READ THIS FILE (beginner guide)
# ======================================================================
#  This program is a small "website security checker". The flow is:
#    1. Ask the user for a website address (URL).
#    2. Check the URL looks valid.
#    3. Visit the site once (an ordinary HTTP GET request).
#    4. Look at the response "headers" and "cookies" for security settings.
#    5. Collect everything in a big dictionary called `report`.
#    6. Turn that dictionary into a nice HTML page you can open in a browser.
#
#  Python basics you will see a lot:
#    - `#` starts a comment (Python ignores it; it is for humans).
#    - `def name(args):` defines a function (a reusable block of code).
#    - A dictionary `{ "key": value }` stores labelled data.
#    - A list `[a, b, c]` stores an ordered collection of items.
# ======================================================================

"""WebGuard 3.0: user-friendly website security configuration review."""
# ^ A string placed at the very top of a file is called a "docstring".
#   It documents what the whole file (module) does.

# ---------- IMPORTS ----------
# `import` brings in ready-made code (modules) written by other people so we
# don't have to write everything from scratch.
import html                                   # Built-in: safely escape text for HTML (e.g. "<" -> "&lt;")
import json                                   # Built-in: convert dictionaries/lists to text (JSON format)
import re                                     # Built-in: "regular expressions" = powerful text pattern matching
from collections import Counter               # Built-in: counts how many times things appear
from datetime import datetime, timezone       # Built-in: work with dates and times
from pathlib import Path                      # Built-in: modern way to handle file/folder paths
from urllib.parse import urlparse             # Built-in: split a URL into parts (scheme, host, path...)

import requests                               # THIRD-PARTY: makes HTTP requests. Install with: pip install requests

# ---------- CONSTANTS ----------
# By convention, names in ALL_CAPS are "constants": values we set once and
# never change while the program runs.
TOOL_NAME = "WebGuard"
REPORT_VERSION = "3.0"
TIMEOUT_SECONDS = 10   # Give up on a request if the server doesn't answer within 10 seconds

# Several string pieces placed next to each other inside ( ) are joined into
# ONE long string by Python. This is a neat way to split a long sentence over
# multiple lines.
IMPORTANT_NOTE = (
    "WebGuard performs passive HTTP response checks and limited, non-destructive "
    "validation requests. Findings describe observed configuration, not proof of "
    "exploitability. The scanner does not submit attack payloads, test authenticated "
    "workflows, or establish that an application is secure. Redirect-chain responses "
    "are recorded where available, but cookie analysis is limited to captured "
    "Set-Cookie headers from responses observed during this scan."
)

# HEADER_RULES is a dictionary of dictionaries.
#   Outer key   = the name of a security header we want to check.
#   Inner dict  = plain-English explanation (purpose / impact / recommendation).
# Later, the code loops over this to check every header the same way.
# "HTTP headers" are small labelled pieces of info a server sends along with a web page.
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

# Maps severity names to numbers so severities could be compared/sorted.
# (Defined here for ordering; the rest of this script doesn't actually use it yet.)
SEVERITY_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Unrated": -1}


# ======================================================================
#  FUNCTION: validate_url
#  Cleans up what the user typed and makes sure it is a usable web address.
# ======================================================================
def validate_url(raw_url):
    url = raw_url.strip()              # .strip() removes spaces/newlines from both ends
    if not url:                        # An empty string counts as False, so "not url" means "user typed nothing"
        # `raise` creates an error on purpose. The caller (main) catches it.
        raise ValueError("Please enter a website URL.")
    # If the user typed "example.com" without http(s)://, add https:// for them.
    # .startswith() accepts a tuple of options: any one of them matching is enough.
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)             # Break the URL into parts: scheme, hostname, username, ...
    # Reject if: scheme isn't http/https, there's no hostname, or the URL has
    # "user:password@" embedded in it (a trick sometimes used to disguise links).
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("Please enter a valid HTTP or HTTPS URL.")
    # any(...) is True if AT LEAST ONE item is True. Here: "does any character
    # in the URL count as whitespace (space, tab, newline)?"
    if any(ch.isspace() for ch in url):
        raise ValueError("URL must not contain whitespace.")
    return url                         # Hand the cleaned URL back to whoever called this function


# ======================================================================
#  FUNCTION: make_finding
#  A "factory" that builds one finding (a dictionary describing one issue or
#  observation). Using one function everywhere keeps all findings consistent.
# ======================================================================
# Parameters written like `applicability="Applicable"` have DEFAULT values:
# if the caller doesn't supply them, the default is used.
def make_finding(rule_id, title, classification, severity, confidence, evidence,
                 impact, recommendation, applicability="Applicable", status="OBSERVATION"):
    return {
        "id": rule_id,                         # Short unique code, e.g. "HDR-HSTS-HTTP"
        "title": title,                        # Human-readable headline
        "classification": classification,      # e.g. "Potential issue", "Informational"
        "severity": severity,                  # "High" / "Medium" / "Low" / "Informational" / "Unrated"
        "confidence": confidence,              # How sure the scanner is about this observation
        "applicability": applicability,        # Does this finding apply in this situation?
        "status": status,                      # MISSING / REVIEW / NOT_ASSESSED / OBSERVATION
        "evidence": evidence,                  # The raw data that led to this finding
        "impact": impact,                      # Why it might matter
        "recommendation": recommendation,      # What to do about it
    }


# ======================================================================
#  FUNCTION: get_header_values
#  Some headers can appear several times in one response. The normal
#  `response.headers` view merges them. This tries to get EVERY value.
# ======================================================================
def get_header_values(response, name):
    """Return repeated header values when urllib3 exposes them."""
    # getattr(obj, "attr", default) safely reads an attribute; if it doesn't
    # exist you get the default (None) instead of a crash.
    # Here we dig down: response -> raw -> headers (the low-level urllib3 version).
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    # hasattr() checks whether an object has a certain method/attribute.
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        try:
            values = raw_headers.getlist(name)          # A list of ALL values for this header
            if values:                                  # A non-empty list counts as True
                return [str(v) for v in values]         # List comprehension: convert each value to text
        except Exception:
            pass                                        # If anything goes wrong, just fall through to the fallback below
    # Fallback: use the ordinary (merged) header view.
    value = response.headers.get(name)                  # .get() returns None if the header is absent
    # Conditional expression:  A if condition else B
    return [] if value is None else [str(value)]


# ======================================================================
#  FUNCTION: analyze_security_headers
#  The biggest "checker". For each header in HEADER_RULES it decides:
#  present? missing? empty? wrong value? Then records findings.
# ======================================================================
def analyze_security_headers(response, report):
    print("\n--- Security Header Analysis ---")            # "\n" = a blank line before the text
    headers = report["security_headers"]                   # Shortcut names pointing at lists INSIDE `report`
    findings = report["findings"]                          # (Appending to these changes `report` too.)
    # Is the page we finally landed on HTTPS? (.lower() makes comparison case-insensitive)
    is_https = urlparse(response.url).scheme.lower() == "https"
    # Dictionary comprehension: build a dict of all headers with lowercase names,
    # because header names are case-insensitive ("Server" == "server").
    all_values = {key.lower(): value for key, value in response.headers.items()}

    # Loop through each header name and its rule. `.items()` gives (key, value) pairs.
    for name, rule in HEADER_RULES.items():
        values = get_header_values(response, name)         # All values (list)
        value = response.headers.get(name)                 # Single value, or None if missing
        # Decide a status using nested conditional expressions:
        #   None            -> "MISSING"
        #   empty/blank     -> "REVIEW"
        #   otherwise       -> "PRESENT"
        status = "MISSING" if value is None else ("REVIEW" if not value.strip() else "PRESENT")
        note = ("Header was observed." if status == "PRESENT" else
                "Header was not observed." if status == "MISSING" else
                "Header exists but its value is empty.")
        item_findings = []                                 # Findings that belong to THIS header only

        # ---- CASE 1: HSTS but the page was loaded over plain HTTP ----
        # Browsers ignore HSTS sent over HTTP, so we can't judge it here.
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

        # ---- CASE 2: header is missing ----
        elif status == "MISSING":
            # Sub-case: no enforced CSP, but a "report-only" CSP exists
            # (report-only just logs problems; it doesn't block anything).
            if name == "Content-Security-Policy" and all_values.get("content-security-policy-report-only"):
                classification, severity = "Informational", "Informational"
                note = "Enforced CSP was not observed; Content-Security-Policy-Report-Only is present and does not enforce restrictions."
            # Sub-case: X-Frame-Options missing, BUT CSP has "frame-ancestors"
            # which does the same job (a modern replacement). re.search looks
            # for that pattern in the text; re.I = ignore upper/lower case.
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
            # (Writing "a, b = x, y" assigns two variables in one line.)

            if not item_findings:                          # Empty list == False, so this means "no finding yet"
                finding = make_finding(
                    # Build an ID like "HDR-CONTENT-SECURITY-POLICY":
                    # re.sub replaces every run of characters that are NOT A-Z or 0-9 with "-",
                    # and .strip("-") trims leftover dashes at the ends.
                    "HDR-" + re.sub(r"[^A-Z0-9]+", "-", name.upper()).strip("-"),
                    f"Missing {name}", classification, severity, "High",   # f"..." = f-string: {name} is replaced by its value
                    {"header": name, "observed_values": values, "response_url": response.url},
                    rule["impact"] + " The scan did not establish an exploitable vulnerability.",
                    rule["recommendation"],
                    applicability=("HTTPS response" if name == "Strict-Transport-Security" else "General HTTP response"),
                    status="MISSING")
                item_findings.append(finding)
                findings.append(finding)

        # ---- CASE 3: header exists but its value is empty/blank ----
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

        # ---- CASE 4: X-Content-Type-Options exists but isn't "nosniff" ----
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

        # ---- CASE 5: HSTS present on HTTPS -> validate its max-age ----
        elif name == "Strict-Transport-Security":
            # Split "max-age=31536000; includeSubDomains" at ";" into pieces,
            # trimming spaces and dropping empty pieces.
            directives = [d.strip() for d in value.split(";") if d.strip()]
            # next(generator, None) returns the FIRST matching item, or None if nothing matches.
            # Here: find the "max-age=..." piece and keep the text after "=".
            max_age = next((d.split("=", 1)[1].strip() for d in directives
                            if d.lower().startswith("max-age=") and "=" in d), None)
            # .isdigit() is True only if the text is made of digits (e.g. "31536000").
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

        # ---- CASE 6: (effectively never runs) ----
        # `name` is something like "Content-Security-Policy", which never
        # contains "report-only", so this condition is always False.
        # It is harmless leftover logic; the report-only check actually
        # happens in CASE 2 above.
        elif name == "Content-Security-Policy" and "report-only" in name.lower():
            note = "CSP was observed."

        # ---- Print a readable summary for this header to the terminal ----
        print(f"\n[{status}] {name}")
        if value is not None:
            print("  Value:", value)
        print("  Note:", note)
        print("  Purpose:", rule["purpose"])

        # Save everything about this header into the report dictionary.
        headers.append({
            "name": name, "status": status, "value": value, "values": values,
            "note": note, "purpose": rule["purpose"], "security_relevance": rule["impact"],
            "recommendation": rule["recommendation"],
            "findings": item_findings,
        })

    # ---- Second pass: look for headers sent more than once ----
    # Duplicates are recorded as an observation, not automatically a vulnerability.
    for name in HEADER_RULES:                              # Looping over a dict gives its keys
        values = get_header_values(response, name)
        if len(values) > 1:                                # len() = how many items in the list
            finding = make_finding(
                "HDR-DUP-" + re.sub(r"[^A-Z0-9]+", "-", name.upper()).strip("-"),
                f"Repeated {name} headers", "Potential issue", "Low", "Medium",
                {"header": name, "values": values},
                "Repeated or conflicting security header values can be interpreted differently by components.",
                "Review the server, reverse proxy, and application configuration to ensure one consistent policy is emitted.",
                status="REVIEW")
            findings.append(finding)


# ======================================================================
#  FUNCTION: parse_set_cookie
#  A cookie arrives as one text line, e.g.:
#     sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax
#  This function splits it into: (name, {attributes}, [duplicate attributes]).
# ======================================================================
def parse_set_cookie(raw_value):
    """Parse one Set-Cookie header without splitting the Expires date on commas."""
    # Split on ";" (NOT on commas, because dates like "Mon, 01 Jan" contain commas).
    parts = [part.strip() for part in raw_value.split(";")]
    # The first piece must look like "name=value". If not, we can't parse it.
    if not parts or "=" not in parts[0]:
        return None, {}, ["Cookie name/value pair could not be parsed."]
    name, value = parts[0].split("=", 1)       # split("=", 1) splits only at the FIRST "="
    name = name.strip()
    attributes = {}                            # Will hold e.g. {"path": "/", "secure": True}
    duplicates = []                            # Attribute names that appeared more than once
    for part in parts[1:]:                     # [1:] = everything after the first item (a "slice")
        if not part:
            continue                           # `continue` skips to the next loop round
        if "=" in part:                        # Attributes like "Path=/" have a value...
            key, attr_value = part.split("=", 1)
            key = key.strip().lower()
            attr_value = attr_value.strip()
        else:                                  # ...flags like "Secure" have no value, so store True
            key, attr_value = part.strip().lower(), True
        if key in attributes:                  # Already seen this attribute -> duplicate
            duplicates.append(key)
        attributes[key] = attr_value           # Store it in the dictionary
    return name, attributes, duplicates        # A function can return several values at once (a tuple)


# ======================================================================
#  FUNCTION: analyze_cookies
#  Examines every Set-Cookie header and checks the Secure, HttpOnly and
#  SameSite flags plus special name prefixes (__Secure-, __Host-).
# ======================================================================
def analyze_cookies(response, report):
    print("\n--- Cookie Security Analysis ---")
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        cookie_headers = list(raw_headers.getlist("Set-Cookie"))   # Each cookie as a separate string
    else:
        # Requests' merged header view may collapse repeated Set-Cookie values.
        cookie_headers = []
        report["cookie_scan_note"] = (
            "The response library did not expose separate Set-Cookie header values; "
            "cookie analysis may be incomplete."
        )

    if not cookie_headers:                     # No cookies at all -> record a note and stop early
        # setdefault: set this key ONLY if it doesn't already exist.
        report.setdefault("cookie_scan_note", "No Set-Cookie headers were observed in the final response.")
        print(report["cookie_scan_note"])
        return                                 # `return` with no value just exits the function

    # enumerate(list, start=1) gives (counter, item) pairs: (1, first), (2, second)...
    for index, raw_cookie in enumerate(cookie_headers, start=1):
        name, attrs, duplicate_attrs = parse_set_cookie(str(raw_cookie))   # Unpack the 3 returned values
        if not name:                           # Parsing failed -> record "not assessed" and move on
            finding = make_finding(
                f"COOKIE-PARSE-{index:02d}", "Unparseable Set-Cookie header",   # {index:02d} = number padded to 2 digits (01, 02...)
                "Not assessed", "Unrated", "High", {"set_cookie": str(raw_cookie)},
                "The scanner could not reliably evaluate this cookie's attributes.",
                "Review the raw Set-Cookie header manually.", status="NOT_ASSESSED")
            report["findings"].append(finding)
            report["cookies"].append({"name": None, "raw_header": str(raw_cookie), "findings": [finding]})
            continue

        # Check which security flags exist. `"secure" in attrs` is True/False.
        secure = "secure" in attrs
        httponly = "httponly" in attrs
        same_site = attrs.get("samesite")      # None if the cookie has no SameSite attribute
        cookie_findings = []                   # Findings for THIS cookie only

        # A "nested function": a function defined inside another function.
        # It can use variables from the outer function (name, attrs, index...).
        # It saves us from repeating the same make_finding(...) code many times.
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
        # SameSite exists but has a value that isn't Strict/Lax/None
        elif not isinstance(same_site, str) or same_site.lower() not in ("strict", "lax", "none"):
            add_cookie_finding("SAMESITE-VALUE", f"Cookie {name} has an unrecognized SameSite value",
                "Configuration weakness", "Low", "High",
                "An unrecognized SameSite value may not produce the intended browser behavior.",
                "Use SameSite=Strict, Lax, or None according to the application's cross-site requirements.", "REVIEW")
        # SameSite=None requires the Secure flag in modern browsers
        elif same_site.lower() == "none" and not secure:
            add_cookie_finding("SAMESITE-NONE-SECURE", f"Cookie {name} uses SameSite=None without Secure",
                "Configuration weakness", "Low", "High",
                "Modern browsers generally require Secure with SameSite=None; the cookie may be rejected or not behave as intended.",
                "Add Secure and verify the intended cross-site cookie behavior.", "REVIEW")

        # `pass` means "do nothing". This check is redundant because we already
        # skipped cookies with no name above. It's harmless dead code.
        if not name:
            pass
        # Cookie NAME prefixes are special promises enforced by browsers:
        #   __Secure-  => must have the Secure flag.
        if name.startswith("__Secure-") and not secure:
            add_cookie_finding("PREFIX-SECURE", f"Cookie {name} violates __Secure- prefix requirements",
                "Configuration weakness", "Low", "High",
                "Browsers require a __Secure- cookie to be set from a secure context with the Secure attribute.",
                "Set the cookie over HTTPS with Secure, or rename it if the prefix is not intended.", "REVIEW")
        #   __Host-    => must have Secure, Path=/, and NO Domain attribute.
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

        # Report any attribute that was written more than once.
        for attr in duplicate_attrs:
            add_cookie_finding("DUP-ATTR", f"Cookie {name} repeats the {attr} attribute",
                "Potential issue", "Low", "Medium",
                "Duplicate cookie attributes can cause ambiguous configuration or inconsistent interpretation.",
                "Emit each cookie attribute at most once.", "REVIEW")

        # Store a full description of this cookie in the report.
        cookie_report = {
            "name": name, "raw_header": str(raw_cookie),
            "secure": secure, "httponly": httponly,
            "samesite": same_site, "path": attrs.get("path"),
            "domain": attrs.get("domain"), "expires": attrs.get("expires"),
            "max_age": attrs.get("max-age"), "attributes": attrs,
            "findings": cookie_findings,
        }
        report["cookies"].append(cookie_report)
        # `A or B` gives A if A is "truthy", otherwise B. So an unset SameSite prints "not set".
        print(f"\nCookie: {name}")
        print(f"  Secure={secure}; HttpOnly={httponly}; SameSite={same_site or 'not set'}")
        for finding in cookie_findings:
            print(f"  [{finding['severity']}] {finding['title']}")


# ======================================================================
#  FUNCTION: collect_response_details
#  Saves a snapshot of one HTTP response (URL, status, headers, cookies)
#  into report["responses"], so it can be shown in the final HTML.
# ======================================================================
def collect_response_details(response, report, label):
    detail = {
        "label": label,                              # e.g. "primary" or "https-comparison"
        "url": response.url,
        "status_code": response.status_code,         # 200 = OK, 404 = not found, etc.
        "headers": dict(response.headers.items()),   # Convert header view to a normal dictionary
        "set_cookie_headers": get_header_values(response, "Set-Cookie"),
    }
    report["responses"].append(detail)


# ======================================================================
#  FUNCTION: safe_validation_get
#  The ONE place that actually contacts the website. A plain GET request
#  only (no attack data, no POST/DELETE).
# ======================================================================
def safe_validation_get(session, url):
    """One bounded GET with redirects; no payloads or state-changing methods."""
    # timeout   = stop waiting after N seconds
    # allow_redirects=True = follow "go to this other URL" responses automatically
    # stream=True = don't download the whole page body immediately (we only need headers)
    return session.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=True, stream=True)


# ======================================================================
#  FUNCTION: perform_scan
#  Runs the whole scan: request -> analyze headers -> analyze cookies ->
#  optional HTTPS comparison request.
# ======================================================================
def perform_scan(url, report):
    # A Session reuses the connection and settings between requests.
    session = requests.Session()
    # Identify ourselves honestly to the server with a User-Agent header.
    session.headers.update({"User-Agent": "WebGuard/3.0 (passive security configuration review)"})
    # try/finally: the `finally` block ALWAYS runs, even after an error,
    # so we are sure to close the session and free resources.
    try:
        # Main request: normal GET only; no attack payloads.
        response = safe_validation_get(session, url)
        try:
            report["final_url"] = response.url               # The URL after any redirects
            report["http_status_code"] = response.status_code
            collect_response_details(response, report, "primary")
            report["response_headers"] = dict(response.headers.items())
            print("\nRequested URL:", url)
            print("Final URL:", response.url)
            print("Status Code:", response.status_code)
            print("\n--- Response Headers ---")
            for header, value in response.headers.items():
                print(f"{header}: {value}")
            analyze_security_headers(response, report)       # Check the 5 security headers
            analyze_cookies(response, report)                # Check cookies
        finally:
            response.close()                                 # Always release the network connection

        # Non-destructive validation: if the initial URL was HTTP and it did not
        # redirect to HTTPS, make one HTTPS GET to the same host/path for comparison.
        parsed_requested = urlparse(url)
        parsed_final = urlparse(report["final_url"] or url)  # `or url` = fallback if final_url is None
        if parsed_requested.scheme == "http" and parsed_final.scheme == "http":
            # ._replace() makes a copy of the parsed URL with a different scheme; .geturl() turns it back into text.
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
                    # next(..., None): find the HSTS entry in the headers list (or None).
                    hsts = next((h for h in report["security_headers"]
                                 if h["name"] == "Strict-Transport-Security"), None)
                    if hsts:
                        hsts["https_comparison"] = {
                            "url": validation_response.url,
                            "status_code": validation_response.status_code,
                            "hsts_observed": validation_response.headers.get("Strict-Transport-Security") is not None,
                        }
                        if validation_response.headers.get("Strict-Transport-Security"):
                            hsts["note"] += " HSTS was observed on the separate HTTPS comparison response."   # += appends to the string
                finally:
                    validation_response.close()
            except requests.RequestException as error:
                # requests.RequestException is the parent of all network errors
                # (timeout, DNS failure, SSL problem...). We record it instead of crashing.
                report["validation_requests"].append({
                    "type": "https-comparison", "requested_url": https_url,
                    "error": str(error),
                    "note": "The optional HTTPS comparison failed; this does not prove HTTPS is unavailable."
                })
    finally:
        session.close()


# ======================================================================
#  FUNCTION: calculate_summaries
#  Counts things (headers present/missing, cookies, findings by severity)
#  and stores the totals in the report for the summary section.
# ======================================================================
def calculate_summaries(report):
    # .get(key, default) avoids a crash if the key doesn't exist.
    headers = report.get("security_headers", [])
    cookies = report.get("cookies", [])
    findings = report.get("findings", [])
    report["header_summary"] = {
        "headers_checked": len(headers),
        # sum() of True/False values: True counts as 1, False as 0 -> it counts the matches.
        "headers_present": sum(h["status"] == "PRESENT" for h in headers),
        "headers_missing": sum(h["status"] == "MISSING" for h in headers),
        "headers_needing_review": sum(h["status"] in ("REVIEW", "NOT_ASSESSED") for h in headers),
    }
    report["cookie_summary"] = {
        "cookie_count": len(cookies),
        "cookies_with_findings": sum(bool(c.get("findings")) for c in cookies),
        "cookie_findings_count": sum(len(c.get("findings", [])) for c in cookies),
    }
    # Counter tallies items: Counter(["a","b","a"]) -> {"a": 2, "b": 1}
    counts = Counter(f["classification"] for f in findings)
    severity_counts = Counter(f["severity"] for f in findings)
    report["finding_summary"] = {
        "total_findings": len(findings),
        "by_classification": dict(counts),
        "by_severity": dict(severity_counts),
    }
    # `{**a, **b, "x": 1}` merges dictionaries together into a new one.
    report["scan_summary"] = {**report["header_summary"], **report["cookie_summary"],
                              "total_findings": len(findings)}


# ======================================================================
#  FUNCTION: esc  (short for "escape")
#  Prepares any value to be safely placed inside HTML.
#  IMPORTANT for security: if text contained "<script>", it could run in
#  the browser. html.escape turns "<" into "&lt;" so it shows as plain text.
# ======================================================================
def esc(value):
    if value is None:
        return "Not available"
    if isinstance(value, (dict, list)):                    # isinstance checks the type of a value
        value = json.dumps(value, indent=2, ensure_ascii=False)   # Turn dict/list into pretty text
    return html.escape(str(value), quote=True)


# ======================================================================
#  FUNCTION: render_finding
#  Returns the HTML text (a string) for ONE finding card.
# ======================================================================
def render_finding(finding):
    severity = finding.get("severity", "Unrated")
    # Choose a CSS class name (used for badge colour) based on severity.
    badge_class = {"High": "high", "Medium": "medium", "Low": "low",
                   "Informational": "info", "Unrated": "neutral"}.get(severity, "neutral")
    classification = finding.get("classification", "Observation")
    # f""" ... """ is a multi-line f-string. Anything in {braces} is replaced by Python values.
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


# ======================================================================
#  FUNCTION: generate_html_report
#  Builds the full HTML page from the `report` dictionary and writes it
#  to a file. HTML = the page structure; CSS (inside <style>) = the looks.
# ======================================================================
def generate_html_report(report, output_path):
    findings = report.get("findings", [])
    # "".join(...) glues many strings together with nothing between them.
    # Here: build the HTML for every finding, then join into one big string.
    findings_html = "".join(render_finding(f) for f in findings)
    if not findings_html:                                  # Empty string == False -> no findings at all
        findings_html = '<div class="empty"><h3>No findings recorded</h3><p>The configured checks did not produce findings. This does not prove the website is secure.</p></div>'

    # Build the table rows (one row per HTTP response we recorded).
    response_rows = ""
    for response in report.get("responses", []):
        response_rows += (                                 # += keeps adding more text to the same string
            "<tr><td>" + esc(response.get("label")) + "</td><td>" + esc(response.get("url")) +
            "</td><td>" + esc(response.get("status_code")) + "</td><td><details><summary>View headers</summary><pre>" +
            esc(response.get("headers")) + "</pre></details></td></tr>"
        )
    # If the scan hit an error, prepare a red "Scan issue" box; otherwise leave it empty.
    scan_error = ""
    if report.get("scan_error"):
        scan_error = f'<section class="panel error"><h2>Scan issue</h2><p>WebGuard could not complete every scan step. Review the technical message below.</p><pre>{esc(report["scan_error"])}</pre></section>'

    # ---- Decide the overall "traffic light" label at the top of the report ----
    summary = report.get("finding_summary", {})
    severity_counts = summary.get("by_severity", {})
    # Find the most serious severity that has at least one finding (checked High -> Medium -> Low).
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

    # ---- Build the "Additional checks" list ----
    validation_items = report.get("validation_requests", [])
    if validation_items:
        validation_html = "".join(f'<li><strong>{esc(item.get("type", "Validation request"))}:</strong> {esc(item.get("note", item.get("error", "Completed")))}' + (f'<pre>{esc(item.get("error"))}</pre>' if item.get("error") else "") + '</li>' for item in validation_items)
        validation_html = f"<ul>{validation_html}</ul>"
    else:
        validation_html = '<p class="muted">No additional validation requests were needed for this scan.</p>'

    # Numbers shown in the three "metric" boxes.
    cookie_count = report.get("cookie_summary", {}).get("cookie_count", 0)
    header_missing = report.get("header_summary", {}).get("headers_missing", 0)
    status_code = report.get("http_status_code") if report.get("http_status_code") is not None else "Not received"

    # ---- The full HTML page as one giant f-string ----
    # NOTE for beginners: inside an f-string, a literal curly brace must be
    # DOUBLED: "{{" prints "{" and "}}" prints "}". That is why the CSS below
    # (which uses lots of braces) looks like it has double braces everywhere.
    # Single {braces} such as {esc(...)} insert Python values into the page.
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
    # Write the finished HTML text into the file on disk (UTF-8 so emoji/symbols work).
    output_path.write_text(document, encoding="utf-8")

# ======================================================================
#  FUNCTION: choose_report_path
#  Finds a file name that doesn't exist yet, so old reports are never
#  overwritten: scan_Report_01.html, scan_Report_02.html, ...
# ======================================================================
def choose_report_path(directory):
    """Return the next unused HTML report path without overwriting old reports."""
    number = 1
    while True:                                            # `while True` loops forever until we `return`
        html_path = directory / f"scan_Report_{number:02d}.html"   # The "/" operator joins paths in pathlib
        if not html_path.exists():                         # Found a free name -> use it
            return html_path
        number += 1                                        # Otherwise try the next number


# ======================================================================
#  FUNCTION: main
#  The "starting point" that ties everything together.
# ======================================================================
def main():
    print("--- WebGuard 3.0 ---")
    try:
        # input() pauses the program and waits for the user to type something.
        url = validate_url(input("Enter a website URL: "))
    except ValueError as error:                            # Catch the errors raised in validate_url
        print("Error:", error)
        raise SystemExit(1)                                # Quit the program (exit code 1 = "something went wrong")

    # Create the report dictionary with starting (empty) values.
    # Every other function fills in the parts that belong to it.
    report = {
        "tool": TOOL_NAME, "report_version": REPORT_VERSION,
        "scan_mode": "passive_plus_non_destructive_validation",
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),   # Current time in UTC as text
        "requested_url": url, "final_url": None, "http_status_code": None,
        "scan_error": None, "security_headers": [], "cookies": [],
        "findings": [], "responses": [], "validation_requests": [],
        "response_headers": {}, "important_note": IMPORTANT_NOTE,
    }
    # Run the scan inside try/except so a network problem doesn't crash the program.
    try:
        perform_scan(url, report)
    except requests.RequestException as error:             # Expected network errors (timeout, DNS, SSL...)
        report["scan_error"] = str(error)
        print("\nRequest failed:", error)
    except Exception as error:                             # Any other unexpected error (a safety net)
        report["scan_error"] = f"Unexpected scan error: {type(error).__name__}: {error}"
        print("\nScan error:", report["scan_error"])

    calculate_summaries(report)                            # Count totals for the summary section
    reports_directory = Path("reports")                    # A folder named "reports" next to where you run the script
    try:
        reports_directory.mkdir(parents=True, exist_ok=True)   # Create folder; no error if it already exists
        html_path = choose_report_path(reports_directory)
        generate_html_report(report, html_path)
        print("\n--- Report ---")
        print("HTML report saved to:", html_path.resolve())    # .resolve() = full absolute path
        print("Open it in a browser. Use ‘Print / Save as PDF’ if you need a PDF copy.")
    except OSError as error:                               # File/folder problems (permissions, disk full...)
        print("Could not save the HTML report:", error)

# This special check means: "only run main() if this file is run directly"
# (e.g. `python webguard.py`). If another file imports this one, main() will
# NOT run automatically. `__name__` is "__main__" only when run directly.
if __name__ == "__main__":
    main()
