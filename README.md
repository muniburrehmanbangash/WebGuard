# WebGuard

WebGuard is a command-line tool for reviewing selected HTTP security settings on a website. It produces an HTML report with findings, evidence, and recommended actions. The report can be printed or saved as a PDF from your browser.

## Checks

- Common HTTP security headers, including Content-Security-Policy and Strict-Transport-Security.
- Cookie attributes visible in the responses examined by the scanner.
- A limited HTTPS comparison request when applicable.
- Findings with severity labels, evidence, and recommendations.

WebGuard is a lightweight configuration review, not a full penetration test. A missing header is not automatically a vulnerability, and a clean report does not prove that a site is secure. Only scan websites you own or have permission to assess.

## Requirements

- Python 3.10 or newer
- `requests`

## Installation

```bash
git clone YOUR_REPOSITORY_URL
cd WebGuard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Replace `YOUR_REPOSITORY_URL` with your GitHub repository URL.

## Run WebGuard

```bash
python webguard.py
```

Enter the website URL when prompted. Each scan creates one HTML report in `reports/`, named `scan_Report_01.html`, `scan_Report_02.html`, and so on. Existing reports are not overwritten.

Open the report in a browser. Use **Print / Save as PDF** to save a PDF copy if needed. The current release creates HTML reports only; it does not create a separate JSON report.

## Version history

The current entry point is `webguard.py` (WebGuard 3.0). Archived source snapshots are available in `versions/`:

- `webguard_v1.py` — initial scanner source.
- `webguard_v2.py` — version with HTML and JSON reports.
- `webguard_v3_original.py` — original WebGuard 3.0 source before the single-report adjustment.

The archived files are provided for reference; run the root-level `webguard.py` for the current version. These files do not recreate the original Git commit history. Create historical Git tags only if you have the matching original commits; otherwise, tag the current code as `v3.0.0` and document the archived snapshots in the release notes.

## Reports and privacy

Generated reports are excluded from version control by `.gitignore`. Review a report before sharing it because it may contain the target URL, response headers, and other technical details.

## Limitations

WebGuard makes ordinary HTTP requests and performs a limited set of non-destructive checks. It does not submit attack payloads, test authenticated workflows, or determine whether a finding is exploitable. Interpret results in the context of the application and its deployment.
