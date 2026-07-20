# Ai_Recone_agent_v3.0

> **Version 3.0.0 — Work in Progress**

Ai_Recone_agent_v3.0 is a modular asynchronous web reconnaissance tool for authorized security assessments, local labs, and CTF environments. It runs twelve lightweight scanners, shares the main HTTP response where possible, performs independent checks concurrently, and now saves structured JSON reports for later automated or AI-assisted analysis.

## What is new in v3.0

- Persistent JSON reports organized by target and timestamp
- A stable top-level report schema with project and version metadata
- `analysis_ready` and `analysis_status` fields for future AI pipelines
- A dedicated `reporting` package for JSON serialization
- An `analysis` package reserved for future finding classification
- Safer Git ignore rules that keep generated reports and local backup code out of GitHub
- Connection failures returned in a consistent list-based result structure

AI analysis is not implemented yet. Version 3.0 prepares reliable, machine-readable input so a later analyzer can classify findings, assign confidence, correlate evidence, and produce reviewable summaries without changing the scanners.

## Current scanners

Scanners that reuse the target's base response:

- `SecurityHeadersScanner`
- `HTTPScanner`
- `HeaderScanner`
- `TitleScanner`
- `CookieScanner`
- `TechnologyScanner`
- `RedirectScanner`
- `LinkScanner`
- `FormScanner`

Scanners that issue independent requests:

- `SitemapScanner`
- `RobotsScanner`
- `CORSScanner`

## JSON report format

Each run creates a report under:

```text
output/<target>/recon_<timestamp>.json
```

The top-level structure is:

```json
{
  "project": "Ai_Recone_agent_v3.0",
  "project_version": "3.0.0",
  "report_schema": "ai-recon-report",
  "report_schema_version": "1.0",
  "analysis_ready": true,
  "analysis_status": "pending",
  "target": "https://authorized.example",
  "scanned_at": "2026-07-20_20-00-00",
  "duration_seconds": 1.25,
  "scanner_count": 12,
  "results": []
}
```

Generated reports are ignored by Git because they may contain target-specific URLs, headers, cookies, form details, or other response evidence. Review and sanitize a report before sharing it.

## Requirements

- Python 3.10 or newer
- `httpx`
- `beautifulsoup4`

## Installation

```bash
python -m venv .venv
```

Activate the virtual environment and install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

Edit the `targets` list in `main.py` so it contains only systems you own or are explicitly authorized to assess. Then run:

```bash
python main.py
```

The console prints a summary for each target and the saved JSON report path.

## Project structure

```text
Ai_Recone_agent_v3.0/
├── main.py
├── core/
│   ├── base_scanner.py
│   ├── tool_manager.py
│   └── recon_agent.py
├── scanners/
│   ├── passive.py
│   └── active.py
├── reporting/
│   └── json_reporter.py
├── analysis/
│   └── finding_analyzer.py
├── output/
│   └── .gitkeep
├── requirements.txt
├── README.md
└── .gitignore
```

Importing `scanners` registers every scanner class in `BaseScanner.plugins`. `ReconAgent` creates an asynchronous client per target, while `ToolManager` separates shared-response scanners from scanners that issue their own requests.

## Roadmap

- Implement evidence-based finding normalization in `FindingAnalyzer`
- Add AI-assisted analysis over the versioned JSON schema
- Add confidence scores and human-review requirements
- Add tests, scope controls, configurable concurrency, and rate limits
- Add optional HTML or Markdown reporting generated from reviewed findings

## Responsible use

Run this project only against local labs, CTF environments, systems you own, or targets for which you have explicit written authorization. Do not scan third-party systems without permission. Scanner observations require manual verification before they are treated as security findings.
