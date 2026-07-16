# Async Web Recon Agent

> **Status: Work in Progress** — this is an educational prototype under active development, not a production vulnerability scanner.

Async Web Recon Agent is a modular Python project that runs lightweight web reconnaissance checks concurrently against explicitly authorized targets. It started as an exercise in combining object-oriented design, `asyncio`, `httpx`, and HTML parsing inside a practical security tool.

## What it currently checks

- HTTP status, final URL, server header, content type, and response time
- Common defensive response headers
- Page title and basic technology indicators
- Cookie attributes such as `Secure`, `HttpOnly`, and `SameSite`
- `robots.txt` and `sitemap.xml`
- A limited CORS preflight observation

The scanner plugin system registers each `BaseScanner` subclass automatically. Scanners that need the main page share one base response, while independent checks run their own requests. Targets are also processed concurrently.

## Installation

```bash
python -m venv .venv
```

Activate the environment, then install the dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

Run the agent only against systems you own or are explicitly authorized to assess:

```bash
python recon_agent.py http://127.0.0.1:8000
```

Scan multiple authorized targets and save a JSON report:

```bash
python recon_agent.py https://lab-one.example https://lab-two.example --output report.json
```

Options:

```text
--timeout SECONDS   Per-request timeout (default: 10)
--output PATH       Save the JSON report to a file
```

## Architecture

```text
ReconAgent
└── ToolManager
    ├── Shared base-response scanners
    │   ├── HTTPScanner
    │   ├── HeaderScanner
    │   ├── SecurityHeadersScanner
    │   ├── TitleScanner
    │   ├── CookieScanner
    │   └── TechnologyScanner
    └── Independent-request scanners
        ├── RobotsScanner
        ├── SitemapScanner
        └── CORSScanner
```

## Why it is still a work in progress

The current implementation provides observations, not verified vulnerability findings. Header absence, technology fingerprints, and CORS responses require context and manual review before any security conclusion is made.

Planned work:

- Add automated tests and local mock targets
- Add explicit scope files and stronger target controls
- Add rate limiting, retry policy, and concurrency configuration
- Improve technology fingerprint confidence and evidence fields
- Add structured logging and a versioned result schema
- Package the project as an installable command-line tool

## Responsible use

This project is intended for learning, local labs, CTF environments, and authorized security assessments. Do not scan third-party systems without clear permission. The author is not responsible for misuse.
