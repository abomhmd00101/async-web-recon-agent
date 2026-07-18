# Ai_Recone_agent_v2.0

> **Status: Work in Progress** — this project is an educational reconnaissance prototype, not a production vulnerability scanner.

Ai_Recone_agent_v2.0 is a modular asynchronous Python project that runs lightweight web reconnaissance checks across multiple targets. It demonstrates plugin registration, shared HTTP responses, concurrent target processing, response inspection, and structured scanner results.

The project preserves all scanners from the original single-file implementation while separating orchestration from passive and active request logic.

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

Scanners that issue an independent request:

- `SitemapScanner`
- `RobotsScanner`
- `CORSScanner`

## Requirements

- Python 3.10 or newer
- `httpx`
- `beautifulsoup4`

Install the Python dependencies from `requirements.txt`.

## Installation

```bash
python -m venv .venv
```

Activate the virtual environment, then run:

```bash
python -m pip install -r requirements.txt
```

## Usage

Edit the `targets` list in `main.py` so it contains only systems you own or are explicitly authorized to assess. Then run:

```bash
python main.py
```

Each target is scanned concurrently. The program prints every scanner result followed by the total execution time.

## Project structure

```text
Ai_Recone_agent_v2.0/
├── main.py
├── core/
│   ├── __init__.py
│   ├── base_scanner.py
│   ├── tool_manager.py
│   └── recon_agent.py
├── scanners/
│   ├── __init__.py
│   ├── passive.py
│   └── active.py
├── output/
│   └── .gitkeep
├── README.md
├── requirements.txt
└── .gitignore
```

Importing the `scanners` package loads both scanner modules. Each scanner class is then registered automatically in `BaseScanner.plugins` through `BaseScanner.__init_subclass__()`.

## Responsible use

Run this project only against local labs, CTF environments, systems you own, or targets for which you have clear written authorization. Do not scan third-party systems without permission. Scanner output is observational and requires manual review before drawing security conclusions.
