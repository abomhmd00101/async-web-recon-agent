import asyncio
import time
from datetime import datetime

import scanners  # noqa: F401 - importing scanners registers every plugin.
from __init__ import __version__
from core.base_scanner import BaseScanner
from core.recon_agent import ReconAgent
from reporting.json_reporter import JSONReporter


targets = ["https://officemaxpal.com"]


async def main():
    start_time = time.time()

    plugins = [
        plugin_class()
        for plugin_class in BaseScanner.plugins
    ]

    agent = ReconAgent(plugins)

    results = await agent.run(targets)

    final_time = time.time() - start_time

    reports = JSONReporter()

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


    for target, data in results.items():
        report_data = {
            "project": "Ai_Recone_agent_v3.0",
            "project_version": __version__,
            "report_schema": "ai-recon-report",
            "report_schema_version": "1.0",
            "analysis_ready": True,
            "analysis_status": "pending",
            "target": target,
            "scanned_at": timestamp,
            "duration_seconds": round(final_time, 2),
            "scanner_count": len(data),
            "results": data,
        }

        final_path = reports.save(target, f"recon_{timestamp}.json", report_data)

        print("=" * 50)
        print("=" * 50)
        print(f"[+] Target: {target}")
        print(f"[+] Scanners completed: {len(data)}")
        print(f"[+] Report saved at: {final_path}")
    print("=" * 50)
    print(f"Finished in {final_time:.2f} seconds")


if __name__ == "__main__":
    asyncio.run(main())
