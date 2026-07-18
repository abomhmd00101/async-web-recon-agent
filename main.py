import asyncio
import time

import scanners  # noqa: F401 - importing the package registers every scanner plugin.
from core.base_scanner import BaseScanner
from core.recon_agent import ReconAgent


targets = [
    "https://exaple1.com",
    "https://exaple2.com",
]


async def main():
    start_time = time.time()

    plugins = [
        plugin_class()
        for plugin_class in BaseScanner.plugins
    ]

    agent = ReconAgent(plugins)
    results = await agent.run(targets)

    for target, data in results.items():
        print("=" * 50)
        print(target)

        for result in data:
            print(result)

    print("=" * 50)
    print(f"Finished in {time.time() - start_time:.2f} seconds")


if __name__ == "__main__":
    asyncio.run(main())
