import asyncio

import httpx

from core.tool_manager import ToolManager


class ReconAgent:
    """Coordinate concurrent scans across all configured targets."""

    def __init__(self, tools):
        self.manager = ToolManager(tools)

    async def scan_target(self, target):
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            results = await self.manager.run_target(target, client)
            return results

    async def run(self, targets):
        tasks = []

        for target in targets:
            tasks.append(self.scan_target(target))

        results = await asyncio.gather(*tasks)
        return dict(zip(targets, results))
