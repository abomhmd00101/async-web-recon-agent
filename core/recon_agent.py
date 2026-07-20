import asyncio
import httpx
from core.tool_manager import ToolManager


class ReconAgent:


    def __init__(self, tools):
        self.manager = ToolManager(tools)

    async def scan_target(self, target):

        # Create a dedicated HTTP session for this target.
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:

            results = await self.manager.run_target(target,client)
            return results


    async def run(self, targets):
        tasks = []

        for target in targets:

            tasks.append(self.scan_target(target))

        # Run all configured targets concurrently.
        results = await asyncio.gather(*tasks)

        return dict(zip(targets, results))
