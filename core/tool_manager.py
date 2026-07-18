import asyncio
import time

import httpx


class ToolManager:
    """Run registered scanners while sharing the target's base response."""

    def __init__(self, tools):
        self.tools = tools

    async def run_target(self, target, client):
        try:
            tasks1 = []
            tasks2 = []

            start_time = time.time()
            response = await client.get(target)
            final_time = time.time() - start_time

            for tool in self.tools:
                status = tool.needs_base_response

                if status is True:
                    tasks1.append(tool.scan(target, client, response, final_time))
                elif status is False:
                    tasks2.append(
                        tool.scan(
                            target,
                            client,
                            response=None,
                            final_time=None,
                        )
                    )

            results1 = await asyncio.gather(*tasks1)
            results2 = await asyncio.gather(*tasks2)

            return results1 + results2

        except httpx.RequestError:
            return [{
                "target": target,
                "error": "Connection Failed",
            }]
