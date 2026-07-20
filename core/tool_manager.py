import asyncio
import time
import httpx


class ToolManager:

    def __init__(self, tools):
        self.tools = tools


    async def run_target(self, target, client):

        try:
            base_response_tasks = []
            independent_tasks = []

            start_time = time.time()
            response = await client.get(target)
            final_time = time.time() - start_time

            for tool in self.tools:
                if tool.needs_base_response:
                    base_response_tasks.append(tool.scan(target,client,response,final_time))
                else:
                    independent_tasks.append(tool.scan(target,client,response=None,final_time=None))

            base_results = await asyncio.gather(*base_response_tasks)
            independent_results = await asyncio.gather(*independent_tasks)

            return base_results + independent_results



        except httpx.RequestError as error:

            return [{

                "target": target,

                "error": "Connection Failed",

                "details": str(error)

            }]