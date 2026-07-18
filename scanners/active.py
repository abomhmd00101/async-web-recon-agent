import time

import httpx

from core.base_scanner import BaseScanner


class SitemapScanner(BaseScanner):
    async def scan(self, target, client, response, final_time):
        start_time = time.time()
        try:
            sitemap_url = target.rstrip("/") + "/sitemap.xml"
            response = await client.get(sitemap_url)
            final_time = time.time() - start_time

            return {
                "tool": "SitemapScanner",
                "target": target,
                "url": sitemap_url,
                "status": response.status_code,
                "response_text": response.text[:300],
                "time": final_time,
            }
        except httpx.RequestError:
            return {
                "tool": "SitemapScanner",
                "target": target,
                "status": "failed",
                "error": "Request error",
            }


class RobotsScanner(BaseScanner):
    async def scan(self, target, client, response, final_time):
        start_time = time.time()
        try:
            response = await client.get(target.rstrip("/") + "/robots.txt")
            final_time = time.time() - start_time

            return {
                "tool": "RobotsScanner",
                "target": target,
                "status": response.status_code,
                "server": response.headers.get("Server"),
                "response_text": response.text[:300],
                "time": final_time,
            }
        except httpx.RequestError:
            return {
                "tool": "RobotsScanner",
                "target": target,
                "status": "failed",
                "error": "Request error",
            }


class CORSScanner(BaseScanner):
    needs_base_response = False

    async def scan(self, target, client, response, final_time):
        try:
            test_origin = "https://evil.com"

            custom_headers = {
                "Origin": test_origin,
                "Access-Control-Request-Method": "GET",
            }

            start_time = time.time()
            response = await client.options(target, headers=custom_headers)
            final_time = time.time() - start_time

            origin = response.headers.get("access-control-allow-origin")
            creds = response.headers.get("access-control-allow-credentials")

            potential_issue = False
            cors_headers = {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": creds,
                "Access-Control-Allow-Methods": response.headers.get(
                    "access-control-allow-methods"
                ),
                "Access-Control-Allow-Headers": response.headers.get(
                    "access-control-allow-headers"
                ),
            }

            if origin == test_origin and creds and creds.lower() == "true":
                potential_issue = True

            return {
                "tool": "CORSScanner",
                "target": target,
                "CORS_Headers": cors_headers,
                "potential_issue": potential_issue,
                "time": final_time,
                "method": response.request.method,
            }
        except httpx.RequestError:
            return {
                "tool": "CORSScanner",
                "target": target,
                "problem": None,
            }
