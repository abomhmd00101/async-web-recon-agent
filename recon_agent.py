"""Modular asynchronous web reconnaissance for authorized targets."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup


class BaseScanner:
    """Base class that automatically registers scanner plugins."""

    plugins: list[type["BaseScanner"]] = []
    needs_base_response = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        BaseScanner.plugins.append(cls)

    async def scan(
        self,
        target: str,
        client: httpx.AsyncClient,
        response: httpx.Response | None,
        response_time: float | None,
    ) -> dict[str, Any]:
        raise NotImplementedError


class SecurityHeadersScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, response_time):
        headers_to_check = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        present = [header for header in headers_to_check if header in response.headers]
        missing = [header for header in headers_to_check if header not in response.headers]
        return {
            "tool": "SecurityHeadersScanner",
            "target": target,
            "present": present,
            "missing": missing,
            "score": f"{len(present)} / {len(headers_to_check)}",
            "time": response_time,
        }


class SitemapScanner(BaseScanner):
    async def scan(self, target, client, response, response_time):
        url = target.rstrip("/") + "/sitemap.xml"
        started = time.perf_counter()
        try:
            result = await client.get(url)
            return {
                "tool": "SitemapScanner",
                "target": target,
                "url": url,
                "status": result.status_code,
                "response_preview": result.text[:300],
                "time": time.perf_counter() - started,
            }
        except httpx.RequestError as error:
            return {
                "tool": "SitemapScanner",
                "target": target,
                "status": "failed",
                "error": type(error).__name__,
            }


class RobotsScanner(BaseScanner):
    async def scan(self, target, client, response, response_time):
        url = target.rstrip("/") + "/robots.txt"
        started = time.perf_counter()
        try:
            result = await client.get(url)
            return {
                "tool": "RobotsScanner",
                "target": target,
                "url": url,
                "status": result.status_code,
                "server": result.headers.get("server"),
                "response_preview": result.text[:300],
                "time": time.perf_counter() - started,
            }
        except httpx.RequestError as error:
            return {
                "tool": "RobotsScanner",
                "target": target,
                "status": "failed",
                "error": type(error).__name__,
            }


class HTTPScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, response_time):
        return {
            "tool": "HTTPScanner",
            "target": target,
            "status": response.status_code,
            "final_url": str(response.url),
            "server": response.headers.get("server"),
            "time": response_time,
        }


class HeaderScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, response_time):
        return {
            "tool": "HeaderScanner",
            "target": target,
            "server": response.headers.get("server"),
            "content_type": response.headers.get("content-type"),
            "content_length": response.headers.get("content-length"),
            "time": response_time,
        }


class TitleScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, response_time):
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else None
        return {
            "tool": "TitleScanner",
            "target": target,
            "title": title,
            "time": response_time,
        }


class CookieScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, response_time):
        cookies = []
        for cookie_string in response.headers.get_list("set-cookie"):
            attributes = [part.strip() for part in cookie_string.split(";")]
            lower_attributes = [part.lower() for part in attributes]
            same_site = next(
                (
                    part.split("=", 1)[1]
                    for part in attributes
                    if part.lower().startswith("samesite=")
                ),
                None,
            )
            cookies.append(
                {
                    "name": attributes[0].split("=", 1)[0],
                    "secure": "secure" in lower_attributes,
                    "httponly": "httponly" in lower_attributes,
                    "samesite": same_site,
                }
            )

        return {
            "tool": "CookieScanner",
            "target": target,
            "cookies": cookies,
            "count": len(cookies),
            "time": response_time,
        }


class TechnologyScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, response_time):
        technologies: set[str] = set()
        server_header = response.headers.get("server", "").lower()
        powered_by = response.headers.get("x-powered-by", "").lower()

        header_signatures = {
            "php": "PHP",
            "asp.net": "ASP.NET",
            "nginx": "Nginx",
            "apache": "Apache",
            "iis": "Microsoft IIS",
        }
        for signature, label in header_signatures.items():
            if signature in powered_by or signature in server_header:
                technologies.add(label)

        soup = BeautifulSoup(response.text, "html.parser")
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator and generator.get("content"):
            technologies.add(generator["content"].strip())

        scripts = " ".join(
            script.get("src", "").lower()
            for script in soup.find_all("script")
            if script.get("src")
        )
        html = response.text.lower()
        page_signatures = {
            "jquery": "jQuery",
            "react": "React",
            "/_next/static/": "Next.js",
            "wp-content": "WordPress",
            "laravel": "Laravel",
        }
        searchable = f"{scripts} {html}"
        for signature, label in page_signatures.items():
            if signature in searchable:
                technologies.add(label)

        return {
            "tool": "TechnologyScanner",
            "target": target,
            "technologies": sorted(technologies),
            "count": len(technologies),
            "time": response_time,
        }


class CORSScanner(BaseScanner):
    async def scan(self, target, client, response, response_time):
        test_origin = "https://scanner-test.example"
        headers = {
            "Origin": test_origin,
            "Access-Control-Request-Method": "GET",
        }
        started = time.perf_counter()
        try:
            result = await client.options(target, headers=headers)
            allowed_origin = result.headers.get("access-control-allow-origin")
            credentials = result.headers.get("access-control-allow-credentials")
            return {
                "tool": "CORSScanner",
                "target": target,
                "cors_headers": {
                    "allow_origin": allowed_origin,
                    "allow_credentials": credentials,
                    "allow_methods": result.headers.get("access-control-allow-methods"),
                    "allow_headers": result.headers.get("access-control-allow-headers"),
                },
                "potential_credentialed_origin_reflection": (
                    allowed_origin == test_origin
                    and bool(credentials)
                    and credentials.lower() == "true"
                ),
                "status": result.status_code,
                "time": time.perf_counter() - started,
            }
        except httpx.RequestError as error:
            return {
                "tool": "CORSScanner",
                "target": target,
                "status": "failed",
                "error": type(error).__name__,
            }


class ToolManager:
    def __init__(self, tools: list[BaseScanner]):
        self.tools = tools

    async def run_target(
        self, target: str, client: httpx.AsyncClient
    ) -> list[dict[str, Any]]:
        response = None
        response_time = None

        if any(tool.needs_base_response for tool in self.tools):
            started = time.perf_counter()
            try:
                response = await client.get(target)
                response_time = time.perf_counter() - started
            except httpx.RequestError as error:
                return [
                    {
                        "tool": "BaseRequest",
                        "target": target,
                        "status": "failed",
                        "error": type(error).__name__,
                    }
                ]

        tasks = [
            tool.scan(target, client, response, response_time)
            for tool in self.tools
            if response is not None or not tool.needs_base_response
        ]
        return await asyncio.gather(*tasks)


class ReconAgent:
    def __init__(self, tools: list[BaseScanner], timeout: float):
        self.manager = ToolManager(tools)
        self.timeout = timeout

    async def scan_target(self, target: str) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "Async-Web-Recon-Agent/0.1 (authorized testing only)"},
        ) as client:
            return await self.manager.run_target(target, client)

    async def run(self, targets: list[str]) -> dict[str, list[dict[str, Any]]]:
        results = await asyncio.gather(*(self.scan_target(target) for target in targets))
        return dict(zip(targets, results))


def valid_target(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError(
            "Targets must be complete HTTP(S) URLs, for example http://127.0.0.1:8000"
        )
    return value.rstrip("/")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run modular asynchronous web checks against authorized targets."
    )
    parser.add_argument("targets", nargs="+", type=valid_target)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--output", help="Optional path for the JSON report")
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    tools = [plugin() for plugin in BaseScanner.plugins]
    agent = ReconAgent(tools, timeout=args.timeout)

    started = time.perf_counter()
    results = await agent.run(args.targets)
    report = {
        "project": "Async Web Recon Agent",
        "status": "work-in-progress",
        "duration_seconds": round(time.perf_counter() - started, 3),
        "results": results,
    }
    output = json.dumps(report, indent=2, ensure_ascii=False)
    print(output)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as report_file:
            report_file.write(output + "\n")


if __name__ == "__main__":
    asyncio.run(main())
