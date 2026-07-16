import asyncio
import httpx
import time
from bs4 import BeautifulSoup

start_time = time.time()

targets = [
    "https://example.com",
    "https://example.com"
]


# =========================
# Base Tool
# =========================

class BaseScanner:

    plugins = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if not hasattr(cls, 'needs_base_response'):
            cls.needs_base_response = False

        BaseScanner.plugins.append(cls)

    async def scan(self, target, client, response, final_time):
        raise NotImplementedError


# =========================
# Tools
# =========================

class SecurityHeadersScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        missing = []
        present = []

        headers_to_check = ["Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"]

        for header in headers_to_check:
            if header in response.headers:
                present.append(header)
            else:
                missing.append(header)



        score = f"{len(present)} / {len(headers_to_check)}"

        return {
            "tool": "SecurityHeadersScanner",
            "target": target,
            "present": present,
            "missing": missing,
            "score": score,
            "final_time": final_time
        }



class SitemapScanner(BaseScanner):

    async def scan(self, target, client, response, final_time):
        start_time = time.time()
        try :
            sitemap_url = target.rstrip("/") + "/sitemap.xml"
            response = await client.get(sitemap_url)
            final_time = time.time() - start_time

            return {
                "tool": "SitemapScanner",
                "target": target,
                "url": sitemap_url,
                "status": response.status_code,
                "response_text": response.text[:300],
                "time": final_time
            }
        except httpx.RequestError:
            return {
            "tool": "SitemapScanner",
            "target": target,
            "status": "failed",
            "error": "Request error"
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
                "time": final_time
            }
        except httpx.RequestError:
            return {
            "tool": "RobotsScanner",
            "target": target,
            "status": "failed",
            "error": "Request error"
        }



class HTTPScanner(BaseScanner):

    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        # start_time = time.time()
        print(f"[HTTP] Scanning {target}")
        # response = await client.get(target)
        # final_time = time.time() - start_time


        return {
            "tool": "HTTP",
            "target": target,
            "status": response.status_code,
            "server": response.headers.get("Server"),
            "time": final_time
        }



class HeaderScanner(BaseScanner):

    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        # start_time = time.time()
        print(f"[HEADER] Scanning {target}")
        # response = await client.get(target)
        # final_time = time.time() - start_time

        return {
            "tool": "HeaderScanner",
            "target": target,
            "server": response.headers.get("server"),
            "content-type": response.headers.get("content-type"),
            "time": final_time
        }



class TitleScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):

        soup = BeautifulSoup(response.text, 'html.parser')


        if soup.title:
            title = soup.title.string
        else:
            title = None

        return {
            "tool": "TitleScanner",
            "target": target,
            "title": title,
            "time": final_time
        }



class CookieScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        cookies_headers = response.headers.get_list('set-cookie')

        cookies_list = []
        for cookie_string in cookies_headers:
            c_lower = cookie_string.lower()

            samesite_val = None
            if "samesite=" in c_lower:
                parts = cookie_string.split(";")
                for part in parts:
                    if "samesite=" in part.lower():
                        samesite_val = part.split("=")[1].strip()

            cookies_list.append({
                "raw": cookie_string,
                "secure": "secure" in c_lower,
                "httponly": "httponly" in c_lower,
                "samesite": samesite_val
            })

        return {
            "tool": "CookieScanner",
            "target": target,
            "cookies": cookies_list,
            "count": len(cookies_list),
            "final_time": final_time
        }



class TechnologyScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        technologies = set()

        server_header = response.headers.get("server", "").lower()
        powered_by = response.headers.get("x-powered-by", "").lower()

        # Headers detection
        if "php" in powered_by:
            technologies.add("PHP")

        if "asp.net" in powered_by:
            technologies.add("ASP.NET")

        if "nginx" in server_header:
            technologies.add("Nginx")

        if "apache" in server_header:
            technologies.add("Apache")

        if "iis" in server_header:
            technologies.add("Microsoft IIS")

        # HTML parsing
        soup = BeautifulSoup(response.text, "html.parser")

        generator = soup.find("meta", attrs={"name": "generator"})
        if generator:
            generator_content = generator.get("content")
            if generator_content:
                technologies.add(generator_content.strip())

        # Script sources are more reliable than searching all page text
        script_sources = [
            script.get("src", "").lower()
            for script in soup.find_all("script")
            if script.get("src")
        ]

        combined_scripts = " ".join(script_sources)
        html_lower = response.text.lower()

        if "jquery" in combined_scripts:
            technologies.add("jQuery")

        if "react" in combined_scripts:
            technologies.add("React")

        if "/_next/static/" in html_lower or "__next_data__" in html_lower:
            technologies.add("Next.js")

        if "wp-content" in html_lower or "wp-includes" in html_lower:
            technologies.add("WordPress")

        if "laravel" in html_lower:
            technologies.add("Laravel")

        return {
            "tool": "TechnologyScanner",
            "target": target,
            "technologies": sorted(technologies),
            "count": len(technologies),
            "time": final_time
        }



class CORSScanner(BaseScanner):
    needs_base_response = False

    async def scan(self, target, client, response, final_time):
        try :

            test_origin = "https://evil.com"

            custom_headers = {
                "Origin": test_origin,
                "Access-Control-Request-Method": "GET"
            }


            start_timee = time.time()
            response = await client.options(target, headers=custom_headers)
            final_time = time.time() - start_timee

            origin = response.headers.get("access-control-allow-origin")
            creds = response.headers.get("access-control-allow-credentials")

            potential_issue = False
            # الوصول المباشر للـ CORS headers
            cors_headers = {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": creds,
                "Access-Control-Allow-Methods": response.headers.get("access-control-allow-methods"),
                "Access-Control-Allow-Headers": response.headers.get("access-control-allow-headers")
            }

            if origin == test_origin and creds and creds.lower() == "true":
                potential_issue = True

            return {
                "tool": "CORSScanner",
                "target": target,
                "CORS_Headers": cors_headers,
                "potential_issue": potential_issue,
                "time": final_time,
                "method": response.request.method
            }
        except httpx.RequestError:
            return {
                "tool": "CORSScanner",
                "target": target,
                "problem": None
            }








# =========================
# Tool Manager
# =========================

class ToolManager:

    def __init__(self, tools):
        self.tools = tools


    async def run_target(self, target, client):


        try:
            tasks1 = []     # Httpscanner , headerscanner
            tasks2 = []     # sitemapscanner , robotsscanner

            start_time = time.time()
            response = await client.get(target)
            final_time = time.time() - start_time

            for tool in self.tools:                 # هون راح نعدل على هاي اللوب
                status = tool.needs_base_response

                if status == True:
                    tasks1.append(tool.scan(target,client, response, final_time))

                elif status == False:
                    tasks2.append(tool.scan(target, client, response=None, final_time=None))


            results1 = await asyncio.gather(*tasks1)
            results2 = await asyncio.gather(*tasks2)



            return results1 + results2


        except httpx.RequestError:

            return {
                "target": target,
                "error": "Connection Failed"
            }


#################################################################################################
# Recon Agent
# =========================

class ReconAgent:


    def __init__(self, tools):
        self.manager = ToolManager(tools)

    async def scan_target(self, target):

        # Session خاصة بهذا الهدف
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:

            results = await self.manager.run_target(target,client)
            return results


    async def run(self, targets):
        tasks = []

        for target in targets:

            tasks.append(self.scan_target(target))

        # كل Targets تعمل مع بعض
        results = await asyncio.gather(*tasks)

        return dict(zip(targets, results))





###################################################################################
# Main
# =========================

async def main():
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


asyncio.run(main())





