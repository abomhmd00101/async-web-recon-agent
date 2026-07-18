from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.base_scanner import BaseScanner


class SecurityHeadersScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        missing = []
        present = []

        headers_to_check = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

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
            "final_time": final_time,
        }


class HTTPScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        print(f"[HTTP] Scanning {target}")

        return {
            "tool": "HTTP",
            "target": target,
            "status": response.status_code,
            "server": response.headers.get("Server"),
            "time": final_time,
        }


class HeaderScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        print(f"[HEADER] Scanning {target}")

        return {
            "tool": "HeaderScanner",
            "target": target,
            "server": response.headers.get("server"),
            "content-type": response.headers.get("content-type"),
            "time": final_time,
        }


class TitleScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        soup = BeautifulSoup(response.text, "html.parser")

        if soup.title:
            title = soup.title.string
        else:
            title = None

        return {
            "tool": "TitleScanner",
            "target": target,
            "title": title,
            "time": final_time,
        }


class CookieScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        cookies_headers = response.headers.get_list("set-cookie")

        cookies_list = []
        for cookie_string in cookies_headers:
            c_lower = cookie_string.lower()

            samesite_val = None
            if "samesite=" in c_lower:
                parts = cookie_string.split(";")
                for part in parts:
                    if "samesite=" in part.lower():
                        samesite_val = part.split("=")[1].strip()

            cookies_list.append(
                {
                    "raw": cookie_string,
                    "secure": "secure" in c_lower,
                    "httponly": "httponly" in c_lower,
                    "samesite": samesite_val,
                }
            )

        return {
            "tool": "CookieScanner",
            "target": target,
            "cookies": cookies_list,
            "count": len(cookies_list),
            "final_time": final_time,
        }


class TechnologyScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        technologies = set()

        server_header = response.headers.get("server", "").lower()
        powered_by = response.headers.get("x-powered-by", "").lower()

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

        soup = BeautifulSoup(response.text, "html.parser")

        generator = soup.find("meta", attrs={"name": "generator"})
        if generator:
            generator_content = generator.get("content")
            if generator_content:
                technologies.add(generator_content.strip())

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
            "time": final_time,
        }


class RedirectScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        final_results = []

        for old_response in response.history:
            final_results.append(
                {
                    "status": old_response.status_code,
                    "url": str(old_response.url),
                    "location": old_response.headers.get("location"),
                }
            )

        return {
            "tool": "RedirectScanner",
            "target": target,
            "redirected": len(response.history) > 0,
            "redirect_count": len(final_results),
            "redirect_chain": final_results,
            "final_url": str(response.url),
            "final_status": response.status_code,
            "time": final_time,
        }


class LinkScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        base_domain = urlparse(target).netloc
        soup = BeautifulSoup(response.text, "html.parser")

        resolved_relative_links = set()
        internal_links = set()
        external_links = set()

        for a_tag in soup.find_all("a", href=True):
            raw_link = a_tag.get("href")

            if not raw_link:
                continue

            raw_link = raw_link.strip()

            if raw_link.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue

            parsed_link = urlparse(raw_link)

            if not parsed_link.netloc:
                full_url = urljoin(target, raw_link)
                resolved_relative_links.add(full_url)
            elif parsed_link.netloc == base_domain:
                internal_links.add(raw_link)
            else:
                external_links.add(raw_link)

        internal_count = len(internal_links)
        external_count = len(external_links)
        relative_count = len(resolved_relative_links)

        return {
            "tool": "LinkScanner",
            "target": target,
            "internal_links": sorted(internal_links),
            "external_links": sorted(external_links),
            "resolved_relative_links": sorted(resolved_relative_links),
            "internal_count": internal_count,
            "external_count": external_count,
            "relative_count": relative_count,
            "total_count": internal_count + relative_count + external_count,
            "time": final_time,
        }


class FormScanner(BaseScanner):
    needs_base_response = True

    async def scan(self, target, client, response, final_time):
        soup = BeautifulSoup(response.text, "html.parser")

        extracted_forms = []

        get_forms_count = 0
        post_forms_count = 0
        password_forms_count = 0

        for form_tag in soup.find_all("form"):
            method = (form_tag.get("method") or "GET").upper()
            action = (form_tag.get("action") or "").strip()

            resolved_action = urljoin(str(response.url), action)

            form_inputs = []
            has_password = False

            for input_tag in form_tag.find_all("input"):
                name = input_tag.get("name")
                input_type = (input_tag.get("type") or "text").lower()
                is_required = "required" in input_tag.attrs

                if input_type == "password":
                    has_password = True

                form_inputs.append(
                    {
                        "name": name,
                        "type": input_type,
                        "required": is_required,
                    }
                )

            if method == "GET":
                get_forms_count += 1

            if method == "POST":
                post_forms_count += 1

            if has_password:
                password_forms_count += 1

            extracted_forms.append(
                {
                    "method": method,
                    "action": action,
                    "resolved_action": resolved_action,
                    "inputs": form_inputs,
                }
            )

        return {
            "tool": "FormScanner",
            "target": target,
            "forms": extracted_forms,
            "form_count": len(extracted_forms),
            "get_forms": get_forms_count,
            "post_forms": post_forms_count,
            "password_forms": password_forms_count,
            "time": final_time,
        }
