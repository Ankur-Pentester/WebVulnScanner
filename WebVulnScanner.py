import argparse
import aiohttp
import asyncio
import nmap
import json
import os

# Banner
print("====================================")
print("   Web Application Security Scanner   ")
print("====================================")

class WebAppSecurityScanner:
    def __init__(self, target_url=None, target_ip=None):
        self.target_url = target_url.rstrip('/') if target_url else None
        self.target_ip = target_ip
        self.report = []

    def read_payloads(self, wordlist_path):
        """ Read payloads from a file """
        try:
            with open(wordlist_path, "r") as file:
                payloads = file.read().splitlines()
            return payloads
        except Exception as e:
            print(f"[ERROR] Could not read file {wordlist_path}: {e}")
            return []

    async def fetch(self, session, url):
        """ Make asynchronous HTTP GET requests """
        try:
            async with session.get(url) as response:
                return await response.text()
        except Exception as e:
            print(f"[ERROR] Request failed for {url}: {e}")
            return None

    async def xss_scan(self, session, wordlist_path):
        if not self.target_url:
            print("[ERROR] URL is required for XSS scanning.")
            return
        print("\n[INFO] Starting XSS Vulnerability Testing...")
        payloads = self.read_payloads(wordlist_path)
        if not payloads:
            print("[ERROR] No payloads found in the provided file.")
            return

        tasks = []
        for payload in payloads:
            # Assuming the input parameter for XSS is 'input'
            url = f"{self.target_url}?input={payload}"
            task = asyncio.create_task(self.fetch(session, url))
            tasks.append((task, payload))

        responses = await asyncio.gather(*[task for task, _ in tasks])

        for response, payload in zip(responses, payloads):
            if response and payload in response:
                print(f"[+] XSS Found with payload: {payload}")
                self.report.append({"XSS Found with payload": payload})

    async def sqli_scan(self, session, wordlist_path):
        if not self.target_url:
            print("[ERROR] URL is required for SQL Injection scanning.")
            return
        print("\n[INFO] Starting SQL Injection Testing...")
        payloads = self.read_payloads(wordlist_path)
        if not payloads:
            print("[ERROR] No payloads found in the provided file.")
            return

        tasks = []
        for payload in payloads:
            # Assuming the input parameter for SQLi is 'id'
            url = f"{self.target_url}?id={payload}"
            task = asyncio.create_task(self.fetch(session, url))
            tasks.append((task, payload))

        responses = await asyncio.gather(*[task for task, _ in tasks])

        for response, payload in zip(responses, payloads):
            if response and "database error" in response or "500" in response:
                print(f"[+] SQL Injection Found with payload: {payload}")
                self.report.append({"SQL Injection Found with payload": payload})

    async def port_scan(self):
        if not self.target_ip:
            print("[ERROR] IP address is required for port scanning.")
            return
        print("\n[INFO] Starting Port Scanning...")
        try:
            scanner = nmap.PortScanner()
            scanner.scan(self.target_ip, '1-1024')
            open_ports = []
            for host in scanner.all_hosts():
                for port in scanner[host]['tcp']:
                    if scanner[host]['tcp'][port]['state'] == 'open':
                        print(f"[+] Open Port Found: {port}")
                        open_ports.append(port)
            self.report.append({"Open Ports": open_ports})
        except Exception as e:
            print(f"[ERROR] {e}")

    def save_report(self):
        print("\n[INFO] Saving Report...")
        try:
            if not os.path.exists("reports"):
                os.makedirs("reports")

            # Save as JSON if requested
            if args.json:
                report_path = f"reports/scan_report.json"
                with open(report_path, "w") as report_file:
                    json.dump(self.report, report_file, indent=4)
                print(f"[SUCCESS] Report saved at {report_path}")

            # Save as HTML if requested
            if args.html:
                report_path_html = f"reports/scan_report.html"
                with open(report_path_html, "w") as report_file_html:
                    report_file_html.write("<html><head><title>Scan Report</title></head><body>")
                    report_file_html.write("<h1>Web Application Security Scanner Report</h1>")
                    report_file_html.write("<h2>Results:</h2><ul>")

                    for entry in self.report:
                        for key, value in entry.items():
                            report_file_html.write(f"<li><strong>{key}</strong>: {value}</li>")
                    
                    report_file_html.write("</ul></body></html>")
                print(f"[SUCCESS] Report saved as HTML at {report_path_html}")
        except Exception as e:
            print(f"[ERROR] {e}")

    async def run_scan(self):
        async with aiohttp.ClientSession() as session:
            if args.xss:
                await self.xss_scan(session, args.wordlist)
            if args.sqli:
                await self.sqli_scan(session, args.wordlist)
            if args.ports:
                await self.port_scan()
            if args.json or args.html:
                self.save_report()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Web Application Security Scanner")

    parser.add_argument("-u", "--url", help="Target URL for the scan (e.g., https://example.com)")
    parser.add_argument("-i", "--ip", help="Target IP address for port scanning (e.g., 192.168.1.1)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file for XSS and SQLi scan")
    parser.add_argument("--xss", action="store_true", help="Enable XSS scanning")
    parser.add_argument("--sqli", action="store_true", help="Enable SQL Injection scanning")
    parser.add_argument("--ports", action="store_true", help="Enable port scanning")
    parser.add_argument("--html", action="store_true", help="Save report as HTML")
    parser.add_argument("--json", action="store_true", help="Save report as JSON")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()

    # Check if at least one of URL or IP is provided
    if not (args.url or args.ip):
        print("[ERROR] Please provide either a URL or an IP address for the scan.")
    else:
        scanner = WebAppSecurityScanner(target_url=args.url, target_ip=args.ip)
        asyncio.run(scanner.run_scan())
