# WebVulnScanner

WebVulnScanner is a powerful, user-friendly, and highly customizable security tool designed for ethical hackers, penetration testers, and web developers. It helps identify, assess, and report vulnerabilities in web applications, ensuring enhanced security and compliance with industry standards. Whether you are a seasoned security professional or a developer aiming to secure your application, this tool offers a seamless way to discover security loopholes.
Key Features:

    Directory Enumeration: Efficiently scans for hidden directories using custom wordlists to identify sensitive endpoints.
    XSS Vulnerability Detection: Detects Cross-Site Scripting (XSS) vulnerabilities using both built-in and user-provided payload lists.
    SQL Injection Testing: Identifies potential SQL injection points using robust payload testing methods.
    Port Scanning: Performs comprehensive port scans on target IPs to discover open and potentially vulnerable ports.
    Custom Payload Support: Allows users to test custom payloads for XSS and SQL injection attacks via text file inputs.
    Multi-threaded Scanning: Achieves faster scan times for larger applications by leveraging asynchronous requests.
    Detailed Reports: Generates vulnerability reports in JSON and HTML formats for easier documentation and tracking.
    Why Choose WebVulnScanner?

Unlike traditional security scanners, WebVulnScanner empowers users with the flexibility to provide custom payloads, ensuring more tailored and thorough security testing. With its efficient directory enumeration, real-time XSS and SQLi scanning, and comprehensive port discovery features, it provides everything required for a full-scale web application security audit.
How to Use:

    Scan for XSS vulnerabilities:

python3 web_tool.py -u https://example.com --xss -w /path/to/xss.txt

Perform directory enumeration:

python3 web_tool.py -u https://example.com -w /path/to/wordlist.txt

SQL Injection testing:

python3 web_tool.py -u https://example.com --sqli -w /path/to/sqli.txt

Port scanning:

    python3 web_tool.py -i 192.168.1.1 --ports

Installation:

Clone the repository and install dependencies using:

git clone https://github.com/your-username/WebVulnScanner.git  
cd WebVulnScanner  
pip3 install -r requirements.txt  

This tool helps organizations and individual developers protect their applications from common web vulnerabilities, fostering secure development practices.
