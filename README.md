# WebVulnScanner

WebVulnScanner is a powerful, user-friendly, and highly customizable security tool designed for ethical hackers, penetration testers, and web developers. It helps identify, assess, and report vulnerabilities in web applications, ensuring enhanced security and compliance with industry standards. Whether you are a seasoned security professional or a developer aiming to secure your application, this tool offers a seamless way to discover security loopholes.


Installation:

Clone the repository and install dependencies using:

git clone https://github.com/Ankur-Pentester/WebVulnScanner.git 

cd WebVulnScanner  

pip3 install -r requirements.txt  


How to Use:

python3 WebVulnScanner.py --help       <---  TO  SEE ALL OPTIONS OF THIS TOOL.

1. Scan for XSS vulnerabilities:
   python3 WebVulnScanner.py -u https://example.com --xss -w /path/to/xss.txt

2. Perform directory enumeration:
   python3 WebVulnScanner.py -u https://example.com -w /path/to/wordlist.txt

3. SQL Injection testing:
   python3 WebVulnScanner.py -u https://example.com --sqli -w /path/to/sqli.txt
  
4. Port scanning:
   python3 WebVulnScanner.py -i 192.168.1.1 --ports
