import os
import re
import requests
import subprocess
import time
from colorama import Fore, Style, init
from bs4 import BeautifulSoup

# Global Values
init(autoreset=True)
subdomains = set()
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive"
}
version = "2.9"

def install_nmap():
    try:
        if subprocess.run("nmap --version", shell=True, capture_output=True, text=True).returncode == 0:
            print(f"{Fore.GREEN}[âœ”] Nmap is already installed.{Style.RESET_ALL}")
            return
        print(f"{Fore.YELLOW}[!] Nmap not found. Installing...{Style.RESET_ALL}")
        if os.name == "posix":
            os.system("sudo apt install nmap -y || sudo yum install nmap -y || brew install nmap")
        else:
            print(f"{Fore.RED}[!] Please install Nmap manually from https://nmap.org/download.html{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[X] Failed to check/install Nmap: {e}{Style.RESET_ALL}")

def run_nmap(subdomain):
    print(f"{Fore.BLUE}[*] Running Nmap scan on {subdomain}...{Style.RESET_ALL}")
    try:
        command = f"nmap -Pn -sCV --script=vuln {subdomain}"
        output = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, text=True)
        return output
    except subprocess.CalledProcessError:
        return "Nmap scan failed."

def print_banner():
    os.system("figlet -f slant 'M i n t  F i b e r' | lolcat")
    print(f"{Fore.RED}==================================================================={Style.RESET_ALL}")
    print(f"|{Fore.BLUE} MintFiber{Style.RESET_ALL} - Advanced Web Enumeration and Security Scanner       |")
    print(f"{Fore.WHITE}|        designed for ethical hackers and penetration testers.    |")
    print(f"{Fore.YELLOW}-------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"|Developed by:{Fore.MAGENTA} Anusha Gupta , Avik Samanta{Style.RESET_ALL} |        MINTFIRE     {Style.RESET_ALL} |")
    print(f"{Fore.GREEN}-------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"|Version:{Fore.MAGENTA} {version}{Style.RESET_ALL} | {Fore.GREEN}                   STABLE                         {Style.RESET_ALL}|")
    print(f"{Fore.MAGENTA}-------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"|GitHub: {Fore.YELLOW}https://github.com/anushagupta11                         {Fore.WHITE}|")
    print(f"|LinkedIn: {Fore.CYAN}https://www.linkedin.com/in/anusha-gupta-735826284/    {Fore.WHITE}|")
    print(f"{Fore.CYAN}-------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"|GitHub: {Fore.YELLOW}https://github.com/avik-root/                            {Fore.WHITE}|")
    print(f"|LinkedIn: {Fore.CYAN}https://www.linkedin.com/in/avik-samanta-root/         {Fore.WHITE}|")
    print(f"{Fore.YELLOW}===================================================================\n")

def crt_sh_enum(domain):
    """ Fetch subdomains from crt.sh """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            for entry in json_data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    if sub.strip() and "*" not in sub:
                        subdomains.add(sub.strip())
            print(f"{Fore.GREEN}[âœ”] Found {len(subdomains)} subdomains from crt.sh{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[X] Failed to fetch data from crt.sh (Status: {response.status_code}){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[X] Error in crt_sh_enum: {e}{Style.RESET_ALL}")

def wayback_enum(domain):
    """ Fetch subdomains from the Wayback Machine """
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            for entry in json_data[1:]:  # Skip headers
                sub = entry[0].split("/")[2]
                if sub.strip() and "*" not in sub:
                    subdomains.add(sub.strip())
            print(f"{Fore.GREEN}[âœ”] Found {len(subdomains)} subdomains from Wayback Machine{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[X] Failed to fetch data from Wayback Machine (Status: {response.status_code}){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[X] Error in wayback_enum: {e}{Style.RESET_ALL}")

def check_csrf(subdomain):
    try:
        response = requests.get(f"http://{subdomain}", headers=HEADERS, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            if not form.find('input', {'name': 'csrf_token'}):
                return "Vulnerable"
        return "Not Found"
    except Exception:
        return "Not Found"

def check_clickjacking(subdomain):
    try:
        response = requests.get(f"http://{subdomain}", headers=HEADERS, timeout=10)
        headers = response.headers
        if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
            return "Vulnerable"
        return "Not Found"
    except Exception:
        return "Not Found"

def process_subdomain(subdomain, output_file):
    print(f"{Fore.CYAN}[+] Scanning {subdomain}...{Style.RESET_ALL}")
    nmap_result = run_nmap(subdomain)
    xss_vulnerable = check_csrf(subdomain)
    clickjacking_vulnerable = check_clickjacking(subdomain)
    csrf_vulnerable = check_csrf(subdomain)
    vulnerability_report = f"""
[+] Vulnerability Results for {subdomain}:
  - XSS: {xss_vulnerable}
  - Clickjacking: {clickjacking_vulnerable}
  - CSRF: {csrf_vulnerable}
  - Nmap Scan:
{nmap_result}
"""
    print(Fore.GREEN + vulnerability_report + Style.RESET_ALL)
    with open(output_file, 'a') as f:
        f.write(vulnerability_report + "\n")

def main():
    install_nmap()
    print_banner()
    domain = input(f"{Fore.GREEN}[?] Enter target domain: {Style.RESET_ALL}").strip()
    output_file = input(f"{Fore.GREEN}[?] Enter output file name: {Style.RESET_ALL}").strip()
    print(f"{Fore.GREEN}[*] Enumerating subdomains for {domain}...{Style.RESET_ALL}")
    crt_sh_enum(domain)
    wayback_enum(domain)
    unique_subdomains = sorted(subdomains)
    if not unique_subdomains:
        print(f"{Fore.RED}[!] No subdomains found. Exiting...{Style.RESET_ALL}")
        return
    print(f"{Fore.YELLOW}[!] Found {len(unique_subdomains)} unique subdomains:{Style.RESET_ALL}")
    for subdomain in unique_subdomains:
        print(f"  - {subdomain}")
    for subdomain in unique_subdomains:
        process_subdomain(subdomain, output_file)
    print(f"{Fore.GREEN}[âœ”] Scan complete! Results saved in {output_file}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()