# MintFiber
Advanced Web Enumeration and Security Scanner designed for Ethical Hackers and Penetration testers.

# 🚨 MintFiber - Advanced Web Enumeration & Security Scanner

> **Crafted by:** [Anusha Gupta](https://github.com/anushagupta11) & [Avik Samanta](https://github.com/avik-root)

---

## 🚀 What is MintFiber?
**MintFiber** is your go-to command-line toolkit for comprehensive web reconnaissance and vulnerability scanning. It blends deep subdomain discovery with real-time threat detection and is tailor-made for:
- 🛡️ Ethical Hackers
- 🕵️‍♀️ Penetration Testers
- 🔍 Bug Bounty Hunters

---

## ⚙️ Key Features

### 🌐 Subdomain Enumeration
- Sources include `crt.sh` and the **Wayback Machine**
- Automatically filters wildcards and duplicates
- Efficient and sorted collection

### 🔐 Security Checks
- **CSRF**: Detects forms missing anti-CSRF tokens
- **Clickjacking**: Checks for missing `X-Frame-Options` or `CSP` headers
- **XSS Indicators**: Detects potentially exploitable forms

### 🧠 Integrated Nmap Scanning
- Auto-detects and optionally installs `nmap`
- Runs detailed service and vulnerability scans:  
  `nmap -Pn -sCV --script=vuln`

### 💾 Output & Logging
- All scans saved in a specified output file
- Neatly formatted vulnerability reports for each subdomain

### 🎨 Terminal UI
- Dynamic ASCII banner via `figlet` + `lolcat`
- Colored output using `colorama`
- Designed to impress, built for clarity

---

## 📦 Installation

### 🔁 Clone the Repository
```bash
git clone https://github.com/anushagupta11/mintfiber.git
cd mintfiber
```

### 📜 Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 🔧 Install System Tools (Linux/macOS)
```bash
sudo apt install nmap figlet lolcat -y
# or
brew install nmap figlet lolcat
```

---

## 🚀 How to Use
Run the tool using:
```bash
python3 mintfiber.py
```

You'll be prompted to:
1. Enter the domain (e.g., `example.com`)
2. Choose a file name to save the report

**MintFiber** will then:
- 🔍 Enumerate subdomains
- 📡 Perform Nmap scans
- 🧪 Run security tests (CSRF, Clickjacking, XSS)
- 🗃️ Save everything to your output file

---

## 📋 Sample Output
```text
[+] Vulnerability Results for blog.example.com:
  - XSS: Vulnerable
  - Clickjacking: Vulnerable
  - CSRF: Not Found
  - Nmap Scan:
    PORT   STATE SERVICE
    80/tcp open  http
    ...
```

---

## 👩‍💻 Developer Info

| Name         | GitHub                                            | LinkedIn                                                        |
| ------------ | ------------------------------------------------- | --------------------------------------------------------------- |
| Anusha Gupta | [anushagupta11](https://github.com/anushagupta11) | [Anusha Gupta](https://www.linkedin.com/in/anusha-gupta-735826284/) |
| Avik Samanta | [avik-root](https://github.com/avik-root)         | [Avik Samanta](https://www.linkedin.com/in/avik-samanta-root/)     |

---

## 📜 License
**MIT License** © 2025 MintFiber Team

> _"Scan smart. Stay ahead. Use MintFiber."_

