# PyPI Package Security Research

## Overview

This project focuses on vulnerability research and exploit development in the PyPI ecosystem. The goal is to identify and document command injection vulnerabilities in Python packages through systematic security auditing.

This project was completed as part of CSC199 coursework at California State University, Sacramento under Professor Daniel Hammon.

---

## Objectives

- Identify and document command injection vulnerabilities in PyPI packages
- Develop proof-of-concept exploits for discovered vulnerabilities
- Practice responsible disclosure to package maintainers
- Contribute to software supply chain security

---

## Methodology

### 1. Reconnaissance
- Find candidate packages using https://hugovk.github.io/top-pypi-packages/
- Focus on packages that wrap command-line tools
- Review documentation and analyze dependencies

### 2. Static Analysis
- Search for dangerous patterns: `subprocess`, `shell=True`, `os.system`
- Check for input validation: `sanitize`, `whitelist`, `blacklist`
- Review the wrapped tool's documentation for dangerous options

### 3. Dynamic Analysis
- Craft malicious inputs
- Test exploitation in isolated environment

### 4. Exploit Development
- Create proof-of-concept if vulnerability is confirmed
- Document reproduction steps

---

## Reconnaissance Process

### Finding Packages

Go to https://hugovk.github.io/top-pypi-packages/

### Searching for Vulnerabilities

On GitHub, search the repo for:
```
subprocess
shell=True
os.system
os.popen
sanitize
whitelist
blacklist
```

---

## Repository Structure
```
├── README.md
├── RECON.md                    # Reconnaissance process guide
├── findings/
│   └── [package_name].md       # Documented findings
└── poc/
    └── [package_name]_poc.py   # Proof of concept exploits
```

---

## Tools Used

- **Static Analysis:** Manual code review, GitHub search
- **Package Discovery:** https://hugovk.github.io/top-pypi-packages/

---

## Findings

| Package | Status        | Type             | Details                    |
| ------- | ------------- | ---------------- | -------------------------- |
| pdfkit  | Investigating | Option Injection | [Link](findings/pdfkit.md) |

---

## Responsible Disclosure

All vulnerabilities will be reported following responsible disclosure practices:
1. Contact package maintainers privately
2. Provide technical details and reproduction steps
3. Allow time for fix before public disclosure
4. Submit CVE request if applicable

---

## Author

Marcos Pantoja  
Computer Science, California State University, Sacramento

---

## Acknowledgments

Professor Daniel Hammon - Project Advisor