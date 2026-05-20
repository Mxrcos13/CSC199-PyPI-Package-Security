# PyPI Package Security Research

## Overview

Systematic security audit of the Python Package Index (PyPI) ecosystem, targeting command injection vulnerabilities (CWE-78). Conducted as independent study CSC199 at California State University, Sacramento.

Approximately 185 packages were reviewed using a custom-built static analysis scanner and a four-phase manual methodology. The primary finding is an unpatched, high-severity command injection vulnerability in Luigi's SGE workflow module (CVSS 7.8), responsibly disclosed to Spotify.

---

## Methodology

1. **Reconnaissance** — identify candidate packages via download rankings and documentation review; prioritize packages that wrap subprocess calls around user-configured parameters
2. **Static Analysis** — trace data flow from user-controlled sources (`luigi.Parameter()`, `input()`, filesystem filenames) to dangerous sinks (`shell=True`, `os.system`)
3. **Dynamic Analysis** — confirm injection by crafting malicious inputs and verifying execution in an isolated environment
4. **Exploit Development** — write a minimal proof-of-concept demonstrating the full attack chain

See `Reports/luigi_sge_command_injection_report.md` for the full vulnerability audit report.

---

## Repository Structure

```
├── scan_script/
│   ├── scanner.py           # Automated static analysis tool (downloads + regex-scans PyPI packages)
│   ├── packages.txt         # Bulk package list (round 1)
│   ├── targets_round2.txt   # Categorized targets (round 2)
│   └── targets_round4.txt   # Categorized targets (round 4)
├── findings/
│   ├── luigi.md             # Primary finding: command injection (CVSS 7.8 High)
│   ├── watchdog.md          # Independent re-discovery (patched PR #1164, Mar 2026)
│   └── pdfkit.md            # Investigated: dropped (attack requires controlling app code)
├── poc/
│   ├── luigi_sge_poc.py     # Working PoC — Luigi SGE command injection
│   └── watchdog_poc.py      # Working PoC — Watchdog filename injection
├── test_scripts/            # Dynamic analysis scripts used during research
│   ├── test_subprocess.py   # Basic shell=True behavior
│   ├── test_subprocess2.py  # Semicolon metacharacter interpretation
│   ├── test_subprocess3.py  # Luigi-style parallel_env injection pattern
│   ├── test_luigi.py        # Luigi task runner tests
│   ├── test_sge_cli.py      # CLI-based SGE injection demonstration
│   └── luigi.cfg            # Config file for SGE injection via luigi.cfg
├── Reports/
│   ├── luigi_sge_command_injection_report.md  # Full vulnerability audit report (sent to Spotify)
│   ├── project_summary.md                    # One-paragraph executive summary
│   └── disclosure_record.md                  # Record of all disclosure attempts
└── Notes/                   # Research notes (Obsidian vault)
```

---

## Findings

| Package | Status | CVSS | Vulnerability | Details |
|---|---|---|---|---|
| Luigi (Spotify) | **Unpatched** | 7.8 High | Command injection via `parallel_env` in `sge.py` | [findings/luigi.md](findings/luigi.md) |
| Watchdog | Patched (PR #1164, Mar 2026) | 7.8 High | Filename injection via `ShellCommandTrick` | [findings/watchdog.md](findings/watchdog.md) |
| PDFKit | Dropped | — | Option injection into `wkhtmltopdf` (requires controlling app code) | [findings/pdfkit.md](findings/pdfkit.md) |

---

## Responsible Disclosure

| Package | Channels Attempted | Outcome |
|---|---|---|
| Luigi (Spotify) | HackerOne, GitHub issue, direct email | No response on any channel; vulnerability unpatched in latest release (3.7.3) |
| Watchdog | Pre-disclosure research only | Already patched before submission; not filed to avoid duplicate |

Full disclosure record: [Reports/disclosure_record.md](Reports/disclosure_record.md)

---

## Reconnaissance Process

**Finding packages:** [https://hugovk.github.io/top-pypi-packages/](https://hugovk.github.io/top-pypi-packages/) — sort by downloads, filter for packages that wrap CLI tools or spawn subprocesses.

**GitHub search patterns:**
```
subprocess
shell=True
os.system
os.popen
sanitize
shlex
```

---

## Tools Used

- **Static Analysis:** `scan_script/scanner.py` (custom-built) + manual code review
- **Package Discovery:** [https://hugovk.github.io/top-pypi-packages/](https://hugovk.github.io/top-pypi-packages/), GitHub search

---

## Author

Marcos Pantoja
Computer Science, California State University, Sacramento

Professor Daniel Hammon — Project Advisor
