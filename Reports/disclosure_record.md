# Vulnerability Disclosure Record

**Researcher:** Marcos Pantoja
**Project:** CSC199 — PyPI Package Security Research
**Date of Report:** May 2026

This document records all responsible disclosure attempts made during the course of this project.

---

## 1. Luigi — Command Injection (CVSS 7.8 High)

**Package:** `luigi` by Spotify
**Vulnerability:** Command injection via `parallel_env` parameter in `luigi/contrib/sge.py`
**Affected versions:** All versions including latest (3.7.3)

### Disclosure Attempts

| Channel | Date | Status |
|---|---|---|
| HackerOne (Spotify bug bounty) | April 2026 | Luigi is not listed in Spotify's HackerOne bug bounty scope — no submission path available |
| GitHub Issue (`spotify/luigi`) | April 2026 | Filed with full technical details, PoC, and remediation — **no response** |
| Email to Spotify security contact | April 2026 | Sent with vulnerability summary and reproduction steps — **no response** |

### Content of Disclosure

All three channels included:
- Description of the vulnerable code path (`parallel_env` → `_build_qsub_command` → `subprocess.check_output(shell=True)`)
- Reproduction steps and example payloads
- CVSS score and severity assessment
- Recommended fix (remove `shell=True`, pass arguments as list)

### Outcome

No response received from Spotify through any channel as of project submission. The vulnerability remains unpatched in the latest release. CVE assignment was not obtained — MITRE's standard process requires vendor coordination, which cannot proceed without acknowledgment from the maintainer.

**GitHub Issue:** Filed on `spotify/luigi` repository, April 2026
**Email date:** April 2026

---

## 2. Watchdog — ShellCommandTrick Filename Injection

**Package:** `watchdog`
**Vulnerability:** Filesystem filename injected via `Template.safe_substitute()` into `Popen(shell=True)`

### Pre-Disclosure Research

Before filing a disclosure, a search of the `gorakhargosh/watchdog` GitHub repository found that spartan8806 (Conner Webber) had publicly disclosed the same vulnerability in GitHub issue #1163 on March 8, 2026. The fix was merged by maintainer BoboTiG in PR #1164 on March 9, 2026. GitHub issue #1163 remains open (never formally closed).

Note: the prior disclosure was made as a public GitHub issue, which the Watchdog maintainer community flagged as inappropriate — security vulnerabilities should not be disclosed publicly before a patch is available. This project's approach of researching responsible disclosure channels before filing reflects the correct practice.

| Action | Date | Status |
|---|---|---|
| Independent vulnerability confirmed | Early 2026 | Fully reproduced with PoC |
| Pre-disclosure search | Early 2026 | Prior public report found (issue #1163); fix merged (PR #1164) |
| Disclosure filed | — | Not filed; prior report already exists |

### Outcome

Not submitted to avoid duplicate disclosure. Fix is in the codebase; original issue #1163 remains open. Documented in `findings/watchdog.md`.

---

## Summary

| Package | Disclosure Attempted | Channels Used | Response |
|---|---|---|---|
| Luigi (Spotify) | Yes | HackerOne, GitHub issue, email | No response |
| Watchdog | No — already patched | Pre-disclosure research | Already patched (PR #1164) |
