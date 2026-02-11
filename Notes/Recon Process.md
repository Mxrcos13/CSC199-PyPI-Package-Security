# PyPI Command Injection Reconnaissance Guide

## Overview

**Goal:** Find command injection vulnerabilities in Python packages  

---

## Step 1: Find Packages to Analyze

1. Go to https://hugovk.github.io/top-pypi-packages/
2. Look for packages that likely execute shell commands:
   - CLI wrappers (ffmpeg, imagemagick, wkhtmltopdf)
   - DevOps tools (fabric, invoke, sh)
   - Git/system utilities
   - PDF/image processors

---

## Step 2: Find the GitHub Repo

1. Go to https://pypi.org/project/[package-name]/
2. Click "Homepage" or "Source" link to find GitHub repo

---

## Step 3: Search on GitHub

In the repository search bar, search for:
```
# Critical
shell=True
os.system
os.popen

# High
subprocess.Popen
subprocess.call

# Sanitization (no results = possible vulnerability)
sanitize
whitelist
blacklist
validate
```

---

## Step 4: Document Finding

| Field | Value |
|-------|-------|
| Package | |
| PyPI Rank | |
| GitHub URL | |
| File:Line | |
| Pattern Found | |
| User Controlled? | Yes / No |
| Sanitized? | Yes / No |
| Exploitable? | Yes / No |
| Type | Command Injection / Option Injection |

---

## Good Candidates from Top PyPI

| Package | Why It's a Good Target |
|---------|------------------------|
| GitPython | Wraps git CLI |
| Pillow | Image processing |
| paramiko | SSH commands |
| fabric | Remote execution |
| sh | Shell wrapper |
| ffmpeg-python | Wraps ffmpeg |
| pdf2image | Wraps poppler |
| python-docx | Document processing |