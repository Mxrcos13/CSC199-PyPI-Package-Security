# Finding: PDFKit — Option Injection (Investigated, Dropped)

## Package Information

| Field      | Value                                     |
| ---------- | ----------------------------------------- |
| Package    | pdfkit                                    |
| Version    | 1.0.0 (latest at time of research)        |
| PyPI       | https://pypi.org/project/pdfkit/          |
| GitHub     | https://github.com/JazzCore/python-pdfkit |
| File       | `pdfkit/pdfkit.py`                        |

---

## Summary

PDFKit constructs a `wkhtmltopdf` subprocess call using an `options` dict passed by the caller. Attacker-controlled keys or values in that dict can inject extra command-line arguments into the `wkhtmltopdf` process, including options like `--enable-local-file-access` that allow the generated PDF to read files from the local filesystem.

---

## Why Dropped

Exploitation requires the attacker to already control the `options` dictionary passed to `pdfkit.from_string()` or `pdfkit.from_url()`. In a typical web application, these options are set by the developer, not supplied by end users. There is no direct path from untrusted external input to the `options` dict without the application already being compromised at the code level. The attack surface is materially narrower than the Luigi or Watchdog findings, where the source is unambiguously attacker-controlled through a config file or filesystem filename.

---

## References

- [pdfkit source](https://github.com/JazzCore/python-pdfkit)
- [wkhtmltopdf documentation](https://wkhtmltopdf.org/usage/wkhtmltopdf.txt)
