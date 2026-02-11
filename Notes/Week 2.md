### Target 1

### **PDFKit**
PyPI: https://pypi.org/project/pdfkit/
GitHub: https://github.com/JazzCore/python-pdfkit

### Searched for Dangerous Patterns

On GitHub, searched the repo for:

| Search       | Result                         |
| ------------ | ------------------------------ |
| `shell=True` | No results                     |
| `subprocess` | 12 results in pdfkit/pdfkit.py |

---

## Examined subprocess Usage

Clicked into `pdfkit/pdfkit.py` and found:
```python
result = subprocess.Popen(
    args,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=self.environ
)
```

Where does `args` come from? Is it validated?

### Traced the Input

Found that `args` comes from user-supplied `options` dict.

Found the only validation code:
```python
def _normalize_arg(self, arg):
    return arg.lower()
```

This only lowercases the input with no sanitization.