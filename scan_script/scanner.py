"""
PyPI Command Injection Scanner

Usage:
    python3 scanner.py packages.txt
"""
import os
import re
import sys
import subprocess
import zipfile
import tarfile
import tempfile

# Dangerous sink patterns
SINK_PATTERNS = [
    r'shell\s*=\s*True',
    r'os\.system\s*\(',
    r'os\.popen\s*\(',
]

# Source pattern categories — each is (label, [patterns])
SOURCE_CATEGORIES = [
    ('CLI/USER INPUT', [
        r'sys\.argv',
        r'\binput\s*\(',
        r'\bargs\.',
        r'Parameter\s*\(',
        r'argparse',
        r'optparse',
        r'click\.argument',
        r'click\.option',
    ]),
    ('FILESYSTEM PATH', [
        r'os\.walk\s*\(',
        r'os\.listdir\s*\(',
        r'os\.scandir\s*\(',
        r'glob\.glob\s*\(',
        r'glob\.iglob\s*\(',
        r'\.src_path',
        r'\.dest_path',
        r'\.filename',
        r'\.filepath',
        r'event\.src',
        r'pathlib',
        r'Path\s*\(',
    ]),
    ('ENVIRONMENT VAR', [
        r'os\.environ',
        r'os\.getenv\s*\(',
        r'environ\.get\s*\(',
    ]),
    ('NETWORK/REQUEST', [
        r'request\.',
        r'requests\.get',
        r'urllib',
        r'socket\.',
        r'\.recv\s*\(',
        r'flask',
        r'django',
        r'fastapi',
    ]),
    ('TEMPLATE SUBSTITUTION', [
        r'safe_substitute',
        r'Template\s*\(',
        r'\.format\s*\(',
        r'f".*{',
        r"f'.*{",
        r'%\s*\(',
    ]),
    ('FILE METADATA', [
        r'\.tag\b',
        r'\.tags\b',
        r'ID3\s*\(',
        r'mutagen',
        r'exif',
        r'metadata',
        r'EasyID3',
    ]),
]

# Flatten for quick "has any source" check
SOURCE_PATTERNS = [p for _, patterns in SOURCE_CATEGORIES for p in patterns]

def load_packages(filepath):
    """Load package names from a text file (one per line)."""
    packages = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                packages.append(line)
    return packages

def download_package(name, dest):
    try:
        subprocess.run(
            ['pip', 'download', name, '--no-deps', '-d', dest],
            capture_output=True,
            timeout=60
        )
        return True
    except:
        return False

def extract_package(dest):
    for f in os.listdir(dest):
        path = os.path.join(dest, f)
        out = os.path.join(dest, f.replace('.whl', '').replace('.tar.gz', ''))
        try:
            if f.endswith('.whl'):
                with zipfile.ZipFile(path, 'r') as z:
                    z.extractall(out)
            elif f.endswith('.tar.gz'):
                with tarfile.open(path, 'r:gz') as t:
                    t.extractall(dest)
        except:
            pass

def scan_file(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
    except:
        return None

    has_sink = any(re.search(p, content) for p in SINK_PATTERNS)
    if not has_sink:
        return None

    # Find which source categories matched
    matched_sources = []
    for label, patterns in SOURCE_CATEGORIES:
        if any(re.search(p, content) for p in patterns):
            matched_sources.append(label)

    findings = []
    for i, line in enumerate(content.split('\n'), 1):
        for p in SINK_PATTERNS:
            if re.search(p, line):
                findings.append({
                    'line': i,
                    'code': line.strip()[:100],
                    'sources': matched_sources,
                })
    return findings

def scan_package(pkg_dir):
    results = []
    for root, dirs, files in os.walk(pkg_dir):
        for f in files:
            if f.endswith('.py'):
                path = os.path.join(root, f)
                findings = scan_file(path)
                if findings:
                    results.append({
                        'file': path,
                        'findings': findings
                    })
    return results

def main():
    # Check for argument
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py packages.txt")
        print("\nCreate a packages.txt file with one package name per line:")
        print("  luigi")
        print("  watchdog")
        print("  # this is a comment")
        sys.exit(1)

    # Load packages from file
    packages_file = sys.argv[1]
    if not os.path.exists(packages_file):
        print(f"Error: File '{packages_file}' not found")
        sys.exit(1)

    packages = load_packages(packages_file)
    print("=" * 60)
    print("PyPI Command Injection Scanner")
    print("=" * 60)
    print(f"Loaded {len(packages)} packages from {packages_file}")

    for pkg in packages:
        print(f"\n[*] Scanning {pkg}...")

        with tempfile.TemporaryDirectory() as tmp_dir:
            if download_package(pkg, tmp_dir):
                extract_package(tmp_dir)
                results = scan_package(tmp_dir)

                if results:
                    for r in results:
                        for f in r['findings']:
                            if f['sources']:
                                print(f"    [{', '.join(f['sources'])}] + SINK FOUND!")
                            else:
                                print(f"     SINK ONLY")
                            print(f"     File: {r['file']}")
                            print(f"     Line {f['line']}: {f['code']}")
                else:
                    print(f"    Clean")
            else:
                print(f"    Download failed")

    print("\n" + "=" * 60)
    print("Done!")

if __name__ == "__main__":
    main()