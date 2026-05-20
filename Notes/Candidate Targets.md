## Candidate Targets

| Package | Priority | File | Pattern | Notes |
| ------- | -------- | ---- | ------- | ----- |
| ansible (ovirt.ovirt) | Dropped | `fail_over.py`, `fail_back.py` | `os.system("..." + vault_pass + "...")` | Investigated — not included in final project scope |
| awscli | Investigate | `alias.py` | `shell=True` on alias invocation | User-defined alias content passed to shell — needs deeper trace |
| pipenv | Investigate | `shell.py` | `script.cmdify()` + `shell=True` | Need to verify if `cmdify()` sanitizes metacharacters |
| yt-dlp | Investigate | `postprocessor/exec.py` | `Popen(cmd, shell=True)` | `--exec` template with `{}` for filepath — check if `shell_quote` fully protects |
| pyinotify | Low/By-design | `pyinotify.py` | `subprocess.Popen(options.command, shell=True)` | By design — user explicitly provides `--command` |
| dulwich | Low/By-design | `cli.py` | `shell=True` in filter-branch, pager | filter-branch by design; pager reads env var `DULWICH_PAGER`/`GIT_PAGER`/`PAGER` |
| dvc | Low/False-positive | `pager.py` | `os.system(DEFAULT_PAGER)` | DEFAULT_PAGER is hardcoded "less" — not user-controlled |
| invoke | Low/By-design | `runners.py` | `shell=True` | Core task runner, by design |
| doit | Low/By-design | `action.py` | `CmdAction(action, shell=True)` | Task actions defined by developer in dodo.py, by design |
| pdfkit | Dropped | `pdfkit.py` | Option injection → `wkhtmltopdf` | Investigated — dropped (attack requires controlling app code). See findings/pdfkit.md |
| Luigi | Done | `contrib/sge.py` | `parallel_env` → `subprocess.check_output(shell=True)` | Report + PoC complete. Disclosed to Spotify — no response. |
| Watchdog | Done | `ShellCommandTrick` | Filename template → `Popen(shell=True)` | PoC complete. Already patched (PR #1164). See findings/watchdog.md |
| salt | Low | various | `shell=True` | Massive codebase — many hits, mostly internal/admin use |
| gitpython | Low | `cmd.py` | `shell=True` | Hits in documentation comments only |
| metaflow | Low | `_termui_impl.py` | `os.system()` | Hits in vendored `click` internals — false positives |
| cmd2 | Low | `cmd2.py` | `shell=True` | By design — interactive shell emulator |
| fabric3 | Low | `operations.py` | `shell=True` | Core remote execution, by design |
| ray | Low | `job_supervisor.py` | `shell=True` | Job entrypoint is user-submitted by design |
| impacket | Low | `examples/` | `os.system(s)` | Interactive shell tools, by design |
| scapy | Low | `utils.py` | `Popen(target[1:], shell=True)` | Pipe-to-command target syntax, by design |
| gallery-dl | Low | `actions.py` | `Popen(opts, shell=True)` | `--exec` flag, by design |
| wand | Low | `display.py` | `os.system(... + path)` | path is from tempfile.mktemp(), not user-controlled |
| pelican | Low | `pelican_import.py` | `subprocess.call(cmd, shell=True)` | Operator controls output path via CLI — limited attack surface |
