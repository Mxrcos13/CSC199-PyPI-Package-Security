## Candidate Targets

| Package | Priority | File | Pattern | Notes |
| ------- | -------- | ---- | ------- | ----- |
| ansible | High | `fail_over.py`, `fail_back.py` | `os.system("..." + vault_pass + "...")` | Direct string concat with user input |
| pyinotify | High | `pyinotify.py` | `subprocess.Popen(options.command, shell=True)` | CLI `--command` arg goes straight to shell |
| dulwich | High | `cli.py` | `shell=True` in CLI handlers | Filenames/branch names potentially attacker-controlled |
| awscli | High | `alias.py` | `shell=True` on alias invocation | User-defined alias content passed to shell |
| dvc | High | `pager.py`, `run.py` | `os.system(DEFAULT_PAGER)` | `DEFAULT_PAGER` env var flows into `os.system()` |
| invoke | Medium | `runners.py` | `shell=True` | Need to verify if task args flow in unsanitized |
| doit | Medium | `action.py` | `CmdAction(action, shell=True)` | Action sourced from task config |
| pipenv | Medium | `shell.py` | `script.cmdify()` + `shell=True` | Need to verify cmdify escaping |
| pdfkit | Done | `pdfkit.py` | Option injection → `wkhtmltopdf` | PoC complete |
| Luigi | Done | `contrib/sge.py` | `parallel_env` → `subprocess.check_output(shell=True)` | PoC complete |
| Watchdog | Done | `ShellCommandTrick` | Filename template → `Popen(shell=True)` | PoC complete |
| salt | Low | various | `shell=True` | Hits mostly in test files |
| gitpython | Low | `cmd.py` | `shell=True` | Hits in documentation comments only |
| metaflow | Low | `_termui_impl.py` | `os.system()` | Hits in vendored `click` internals |
| cmd2 | Low | `cmd2.py` | `shell=True` | By design — interactive shell emulator |
