# Windows Tcl/Tk CI reliability gate

Tracked by [issue #46](https://github.com/promirmir/KRYPTA/issues/46).
Windows Python 3.11 / 3.13 hosted runners intermittently reported
`invalid command name "tcl_findLibrary"` or `Can't find a usable init.tcl`
when sequential desktop widget smoke tests shared a Python process.
A retry that passes does **not** prove that the failure is resolved.

## Isolated test execution

On the Windows jobs of the **file vault tests** and **desktop alpha builds**
workflows, core pytest tests run with the two real Tk smoke test modules
excluded *from that one process only*. Both GUI smoke modules are then
collected by pytest and **every collected test node is run in a fresh Python
process**, three times, through:

```powershell
python -m tools.test_windows_gui_isolated --repeat 3
```

The required modules are `tests/test_volume_lab_gui.py` and
`tests/test_desktop_languages.py`. Their existing assertions are unchanged.
The runner rejects failed collection, missing modules, nonzero exit codes and
timeouts. It never retries a failed test, ignores test return values, marks
a GUI failure as expected, or sets a fake Tcl library path. Each invocation
initializes and disposes a separate Tcl interpreter; it cannot inherit prior
process-global Tcl state. This is a reliability isolation measure, not a
product cryptographic feature or a fix in the Tcl/Tk runtime itself.

Linux unit jobs retain the entire normal pytest suite; Linux localized UI
validation runs its existing display-backed Xvfb test job unchanged.

The isolated gate reports Python executable, platform and available Tcl/Tk
library environment variables before test execution; failures retain the
individual pytest diagnostics. The process-launch behavior and fail-closed
error propagation are tested in
`tests/test_windows_gui_isolated.py` without requiring a GUI.

## Acceptance and remaining unknowns

All Windows 3.11/3.13 core tests plus each Tk test in its own interpreter
must pass, including repeated runs, without disabling assertions. The
pipeline can show improved CI stability, but it does not prove the precise
upstream Tcl/Tk root cause or guarantee that a runner will never fail again.
Any recurrence requires preserving the complete failing job log and
investigating the runner's library path and interpreter lifecycle.
