# T1546.018-1: Python Startup Hooks — Python Startup Hook via atomic_hook.pth (Windows)

## Technique Context

T1546.018 (Python Startup Hooks) is a relatively recent addition to MITRE ATT&CK covering persistence through Python's module loading infrastructure. Python's `site` module, loaded at interpreter startup, processes `.pth` files in every `site-packages` directory: any line beginning with `import` is executed, and any line that is a valid filesystem path is added to `sys.path`. Attackers can drop a `.pth` file into a writable `site-packages` directory containing an `import` statement that loads a malicious module. Since Python is often available on developer systems and increasingly on enterprise endpoints, and since `.pth` files are not executable in the traditional sense, they can evade endpoint protection tools that focus on `.py` or binary file drops. The persistence triggers every time the Python interpreter starts.

## What This Dataset Contains

This test creates a Python virtual environment, installs the persistence hook, and runs Python twice — demonstrating the hook firing. The dataset is the largest in this T1546 series with 1,037 Sysmon events, dominated by 981 Event ID 11 (File Created) records from the Python virtualenv setup (hundreds of `.py`, `.pyc`, and pip package files written to `C:\Windows\Temp\atomic_pth_win\`).

The key persistence file write is captured by Sysmon Event ID 11:
- `C:\Windows\Temp\atomic_pth_win\env\Lib\site-packages\atomic_hook.pth`
- Written by `powershell.exe` running as `NT AUTHORITY\SYSTEM`

The hook execution is confirmed by Security 4688, which shows two Python runtime invocations:
- `C:\Program Files\Python312\python.exe` (system Python used to create the venv)
- `C:\Windows\Temp\atomic_pth_win\env\Scripts\python.exe` (venv Python executing the hook)
- `C:\Windows\System32\calc.exe` — the payload launched by the `.pth` hook

Sysmon Event ID 1 captures `python.exe` process creates (tagged `T1036` Masquerading due to non-standard path), `whoami.exe`, and `powershell.exe`. Event ID 5 (ProcessTerminate) records all four Python processes exiting. Event ID 10 (ProcessAccess) shows `python.exe` accessing `calc.exe` during payload execution.

The PowerShell channel (4104) captures the script block that writes the `.pth` file, though it is interleaved with extensive test framework boilerplate from the virtualenv setup.

## What This Dataset Does Not Contain

- **No content of the `.pth` file itself in the event data**: Sysmon Event ID 11 records only the filename and creating process. The actual content of `atomic_hook.pth` (which would contain the `import` statement or path directive triggering `calc.exe`) is not captured in any event. File content is never logged by the configured channels.
- **No system-installed site-packages path**: the hook is placed in a temporary virtualenv at `C:\Windows\Temp\...`, not in the system Python's `site-packages` at `C:\Program Files\Python312\Lib\site-packages\`. A hook in the system site-packages would persist for any Python invocation systemwide; this test's scope is limited to the venv.
- **Defender did not block the payload**: `calc.exe` was launched successfully, confirming Defender allowed the Python hook execution in this context.
- The 981 Sysmon Event ID 11 records from pip/venv setup are not technique-relevant and substantially increase the volume compared to other datasets in this collection.

## Assessment

This dataset captures the core indicators for Python startup hook persistence, including the `.pth` file write and confirmed payload execution via `calc.exe`. The challenge for detection is that the payload delivery is several hops removed from the hook drop: you see Python spawning `calc.exe` but need to correlate back to the `.pth` file write to understand why. The high volume of file create events from Python package installation makes it important to have targeted rules focused on `.pth` file writes to `site-packages` directories rather than broad file create alerting. The non-standard venv path at `C:\Windows\Temp\` also raises the anomaly bar — a `.pth` file in a temp directory's site-packages is significantly more suspicious than one in a user's home directory.

## Detection Opportunities Present in This Data

1. **Sysmon Event ID 11 — `.pth` file created in a `site-packages` directory**: Alert on any `.pth` file write to any `site-packages` path. Legitimate `.pth` files are created by package installers (`pip`, `setuptools`) and should correlate with package installation activity. Writes from `powershell.exe`, `cmd.exe`, or other non-installer processes are anomalous.
2. **Sysmon Event ID 11 — `.pth` file created in `C:\Windows\Temp\` or other unexpected locations**: A `site-packages` directory under `Temp` or another writable system directory is a strong indicator of deliberate placement rather than legitimate package installation.
3. **Security 4688 — `python.exe` spawning unexpected child processes**: `calc.exe`, `cmd.exe`, `powershell.exe`, or other execution primitives as direct children of `python.exe` in a non-development context is a high-fidelity payload execution indicator.
4. **Sysmon Event ID 1 — `python.exe` from a non-standard installation path**: Python running from `C:\Windows\Temp\` or another writable directory (as tagged `T1036` Masquerading in this dataset) warrants investigation of what triggered its execution.
5. **Correlation — `.pth` file write followed by Python execution within a short time window**: Linking a `.pth` file creation event to a subsequent Python process invocation that spawns unexpected children provides a behavioral chain across the hook installation and activation phases.
6. **Baseline — enumerate `.pth` files in all Python `site-packages` directories**: Periodic enumeration of all `.pth` files across system and user Python installations, compared against a pip-install baseline, provides a persistent detection capability independent of event log coverage.
