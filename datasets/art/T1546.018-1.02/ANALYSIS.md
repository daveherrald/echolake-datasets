# T1546.018-1: Python Startup Hooks — Python Startup Hook via atomic_hook.pth (Windows)

## Technique Context

T1546.018 (Python Startup Hooks) covers persistence through Python's interpreter initialization infrastructure. Python's `site` module — loaded automatically at every interpreter startup — processes `.pth` files in `site-packages` directories. Any line in a `.pth` file beginning with `import` is executed as Python code before user scripts run. An attacker with write access to any `site-packages` directory can drop a `.pth` file containing `import` statements that load a malicious module or execute arbitrary code. The persistence fires every time Python is invoked under the affected user context.

This test uses the virtual environment (`venv`) variant: it creates a Python virtualenv at `C:\Windows\Temp\atomic_pth_win\`, writes `atomic_hook.pth` into the venv's `site-packages`, and then triggers Python twice to confirm the hook fires. The hook payload is:

```python
import os, subprocess; os.environ.get('CALC_SPAWNED') or (os.environ.update({'CALC_SPAWNED':'1'}) or subprocess.Popen(['calc.exe']))
```

This launches `calc.exe` while using an environment variable guard to prevent recursive spawning.

In the defended variant, this technique was not blocked by Windows Defender. Both datasets are nearly identical in event count (1,038 vs 1,037), making the undefended version the cleaner baseline.

## What This Dataset Contains

The dataset spans 15 seconds (2026-03-17 17:07:33–17:07:48 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`. This is the largest dataset in this batch by a wide margin, driven by Python virtualenv creation.

**Sysmon (1,038 events — Event IDs 1, 5, 7, 10, 11, 17):**

The dominant event type is EID 11 (FileCreate, 979 events). Python virtualenv creation writes hundreds of `.py`, `.pyc`, and pip package files to `C:\Windows\Temp\atomic_pth_win\`. These are real filesystem artifacts of the venv setup — they provide context but are not technique-specific in isolation. The persistence file itself is one of those 979 EID 11 events: `C:\Windows\Temp\atomic_pth_win\env\Lib\site-packages\atomic_hook.pth` written by `powershell.exe`.

Sysmon EID 1 (ProcessCreate, 9 events) records:
1. `whoami.exe` — test framework context check, tagged `technique_id=T1033`
2. `powershell.exe` — the full test script, tagged `technique_id=T1083`:
   ```
   "powershell.exe" & {$TempDir = Join-Path $env:TEMP "atomic_pth_win"
   New-Item -ItemType Directory -Path $TempDir -Force
   & "python.exe" -m venv "$TempDir\env"
   $SitePackages = & "$TempDir\env\Scripts\python.exe" -c "import site; print(site.getsitepackages()[1])"
   "import os, subprocess; ..." | Out-File -Encoding ASCII "$SitePackages\atomic_hook.pth"
   & "$TempDir\env\Scripts\python.exe" -c "print('Triggering Hook via atomic_hook...')"}
   ```

Additional EID 1 events capture Python processes spawned as part of venv creation and hook execution.

Sysmon EID 5 (ProcessTerminate, 4 events) records Python interpreter exits — these are present because the Sysmon configuration captures process termination for Python, reflecting the multiple Python invocations during venv setup and hook firing.

Sysmon EID 7 (ImageLoad, 32 events) records DLL loads into PowerShell and Python processes — .NET runtime, Defender, and Python runtime DLLs.

Sysmon EID 10 (ProcessAccess, 11 events) records `powershell.exe` accessing child Python processes.

Sysmon EID 17 (PipeCreate, 3 events) records PowerShell named pipes.

**Security (14 events — Event ID 4688):**

Fourteen process creation events trace the full Python execution chain:

- `whoami.exe` (test framework context check)
- `powershell.exe` (full test script command line)
- `C:\Program Files\Python312\python.exe -m venv C:\Windows\TEMP\atomic_pth_win\env` — system Python creating the virtualenv
- `C:\Windows\Temp\atomic_pth_win\env\Scripts\python.exe -m ensurepip --upgrade --default-pip` — venv Python bootstrapping pip
- `C:\Windows\Temp\atomic_pth_win\env\Scripts\python.exe -c "import site; print(site.getsitepackages()[1])"` — discovering the site-packages path
- `C:\Windows\Temp\atomic_pth_win\env\Scripts\python.exe -c "print('Triggering Hook via atomic_hook...')"` — the hook trigger invocation

The final venv Python invocation is the one where `atomic_hook.pth` fires. The Security log does not capture `calc.exe` in the available samples, but the hook's `subprocess.Popen(['calc.exe'])` would produce a child process of the venv Python.

**PowerShell (111 events — Event IDs 4103, 4104):**

ScriptBlock logging captures the full test and cleanup scripts verbatim, including the hook payload code written to `atomic_hook.pth` via `Out-File`. This is a particularly useful channel because it captures the exact Python code planted on disk without requiring a read of the `.pth` file itself.

## What This Dataset Does Not Contain

- **`calc.exe` process creation:** The hook payload spawns `calc.exe` via `subprocess.Popen`. This process creation is not captured in the available Security or Sysmon samples, though it would appear as a child of the venv Python process. It may be present in the full 1,038-event Sysmon dataset.
- **Persistence durability:** The venv and `atomic_hook.pth` are created in `C:\Windows\Temp\`, a temporary location. The test demonstrates the mechanism but the persistence would not survive system cleanup cycles or temp-folder purges.
- **System-level site-packages:** The test uses a virtualenv rather than the system Python's `site-packages`. A real-world deployment targeting `C:\Program Files\Python312\Lib\site-packages\` would be more durable but would require write access to a protected path. That variant is not represented here.

## Assessment

This dataset is notable for its volume: 979 EID 11 events from Python venv creation are legitimate filesystem activity that accompanies the technique. The persistence file (`atomic_hook.pth`) is one among hundreds of Python-related file creates. Isolating it requires either knowing the filename or filtering for `.pth` files in `site-packages` paths written by `powershell.exe` rather than a Python installer.

The Security channel's process chain is the most actionable record: it shows `powershell.exe` → system `python.exe` → venv `python.exe` (with `-m ensurepip`) → venv `python.exe` (with the final trigger `-c "print(...)"`) as a complete execution sequence that is anomalous outside development workflows.

The undefended and defended event counts are nearly identical (1,038 vs 1,037), confirming that Windows Defender plays no role in this technique's behavior — the difference is within measurement noise.

## Detection Opportunities Present in This Data

- **Sysmon EID 11 / Security EID 4688:** `powershell.exe` writing a `.pth` file to a `site-packages` directory. Writes to `site-packages\*.pth` by a non-Python-installer process are rare and warrant examination.
- **Sysmon EID 1 / Security EID 4688:** `python.exe` spawning `calc.exe` (or any non-Python process) as a child. Python spawning `cmd.exe`, `powershell.exe`, or any executable not in the Python installation tree is anomalous outside developer environments.
- **Security EID 4688:** `powershell.exe` as the parent of a `python.exe` invocation that in turn spawns additional Python instances. The chain `powershell.exe → python.exe -m venv → venv\Scripts\python.exe` is a recognizable pattern for scripted venv manipulation.
- **PowerShell EID 4104:** The hook payload `import os, subprocess; os.environ.get...subprocess.Popen` written via `Out-File` to a `.pth` file path appears verbatim in ScriptBlock logging, enabling content-based detection of the planted code before it ever executes.
