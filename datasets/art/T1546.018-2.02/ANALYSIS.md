# T1546.018-2: Python Startup Hooks — Python Startup Hook via usercustomize.py (Windows)

## Technique Context

T1546.018 (Python Startup Hooks) covers persistence through Python's interpreter startup sequence. This test exercises a different hook point than T1546.018-1: `usercustomize.py`. When the `ENABLE_USER_SITE` flag is set (the default for non-virtual-environment Python), the interpreter loads `usercustomize.py` from the user site-packages directory before any user script runs. This module is intended for user-specific Python environment customization, but an attacker who can write to the user site-packages path gains code execution on every Python invocation under that user context.

On Windows running as `NT AUTHORITY\SYSTEM`, the user site-packages path resolves to `C:\Windows\System32\config\systemprofile\AppData\Roaming\Python\Python312\site-packages\`. The test determines this path dynamically by calling `python.exe -c "import site; print(site.getusersitepackages())"`, writes the payload `import os; os.system('calc.exe')` to `usercustomize.py` in that directory, then invokes Python once more to trigger the hook.

Unlike the `.pth` file variant (T1546.018-1), `usercustomize.py` is a named module Python always looks for by filename. Detection rules targeting `usercustomize.py` creation are more targeted than those hunting for arbitrary `.pth` files.

In the defended variant, Defender did not block this technique. The undefended dataset has more Sysmon events (48 vs 32), primarily because without Defender's real-time scanning overhead, more EID 7 DLL loads are recorded for the Python processes.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17 17:07:54–17:07:57 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`.

**Sysmon (48 events — Event IDs 1, 7, 10, 11, 17):**

Sysmon EID 1 (ProcessCreate, 5 events) records:

1. `whoami.exe` — test framework context check, tagged `technique_id=T1033`
2. `powershell.exe` — the test script, tagged `technique_id=T1083`:
   ```
   "powershell.exe" & {$UserDir = & "python.exe" -c "import site; print(site.getusersitepackages())"
   if (!(Test-Path $UserDir)) { New-Item -ItemType Directory -Path $UserDir -Force }
   "import os; os.system('calc.exe')" | Out-File -FilePath "$UserDir\usercustomize.py" -Encoding ASCII
   Get-ChildItem -Path "$UserDir"
   & "python.exe" -c "print('Triggering Hook via usercustomize...')"}
   ```

Sysmon EID 11 (FileCreate, 7 events) records the creation of `usercustomize.py` and associated PowerShell startup profile data files. The `usercustomize.py` write by `powershell.exe` at `C:\Windows\System32\config\systemprofile\AppData\Roaming\Python\Python312\site-packages\usercustomize.py` is the central persistence artifact.

Sysmon EID 7 (ImageLoad, 26 events) records DLL loads into `powershell.exe` and the `python.exe` instances.

Sysmon EID 10 (ProcessAccess, 7 events) records `powershell.exe` accessing child Python and `whoami.exe` processes.

Sysmon EID 17 (PipeCreate, 3 events) records PowerShell named pipes.

**Security (9 events — Event ID 4688):**

The Security channel provides the most readable record of hook execution. The full process chain is:

1. `whoami.exe` — test framework check
2. `powershell.exe` — full test script
3. `C:\Program Files\Python312\python.exe -c "import site; print(site.getusersitepackages())"` — path discovery
4. `C:\Program Files\Python312\python.exe -c "print('Triggering Hook via usercustomize...')"` — hook trigger
5. `C:\Windows\system32\cmd.exe /c calc.exe` — spawned by Python's `os.system()` call
6. `C:\Windows\System32\calc.exe` — the payload

Security EID 4688 confirms that `calc.exe` was actually launched as a child of `cmd.exe`, which was itself a child of `python.exe`. This is the complete execution chain from Python hook invocation to payload delivery, captured in a single log channel. The process lineage `python.exe → cmd.exe → calc.exe` is the direct evidence of successful hook execution.

**PowerShell (105 events — Event IDs 4103, 4104):**

ScriptBlock logging captures the test script verbatim, including `"import os; os.system('calc.exe')"` piped to `Out-File` for `usercustomize.py`. The cleanup script (removing `usercustomize.py` and killing any Calculator process) is also captured in a separate ScriptBlock.

## What This Dataset Does Not Contain

- **No direct file read of usercustomize.py:** The dataset confirms the file was written (Sysmon EID 11, Security EID 4688 command line implies the write) and that the hook fired (Security chain ending in `calc.exe`), but the contents of `usercustomize.py` are not in the telemetry — they must be inferred from the `Out-File` command captured in PowerShell ScriptBlock logging.
- **No Sysmon EID 13:** No registry artifacts are involved in this technique.
- **No venv overhead:** Unlike T1546.018-1, this test uses the system Python directly and does not create a virtual environment. The event volume is accordingly much lower (48 Sysmon events vs 1,038).

## Assessment

This dataset is compact and high-fidelity. The complete attack flow — path discovery, file write, trigger, and payload execution — is documented across Sysmon EID 1, EID 11, and Security EID 4688. The process chain `python.exe → cmd.exe → calc.exe` in the Security log provides direct evidence of hook execution without needing to interpret the Python source code.

The key distinction from the defended variant is event volume rather than content: the undefended dataset captures 48 Sysmon events (vs 32 defended), likely because Defender's presence suppresses some DLL load telemetry through its own process scanning behavior. The attack completion is identical in both variants.

## Detection Opportunities Present in This Data

- **Sysmon EID 11:** `powershell.exe` writing a file named `usercustomize.py` to a path under `config\systemprofile\AppData\Roaming\Python\`. Writes to `usercustomize.py` by any non-Python-installer process are a direct indicator of this technique.
- **Security EID 4688:** `python.exe` spawning `cmd.exe` with a `calc.exe` argument, or any non-Python process appearing as a child of `python.exe`. The chain `python.exe → cmd.exe → <executable>` is a behavioral signature of `os.system()` calls from a Python hook.
- **Security EID 4688:** `powershell.exe` as the parent of `python.exe -c "import site; print(site.getusersitepackages())"`. Using Python programmatically to discover site-packages paths from a PowerShell context is not a normal administrative pattern.
- **PowerShell EID 4104:** `"import os; os.system('calc.exe')" | Out-File` with a `usercustomize.py` target filename appears verbatim in ScriptBlock logging. The combination of Python code in a string piped to `Out-File` targeting a Python startup module path is a specific and actionable indicator.
