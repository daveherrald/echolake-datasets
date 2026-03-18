# T1546.018-2: Python Startup Hooks — Windows

## Technique Context

T1546.018 covers adversary abuse of Python startup hooks — special Python modules that are automatically imported whenever the Python interpreter starts. This test exercises the `usercustomize.py` hook, which Python loads from the user site-packages directory at interpreter startup before any user code runs. An adversary who can write to the user site-packages path gains automatic code execution any time Python is invoked under that user context. On Windows, the path resolves through `site.getusersitepackages()`, which for the SYSTEM account points to `C:\Windows\System32\config\systemprofile\AppData\Roaming\Python\Python312\site-packages\`.

## What This Dataset Contains

The test executed from NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, domain `acme.local`). The payload is a two-step PowerShell script: first, it calls `python.exe -c "import site; print(site.getusersitepackages())"` to discover the correct user site-packages path, then writes `import os; os.system('calc.exe')` to `usercustomize.py` in that directory, and finally invokes `python.exe` a second time to trigger the hook.

**Sysmon (32 events — Event IDs 1, 7, 10, 11, 17):**
- Sysmon Event ID 11 (FileCreate) records the creation of `usercustomize.py` at `C:\Windows\System32\config\systemprofile\AppData\Roaming\Python\Python312\site-packages\usercustomize.py` by `powershell.exe` via `Out-File`. This is the central persistence artifact.
- Sysmon Event ID 1 (ProcessCreate) records `C:\Program Files\Python312\python.exe` launching `cmd.exe`, which in turn spawns `calc.exe` — the hook execution chain. The cmd.exe process has RuleName `technique_id=T1059.003`.
- Sysmon Event ID 1 also records `whoami.exe` launched by the ART test framework for identity validation.
- Sysmon Event ID 7 (ImageLoad) records .NET runtime DLLs, Defender platform DLLs (`MpOAV.dll`, `MpClient.dll`), and `urlmon.dll` loading into `powershell.exe` — standard PowerShell process startup artifacts.
- Sysmon Event ID 10 (ProcessAccess) records `powershell.exe` accessing child processes it spawns, tagged with `technique_id=T1055.001` by the sysmon-modular rules (standard parent-child access patterns).
- Sysmon Event ID 17 (PipeCreate) records the named pipe `\PSHost.<...>.powershell` created by each PowerShell instance.

**Security (16 events — Event IDs 4688, 4689, 4703):**
- Event ID 4688 records process creation for `powershell.exe`, `python.exe`, `cmd.exe`, `calc.exe`, and `whoami.exe` with full command lines, all running as `S-1-5-18` (SYSTEM).
- Event ID 4689 records the corresponding exits for each process.
- Event ID 4703 records a token right adjustment for the PowerShell process, typical of SYSTEM-context execution.

**PowerShell (33 events — Event IDs 4103, 4104):**
- Event ID 4104 (ScriptBlock) captures the complete ART test payload: the wrapped call that invokes `python.exe -c "import site; print(site.getusersitepackages())"`, creates the directory, writes the hook file with `Out-File`, and triggers Python to load it.
- Event ID 4103 (Module logging) records `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` — standard ART test framework setup — and individual cmdlet invocations including `Test-Path`, `New-Item`, `Out-File`, and `Get-ChildItem`.
- The profile script at `C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` is logged as an empty scriptblock, confirming it was present but contained no content.
- Remaining 4104 events are PowerShell runtime boilerplate (error-handling lambdas: `$_.PSMessageDetails`, `$_.ErrorCategory_Message`, `$_.OriginInfo`, `$this.Exception.InnerException.PSMessageDetails`).

## What This Dataset Does Not Contain

- No registry modification events. This persistence mechanism does not use the Windows registry.
- No Sysmon Event ID 13 (RegistrySetValue). Persistence is file-based only.
- No network events. The test is entirely local.
- No Defender block events. The test completed successfully; `calc.exe` launched and exited normally (exit status `0x0`).
- No events showing Python importing `usercustomize.py` from the Python interpreter's perspective — that visibility would require ETW or Python-specific instrumentation.
- No Event ID 4656/4663 (object access auditing). The audit policy has object access set to none.
- The Sysmon ProcessCreate filter (include-mode, matching known-suspicious patterns) captured `python.exe` creating `cmd.exe` and `calc.exe` because `cmd.exe` matched the T1059.003 rule. Generic `python.exe` invocations without suspicious child processes may not be captured by Sysmon's include filter.

## Assessment

The test executed successfully end-to-end: `usercustomize.py` was written and Python honored it immediately, spawning `calc.exe`. This dataset provides a realistic and complete example of file-based Python startup hook persistence. The most forensically significant artifact — the hook file creation at `usercustomize.py` — is clearly recorded in Sysmon Event ID 11. The full payload is also reconstructible from PowerShell script block logging (Event ID 4104).

## Detection Opportunities Present in This Data

- **Sysmon Event ID 11**: File creation of any file named `usercustomize.py` or `sitecustomize.py` in a Python `site-packages` directory, especially by `powershell.exe` or other scripting hosts rather than a package manager.
- **Sysmon Event ID 11**: File creation of any executable or script under `C:\Windows\System32\config\systemprofile\AppData\Roaming\Python\` by non-Python processes.
- **Security Event ID 4688**: `python.exe` spawning `cmd.exe` or other shells, particularly under SYSTEM context.
- **Security Event ID 4688**: `Out-File` or `New-Item` writing `.py` files to user site-packages paths.
- **PowerShell Event ID 4104**: Script blocks referencing `site.getusersitepackages()`, `usercustomize`, or writing to Python site-packages paths via `Out-File`.
- **PowerShell Event ID 4103**: `Out-File` cmdlet invocations targeting `*.py` files in AppData-rooted Python paths.
- **Sysmon Event ID 1**: `python.exe` launching `cmd.exe` as a child process — uncommon in normal Python usage and a strong behavioral indicator of hook execution.
