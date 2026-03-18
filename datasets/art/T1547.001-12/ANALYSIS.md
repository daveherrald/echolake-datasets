# T1547.001-12: Registry Run Keys / Startup Folder — HKCU - Policy Settings Explorer Run Key

## Technique Context

T1547.001 covers Registry Run Keys and Startup Folder persistence. This test exercises the Group Policy-administered `Run` key under `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`. Unlike the standard `HKCU\...\Run` key, the Policies path is associated with Group Policy software installation and is less commonly monitored by endpoint security tools. Values written here cause the referenced executable to run at logon for the current user. Using a policy-path Run key can blend into environments where GPO-driven software deployment is common.

## What This Dataset Contains

The test executed from NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, domain `acme.local`). The payload creates the required registry keys if they do not exist and sets a value named `atomictest` pointing to `C:\Windows\System32\calc.exe` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`.

**Sysmon (47 events — Event IDs 1, 7, 10, 11, 13, 17):**
- Sysmon Event ID 13 (RegistrySetValue) is present, tagged `technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder`. The entry records: `TargetObject: HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\policies\Explorer\Run\atomictest`, `Details: C:\Windows\System32\calc.exe`, set by `powershell.exe` (PID 3428) as NT AUTHORITY\SYSTEM. The key path uses lowercase `policies` — matching exactly what was set.
- Sysmon Event ID 1 (ProcessCreate) captures `whoami.exe` (tagged `T1033`) and `powershell.exe` (tagged `T1059.001` because of the command-line pattern).
- Sysmon Event ID 7 (ImageLoad), Event ID 10 (ProcessAccess), and Event ID 17 (PipeCreate) are standard PowerShell initialization artifacts for two PowerShell instances.
- Sysmon Event ID 11 (FileCreate) records PowerShell startup profile data files.
- No Sysmon Event ID 29 (FileExecutableDetected) in this test — no executable file was staged in the filesystem, only a registry value pointing to an existing system executable.

**Security (10 events — Event IDs 4688, 4689, 4703):**
- Event ID 4688 records `powershell.exe` and `whoami.exe` creation. The `powershell.exe` entry shows the full command line including the conditional key creation logic and `Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name "atomictest" -Value "C:\Windows\System32\calc.exe"`.
- Event ID 4689 records process exits.
- Event ID 4703 records a token right adjustment.

**PowerShell (41 events — Event IDs 4103, 4104):**
- Event ID 4104 captures the test payload in both wrapper and body forms: the complete `if (!(Test-Path ...)) { New-Item ... } ... Set-ItemProperty ... "atomictest" ... "C:\Windows\System32\calc.exe"` sequence.
- Event ID 4103 records `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`.
- An empty profile script at the systemprofile Documents path is logged.
- Remaining 4104 events are runtime boilerplate.

## What This Dataset Does Not Contain

- No evidence of logon or execution of `calc.exe` via the Run key — the persistence mechanism was registered but not triggered.
- No Sysmon Event ID 29 (FileExecutableDetected). The payload points to an existing system binary, so no new executable was created in the filesystem.
- No Defender block events.
- No network events.
- Object access auditing is disabled.

## Assessment

This dataset cleanly captures the HKCU Policy Explorer Run key registration, with Sysmon Event ID 13 directly tagging the operation as T1547.001. The registry write is recorded with the exact key path, value name (`atomictest`), and data (`C:\Windows\System32\calc.exe`). The PowerShell script block provides the full context including the conditional key creation logic. The use of the Policies sub-path rather than the standard `Run` key path is the distinguishing characteristic of this technique variant.

## Detection Opportunities Present in This Data

- **Sysmon Event ID 13**: `SetValue` on `HKU\*\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\` — the sysmon-modular config tags this as T1547.001. Any value set here by a process other than `Group Policy Client` or a legitimate Group Policy agent should be investigated.
- **Security Event ID 4688**: `powershell.exe` command lines containing both `Policies\Explorer\Run` and `Set-ItemProperty`.
- **PowerShell Event ID 4104**: Script blocks that create registry keys under `HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` and set values pointing to executables.
- **Correlation**: The key path `Policies\Explorer\Run` differs from the commonly-monitored `Run` key. Detection rules targeting only the standard `Run` key would miss this variant.
- Baseline monitoring of values under `Policies\Explorer\Run` in environments where Group Policy does not legitimately use this key would provide a low-noise detection signal.
