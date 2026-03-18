# T1547.001-13: Registry Run Keys / Startup Folder — HKLM - Policy Settings Explorer Run Key

## Technique Context

T1547.001 covers Registry Run Keys and Startup Folder persistence. This test exercises the machine-wide policy-administered Run key at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`. Unlike the HKCU variant (T1547.001-12), this HKLM path requires administrative privileges to write but causes the registered executable to run at logon for all users on the system, not just the current user. The `Policies\Explorer\Run` path is associated with Group Policy software deployment and is less frequently monitored than the canonical `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` key, making it an evasion opportunity in environments with GPO-heavy tooling.

## What This Dataset Contains

The test executed from NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, domain `acme.local`). The payload conditionally creates `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` if it does not exist, then sets a value named `atomictest` pointing to `C:\Windows\System32\calc.exe`.

**Sysmon (43 events — Event IDs 1, 7, 10, 11, 13, 17):**
- Sysmon Event ID 13 (RegistrySetValue) is present, tagged `technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder`. The entry records: `TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\atomictest`, `Details: C:\Windows\System32\calc.exe`, set by `powershell.exe` (PID 6484) as NT AUTHORITY\SYSTEM.
- Sysmon Event ID 1 (ProcessCreate) captures `whoami.exe` (tagged `T1033`) and `powershell.exe` (tagged `T1059.001`).
- Sysmon Event ID 7 (ImageLoad), Event ID 10 (ProcessAccess), and Event ID 17 (PipeCreate) are standard PowerShell initialization artifacts.
- Sysmon Event ID 11 (FileCreate) records PowerShell startup profile data files.
- No Sysmon Event ID 29. The payload references an existing system binary; no new executable was created.

**Security (10 events — Event IDs 4688, 4689, 4703):**
- Event ID 4688 records `powershell.exe` and `whoami.exe` creation. The PowerShell entry shows the full command line: `"powershell.exe" & {if (!(Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")) { New-Item -ItemType Key -Path "HKLM:\..." } Set-ItemProperty -Path "HKLM:\...\Policies\Explorer\Run" -Name "atomictest" -Value "C:\Windows\System32\calc.exe"}`.
- Event ID 4689 records process exits.
- Event ID 4703 records a token right adjustment.

**PowerShell (40 events — Event IDs 4103, 4104):**
- Event ID 4104 captures the test payload in both wrapper and body forms, clearly showing the conditional key creation and `Set-ItemProperty` writing `atomictest` = `C:\Windows\System32\calc.exe` to `HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`.
- Event ID 4103 records `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`.
- An empty profile script at the systemprofile Documents path is logged.
- Remaining 4104 events are runtime boilerplate.

## What This Dataset Does Not Contain

- No logon trigger or execution of `calc.exe` — persistence registered but not triggered.
- No Sysmon Event ID 29.
- No Defender block events.
- No network events.
- Object access auditing is disabled.

## Assessment

This dataset is structurally similar to T1547.001-12 (the HKCU variant) but targets HKLM, granting persistence for all users rather than just the current user. Sysmon Event ID 13 directly captures the registry write with the T1547.001 technique tag, providing the highest-fidelity detection artifact. The key distinction from the more commonly monitored `HKLM\...\Run` path is the `Policies\Explorer\Run` subpath, which detection rules targeting only the canonical Run key would miss.

## Detection Opportunities Present in This Data

- **Sysmon Event ID 13**: `SetValue` on `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\` — tagged as T1547.001 by sysmon-modular. This path should rarely if ever be written by interactive or scripted processes; legitimate Group Policy management goes through the policy client service, not `powershell.exe`.
- **Security Event ID 4688**: `powershell.exe` command lines containing `HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`.
- **PowerShell Event ID 4104**: Script blocks that create registry keys and set Run values under the Policies path.
- **Comparison with T1547.001-12**: The HKLM variant requires admin privileges (SYSTEM in this case). Seeing this modification from a standard user context would indicate privilege escalation has already occurred.
- Both HKCU (test -12) and HKLM (test -13) variants write a value named `atomictest` — in real attacks the value name would be something that blends in with legitimate software names. Detection should focus on the key path rather than the value name.
