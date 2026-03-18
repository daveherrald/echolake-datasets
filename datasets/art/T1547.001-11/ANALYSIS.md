# T1547.001-11: Registry Run Keys / Startup Folder — Change Startup Folder - HKCU Modify User Shell Folders Startup Value

## Technique Context

T1547.001 covers Registry Run Keys and Startup Folder persistence. This test redirects the per-user startup folder by modifying `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` with the value name `Startup`. Windows uses this value to determine where to look for per-user startup items at logon. By pointing this value to an attacker-controlled directory containing malicious executables, an adversary achieves logon persistence for the affected user without using traditional Run keys. This is the HKCU counterpart to the HKLM `Common Startup` modification tested in T1547.001-10 — it affects only the current user rather than all users.

## What This Dataset Contains

The test executed from NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, domain `acme.local`). The payload creates `C:\Windows\Temp\atomictest\`, copies `calc.exe` there, and then modifies `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup` to point to that directory.

**Sysmon (40 events — Event IDs 1, 7, 10, 11, 13, 17, 29):**
- Sysmon Event ID 13 (RegistrySetValue) is present, tagged `technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder`. The entry records: `TargetObject: HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup`, `Details: C:\Windows\TEMP\atomictest\`, set by `powershell.exe` (PID 2096) as NT AUTHORITY\SYSTEM. This is the central persistence artifact and is the key difference from T1547.001-10, where no Event ID 13 was captured.
- Sysmon Event ID 1 (ProcessCreate) captures `whoami.exe` (tagged `T1033`) and a child `powershell.exe` (tagged `T1083` because of `New-Item` in the commandline).
- Sysmon Event ID 29 (FileExecutableDetected) records `calc.exe` being written to `C:\Windows\Temp\atomictest\` with full hashes.
- Sysmon Event ID 11 (FileCreate) records directory and file creation in `C:\Windows\Temp\atomictest\`.
- Sysmon Event ID 7 (ImageLoad), Event ID 10 (ProcessAccess), and Event ID 17 (PipeCreate) are standard PowerShell initialization artifacts.

**Security (10 events — Event IDs 4688, 4689, 4703):**
- Event ID 4688 records `powershell.exe` and `whoami.exe` creation, with the PowerShell entry showing the full command line: `"powershell.exe" & {New-Item -ItemType Directory -path "$env:TMP\atomictest\"...Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup" -Value "$env:TMP\atomictest\"}`
- Event ID 4689 records process exits.
- Event ID 4703 records a token right adjustment.
- Unlike T1547.001-10, this test did not involve WMI execution, so there are no 4624/4627/4672 logon events.

**PowerShell (40 events — Event IDs 4103, 4104):**
- Event ID 4104 captures both the outer wrapper and inner body of the test script, clearly showing `Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup" -Value "$env:TMP\atomictest\"`.
- Event ID 4103 records `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`.
- An empty profile script is logged at `C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`.
- Remaining 4104 events are runtime boilerplate.

## What This Dataset Does Not Contain

- No evidence of the modified startup folder being honored at logon — no logon was triggered.
- No Defender block events. The operation completed successfully.
- No network events.
- Object access auditing is disabled.
- Unlike T1547.001-10 (which used WMI invocation), this test was executed directly, so no WMI-related process creation or logon events appear.

## Assessment

This is one of the cleaner datasets in the T1547.001 series because Sysmon Event ID 13 directly captured the registry value modification with the T1547.001 technique tag. The combination of Event ID 13 (the registry write), Event ID 29 (the executable staged in the new startup directory), and Event ID 4104 (the full script) provides a complete picture of the attack chain. The value is set on `HKU\.DEFAULT` (the SYSTEM account's hive) because the test ran as SYSTEM, which in a real attack would typically target a regular user's `HKCU`.

## Detection Opportunities Present in This Data

- **Sysmon Event ID 13**: `SetValue` on `HKU\*\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup` or `Common Startup` — this is a high-fidelity indicator; the sysmon-modular config tags it directly as T1547.001.
- **Sysmon Event ID 29 (FileExecutableDetected)**: Executables appearing in newly created directories that are registered as startup locations.
- **Security Event ID 4688**: `powershell.exe` command lines containing `User Shell Folders` and `Startup` in the same invocation.
- **PowerShell Event ID 4104**: Script blocks that modify `User Shell Folders` registry values, particularly in combination with file copy operations into the target path.
- **Correlation**: Sysmon ID 13 for the registry modification correlated with Sysmon ID 29 for an executable appearing in the redirected path provides a high-confidence combined detection.
