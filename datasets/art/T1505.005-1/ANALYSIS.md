# T1505.005-1: Terminal Services DLL — Simulate Patching termsrv.dll

## Technique Context

T1505.005 (Terminal Services DLL) covers adversary replacement or modification of `termsrv.dll`, the core DLL for Windows Remote Desktop Services (TermService). The canonical attacker objective is to patch the DLL to remove the single-session RDP limit (enabling concurrent RDP connections without a Terminal Server license), or to replace it with a malicious DLL that executes attacker code every time a Remote Desktop connection is established. Because `TermService` runs as `NT AUTHORITY\NETWORK SERVICE` and loads `termsrv.dll` at service start, a malicious replacement provides persistent, privileged code execution triggered by any incoming RDP session. Detection engineering focuses on writes to `C:\Windows\System32\termsrv.dll`, ACL changes on that file, and changes to `HKLM\System\CurrentControlSet\Services\TermService\Parameters\ServiceDll`.

## What This Dataset Contains

This test simulates the file-patching approach: it grants Administrators full control of `termsrv.dll`, makes a backup copy, attempts to append a null byte to modify the DLL in place, then restores from backup. The result is rich multi-source telemetry covering the ACL change, file operations, and the failed in-place write.

**Sysmon (Event ID 1, ProcessCreate tagged `technique_id=T1059.001`)** — The child `powershell.exe` process is captured with the full script in its command line argument, including `Get-Acl`, `Set-Acl`, `Copy-Item`, `Add-Content`, and `Move-Item` targeting `termsrv.dll`.

**Sysmon (Event ID 11, FileCreate)** — `C:\Windows\System32\termsrv_backup.dll` is created by `powershell.exe`. This is the backup copy of the original DLL, created before the attempted in-place patch.

**Sysmon (Event ID 29, FileExecutableDetected)** — Sysmon flagged `termsrv_backup.dll` as a PE/executable file written by `powershell.exe`, with full SHA256 hash `F7344AB9BFA487C25841F7546F0EB5FE23D863EF34A5EB432069A3474A76A1D8`. This is a high-fidelity event: a PowerShell process writing a file that Sysmon identifies as a PE executable directly to `C:\Windows\System32\`.

**PowerShell (Event ID 4104, script block)** — The complete script is captured:
```
$termsrvDll = "C:\Windows\System32\termsrv.dll"
$ACL = Get-Acl $termsrvDll
$permission = "Administrators","FullControl","Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$ACL.SetAccessRule($accessRule)
Set-Acl -Path $termsrvDll -AclObject $ACL
Copy-Item -Path "C:\Windows\System32\termsrv.dll" -Destination "C:\Windows\System32\termsrv_backup.dll"
Add-Content -Path "C:\Windows\System32\termsrv.dll" -Value "`n" -NoNewline -ErrorAction Ignore
Move-Item -Path "C:\Windows\System32\termsrv_backup.dll" -Destination "C:\Windows\System32\termsrv.dll" -Force
```

**PowerShell (Event ID 4103, module logging)** — Individual cmdlet invocations are recorded: `Get-Acl` (path: `termsrv.dll`), `New-Object` (type: `FileSystemAccessRule`), `Set-Acl`, `Copy-Item`, and `Add-Content` (with a `NonTerminatingError`: "The process cannot access the file … because it is being used by another process"). The `Move-Item` also logs a `NonTerminatingError`: "Cannot create a file when that file already exists." Both errors indicate the in-place modification failed but the ACL change and backup copy succeeded.

**System (Event ID 7040)** — BITS service start type changed from demand to auto start. This is a side effect of the WMI activity event listener established during the test run, not directly related to the technique.

**WMI (Event ID 5860)** — A temporary WMI subscription for `Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` was registered by SYSTEM. This is a WMI side effect from the ART test framework.

**Security (Event IDs 4624, 4627, 4672)** — Logon and special privilege events appear, reflecting the SYSTEM logon context used during execution.

## What This Dataset Does Not Contain

- No Sysmon Event 13 (registry value set) — this test does not modify `TermService\Parameters\ServiceDll`. That path is covered by T1505.005-2.
- The `Add-Content` call failed because `termsrv.dll` is held open by TermService; the actual DLL was not modified. No hash change on `termsrv.dll` itself is observable.
- No TermService restart event — the test does not restart the service after the (failed) patch attempt.
- Sysmon Event 11 does not show a write to `termsrv.dll` itself — only the backup copy is captured.

## Assessment

This is a high-quality dataset for detection engineering against the termsrv.dll abuse pattern. The combination of Sysmon Event 29 (PE written to System32 by PowerShell), Sysmon Event 11 (backup DLL created), PowerShell 4104 (full script), and PowerShell 4103 (per-cmdlet invocation with error messages) gives defenders multiple independent detection layers. The module logging error messages ("being used by another process") are useful for distinguishing live system tests from lab-only scenarios. The one gap — no registry modification — is addressed by the companion dataset T1505.005-2.

## Detection Opportunities Present in This Data

1. **Sysmon Event 29** — `powershell.exe` writing a PE file (EventID 29, FileExecutableDetected) to `C:\Windows\System32\` is a near-unconditional high-severity alert.
2. **Sysmon Event 11** — Creation of `termsrv_backup.dll` or any DLL with a `_backup` suffix in `System32` by a non-SYSTEM service process.
3. **PowerShell 4104** — Script block containing `Set-Acl` and `termsrv.dll` in the same execution context. The combination of ACL modification targeting a service DLL is an exceptionally rare legitimate activity.
4. **PowerShell 4103** — `Get-Acl` + `Set-Acl` + `Copy-Item` + `Add-Content` targeting `C:\Windows\System32\termsrv.dll` in a single PowerShell session.
5. **Security 4688 / Sysmon Event 1** — Child `powershell.exe` spawned with command line containing `termsrv.dll` and `Set-Acl` or `Get-Acl`.
6. **Sysmon Event 1 tagged `technique_id=T1059.001`** — The sysmon-modular config correctly annotated this process create; teams using rule-tag-based alerting will see this as a first-pass triage signal.
