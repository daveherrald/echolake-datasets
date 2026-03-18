# T1505.005-2: Terminal Services DLL — Modify Terminal Services DLL Path

## Technique Context

T1505.005 (Terminal Services DLL) covers adversary modification of `termsrv.dll` or the registry value that points to it. This test exercises the registry-redirect approach: rather than patching the DLL itself, the attacker copies `termsrv.dll` to a writable location under their control, modifies `HKLM\System\CurrentControlSet\Services\TermService\Parameters\ServiceDll` to point to the copy, and on the next TermService restart their version loads instead of the legitimate one. This is preferred over in-place patching because the copy avoids the file-locked-by-running-service problem, and the registry change is durable across reboots. In real intrusions this is combined with patching the copied DLL before redirecting the registry key.

## What This Dataset Contains

The test grants Administrators full control of `termsrv.dll`, copies it to `C:\Windows\system32\config\systemprofile\AtomicTest.dll` (the SYSTEM user's home directory), then writes that path into `TermService\Parameters\ServiceDll`.

**Sysmon (Event ID 13, RegistryValueSet)** — The definitive technique indicator:
```
TargetObject: HKLM\System\CurrentControlSet\Services\TermService\Parameters\ServiceDll
Details: C:\Windows\system32\config\systemprofile\AtomicTest.dll
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```
A `powershell.exe` process directly modifying `ServiceDll` under TermService is captured with the new value, process GUID, and user (`NT AUTHORITY\SYSTEM`).

**Sysmon (Event ID 29, FileExecutableDetected)** — `AtomicTest.dll` (a copy of `termsrv.dll`) is flagged when `powershell.exe` writes it to the SYSTEM profile directory. Hash: `SHA256=F7344AB9BFA487C25841F7546F0EB5FE23D863EF34A5EB432069A3474A76A1D8` (matches `termsrv.dll` — the copy is unmodified).

**Sysmon (Event ID 11, FileCreate)** — `C:\Windows\System32\config\systemprofile\AtomicTest.dll` creation event from `powershell.exe`.

**Sysmon (Event ID 1, ProcessCreate)** — Child `powershell.exe` with full command line including the registry modification logic and `termsrv.dll` ACL change:
```
"powershell.exe" & {$termsrvDll = "C:\Windows\System32\termsrv.dll"
$ACL = Get-Acl $termsrvDll
$permission = "Administrators","FullControl","Allow"
...
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\services\TermService\Parameters" -Name "ServiceDll" -Value $newServiceDll}
```

**PowerShell (Event ID 4104)** — Complete script block is captured, including the full `Set-ItemProperty` call with path, name, and value parameters visible.

**PowerShell (Event ID 4103)** — Per-cmdlet module logging records each step in sequence: `Get-Acl`, `New-Object` (FileSystemAccessRule), `Set-Acl`, `Copy-Item`, `Test-Path` (HKLM path check), `Set-ItemProperty` with the explicit `ServiceDll` name and new path value, and `Write-Host` confirming "ServiceDll value in the registry has been updated to: C:\Windows\system32\config\systemprofile\AtomicTest.dll". The `Write-Host` output confirms the `Set-ItemProperty` succeeded.

## What This Dataset Does Not Contain

- No TermService restart event. The service is not restarted after the registry modification, so `AtomicTest.dll` is never actually loaded into `svchost.exe`. No Sysmon Event 7 showing `AtomicTest.dll` loaded into a service process is present.
- No Sysmon Event 11 for a write to `termsrv.dll` itself — the original DLL is not patched.
- No Security audit policy object access events for the registry key — object access auditing is not enabled in this environment.
- The `ServiceDll` registry value is restored during ART cleanup (per-test isolation), but no corresponding cleanup registry write appears in this dataset's time window.

## Assessment

This is an excellent dataset for the registry-redirect variant of T1505.005. The Sysmon Event 13 alone is a near-dispositive indicator — `powershell.exe` writing to `TermService\Parameters\ServiceDll` with a value outside `%SystemRoot%\System32\` is not a legitimate operation. The stacking of Event 13 (registry), Event 29 (PE written by PowerShell), Event 11 (file create), and PowerShell 4103/4104 gives defenders four independent detection layers with correlated process GUIDs for pivoting. The main gap is the absence of a TermService load event to close the "did this actually execute?" question, which requires a service restart outside the test window.

## Detection Opportunities Present in This Data

1. **Sysmon Event 13** — Any write to `HKLM\System\CurrentControlSet\Services\TermService\Parameters\ServiceDll` with a value not equal to `%SystemRoot%\System32\termsrv.dll` is high-confidence malicious activity.
2. **Sysmon Event 13 + non-system path** — The value `C:\Windows\system32\config\systemprofile\AtomicTest.dll` is outside the expected DLL location and should trigger on path-based anomaly detection.
3. **Sysmon Event 29** — A PE file written to the SYSTEM profile directory (`config\systemprofile\`) by `powershell.exe` is anomalous.
4. **Sysmon Event 11 correlated with Event 13** — File creation of a DLL in an unusual path followed within seconds by a TermService registry write, both from the same ProcessGuid.
5. **PowerShell 4103** — `Set-ItemProperty` with `Name=ServiceDll` targeting `TermService\Parameters` is a precise string match that is trivially detectable in module logging.
6. **PowerShell 4104** — Script block containing both `termsrv.dll` and `Set-ItemProperty` or `ServiceDll` in the same block.
7. **Security 4688** — Child `powershell.exe` spawned with a command line referencing `TermService\Parameters` and `ServiceDll`.
