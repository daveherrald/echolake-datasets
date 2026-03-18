# T1546.011-2: Application Shimming — New Shim Database Files Created in the Default Shim Database Directory

## Technique Context

T1546.011 (Application Shimming) exploits the Windows Application Compatibility Framework, which allows legacy applications to run on modern Windows versions by redirecting API calls or patching in-memory behavior via Shim Database (.sdb) files. Attackers abuse this mechanism to achieve persistence and, in some cases, privilege escalation: a shim installed against a system binary will execute the shim payload each time that binary runs, including under elevated contexts. The detection community focuses on file writes to `C:\Windows\apppatch\Custom\` and `C:\Windows\apppatch\Custom\Custom64\` (the standard shim drop locations), registry modifications under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\`, and unexpected execution of `sdbinst.exe` to install new shim databases.

## What This Dataset Contains

The test copies a pre-built shim database (`T1546.011CompatDatabase.sdb`) into both Custom shim directories. The central evidence lives in Sysmon Event ID 11 (File Created), where two writes are captured with `RuleName: technique_id=T1546.011,technique_name=Application Shimming`:

- `C:\Windows\apppatch\Custom\T1546.011CompatDatabase.sdb`
- `C:\Windows\apppatch\Custom\Custom64\T1546.011CompatDatabase.sdb`

Both are written by `powershell.exe` running as `NT AUTHORITY\SYSTEM`.

The Security channel (Event ID 4688) provides the full command line via the test framework:

```
"powershell.exe" & {Copy-Item "C:\AtomicRedTeam\atomics\T1546.011\bin\T1546.011CompatDatabase.sdb"
  C:\Windows\apppatch\Custom\T1546.011CompatDatabase.sdb
Copy-Item "C:\AtomicRedTeam\atomics\T1546.011\bin\T1546.011CompatDatabase.sdb"
  C:\Windows\apppatch\Custom\Custom64\T1546.011CompatDatabase.sdb}
```

PowerShell script block logging (Event ID 4104) also captures the `Copy-Item` block verbatim, and a profile load event shows the SYSTEM profile at `C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` was executed, confirming Sysmon Event ID 1 caught this as a child PowerShell process (`technique_id=T1059.001`).

## What This Dataset Does Not Contain

- **No `sdbinst.exe`** execution: the test drops files directly via `Copy-Item` rather than installing them through the Windows shim installer. A real attacker deploying a functional shim for persistence would typically run `sdbinst.exe`. That execution chain and any resulting AppCompat event log entries are absent.
- **No registry writes**: shim registration under `AppCompatFlags\Custom\` or `AppCompatFlags\InstalledSDB\` does not occur here — that is covered in T1546.011-3.
- **No shim activation events**: there is no evidence of the shim actually triggering, so there are no downstream child process creations attributable to shim execution.
- **Sysmon ProcessCreate filtering**: the test framework's outer PowerShell process is not captured by Sysmon Event ID 1; only the spawned child PowerShell (which matches the `T1059.001` include rule) appears. The outer process is only visible via Security 4688.
- The PowerShell channel beyond the `Copy-Item` script block consists entirely of internal test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy -Scope Process -Bypass`, `$_.PSMessageDetails`).

## Assessment

This is a clean, well-labeled dataset for file-placement detections. The Sysmon Event ID 11 records carry accurate rule tags for T1546.011. The Security 4688 command line and the PowerShell 4104 script block both reproduce the `Copy-Item` operation faithfully. The data is useful for tuning file-create rules on the Custom apppatch directories and for testing that script block logging correctly surfaces drop payloads. It is weaker as a full-lifecycle dataset because neither the installation step (`sdbinst.exe`) nor any shim-triggered execution is present.

## Detection Opportunities Present in This Data

1. **Sysmon Event ID 11 — file creation in `apppatch\Custom\`**: Alert on any process writing a `.sdb` file to `C:\Windows\apppatch\Custom\` or `C:\Windows\apppatch\Custom\Custom64\`. The rule tag `technique_id=T1546.011` is already applied in sysmon-modular.
2. **Security Event ID 4688 — PowerShell copying to apppatch**: Correlate a PowerShell process with a command line referencing `apppatch\Custom` as a destination, running as SYSTEM outside of a software installation context.
3. **PowerShell Event ID 4104 — script block containing Copy-Item to apppatch**: Monitor for script blocks containing file copy operations targeting `apppatch\Custom` paths.
4. **Anomalous .sdb file presence**: Scheduled or on-demand file integrity checks on `C:\Windows\apppatch\Custom\` for unexpected `.sdb` files not present in a baseline.
5. **Absence of sdbinst.exe before .sdb drop**: A shim database appearing in the Custom directory without a preceding `sdbinst.exe` execution is itself anomalous and worth alerting on as a behavioral gap.
