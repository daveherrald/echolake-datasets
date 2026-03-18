# T1562.001-56: Disable or Modify Tools — Disable EventLog-Application ETW Provider Via Registry - Cmd

## Technique Context

MITRE ATT&CK T1562.001 covers disabling or modifying security tools and logging infrastructure. This test disables a specific ETW provider registered under the `EventLog-Application` Auto Logger session by setting the `Enabled` value to `0` for the provider GUID `{B6D775EF-1436-4FE6-BAD3-9E436319E218}` under `HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{B6D775EF-1436-4FE6-BAD3-9E436319E218}`. This is a more surgical approach than disabling the entire Auto Logger session (T1562.001-54): rather than stopping all EventLog-Application collection, this disables a single ETW provider within that session. The provider GUID corresponds to a specific telemetry source feeding the Application event log. This granular technique can reduce specific log categories while leaving the overall logging infrastructure intact, making it harder to detect as wholesale log tampering.

## What This Dataset Contains

**Security (4688):** Two process creation events capture the execution chain:
1. Parent PowerShell spawning `cmd.exe` with:
   ```
   "cmd.exe" /c reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{B6D775EF-1436-4FE6-BAD3-9E436319E218}" /v "Enabled" /t REG_DWORD /d "0" /f
   ```
2. `cmd.exe` spawning `reg.exe` executing the same command directly.

Both processes exit with status 0x0. The Security log also captures the test framework PowerShell and `conhost.exe` lifecycle events.

**Sysmon Event 1:** Process creation for `whoami.exe`, `cmd.exe`, and `reg.exe` with full command lines. The `reg.exe` command line shows the full provider GUID subkey path and `Enabled = 0`.

**Sysmon Events 7, 10, 17:** DLL loads, cross-process access, and pipe creation from the test framework PowerShell — standard noise from the ART execution infrastructure.

**PowerShell (4104):** The ART test framework `Set-ExecutionPolicy Bypass` script blocks are present. The technique command does not appear in a 4104 event because it is executed via `cmd.exe`, not as a PowerShell expression.

## What This Dataset Does Not Contain (and Why)

**No Sysmon 13 (RegistryValue Set):** The Sysmon registry monitoring configuration does not capture writes to the `WMI\Autologger\EventLog-Application\{GUID}` path. Only the `reg.exe` command line evidences the write.

**No provider GUID resolution:** The dataset does not contain information identifying what specific ETW provider `{B6D775EF-1436-4FE6-BAD3-9E436319E218}` represents. Resolving this GUID requires cross-referencing the system's ETW provider manifest registry (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers`).

**No PowerShell technique script block:** The technique runs via `cmd.exe`/`reg.exe`, so no 4104 script block containing the technique content is generated.

**No contrast with a PowerShell variant in this dataset:** Unlike the Auto Logger session tests (54 and 55), there is no corresponding PowerShell variant for the ETW provider disablement in this dataset collection.

**Minimal Sysmon event count (17 events):** This is the smallest Sysmon dataset in this series, reflecting the simple cmd/reg execution path and the lack of Sysmon 13 for this registry path.

## Assessment

The technique executed successfully with `reg.exe` exiting 0x0. The dataset is relatively sparse — the primary artifacts are the `cmd.exe` and `reg.exe` process creation events with the full provider GUID and `Enabled = 0` in the command lines. The absence of Sysmon 13 for this path is the same coverage gap seen in T1562.001-54. The provider GUID `{B6D775EF-1436-4FE6-BAD3-9E436319E218}` is the key pivot point for detection: monitoring registry writes under `WMI\Autologger\*\{GUID}\Enabled = 0` covers this class of ETW provider disablement regardless of which specific session or provider is targeted.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon 1:** `reg.exe` with command line containing `WMI\Autologger\EventLog-Application\{` and `/v Enabled /d 0` — specific ETW provider disablement
- **Sysmon 1:** `cmd.exe` from `powershell.exe` with the full GUID provider path and `Enabled = 0`
- **Broad pattern:** `reg.exe` or `reg add` with `\Autologger\` and `/v Enabled /d 0` in any command line — covers ETW provider disablement across any Auto Logger session
- **Security 4688 execution chain:** `powershell.exe → cmd.exe → reg.exe` targeting an `\Autologger\` registry path is anomalous and detectable
- **Registry state hunt:** Periodic queries for any `Enabled = 0` values under `HKLM\System\CurrentControlSet\Control\WMI\Autologger\*\{GUID}\Enabled` — covers persistence of this configuration change after reboot
