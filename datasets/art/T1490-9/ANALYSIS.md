# T1490-9: Inhibit System Recovery — Disable System Restore Through Registry

## Technique Context

T1490 (Inhibit System Recovery) covers attacker actions that delete, disable, or modify backup and recovery mechanisms to prevent victims from restoring their systems after a destructive attack. Ransomware operators in particular treat this as a prerequisite step: before encrypting data, they ensure Windows System Restore, Volume Shadow Copies, and Backup Catalog entries are neutralized so that recovery without paying the ransom is difficult. Test 9 specifically targets the Group Policy registry path for System Restore — a less commonly instrumented surface than the `vssadmin` or `wbadmin` commands that appear in most ransomware playbooks. The detection community focuses heavily on shadow copy deletion (`vssadmin delete shadows`) and BCDEdit modifications, so registry-based System Restore disabling receives comparatively less attention. This test is useful for filling that gap.

## What This Dataset Contains

The primary technique evidence is carried by Sysmon Event ID 1 (ProcessCreate) and Security Event ID 4688 (Process Creation with command-line auditing). The execution chain is:

```
powershell.exe (NT AUTHORITY\SYSTEM)
  └─ cmd.exe /c reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
             & reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f
             & reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
             & reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f
       └─ reg.exe (×4 individual invocations)
```

Sysmon captures this at two levels: the chained `cmd.exe` launch with the full multi-command line visible in the `CommandLine` field, and each of the four `reg.exe` invocations as separate Event ID 1 records. The Sysmon rule tags the `cmd.exe` launch as `technique_id=T1059.003` and the `reg.exe` invocations as `technique_id=T1012`. Security 4688 events corroborate with identical command-line content. The full command line is available in both channels.

Both registry paths are modified: the Group Policy path (`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore`) and the native System Restore path (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore`), each receiving `DisableConfig=1` and `DisableSR=1`. Notably, Sysmon Event ID 13 (RegistryValue Set) is **absent** from this dataset — the registry writes were performed by `reg.exe` CLI rather than via an API that Sysmon's registry monitoring hooks intercept directly. The sysmon-modular config in use does not capture all registry writes via ID 13 for these paths.

The PowerShell channel contains only ART test framework boilerplate: repeated `Set-StrictMode` and `Set-ExecutionPolicy -Bypass` script blocks with no technique-specific content. The actual technique was executed through a child `cmd.exe` process, not inline PowerShell.

## What This Dataset Does Not Contain

- **Sysmon Event ID 13 (RegistryValue Set)**: The four registry writes that are the core of this technique are not captured as registry events. The sysmon-modular config does not include rules matching these System Restore key paths. A dedicated registry-monitoring rule targeting `DisableSR` and `DisableConfig` under `SystemRestore` keys would be needed.
- **No `vssadmin` or `wbadmin` activity**: This test is narrowly scoped to registry modification only; shadow copy deletion and other recovery inhibition methods are not present.
- **No Sysmon Event ID 12 (RegistryKey Create/Delete)**: The test adds to existing keys rather than creating new ones.
- **No audit policy Object Access logging**: The environment has object access auditing set to `none`, so no Security 4656/4663 file or registry object access events are generated.

## Assessment

This dataset provides high-quality, low-ambiguity technique evidence. The command lines are unambiguous and specific: four `reg.exe` add operations targeting well-known System Restore registry keys are recorded across both Sysmon and Security channels with full command-line logging. The parent-child process chain from `powershell.exe` through `cmd.exe` to `reg.exe` is fully visible, making this suitable for multi-step correlation rules. The dataset would be stronger with Sysmon Event ID 13 coverage of the actual registry writes — that would allow registry-event-based detections without relying on process command-line parsing. Adding the `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore` path to Sysmon registry monitoring would round this out.

## Detection Opportunities Present in This Data

1. **Process command-line matching on `reg.exe` targeting `SystemRestore` registry keys** — Security 4688 or Sysmon Event ID 1 with `CommandLine` containing `DisableSR` or `DisableConfig` under `SystemRestore` paths.
2. **Parent-child chain: `cmd.exe` spawned by `powershell.exe` with chained `reg add` commands** — Sysmon Event ID 1 shows `cmd.exe /c reg add … & reg add …` with parent `powershell.exe`, a pattern consistent with scripted registry manipulation.
3. **Multiple `reg.exe` launches in rapid succession from the same parent `cmd.exe`** — Four `reg.exe` processes sharing the same parent PID within milliseconds is detectable via process sequencing or burst rules.
4. **`reg.exe` running as `NT AUTHORITY\SYSTEM` with `IntegrityLevel: System`** — Legitimate System Restore configuration changes do not typically occur via interactive `reg.exe` commands under SYSTEM context.
5. **Command-line string matching for both Group Policy and CurrentVersion SystemRestore paths in a single `cmd.exe` invocation** — The combined command line targeting both policy and native paths simultaneously is a high-confidence indicator of deliberate recovery inhibition rather than administrative activity.
