# T1562.001-57: Disable or Modify Tools — Disable EventLog-Application ETW Provider Via Registry - PowerShell

## Technique Context

T1562.001 (Disable or Modify Tools) covers adversary actions to impair defenses by disabling or degrading security tooling. This test targets the Windows ETW (Event Tracing for Windows) subsystem by setting a registry value that disables a specific ETW provider used by the Application event log. Specifically, it sets `Enabled = 0` on the `EventLog-Application` autologger entry for provider GUID `{B6D775EF-1436-4FE6-BAD3-9E436319E218}` under `HKLM\System\CurrentControlSet\Control\WMI\Autologger`. Disabling this provider silences a source of event log telemetry without stopping the Event Log service, making the change quieter than a service stop. This is a registry-only technique requiring no binary drop — the entire action is accomplished with a single PowerShell `New-ItemProperty` call.

## What This Dataset Contains

The dataset spans roughly six seconds and captures 105 events across PowerShell (99) and Security (6) channels.

**Security (EID 4688):** Four process creation events document the execution. PowerShell (parent) spawns `whoami.exe` (ART test framework identity check), then spawns a child `powershell.exe` with the attack command embedded in its command line:

```
"powershell.exe" & {New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{B6D775EF-1436-4FE6-BAD3-9E436319E218}" -Name Enabled -Value 0 -PropertyType "DWord" -Force}
```

A second `whoami.exe` appears at cleanup time. Also present is a background process creation for `MpCmdRun.exe`:

```
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MpCmdRun.exe" GetDeviceTicket -AccessKey 2CF0BB6A-AB06-1687-B7E9-3847BCC2602F
```

This is Windows Defender's telemetry/device registration subprocess — a background activity from MsMpEng.exe unrelated to the technique itself.

**Security (EID 4663 + 4657):** Two events directly confirming the registry modification:

- EID 4663 (object access — key access): Process `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (PID 0x3f30, SYSTEM) accessed `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{b6d775ef-1436-4fe6-bad3-9e436319e218}` with `Access Mask: 0x2` (Set key value).

- EID 4657 (registry value modified): The same registry object, value name `Enabled`, changed from `REG_DWORD: 1` to `REG_DWORD: 0` (new value shown as `REG_DWORD: ...` — the change is confirmed). Operation type: "Existing registry value modified."

These two security events are only present because the undefended environment has enhanced auditing active on this registry key. This is the most precise possible confirmation that the ETW provider was disabled.

**PowerShell (EID 4103 + 4104):** 99 events. EID 4103 appears twice: one records `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` (test framework setup), and another records `New-ItemProperty` cmdlet execution with all parameter bindings. EID 4104 events are predominantly boilerplate error-handling closures repeated across three PowerShell runspace startups, plus the cleanup invocation `Invoke-AtomicTest T1562.001 -TestNumbers 57 -Cleanup`.

## What This Dataset Does Not Contain

**No Sysmon events.** The defended variant captured 36 Sysmon events including EID 7 (image loads), EID 10 (process access), EID 11 (file creates for PS profile), EID 17 (named pipe creation), and EID 1 (process creates for `whoami.exe` and child PowerShell). None of that Sysmon telemetry is present here.

**No Sysmon EID 13 (RegistryValue Set).** In the defended variant there was also no Sysmon registry event, because the sysmon-modular configuration does not include a rule matching the `WMI\Autologger` path. The undefended dataset compensates with Security EID 4657, which actually provides stronger confirmation because it records both the old value (1) and the new value (0), not just the write.

**No ETW provider behavior change confirmation.** The dataset shows the registry write succeeding but does not capture the downstream effect — there is no test of whether Application event log telemetry was actually suppressed following the change.

## Assessment

The technique executed successfully. The Security EID 4657 event is the definitive confirmation: `Enabled` changed from `1` to `0` on the `EventLog-Application` ETW autologger provider GUID. The EID 4663 access event and the EID 4688 process creation together form a complete chain from process launch through registry modification.

Compared to the defended variant (36 Sysmon + 10 Security + 38 PowerShell = 84 events), the undefended run produced 99 PowerShell + 6 Security events (105 total). The higher PowerShell count reflects additional test framework activity across multiple runspace instances. The security channel is richer in the undefended run because EID 4657 and 4663 appear — in the defended run those events were absent due to audit policy differences. The undefended run thus provides stronger registry write confirmation despite having no Sysmon data.

The MpCmdRun.exe background process is a real-world artifact from Defender's cloud telemetry subsystem. It is unrelated to the technique and represents authentic environmental noise co-collected with the attack telemetry.

## Detection Opportunities Present in This Data

- **Security EID 4657:** Registry value `Enabled` set to `0` on any path matching `HKLM\...\WMI\Autologger\EventLog-*\{...}` — this is a direct, high-confidence indicator of ETW provider suppression.
- **Security EID 4663:** `powershell.exe` accessing any `WMI\Autologger` registry key with `Set key value` access mask.
- **Security EID 4688:** Child `powershell.exe` spawned by `powershell.exe` with `New-ItemProperty` targeting `HKLM:\System\CurrentControlSet\Control\WMI\Autologger` in the command-line field.
- **PowerShell EID 4103:** `New-ItemProperty` cmdlet invoked against the autologger path with `Value=0` and `PropertyType=DWord` — module logging captures this with full parameter context even without the command line.
