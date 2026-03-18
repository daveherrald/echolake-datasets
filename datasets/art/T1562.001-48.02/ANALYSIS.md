# T1562.001-48: Disable or Modify Tools — Tamper with Windows Defender Registry - Reg.exe

## Technique Context

MITRE ATT&CK T1562.001 covers disabling or modifying security tools. This test uses `reg.exe` to write a comprehensive set of Windows Defender policy registry values that disable nearly every Defender protection component. The values are written to `HKLM\Software\Policies\Microsoft\Windows Defender` and its subkeys (`Real-Time Protection`, `Reporting`, `SpyNet`, `MpEngine`) using the Group Policy path rather than the direct Defender settings path. Writing through the policy keys can bypass Tamper Protection on some Windows versions because these paths are treated as legitimate Group Policy overrides. This is a bulk disablement technique — the single `cmd.exe` invocation chains 14 separate `reg.exe` calls covering real-time protection, behavior monitoring, IOAV, script scanning, cloud submission, and PUA protection in one shot.

## What This Dataset Contains

The dataset spans roughly five seconds and captures 117 events across PowerShell (96) and Security (21) channels.

**Security (EID 4688):** 21 process creation events document the full execution. PowerShell (PID 0x40d4) spawns `whoami.exe` (ART test framework identity check), then spawns `cmd.exe` (PID 0x39d4) with a long chained command containing all 14 `reg add` invocations:

```
"cmd.exe" /c reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >NUL 2>nul & reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f >NUL 2>nul & reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >NUL ...
```

`cmd.exe` then spawns individual `reg.exe` processes sequentially. Each `reg.exe` call is captured separately in Security 4688 with its specific command line, for example:

```
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIntrusionPreventionSystem" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScriptScanning" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg  add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
```

All processes run as `NT AUTHORITY\SYSTEM` (S-1-5-18, ACME\ACME-WS06$) with `TokenElevationTypeDefault (1)` and System integrity label.

**PowerShell (EID 4103 + 4104):** 96 events. One EID 4103 (module logging) records `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` with full parameter binding context confirming `User = ACME\SYSTEM`. EID 4104 events are predominantly ART test framework boilerplate. The cleanup invocation block `Invoke-AtomicTest T1562.001 -TestNumbers 48 -Cleanup -Confirm:$false` appears in 4104, and `$ErrorActionPreference = 'Continue'` is recorded.

## What This Dataset Does Not Contain

**No Sysmon events.** The defended variant captured 59 Sysmon events including EID 13 (RegistryValue Set) confirming every individual registry write to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\*`, plus EID 1 (process create) for each `reg.exe` call with parent-chain annotations. None of that Sysmon telemetry is present here.

**No Defender service modification.** Writing to policy keys does not stop or restart the Defender service. The values take effect on next Defender refresh or reboot. No service control events (EID 7036 or 4689 for `MsMpEng.exe`) appear.

**No registry value confirmation beyond Security 4688.** In the absence of Sysmon EID 13 events, there is no independent log source confirming that each registry write succeeded — only the process creation records showing the commands were issued.

**Fewer events than the defended variant.** The defended run produced 59 Sysmon + 46 Security + 34 PowerShell events (139 total). The undefended run produced 96 PowerShell + 21 Security events (117 total). The difference is entirely the missing Sysmon channel.

## Assessment

The technique executed successfully. Every one of the 14 `reg.exe` invocations is captured in Security EID 4688 with the exact command line, target path, value name, and data. Because Defender was disabled in this environment, there was no Tamper Protection to block the writes, no Defender alert, and no MpCmdRun.exe activity. The policy keys were written without interference.

This dataset is valuable precisely because Defender was already disabled: you can see the complete, unimpeded execution trace. In a real attack, these writes would typically follow an initial Defender bypass or arrive via a privileged process that Tamper Protection does not scrutinize, and the resulting telemetry would look exactly like this.

The undefended dataset has more PowerShell events than the defended variant (96 vs. 34) because the PowerShell channel captured more test framework activity across multiple runspace startups, and the absence of Sysmon means less selective filtering was applied.

## Detection Opportunities Present in This Data

- **Security EID 4688:** `reg.exe` command lines targeting `HKLM\Software\Policies\Microsoft\Windows Defender` with value names like `DisableAntiSpyware`, `DisableRealtimeMonitoring`, or `DisableBehaviorMonitoring` — any single one of these is a high-confidence indicator; seeing 14 in rapid succession from `cmd.exe` is unambiguous.
- **Security EID 4688:** The parent `cmd.exe` process contains the complete chained command in its command-line field, providing a single event that documents the entire attack intent before any individual `reg.exe` process is created.
- **Volume and velocity:** 14 `reg.exe` processes spawned by `cmd.exe` within a few seconds, all targeting the same registry tree, is a pattern with essentially no legitimate analog in normal Windows administration.
- **PowerShell EID 4103:** The `Set-ExecutionPolicy Bypass` with `User = ACME\SYSTEM` context confirms a scripted execution environment and provides a behavioral anchor point for correlation.
