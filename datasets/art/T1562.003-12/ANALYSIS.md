# T1562.003-12: Impair Command History Logging — Disable Windows Command Line Auditing Using PowerShell Cmdlet

## Technique Context

T1562.003 covers techniques that impair command history logging. Test 12 achieves the same
outcome as test 11 (disabling Security 4688 command-line arguments) but uses a PowerShell
cmdlet instead of reg.exe. The invocation uses `New-ItemProperty` to write
`ProcessCreationIncludeCmdLine_Enabled = 0` to the Audit policy key:
`HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit`. This is a PowerShell-
native alternative to the reg.exe approach, producing a different telemetry profile.

## What This Dataset Contains

**Sysmon (37 events):** Sysmon ID 1 captures the PowerShell process launched by the ART test framework:

```
"powershell.exe" & {New-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\
Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 0
-PropertyType DWORD -Force -ErrorAction Ignore}
```

Sysmon ID 13 records the registry write:
- `TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled`
- `Details: DWORD (0x00000000)`
- RuleName: `technique_id=T1548.002` (same cross-label as test 11)

Sysmon 7 (image loads), 10 (process access), 11 (file create for PS profile), and 17 (named
pipe) events document the PowerShell process lifecycle. Unlike test 11, no cmd.exe or reg.exe
child processes appear.

**Security (12 events):** 4688/4689 for the PowerShell process and cleanup processes. Token
adjustment (4703) for the PowerShell session. No logon cluster. Fewer events than test 11
because no WmiPrvSE intermediary is present — the test framework dispatches directly.

**PowerShell (38 events):** Script block logging (4104) captures the full technique body:

```
& {New-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
-Name "ProcessCreationIncludeCmdLine_Enabled" -Value 0 -PropertyType DWORD -Force -ErrorAction Ignore}
```

Module logging (4103) records `New-ItemProperty` with all parameter bindings including the exact
path, name, value (`0`), and property type (`DWORD`). ART test framework boilerplate (`Set-ExecutionPolicy
Bypass`, error-handling fragments) fills the remainder of the PS events.

## What This Dataset Does Not Contain (and Why)

**No cmd.exe or reg.exe.** This variant is PowerShell-only; defenders relying solely on reg.exe-
based signatures will not catch it.

**No Security 1100 or Event Log service restart.** The audit policy key change takes effect
immediately for new processes; no service restart is needed.

**No post-change proof of blind spot.** As with test 11, the dataset captures the enabling action
but not its consequence on subsequent 4688 events.

**No Sysmon 12 (registry key create).** The `HKLM\...\Policies\System\Audit` key already exists
on this system; only a value write (Sysmon 13) occurs.

**Sysmon-modular ProcessCreate filtering** applies; the PowerShell process is captured because it
matches the T1059.001 PowerShell include rule.

## Assessment

The test completed successfully. The registry write is confirmed by Sysmon 13 and by PowerShell
4103 module logging. The PowerShell script block provides a complete, independently verifiable
record of the attack. Compared to test 11, this variant generates richer PowerShell telemetry
but no reg.exe/cmd.exe trail — a meaningful difference for detection engineering.

## Detection Opportunities Present in This Data

- **Sysmon 13:** Write to `ProcessCreationIncludeCmdLine_Enabled` with value 0 — same high-
  fidelity indicator as test 11, independent of execution mechanism.
- **PowerShell 4103:** `New-ItemProperty` with path `HKLM:Software\Microsoft\Windows\
  CurrentVersion\Policies\System\Audit`, name `ProcessCreationIncludeCmdLine_Enabled`, value `0`
  is a precise, behaviorally specific indicator.
- **PowerShell 4104:** The SDDL-free script block targeting the audit policy key with value 0 is
  signable and distinct from test 11's reg.exe approach.
- **Sysmon 1 / Security 4688:** PowerShell command line containing `ProcessCreationIncludeCmdLine_Enabled`
  and `-Value 0` is directly detectable.
- **Coverage comparison with test 11:** A detection strategy covering both reg.exe (Sysmon 13 +
  4688) and PowerShell (4103/4104 + Sysmon 13) is needed; neither mechanism alone covers both
  variants.
