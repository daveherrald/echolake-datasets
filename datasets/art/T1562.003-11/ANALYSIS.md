# T1562.003-11: Impair Command History Logging — Disable Windows Command Line Auditing Using reg.exe

## Technique Context

T1562.003 covers techniques that impair command history logging. This test uses `reg.exe` to
write a DWORD value of 0 to
`HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled`,
disabling the inclusion of command-line arguments in Security event 4688 (process creation)
records. When this value is 0, process creation events are logged but without the command line —
blinding analysts to the specific commands run. This is a lightweight, dependency-free technique
executed via a cmd.exe wrapper.

## What This Dataset Contains

**Sysmon (22 events):** Sysmon ID 1 captures the attack chain — a WmiPrvSE.exe process (the ART
execution test framework uses WMI for remote invocation), followed by the PowerShell test framework process,
then cmd.exe and reg.exe with the full command line:

```
"cmd.exe" /c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0 /f
```

Sysmon ID 13 records the registry write directly:
- `TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled`
- `Details: DWORD (0x00000000)`
- RuleName: `technique_id=T1548.002` (UAC bypass — a Sysmon rule cross-label)

Sysmon 7 (image load) and 17 (named pipe) events capture the PowerShell test framework startup. Sysmon
10 (process access) events are present for test framework-related cross-process activity.

**Security (14 events):** 4688/4689 for the execution chain: WmiPrvSE.exe, PowerShell test framework,
cmd.exe, reg.exe, and cleanup processes. Token adjustment (4703) for the PowerShell process. No
logon cluster — execution runs under the existing SYSTEM session. Importantly, the 4688 for
reg.exe is captured here, including the process command line (auditing is still enabled at this
point and is only disabled by the test's action itself).

**PowerShell (34 events):** ART test framework boilerplate — `Set-ExecutionPolicy Bypass`, standard
error-handling script blocks (`$_.PSMessageDetails`, etc.). No technique-specific PowerShell
cmdlet is invoked here; the actual attack uses cmd.exe/reg.exe, so no 4103/4104 with
`ProcessCreationIncludeCmdLine` appears.

## What This Dataset Does Not Contain (and Why)

**No proof that auditing was actually disabled for subsequent processes.** The dataset shows the
registry write; it does not include any post-attack process creation event that would demonstrate
missing command-line arguments — that would require a follow-on collection window.

**No Group Policy processing events.** The registry change takes effect immediately for new
processes without requiring a GP refresh.

**No 4688 command-line blind spot in this dataset.** Because auditing was active throughout the
collection window, all 4688 events include command lines. The *effect* of this technique would
only appear in subsequent logs.

**Sysmon-modular include filtering** restricts ProcessCreate coverage. WmiPrvSE and reg.exe are
captured because they match known LOLBin/WMI rules. Generic cmd.exe might not always be caught.

## Assessment

The test completed successfully. The registry write is confirmed by both Sysmon 13 and Security
4688 for reg.exe with the exact command line. The technique is entirely captured within this
dataset. The irony of this technique — that it relies on command-line logging to document its own
execution — is reflected in the data: the 4688 for the disabling command itself contains the
command line.

## Detection Opportunities Present in This Data

- **Sysmon 13:** Write to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled`
  with value 0 is a precise, high-fidelity indicator with no legitimate use case.
- **Sysmon 1 / Security 4688:** `reg.exe` or `reg add` with `ProcessCreationIncludeCmdLine_Enabled`
  and `/d 0` in the command line.
- **Security 4688:** cmd.exe spawning reg.exe with the audit policy path is low-noise and
  detectable even without Sysmon.
- **PowerShell 4104 absence:** The lack of technique-specific script blocks in the PS log is
  itself informative — this variant uses cmd/reg, not PowerShell cmdlets.
- **Baseline monitoring:** Any write setting `ProcessCreationIncludeCmdLine_Enabled=0` should be
  treated as a critical alert given its direct impact on detection coverage.
