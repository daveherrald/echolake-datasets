# T1562-1: Impair Defenses — Windows Disable LSA Protection

## Technique Context

T1562 (Impair Defenses) covers adversary actions that disable or weaken security controls to reduce the risk of detection or to enable subsequent credential theft. This test targets LSA Protection, a Windows security feature that runs the Local Security Authority (lsass.exe) as a Protected Process Light (PPL). When RunAsPPL is enabled, it prevents unprivileged processes — including many credential dumping tools — from reading LSASS memory. Disabling RunAsPPL is a prerequisite for credential theft tools that cannot operate against PPL-protected processes.

## What This Dataset Contains

The dataset captures 84 events across Sysmon, Security, and PowerShell logs collected during a 6-second window on 2026-03-14 at 01:21 UTC.

The core registry modification is captured in both Sysmon and Security. The command sequence visible in the data:

```
"cmd.exe" /c reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0 /f
```

Key observations from the data:

- Sysmon EID 13 (RegistryValueSet) records the modification: `TargetObject: HKLM\System\CurrentControlSet\Control\Lsa\RunAsPPL`, `Details: DWORD (0x00000000)`, performed by `reg.exe` as NT AUTHORITY\SYSTEM. The RuleName is `technique_id=T1547.002,technique_name=Authentication Package` — the sysmon-modular rule annotates LSA registry writes under the authentication package rule.
- Sysmon EID 1 fires for `whoami.exe` (T1033 rule), then for `cmd.exe` (T1134 — Access Token Manipulation rule, triggered by the LSA key write pattern), then for `reg.exe` (also T1134). The T1134 annotation here reflects the sysmon-modular rule that flags LSA-related registry operations under Access Token Manipulation, not an actual token manipulation event.
- Security EID 4688 records `cmd.exe` with full command line showing the `reg add ... RunAsPPL ... /d 0` invocation, spawned by `powershell.exe` as SYSTEM.
- Security EID 4688 records `reg.exe` with the full command: `reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0 /f`.
- Security EID 4703 records token right adjustment for the SYSTEM process.
- Sysmon EID 7 (ImageLoad) fires for PowerShell's DLL load chain with standard rule annotations.
- Sysmon EID 17 records the PowerShell named pipe creation.
- PowerShell EID 4104 and 4103 contain ART test framework boilerplate (error-handling scriptblocks and `Set-ExecutionPolicy` bypass).

The `/d 0` value sets RunAsPPL to disabled, removing LSA protection. This change requires a reboot to take effect, so no lsass.exe access events appear in this dataset.

## What This Dataset Does Not Contain (and Why)

**No LSASS access events.** Disabling LSA Protection via registry requires a reboot. The dataset captures the configuration change but not any subsequent credential theft attempt. There are no Sysmon EID 10 events targeting lsass.exe.

**No Security audit policy change events (EID 4657, 4719).** Object access auditing is not enabled in this environment (`audit_policy.object_access: none`), so registry key write events at the Security log level are not present. Sysmon EID 13 provides this coverage instead.

**No cleanup/restoration of RunAsPPL.** The ART cleanup step would restore the original value, but that activity falls outside the dataset time window.

**No reboot event.** LSA protection changes do not take effect until reboot, but the dataset captures no system restart.

## Assessment

This dataset provides strong telemetry for a registry-based LSA Protection bypass attempt. The Sysmon EID 13 event directly records the RunAsPPL value being set to zero, and the Security EID 4688 events preserve the full command-line chain from PowerShell through cmd.exe to reg.exe. The combination gives both the behavioral context (how the command was invoked) and the specific registry impact (what was changed). The sysmon-modular rule annotations on EID 1 events (T1134 for `cmd.exe`, T1134 for `reg.exe`) are a Sysmon rule artifact reflecting the config's approach to flagging LSA-related operations — the labels describe the defensive context rather than the parent technique. This is a complete, actionable dataset for LSA Protection bypass detection training.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: `TargetObject` matching `HKLM\System\CurrentControlSet\Control\Lsa\RunAsPPL` with a value of `DWORD (0x00000000)` — direct evidence of LSA Protection being disabled.
- **Security EID 4688**: `reg.exe` with command line containing `HKLM\SYSTEM\CurrentControlSet\Control\LSA`, `RunAsPPL`, and `/d 0` — enables detection without Sysmon.
- **Sysmon EID 1**: `reg.exe` spawned by `cmd.exe` spawned by `powershell.exe` as SYSTEM, with LSA-related command line — process chain detection.
- **Correlation**: `whoami.exe` immediately preceding LSA registry modification as SYSTEM indicates automated post-exploitation execution, not administrative maintenance.
- **Baseline deviation**: `RunAsPPL` being set to 0 from a previously non-zero value (or the key being written where it previously didn't exist) is detectable via registry change baselining.
