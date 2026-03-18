# T1112-66: Modify Registry — Disabling ShowUI Settings of Windows Error Reporting (WER)

## Technique Context

T1112 (Modify Registry) is used here to suppress Windows Error Reporting dialogs by setting `DontShowUI` to `1` in `HKCU\Software\Microsoft\Windows\Windows Error Reporting`. When this value is present and set, WER silently discards crash reports rather than displaying dialog boxes to the user or prompting for developer mode reporting.

Adversaries disable WER to reduce operational visibility. Malicious tooling—particularly injected shellcode, rootkits, and unstable implants—frequently causes application crashes or unhandled exceptions. If WER is active, these crashes generate dialog boxes, event log entries (EID 1000, 1001, 1002), and dump files that security teams can analyze. Disabling the UI removes the user-facing notification and reduces the likelihood of a crash triggering an investigation. This pattern is particularly common in ransomware pre-staging and long-term persistence scenarios where operational silence is a priority.

The target hive (`HKCU`) is notable: this test writes to the current user's hive rather than `HKLM`, meaning the modification is user-scoped. When executed as `NT AUTHORITY\SYSTEM`, `HKCU` maps to the SYSTEM account's hive. This limits the effect to processes running as SYSTEM, but in the context of ransomware or system-wide malware, that is the relevant scope.

## What This Dataset Contains

This dataset captures the complete DontShowUI registry modification on a Windows 11 Enterprise domain workstation with Defender disabled. Events occur in the same continuous session as T1112-63 through T1112-66, with this test running approximately 32 seconds after T1112-63 started (2026-03-14T23:53:25Z to 23:53:26Z).

The attack chain is PowerShell (SYSTEM) → cmd.exe → reg.exe. Sysmon EID 1 captures both child processes:

- `cmd.exe` (PID 3244, ProcessGuid `{9dc7570a-f4f5-69b5-e212-000000000600}`, RuleName `technique_id=T1059.003`) with command line: `"cmd.exe" /c reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f`
- `reg.exe` (PID 1216, ProcessGuid `{9dc7570a-f4f5-69b5-e412-000000000600}`, RuleName `technique_id=T1012`) with command line: `reg  add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f`

Both run from `C:\Windows\Temp\` at System integrity. Security EID 4688 records the same process chain independently.

The Sysmon EID breakdown (7: 9, 1: 4, 10: 3, 17: 1) is structurally identical to T1112-64 and T1112-65, confirming this test runs in the same PowerShell process context with the same execution test framework pattern.

The PowerShell channel contains 55 EID 4104 events—notably more than the 36 seen in neighboring tests. This elevated count reflects additional script block fragments generated during the Invoke-AtomicTest execution, including WER-related cleanup scripting. The cleanup wrapper `Invoke-AtomicTest T1112 -TestNumbers 66 -Cleanup` is visible in the sample set.

## What This Dataset Does Not Contain

No Security EID 4657 or 4663 events appear—the HKCU WER path has no SACL by default. The EID 13 registry write event exists in the full dataset but is not represented in the sample subset.

There is no downstream evidence of WER suppression taking effect—no crash events, no WER telemetry, no application fault records. The test is a single-point registry write.

The modification targets `HKCU` (the SYSTEM account's hive in this execution context), not a system-wide setting. Processes running as other users or under different service accounts would not be affected by this specific write.

## Assessment

The undefended dataset (Sysmon: 17, Security: 4, PowerShell: 55) compared to the defended variant (Sysmon: 27, Security: 12, PowerShell: 34) shows two interesting differences. First, the Security channel shrinks from 12 to 4 events as expected when Defender is absent. Second, the PowerShell channel grows from 34 to 55—this increase reflects additional script block logging activity in the undefended environment, likely because AMSI interception is absent and certain script paths that Defender would have intercepted (and possibly short-circuited) instead execute to completion, generating more EID 4104 fragments.

The core technique evidence—the command line with `HKCU\Software\Microsoft\Windows\Windows Error Reporting`, `DontShowUI`, and value `1`—is fully present and equally detectable in both variants.

## Detection Opportunities Present in This Data

**Process creation command line (Sysmon EID 1 / Security EID 4688):** The full command line writing `DontShowUI=1` to the WER registry path is captured in both channels. WER path modifications via `reg.exe` are uncommon in normal operations and straightforward to detect.

**HKCU vs. HKLM distinction:** This test writes to `HKCU` rather than `HKLM`. Detection logic covering WER suppression should address both hives: `HKCU\Software\Microsoft\Windows\Windows Error Reporting` (user-scoped) and `HKLM\Software\Microsoft\Windows\Windows Error Reporting` (system-wide). Modifications to either path warrant investigation.

**Registry value set (Sysmon EID 13):** The full dataset includes the direct write event. Combined with the process context (reg.exe from TEMP at SYSTEM integrity), this provides a high-confidence detection path.

**Process lineage from TEMP (Sysmon EID 1):** The PowerShell → cmd.exe → reg.exe chain executing from `C:\Windows\Temp\` at SYSTEM integrity is the shared indicator across this T1112 cluster and remains the most reliable field-observable pattern.
