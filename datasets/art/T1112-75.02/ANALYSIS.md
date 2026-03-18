# T1112-75: Modify Registry — Enforce Smart Card Authentication Through Registry

## Technique Context

T1112 (Modify Registry) is used here to set `scforceoption` to `1` in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`. The `scforceoption` value corresponds to the Group Policy setting "Interactive logon: Require smart card." When enabled, this policy requires all interactive logons to use a smart card, blocking password-based console and RDP authentication.

This is a disruptive technique rather than a stealth one. Enabling `scforceoption` on a system where smart cards are not deployed causes interactive logons to fail for all users, effectively locking the console and blocking RDP sessions that use password credentials. Ransomware operators and destructive threat actors apply this setting to prevent administrators from logging in to compromised systems during an attack—complementing RDP-disabling techniques like `fDenyTSConnections` (T1112-74) and creating defense-in-depth lockout through multiple mechanisms.

The key path `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` is a high-value target. It hosts numerous security-relevant values including `EnableLUA` (UAC), `ConsentPromptBehaviorAdmin`, `scforceoption`, and others. Modifications to any value in this key path warrant investigation. In the context of a broader attack, `scforceoption` enforcement is typically applied alongside other lockout or persistence steps.

## What This Dataset Contains

This dataset captures the `scforceoption` registry modification on a Windows 11 Enterprise domain workstation with Defender disabled. Events occur at approximately 2026-03-17T16:35:05Z to 16:35:06Z, in the same session as T1112-74 and the other March 17 tests.

The attack chain is PowerShell (SYSTEM) → cmd.exe → reg.exe. Sysmon EID 1 captures both child processes:

- `cmd.exe` (PID 16788, ProcessGuid `{9dc7570a-82b9-69b9-cf39-000000000900}`, RuleName `technique_id=T1059.003`) with command line: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v scforceoption /t REG_DWORD /d 1 /f`
- `reg.exe` (PID 14532, ProcessGuid `{9dc7570a-82b9-69b9-d139-000000000900}`, RuleName `technique_id=T1012`) with command line: `reg  add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v scforceoption /t REG_DWORD /d 1 /f`

Both run from `C:\Windows\TEMP\` as `NT AUTHORITY\SYSTEM`. Security EID 4688 independently records the same process chain.

The Sysmon EID breakdown (7: 9, 1: 4, 10: 3, 17: 1, 13: 1) is structurally consistent with neighboring tests. The EID 13 event in the full dataset records the write to the `Policies\System` key. The PowerShell channel contains 35 EID 4104 events including the cleanup wrapper `Invoke-AtomicTest T1112 -TestNumbers 75 -Cleanup`.

## What This Dataset Does Not Contain

There is no evidence of logon failures or authentication changes resulting from the `scforceoption` modification in this dataset. The test is the registry write in isolation; no interactive logons were attempted afterward in the captured window.

Security EID 4657/4663 events are absent—no SACL on the `Policies\System` key by default. The EID 13 event for the direct write is in the full dataset but not in the sample subset.

No accompanying modifications to related values in the same key (`EnableLUA`, `ConsentPromptBehaviorAdmin`, etc.) appear—this test touches only `scforceoption`.

## Assessment

The undefended dataset (Sysmon: 18, Security: 4, PowerShell: 35) versus the defended variant (Sysmon: 38, Security: 14, PowerShell: 34) shows the largest Sysmon differential in this batch: 38 versus 18 events. This suggests the defended environment generated substantially more Sysmon activity around the `Policies\System` key modification—likely because Defender monitors modifications to security policy keys more aggressively than, for example, Terminal Services settings. With Defender disabled, only the core process creation and DLL load events are generated.

The Security channel also shows a larger reduction here (14 → 4) than in tests targeting less security-critical key paths, consistent with the interpretation that Defender's active monitoring of policy key modifications accounts for the additional events.

The technique evidence quality is equal between variants: the full command line writing `scforceoption=1` to the Policies\System path is fully captured.

## Detection Opportunities Present in This Data

**Process creation command line (Sysmon EID 1 / Security EID 4688):** The command line `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v scforceoption /t REG_DWORD /d 1 /f` is captured in both channels. Modifications to `Policies\System` via `reg.exe` from a PowerShell-spawned process are a strong indicator.

**Policies\System key family (Sysmon EID 13):** The direct registry write event targets one of the most security-sensitive key paths on Windows. Detection coverage for any write to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` from non-SYSTEM service processes (Group Policy enforcement would use different process context) covers a broad range of defense evasion behaviors including this one.

**`scforceoption` value specifically:** Setting `scforceoption=1` on a system not provisioned for smart card authentication will cause interactive logon failures. Detecting this value at `1` and correlating with subsequent authentication failures provides a complete picture of the disruptive impact.

**Process ancestry from TEMP (Sysmon EID 1):** The shared process chain pattern (PowerShell → cmd.exe → reg.exe from `C:\Windows\TEMP\` at SYSTEM) connects this test to the broader cluster of T1112 tests in the same session, supporting temporal correlation across multiple registry modification alerts.
