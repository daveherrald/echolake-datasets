# T1562.001-19: Disable or Modify Tools — Disable Microsoft Office Security Features

## Technique Context

T1562.001 (Disable or Modify Tools) encompasses disabling application-layer security controls, not just endpoint protection software. Microsoft Office provides multiple security layers that block malicious document execution: Protected View (which opens untrusted documents in a sandboxed read-only mode), VBA macro execution warnings, and block-at-first-seen protections. Adversaries disable these controls through registry manipulation before delivering Office-based payloads.

This test targets Excel's security configuration, disabling four specific protections:
- `VBAWarnings = 1` — enables VBA macros without prompting (value 1 means "Enable all macros")
- `DisableInternetFilesInPV = 1` — disables Protected View for files downloaded from the Internet
- `DisableUnsafeLocationsInPV = 1` — disables Protected View for files opened from unsafe locations
- `DisableAttachementsInPV = 1` — disables Protected View for email attachments

Disabling all four simultaneously eliminates the primary defenses against malicious Excel documents: Protected View is bypassed (the document opens normally without sandboxing), and any embedded macros execute automatically without prompting. This preparation step is a prerequisite in phishing campaigns that deliver Excel-based payloads with malicious macros or XLSB/XLAM abuse.

The ART script uses PowerShell's `New-Item` and `New-ItemProperty` to create the registry keys under `HKCU:\Software\Microsoft\Office\16.0\Excel\Security\`.

## What This Dataset Contains

The dataset spans 7 seconds (2026-03-17 17:35:24–17:35:31 UTC) and contains 137 PowerShell events and 3 Security events.

The full attack command is captured in Security EID 4688:
```
"powershell.exe" & {New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\"
New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\"
New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView\"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security" -Name "VBAWarnings" -Value "1" -PropertyType "Dword"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Name "DisableInternetFilesInPV" -Value "1" -PropertyType "Dword"
[...DisableUnsafeLocationsInPV and DisableAttachementsInPV follow...]}
```

Security EID 4688 records 3 process creation events: `whoami.exe` (pre-check), the attack `powershell.exe` with the full multi-line `New-Item` / `New-ItemProperty` command, and a second `whoami.exe` (post-check). All run as `NT AUTHORITY\SYSTEM`.

The PowerShell events are 129 EID 4104 (script block logging) and 8 EID 4103 (module logging). The EID 4103 events record `CommandInvocation(New-ItemProperty)` for each registry value set, capturing the exact path, name, value, and property type:
- `HKCU:\Software\Microsoft\Office\16.0\Excel\Security` | `VBAWarnings` | `1` | `Dword`
- `HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView` | `DisableInternetFilesInPV` | `1` | `Dword`
- `HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView` | `DisableUnsafeLocationsInPV` | `1` | `Dword`
- `HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView` | `DisableAttachementsInPV` | `1` | `Dword`

These EID 4103 events also include the additional `ParameterBinding` entries for `New-ItemProperty`, including the `Path`, `Name`, `Value`, and `PropertyType` parameters with their exact values.

An important technical detail: the script targets `HKCU:` but execution runs as `NT AUTHORITY\SYSTEM`. Under SYSTEM, `HKCU` maps to `HKU\.DEFAULT` — the default user profile's registry hive, not any interactive user's profile. The registry writes affect the SYSTEM account's Office configuration, not any domain user's configuration. A real attacker would need to target the correct user hive for the attack to be effective against the logged-on user.

## What This Dataset Does Not Contain

No Sysmon events. This test continues the pattern seen throughout the 17:35:xx UTC test cluster: the Sysmon driver is in a degraded state following T1562.001-11, and no Sysmon events are generated. In the defended variant, Sysmon EID 13 (Registry value set) events tagged `RuleName: T1562,office` documented the four registry writes explicitly. Those events are absent here.

No Office application events. Office Trust Center does not generate Application log entries when its registry-based security settings are changed. No Excel diagnostic or audit events appear because Excel was not running.

No Security EID 4657 registry audit events. Object access auditing for registry keys is not enabled in this environment.

No validation that the registry writes succeeded. Without Sysmon EID 13 registry set events or Security EID 4657, the success of the registry modifications cannot be confirmed from the telemetry. The command line is present, but whether the `New-ItemProperty` calls completed without error requires either process exit code events (absent) or registry monitoring.

Compared to the defended variant (50 Sysmon, 10 Security, 64 PowerShell), this undefended run is identical in Security events (3 vs 10, slightly different) and has more PowerShell events (137 vs 64). The defended Sysmon EID 13 registry write events with their `T1562,office` RuleName annotations are the key artifacts absent here.

## Assessment

The Security EID 4688 command line and PowerShell EID 4103 module logging events provide complete documentation of the attack, including every registry key and value targeted. The absence of Sysmon registry events is a gap in this specific collection, but the PowerShell and Security channels together constitute a thorough record.

The SYSTEM-context issue (HKCU mapping to HKU\.DEFAULT) means this specific test does not actually affect interactive user sessions — it configures the SYSTEM account's Office preferences, which are not normally used. This is an ART test artifact, not representative of how a real attacker would execute this technique. An attacker would target specific user hives (e.g., `HKU\<user-SID>\Software\Microsoft\Office\...`) or run the commands in the context of the target user.

This nuance is worth understanding when using this dataset to build detection logic: your detection should trigger on the registry path pattern (`Software\Microsoft\Office\16.0\<app>\Security`) regardless of which hive root is targeted, since a real attacker may target HKCU, HKU\<SID>, or HKLM depending on their access level and target scope.

## Detection Opportunities Present in This Data

**Security EID 4688 / PowerShell EID 4103 — Registry paths**: `HKCU:\Software\Microsoft\Office\16.0\Excel\Security\VBAWarnings` with value `1` is the primary indicator. The combination of Office Security registry modification + `VBAWarnings = 1` (enable all macros) is a near-definitive indicator. Any monitoring that watches for writes to `Software\Microsoft\Office\16.0\<app>\Security\VBAWarnings` with value `1` will catch this technique regardless of the PowerShell execution path.

**PowerShell EID 4103 `New-ItemProperty` calls**: The module logging events capture `ParameterBinding(New-ItemProperty): name="Path"; value="HKCU:\Software\Microsoft\Office\16.0\Excel\Security"` with `name="Name"; value="VBAWarnings"` and `name="Value"; value="1"`. These specific name/value pairs in EID 4103 are searchable without complex parsing.

**Protected View keys in sequence**: Four `New-ItemProperty` or `reg add` calls targeting `Software\Microsoft\Office\16.0\<app>\Security\ProtectedView\` within a few seconds is anomalous. The three Protected View disable flags rarely change independently of each other in normal operations — simultaneous disabling of all three is characteristic of attack preparation.

**Sysmon EID 13 in healthy environments**: When Sysmon is operational, the sysmon-modular ruleset tags writes to Office Security registry paths with `RuleName: T1562,office` (as seen in the defended variant). This annotation makes the detection extremely specific and requires no additional correlation logic.

**SYSTEM context + Office Security paths**: PowerShell running as SYSTEM modifying `Software\Microsoft\Office\` registry paths is unusual. Legitimate Office configuration changes typically run in user context. SYSTEM-context Office registry writes narrow the field to administrative scripts or attackers with elevated access.
