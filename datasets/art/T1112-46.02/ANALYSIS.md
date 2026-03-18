# T1112-46: Modify Registry — Mimic Ransomware: Enable Multiple User Sessions

## Technique Context

T1112 (Modify Registry) is used here to mimic a behavior seen in ransomware operations: enabling multiple concurrent Terminal Services sessions by setting `AllowMultipleTSSessions` to `1` under `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon`. By default, Windows limits the number of concurrent interactive sessions; ransomware and other tools that need to maintain multiple simultaneous connections or operate across several user contexts sometimes modify this setting to remove that restriction.

The specific registry key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Winlogon`) controls user-level logon behavior. Writing to HKCU is notable because it affects the current user's session context rather than system-wide policy. However, since this test runs under `NT AUTHORITY\SYSTEM`, the HKCU hive being modified is the SYSTEM account's user profile — a technical detail that would appear unusual in legitimate use.

Multiple-session enablement supports ransomware operations by allowing the malware to maintain RDP sessions under different accounts simultaneously during encryption, and by ensuring session persistence is not limited by Windows' concurrent session enforcement. Real ransomware families including REvil variants have been documented using similar Winlogon modifications.

In the defended variant, this dataset produced 27 Sysmon, 12 Security, and 34 PowerShell events. The undefended capture produced 17 Sysmon, 4 Security, and 36 PowerShell events — closely matched counts, reflecting that Defender had limited interaction with this specific technique in the defended run as well.

## What This Dataset Contains

The technique's execution chain is captured in Sysmon EID 1 and Security EID 4688. `cmd.exe` (PID 1048) was spawned by PowerShell (PID 6692) with:

```
"cmd.exe" /c reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon /t REG_DWORD /v AllowMultipleTSSessions /d 1 /f
```

`cmd.exe` then spawned `reg.exe` (PID 5160) with:

```
reg  add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon /t REG_DWORD /v AllowMultipleTSSessions /d 1 /f
```

Security EID 4688 records both spawns with `NT AUTHORITY\SYSTEM` as the executing account and `C:\Windows\TEMP\` as the working directory for `cmd.exe`. The full registry key path, value name, data type, and value (`/d 1`) all appear verbatim in the command line.

Sysmon EID 1 shows `whoami.exe` (PID 6284) was executed by PowerShell immediately before the technique, a pre-execution identity check that is standard ART test framework behavior and visible in both Sysmon and Security process creation events.

Sysmon EID 10 (process access) records PowerShell accessing both `whoami.exe` and `cmd.exe` with access mask `0x1FFFFF`.

The PowerShell channel (36 EID 4104 events) contains ART test framework boilerplate, including a cleanup invocation: `Invoke-AtomicTest T1112 -TestNumbers 46 -Cleanup -Confirm:$false`.

## What This Dataset Does Not Contain

There are no Sysmon EID 12 or EID 13 events in this dataset. The sysmon-modular configuration does not capture registry writes to `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon`. This means the actual registry modification is not confirmed through registry telemetry — you can infer success from the clean process execution (exit code 0x0 visible in Security EID 4689, absence of error output), but there is no direct registry event corroborating the write.

The dataset contains no Terminal Services events, no session creation or termination events, and no evidence of concurrent sessions being established. The modification is captured; its operational use is not.

The initial ART test framework PowerShell processes are absent from Sysmon EID 1, as expected given the include-mode filtering.

## Assessment

This dataset's detection value is concentrated in process execution telemetry. The absence of registry modification events (EID 12/13) means a monitoring strategy that relies solely on registry telemetry would miss this specific modification. However, the command-line arguments captured in Security EID 4688 and Sysmon EID 1 contain all necessary information to identify the technique: the registry key path, the value name `AllowMultipleTSSessions`, the data type, and the value being written.

Compared to the defended variant, the undefended execution is structurally similar, with the slight difference that the defended run had a few additional Security events from Defender-related activity. Neither run triggered a blocking response from Defender for this specific modification, suggesting the technique falls below Defender's behavioral threshold when the registry path does not directly involve security-control keys.

The combination of `AllowMultipleTSSessions` registry modification under `SYSTEM` context, running from `C:\Windows\TEMP\`, is the primary detection signal.

## Detection Opportunities Present in This Data

**`reg.exe` command line with `AllowMultipleTSSessions`.** The value name is specific and uncommon in legitimate administrative activity. The full argument `/v AllowMultipleTSSessions /d 1` combined with the Winlogon path is a reliable indicator.

**HKCU Winlogon modifications under SYSTEM.** Writing to `HKEY_CURRENT_USER\...\Winlogon` while running as `NT AUTHORITY\SYSTEM` is structurally unusual. Under SYSTEM, HKCU maps to the SYSTEM account's profile, not a user's profile — a legitimate administrator enabling multiple sessions would do so through Group Policy or under the relevant user account.

**PowerShell → cmd.exe → reg.exe under SYSTEM from TEMP.** The three-hop chain with SYSTEM token and TEMP working directory is a recurring pattern in automated ART execution, but also characteristic of malware scripting chains. The presence of `whoami.exe` immediately preceding the `reg add` chain reinforces the scripted nature.

**Ransomware pre-staging pattern.** In a broader investigation context, `AllowMultipleTSSessions` modification paired with other defense evasion registry changes (such as disabling Defender notifications or modifying update policies) in the same time window is a strong behavioral cluster indicating ransomware preparation activity.
