# T1112-34: Modify Registry — Windows Add Registry Value to Load Service in Safe Mode without Network

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique in which adversaries write to Windows registry keys to alter system behavior, disable security controls, or survive remediation attempts. This test creates a registry key under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\` that causes a named service to load during safe mode boots.

Safe mode persistence is particularly durable because users and incident responders frequently boot into safe mode when attempting to clean an infected system. If an attacker's service loads in safe mode, it can interfere with that cleanup — re-establishing footholds, deleting forensic artifacts, or running before security tools initialize. The `SafeBoot\Minimal` subkey controls which drivers and services are permitted to start when Windows boots with the minimal safe mode driver set. Adding an entry there is a documented persistence technique used by ransomware families and advanced implants.

In the defended variant of this dataset (Defender enabled, Windows 11 with sysmon-modular), the same execution chain produced 28 Sysmon events, 12 Security events, and 35 PowerShell events. This undefended capture produced 18 Sysmon events, 4 Security events, and 61 PowerShell events. The reduction in Security events reflects the absence of Defender-related process creation events; the increase in PowerShell events reflects more verbose script block logging activity from the ART test framework without Defender suppression effects.

## What This Dataset Contains

The registry modification at the heart of this technique is captured directly by Sysmon Event ID 13 (Registry value set):

```
TargetObject: HKLM\System\CurrentControlSet\Control\SafeBoot\Minimal\AtomicSafeMode\(Default)
Details: Service
```

This single event tells you the key that was written, the value name (the default value), and the data written (`Service`). The image responsible is not recorded in this sample's EID 13 message text, but the process chain leading to it is fully documented in surrounding events.

The execution chain is captured across two event sources. Sysmon EID 1 records `cmd.exe` process creation with command line:

```
"cmd.exe" /c REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\AtomicSafeMode" /VE /T REG_SZ /F /D "Service"
```

That `cmd.exe` (PID 6920) was spawned by PowerShell (PID 4316). `cmd.exe` then spawned `reg.exe` (PID 3328) with:

```
REG  ADD "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\AtomicSafeMode" /VE /T REG_SZ /F /D "Service"
```

Security EID 4688 independently corroborates both spawns. The `cmd.exe` event (Creator PID 0x10dc = PowerShell) and the subsequent `reg.exe` event both appear with full command lines and with `NT AUTHORITY\SYSTEM` as the executing user.

Sysmon EID 7 (image load) shows PowerShell loading multiple DLLs, including entries tagged with `technique_id=T1059.001,technique_name=PowerShell` and `technique_id=T1055,technique_name=Process Injection`. Sysmon EID 10 (process access) shows PowerShell accessing child processes with full access rights. Sysmon EID 17 records a named pipe creation for PowerShell's host process (`\PSHost...`).

The PowerShell channel contains 61 EID 4104 (script block logging) events. Most are short boilerplate fragments (`{ Set-StrictMode -Version 1; $_.OriginInfo }`, `Set-ExecutionPolicy Bypass`) that reflect ART test framework initialization rather than the technique itself. One script block captures the test framework calling `Invoke-AtomicTest T1112 -TestNumbers 34`.

## What This Dataset Does Not Contain

The Sysmon EID 1 events for the parent PowerShell processes that initiated the chain are not present. The sysmon-modular configuration used here operates in include mode, which means it only logs process creations for processes matching its rule set. PowerShell was captured as a child process only when it matched specific patterns; the initial ART test framework PowerShell instance did not appear in EID 1.

There are no Sysmon EID 12 events (registry key create/delete). The key `AtomicSafeMode` was created as a new key, but EID 12 is not included in the dataset — only EID 13 captured the value write within it.

There are no network connections, no file writes associated with the technique (only a PowerShell startup profile touch by PowerShell itself), and no system event log entries corresponding to the registry change.

The dataset shows no evidence of what service name the attacker intends to register or what binary would load at safe-mode boot. The persistence mechanism is established but the payload side is absent — this is expected for an atomic test that focuses on the registry write action alone.

## Assessment

This dataset provides direct, high-confidence evidence of safe-mode registry persistence. The combination of a Sysmon EID 13 event naming the exact target object and value, paired with Security EID 4688 events showing the full `REG ADD` command line, produces corroborating evidence from two independent telemetry sources. Either source alone is sufficient to identify the behavior; together they make the case robust against individual log gaps.

The undefended capture is richer in process execution detail than the defended variant because Defender's intervention in the defended run produced additional process creation events for remediation actions. Here, execution proceeds cleanly: PowerShell spawns `cmd.exe`, which spawns `reg.exe`, which writes the key, and nothing interrupts the chain.

The dataset timestamp window is narrow — under six seconds from earliest to latest event — which reflects how quickly this technique executes. An attacker would spend more time in surrounding reconnaissance and lateral movement than in the registry write itself.

## Detection Opportunities Present in This Data

**Sysmon EID 13 on SafeBoot keys.** Any registry write targeting `HKLM\System\CurrentControlSet\Control\SafeBoot\` is a high-fidelity indicator. Legitimate software rarely modifies safe-boot driver lists outside of installation contexts.

**`reg.exe` with SafeBoot path argument.** The `reg.exe` command line contains the literal string `SafeBoot\Minimal` and the `/D "Service"` data value. Both the registry path and the value data are unique enough to distinguish malicious from benign `reg.exe` usage.

**PowerShell spawning `cmd.exe` spawning `reg.exe`.** The three-process chain (PowerShell → cmd.exe → reg.exe) with `NT AUTHORITY\SYSTEM` context and `C:\Windows\TEMP\` working directory for `cmd.exe` is consistent with automated script execution. Security EID 4688 captures this chain with full command lines.

**Process working directory anomaly.** Both `cmd.exe` and `reg.exe` show `CurrentDirectory: C:\Windows\TEMP\` and `C:\Windows\Temp\` respectively. Legitimate registry administration from interactive shells typically shows a user home directory or administrative working directory, not the TEMP folder.
