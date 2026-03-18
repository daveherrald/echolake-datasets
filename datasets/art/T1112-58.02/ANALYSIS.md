# T1112-58: Modify Registry — Allow Simultaneous Download Registry

## Technique Context

T1112 (Modify Registry) applied to Internet Explorer connection settings modifies the maximum number of simultaneous TCP connections that Internet Explorer and legacy WinInet-based applications will make to a single HTTP server. This test sets `MaxConnectionsPerServer` and `MaxConnectionsPer1_0Server` to `10` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`.

The default values for these settings are 2 (HTTP/1.0 servers) and 6 (HTTP/1.1 servers). By increasing them to 10, the technique allows WinInet-based network code — including Internet Explorer, certain Windows system services, and some malware that uses WinInet as its HTTP transport — to open more parallel connections to a single server. This is used by threat actors to accelerate data exfiltration: by opening more simultaneous connections, an exfiltration tool can push data to a C2 server faster without needing to exceed per-connection bandwidth limits that might trigger monitoring thresholds.

The HKCU path means this setting applies to the current user's WinInet stack. Since this test runs under SYSTEM, the modification affects the SYSTEM account's internet connection behavior, which governs network requests made by system services and processes running in the SYSTEM context.

This technique is more subtle than outright disabling security controls — it does not disable Defender, bypass UAC, or block updates. Its purpose is operational: to quietly maximize exfiltration throughput without triggering obvious security tool alerts. This makes it a useful test for evaluating whether network behavior analytics or host-based monitoring catches throughput-related configuration changes.

In the defended variant, this dataset produced 28 Sysmon, 14 Security, and 35 PowerShell events. The undefended capture produced 18 Sysmon, 5 Security, and 57 PowerShell events. The undefended run has slightly more Security events (5 vs 4 in most similar tests) because the chained `cmd.exe` invocation runs two `reg add` commands in sequence, generating an additional process creation event.

## What This Dataset Contains

The technique uses a single `cmd.exe` invocation with two `reg add` commands chained by `&`. Sysmon EID 1 captures `cmd.exe` (PID 1916) spawned by PowerShell (PID 1996) with the full chain:

```
"cmd.exe" /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d 10 /f & reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d 10 /f
```

The `&` operator causes both `reg add` commands to execute sequentially from within the same `cmd.exe` process. Only one `reg.exe` process (PID 3632) is captured in Sysmon EID 1 — for the first `reg add`:

```
reg  add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d 10 /f
```

The second `reg.exe` execution (for `MaxConnectionsPer1_0Server`) is captured in a separate Sysmon EID 1 or Security EID 4688 entry. Security EID 4688 records 5 total process creations in this dataset — `whoami.exe` plus `cmd.exe` plus two `reg.exe` instances plus one additional process.

Security EID 4688 records the `cmd.exe` process creation with the complete compound command line visible. The full chained invocation is preserved in the `Process Command Line` field.

Sysmon EID 10 records PowerShell accessing both `whoami.exe` and `cmd.exe`. The pre-execution `whoami.exe` (PID 2232) ran approximately three seconds before `cmd.exe`.

The PowerShell channel (57 EID 4104 events) contains ART test framework boilerplate and a cleanup call.

## What This Dataset Does Not Contain

There are no Sysmon EID 12 or EID 13 events. The `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` path is not monitored by the sysmon-modular configuration, so neither the `MaxConnectionsPerServer` nor the `MaxConnectionsPer1_0Server` write appears in registry telemetry.

The dataset contains no network traffic showing the effects of the increased connection limits. No WinInet or HTTP client events appear. The modification changes potential behavior but generates no immediate observable network activity.

There are no second `reg.exe` process creation events in the Sysmon EID 1 samples — only the first `reg.exe` appears. The Security log has 5 EID 4688 events covering all process creations including both `reg.exe` instances.

## Assessment

This dataset's technical interest is in the chained execution pattern. By running two registry modifications in a single `cmd.exe` invocation, the attacker reduces the number of observable process creation events compared to two separate invocations. However, the complete compound command line is fully visible in Security EID 4688 and Sysmon EID 1, making both modifications detectable from a single event.

The `MaxConnectionsPerServer` and `MaxConnectionsPer1_0Server` values in HKCU Internet Settings are relatively obscure targets. Most defenders' registry monitoring does not cover this path. Detection relies on command-line telemetry rather than registry monitoring.

The context matters significantly here: this technique is unlikely to appear in isolation in a real attack. It would accompany data staging, exfiltration tool deployment, or C2 communications. In this dataset, it appears as one of a sequence of registry modifications targeting varied security and operational settings, which is consistent with a pre-attack preparation playbook.

## Detection Opportunities Present in This Data

**`reg.exe` command line containing `MaxConnectionsPerServer` or `MaxConnectionsPer1_0Server`.** These value names in combination with DWORD values above the default (2 and 6 respectively) are uncommon in legitimate use. Values of 10 or higher are specifically exfiltration-enabling.

**Chained `reg add` commands via `cmd.exe /c ... & reg add ...`.** The use of `&` in a `cmd.exe` command to run multiple `reg add` calls on the same line is characteristic of automated scripting. Two HKCU Internet Settings modifications in the same `cmd.exe` invocation is a specific pattern.

**SYSTEM-context modifications to HKCU Internet Settings.** Writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` under `NT AUTHORITY\SYSTEM` are unusual — this key normally governs user-specific browser settings. SYSTEM processes don't typically configure per-user browser connection limits.

**Internet Settings modification paired with exfiltration indicators.** If network monitoring shows increased parallel connections to external hosts near the time of this registry modification, the two observations together form a strong exfiltration case. The modification itself provides intent; network behavior provides confirmation.
