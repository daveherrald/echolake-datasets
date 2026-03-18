# T1082-19: System Information Discovery — WinPwn - Morerecon

## Technique Context

T1082 (System Information Discovery) encompasses the enumeration of host information that adversaries conduct to understand the compromised environment before proceeding with their objectives. `Morerecon` is a WinPwn module that — as the name implies — performs additional reconnaissance beyond the general checks covered by other modules. It targets information not fully covered by GeneralRecon or the privilege escalation focused modules: things like detailed user privilege information, installed patches, software licensing, specific registry configurations, and environment-specific details that may reveal additional attack surface.

In the context of a real intrusion, an attacker who has already run GeneralRecon and the privilege escalation enumeration modules might invoke Morerecon to probe for residual information — additional user accounts with stale configurations, specific software that might be exploitable, or environment details that narrow the attack surface analysis.

## What This Dataset Contains

This dataset captures the full execution of WinPwn's `Morerecon` function on ACME-WS06.acme.local with Defender disabled. The execution runs as `NT AUTHORITY\SYSTEM`.

The dataset spans a 6-second window (23:31:50Z to 23:31:56Z) and captures 254 total events: 86 sysmon, 56 security, 109 PowerShell, 2 task scheduler, and 1 application.

The Security channel (56 events) breaks down as: 50 EID 4688 (process creation), 3 EID 4660 (object deleted), and 3 EID 4663 (object access). The 4660 and 4663 events are significant — they indicate Morerecon performed object access auditing-visible operations on files or registry keys. EID 4663 (object access) appears when an object with SACL auditing enabled is accessed; EID 4660 (object deleted) appears when such an object is deleted. The presence of these events indicates Morerecon touched audited system objects, likely registry keys or files with security auditing configured.

The 50 EID 4688 process creation events represent the second-highest count in the T1082 WinPwn series (after itm4nprivesc at 62). The non-mscorsvw process creation events visible in the samples include `whoami.exe` (identity check) and a `powershell.exe` instance with an empty command block (the cleanup phase).

The Security EID 4688 events also include a `ngen.exe` invocation:
```
"C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe" install "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" /NoDependencies /noroot /version:v4.0.30319 /LegacyServiceBehavior
```

This is the .NET Native Image Generator being explicitly invoked (rather than via the background worker) to compile `System.Core` — one of the fundamental .NET framework assemblies. This can occur when a PowerShell module requests compilation of a core assembly that hasn't been natively compiled yet for the specific execution context.

The Sysmon channel (86 events) breaks down as: 53 EID 11 (file creates), 21 EID 7 (image loads), 5 EID 10 (process access), 4 EID 1 (process creates), 2 EID 17 (named pipe creates), and 1 EID 22 (DNS). The 5 EID 10 (process access) events are the highest in the T1082 series, suggesting Morerecon opens more process handles than the other modules during its enumeration.

The Sysmon EID 17 (named pipe create) records a PowerShell host pipe:
```
PipeName: \PSHost.134180047079335890.4548.DefaultAppDomain.powershell
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: NT AUTHORITY\SYSTEM
```

The Task Scheduler channel (2 events) shows the .NET NGEN scheduled task completing:
- EID 102: `Task Scheduler successfully finished` instance of `\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319`
- EID 201: `Task Scheduler successfully completed task` with return code 0

This is the scheduled task triggered by the `ngen.exe` invocation — the explicit NGen call for `System.Core` triggered the .NET Framework NGEN scheduled task infrastructure.

Compared to the defended dataset (31 sysmon, 10 security, 53 PowerShell events), the undefended execution shows significantly more activity: 86 sysmon (vs. 31), 56 security (vs. 10). The undefended run's 50 EID 4688 events vs. 10 in the defended variant indicates that Morerecon's full execution was substantially curtailed by Defender's interference.

## What This Dataset Does Not Contain

The EID 4660 and 4663 events appear in the Security log breakdown (3 each) but are not present in the 20-event sample selection, making it impossible to determine from the samples which specific objects (files or registry keys) Morerecon accessed or deleted. These events would be visible in the full dataset.

The reconnaissance output from Morerecon — the additional system details it collected — is console output only and is not captured in event telemetry.

The WinPwn invocation command line (with `Morerecon -noninteractive -consoleoutput`) is not visible in the 20-event Security EID 4688 sample because that specific process creation event was not selected in the sample. The pattern is consistent with all other T1082 WinPwn tests.

## Assessment

Morerecon has a distinctive profile within the WinPwn T1082 series: it generates the most Security EID 4688 process creation events among the WinPwn modules that operate in this way (50 events, second only to itm4nprivesc), the most EID 10 process access events (5), and it is the only module to produce EID 4660 and EID 4663 (audited object access and deletion) events. It also uniquely triggers an explicit `ngen.exe` invocation for `System.Core` — suggesting that Morerecon requires a .NET component that needs ahead-of-time compilation to run efficiently.

The EID 4660/4663 events are particularly interesting: they indicate Morerecon touched objects with Security Access Control Lists (SACLs) configured for auditing. On a default Windows 11 endpoint, few objects have SACLs that trigger these events under normal use. Morerecon's access to SACL-audited objects suggests it probes registry keys or files that Windows has specifically marked as sensitive enough to audit — things like SAM database entries, LSASS-related registry keys, or security policy objects.

The NGEN scheduled task completion events (Task Scheduler EID 102 and 201) provide an additional cross-channel correlation point: the task scheduler records correlate the explicit `ngen.exe` invocation visible in EID 4688 with a task completion event, confirming the compilation ran to completion.

## Detection Opportunities Present in This Data

**Security EID 4660/4663 — Audited object access during offensive tool execution:** Three object access events and three object deletion events against SACL-protected resources during a WinPwn execution window. The combination of these events with the EID 4688 process creation context (SYSTEM-level PowerShell) indicates offensive tool activity touching sensitive system objects.

**Security EID 4688 — Explicit ngen.exe invocation for System.Core:** The `ngen.exe install "System.Core"` command appearing during a post-exploitation session is anomalous. Normal users do not manually invoke NGen for core framework assemblies. This suggests Morerecon has a dependency that required explicit just-in-time compilation of a fundamental .NET assembly.

**Security EID 4688 — 50 process creation events in a 6-second window:** The volume of process creation events concentrated in a very short window is characteristic of automated enumeration tool operation. Individual processes may be benign; the pattern of volume, speed, and SYSTEM execution context is the anomaly.

**Task Scheduler EID 102/201 — .NET NGEN task completion:** The NGEN scheduled task completing during a post-exploitation session corroborates that new .NET assemblies were being compiled — a secondary indicator of in-memory .NET framework loading triggered by offensive tools.

**Sysmon EID 10 — 5 process access events (highest in T1082 series):** Morerecon's elevated process access count suggests it opens more process handles as part of its enumeration. Combined with SYSTEM execution context, this is consistent with a module that inspects running process state as part of its reconnaissance.

**Sysmon EID 17 — Named pipe creation under SYSTEM:** Consistent with all T1082 WinPwn tests — confirms non-interactive SYSTEM-level PowerShell execution for correlation across the campaign timeline.
