# T1082-34: System Information Discovery — Operating system discovery

## Technique Context

T1082 (System Information Discovery) includes straightforward OS enumeration queries that are among the most commonly observed techniques in real-world intrusions. Attackers query OS version, architecture, and service pack level to select appropriate exploits, determine compatibility with post-exploitation tools, and understand the target environment. PowerShell's `Get-CimInstance Win32_OperatingSystem` is a standard administrative cmdlet that returns detailed OS information including version string, architecture, computer name, and Windows directory path.

This technique is essentially benign in isolation — every Windows administrator uses these queries regularly. Its significance is contextual: OS enumeration executed by a SYSTEM-level process spawned from a test framework, alongside other discovery techniques in rapid succession, indicates adversarial reconnaissance rather than legitimate administration. The defended and undefended variants of this dataset are structurally identical because Defender does not flag built-in CimInstance queries.

## What This Dataset Contains

This dataset captures a 5-second window (2026-03-14T23:32:46Z–23:32:51Z) of OS discovery via PowerShell CimInstance.

**Process execution chain**: Sysmon EID 1 records the PowerShell process (PID 6240) spawned as `NT AUTHORITY\SYSTEM` with the explicit command line:

```
"powershell.exe" & {Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory | Out-null}
```

The `Out-Null` at the end discards console output, meaning the enumeration result is not preserved in any log — only the query itself is. The sysmon-modular rule tags this process with `technique_id=T1083,technique_name=File and Directory Discovery`, which is an approximate match; the CimInstance query is more precisely OS discovery than file discovery.

`whoami.exe` executes before (PID 6096) and after (PID 4004) the main PowerShell process, both as SYSTEM — standard test framework identity checks.

**Security events**: Three EID 4688 events cover the `whoami.exe` instances and the `powershell.exe` process. No parent process name appears in the samples, consistent with the test framework orchestration pattern.

**PowerShell script block logging**: 107 EID 4104 events and 13 EID 4103 events were captured (120 total). The available samples include `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'` and `Invoke-AtomicTest T1082 -TestNumbers 34 -Cleanup`. The 13 EID 4103 module pipeline events are notable — the `Get-CimInstance` command produces structured pipeline output that triggers 4103 logging when the PowerShell module logging policy is active. These pipeline events capture the actual CimInstance invocation in more detail than EID 4104 script blocks alone.

**DLL loading**: 17 Sysmon EID 7 events capture .NET runtime and PowerShell module DLLs loading. The CimInstance query uses WMI internally, so WBEM-related DLLs may appear in this set.

**Process access**: Three Sysmon EID 10 events show standard test framework process access patterns (parent PowerShell accessing child processes).

**Named pipe and file creation**: Sysmon EID 17 records the standard PowerShell host pipe. Sysmon EID 11 records the `StartupProfileData-NonInteractive` profile cache file.

Comparing to the defended dataset (46 sysmon, 11 security, 63 powershell), the undefended run is nearly identical structurally (26 sysmon, 3 security, 120 powershell). The PowerShell count is slightly higher in the undefended run, and the security count slightly lower — differences attributable to Defender process activity rather than technique-related telemetry differences. This confirms what you would expect: Defender does not interfere with `Get-CimInstance Win32_OperatingSystem`.

## What This Dataset Does Not Contain

The `Out-Null` in the command line means the WMI query results — OS version, architecture, computer name — are explicitly discarded and do not appear in any log. There are no WMI subscription events, no ETW traces of the CimInstance query internals, and no registry reads that would individually indicate OS version lookup. The dataset shows that the query was issued, not what it returned.

There are no network events, no file writes containing enumeration output, and no external communication triggered by this technique.

## Assessment

This is a clean, minimal dataset for a basic OS discovery technique. The entire attack surface is the PowerShell command line in Sysmon EID 1 and Security EID 4688, which explicitly names `Get-CimInstance Win32_OperatingSystem`. The 13 EID 4103 pipeline events provide additional execution detail. The technique executes successfully and completely; the only reason it is detectable at all is the explicit, unfobscated command line.

This dataset is most useful in combination with other T1082 tests — a time-correlated burst of system information discovery commands across multiple EID 4688 events is a stronger indicator than any single query in isolation.

## Detection Opportunities Present in This Data

**Security EID 4688 / Sysmon EID 1**: The command line `Get-CimInstance Win32_OperatingSystem` is fully visible. Combined with the process running as `NT AUTHORITY\SYSTEM` in `C:\Windows\TEMP\` as the working directory, this is an anomalous pattern for legitimate administration.

**PowerShell EID 4103 (Module Logging)**: The 13 module pipeline events provide structured records of the CimInstance command execution, including the specific WMI class being queried.

**Working directory**: The PowerShell process runs from `C:\Windows\TEMP\` — a strong contextual indicator of automated or adversarial execution rather than interactive administration.

**Behavioral clustering**: A SYSTEM-privilege PowerShell process querying OS information at 23:32:49, sandwiched between `whoami.exe` executions, occurring within a broader sequence of discovery techniques, is the signature of a systematic reconnaissance sweep rather than routine administration.
