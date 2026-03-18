# T1087.002-21: Domain Account — Suspicious LAPS Attributes Query with adfind all properties

## Technique Context

T1087.002 (Account Discovery: Domain Account) includes querying for specific sensitive Active Directory attributes that reveal security configuration details. LAPS (Local Administrator Password Solution) is Microsoft's mechanism for managing unique local administrator passwords for each domain-joined computer, storing the passwords as Active Directory attributes (`ms-mcs-admpwd`). Attackers who can query LAPS attributes gain plaintext local administrator passwords for potentially every computer in the domain — direct credentials for lateral movement.

AdFind.exe is a powerful Active Directory query tool developed by Joe Richards that predates PowerView by over a decade. It is widely used by legitimate administrators and is equally popular among ransomware operators and APT groups for its speed, flexibility, and output formatting. This test queries all computer objects with all attributes (`-f "objectclass=computer" *`), which would return LAPS password attributes for any computer where the querying account has read access.

In the defended dataset, AdFind.exe was already staged in `C:\AtomicRedTeam\ExternalPayloads\` but Defender blocked its execution. In this undefended run, AdFind executes — though the telemetry tells a more nuanced story about what actually ran.

## What This Dataset Contains

This dataset covers a 5-second window (2026-03-14T23:34:37Z–23:34:42Z).

**Process execution chain**: Sysmon EID 1 captures 5 events in the full dataset. The available samples show:

1. `whoami.exe` (PID 4984) at 23:34:37 — pre-execution identity check.
2. `WmiPrvSE.exe` (PID 6180) at 23:34:38 — WMI Provider Host spawning during the test window. Command line: `C:\Windows\system32\wbem\wmiprvse.exe -Embedding`. This runs as `NT AUTHORITY\NETWORK SERVICE`, not SYSTEM, and is tagged `technique_id=T1047,technique_name=Windows Management Instrumentation`.

The PowerShell orchestration process and any AdFind.exe process creation events fall within the remaining 3 EID 1 events outside the sample set. The defended analysis confirms the PowerShell command line:

```
"powershell.exe" & {& "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe"
 -h $env:USERDOMAIN -s subtree -f "objectclass=computer" *}
```

**Security EID 4798 (5 events)**: User local group membership enumeration events from `C:\Windows\System32\wbem\WmiPrvSE.exe`. These capture WMI-driven enumeration of local accounts. This is background activity from the WMI provider, not from AdFind.exe or the test technique.

**Security EID 4798 (5 events)**: User local group membership enumeration events from `C:\Windows\System32\wbem\WmiPrvSE.exe`. These capture WMI-driven enumeration of local accounts: `DefaultAccount`, `Administrator`, `Guest`, `mm11711`, and `WDAGUtilityAccount`. The WMI queries are triggered by the test framework or a concurrent system process, not directly by AdFind.

**Security EID 4688 (5 events)**: Process creation events covering `whoami.exe`, `powershell.exe`, `WmiPrvSE.exe`, and the cleanup sequence.

**PowerShell script block logging**: 103 EID 4104 events were captured. Available samples show test framework invocations; the full set contains the AdFind command script block.

**DLL loading**: 25 Sysmon EID 7 events reflect .NET, PowerShell, and potentially AdFind.exe's runtime DLL loading. The WMI-related DLLs (`wbemcomn.dll`, `wbem*.dll`) correspond to the WmiPrvSE.exe activity.

**Process access**: Four Sysmon EID 10 events show process access patterns.

**Named pipes**: Three Sysmon EID 17 events for multiple PowerShell instances.

**File creation**: Two Sysmon EID 11 events. The `StartupProfileData-NonInteractive` PS profile cache is one; the other may be AdFind.exe's output file.

**Application channel**: Single EID 15 indicating Defender status restored after test completion.

Comparing to the defended dataset (36 sysmon, 10 security, 45 powershell): the undefended run has 39 sysmon, 29 security, and 103 powershell events. The security count jumped dramatically (29 vs 10) primarily because of the 5 WMI-generated EID 4798 events and additional EID 4688 process creation events. The powershell count increase (103 vs 45) reflects successful execution proceeding further.

## What This Dataset Does Not Contain

The results of the AdFind LAPS query — whether LAPS attributes were readable, which computers had LAPS configured, and what password values were returned — do not appear in any event. AdFind writes output to the console or a specified file, neither of which generates Windows event log entries.

LDAP connections from AdFind to ACME-DC01 are not captured — Sysmon EID 3 network connection filtering excludes AdFind.exe. DNS queries for the domain controller are not present.

The AdFind.exe process creation event (with its full command-line arguments) is not in the available 20-sample set but exists in the full dataset's Sysmon EID 1 events.

## Assessment

This dataset has two distinct layers of content that require separate analytical attention. The first layer is the actual T1087.002-21 technique: AdFind.exe executing an all-attributes query against AD computer objects, potentially revealing LAPS passwords. The primary evidence for this is the PowerShell EID 4688 command line and the AdFind EID 1 process creation events in the full dataset.

The second layer is the background infrastructure activity that dominates the Security channel: 19 EID 4799 events from Cribl's local group enumeration and 5 EID 4798 events from WMI-driven account enumeration. These events are not attack artifacts but real-world system behavior from the monitoring stack and Windows background processes. Analysts using this dataset need to distinguish these sources before attributing group enumeration activity to the technique.

The WmiPrvSE.exe activity generating EID 4798 events is particularly notable: it enumerates all local users (DefaultAccount, Administrator, Guest, mm11711, WDAGUtilityAccount) via WMI — behavior that mimics T1087.001 account discovery while being entirely OS-background in origin.

## Detection Opportunities Present in This Data

**Sysmon EID 1 (AdFind.exe process creation)**: The full dataset contains AdFind.exe's process creation with command line `-h $env:USERDOMAIN -s subtree -f "objectclass=computer" *`. AdFind.exe execution from any user context is a high-priority indicator given its frequent use by ransomware operators. The wildcard (`*`) attribute specification indicating a request for all attributes, including LAPS passwords, elevates this further.

**Security EID 4688 (PowerShell)**: The command line `& "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe"` names AdFind explicitly, providing a second source confirming execution intent even if the AdFind.exe EID 1 is not available.

**Sysmon EID 7 (DLL loading for AdFind)**: AdFind.exe loads a specific set of Active Directory LDAP client libraries at runtime. These DLL loading events, correlated with an unknown executable binary, can indicate AD query tool execution even without recognizing the binary name.

**Source attribution for EID 4799**: The 19 EID 4799 events are from `cribl.exe`, not from the attack technique. Any detection logic targeting bulk group membership enumeration must correlate the `Process Name` field to distinguish infrastructure-generated enumeration from adversary-generated enumeration. Raw EID 4799 volume without process attribution can produce false positives in this environment.

**WmiPrvSE.exe EID 4798**: The 5 user local group membership enumeration events from `WmiPrvSE.exe` represent OS-background WMI-driven account queries. These are not attack artifacts, but they demonstrate that account enumeration events can be generated by legitimate system processes in a normal instrumented Windows environment.
