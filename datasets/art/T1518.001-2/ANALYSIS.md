# T1518.001-2: Security Software Discovery — Security Software Discovery - PowerShell

## Technique Context

T1518.001 (Security Software Discovery) describes adversary attempts to enumerate security tools present on a target system. Attackers routinely perform this reconnaissance during post-exploitation to understand what defenses they face before executing subsequent stages such as lateral movement, credential access, or impact. Common approaches include querying process names and descriptions, WMI namespaces, registry keys, installed services, and filesystem paths. Detection engineering for this technique focuses on the combination of tools invoked and the namespaces or property names they target — particularly queries to `root\SecurityCenter2`, `Get-Process` filters on AV-related descriptions, and `fltMC` invocations to enumerate filter drivers.

## What This Dataset Contains

The test queries running processes and filters by description and name patterns associated with common endpoint security products. The full script block captured in PowerShell event ID 4104 reads:

```
get-process | ?{$_.Description -like "*virus*"}
get-process | ?{$_.Description -like "*carbonblack*"}
get-process | ?{$_.Description -like "*defender*"}
get-process | ?{$_.Description -like "*cylance*"}
get-process | ?{$_.Description -like "*mc*"}
get-process | ?{$_.ProcessName -like "*mc*"}
get-process | Where-Object { $_.ProcessName -eq "Sysmon" }
```

The PowerShell channel carries the complete query in event ID 4104 (script block logging) and the per-command invocation detail in event ID 4103 (module logging), showing each `Get-Process | Where-Object` pipeline with its `FilterScript` and the full process list being evaluated against it — including process names such as `AggregatorHost`, `cmd`, and the test framework's own PowerShell instances.

The Security channel records two 4688 process creation events: one for `whoami.exe` (the ART test framework pre-check) and one for a nested `powershell.exe` spawned to execute the discovery script. Both show creator process `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` running as `NT AUTHORITY\SYSTEM`.

The Sysmon channel provides Sysmon event ID 1 (Process Create) for `whoami.exe` with `RuleName: technique_id=T1033` and for the second `powershell.exe` with `RuleName: technique_id=T1059.001`. Event ID 7 (Image Loaded) captures DLL loads into each PowerShell instance, including `MpOAV.dll` and `MpClient.dll` from the Defender platform directory, tagged with `technique_id=T1574.002,technique_name=DLL Side-Loading`. Event ID 10 (Process Access) fires when the parent PowerShell opens a handle to each child process, tagged `technique_id=T1055.001`. Event ID 17 (Pipe Created) records the `\PSHost.*` named pipe created by each PowerShell instance.

## What This Dataset Does Not Contain

There is no Sysmon event ID 1 for the main PowerShell instance that executed the discovery script itself — the include-mode Sysmon configuration matched `powershell.exe` only via the T1059.001 rule when it was a child of a CMD launcher. The initial PowerShell test framework process that ran the ART framework was already running before the capture window.

No Security event ID 4688 with the specific command line `powershell -c "get-process | ?{...}"` appears; the command line is only visible in the PowerShell channel. The Security channel captures process creation without embedding the full script payload.

There is no evidence that the query returned any results confirming security tool presence — the dataset captures the enumeration attempt only, not the output. No Defender detection or block event appears; `Get-Process` enumeration is not blocked.

## Assessment

This is a strong dataset for PowerShell-based process enumeration detection. The PowerShell channel provides the cleanest detection surface: the full script block in event ID 4104 contains the literal strings `*virus*`, `*carbonblack*`, `*defender*`, `*cylance*`, and `"Sysmon"` in filter expressions. Event ID 4103 provides per-cmdlet parameter binding, making it straightforward to extract the `FilterScript` value and match on AV-vendor keyword patterns. The Security 4688 and Sysmon event ID 1 events confirm the execution chain but do not carry the script content. To strengthen the dataset, capturing the command line argument passed to `powershell.exe` via Security 4688 command-line auditing would make the process-create event standalone-detectable without requiring script block correlation.

## Detection Opportunities Present in This Data

1. **PowerShell 4104 script block containing AV vendor keywords** — Match `Get-Process` pipelines where `FilterScript` values include `*virus*`, `*defender*`, `*carbonblack*`, `*cylance*`, or `Sysmon` in Microsoft-Windows-PowerShell/Operational event ID 4104.
2. **PowerShell 4103 module logging with Get-Process + AV filter** — Event ID 4103 records `CommandInvocation(Where-Object)` with `FilterScript` values containing endpoint vendor strings, enabling per-invocation alerting.
3. **PowerShell spawning from SYSTEM context** — The test framework runs as `NT AUTHORITY\SYSTEM`; a PowerShell process created by SYSTEM on a workstation outside of recognized service workflows is itself a detection opportunity visible in Security 4688.
4. **Sysmon event ID 1 for child powershell.exe with T1059.001 rule match** — The second PowerShell instance is captured with the technique tag directly in the RuleName field, usable as a detection field filter.
5. **Sysmon event ID 10 (Process Access) from powershell.exe to child processes** — The parent PowerShell accessing child `whoami.exe` and `powershell.exe` via `GrantedAccess: 0x1FFFFF` is visible and correlated via ProcessGUID.
