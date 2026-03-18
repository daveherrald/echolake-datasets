# T1049-7: System Network Connections Discovery — System Discovery using SharpView

## Technique Context

T1049 System Network Connections Discovery covers adversary efforts to enumerate active network connections, listening ports, and associated processes on a compromised host. This reconnaissance feeds into lateral movement planning: knowing which services are running, which remote hosts are connected, and which processes own network sockets helps attackers identify pivoting opportunities, locate sensitive services, and map the network from the inside. Common implementations include built-in utilities like `netstat`, `ss`, and PowerShell's `Get-NetTCPConnection`, but post-exploitation frameworks increasingly delegate this enumeration to purpose-built .NET assemblies.

This specific test uses SharpView, a C# port of the widely-used PowerView Active Directory enumeration module. SharpView exposes many of the same AD query functions as PowerView but runs as a standalone executable rather than a PowerShell module, which can bypass script-block logging for the enumeration logic itself. The test exercises three particular SharpView functions: `Invoke-ACLScanner` (enumerate ACL misconfigurations), `Invoke-Kerberoast` (find Kerberoastable service accounts), and `Find-DomainShare` (discover accessible SMB shares). These lean heavily into the discovery and credential-access space even though the MITRE mapping is T1049.

Detection for this technique typically centers on process creation events for SharpView.exe or other enumeration tools, PowerShell script blocks that reference enumeration function names, and LDAP query volume from workstations. Because SharpView is a .NET binary, it also generates predictable image-load telemetry when the .NET CLR initializes inside a spawned process.

## What This Dataset Contains

This dataset captures the attempt to execute SharpView with three enumeration functions via a PowerShell loop. Windows Defender was disabled, so the binary was not blocked at load time, but the telemetry shows execution reaching the tool invocation.

**Security EID 4688 — process creation (4 events):** Two pairs of process creation events document the execution test framework. The critical entry shows a child `powershell.exe` process created with the full enumeration command:

```
"powershell.exe" & {$syntaxList = "Invoke-ACLScanner", "Invoke-Kerberoast", "Find-DomainShare"
foreach ($syntax in $syntaxList) {
C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpView.exe $syntax -}}
```

`whoami.exe` appears twice as a test framework pre/post check, both with parent `powershell.exe`. All four events run as `NT AUTHORITY\SYSTEM` (S-1-5-18, IntegrityLevel: System, MandatoryLabel: S-1-16-16384).

**Sysmon EID 1 — process create (4 events):** Two `whoami.exe` creates and two child `powershell.exe` creates are captured by Sysmon. The child PowerShell launching SharpView carries the Sysmon rule tag `technique_id=T1083,technique_name=File and Directory Discovery` (triggered by its current directory being `C:\Windows\TEMP\`). Importantly, no Sysmon EID 1 for `SharpView.exe` itself appears — the sysmon-modular include-mode ProcessCreate filter does not match the binary name, leaving a gap in Sysmon process lineage for the actual tool.

**Sysmon EID 7 — image load (22 events):** Multiple .NET CLR components load into both PowerShell processes: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`. These carry the rule tag `technique_id=T1055,technique_name=Process Injection`. Additionally, Windows Defender components `MpOAV.dll` and `MpClient.dll` load into both PowerShell processes (tagged `technique_id=T1574.002,technique_name=DLL Side-Loading`). `urlmon.dll` also loads, likely related to Defender's scanning activity. Although Defender is disabled for real-time protection, its DLLs still load into PowerShell due to AMSI integration hooks.

**Sysmon EID 10 — process access (4 events):** Two sets of process access events show the parent PowerShell (PID 6992) accessing its child processes with `GrantedAccess: 0x1fffff` (PROCESS_ALL_ACCESS). The call trace runs through `ntdll.dll` → `KERNELBASE.dll` → .NET assemblies (`System.ni.dll`, `System.Management.Automation.ni.dll`), reflecting the ART test framework's PowerShell-driven child process management. These are tagged `technique_id=T1055.001`.

**Sysmon EID 17 — named pipe create (3 events):** Named pipes like `\PSHost.134180036349887813.6992.DefaultAppDomain.powershell` are created for each PowerShell host instance. These are standard PowerShell IPC artifacts.

**Sysmon EID 11 — file create (2 events):** `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` is created/updated, a routine PowerShell profile initialization artifact.

**PowerShell EID 4104 (122) and 4103 (2):** The 122 script block events consist almost entirely of PowerShell runtime internal boilerplate (`Set-StrictMode`, error formatting helpers, `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'`). The SharpView invocation loop does not appear directly as a logged script block in the samples, suggesting the command was passed as a literal string argument to PowerShell rather than compiled as a new script block.

**Compared to the defended dataset:** The defended version captured 45 PowerShell events, 10 security events, and 26 sysmon events. This undefended dataset has significantly more telemetry: 124 PowerShell events, only 4 security events, and 35 sysmon events. The undefended run appears to have generated more PowerShell internal activity — likely from SharpView's .NET execution actually proceeding rather than being cut off early. The defended run had 10 security events versus 4 here; the difference may reflect Defender's own process activity generating 4688 events in the defended run.

## What This Dataset Does Not Contain

The most consequential gap is the absence of any Sysmon EID 1 event for `SharpView.exe`. The sysmon-modular include-mode ProcessCreate configuration only captures processes matching known-suspicious patterns (LOLBins, specific tool names). SharpView does not match these filters, so its process creation — and by extension any child processes it might spawn for LDAP queries — is invisible in Sysmon. Security EID 4688 with command-line auditing also does not capture SharpView's own creation because it is invoked as a bare path within a PowerShell script block rather than through `cmd.exe`.

There are no Sysmon EID 3 (NetworkConnect) events for LDAP, SMB, or Kerberos traffic that the enumeration functions would generate. Network connection logging is enabled in the Sysmon config, but either the connections did not occur within the narrow 5-second collection window, or the SharpView functions did not successfully execute to the point of making network calls.

No Sysmon EID 22 (DNSQuery) events are present. No registry access or WMI events appear. The PowerShell script block content of the SharpView loop itself is not captured — the 122 EID 4104 events are almost entirely runtime internals rather than technique-specific script logic.

## Assessment

This dataset has moderate value for detection engineering. It reliably captures the PowerShell command line containing the SharpView invocation and the three enumeration function names in Security EID 4688, which is the primary actionable detection signal. The Sysmon EID 10 process access events add corroborating evidence. However, the dataset does not capture SharpView's execution artifacts directly — no process creation, no LDAP queries, no network connections. For defenders trying to build detections around SharpView's behavioral footprint (query patterns, child processes, network connections), this dataset provides limited material. It is more useful for building command-line and script-block detections that catch the invocation pattern regardless of whether the tool completes successfully.

The 5-second collection window (23:13:57 to 23:14:02) is very narrow. SharpView's three enumeration functions may require more time to complete LDAP queries, particularly `Invoke-Kerberoast` and `Find-DomainShare` in a live AD environment. This dataset likely captures only the early execution phase.

## Detection Opportunities Present in This Data

1. Security EID 4688 command line contains `SharpView.exe` alongside known enumeration function names (`Invoke-ACLScanner`, `Invoke-Kerberoast`, `Find-DomainShare`) — the full argument string is preserved in `CommandLine`.

2. The PowerShell process executing the SharpView loop has `CurrentDirectory: C:\Windows\TEMP\` at `IntegrityLevel: System`, which is unusual for interactive user sessions and indicates automation or elevated code execution.

3. Sysmon EID 10 events show a parent PowerShell process opening child processes with `GrantedAccess: 0x1fffff` — the combination of PROCESS_ALL_ACCESS from a PowerShell parent to freshly-created processes (whoami, child PowerShell) is consistent with ART test framework behavior but also with injector-style tooling.

4. Sysmon EID 7 image loads show `MpOAV.dll` and `MpClient.dll` loading into PowerShell processes that are running as SYSTEM — when Defender is active, this is normal, but in environments where Defender is confirmed disabled via policy, unexpected loading of these DLLs into SYSTEM-level PowerShell is worth investigating.

5. The named pipe `\PSHost.*.DefaultAppDomain.powershell` pattern in Sysmon EID 17 can anchor a PowerShell process lifecycle timeline, helping correlate which script block events belong to which execution instance.

6. The parent PowerShell process (as the "orchestrator" visible in EID 4688's `ParentProcessName`) spawning multiple child PowerShell processes in rapid succession (within 5 seconds) in `C:\Windows\TEMP\` as SYSTEM is a behavioral pattern worth baselining.
