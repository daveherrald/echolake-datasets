# T1016.001-5: Internet Connection Discovery — Check Internet Connection via Test-NetConnection (TCP-SMB)

## Technique Context

T1016.001 Internet Connection Discovery is a reconnaissance sub-technique where an adversary verifies whether the compromised host has outbound internet connectivity and what network paths are available. This is typically done early in post-compromise operations to determine whether direct C2 communication is possible, whether a proxy is required, and whether data exfiltration via common protocols will work.

This specific test uses PowerShell's `Test-NetConnection` cmdlet with `-CommonTCPPort SMB -ComputerName 8.8.8.8`. The choice of SMB (port 445) to Google's public DNS IP is deliberate: it tests whether outbound TCP is permitted on a protocol that is typically blocked for egress, which helps map firewall rules by proxy. A successful TCP connection to 8.8.8.8:445 would be unusual (Google doesn't run SMB services), but the test itself reveals whether port 445 outbound is filtered.

`Test-NetConnection` is a legitimate PowerShell networking cmdlet and generates no suspicious binary execution. Detection requires monitoring either the PowerShell command content (EID 4104/4103) or network-level telemetry showing the connection attempt. With Defender disabled, the test runs identically to the defended variant — this technique is not blocked by signature-based detection.

## What This Dataset Contains

The dataset spans 36 seconds (22:57:02 to 22:57:38) — the long duration reflects `Test-NetConnection`'s built-in timeout waiting for the TCP connection response from 8.8.8.8:445, which ultimately fails since Google doesn't accept SMB connections.

The Security channel captures the key process creation events. The parent PowerShell (PID `0x474`) spawns `whoami.exe` for user context, then spawns a child PowerShell (PID `0x108`) with the command line:

```
"powershell.exe" & {Test-NetConnection -CommonTCPPort SMB -ComputerName 8.8.8.8}
```

(The `&amp;` in the raw event data is HTML-encoded `&`, standard in Windows XML event encoding.) After the test completes, a second child PowerShell (PID `0x12dc`) appears with `"powershell.exe" & {}` — the cleanup/teardown step.

Security EID 4663 captures an access attempt on `C:\Windows\servicing\Sessions\31241302_77600615.xml` by SYSTEM — this is concurrent Windows servicing activity (TrustedInstaller) reading a session state file, unrelated to the technique.

The Sysmon channel shows 23 EID 7 (ImageLoad) events for the child PowerShell process loading the .NET CLR stack — `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `clrjit.dll`, and `mscorlib` native image. These are tagged `technique_id=T1055,technique_name=Process Injection` by the Sysmon ruleset since .NET runtime loading in PowerShell matches that rule. The named pipe (EID 17) `\PSHost.134180020966345059.5588.DefaultAppDomain.powershell` from the parent PowerShell confirms the test framework IPC channel.

System EID 7040 events record the Windows Modules Installer service changing start type twice (demand → auto and back) — TrustedInstaller activating and then returning to on-demand mode around a Windows servicing operation.

Compared to the defended version (37 sysmon, 18 security, 82 PowerShell), the undefended run has 36 sysmon, 5 security, 141 PowerShell events. The security channel is much smaller here (5 vs. 18), while the PowerShell channel is slightly larger (141 vs. 82). The PowerShell increase reflects additional cmdlet invocations completing in the undefended environment — the defended version's EID 4103 events in the full stream included the TCP connection failure message, which should also appear here.

The WMI channel's EID 5858 records a query error from process `4752` running `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` — this is a WinRM/PS Remoting infrastructure monitor checking for remote shell creation, running as a background service.

## What This Dataset Does Not Contain

Despite the 36-second window that includes the TCP connection attempt to 8.8.8.8:445, there are no Sysmon EID 3 (NetworkConnect) events. The PowerShell 4103 events in the full dataset (beyond the 5 samples) would show the actual connection attempt and its failure message (`TCP connect to (8.8.8.8 : 445) failed`), but the network connection itself did not generate a Sysmon network event. This is likely because the connection failed quickly at the TCP SYN stage without completing the handshake, and the Sysmon network monitoring configuration may filter failed/refused connections.

The `Test-NetConnection` cmdlet also internally calls `Resolve-DnsName` and `Find-NetRoute`, but no Sysmon EID 22 (DNS query) events appear — PowerShell DNS resolution via this cmdlet may bypass the standard DNS resolver stack monitored by Sysmon.

The PowerShell 4104 samples contain only boilerplate. The actual `Test-NetConnection` ScriptBlock text is in the full 109 EID 4104 events but not in the 5 sampled events.

## Assessment

The most actionable content in this dataset is the Security EID 4688 command line capturing `Test-NetConnection -CommonTCPPort SMB -ComputerName 8.8.8.8`. This is a reasonably specific indicator — SMB port testing to external IP addresses is unusual for legitimate PowerShell administration. The PowerShell EID 4103/4104 full event stream provides richer execution context. The absence of network connection telemetry despite the TCP attempt is a limitation for network-layer detection scenarios. This dataset is best suited for building PowerShell content-based detections rather than network behavioral analytics.

## Detection Opportunities Present in This Data

1. Security EID 4688 with a PowerShell command line containing `Test-NetConnection` combined with an external IP address or `-CommonTCPPort SMB` is a moderately specific indicator. `Test-NetConnection` to external hosts on non-HTTP ports is rarely seen in legitimate admin workflows.

2. PowerShell EID 4104 ScriptBlock events with `Test-NetConnection -CommonTCPPort SMB` as the ScriptBlockText are present in the full dataset and provide a content-based detection surface that doesn't depend on process monitoring.

3. PowerShell EID 4103 CommandInvocation events showing `TestTCP` function calls with `TargetIPAddress: 8.8.8.8` and `TargetPort: 445` in the Payload field are present in the full event stream — these are the internal cmdlet function traces.

4. Sysmon EID 7 (ImageLoad) showing the full .NET CLR stack loading in a child PowerShell process shortly after the parent PowerShell spawns it is a secondary behavioral indicator. Combined with a 30+ second delay before process termination (from the connection timeout), this creates a temporal signature.

5. Parent PowerShell spawning a child PowerShell (not cmd.exe) with a command-line argument containing an IP address is an unusual pattern that combines the spawning behavior with network discovery intent.

6. The 36-second execution duration for what should be a quick cmdlet invocation is itself anomalous — `Test-NetConnection`'s default timeout behavior on failed connections can be fingerprinted in environments where process lifetime telemetry is available.
