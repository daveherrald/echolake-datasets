# T1021.004-1: SSH — ESXi - Enable SSH via PowerCLI

## Technique Context

T1021.004 covers the use of SSH for lateral movement. In environments running VMware ESXi hypervisors, SSH is an administrative interface that is typically disabled by default but can be enabled remotely using VMware's PowerCLI management framework. An attacker who gains access to VMware vCenter credentials or to a management host with PowerCLI installed can enable SSH on ESXi hosts, creating a persistent, low-visibility access channel directly to the hypervisor — bypassing guest OS security controls entirely.

PowerCLI is VMware's PowerShell extension for managing vSphere environments. `Connect-VIServer` establishes a session to a vCenter or ESXi host, and `Get-VMHostService | Start-VMHostService` starts or enables a host service, in this case the TSM-SSH service (the ESXi Shell/SSH service). The technique is particularly dangerous because hypervisor-level access gives an attacker control over all guest VMs without triggering guest endpoint security tools.

Detection for this variant focuses on PowerCLI cmdlet invocations in PowerShell script block logs — specifically `Connect-VIServer`, `Get-VMHostService`, and `Start-VMHostService` — combined with network connections to ESXi management interfaces (typically port 443 for the vSphere API). Because PowerCLI is a legitimate administrative tool, behavioral context (who is running it, from where, and against which hosts) matters for triage.

## What This Dataset Contains

The dataset spans a few seconds (23:03:44–23:03:56 UTC on 2026-03-14) and totals 150 events across two channels.

The technique process is captured definitively in Sysmon EID 1: PowerShell (PID 6012) spawns with the full command line: `"powershell.exe" & {Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -ParticipateInCEIP:$false -Confirm:$false Connect-VIServer -Server atomic.local -User root -Password pass Get-VMHostService -VMHost atomic.local | Where-Object {$_.Key -eq "TSM-SSH" } | Start-VMHostService -Confirm:$false}`. The full PowerCLI command sequence is visible in the command line field, including the target host (`atomic.local`), the hardcoded credentials (`root` / `pass`), and the specific SSH service key (`TSM-SSH`).

The `RuleName` tag on this process create is `technique_id=T1083,technique_name=File and Directory Discovery` — a labeling artifact from the Sysmon configuration matching the `Get-VMHostService` piped output as a directory-like discovery operation. The actual MITRE technique is T1021.004.

Sysmon EID 7 captures DLL image loads for the PowerShell process: the standard .NET CLR stack (mscoree.dll, mscoreei.dll, clr.dll, mscorlib.ni.dll, clrjit.dll) and `urlmon.dll`. The urlmon.dll load indicates a network request was attempted (likely the `Connect-VIServer` API call to port 443 on `atomic.local`). The Defender MpOAV.dll and MpClient.dll are also loaded, present even with real-time protection disabled.

The PowerShell channel contains 112 EID 4104 events. In the sample set, only test framework boilerplate is represented, but the full dataset contains the PowerCLI script block text. The defended version's analysis confirmed the script block `Set-PowerCLIConfiguration -InvalidCertificateAction Ignore ...` is logged in EID 4104. This undefended run generates the same content — the key difference from the defended version is the absence of any Defender interference events; the event counts are similar (37 Sysmon vs 34 Sysmon in the defended run).

## What This Dataset Does Not Contain

There are no Sysmon EID 3 network connection events showing the `Connect-VIServer` attempt to `atomic.local`. The connection would be to port 443 (vSphere API), but either the hostname did not resolve, the connection was refused (no ESXi at that address in this environment), or the connection attempt completed too quickly for Sysmon to capture. No PowerCLI module loading events appear — specifically, no VMware.VimAutomation.Core.dll or similar PowerCLI DLLs appear in Sysmon EID 7. This suggests PowerCLI was not installed on this test machine, meaning the PowerShell process likely failed immediately with a cmdlet not found error. There are no error events or Windows event log entries confirming this failure.

## Assessment

This dataset's primary value is the PowerCLI command line captured in Sysmon EID 1 and Security EID 4688. The full invocation — including `Connect-VIServer` with explicit credentials, target hostname, and the `TSM-SSH` service key — is a high-fidelity detection target. In a real attack, the credentials would be stolen or read from a vault rather than hardcoded, but the cmdlet structure is identical. Defenders building detections for PowerCLI-based ESXi management should validate their rules against this command line. The dataset does not demonstrate a successful SSH enablement, but the process creation evidence is sufficient for detection rule development. For environments with ESXi infrastructure, catching this PowerShell pattern before the connection succeeds is the primary defensive use case.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 / EID 4688 — PowerShell command line with Connect-VIServer**: The string `Connect-VIServer` in a PowerShell process command line is a reliable indicator of vSphere management activity. When combined with the `Start-VMHostService` cmdlet, it specifically indicates service modification on an ESXi host.

2. **EID 4104 — PowerCLI cmdlets in script block logging**: The PowerCLI command sequence (`Set-PowerCLIConfiguration`, `Connect-VIServer`, `Get-VMHostService`, `Start-VMHostService`) will appear in EID 4104 when PowerCLI is installed. Monitoring for these cmdlets in script blocks originating from non-administrative contexts or automated processes is the primary detection path.

3. **Sysmon EID 7 — urlmon.dll in PowerShell associated with VMware cmdlets**: The urlmon.dll load in the PowerShell process that contains the PowerCLI command line indicates a web/API request was initiated. Combined with the command line content, this corroborates that a connection attempt was made.

4. **EID 4104 — credentials in script blocks**: The hardcoded `-User root -Password pass` arguments in the script block expose credentials in plaintext. Monitoring for password-like patterns following `-Password` or `-Credential` flags in script block logs can catch credential exposure for threat intelligence purposes.

5. **Sysmon EID 3 — outbound TCP to port 443 from PowerShell**: If PowerCLI successfully connects to an ESXi host, a Sysmon EID 3 network connection from `powershell.exe` to port 443 on an internal host would be generated. This is not present in this dataset but would be the definitive network-layer confirmation.
