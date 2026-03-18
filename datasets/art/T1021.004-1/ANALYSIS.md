# T1021.004-1: SSH — ESXi - Enable SSH via PowerCLI

## Technique Context

T1021.004 describes the use of SSH for lateral movement, where attackers leverage legitimate SSH services to move between systems in a network. In enterprise environments, SSH is commonly enabled on Linux systems, network devices, and virtualization platforms like VMware ESXi. The detection community focuses on unusual SSH authentication patterns, connections to unexpected hosts, and the use of administrative tools to enable SSH services remotely.

This specific test simulates an attacker using VMware PowerCLI to enable SSH on an ESXi host, which is a common administrative task but could indicate lateral movement preparation. PowerCLI is a legitimate VMware management tool that can be weaponized to enable remote access services on virtualization infrastructure.

## What This Dataset Contains

The dataset captures a PowerShell execution attempting to use PowerCLI cmdlets to enable SSH on a VMware ESXi host. Key telemetry includes:

**Process Creation Events:**
- Security 4688: `"powershell.exe" & {Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -ParticipateInCEIP:$false -Confirm:$false Connect-VIServer -Server atomic.local -User root -Password pass Get-VMHostService -VMHost atomic.local | Where-Object {$_.Key -eq \"TSM-SSH\" } | Start-VMHostService -Confirm:$false}`
- Sysmon 1: PowerShell process creation with the full PowerCLI command line visible

**PowerShell Script Block Logging:**
- PowerShell 4104: Complete script block showing the PowerCLI commands: `Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -ParticipateInCEIP:$false -Confirm:$false Connect-VIServer -Server atomic.local -User root -Password pass Get-VMHostService -VMHost atomic.local | Where-Object {$_.Key -eq "TSM-SSH" } | Start-VMHostService -Confirm:$false`

**Process Activity:**
- Multiple PowerShell processes spawned (PIDs 1444, 1428, 7444)
- .NET framework and PowerShell automation DLL loads captured in Sysmon 7 events
- Process access events (Sysmon 10) showing PowerShell accessing child processes

## What This Dataset Does Not Contain

This dataset lacks several key elements for complete SSH lateral movement detection:

**Missing Network Activity:** No Sysmon network connection events showing the attempted connection to the ESXi host at "atomic.local" - this suggests the connection failed or was blocked before establishment.

**No PowerCLI Module Loading:** The PowerShell script blocks show execution attempts but no evidence of successful PowerCLI module imports or VMware-specific cmdlet execution telemetry.

**Limited Error Information:** While we see process creation, there's no indication in the logs whether the PowerCLI commands succeeded, failed due to authentication issues, or failed due to network connectivity.

**No SSH Service Evidence:** No telemetry showing successful SSH service enablement or subsequent SSH connections, indicating the technique likely failed at the ESXi connection phase.

## Assessment

This dataset provides good visibility into the initial stages of using PowerCLI for SSH enablement but captures what appears to be a failed execution. The PowerShell script block logging (4104) and command-line auditing (4688) provide excellent detection opportunities for this technique. However, the lack of network connections and successful PowerCLI execution limits its utility for understanding the complete attack chain.

The telemetry is strongest for detecting the attempt rather than the success of the technique. This is common in test environments where the target ESXi host may not exist or be reachable.

## Detection Opportunities Present in This Data

1. **PowerCLI Usage Detection** - Monitor PowerShell 4104 events for PowerCLI cmdlets like `Connect-VIServer`, `Get-VMHostService`, and `Start-VMHostService` in enterprise environments where VMware administration is restricted.

2. **Credential Exposure in Command Lines** - Security 4688 events show hardcoded credentials (`-User root -Password pass`) in command lines, which should trigger high-priority alerts.

3. **Suspicious PowerCLI Configuration Changes** - Detection of `Set-PowerCLIConfiguration -InvalidCertificateAction Ignore` which bypasses certificate validation and could indicate malicious PowerCLI usage.

4. **SSH Service Manipulation via PowerCLI** - Monitor for PowerShell script blocks containing `TSM-SSH` service references combined with `Start-VMHostService` cmdlets.

5. **Administrative Tool Abuse** - Correlate PowerShell execution with VMware-specific cmdlets in environments where such administrative actions should be limited to specific users or systems.

6. **Process Spawning Patterns** - Multiple PowerShell processes spawning in rapid succession (PIDs 1444, 1428, 7444) with similar PowerCLI command patterns could indicate automated tooling or script execution.
