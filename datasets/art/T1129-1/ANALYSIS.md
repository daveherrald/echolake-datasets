# T1129-1: Shared Modules — Shared Modules - ESXi Install a custom VIB on an ESXi host

## Technique Context

T1129 (Shared Modules) describes how adversaries load malicious code into processes through shared libraries or modules. While typically focused on native Windows DLLs or Linux shared objects, this test simulates installing a malicious VMware Infrastructure Bundle (VIB) on an ESXi hypervisor. VIBs are VMware's package format for distributing software to ESXi hosts, and malicious VIBs can provide persistent access to virtualized infrastructure. Attackers targeting virtualized environments often seek to install backdoored VIBs for hypervisor-level persistence that survives VM reboots and is difficult to detect from guest operating systems.

The detection community focuses on identifying unauthorized VIB installations, abnormal hypervisor modifications, and lateral movement patterns involving virtualization management tools. This technique is particularly concerning in enterprise environments where hypervisor compromise can affect multiple virtual machines and provide privileged access to the entire virtual infrastructure.

## What This Dataset Contains

This dataset captures an Atomic Red Team test that attempts to install a custom VIB on an ESXi host from a Windows workstation. The primary evidence appears in Security event 4688, which shows the main command execution:

`"cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\pscp.exe -pw pass C:\AtomicRedTeam\atomics\..\atomics\T1129\src\atomicvibes.vib root@atomic.local:/tmp & echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe" "atomic.local" -ssh  -l "root" -pw "pass" -m "C:\AtomicRedTeam\atomics\..\atomics\T1129\src\esxi_vibinstall.txt"`

The process chain shows PowerShell (PID 31472) spawning cmd.exe (PID 10536), which attempts to execute pscp.exe and plink.exe for file transfer and remote command execution. A second cmd.exe process (PID 18780) is created to handle the piped echo command. All cmd.exe processes exit with non-zero status codes (0xFF, 0x1), indicating the operations failed.

Sysmon captures the process creation events for whoami.exe (system discovery), both cmd.exe instances, and process access events showing PowerShell accessing the child processes. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy) with no technique-specific script content.

## What This Dataset Does Not Contain

The dataset does not contain evidence of successful VIB installation since the external tools (pscp.exe, plink.exe) and target ESXi host (atomic.local) are not available in this test environment. There are no network connection events, file transfer confirmations, or remote command execution results. The sysmon-modular configuration filtered out ProcessCreate events for pscp.exe and plink.exe since they are not in the known-suspicious patterns list.

Missing telemetry includes DNS resolution attempts for atomic.local, network connections to SSH ports, authentication logs, and any VMware vSphere or ESXi-specific events that would occur during actual VIB installation. The test also lacks filesystem evidence of the atomicvibes.vib file or esxi_vibinstall.txt script being accessed.

## Assessment

This dataset provides limited value for detection engineering focused on T1129 in virtualized environments. While it captures the Windows-side command execution patterns, the core technique (VIB installation on ESXi) fails due to environmental constraints. The telemetry is more useful for detecting the precursor activities—use of SSH client tools, attempts to connect to hypervisor infrastructure, and command-line patterns indicating virtualization management activities.

The Security 4688 events with command-line logging provide the most valuable detection content, clearly showing the attempted pscp/plink execution with credentials and target paths. The failed exit codes actually enhance detection opportunities by providing examples of how these attacks fail in environments lacking proper network access or target systems.

## Detection Opportunities Present in This Data

1. **SSH Client Tool Execution** - Security 4688 events showing pscp.exe and plink.exe execution with hardcoded credentials in command lines
2. **Hypervisor Management Activity** - Command lines containing ESXi-related paths (/tmp) and VMware administration tools
3. **Credential Exposure** - Plaintext passwords ("pass") visible in process command lines during SSH connection attempts
4. **VIB File Handling** - References to .vib file extensions in command-line arguments indicating VMware package operations
5. **Failed Infrastructure Access** - Process exit codes 0xFF and 0x1 indicating connection or authentication failures to hypervisor targets
6. **PowerShell-to-SSH Tool Chain** - Process relationship between powershell.exe and SSH client utilities suggesting automated hypervisor management
7. **Atomic Red Team Indicators** - File paths containing "AtomicRedTeam" and "atomics" directories indicating security testing activity
