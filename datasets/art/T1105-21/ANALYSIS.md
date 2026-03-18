# T1105-21: Ingress Tool Transfer — MAZE Propagation Script

## Technique Context

T1105 Ingress Tool Transfer covers adversaries transferring tools or other files from external systems into compromised environments. This particular test simulates the MAZE ransomware's lateral movement script, which copies malicious executables to multiple network hosts and executes them remotely. The MAZE ransomware family was notorious for combining encryption with data exfiltration and used automated propagation scripts to spread across enterprise networks.

The detection community focuses on unusual file copies to administrative shares (C$), remote process execution via WMIC, use of regsvr32.exe for execution, and PowerShell scripts that iterate through host lists. These behaviors represent common lateral movement patterns seen across multiple ransomware families and APT groups.

## What This Dataset Contains

The core technique execution is captured in Security event 4688, which shows PowerShell launching with a complete MAZE propagation script command line:

```
"powershell.exe" & {$machine_list = "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1105MachineList.txt"
$offline_list = "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1105OfflineHosts.txt"
$completed_list = "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1105CompletedHosts.txt"
foreach ($machine in get-content -path "$machine_list")
{if (test-connection -Count 1 -computername $machine -quiet) 
{cmd /c copy "$env:comspec" "\\$machine\C$\Windows\Temp\T1105.exe"
echo $machine >> "$completed_list"
wmic /node: "$machine" process call create "regsvr32.exe /i C:\Windows\Temp\T1105.exe"}
else
{echo $machine >> "$offline_list"}}}
```

PowerShell script block logging in event 4104 captures the same script content across multiple script blocks. Sysmon provides process creation events for whoami.exe (EID 1) and the child PowerShell process (EID 1), along with process access events (EID 10) showing PowerShell accessing both the whoami and child PowerShell processes. The telemetry includes detailed parent-child process relationships, with the parent PowerShell (PID 27268) spawning both whoami (PID 28132) and a child PowerShell (PID 24072) to execute the MAZE script.

## What This Dataset Does Not Contain

This dataset represents script execution without actual network propagation. The key missing elements are:
- Network file copy operations to remote C$ shares (no Sysmon EID 3 network connections)
- Remote WMIC process creation attempts (no evidence of successful or failed remote execution)
- Error events from failed network operations or access denied messages
- File creation events for T1105.exe being copied to remote systems
- DNS queries for hostname resolution during host list enumeration

The absence of network activity suggests either the machine list file was empty/nonexistent, or network connectivity to target hosts failed immediately. This is common in isolated test environments where the lateral movement components cannot complete successfully.

## Assessment

This dataset provides excellent visibility into the initial stages of automated lateral movement scripts but lacks the network propagation evidence that would make it complete for detection engineering. The PowerShell script block logging and Security 4688 events with command-line capture provide the primary detection value, showing the full script logic including file paths, remote execution methods (WMIC + regsvr32), and target file placement.

The Sysmon coverage captures process relationships and basic execution flow, but the filtered ProcessCreate configuration means some child processes may be missing. The lack of network telemetry significantly limits the dataset's utility for detecting the actual file transfer and remote execution components of the technique.

## Detection Opportunities Present in This Data

1. **MAZE-specific PowerShell script patterns** - PowerShell 4104 events containing the distinctive MAZE propagation script structure with machine lists, offline lists, and completed lists file references.

2. **Administrative share file copy commands** - Security 4688 command lines containing `copy "$env:comspec" "\\$machine\C$\Windows\Temp\"` patterns indicating cmd.exe being copied to remote admin shares.

3. **Remote WMIC process execution attempts** - Command lines containing `wmic /node:` followed by `process call create` and regsvr32.exe execution, indicating remote process creation attempts.

4. **Regsvr32.exe abuse for execution** - PowerShell scripts using regsvr32.exe with the `/i` flag to execute copied binaries, a common LOLBin technique.

5. **Bulk network host enumeration** - PowerShell scripts reading from machine list files and performing test-connection operations against multiple hosts in sequence.

6. **PowerShell parent-child process spawning** - Sysmon EID 1 showing PowerShell processes creating child PowerShell processes with suspicious command lines containing lateral movement logic.
