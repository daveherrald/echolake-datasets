# T1082-31: System Information Discovery — ESXi - VM Discovery using ESXCLI

## Technique Context

T1082 (System Information Discovery) encompasses adversary attempts to gather information about the host system they've compromised. While typically focused on Windows or Linux host enumeration, this specific test (T1082-31) simulates an interesting scenario where an attacker attempts to discover virtual machines on a VMware ESXi hypervisor using SSH and ESXCLI commands. This represents lateral movement from a Windows workstation to hypervisor infrastructure - a critical escalation path in virtualized environments.

The detection community focuses heavily on traditional system discovery commands like `whoami`, `systeminfo`, `wmic`, and PowerShell cmdlets. However, attacks against virtualization infrastructure require different detection approaches, particularly monitoring for SSH connections to hypervisors and ESXCLI command execution patterns.

## What This Dataset Contains

This dataset captures a failed attempt to connect to an ESXi server and execute VM discovery commands. The key evidence includes:

**Security Event 4688 process creation events** showing the attack chain:
- `whoami.exe` execution for initial reconnaissance
- `cmd.exe` execution with the command: `"cmd.exe" /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe" "atomic.local" -ssh -l "root" -pw "pass" -m "C:\AtomicRedTeam\atomics\T1082\src\esx_vmdiscovery.txt"`
- A child `cmd.exe` process with command: `C:\Windows\system32\cmd.exe /S /D /c" echo "" "`

**Sysmon Event ID 1 (ProcessCreate)** captures the same process creation chain with additional detail including file hashes and parent-child relationships.

**Process exit events (Security 4689)** show failure indicators:
- The main cmd.exe process exits with status `0xFF` (255), indicating failure
- The child cmd.exe exits with status `0x1` (1), also indicating failure

**PowerShell events** contain only test framework boilerplate (Set-ExecutionPolicy, Set-StrictMode) with no actual technique-related PowerShell execution.

## What This Dataset Does Not Contain

This dataset is missing several critical elements due to the test's failure to connect:

**No plink.exe execution**: The Sysmon config's include-mode filtering for ProcessCreate events means plink.exe execution wasn't captured, though Security 4688 events should have caught it if it executed successfully.

**No network connection events**: There are no Sysmon Event ID 3 (NetworkConnect) events showing the attempted SSH connection to the ESXi server, likely because the connection failed immediately.

**No successful ESXi command execution**: The test appears to fail at the SSH connection stage, so there's no telemetry of actual ESXCLI commands being executed on the target hypervisor.

**Limited failure details**: While exit codes indicate failure, there's no detailed error output showing why the SSH connection failed (likely because "atomic.local" doesn't exist or isn't reachable).

## Assessment

This dataset provides limited value for detection engineering focused on successful ESXi VM discovery attacks. The primary utility lies in demonstrating the Windows-side preparation and execution of such an attack, particularly the use of plink.exe for SSH connectivity to hypervisor infrastructure.

The Security 4688 events with command-line logging provide excellent coverage of the attack attempt, capturing the full command line including credentials, target host, and script file reference. However, the failure of the technique means there's no telemetry of successful hypervisor enumeration or the specific ESXCLI commands that would be executed.

For building detections around hypervisor attacks, you'll need datasets that capture successful connections and command execution on the ESXi side, not just the Windows launching point.

## Detection Opportunities Present in This Data

1. **SSH client execution with embedded credentials**: Monitor Security 4688 events for plink.exe, putty.exe, or ssh.exe execution with command lines containing `-pw` parameters and credential patterns.

2. **Hypervisor targeting indicators**: Detect processes attempting connections to common hypervisor hostnames (containing "esx", "vcenter", "vmware") or IP ranges typically used for management networks.

3. **Atomic Red Team artifact detection**: The command line references `C:\AtomicRedTeam\atomics\` paths and `..\ExternalPayloads\` which are clear indicators of testing frameworks.

4. **Suspicious PowerShell to cmd.exe chain**: Monitor for PowerShell processes spawning cmd.exe with complex command lines involving pipe operations and external tools.

5. **Process failure patterns**: Correlate process creation events with immediate exit codes (0xFF, 0x1) to identify failed attack attempts that may indicate reconnaissance or testing activity.

6. **SSH automation script references**: The `-m` parameter references a script file (`esx_vmdiscovery.txt`) - monitor for SSH clients being launched with script file parameters targeting hypervisor discovery.
