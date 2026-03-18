# T1083-7: File and Directory Discovery — ESXi - Enumerate VMDKs available on an ESXi Host

## Technique Context

T1083 File and Directory Discovery encompasses adversary attempts to enumerate files and folders within target systems to understand the environment and identify valuable data. The ESXi-specific variant targets VMware vSphere environments, where attackers attempt to discover virtual machine disk (VMDK) files and storage configurations on ESXi hypervisors. This technique is particularly valuable for ransomware operators targeting virtualized environments, as VMDKs contain the actual virtual machine data that can be encrypted or exfiltrated. Detection engineers typically focus on monitoring for unusual SSH connections to ESXi hosts, execution of ESXi-specific commands like `find`, `ls`, and `esxcli`, and attempts to enumerate datastore contents remotely.

## What This Dataset Contains

This dataset captures an attempt to execute ESXi file discovery commands remotely via SSH using PuTTY's plink utility. The key evidence appears in Security event 4688 showing the command execution:

`"cmd.exe" /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe" "atomic.local" -ssh  -l "root" -pw "pass" -m "C:\AtomicRedTeam\atomics\T1083\src\esxi_file_discovery.txt"`

The dataset shows a complete process chain starting with PowerShell (PID 35816), spawning cmd.exe (PID 11692), which attempts to pipe empty input to plink.exe for SSH connection to "atomic.local" with root credentials. A child cmd.exe process (PID 16920) is created with command line `C:\Windows\system32\cmd.exe  /S /D /c" echo "" "`, indicating the echo command execution. Both cmd.exe processes exit with non-zero status codes (0xFF and 0x1), suggesting the SSH connection attempt failed.

Sysmon captures the process creation events with full command lines, process access events showing PowerShell accessing both spawned processes (EID 10), and typical PowerShell .NET assembly loading. Security events provide complementary process creation and termination logging with exit status codes indicating failure.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful SSH connection establishment or actual ESXi command execution. There are no Sysmon network connection events (EID 3) showing successful TCP connections to port 22 on the target host, suggesting the connection attempt failed. The script file referenced (`esxi_file_discovery.txt`) is not captured in file creation events, and there's no evidence of the plink.exe process actually starting (likely due to connection failure). The dataset doesn't contain any ESXi-side logs that would show successful authentication or command execution. PowerShell script block logging shows only test framework boilerplate (`Set-ExecutionPolicy Bypass`) rather than the actual technique implementation.

## Assessment

This dataset provides limited detection value as it captures only a failed attempt at ESXi file discovery. While the command line artifacts are excellent for detecting the attack pattern, the lack of successful execution means defenders won't see the complete attack lifecycle. The process chain and command line logging from both Sysmon EID 1 and Security EID 4688 offer strong detection opportunities for the initial execution phase. The exit codes clearly indicate failure, which is valuable for understanding when techniques don't succeed due to network or authentication issues. For detection engineering, this represents the "attempt" phase of the attack but not the "success" phase.

## Detection Opportunities Present in This Data

1. Command line detection for plink.exe execution with SSH parameters containing hardcoded credentials (`-l "root" -pw "pass"`)
2. Process chain analysis showing PowerShell -> cmd.exe -> plink.exe execution pattern typical of automated SSH-based reconnaissance
3. Command line patterns containing references to ESXi-related script files (`esxi_file_discovery.txt`)
4. Detection of SSH client tools (plink.exe) being executed from scripted contexts rather than interactive sessions
5. Process access events showing PowerShell accessing child processes during SSH connection attempts
6. Non-zero exit codes from cmd.exe processes indicating failed remote connection attempts
7. File path patterns indicating Atomic Red Team testing framework usage (`C:\AtomicRedTeam\atomics\`)
