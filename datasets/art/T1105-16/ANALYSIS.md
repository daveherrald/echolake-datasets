# T1105-16: Ingress Tool Transfer — File download with finger.exe on Windows

## Technique Context

T1105 (Ingress Tool Transfer) involves adversaries transferring tools or files from an external system into a compromised environment. The finger.exe utility is a lesser-known Windows binary that can be abused for file transfer operations by connecting to finger servers and retrieving data. This technique is particularly interesting because finger.exe is a legitimate Windows utility that may fly under the radar of security tools focused on more common file transfer methods like PowerShell's Invoke-WebRequest or certutil.exe.

The detection community typically focuses on monitoring network connections from unusual processes, command-line patterns indicating file transfer operations, and the creation of files in suspicious locations. Finger.exe abuse is less commonly seen in the wild compared to other Living Off The Land Binaries (LOLBins), making it an effective technique for adversaries seeking to avoid detection.

## What This Dataset Contains

This dataset captures a PowerShell-initiated finger.exe command attempting to connect to localhost. The key telemetry includes:

**Process Creation Chain**: Security event 4688 shows the execution flow: PowerShell (PID 20164) → cmd.exe (PID 37968) → finger.exe (PID 40624) with command line `finger base64_filedata@localhost`. Sysmon EID 1 events capture the same process creations with additional metadata including file hashes and parent process relationships.

**Network Protocol Usage**: The command `finger base64_filedata@localhost` demonstrates the technique attempting to use the finger protocol to retrieve data, with "base64_filedata" likely representing encoded file content that would be served by a finger daemon.

**PowerShell Telemetry**: Multiple Sysmon EID 7 events show .NET framework DLLs being loaded into the PowerShell process, including System.Management.Automation components. PowerShell script block logging (EID 4104) contains only test framework boilerplate with Set-StrictMode commands and execution policy changes.

**Process Access**: Sysmon EID 10 events show PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating process monitoring or injection-style access patterns.

## What This Dataset Does Not Contain

The dataset lacks several critical elements for a complete T1105 analysis:

**Network Connection Events**: No Sysmon EID 3 events are present, meaning we cannot see if finger.exe actually established a network connection to localhost or any external host. This is crucial telemetry missing for validating whether the file transfer attempt succeeded.

**File Creation Evidence**: While the technique aims to download/transfer files, there are no Sysmon EID 11 events showing suspicious file creation that would result from a successful finger-based file transfer.

**DNS Query Telemetry**: No Sysmon EID 22 events are captured, which would show DNS resolution attempts if the technique targeted external hosts instead of localhost.

**Error or Success Indicators**: The process exit codes show 0x0 (success) for all processes, but without network or file evidence, we cannot determine if the finger operation actually transferred data or simply failed gracefully.

## Assessment

This dataset provides good process execution telemetry for finger.exe abuse detection but lacks the network and file system evidence needed to assess the technique's effectiveness. The Security 4688 and Sysmon EID 1 events offer excellent command-line visibility that would enable detection of finger.exe being used with suspicious parameters. However, the absence of network connection telemetry significantly limits the dataset's utility for understanding the complete attack chain.

The PowerShell process creation and library loading events provide valuable context about how attackers might invoke finger.exe programmatically, but the script block logging doesn't capture the actual PowerShell commands used to execute the technique. For detection engineering purposes, this dataset is most valuable for building process-based detections rather than network-based ones.

## Detection Opportunities Present in This Data

1. **Process execution of finger.exe with suspicious command-line patterns** - Security EID 4688 and Sysmon EID 1 show finger.exe executing with parameters that include "@" symbols, which could indicate data exfiltration attempts

2. **Unusual parent-child process relationships** - PowerShell spawning cmd.exe which then spawns finger.exe represents an uncommon process chain that could indicate automation or scripted attacks

3. **Command-line analysis for finger.exe data transfer patterns** - The command line `finger base64_filedata@localhost` contains patterns consistent with encoded data transfer that could be detected via regex matching

4. **Process access monitoring** - Sysmon EID 10 events show PowerShell accessing child processes with full rights, which could indicate process injection or monitoring techniques often used in attack frameworks

5. **LOLBin execution detection** - Finger.exe execution from non-administrative contexts or with network-related parameters could trigger alerts for Living Off The Land Binary abuse

6. **PowerShell execution policy changes** - EID 4103 events show execution policy being set to Bypass, which is often associated with malicious PowerShell usage
