# T1105-20: Ingress Tool Transfer — Download a file with Microsoft Connection Manager Auto-Download

## Technique Context

T1105 (Ingress Tool Transfer) covers how adversaries transfer tools and files from external systems into compromised environments. This specific test attempts to use Microsoft Connection Manager Auto-Download, a feature designed to automatically download and execute content based on Connection Manager profiles (.cmp files). Attackers abuse this mechanism as an alternative download method to bypass security controls that might block traditional tools like PowerShell's Invoke-WebRequest or certutil. Connection Manager profiles can be crafted to download and execute malicious payloads, making this technique particularly concerning for defense teams monitoring file transfer activities.

## What This Dataset Contains

This dataset captures a test execution that appears to have failed. The primary evidence shows:

**Process Execution Chain**: Security EID 4688 shows PowerShell (PID 26192) spawning `"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1105\src\T1105.bat" 1>NUL`, which exits with status code 0x1 (failure). Sysmon EID 1 confirms the same command line execution.

**PowerShell Activity**: Both PowerShell instances (PIDs 43564 and 26192) show standard initialization with .NET runtime loading (mscoree.dll, mscoreei.dll, clr.dll) and PowerShell automation assembly loading. Sysmon EID 7 events capture these library loads. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass).

**File System Activity**: Sysmon EID 11 shows PowerShell creating profile data files in `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`.

**Process Access Events**: Sysmon EID 10 shows PowerShell accessing both the whoami.exe process (PID 15012) and cmd.exe process (PID 24412) with full access rights (0x1FFFFF).

**Missing Network Activity**: No DNS queries, network connections, or file downloads are captured in this dataset, indicating the Connection Manager Auto-Download mechanism did not execute successfully.

## What This Dataset Does Not Contain

The dataset lacks the key evidence of successful T1105 execution. Missing elements include:

- **Network Connections**: No Sysmon EID 3 events showing outbound connections to download files
- **DNS Queries**: No Sysmon EID 22 events for domain resolution
- **Downloaded Files**: No file creation events showing downloaded payloads
- **Connection Manager Activity**: No process creation events for Connection Manager (rasdial.exe, rasphone.exe) or related utilities
- **Success Indicators**: The cmd.exe process exits with code 0x1, indicating the batch file execution failed

The failure could be due to several factors: Windows Defender blocking the technique, network restrictions, missing dependencies, or the test environment lacking required Connection Manager components.

## Assessment

This dataset provides limited value for detecting successful T1105 via Connection Manager Auto-Download since the technique execution failed. However, it offers moderate utility for detection engineering because it captures the attempt artifacts that would be visible regardless of success. The process execution chain from PowerShell to cmd.exe with the specific Atomic Red Team batch file path is clearly documented. The combination of Security EID 4688 command-line logging and Sysmon EID 1 process creation provides comprehensive coverage of the initial execution attempt. Detection engineers can use this data to build signatures for the attempt phase, but would need successful execution samples to develop complete detection coverage.

## Detection Opportunities Present in This Data

1. **Atomic Red Team Artifact Detection**: Security EID 4688 and Sysmon EID 1 capture command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1105\src\T1105.bat" 1>NUL`, enabling detection of this specific test execution path.

2. **Failed Process Execution Monitoring**: Security EID 4689 shows cmd.exe exiting with status code 0x1, allowing detection logic to identify and investigate failed tool transfer attempts.

3. **PowerShell to cmd.exe Process Chain**: The parent-child relationship between PowerShell (PID 26192) and cmd.exe (PID 24412) executing batch files could indicate suspicious script-initiated file operations.

4. **Process Access Pattern Detection**: Sysmon EID 10 shows PowerShell accessing spawned processes with full privileges (0x1FFFFF), which could indicate process injection preparation or monitoring behavior.

5. **Batch File Execution from Temp Directory**: The working directory `C:\Windows\TEMP\` combined with batch file execution provides a behavioral indicator for potential staging activities.
