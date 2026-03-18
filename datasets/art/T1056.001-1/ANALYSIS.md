# T1056.001-1: Keylogging — Input Capture

## Technique Context

T1056.001 - Keylogging is a collection technique where adversaries capture user keystrokes to obtain credentials, sensitive data, or other information typed by users. Keyloggers can be hardware-based, software-based, or kernel-level, with software keyloggers being most common in attack scenarios. Adversaries typically deploy keyloggers through malware, compromised applications, or direct installation on compromised systems. The detection community focuses on identifying keylogger installation, monitoring for suspicious API calls related to keyboard hooks (SetWindowsHookEx, GetAsyncKeyState), detecting files with keylogger signatures, and observing unusual process behavior that suggests keystroke capture functionality.

## What This Dataset Contains

This dataset captures execution of the Atomic Red Team T1056.001-1 test, which deploys a PowerShell-based keylogger script. The key evidence includes:

- **PowerShell Process Creation**: Security event 4688 shows creation of `powershell.exe` with command line `"powershell.exe" & {&\"C:\AtomicRedTeam\atomics\T1056.001\src\Get-Keystrokes.ps1\" -LogPath $env:TEMP\key.log}`, directly revealing the keylogger script path and output log location.

- **Sysmon Process Creation**: Event ID 1 captures the same PowerShell process with ProcessId 34308, showing the keylogger script execution with full command line details including the target log path `$env:TEMP\key.log`.

- **Process Access Events**: Sysmon events ID 10 show the PowerShell process accessing other processes (whoami.exe and another PowerShell instance) with GrantedAccess 0x1FFFFF (full access rights), indicating potential injection or monitoring behavior typical of keyloggers.

- **PowerShell Script Block Logging**: Multiple 4104 events capture PowerShell script block creation, though most contain only test framework boilerplate (`Set-StrictMode`, error handling functions) rather than the actual keylogger code.

- **File System Activity**: Sysmon event ID 11 shows PowerShell creating files in the system profile directory, though not the specific keylog output file.

## What This Dataset Does Not Contain

The dataset lacks several critical elements for comprehensive keylogger detection:

- **Actual Keylogger Script Content**: PowerShell script block logging (4104) only captures test framework boilerplate rather than the Get-Keystrokes.ps1 script content, missing the actual keylogging implementation details.

- **API Hook Evidence**: No events capture the specific Windows API calls typically used by keyloggers (SetWindowsHookEx, GetAsyncKeyState, RegisterRawInputDevices) that would indicate keyboard hook installation.

- **Output Log File Creation**: While the command line references `$env:TEMP\key.log`, no Sysmon file creation events show this specific output file being created.

- **Keystroke Capture Evidence**: No events demonstrate actual keystroke interception or logging functionality, likely because the test ran in a non-interactive environment.

- **Registry Modifications**: No registry events show persistence mechanisms or configuration changes typical of keylogger installations.

## Assessment

This dataset provides moderate value for keylogger detection engineering. The command-line evidence in both Security 4688 and Sysmon 1 events clearly identifies keylogger tool execution, making it excellent for detecting this specific Atomic Red Team test. However, the dataset's utility for broader keylogger detection is limited because it captures only the initial deployment phase rather than the actual keystroke interception behavior. The missing PowerShell script content and API-level evidence reduces its value for understanding keylogger implementation patterns. The process access events provide some behavioral indicators but lack the specific API call patterns that characterize most keyloggers.

## Detection Opportunities Present in This Data

1. **PowerShell Keylogger Script Execution**: Monitor Security 4688 and Sysmon 1 for powershell.exe processes with command lines containing "Get-Keystrokes", "keylog", or paths to known keylogger scripts.

2. **Atomic Red Team Keylogger Path Detection**: Alert on command lines referencing `\AtomicRedTeam\atomics\T1056.001\src\Get-Keystrokes.ps1` to detect this specific test execution.

3. **PowerShell Process with Suspicious Parameters**: Detect powershell.exe processes with `-LogPath` parameters combined with file paths ending in common keylogger output extensions (.log, .txt, .dat).

4. **High-Privilege Process Access from PowerShell**: Monitor Sysmon 10 events where PowerShell processes access other processes with full access rights (0x1FFFFF), particularly when combined with suspicious command lines.

5. **PowerShell Execution with TEMP Directory Logging**: Correlate PowerShell execution with command lines referencing `$env:TEMP` for log output, indicating potential data exfiltration staging.

6. **Process Chain Analysis**: Detect PowerShell parent-child relationships where the parent executes keylogger-related commands and spawns child PowerShell processes, indicating script-based keylogger deployment.

7. **System Profile Directory File Creation**: Monitor Sysmon 11 events for PowerShell creating files in system profile directories, which may indicate keylogger persistence or configuration file creation.
