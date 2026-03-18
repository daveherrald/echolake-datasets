# T1218.007-1: Msiexec — Msiexec.exe - Execute Local MSI file with embedded JScript

## Technique Context

T1218.007 (Msiexec) represents a defense evasion technique where attackers abuse the Windows Installer service (msiexec.exe) to proxy execution of malicious code. This Living off the Land Binary (LOLBin) is particularly attractive to adversaries because msiexec.exe is a trusted, signed Microsoft binary that can execute custom actions embedded within MSI packages, including JScript, VBScript, PowerShell, and executables. The detection community focuses on monitoring msiexec.exe spawning from unusual parents, executing with suspicious command-line arguments (particularly network-based installations or quiet mode installations), and the child processes or network connections that result from embedded custom actions.

## What This Dataset Contains

This dataset captures a successful execution of msiexec.exe installing a malicious MSI file with embedded JScript. The process chain shows PowerShell (PID 23916) launching cmd.exe with the command `"cmd.exe" /c c:\windows\system32\msiexec.exe /q /i "C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_JScript.msi"`, which then spawns msiexec.exe (PID 22768) with the same MSI installation command.

Key telemetry includes:
- **Sysmon EID 1**: Process creation events for the complete chain: powershell.exe → cmd.exe → msiexec.exe
- **Security EID 4688**: Corresponding process creation events with full command lines
- **Application EIDs 1040/1042**: Windows Installer transaction start/end events showing MSI processing
- **Security EID 4703**: Token privilege adjustments for the msiexec.exe process, including elevation of SeAssignPrimaryTokenPrivilege and SeSecurityPrivilege
- **Security EID 4689**: Process exit events with exit code 0x653 (1619 - ERROR_INSTALL_PACKAGE_OPEN_FAILED) indicating the MSI installation failed

The msiexec.exe process (PID 22768) attempts to install the malicious MSI but fails with exit code 0x653, while a second msiexec.exe process (PID 24948) launches with `/V` flag for version checking.

## What This Dataset Does Not Contain

This dataset does not contain evidence of successful malicious code execution from the embedded JScript. The msiexec.exe process exits with error code 0x653 (ERROR_INSTALL_PACKAGE_OPEN_FAILED), indicating Windows Defender or another security control prevented the MSI from being processed. As a result, we don't see:
- Custom action execution (JScript payload)
- Network connections from embedded scripts
- File system changes from the malicious payload
- Registry modifications from the MSI installation
- Child processes spawned by the embedded JScript

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual test execution script. No Sysmon EID 3 (network connections) or additional EID 11 (file creation) events from malicious activity are present.

## Assessment

This dataset provides excellent telemetry for detecting msiexec.exe abuse attempts, even when the technique is blocked by security controls. The combination of Security 4688 events with command-line logging and Sysmon process creation events offers comprehensive visibility into the attack chain. The Application log events (1040/1042) provide definitive proof of MSI processing attempts, while the privilege escalation events (4703) show the elevated permissions msiexec.exe requests. The failure with exit code 0x653 demonstrates how modern endpoint protection can disrupt this technique while still leaving valuable forensic artifacts for detection engineering.

## Detection Opportunities Present in This Data

1. **Msiexec.exe with suspicious command-line arguments**: Security 4688 and Sysmon 1 events show msiexec.exe launched with `/q /i` flags and a local MSI path in a non-standard location (AtomicRedTeam directory)

2. **Msiexec.exe spawned by cmd.exe from PowerShell**: Process ancestry chain analysis showing powershell.exe → cmd.exe → msiexec.exe execution pattern

3. **Windows Installer transaction events**: Application 1040/1042 events indicating MSI processing attempts from suspicious file paths

4. **Privilege escalation during msiexec.exe execution**: Security 4703 events showing token right adjustments, particularly SeAssignPrimaryTokenPrivilege and SeSecurityPrivilege

5. **Msiexec.exe process exit with installation failure codes**: Security 4689 events with exit code 0x653 indicating blocked MSI installation attempts

6. **Multiple msiexec.exe processes spawned in short timeframe**: Detection of rapid msiexec.exe process creation suggesting automated or scripted installation attempts

7. **MSI files in unusual directories**: File path analysis showing MSI files located outside standard software installation directories (Program Files, temp directories)
