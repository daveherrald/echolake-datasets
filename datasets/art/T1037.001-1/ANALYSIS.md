# T1037.001-1: Logon Script (Windows) — Windows

## Technique Context

T1037.001 Logon Script (Windows) is a persistence technique where attackers configure scripts to execute automatically when users log into a Windows system. This technique leverages Windows' legitimate logon script functionality, which can be configured through Group Policy, Active Directory, or directly in the Windows Registry. Attackers commonly target the `UserInitMprLogonScript` registry value under `HKCU\Environment` or `HKLM\Environment` to establish persistence that survives reboots and executes with user privileges upon each logon.

The detection community focuses on monitoring registry modifications to known logon script locations, unusual script creation in temporary directories, and the execution chain from winlogon.exe to user-specified scripts. This technique is particularly attractive to attackers because it provides reliable persistence while appearing as legitimate system behavior.

## What This Dataset Contains

This dataset captures a complete execution of the Atomic Red Team T1037.001-1 test, which creates a malicious logon script and configures registry persistence. The key events show:

**Registry Modification**: Sysmon EID 13 captures the core persistence mechanism: `Registry value set: HKU\.DEFAULT\Environment\UserInitMprLogonScript` with the value `C:\Windows\TEMP\art.bat`, created by `reg.exe` (PID 4860).

**Process Chain**: Security EID 4688 events show the execution sequence: PowerShell → cmd.exe → reg.exe. The cmd.exe command line reveals the full attack: `"cmd.exe" /c echo "echo Art "Logon Script" atomic test was successful. >> %USERPROFILE%\desktop\T1037.001-log.txt" > %temp%\art.bat & REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_SZ /d "%temp%\art.bat" /f`

**File Creation**: Sysmon EID 11 shows the malicious script creation at `C:\Windows\Temp\art.bat` by cmd.exe (PID 6524).

**Sysmon Process Creation**: Three EID 1 events capture process creation for whoami.exe, cmd.exe, and reg.exe, with the reg.exe event showing the exact registry modification command.

## What This Dataset Does Not Contain

The dataset does not contain evidence of the logon script actually executing, as this would require a user logon event to trigger the persistence mechanism. The test only establishes the persistence—it doesn't demonstrate the payload execution that would occur during subsequent logons.

The PowerShell channel contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual technique implementation, which was executed through cmd.exe rather than native PowerShell commands.

No Group Policy or Active Directory logon script configurations are present, as this test specifically targets the registry-based persistence method.

## Assessment

This dataset provides excellent telemetry for detecting T1037.001 registry-based logon script persistence. The Sysmon EID 13 registry modification event is the gold standard detection point, capturing both the registry key and the script path. The Security 4688 events with command-line logging provide crucial context showing the complete attack chain and the exact commands used.

The combination of process creation, file creation, and registry modification events creates multiple detection opportunities and enables comprehensive threat hunting. The data quality is high with full command lines, process relationships, and file paths preserved.

## Detection Opportunities Present in This Data

1. **Registry Value Creation**: Monitor Sysmon EID 13 for `SetValue` events targeting `*\Environment\UserInitMprLogonScript` registry keys, especially from non-administrative processes or unusual parent processes.

2. **Suspicious REG.exe Usage**: Alert on Security EID 4688 process creation events for `reg.exe` with command lines containing `ADD` operations targeting `Environment\UserInitMprLogonScript`.

3. **Script File Creation in Temp Directories**: Monitor Sysmon EID 11 file creation events for `.bat`, `.cmd`, `.ps1`, or `.vbs` files created in `%TEMP%` or `%TMP%` directories followed by registry modifications.

4. **Process Chain Analysis**: Detect unusual parent-child relationships where `cmd.exe` or `powershell.exe` spawn `reg.exe` with environment registry modifications.

5. **Command Line Pattern Matching**: Hunt for Security EID 4688 events with command lines containing both file creation (`echo` or `>`) and registry modification (`REG.exe ADD`) operations in a single command.

6. **Cross-Event Correlation**: Correlate file creation events (Sysmon EID 11) with subsequent registry modifications (Sysmon EID 13) where the created file path appears as a registry value within a short time window.
