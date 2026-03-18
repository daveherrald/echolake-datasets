# T1222.001-4: Windows File and Directory Permissions Modification — attrib - hide file

## Technique Context

T1222.001 (Windows File and Directory Permissions Modification) is a defense evasion technique where attackers modify file or directory permissions to hide their activities or evade defensive measures. This specific test focuses on using the `attrib.exe` utility with the `+h` flag to set the hidden attribute on files, making them invisible to normal directory listings and GUI file browsers. While conceptually simple, this technique is frequently used by malware families to hide persistence mechanisms, tools, or stolen data. Detection engineers focus on monitoring `attrib.exe` executions with the `+h` parameter, unusual file attribute modifications, and combinations of file creation followed by immediate attribute changes.

## What This Dataset Contains

This dataset captures a complete execution of the attrib hiding technique with excellent telemetry coverage. The attack chain begins with PowerShell spawning cmd.exe with this command line: `"cmd.exe" /c mkdir %temp%\T1222.001_attrib_2 >nul 2>&1 & echo T1222.001_attrib1 >> %temp%\T1222.001_attrib_2\T1222.001_attrib1.txt & echo T1222.001_attrib2 >> %temp%\T1222.001_attrib_2\T1222.001_attrib2.txt & attrib.exe +h %temp%\T1222.001_attrib_2\T1222.001_attrib1.txt & attrib.exe +h %temp%\T1222.001_attrib_2\T1222.001_attrib2.txt`

Key events captured include:

- **Sysmon EID 1**: Process creation for cmd.exe (PID 44056), and two attrib.exe processes (PIDs 40976 and 32324) with command lines `attrib.exe +h C:\Windows\TEMP\T1222.001_attrib_2\T1222.001_attrib1.txt` and `attrib.exe +h C:\Windows\TEMP\T1222.001_attrib_2\T1222.001_attrib2.txt`
- **Sysmon EID 11**: File creation events showing the target files being created before having their attributes modified
- **Security EID 4688**: Complementary process creation events with full command lines for cmd.exe and both attrib.exe executions
- **Security EID 4689**: Process termination events showing successful completion (exit status 0x0) of all processes

The Sysmon events correctly trigger rule names "technique_id=T1564.001,technique_name=Hidden Files and Directories" for the attrib.exe processes, demonstrating that the sysmon-modular configuration properly identifies this activity.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide a more complete picture of file attribute modifications:

- **File system audit events**: No EID 4656/4658/4663 events showing the actual file attribute changes, as object access auditing was not enabled
- **Registry modifications**: Some file hiding techniques involve registry changes that aren't captured here
- **Before/after file listing**: No evidence of directory enumeration showing the files becoming hidden
- **PowerShell script content**: The PowerShell channel only contains test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual test script

The technique executed successfully without any Windows Defender interference, indicating this basic file hiding method was not blocked by real-time protection.

## Assessment

This dataset provides high-quality telemetry for detecting attrib-based file hiding. The combination of Sysmon process creation events and Security audit logs gives detection engineers multiple data sources to work with. The command-line logging is particularly valuable, as it captures the exact syntax used (`attrib.exe +h <filepath>`). The Sysmon rule matching correctly identifies this as a T1564.001 technique, though the dataset metadata indicates it as T1222.001, highlighting the overlap between these related techniques. The clean process chains and timestamps make this dataset excellent for developing and testing detection rules around file attribute manipulation.

## Detection Opportunities Present in This Data

1. **Monitor attrib.exe with +h parameter**: Alert on any execution of attrib.exe with the "+h" flag in the command line, especially when targeting user-writable directories like %TEMP%

2. **Detect rapid file creation followed by attribute modification**: Correlate Sysmon EID 11 (file creation) with subsequent attrib.exe processes targeting the same file paths within a short time window

3. **Identify suspicious parent processes invoking attrib**: Flag attrib.exe spawned by cmd.exe, PowerShell, or other scripting interpreters, particularly with command line patterns indicating batch operations

4. **Monitor for hidden file creation in common staging directories**: Alert when attrib +h is used against files in %TEMP%, %APPDATA%, or other common malware staging locations

5. **Detect chained file operations**: Identify command lines containing multiple file operations (mkdir, echo, attrib) combined with output redirection, indicating automated file creation and hiding workflows
