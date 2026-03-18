# T1218-12: System Binary Proxy Execution — Lolbas ie4uinit.exe use as proxy

## Technique Context

T1218 System Binary Proxy Execution represents a fundamental defense evasion technique where attackers abuse legitimate, signed system binaries to execute malicious code. The ie4uinit.exe binary, part of Internet Explorer's initialization utilities, is a particularly interesting Living off the Land Binary (LOLBin) because it can process .inf files and execute scriptlets through the `-BaseSettings` parameter. This technique matters because ie4uinit.exe is a Microsoft-signed binary that security tools typically trust, making it an effective method for bypassing application controls and evading detection. Attackers use this technique to execute arbitrary code while appearing to run legitimate system processes, often as part of initial access or persistence mechanisms. The detection community focuses on monitoring unusual command-line arguments to ie4uinit.exe, execution from non-standard locations, and the creation of associated .inf or .sct files.

## What This Dataset Contains

This dataset captures a complete execution chain of the ie4uinit.exe proxy technique. The Security channel shows the full process tree starting with PowerShell (PID 11424) spawning cmd.exe (PID 10728) with the command line `"cmd.exe" /c copy c:\windows\system32\ie4uinit.exe %TEMP%\ie4uinit.exe & copy "C:\AtomicRedTeam\atomics\T1218\src\ieuinit.inf" %TEMP%\ieuinit.inf & %TEMP%\ie4uinit.exe -BaseSettings`. 

Sysmon captures the binary being copied to `C:\Windows\Temp\ie4uinit.exe` (EID 11), followed by creation of the malicious .inf file at `C:\Windows\Temp\ieuinit.inf` (EID 11). The technique execution is visible through two ie4uinit.exe processes: the initial process (PID 41048) with `-BaseSettings` argument, which spawns a child process (PID 10384) with `-ClearIconCache`. 

Critical evidence includes the loading of `scrobj.dll` (SHA256=3BD8F209ED5C65E787D5FC195285E3B23638E191407BC52BEB64B2C212BAC2FA), which handles script component execution, and the creation of `test[1].sct` in the INetCache directory. The Sysmon events show multiple process access events (EID 10) between the PowerShell parent and spawned processes, indicating the technique's execution flow.

## What This Dataset Does Not Contain

The dataset lacks visibility into the actual content of the malicious .inf and .sct files that drive the technique's payload execution. While Sysmon captures file creation events, it doesn't provide file content analysis. The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy Bypass commands) rather than the actual Atomic Red Team test commands that orchestrated this technique. Network connections that might result from payload execution are not present, suggesting either the test payload was benign or no network activity occurred. Registry modifications that ie4uinit.exe might perform during legitimate operation are not captured in this dataset, as the Sysmon configuration doesn't include registry monitoring. The dataset also lacks detailed information about what the scriptlet component actually executed beyond basic file system artifacts.

## Assessment

This dataset provides excellent telemetry for detecting ie4uinit.exe abuse through multiple complementary data sources. The Security 4688 events capture the complete command-line arguments showing the staging and execution phases, while Sysmon ProcessCreate events (EID 1) provide detailed process genealogy with full command lines and file hashes. The combination of file creation events (EID 11) showing the binary staging, .inf file placement, and .sct file creation provides a comprehensive view of the technique's execution. Sysmon's image load events (EID 7) capture the loading of scrobj.dll, which is a key indicator of script component processing. The process access events (EID 10) show the parent-child relationships that characterize this technique. The dataset would be stronger with registry monitoring to capture ie4uinit.exe's legitimate configuration changes and network monitoring to detect potential payload communications.

## Detection Opportunities Present in This Data

1. Monitor Security EID 4688 for ie4uinit.exe execution with `-BaseSettings` parameter, especially when executed from non-standard locations like %TEMP%
2. Detect file creation events (Sysmon EID 11) where ie4uinit.exe is copied from System32 to writable directories like %TEMP%
3. Alert on Sysmon EID 11 creation of .inf files in temporary directories, particularly when followed by ie4uinit.exe execution
4. Monitor Sysmon EID 7 image loads of scrobj.dll by ie4uinit.exe processes, indicating script component processing
5. Correlate Sysmon EID 1 process creation of ie4uinit.exe with unusual parent processes (cmd.exe, PowerShell) rather than typical system initialization
6. Detect creation of .sct files in INetCache directories (Sysmon EID 11) as indicators of scriptlet execution
7. Monitor process access patterns (Sysmon EID 10) where ie4uinit.exe spawns child processes with different command-line arguments
8. Alert on ie4uinit.exe execution chains that include both `-BaseSettings` and `-ClearIconCache` parameters in rapid succession
9. Detect execution of ie4uinit.exe with full file paths in command lines rather than simple binary names
10. Monitor for ie4uinit.exe processes that create files outside of expected Internet Explorer configuration directories
