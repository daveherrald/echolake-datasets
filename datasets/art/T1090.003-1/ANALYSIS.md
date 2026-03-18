# T1090.003-1: Multi-hop Proxy — Multi-hop Proxy (Psiphon) on Windows 11 Enterprise domain workstation

## Technique Context

T1090.003 Multi-hop Proxy involves adversaries using multiple proxies to obscure traffic routes and evade detection. Psiphon is a circumvention tool that creates encrypted tunnels to bypass internet censorship, commonly abused by threat actors to hide command and control communications. The technique is particularly valuable for maintaining persistent access while making traffic analysis and attribution difficult. Detection engineering typically focuses on identifying proxy tool installation, unusual network traffic patterns, and process behaviors associated with tunneling software.

## What This Dataset Contains

This dataset captures an attempt to execute Psiphon through the Atomic Red Team test framework. The key evidence includes:

**Process Chain**: PowerShell (PID 39964) spawns another PowerShell instance (PID 40004) with command line `"powershell.exe" & {& \"C:\AtomicRedTeam\atomics\T1090.003\src\Psiphon.bat\"}`, which then launches cmd.exe (PID 22460) with `C:\Windows\system32\cmd.exe /c ""C:\AtomicRedTeam\atomics\T1090.003\src\Psiphon.bat""`.

**Exit Status Indicators**: Multiple Security 4689 events show process terminations with exit status 0x1 for cmd.exe processes and 0xFFFFFFFF (-1) for PowerShell and cmd.exe processes, indicating failures during execution.

**PowerShell Activity**: EID 4104 shows script block creation for `& {& "C:\AtomicRedTeam\atomics\T1090.003\src\Psiphon.bat"}` and typical PowerShell test framework activities like `Set-ExecutionPolicy Bypass`.

**Sysmon Coverage**: ProcessCreate events (EID 1) capture whoami.exe, PowerShell, and cmd.exe spawning. Network connection event (EID 3) shows Windows Defender connecting to 52.123.249.56:443. Process access events (EID 10) indicate PowerShell accessing child processes.

## What This Dataset Does Not Contain

**Missing Psiphon Execution**: The Psiphon.bat script appears to have failed to execute successfully based on the exit codes. There are no Sysmon ProcessCreate events for the actual Psiphon executable, suggesting it was not launched or was blocked.

**No Proxy Network Traffic**: Sysmon EID 3 only captures one network connection from Windows Defender, not the expected proxy tunnel establishment that would characterize successful Psiphon execution.

**Limited File Operations**: Only PowerShell profile file creation is captured (EID 11), with no evidence of Psiphon binary download, extraction, or execution artifacts.

**Blocked by Defender**: The failure exit codes combined with the absence of proxy-related network activity suggests Windows Defender likely prevented the Psiphon execution before it could establish tunnels.

## Assessment

This dataset provides moderate value for detection engineering focused on proxy tool deployment attempts rather than successful execution. The Security 4688 events with command-line logging offer excellent visibility into the execution chain, while Sysmon ProcessCreate events provide additional process lineage context. However, the dataset's utility is limited for understanding actual proxy traffic patterns since the technique was blocked. The data is most valuable for building detections around proxy tool deployment attempts, command-line patterns, and process behavior that occurs before successful tunnel establishment.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** for PowerShell executing batch files from Atomic Red Team paths containing "T1090" or "Psiphon"
2. **Process chain analysis** detecting PowerShell spawning cmd.exe with specific proxy-related batch file execution patterns  
3. **Unusual exit status monitoring** for processes terminating with failure codes (0x1, 0xFFFFFFFF) in proxy-related execution contexts
4. **File path monitoring** for executions from `C:\AtomicRedTeam\atomics\T1090.003\src\` indicating test framework usage
5. **PowerShell script block analysis** for patterns involving ampersand operators executing external batch files related to proxy tools
6. **Process access anomalies** where PowerShell accesses multiple child processes (whoami, cmd, other PowerShell instances) in rapid succession
7. **Failed execution clustering** when multiple proxy-related processes fail with similar exit codes within short time windows
