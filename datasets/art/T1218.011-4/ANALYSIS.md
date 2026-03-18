# T1218.011-4: Rundll32 — Rundll32 advpack.dll Execution

## Technique Context

T1218.011 involves abusing rundll32.exe to execute malicious code while appearing as a legitimate Windows process. Rundll32 is a Windows utility that loads and runs 32-bit dynamic-link libraries (DLLs), making it an attractive target for attackers seeking to blend in with normal system activity. The advpack.dll variant specifically leverages the Advanced Pack (ADVPACK) library's `LaunchINFSection` function to execute code defined in INF files, which are typically used for software installation and configuration.

This technique is significant because rundll32.exe is a signed Microsoft binary that appears frequently in enterprise environments, making malicious usage difficult to distinguish from legitimate activity. Detection engineers focus on unusual DLL/function combinations, suspicious command-line parameters, and process relationships that deviate from normal administrative tasks.

## What This Dataset Contains

This dataset captures a successful execution of rundll32.exe with advpack.dll targeting an INF file. The key evidence includes:

**Process Creation Chain (Security 4688 & Sysmon 1):**
- PowerShell (PID 21480) spawns cmd.exe (PID 18720) with command: `"cmd.exe" /c rundll32.exe advpack.dll,LaunchINFSection "C:\AtomicRedTeam\atomics\T1218.011\src\T1218.011.inf",DefaultInstall_SingleUser,1,`
- Cmd.exe spawns rundll32.exe (PID 20396) with the full advpack.dll command line
- The technique executes successfully with all processes exiting cleanly (exit status 0x0)

**Sysmon Process Access Events (EID 10):**
- PowerShell accessing whoami.exe with full process rights (0x1FFFFF)
- PowerShell accessing cmd.exe with full process rights, showing the parent-child relationship

**File System Activity (Sysmon 11):**
- PowerShell profile data file creation, indicating normal PowerShell startup behavior

The dataset shows the complete execution chain from PowerShell → cmd.exe → rundll32.exe with the advpack.dll,LaunchINFSection parameters targeting a test INF file.

## What This Dataset Does Not Contain

The dataset lacks several important elements for comprehensive detection coverage:

**Missing Sysmon ProcessCreate events:** The sysmon-modular configuration's include-mode filtering means we don't see Sysmon EID 1 events for the initial PowerShell process or intermediate processes that don't match suspicious patterns. Only whoami.exe, cmd.exe, and rundll32.exe triggered Sysmon process creation events.

**No DLL load events for rundll32.exe:** Despite Sysmon's image load monitoring being enabled, we don't see EID 7 events showing rundll32.exe loading advpack.dll, which would provide additional forensic detail about the DLL execution.

**Limited file system visibility:** We don't see the INF file being accessed or any files potentially created/modified by the INF execution, which could indicate the technique's payload effects.

**No network activity:** If the INF file contained network-based actions, those connections aren't visible in this dataset.

## Assessment

This dataset provides excellent visibility into the core T1218.011 technique execution. The Security channel's command-line auditing captures the complete attack chain with full command-line parameters, while Sysmon adds process relationship details and access patterns. The combination of Security 4688 events and Sysmon 1/10 events gives detection engineers the primary artifacts needed to identify this technique.

The data quality is high for building detections focused on rundll32.exe abuse patterns, unusual parent-child relationships, and advpack.dll usage. However, the missing DLL load events and file system activity limit the dataset's utility for understanding the technique's full impact or building content-aware detections.

## Detection Opportunities Present in This Data

1. **Rundll32 with advpack.dll usage** - Security 4688 and Sysmon 1 showing rundll32.exe with "advpack.dll,LaunchINFSection" in the command line, particularly when launched from unusual parent processes

2. **Suspicious parent-child process relationships** - cmd.exe or PowerShell spawning rundll32.exe with DLL parameters, detected via ParentImage and ParentCommandLine fields in process creation events

3. **INF file targeting in rundll32 parameters** - Command-line analysis for rundll32.exe referencing .inf files, especially from non-standard locations like temp directories or user profiles

4. **Process access anomalies** - Sysmon EID 10 showing PowerShell or other scripting processes accessing rundll32.exe with full process rights (0x1FFFFF), indicating potential process manipulation

5. **Rundll32 execution from scripting contexts** - Security 4688 events showing rundll32.exe spawned by powershell.exe, cmd.exe, or other scripting interpreters rather than typical system processes
