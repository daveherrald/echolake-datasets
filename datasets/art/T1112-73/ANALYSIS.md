# T1112-73: Modify Registry — Flush Shimcache

## Technique Context

T1112 Modify Registry encompasses various methods attackers use to alter Windows registry entries for persistence, defense evasion, or operational purposes. This specific test (T1112-73) focuses on flushing the shimcache (Application Compatibility Cache) through the `rundll32.exe apphelp.dll,ShimFlushCache` command. The shimcache is a Windows mechanism that tracks application execution for compatibility purposes, but it also serves as a valuable forensic artifact for incident responders. Attackers may flush the shimcache to remove evidence of malicious program execution, making forensic analysis more difficult. This technique is particularly relevant for defense evasion as it directly attempts to eliminate execution artifacts that security teams rely on for threat hunting and incident response.

## What This Dataset Contains

This dataset captures a successful shimcache flush execution through PowerShell and cmd.exe. The core activity is visible in Security event 4688 showing the process chain: `powershell.exe` spawns `cmd.exe` with command line `"cmd.exe" /c Rundll32.exe apphelp.dll,ShimFlushCache`, which then spawns `rundll32.exe` with `Rundll32.exe apphelp.dll,ShimFlushCache`. Sysmon EID 1 events provide corresponding process creation data for cmd.exe (ProcessId 43684) and rundll32.exe (ProcessId 37812), both executed with SYSTEM privileges. The PowerShell events show only boilerplate content (Set-StrictMode script blocks and Set-ExecutionPolicy Bypass commands) without the actual technique implementation. Sysmon EID 10 events capture PowerShell accessing both the cmd.exe and whoami.exe processes with full access rights (0x1FFFFF), indicating normal process monitoring behavior. All processes exit cleanly with status 0x0 as recorded in Security EID 4689 events.

## What This Dataset Does Not Contain

This dataset lacks registry modification events that would directly show the shimcache being cleared. Windows doesn't generate standard registry events for this internal cache operation, and the Sysmon configuration doesn't capture registry events (Object Access auditing is set to "none"). The PowerShell script block logging contains only test framework boilerplate rather than the actual Invoke-AtomicTest command that executed the technique. There are no network events, file system changes, or other persistence mechanisms - this is purely a shimcache manipulation technique. The dataset also doesn't include before/after registry snapshots that would demonstrate the cache clearing effect.

## Assessment

This dataset provides solid process execution telemetry for shimcache flushing detection but lacks the deeper registry-level evidence of the technique's impact. The command-line auditing in Security logs and Sysmon ProcessCreate events clearly show the suspicious rundll32.exe execution with apphelp.dll,ShimFlushCache parameters. However, without registry auditing or specialized shimcache monitoring, you cannot directly observe the cache being cleared. This is typical for this technique - the execution is visible but the registry impact requires specialized forensic tools to detect. The data quality is good for building detections around the observable process behaviors but insufficient for understanding the technique's full forensic impact.

## Detection Opportunities Present in This Data

1. **Rundll32 shimcache flushing** - Security EID 4688 and Sysmon EID 1 showing `rundll32.exe` with command line containing `apphelp.dll,ShimFlushCache`

2. **Suspicious cmd.exe execution** - Process creation of `cmd.exe` with `/c Rundll32.exe apphelp.dll,ShimFlushCache` command line, indicating scripted shimcache manipulation

3. **PowerShell spawning system utilities** - PowerShell process (PID 42968) spawning both whoami.exe and cmd.exe, suggesting reconnaissance followed by system modification

4. **SYSTEM-level shimcache manipulation** - All processes running as NT AUTHORITY\SYSTEM with high integrity, indicating privileged shimcache clearing operations

5. **Process access patterns** - Sysmon EID 10 showing PowerShell accessing spawned processes with full privileges (0x1FFFFF), consistent with process monitoring during execution
