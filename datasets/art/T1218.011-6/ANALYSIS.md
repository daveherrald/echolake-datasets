# T1218.011-6: Rundll32 — Rundll32 syssetup.dll Execution

## Technique Context

T1218.011 represents the abuse of rundll32.exe to proxy execution of malicious code while masquerading as a legitimate Windows utility. Rundll32.exe is a standard Windows binary designed to execute functions from DLLs, making it an attractive target for living-off-the-land techniques. Attackers commonly leverage rundll32.exe to execute malicious DLLs, bypass application whitelisting, or invoke specific functions within legitimate DLLs for malicious purposes.

This specific test focuses on the syssetup.dll export `SetupInfObjectInstallAction`, which processes Windows Setup Information (INF) files. INF files can contain directives to copy files, modify registry keys, or execute commands during installation routines. The detection community typically focuses on unusual rundll32.exe command lines, particularly those involving non-standard DLLs, uncommon export functions, or suspicious file paths.

## What This Dataset Contains

The dataset captures a complete execution chain showing rundll32.exe being used to process a malicious INF file. The attack begins with PowerShell launching cmd.exe, which then spawns rundll32.exe with the command line: `rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 "C:\AtomicRedTeam\atomics\T1218.011\src\T1218.011_DefaultInstall.inf"`.

Security Event 4688 captures the full process creation chain: PowerShell (PID 16160) → cmd.exe (PID 17080) → rundll32.exe (PID 36540). The rundll32.exe process is created with the suspicious command line referencing the Atomic Red Team test INF file. Sysmon Event 1 provides additional context with process hashes (SHA256=63D689421DB32725B79CE7E11B8B0414AB64C4208A81634F0D640E2873B63C6F) and the parent-child relationship clearly established through ProcessGuid fields.

The execution completes successfully as evidenced by Security Event 4689 showing rundll32.exe exiting with status 0x0, indicating the INF file was processed without errors. Sysmon also captures process access events (Event 10) showing PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), which is typical behavior for process spawning operations.

## What This Dataset Does Not Contain

The dataset lacks visibility into the actual effects of the INF file execution. There are no registry modification events, file creation events from the rundll32.exe process itself, or network connections that might result from INF file processing. This suggests either the test INF file performs minimal actions, or the sysmon-modular configuration doesn't capture these specific artifact types.

Notably absent are any Windows Defender alerts or blocking actions despite real-time protection being active. The rundll32.exe process executed successfully with exit code 0x0, indicating Defender didn't recognize this specific syssetup.dll abuse pattern as malicious. There are also no Sysmon ProcessCreate events for rundll32.exe itself, as the sysmon-modular config uses include-mode filtering and rundll32.exe apparently doesn't match the suspicious process patterns in this configuration.

## Assessment

This dataset provides excellent telemetry for detecting rundll32.exe abuse through command-line analysis. The Security channel's 4688 events capture the complete command line with full arguments, making this technique highly detectable through process monitoring. The parent-child process relationship is clearly established, and the unusual export function `SetupInfObjectInstallAction` combined with the suspicious file path creates multiple detection opportunities.

However, the dataset's value is somewhat limited by the lack of post-execution artifacts. Without seeing registry changes, file modifications, or other system impacts, analysts cannot fully understand the technique's effects or build comprehensive detection rules that account for the full attack lifecycle. The successful execution without Defender intervention also suggests this specific variant might evade some endpoint protection solutions.

## Detection Opportunities Present in This Data

1. **Rundll32.exe with syssetup.dll and uncommon exports** - Monitor Security 4688 events for rundll32.exe command lines containing `syssetup.dll,SetupInfObjectInstallAction`, as this export is rarely used legitimately
2. **Rundll32.exe processing INF files from non-standard locations** - Alert on rundll32.exe command lines referencing `.inf` files outside of `%SystemRoot%\inf\` or Windows Update directories
3. **Process chain analysis** - Detect PowerShell or cmd.exe spawning rundll32.exe with syssetup.dll, as this combination is uncommon in legitimate scenarios
4. **Suspicious file path patterns** - Monitor for INF files in user-controlled directories (Downloads, Temp, user profiles) being processed by rundll32.exe
5. **Rundll32.exe spawned by scripting engines** - Alert when PowerShell, cmd.exe, or other scripting hosts directly spawn rundll32.exe with non-standard DLL/export combinations
