# T1112-42: Modify Registry — Terminal Server Client Connection History Cleared

## Technique Context

T1112 Modify Registry is a core defense evasion and persistence technique where attackers alter Windows registry entries to maintain access, disable security controls, or cover their tracks. This specific test (T1112-42) focuses on clearing Terminal Server Client (Remote Desktop) connection history by deleting registry keys under `HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client`. This is a common anti-forensics technique used by attackers to remove evidence of lateral movement via RDP connections. Detection engineers typically focus on monitoring registry deletion operations targeting security-relevant keys, process lineage involving reg.exe, and PowerShell executing registry modification commands.

## What This Dataset Contains

This dataset captures the complete execution of Terminal Server Client history clearing through PowerShell-initiated registry deletions. The Security channel shows the full process chain: PowerShell (PID 19900) spawns cmd.exe with the command `"cmd.exe" /c reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" /va /f & reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers" /f`, which then spawns two reg.exe processes targeting the specific registry paths. 

Sysmon EID 1 events capture the process creations with full command lines showing the registry deletion commands: `reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" /va /f` and `reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers" /f`. The Security 4688 events provide complementary process creation telemetry with the same command-line details. Exit status codes show the first reg.exe succeeded (exit status 0x0) while the second failed (exit status 0x1), likely because the target key didn't exist.

The PowerShell channel contains only test framework boilerplate - Set-StrictMode and Set-ExecutionPolicy Bypass commands - without the actual technique implementation, indicating the test was executed through a pre-compiled script rather than interactive PowerShell.

## What This Dataset Does Not Contain

This dataset lacks Sysmon EID 13 (Registry Value Set) or EID 12 (Registry Object Added or Deleted) events that would show the actual registry modifications. The sysmon-modular configuration may not include registry monitoring rules for these specific keys, or the deletion operations may have failed due to non-existent keys. Additionally, there are no network connections or file system artifacts beyond standard PowerShell profile files, which is expected for this registry-focused technique.

## Assessment

This dataset provides excellent telemetry for detecting registry-based anti-forensics techniques through process execution monitoring. The Security and Sysmon process creation events offer comprehensive coverage of the technique execution with full command-line arguments clearly showing the targeted registry paths. The process lineage (PowerShell → cmd.exe → reg.exe) is fully captured and would support robust detection rules. However, the absence of actual registry modification events limits the ability to confirm successful execution and develop registry-focused detection logic.

## Detection Opportunities Present in This Data

1. **Registry deletion command execution** - Security EID 4688 and Sysmon EID 1 showing reg.exe with "delete" operations targeting Terminal Server Client paths
2. **PowerShell spawning cmd.exe with registry commands** - Process lineage showing PowerShell executing cmd.exe with reg delete parameters
3. **Terminal Server Client registry targeting** - Command line arguments containing specific paths "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client"
4. **Anti-forensics process patterns** - Multiple consecutive reg.exe executions targeting connection history storage locations
5. **System-level registry modifications** - NT AUTHORITY\SYSTEM context performing user registry deletions (unusual privilege context)
6. **Batch command execution** - cmd.exe with /c parameter executing multiple registry deletion commands in sequence
7. **Registry tool abuse** - reg.exe usage with force deletion flags (/f) and value deletion (/va) parameters
