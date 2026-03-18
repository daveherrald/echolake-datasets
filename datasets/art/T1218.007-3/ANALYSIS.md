# T1218.007-3: Msiexec — Msiexec.exe - Execute Local MSI file with an embedded DLL

## Technique Context

T1218.007 focuses on abusing msiexec.exe, Windows' legitimate installer service, to execute malicious code while evading detection. Attackers leverage msiexec's trusted reputation and its ability to execute custom actions embedded within MSI packages. This technique is particularly attractive because msiexec runs with elevated privileges, can bypass application whitelisting, and appears as legitimate software installation activity. The detection community focuses on monitoring unusual msiexec command-line patterns, MSI files in non-standard locations, custom actions that spawn suspicious child processes, and network connections from msiexec to external resources.

## What This Dataset Contains

This dataset captures a complete msiexec-based execution chain where a malicious MSI file executes embedded PowerShell code. The Security channel shows the full process tree: PowerShell (PID 41440) → cmd.exe → msiexec.exe (PID 27292) → embedded msiexec.exe (PID 37632) → PowerShell (PID 15480). The key command line is `c:\windows\system32\msiexec.exe /q /i "C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_DLL.msi"` with the `/q` flag for silent installation.

Sysmon EID 1 events capture all process creations including the critical PowerShell spawn: `powershell.exe -nop -Command Write-Host CustomAction export executed me; exit`. The Application channel records Windows Installer events showing successful MSI installation (EID 1033, 11707) for "Atomic Red Team Test Installer" from the International Atomic Test Agency.

Sysmon EID 11 shows MSI file operations in `C:\Windows\Installer\` including the creation of `327edf5.msi` and `MSI385B.tmp`. Security EID 4703 events reveal extensive privilege adjustments for the msiexec processes, including SeBackupPrivilege and SeRestorePrivilege enabling. PowerShell EID 4104 captures the actual command execution: "Write-Host CustomAction export executed me; exit".

## What This Dataset Does Not Contain

The dataset lacks the actual MSI file content analysis that would show the embedded DLL and custom action definitions. Sysmon ProcessCreate filtering means we don't see some intermediate processes that might have been spawned. Network connections are absent, which is expected since this test executes local code rather than downloading payloads. The dataset doesn't contain registry modifications that msiexec typically performs during installation, suggesting the Sysmon configuration doesn't capture registry events comprehensively. File hash analysis of the malicious MSI is also missing from the captured events.

## Assessment

This dataset provides excellent telemetry for detecting msiexec-based execution techniques. The combination of Security 4688 events for complete process lineage, Sysmon EID 1 for detailed command lines, and Application events for installer context creates a comprehensive detection foundation. The PowerShell script block logging successfully captures the embedded payload execution, while privilege adjustment events show the security context changes that accompany MSI installations. The temporal correlation between MSI installation events and suspicious PowerShell execution is clearly visible, making this particularly valuable for building detection logic around msiexec abuse patterns.

## Detection Opportunities Present in This Data

1. Monitor msiexec.exe executing MSI files from non-standard locations (C:\AtomicRedTeam\atomics\) rather than typical download folders or network shares
2. Detect msiexec.exe spawning PowerShell with suspicious command-line patterns (-nop, -Command with base64, or inline scripts)
3. Alert on Windows Installer Application events (EID 1033, 11707) for unexpected software installations, especially from unusual publishers
4. Correlate Security EID 4703 privilege escalation events with msiexec processes gaining backup/restore privileges
5. Monitor for msiexec command lines using silent installation flags (/q, /quiet) combined with local MSI file paths
6. Detect process chains where msiexec spawns scripting interpreters (PowerShell, cmd.exe, wscript.exe) as child processes
7. Alert on PowerShell script block content containing "CustomAction" or "export" keywords when spawned by msiexec
8. Monitor Sysmon EID 11 file creation events for MSI files being copied to Windows\Installer directory followed immediately by execution
