# T1218.007-4: Msiexec — Msiexec.exe - Execute Local MSI file with an embedded EXE

## Technique Context

T1218.007 (Msiexec) is a defense evasion technique where attackers abuse the legitimate Windows Installer service (msiexec.exe) to execute malicious code. Msiexec.exe is a trusted system binary that can install MSI packages, which may contain embedded executables or custom actions. This makes it an attractive Living off the Land (LOLBin) technique for bypassing application controls and execution policies. The detection community focuses on unusual msiexec.exe command-line patterns, particularly remote installations, silent installations with embedded payloads, and child processes spawned from msiexec that don't match normal installer behavior.

## What This Dataset Contains

This dataset captures the complete execution chain of msiexec.exe installing a local MSI file containing an embedded executable. The attack flow begins with PowerShell (PID 30264) spawning cmd.exe with the command line `"cmd.exe" /c c:\windows\system32\msiexec.exe /q /i "C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_EXE.msi"`. The Security channel shows the full process chain: PowerShell → cmd.exe (PID 28316) → msiexec.exe (PID 31044) → MSI8302.tmp (PID 28128).

Sysmon captures three key process creations: whoami.exe (EID 1, rule "technique_id=T1033"), cmd.exe (EID 1, rule "technique_id=T1059.003"), and critically, msiexec.exe (EID 1, rule "technique_id=T1218") with the full command line. The embedded executable appears as `C:\Windows\Installer\MSI8302.tmp` in Security event 4688 with command line `"C:\Windows\Installer\MSI8302.tmp" "Hello, Atomic Red Team from an EXE!"`.

File creation events in Sysmon show the MSI being copied to `C:\Windows\Installer\327edf6.msi` and the temporary executable `C:\Windows\Installer\MSI8302.tmp`. Multiple Security 4703 events show msiexec.exe receiving elevated privileges including SeRestorePrivilege and SeTakeOwnershipPrivilege. Application events 1040, 11707, 1033, and 1042 document the complete Windows Installer transaction from start to completion with exit status 0 (success).

## What This Dataset Does Not Contain

The dataset lacks any blocking or alerting behavior from Windows Defender despite its active presence (evidenced by MpOAV.dll and MpClient.dll loads, plus MsMpEng.exe network connections). The technique executes successfully without any 0xC0000022 (STATUS_ACCESS_DENIED) exit codes. Missing are registry events that would typically accompany MSI installations, likely due to Sysmon configuration filtering. The PowerShell channel contains only test framework boilerplate (Set-StrictMode scriptblocks and Set-ExecutionPolicy Bypass) rather than the actual attack commands. Network events show only Windows Defender telemetry, not any malicious network activity from the embedded executable.

## Assessment

This dataset provides excellent telemetry for detecting T1218.007. The combination of Security 4688 events with full command-line logging and Sysmon ProcessCreate events gives comprehensive process execution visibility. The critical detection points are well-represented: msiexec.exe with suspicious command-line flags (/q for quiet mode, /i for install), execution of temporary files from C:\Windows\Installer\, and privilege escalation events. The Application channel events add valuable context for correlating installer activity with process execution. The main weakness is the lack of registry monitoring, which limits visibility into persistence mechanisms that MSI packages often establish.

## Detection Opportunities Present in This Data

1. **Msiexec.exe with local MSI files and quiet installation flags** - Monitor Security 4688 and Sysmon EID 1 for msiexec.exe processes with command lines containing `/q` (quiet) and `/i` (install) flags, especially when installing from non-standard directories like AtomicRedTeam paths.

2. **Temporary executable execution from Windows Installer directory** - Alert on Security 4688 events showing process creation for executables with paths matching `C:\Windows\Installer\*.tmp` or similar temporary file patterns, indicating embedded executable extraction and execution.

3. **Unusual msiexec.exe privilege escalation** - Monitor Security 4703 events for msiexec.exe processes receiving high-privilege tokens (SeRestorePrivilege, SeTakeOwnershipPrivilege) outside of legitimate software installation contexts.

4. **PowerShell spawning msiexec.exe execution chains** - Correlate Security 4688 events to detect PowerShell → cmd.exe → msiexec.exe process trees, particularly when the msiexec command includes non-standard MSI file locations or suspicious flags.

5. **MSI file creation followed by immediate execution** - Combine Sysmon EID 11 file creation events for .msi files in Windows\Installer\ with subsequent EID 1 process creation events for msiexec.exe targeting those same files, indicating potential payload staging and execution.
