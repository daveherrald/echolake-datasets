# T1036.005-2: Match Legitimate Resource Name or Location — Masquerade as a built-in system executable

## Technique Context

T1036.005 (Match Legitimate Resource Name or Location) is a defense evasion technique where adversaries masquerade malicious executables by giving them names or placing them in locations that resemble legitimate system files. This specific test simulates masquerading as svchost.exe, one of Windows' most critical system processes. In real attacks, adversaries commonly abuse svchost.exe's trusted reputation to avoid detection, as legitimate svchost.exe processes are ubiquitous on Windows systems. Detection engineers focus on identifying suspicious svchost.exe processes running from non-standard locations (outside C:\Windows\System32), lacking digital signatures, or exhibiting unusual parent-child relationships.

## What This Dataset Contains

This dataset captures a complete masquerading attack where PowerShell compiles and executes a malicious binary disguised as svchost.exe. The Security event log shows the PowerShell command line in Security 4688: `"powershell.exe" & {Add-Type -TypeDefinition @'...System.Console.WriteLine("tweet, tweet");...'@ -OutputAssembly "$Env:windir\Temp\svchost.exe"`. The PowerShell logs capture the Add-Type cmdlet compilation in 4103 events with parameters showing `-OutputAssembly "C:\Windows\Temp\svchost.exe"`. 

Sysmon provides rich telemetry of the masquerading executable. Process creation EID 1 shows the fake svchost.exe launching from `C:\Windows\Temp\svchost.exe` with null FileVersion and Description fields, contrasting sharply with legitimate system binaries. File creation EID 11 captures the malicious binary being written to `C:\Windows\Temp\svchost.exe`. The compilation process is visible through csc.exe execution (EID 1) with command line `/noconfig /fullpaths @"C:\Windows\SystemTemp\dlrgfbes\dlrgfbes.cmdline"`. The dataset also shows Windows Defender's real-time scanning activity via MpCmdRun.exe processes responding to the file creation.

## What This Dataset Does Not Contain

The dataset lacks registry modifications or persistence mechanisms that sophisticated masquerading attacks often employ. There are no network communications from the masqueraded process itself (the fake svchost.exe only prints to console and exits). The test doesn't demonstrate more advanced masquerading techniques like DLL side-loading or process hollowing. Since this is a benign test, we don't see typical malicious payloads that real masqueraded processes would execute, such as credential theft, lateral movement, or command-and-control communications.

## Assessment

This dataset provides excellent telemetry for detecting T1036.005 masquerading attacks. The combination of Security 4688 process creation events with full command lines, Sysmon process and file creation events, and PowerShell script block logging creates multiple detection opportunities. The binary metadata differences (missing version information, unsigned status) are clearly visible in Sysmon EID 1 events. However, the benign nature of the payload limits insights into how masqueraded processes typically behave post-execution in real attacks.

## Detection Opportunities Present in This Data

1. **Suspicious svchost.exe location** - Sysmon EID 1 shows svchost.exe executing from C:\Windows\Temp\ instead of the expected C:\Windows\System32\ location

2. **Missing binary metadata** - Process creation event shows FileVersion "0.0.0.0", empty Description field, and unsigned status for the fake svchost.exe

3. **PowerShell compilation to system binary name** - PowerShell 4103 events show Add-Type cmdlet with -OutputAssembly parameter targeting svchost.exe filename

4. **Unusual parent process** - Security 4688 shows svchost.exe spawned by powershell.exe instead of services.exe or other expected system parents

5. **File creation in system directories** - Sysmon EID 11 captures creation of svchost.exe in C:\Windows\Temp\, triggering on executable files created outside expected system locations

6. **C# compiler abuse** - Sysmon EID 1 shows csc.exe execution with suspicious command line parameters indicating dynamic compilation

7. **Defender scanning activity correlation** - MpCmdRun.exe process creation events correlate with malicious file creation, indicating potential evasion attempts against real-time protection
