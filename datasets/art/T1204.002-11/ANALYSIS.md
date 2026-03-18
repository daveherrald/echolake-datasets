# T1204.002-11: Malicious File — Mirror Blast Emulation

## Technique Context

T1204.002 (User Execution: Malicious File) represents one of the most common initial access and execution vectors in modern attacks. Attackers rely on users to open malicious documents, executables, or other files that trigger code execution. This technique is particularly significant because it bypasses many technical security controls by exploiting the human element. The Mirror Blast emulation specifically simulates opening a malicious Excel document with embedded VBA macros, mimicking campaigns like those attributed to APT29/Cozy Bear. Detection engineers focus on identifying Office applications spawning unusual child processes, macro execution indicators, registry modifications that disable security features, and behavioral patterns consistent with document-based malware delivery.

## What This Dataset Contains

This dataset captures a Mirror Blast-style attack simulation executed through PowerShell. The technique involves three key phases visible in the telemetry:

The Security 4688 events show the complete PowerShell command execution chain, including the parent PowerShell process (PID 0xae0c) spawning a child PowerShell process (PID 0x40fc) with a command line that reveals the attack components: `powershell.exe" & {Cd \"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\"New-ItemProperty -Path Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Excel\Security -Name \"VBAWarnings\" -Value \"1\" -PropertyType DWORD -Force | Out-Null& '.\Excel 2016.lnk' \"C:\AtomicRedTeam\atomics\T1204.002\bin\mirrorblast_emulation.xlsm\"}`

The Sysmon events capture detailed process creation and behavioral artifacts. Sysmon EID 1 shows the whoami.exe execution (`C:\Windows\system32\whoami.exe`) spawned by the PowerShell process, demonstrating system discovery behavior. The subsequent PowerShell process creation shows the full attack command targeting the Excel document.

A critical security bypass is captured in Sysmon EID 13, showing the registry modification: `HKU\.DEFAULT\Software\Microsoft\Office\16.0\Excel\Security\VBAWarnings` set to `DWORD (0x00000001)`, which disables VBA macro warnings in Excel.

Multiple Sysmon EID 7 events document .NET CLR and PowerShell assembly loading across the process chain, along with Windows Defender components (MpOAV.dll, MpClient.dll) being loaded, indicating active endpoint protection engagement.

## What This Dataset Does Not Contain

Notably absent are events showing the actual Excel process execution or macro execution within Excel. This suggests Windows Defender's real-time protection likely blocked the malicious Excel document from fully executing, preventing the macro payload from running. The command attempts to launch `Excel 2016.lnk` with the malicious XLSM file, but no corresponding EXCEL.EXE process creation appears in either Security 4688 or Sysmon EID 1 events.

The PowerShell events contain mostly framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual attack payload content. No network connections, file writes to suspicious locations, or additional child processes beyond whoami.exe are observed, indicating the attack was contained before reaching its intended execution phase.

Missing are any Application event log entries that might show Office application errors or security warnings, and no additional process spawning from Excel that would typically indicate successful macro execution.

## Assessment

This dataset provides excellent telemetry for detecting the preparation phases of document-based attacks but limited visibility into the actual malicious payload execution due to Defender's intervention. The Security channel with command-line auditing captures the complete attack command, making it highly valuable for detection engineering. The Sysmon process creation events with full command lines and the registry modification event provide strong behavioral indicators. However, the dataset's utility is somewhat limited for understanding post-exploitation behaviors since the attack was blocked before the Excel macro could execute. This represents a realistic enterprise scenario where endpoint protection prevents full attack progression while still generating valuable detection artifacts.

## Detection Opportunities Present in This Data

1. **Office Security Bypass Detection**: Monitor Sysmon EID 13 for registry writes to `*\Office\*\Security\VBAWarnings` with value `1` (DWORD), indicating attempts to disable macro warnings

2. **Suspicious PowerShell Command Patterns**: Alert on Security EID 4688 command lines containing combinations of registry manipulation, Office application shortcuts (.lnk), and macro-enabled Office files (.xlsm)

3. **Discovery Command Execution**: Detect Sysmon EID 1 showing whoami.exe spawned by PowerShell processes, particularly when part of a larger execution chain

4. **Malicious Document Targeting**: Monitor for process command lines referencing macro-enabled Office files (*.xlsm, *.docm) in combination with Office application shortcuts

5. **Process Access Anomalies**: Investigate Sysmon EID 10 showing PowerShell processes accessing other processes with high privileges (0x1FFFFF), potentially indicating injection or process manipulation attempts
