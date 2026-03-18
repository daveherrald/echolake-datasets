# T1204.002-6: Malicious File — Malicious File (Excel 4 Macro) on Windows 11 Enterprise domain workstation

## Technique Context

T1204.002 (User Execution: Malicious File) occurs when attackers trick users into opening or executing malicious files that contain embedded code. Excel 4.0 macros are a particularly dangerous variant of this technique, as they allow direct system calls and file operations while being less scrutinized by modern security tools than VBA macros. Attackers often embed Excel 4.0 macros in spreadsheet files delivered via phishing emails or malicious downloads. These macros can perform various malicious activities including downloading additional payloads, executing commands, creating persistence mechanisms, and exfiltrating data. The detection community focuses on monitoring COM object instantiation for Office applications, unusual process creation chains from Office processes, file write operations to suspicious locations, and network connections initiated by Office applications.

## What This Dataset Contains

This dataset captures the telemetry from an attempt to execute a simulated Excel 4.0 macro attack that ultimately fails due to missing Excel installation. The PowerShell script attempts to create an Excel COM object with `New-Object -COMObject "Excel.Application"` but fails with error 0x80040154 (REGDB_E_CLASSNOTREG) indicating "Class not registered."

The Security event log shows the complete command line in Security 4688 events, revealing the full PowerShell script that would create an Excel workbook with Excel 4.0 macro sheets containing malicious functions like `FOPEN`, `FWRITELN`, `EXEC`, and `HALT`. The intended macro would write a VBScript file to download Process Explorer from Sysinternals and execute it.

Sysmon captures process creation for the PowerShell instances (PIDs 29108, 39976, 36904), a `whoami.exe` execution (PID 30068), and extensive DLL loading events showing .NET runtime components and Windows Defender integration. The PowerShell channel contains the actual script block logging showing the failed COM object creation and multiple Set-StrictMode scriptblock creations.

Key events include PowerShell EID 4100 showing the COM registration error, PowerShell EID 4103 showing the failed `New-Object` command invocation, and Security 4688 showing the complete command line with the embedded Excel 4.0 macro code.

## What This Dataset Does Not Contain

This dataset lacks the actual execution of the Excel 4.0 macro technique since Excel is not installed on the test system. There are no events showing successful COM object creation, Excel process launch, macro sheet creation, file operations to create the VBScript payload, or the subsequent execution of downloaded files. The Sysmon ProcessCreate events are limited due to the sysmon-modular include-mode filtering - we only see PowerShell and whoami.exe because they match suspicious process patterns, but other potential child processes like explorer.exe or cscript.exe that the macro would have spawned are not captured. There are no network connections, file creation events for the intended payload files, or any evidence of the macro's file manipulation functions executing successfully.

## Assessment

This dataset provides excellent visibility into the attempt phase of an Excel 4.0 macro attack but limited insight into successful execution since the technique fails early due to environmental constraints. The PowerShell script block logging captures the complete malicious macro code, making it valuable for understanding attacker techniques and developing content-based detections. The Security 4688 command-line logging provides full forensic detail of the intended attack. However, the dataset's utility for testing detections of successful Excel 4.0 macro execution is limited since the core technique never executes. The comprehensive DLL loading telemetry and process access events from Sysmon provide good baseline data for PowerShell execution patterns.

## Detection Opportunities Present in This Data

1. **COM Object Creation Failure Detection** - Monitor PowerShell EID 4100 errors with "Class not registered" messages combined with "Excel.Application" in the error text to detect Excel-based attacks on systems without Office

2. **Excel 4.0 Macro Content Analysis** - Alert on PowerShell script blocks containing Excel 4.0 macro functions like `FOPEN`, `FWRITELN`, `EXEC`, and `HALT` in combination with COM object creation attempts

3. **Suspicious PowerShell Command Line Patterns** - Detect Security 4688 events with command lines containing Excel macro sheet operations, particularly sequences of `$sheet.Cells.Item` assignments with macro formulas

4. **Process Creation from PowerShell with Office-Related Content** - Monitor for PowerShell processes (Sysmon EID 1) with command lines containing references to Excel applications and macro execution

5. **Failed COM Object Instantiation Correlation** - Correlate PowerShell EID 4103 `New-Object` command invocations with EID 4100 COM errors to identify attempted but failed Office-based attacks

6. **Embedded Payload URL Detection** - Scan PowerShell script blocks for URLs in macro content, particularly when combined with file download operations like `SaveToFile` and `ADODB.Stream` objects
