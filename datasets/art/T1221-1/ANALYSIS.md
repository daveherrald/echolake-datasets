# T1221-1: Template Injection — WINWORD Remote Template Injection

## Technique Context

T1221 Template Injection is a defense evasion technique where adversaries exploit Microsoft Office applications' ability to retrieve external document templates to execute malicious content. When a document references a remote template, Office applications can download and execute macros or other active content from that template without typical security warnings. This technique is particularly effective because it bypasses many email security controls that scan attachments but may not inspect externally referenced templates. Detection engineers focus on monitoring for Office applications making unexpected network connections, file operations involving template downloads, and process creation chains stemming from Office documents.

## What This Dataset Contains

This dataset captures the execution of a template injection attack using a Word document that references an external template. The primary evidence shows:

**Process Chain**: PowerShell spawns `cmd.exe` with command line `"cmd.exe" /c start "C:\AtomicRedTeam\atomics\T1221\src\Calculator.docx"`, which then creates a child `cmd.exe` process. The Security event 4688 shows the initial command attempting to open `Calculator.docx`.

**System Discovery**: A `whoami.exe` process (PID 29484) is executed from PowerShell, captured in both Sysmon EID 1 and Security EID 4688, indicating potential reconnaissance activity.

**File Operations**: Sysmon EID 11 captures PowerShell creating `StartupProfileData-Interactive` files in the system profile directory.

**Process Access**: Sysmon EID 10 events show PowerShell accessing both the `whoami.exe` and `cmd.exe` processes with full access rights (0x1FFFFF), which may indicate process monitoring or injection attempts.

**Network Components**: Sysmon EID 7 captures the loading of `urlmon.dll` into PowerShell, which is significant as this DLL handles URL operations and could indicate network activity for template retrieval.

## What This Dataset Does Not Contain

The dataset is missing critical Office application telemetry that would typically accompany a template injection attack. There are no Sysmon ProcessCreate events for Word (winword.exe) or related Office processes, likely because the test environment may not have had Office installed or the document failed to open properly. The Security events show multiple cmd.exe processes exiting with status 0x1 (failure), suggesting the document opening was unsuccessful.

There's no network telemetry showing the actual template retrieval, no DNS queries for external domains, and no file creation events showing downloaded templates. The PowerShell events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without any meaningful script content related to the technique.

## Assessment

This dataset provides limited utility for template injection detection engineering. While it captures the test execution infrastructure and some peripheral activities (system discovery with whoami), it lacks the core telemetry that would result from a successful template injection attack. The absence of Office process creation, template download network activity, and actual macro execution significantly reduces its value for building production detections. The dataset is more useful for understanding test framework behavior and basic process monitoring than for detecting the T1221 technique itself.

## Detection Opportunities Present in This Data

1. **Suspicious document opening via command line** - Monitor for cmd.exe processes with command lines containing document file extensions (.docx, .doc, .xls, etc.) being opened from non-standard locations or via automated execution

2. **PowerShell accessing Office-related processes** - Alert on PowerShell processes accessing document viewer processes (even if Word isn't present, this pattern could indicate preparation for document-based attacks)

3. **URLMon.dll loading in scripting contexts** - Monitor for urlmon.dll being loaded into PowerShell or other scripting engines, as this indicates URL/download capability being established

4. **Reconnaissance following document operations** - Detect whoami.exe execution shortly after document-related command line activity, as this suggests post-exploitation discovery

5. **Failed document opening patterns** - Track cmd.exe processes that exit with failure codes after attempting to open Office documents, which could indicate blocked or failed template injection attempts
