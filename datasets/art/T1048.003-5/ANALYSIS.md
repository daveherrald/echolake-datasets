# T1048.003-5: Exfiltration Over Unencrypted Non-C2 Protocol — Exfiltration Over Alternative Protocol - SMTP

## Technique Context

T1048.003 covers exfiltration over unencrypted non-C2 protocols, with this specific test focusing on SMTP email exfiltration. Adversaries commonly use legitimate network protocols like SMTP, HTTP, FTP, or DNS to exfiltrate data, blending their traffic with normal business communications. SMTP exfiltration is particularly attractive because email traffic is ubiquitous in enterprise environments, making malicious data transfers less conspicuous.

The detection community typically focuses on identifying unusual email patterns, large attachments being sent to external domains, use of non-standard SMTP servers, PowerShell email cmdlets in suspicious contexts, and network connections to unexpected SMTP servers. This technique often appears in later stages of attacks when adversaries have already established persistence and are moving to complete their objectives.

## What This Dataset Contains

This dataset captures a PowerShell-based SMTP exfiltration attempt using the `Send-MailMessage` cmdlet. The key evidence appears in PowerShell script block logging (EID 4104) showing the exfiltration command: `Send-MailMessage -From test@corp.com -To test@corp.com -Subject "T1048.003 Atomic Test" -Attachments C:\Windows\System32\notepad.exe -SmtpServer 127.0.0.1`.

Security audit events (EID 4688) show the process creation chain: a parent PowerShell process spawning a child PowerShell process with the full command line visible: `"powershell.exe" & {Send-MailMessage -From test@corp.com -To test@corp.com -Subject \"T1048.003 Atomic Test\" -Attachments C:\Windows\System32\notepad.exe -SmtpServer 127.0.0.1}`.

PowerShell operational logs (EID 4103) capture the actual command invocation with all parameters bound, including the attachment path, SMTP server (127.0.0.1), and sender/recipient addresses. Crucially, this event also contains a "NonTerminatingError" indicating "Unable to connect to the remote server," showing the technique failed due to no SMTP server running on localhost.

Sysmon provides process creation events (EID 1) for both PowerShell instances, process access events (EID 10) showing the parent PowerShell accessing both whoami.exe and the child PowerShell process, and extensive DLL loading events (EID 7) as PowerShell initializes .NET components and Windows Defender hooks.

## What This Dataset Does Not Contain

This dataset lacks successful exfiltration telemetry because the SMTP connection failed (no server listening on 127.0.0.1:25). You won't see network connection events (Sysmon EID 3) that would normally indicate outbound SMTP traffic. There are no file access events showing the attachment (notepad.exe) being read, likely because the connection failure occurred before file operations. 

DNS queries for SMTP server resolution are absent since the test used localhost (127.0.0.1). The dataset also doesn't contain any email-specific artifacts in files or registry since the operation never completed. Windows Defender appears to have monitored the activity (multiple MpOAV.dll and MpClient.dll loads) but didn't block the attempt, as the failure was due to network connectivity rather than security controls.

## Assessment

This dataset provides excellent coverage of attempted SMTP exfiltration through PowerShell, despite the technique's failure. The combination of Security audit logs with full command-line logging and PowerShell operational logs with detailed cmdlet parameter binding creates comprehensive detection opportunities. The script block logging captures the exact exfiltration command, while process auditing shows the execution context.

The failure actually enhances the dataset's value for detection engineering, as it demonstrates how to identify exfiltration attempts even when they don't succeed. The error information in PowerShell logs helps distinguish between blocked attempts and failed attempts, which is crucial for threat hunting.

## Detection Opportunities Present in This Data

1. **PowerShell Send-MailMessage usage** - EID 4104 script blocks containing "Send-MailMessage" with attachment parameters, especially to external or suspicious SMTP servers

2. **Command-line SMTP exfiltration patterns** - Security EID 4688 events with PowerShell command lines containing Send-MailMessage cmdlets with -Attachments parameters

3. **PowerShell cmdlet parameter binding analysis** - EID 4103 CommandInvocation events showing Send-MailMessage with attachment paths pointing to system files or sensitive directories

4. **Process access patterns for email operations** - Sysmon EID 10 showing PowerShell processes accessing file system objects during email composition

5. **Suspicious email parameters** - PowerShell logs showing identical sender/recipient addresses, generic subjects like "test," or localhost SMTP servers

6. **Failed exfiltration attempts** - PowerShell NonTerminatingError events indicating SMTP connection failures, which may indicate blocked or misconfigured exfiltration

7. **PowerShell execution with networking components** - Process chains showing PowerShell loading networking DLLs (urlmon.dll) in conjunction with email-related cmdlets
