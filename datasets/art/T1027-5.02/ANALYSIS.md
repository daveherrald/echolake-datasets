# T1027-5: Obfuscated Files or Information — DLP Evasion via Sensitive Data in VBA Macro over email

## Technique Context

T1027 Obfuscated Files or Information includes scenarios where adversaries hide malicious or sensitive content within seemingly benign file formats to bypass security controls. This specific test demonstrates a DLP evasion scenario: embedding sensitive data or malicious macros within an Excel file (`.xlsm`) and transmitting it via email. Data loss prevention systems often struggle with macro-enabled Office files because the macro content is encoded within the Office XML format and may require execution to be fully inspected.

In practice, attackers use this pattern to exfiltrate data collection scripts, command-and-control implants, or stolen data by embedding them as VBA macros in Office documents that email gateways permit. The attachment (`T1027-cc-macro.xlsm`) simulates a credit-card data file (indicated by the `cc` in the filename) embedded in a macro-enabled workbook. Using PowerShell's `Send-MailMessage` cmdlet to send the email is a living-off-the-land approach that avoids installing an email client.

Detection for this variant focuses on `Send-MailMessage` invocations with macro-enabled Office attachments (`.xlsm`, `.xlam`, `.docm`), PowerShell accessing files from the `C:\AtomicRedTeam` staging path (in real attacks, the staging directory varies), and SMTP connections from PowerShell processes. The subject line `T1027_Atomic_Test` is an ART artifact; in real attacks, subjects impersonate legitimate business email.

## What This Dataset Contains

The dataset spans roughly 3 seconds (23:04:13–23:04:15 UTC on 2026-03-14) and totals 143 events across four channels.

The core technique evidence is in Sysmon EID 1 and Security EID 4688. A child PowerShell (spawned by the test framework) runs with the command line: `"powershell.exe" & {Send-MailMessage -From test@corp.com -To test@corp.com -Subject 'T1027_Atomic_Test' -Attachments "C:\AtomicRedTeam\atomics\T1027\src\T1027-cc-macro.xlsm" -SmtpServer 127.0.0.1}`. The full command is visible including the attachment path and SMTP server.

Sysmon EID 7 image loads for the technique PowerShell process document the .NET CLR stack loading (`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`), the Defender monitoring DLLs (`MpOAV.dll`, `MpClient.dll`), and `urlmon.dll`. The urlmon.dll load is notable — `Send-MailMessage` uses System.Net.Mail, not urlmon.dll, which suggests a web request was also made during this execution context.

Sysmon EID 13 records a registry write by `svchost.exe` to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask\Index` — a Software Protection Platform scheduled task update running concurrently and unrelated to the technique.

The PowerShell channel contains 104 EID 4104 events. In the full dataset (not represented in the 20-event sample), EID 4104 events capture the `Send-MailMessage` script block content, allowing extraction of the SMTP parameters and attachment path. The defended version's analysis confirmed the script block IDs for the `Send-MailMessage` execution were present. This undefended run generates equivalent content.

The event counts are similar to the defended version (26 Sysmon, 11 Security, 37 PowerShell), reflecting that Defender does not interfere with the `Send-MailMessage` technique — neither version is "blocked."

## What This Dataset Does Not Contain

No Sysmon EID 3 network connection event captures the SMTP connection to `127.0.0.1:25`. This indicates either no local SMTP server was listening on port 25, the connection was refused immediately, or the connection was too brief for Sysmon to log. No file read events for `T1027-cc-macro.xlsm` are present — Sysmon EID 10 (process access) and EID 11 (file creation) do not cover file read operations in this configuration. The macro content within the `.xlsm` file itself is not exposed by any captured event. There are no SMTP server logs or email application logs in scope.

## Assessment

This dataset's primary value is the `Send-MailMessage` command line captured in Sysmon EID 1 and Security EID 4688, including the full path to the macro-enabled Office attachment. For detection purposes, the process creation evidence is sufficient for building rules targeting PowerShell-based email transmission with Office document attachments. The PowerShell EID 4104 content in the full dataset provides the complete script block for pattern matching. This dataset does not capture the network transmission or the macro content itself, limiting its usefulness for DLP-specific analytics, but it is effective for endpoint-based detections targeting the email staging behavior.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 / EID 4688 — Send-MailMessage in PowerShell command line**: The string `Send-MailMessage` appearing in a PowerShell process command line is an unusual indicator in most corporate environments. Combined with the presence of an `-Attachments` argument pointing to an Office macro file, it is a high-confidence staging indicator.

2. **Sysmon EID 1 / EID 4688 — macro-enabled Office file in attachment paths**: The attachment path `C:\AtomicRedTeam\atomics\T1027\src\T1027-cc-macro.xlsm` contains a `.xlsm` extension. Monitoring for `.xlsm`, `.xlam`, `.docm`, `.xlsb` extensions in PowerShell process command lines associated with email or network cmdlets catches the attachment preparation pattern.

3. **EID 4104 — script block with Send-MailMessage cmdlet**: Script block logging captures the complete `Send-MailMessage` invocation including SMTP server, from/to addresses, subject, and attachment path. Monitoring EID 4104 events for `Send-MailMessage` with non-standard subjects or attachment paths is a detection opportunity.

4. **Sysmon EID 7 — urlmon.dll and .NET CLR in PowerShell associated with email cmdlets**: PowerShell loading urlmon.dll in the same process that also runs `Send-MailMessage` may indicate that the attachment was fetched or that a URL-based payload was loaded alongside the email operation.

5. **EID 4688 — SMTP server targeting localhost (127.0.0.1)**: The `-SmtpServer 127.0.0.1` argument targets a local SMTP relay. Real attacks may target an attacker-controlled external server, but the 127.0.0.1 pattern is associated with local SMTP relay abuse for evasion, and monitoring for PowerShell sending email via localhost SMTP is a useful detection variant.
