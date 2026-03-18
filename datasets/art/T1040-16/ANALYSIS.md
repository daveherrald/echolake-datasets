# T1040-16: Network Sniffing — PowerShell Network Sniffing

## Technique Context

T1040 Network Sniffing involves capturing network traffic to obtain sensitive information like credentials, session tokens, or business data. Attackers use this technique during credential access and discovery phases to expand their access and understand target environments. The detection community focuses heavily on monitoring the creation of network capture sessions, ETL file creation, and the use of legitimate tools like netsh, Wireshark, or PowerShell's NetEventSession cmdlets for malicious purposes. This technique is particularly concerning because it can capture credentials transmitted in cleartext and provide attackers with detailed network topology information.

## What This Dataset Contains

This dataset captures a PowerShell-based network sniffing attack using Windows' built-in NetEventSession cmdlets. The Security log shows PowerShell process creation with the full command line: `"powershell.exe" & {New-NetEventSession -Name Capture007 -LocalFilePath "$ENV:Temp\sniff.etl" Add-NetEventPacketCaptureProvider -SessionName Capture007 -TruncationLength 100 Start-NetEventSession -Name Capture007 Stop-NetEventSession -Name Capture007 Remove-NetEventSession -Name Capture007}`. PowerShell EID 4103 events capture detailed cmdlet invocations including `New-NetEventSession` with parameters `Name="Capture007"` and `LocalFilePath="C:\Windows\TEMP\sniff.etl"`, `Add-NetEventPacketCaptureProvider` with `TruncationLength="100"`, and the start/stop/remove sequence. Sysmon EID 11 events show the creation of the ETL capture file `C:\Windows\Temp\sniff.etl` by wmiprvse.exe process (PID 4520), indicating the WMI provider executed the actual network capture operations. The dataset includes typical PowerShell process telemetry like .NET runtime DLL loads and named pipe creation for PowerShell hosting.

## What This Dataset Does Not Contain

The dataset lacks actual network traffic content since the capture session was immediately stopped without any meaningful duration for packet collection. There are no DNS queries, network connections, or data exfiltration events that would typically follow successful network sniffing. The Sysmon configuration's include-mode filtering means many supporting processes may not be captured. Windows Defender did not block this technique since it uses legitimate Windows networking APIs. The dataset also doesn't contain any credential extraction or follow-on activities that would demonstrate the attack's ultimate objectives.

## Assessment

This dataset provides excellent telemetry for detecting PowerShell-based network sniffing attempts. The combination of Security 4688 command-line logging, PowerShell 4103 cmdlet invocation tracking, and Sysmon file creation events creates multiple detection opportunities. The PowerShell channel captures the exact parameters used for the network session, while Sysmon reveals the ETL file artifact creation. However, the brief execution timeframe limits its value for understanding sustained network monitoring scenarios. The data sources are highly reliable for building detections around NetEventSession cmdlet usage and ETL file creation patterns.

## Detection Opportunities Present in This Data

1. **PowerShell NetEventSession Cmdlet Usage** - Monitor PowerShell EID 4103 events for New-NetEventSession, Add-NetEventPacketCaptureProvider, Start-NetEventSession cmdlet invocations with network capture parameters

2. **ETL Network Capture File Creation** - Alert on Sysmon EID 11 file creation events for .etl files in temporary directories, especially when created by wmiprvse.exe or other system processes

3. **PowerShell Network Sniffing Command Lines** - Detect Security EID 4688 process creation events with command lines containing NetEventSession cmdlets combined with LocalFilePath parameters pointing to ETL files

4. **WMI Provider Network Capture Activity** - Monitor wmiprvse.exe processes creating ETL files, indicating network capture session execution through WMI interfaces

5. **PowerShell Script Block Network Capture Patterns** - Watch for PowerShell EID 4104 script blocks containing network packet capture cmdlets with session names and file paths for capture storage

6. **Sequential Network Session Management** - Detect rapid succession of New-NetEventSession, Add-NetEventPacketCaptureProvider, Start-NetEventSession, Stop-NetEventSession, and Remove-NetEventSession operations within short timeframes

7. **Network Capture Session Naming Patterns** - Monitor for consistent naming conventions in network capture sessions (like "Capture007") that may indicate automated or scripted network sniffing activities
