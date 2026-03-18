# T1074.001-3: Local Data Staging — Zip a Folder with PowerShell for Staging in Temp

## Technique Context

T1074.001 Local Data Staging involves adversaries collecting data from local systems and organizing it in a central location before exfiltration. This specific test demonstrates using PowerShell's `Compress-Archive` cmdlet to create ZIP archives in temporary directories - a common pattern where attackers compress stolen data to reduce transfer time and evade detection. The technique is frequently observed in ransomware operations, data theft campaigns, and insider threats where bulk data needs to be prepared for exfiltration. Detection engineers typically focus on unusual archive creation patterns, compression activity in sensitive directories, and PowerShell cmdlets operating on large file sets.

## What This Dataset Contains

The dataset captures a PowerShell-based data staging operation with clear telemetry across multiple channels. The primary activity is visible in Security event 4688 showing the PowerShell process creation with command line `"powershell.exe" & {Compress-Archive -Path \"C:\AtomicRedTeam\atomics\T1074.001\bin\Folder_to_zip\" -DestinationPath $env:TEMP\Folder_to_zip.zip -Force}`. PowerShell script block logging in event 4104 captures the actual cmdlet execution: `Compress-Archive -Path "C:\AtomicRedTeam\atomics\T1074.001\bin\Folder_to_zip" -DestinationPath $env:TEMP\Folder_to_zip.zip -Force`. 

Sysmon provides complementary process creation events (EID 1) for both the parent PowerShell process and the child PowerShell process executing the compression command. The key artifact creation is captured in Sysmon event 11 showing the ZIP file creation: `TargetFilename: C:\Windows\Temp\Folder_to_zip.zip`. Additional Sysmon events capture .NET CLR loading, PowerShell module initialization, and Windows Defender DLL loading during PowerShell execution. The dataset also includes a `whoami.exe` execution, likely part of the test framework reconnaissance.

## What This Dataset Does Not Contain

The dataset lacks visibility into the source directory contents being compressed - we see the path `C:\AtomicRedTeam\atomics\T1074.001\bin\Folder_to_zip` but no file enumeration or access events for individual files within that directory. There are no network connections showing potential exfiltration of the created archive. The Sysmon configuration's include-mode filtering means we miss intermediate processes that might be involved in real-world staging operations (like file discovery tools that don't match LOLBin patterns). Windows Defender is active but doesn't generate any alert events, indicating this benign test activity doesn't trigger behavioral detection. The PowerShell transcript logging mentioned in the environment configuration doesn't appear in the collected events.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based data staging operations. The combination of Security 4688 command-line logging, PowerShell script block logging (4104), and Sysmon file creation events (11) gives comprehensive visibility into the staging technique. The data quality is high with clear command lines, process chains, and artifact creation timestamps. For detection engineering, this represents an ideal scenario where multiple complementary data sources confirm the activity. The main limitation is the lack of file access patterns within the source directory, which would help distinguish between legitimate backup operations and malicious data staging.

## Detection Opportunities Present in This Data

1. PowerShell Compress-Archive cmdlet usage with temp directory destinations (PowerShell 4104 script blocks containing "Compress-Archive" with "$env:TEMP" or temp paths)

2. PowerShell process creation with compression-related command lines (Security 4688 with command lines matching "Compress-Archive.*-DestinationPath.*\.zip")

3. ZIP file creation in temporary directories by PowerShell processes (Sysmon 11 with Image containing "powershell.exe" and TargetFilename ending in ".zip" in temp locations)

4. Parent-child PowerShell process relationships executing compression operations (Sysmon 1 events showing powershell.exe spawning powershell.exe with compression cmdlets)

5. PowerShell execution with Force parameters on archive operations (command lines containing both "Compress-Archive" and "-Force" flags)

6. Bulk file operations preceded by system reconnaissance (correlation of whoami.exe execution followed by compression activities within short time windows)
