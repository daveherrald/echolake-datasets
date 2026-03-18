# T1105-29: Ingress Tool Transfer — iwr or Invoke Web-Request download

## Technique Context

T1105 Ingress Tool Transfer represents one of the most fundamental command and control techniques, where adversaries transfer tools or files from an external system into a compromised environment. This technique is critical to nearly all multi-stage attacks, as initial access rarely provides attackers with all the tools they need for their objectives. The detection community focuses heavily on monitoring network connections, file creation events, and the specific utilities used for downloads.

PowerShell's Invoke-WebRequest (aliased as `iwr`) is particularly significant because it's a legitimate administrative tool that's frequently abused by attackers. Unlike traditional download utilities like `wget` or `curl` (which aren't natively available on Windows), `iwr` is built into every Windows system and provides robust HTTP/HTTPS download capabilities. Detection engineers often monitor PowerShell command lines containing URL patterns, outbound HTTP requests to suspicious domains, and file creation events in temporary directories.

## What This Dataset Contains

This dataset captures a successful web-based file download using PowerShell's `iwr` command. The core technique execution shows in Security event 4688: `powershell.exe iwr -URI https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt -Outfile C:\Windows\TEMP\Atomic-license.txt`. The execution follows a process chain: initial PowerShell → cmd.exe → final PowerShell that performs the download.

PowerShell logging captures the technique beautifully in event 4103: `CommandInvocation(Invoke-WebRequest): "Invoke-WebRequest"` with parameters `name="Uri"; value="https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt"` and `name="OutFile"; value="C:\Windows\TEMP\Atomic-license.txt"`. The PowerShell script block logging also records the exact command: `iwr -URI https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt -Outfile C:\Windows\TEMP\Atomic-license.txt`.

Sysmon provides excellent complementary telemetry. Process creation events (EID 1) show the full process chain with command lines, and file creation event (EID 11) confirms the successful download: `C:\Windows\Temp\Atomic-license.txt` created by the PowerShell process. Image load events (EID 7) show the PowerShell process loading `urlmon.dll`, which is the underlying Windows component that handles the HTTP download.

## What This Dataset Does Not Contain

The dataset lacks network-level telemetry that would be crucial for comprehensive detection coverage. No DNS resolution events show the lookup for `raw.githubusercontent.com`, and no network connection events (Sysmon EID 3) capture the actual HTTP request. This is likely due to the sysmon-modular configuration not including network monitoring rules for this specific scenario.

The dataset also doesn't contain any proxy or web filtering logs that would show the HTTP transaction details, response codes, or data transfer volumes. Windows Firewall logs aren't present, which could have provided additional network context. File access auditing isn't enabled, so we don't see the subsequent file read operations that might occur after the download completes.

## Assessment

This dataset provides solid telemetry for building detections around PowerShell-based file downloads, particularly through process monitoring and PowerShell logging. The combination of Security 4688 events with command-line logging, PowerShell operational logs, and Sysmon process/file creation events creates multiple overlapping detection opportunities.

The strength lies in the detailed PowerShell logging, which captures both the module invocation and the script block content. The process creation telemetry with full command lines provides excellent hunting data. However, the absence of network telemetry significantly limits the ability to detect variants that might use different file paths or process injection techniques while maintaining the same network signatures.

For a complete ingress tool transfer detection strategy, this dataset would need supplementation with network monitoring, DNS logs, and potentially web proxy data to catch techniques that bypass process-level monitoring.

## Detection Opportunities Present in This Data

1. **PowerShell Invoke-WebRequest Module Usage** - Monitor PowerShell operational logs (EID 4103) for CommandInvocation events containing "Invoke-WebRequest" with URI parameters pointing to external domains

2. **PowerShell Command Line URL Patterns** - Alert on Security 4688 or Sysmon EID 1 process creation events where PowerShell command lines contain "iwr", "-URI", and external HTTP/HTTPS URLs

3. **PowerShell Script Block Download Commands** - Detect PowerShell script block logging (EID 4104) containing download-related cmdlets with external URLs and local file output paths

4. **File Creation in Temporary Directories** - Monitor Sysmon EID 11 file creation events for new files in `%TEMP%`, `C:\Windows\Temp`, or `C:\Users\*\AppData\Local\Temp` by PowerShell processes

5. **PowerShell Process Chain Anomalies** - Identify unusual parent-child relationships where cmd.exe spawns PowerShell with download commands, especially when the original PowerShell parent suggests automation or remote execution

6. **URLMon DLL Loading Pattern** - Correlate PowerShell processes loading urlmon.dll (Sysmon EID 7) with subsequent file creation events to identify download activity

7. **Cross-Process File Operations** - Alert when PowerShell processes create files immediately after loading network-related DLLs like urlmon.dll, indicating potential download-and-save operations
