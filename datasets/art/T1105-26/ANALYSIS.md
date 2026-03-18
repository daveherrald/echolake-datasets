# T1105-26: Ingress Tool Transfer — Download a file using wscript

## Technique Context

T1105 Ingress Tool Transfer describes adversary actions to transfer tools or other files from an external system into a compromised environment. This technique is fundamental to multi-stage attacks where initial access tools need to retrieve additional payloads, utilities, or configuration files. The detection community focuses heavily on network connections from unexpected processes, file downloads to suspicious locations, and the use of living-off-the-land binaries (LOLBins) for download activities.

This specific test (T1105-26) demonstrates using Windows Script Host (`wscript.exe`) to execute a VBScript that downloads a file from a remote location. VBScript-based downloads are particularly relevant because they leverage built-in Windows functionality, making them attractive to attackers who want to avoid dropping custom executables. The technique combines T1105 (file transfer) with T1202 (Indirect Command Execution) through the use of wscript.

## What This Dataset Contains

The dataset captures a complete execution chain starting from PowerShell invoking `wscript.exe` with a VBScript file. The Security channel shows the full process chain in 4688 events: `powershell.exe` → `cmd.exe /c wscript.exe "C:\AtomicRedTeam\atomics\T1105\src\T1105-download-file.vbs"` → `wscript.exe "C:\AtomicRedTeam\atomics\T1105\src\T1105-download-file.vbs"`.

Sysmon provides rich telemetry including Sysmon EID 1 process creation events for the cmd.exe and wscript.exe processes, with the crucial command line `wscript.exe "C:\AtomicRedTeam\atomics\T1105\src\T1105-download-file.vbs"`. The dataset captures the actual network activity with Sysmon EID 3 showing wscript.exe making a TCP connection to 185.199.111.133:443 (GitHub's CDN infrastructure), and EID 22 DNS query for `raw.githubusercontent.com`.

The file download is evidenced by Sysmon EID 11 showing wscript.exe creating `C:\Windows\Temp\Atomic-License.txt`. Multiple Sysmon EID 7 events show wscript.exe loading key DLLs including `vbscript.dll` (the VBScript engine), `amsi.dll` (AMSI integration), and Windows Defender components (`MpOAV.dll`, `MpClient.dll`), indicating real-time protection was active during execution.

## What This Dataset Does Not Contain

The dataset doesn't contain the actual VBScript source code content, which would be valuable for understanding the download mechanism. While Sysmon captures the file creation, it doesn't provide file content or hash information for the downloaded file itself. The PowerShell channel contains only execution policy changes and error handling scriptblocks - no evidence of the actual download logic.

There are no Windows Defender detection or blocking events despite the significant security-relevant activity, suggesting this particular test didn't trigger behavioral detections. The dataset also lacks any process access events showing wscript.exe interacting with the downloaded file post-creation.

## Assessment

This dataset provides excellent telemetry for detecting VBScript-based file downloads. The combination of Security 4688 command-line logging and Sysmon process creation, network connection, and file creation events creates multiple detection opportunities. The presence of both DNS resolution and network connection events makes this particularly valuable for network-based detection engineering.

The dataset is strongest for behavioral detection patterns rather than static analysis, as the actual script content isn't captured. However, the process execution chain, network indicators, and file system artifacts provide sufficient evidence for building robust detections around this common attack pattern.

## Detection Opportunities Present in This Data

1. **Process Chain Analysis**: Detect `cmd.exe` spawning `wscript.exe` with .vbs file arguments, particularly when the parent process is PowerShell or other scripting hosts
2. **VBScript Network Activity**: Alert on wscript.exe making outbound network connections, especially HTTPS connections to file hosting services
3. **GitHub CDN Downloads**: Monitor for connections to raw.githubusercontent.com or GitHub's CDN IP ranges from script execution processes
4. **LOLBin File Downloads**: Detect file creation events where the creating process is wscript.exe and the target location is a temporary directory
5. **Command Line Pattern Matching**: Identify command lines containing `wscript.exe` with .vbs file paths, particularly those referencing atomic red team or test directories
6. **DNS Query Correlation**: Correlate DNS queries for file hosting domains with subsequent file creation events from the same process
7. **VBScript Engine Loading**: Monitor for vbscript.dll loading in unexpected processes or contexts that might indicate script-based malicious activity
8. **AMSI Integration Monitoring**: Track amsi.dll loading in wscript.exe as an indicator of script execution that may bypass traditional signature detection
