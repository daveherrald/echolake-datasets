# T1105-8: Ingress Tool Transfer — certutil download (verifyctl)

## Technique Context

T1105 (Ingress Tool Transfer) represents adversaries' efforts to transfer tools, scripts, or other files from external systems into a compromised environment. This technique is fundamental to most attack chains, as attackers rarely bring all necessary tools with them initially. The `certutil -verifyctl` variant is particularly notable because it abuses a legitimate Windows certificate utility for file downloads, making detection more challenging than obvious download tools.

In this specific test, certutil's `-verifyctl -split -f` parameters are used to download and split a remote file. The `-verifyctl` flag was originally intended to verify Certificate Trust Lists but can be misused for arbitrary file downloads. The `-split` parameter saves the downloaded content to disk, while `-f` forces the operation. This technique has been observed in real-world campaigns where attackers leverage certutil's built-in network capabilities to bypass application whitelisting and avoid deploying obvious download utilities.

Detection engineers focus on certutil network activity, unusual command-line parameters, and the creation of files from remote sources. The challenge lies in distinguishing malicious usage from legitimate certificate operations.

## What This Dataset Contains

The dataset captures a PowerShell script attempting to use certutil for file download, but Windows Defender blocked the execution. The key evidence includes:

**Security Event 4688** shows the PowerShell command line: `"powershell.exe" & {$datePath = \"certutil-$(Get-Date -format yyyy_MM_dd)\"\nNew-Item -Path $datePath -ItemType Directory\nSet-Location $datePath\ncertutil -verifyctl -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt\nGet-ChildItem | Where-Object {$_.Name -notlike \"*.txt\"} | Foreach-Object { Move-Item $_.Name -Destination Atomic-license.txt }}`

**Security Event 4689** reveals the PowerShell process exited with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution.

**Sysmon Event 1** captured the `whoami.exe` execution (ProcessId 11040) with full command line and hashes, showing successful process creation before the main certutil command was blocked.

**Sysmon Events 7** document .NET framework DLL loads in the PowerShell process, including System.Management.Automation assemblies, showing PowerShell's initialization phase.

**Sysmon Event 10** shows PowerShell accessing the whoami process with full access rights (0x1FFFFF), demonstrating normal process interaction before the block.

**Sysmon Event 17** captures named pipe creation for PowerShell (`\PSHost.134179037579439169.12756.DefaultAppDomain.powershell`).

## What This Dataset Does Not Contain

The dataset lacks the critical certutil execution that would demonstrate the actual T1105 technique. Windows Defender's real-time protection blocked the PowerShell script before the certutil command could execute, so there are no:

- Sysmon ProcessCreate events for certutil.exe (the sysmon-modular config would have captured this as certutil is a known LOLBin)
- Network connection events showing the HTTPS download attempt
- File creation events for the downloaded LICENSE.txt file
- Directory creation for the date-stamped folder

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual script content, as the script was blocked before substantial execution.

No Sysmon ProcessCreate event exists for the main PowerShell process (PID 12756) because it doesn't match the sysmon-modular include patterns, though its child processes like whoami.exe are captured.

## Assessment

This dataset provides limited value for T1105 detection engineering because the core technique was prevented by endpoint protection. However, it offers excellent insight into how modern EDR solutions can block certutil abuse attempts, and demonstrates what telemetry remains available when techniques are blocked.

The Security 4688 events with command-line logging prove their detection value, capturing the full attack attempt even when execution fails. The exit code 0xC0000022 serves as a clear indicator of security software intervention. For organizations relying heavily on process creation telemetry for detection, this demonstrates why both successful and failed execution attempts provide valuable threat intelligence.

The dataset would be significantly stronger if it included a successful execution variant or if Defender were temporarily disabled to capture the complete technique telemetry.

## Detection Opportunities Present in This Data

1. **Certutil command-line abuse detection** - Monitor Security 4688 events for `certutil.exe` with `-verifyctl`, `-split`, and remote URL parameters in the command line
2. **PowerShell execution with suspicious certutil calls** - Detect PowerShell processes with command lines containing "certutil" and HTTP/HTTPS URLs
3. **Process exit status monitoring** - Alert on processes terminating with 0xC0000022 status codes, indicating potential security software blocks of malicious activity
4. **PowerShell script block analysis** - While not present in this dataset, monitor for PowerShell script blocks containing certutil download patterns
5. **Parent-child process relationships** - Track PowerShell spawning certutil with network-related parameters
6. **Endpoint protection log correlation** - Correlate process creation events with security software block notifications for comprehensive threat detection
