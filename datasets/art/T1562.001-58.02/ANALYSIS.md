# T1562.001-58: Disable or Modify Tools — Freeze PPL-protected Process with EDR-Freeze

## Technique Context

T1562.001 (Disable or Modify Tools) covers adversary actions to impair defenses. This test attempts to use EDR-Freeze, a publicly available tool that targets PPL (Protected Process Light) processes — the protection level used by many EDR agents and Windows security processes. Rather than terminating a PPL-protected process (which would be blocked by the kernel and generate obvious alerts), EDR-Freeze freezes the process's threads using `NtSuspendThread`, preventing it from processing events or sending telemetry without triggering service-terminated alarms. The technique requires `SeDebugPrivilege` and uses a custom C# assembly compiled at runtime via PowerShell's `Add-Type` to acquire that privilege before attempting to download and run EDR-Freeze.

## What This Dataset Contains

The dataset spans 24 seconds and captures 133 events across PowerShell (124), Security (5), and Sysmon (4) channels.

**Security (EID 4688):** Five process creation events. The core attack sequence starts with `whoami.exe` (test framework identity check), then a child `powershell.exe` with the attack payload embedded in its command line — a 500+ character block beginning:

```
"powershell.exe" & {# Enable SeDebugPrivilege
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class TokenAdjuster {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(...
```

This child PowerShell then triggers the .NET runtime compiler: Security 4688 captures `csc.exe` (the C# compiler) invoked with a temporary response file:

```
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Windows\SystemTemp\dvrrvbfu\dvrrvbfu.cmdline"
```

And `cvtres.exe` (resource converter, always invoked alongside `csc.exe` for managed code compilation):

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Windows\SystemTemp\RESE4D6.tmp" "c:\Windows\SystemTemp\dvrrvbfu\CSC32D847D28B16413593A6EDAAE8DC51B.TMP"
```

This `csc.exe`/`cvtres.exe` pair confirms that `Add-Type` successfully compiled the `TokenAdjuster` C# class. The compilation output is a temporary DLL in `C:\Windows\SystemTemp\`.

A final `whoami.exe` appears at cleanup time.

**Sysmon (EID 3 + EID 22):** Four Sysmon events capture the EDR-Freeze download attempt. Two EID 22 (DNS query) events record the name resolution:

- `github.com` → `140.82.113.4` (queried by `powershell.exe`, PID 16944, SYSTEM)
- `release-assets.githubusercontent.com` → `185.199.108.133;185.199.109.133;185.199.110.133;185.199.111.133` (GitHub's CDN)

Two EID 3 (network connection) events confirm the TCP connections to:

- `140.82.113.4:443` (github.com) — source port 51897
- `185.199.108.133:443` (githubusercontent CDN) — source port 51898

Both connections are initiated by `powershell.exe` (PID 16944, `NT AUTHORITY\SYSTEM`, `192.168.4.16`), tagged by sysmon-modular with `technique_id=T1059.001,technique_name=PowerShell`.

**PowerShell (EID 4100 + 4103 + 4104):** 124 events. One EID 4100 records an execution failure. Multiple EID 4103 events record the attack flow: `Add-Type` execution (C# compilation), `Write-Host "SeDebugPrivilege enabled successfully."`, `Invoke-WebRequest` to `https://github.com/TwoSevenOneT/EDR-Freeze/releases/download/main/EDR-Freeze_1.0.zip`, and the failure message `Write-Host "Failed to download or extract EDR-Freeze: Cannot bind argument to parameter 'Path' because it is null."` — the download to GitHub succeeded but path resolution for the extracted executable failed, so EDR-Freeze never executed.

## What This Dataset Does Not Contain

**EDR-Freeze never ran.** The download succeeded (DNS queries and network connections are confirmed), but the path resolution step after extraction failed. No process creation event for `EDR-Freeze.exe` appears in Security 4688 or Sysmon EID 1. No process access to any PPL-protected process is recorded. No `NtSuspendThread` syscall activity is logged.

**No Security EID 4672 (special privileges).** Unlike the defended variant which captured a SYSTEM batch logon sequence (4624/4627/4672) showing `SeDebugPrivilege` in the assigned privilege set, the undefended run did not generate a new logon event — the SYSTEM context was already established. The `Add-Type` compilation succeeded without needing to log a privilege escalation event.

**No `csc.exe` in Sysmon EID 1.** The sysmon-modular include rules do not match `csc.exe` or `cvtres.exe` by default, so the compiler invocations are only present in Security 4688.

**No EDR-Freeze binary on disk.** The extraction path failure means the binary was either not written to disk or was written to an unexpected location. No Sysmon EID 11 (file create) for the EDR-Freeze zip or executable appears.

## Assessment

The technique partially executed: SeDebugPrivilege was successfully enabled (the C# `TokenAdjuster` class compiled and ran), and the EDR-Freeze binary was successfully downloaded from GitHub. However, the path resolution failure in the extraction step prevented EDR-Freeze from actually running. This is an interesting partial-execution case — the most dangerous part (freezing a PPL process) did not occur, but the preparatory steps (privilege acquisition, GitHub download) are fully documented.

Compared to the defended variant (4 Sysmon + 24 Security + 85 PowerShell = 113 events), the undefended run produced 4 Sysmon + 5 Security + 124 PowerShell events (133 total). The defended variant had a richer Security channel because it captured a SYSTEM logon sequence (4624/4627/4672); the undefended run had more PowerShell events due to additional module logging across multiple test framework runspace startups. The Sysmon coverage is identical — 4 events in both runs (the same DNS and network connection events), because those events are driven by network activity, not Defender.

## Detection Opportunities Present in This Data

- **Security EID 4688:** `csc.exe` spawned by `powershell.exe` with a `SystemTemp` path is a signature of `Add-Type` compilation; paired with the parent's command line containing `DllImport("advapi32.dll")` and privilege-related function names, it is a reliable indicator of runtime privilege escalation tooling.
- **Sysmon EID 22 + EID 3:** `powershell.exe` (SYSTEM context) resolving `github.com` or `githubusercontent.com` and immediately establishing TCP:443 connections is unusual in most enterprise environments and should be treated as a high-priority signal when the originating process is running as SYSTEM.
- **PowerShell EID 4103:** The `Invoke-WebRequest` to a GitHub releases URL is logged with the full URI, providing the download source. Combined with the `Add-Type` in the same session, this documents the complete tooling acquisition chain.
- **Security EID 4688 command line:** The full C# class definition including `OpenProcessToken` and `LookupPrivilegeValue` P/Invoke signatures appears in the process command-line field, which is indexed by most SIEM platforms.
