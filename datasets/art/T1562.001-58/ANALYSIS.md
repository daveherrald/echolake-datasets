# T1562.001-58: Disable or Modify Tools — Freeze PPL-protected Process with EDR-Freeze

## Technique Context

T1562.001 (Disable or Modify Tools) covers adversary actions to impair defenses. This test attempts to use EDR-Freeze, a publicly available tool that targets PPL (Protected Process Light) processes — the protection level used by many EDR agents — by freezing their threads rather than terminating them, which would be blocked by PPL. Freezing a PPL-protected security process could prevent it from processing events or sending telemetry without triggering the service-terminated alerts that a full kill would cause. The technique requires SeDebugPrivilege and uses a custom C# assembly compiled at runtime via `Add-Type`.

## What This Dataset Contains

The dataset spans 24 seconds and captures 113 events across Sysmon (4), Security (24), and PowerShell (85) channels.

**PowerShell 4104 (script block logging)** records the core attack payload:

```
# Enable SeDebugPrivilege
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class TokenAdjuster {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(...)
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(...)
```

**PowerShell 4103 (module logging)** records a sequence confirming the attack flow: `Add-Type` (C# compilation), `Write-Host "SeDebugPrivilege enabled successfully."`, then `Invoke-WebRequest` to `https://github.com/TwoSevenOneT/EDR-Freeze/releases/download/main/EDR-Freeze_1.0.zip`. It also records the failure path: `Write-Host "Failed to download or extract EDR-Freeze: Cannot bind argument to parameter 'Path' because it is null."` — the download succeeded but path resolution for the extracted executable failed, so EDR-Freeze never ran.

**Sysmon Event ID 3** (network connection) records two outbound TCP connections from `powershell.exe` (NT AUTHORITY\SYSTEM, PID 660) to `185.199.108-111.133` (GitHub CDN). **Sysmon Event ID 22** (DNS query) shows resolution of both `github.com` (→ 140.82.112.4) and `release-assets.githubusercontent.com` (→ 185.199.108-111.133/4 IPs).

**Security** events include a full logon sequence (4624 logon type 5, 4627 group membership, 4672 special privileges for SeDebugPrivilege and others), process creates for `csc.exe` and `cvtres.exe` (the .NET compiler toolchain invoked by `Add-Type`), and process exits for multiple powershell.exe instances. One powershell.exe exits with status `0x1` (failure), corresponding to the EDR-Freeze execution path that aborted.

## What This Dataset Does Not Contain (and Why)

EDR-Freeze was downloaded but never executed. The path resolution failure (`Join-Path` binding error) prevented the tool from being located after extraction, so there is no evidence of EDR-Freeze spawning, no process access to any PPL-protected process, and no NtSuspendThread or similar syscall activity.

There are no Sysmon Event ID 1 (process create) events for `csc.exe` or `cvtres.exe`, because the sysmon-modular include-mode filter does not match the .NET compiler toolchain. These compiles are instead visible only through Security 4688/4689. Similarly, no Sysmon process create is recorded for the powershell.exe instances, as they are spawned by the ART test framework in a way that does not match include rules.

The downloaded zip file and any extracted contents are not captured — file creates from `Invoke-WebRequest` to Temp paths are not covered by the Sysmon FileCreate rules in this configuration.

Windows Defender did not block the download or `Add-Type` compilation in this case, though the effective outcome was identical to a block: the tool did not execute.

## Assessment

The technique partially executed. SeDebugPrivilege was successfully enabled, the EDR-Freeze zip was downloaded from GitHub, but a PowerShell path-handling bug in the ART test script prevented the executable from being found and run. The target process was never frozen. The dataset represents the attempt telemetry pattern, not a successful freeze.

The most security-relevant signals here — the outbound connection to GitHub for an offensive tool and the in-memory C# compilation for privilege adjustment — are both captured and detectable.

## Detection Opportunities Present in This Data

- **Sysmon 22 (DNS):** `powershell.exe` querying `release-assets.githubusercontent.com` from a SYSTEM context with no user session is highly anomalous.
- **Sysmon 3 (network):** Outbound TCP from `powershell.exe` as SYSTEM to GitHub CDN IP ranges (185.199.108.0/22) is detectable, particularly in conjunction with the DNS query pattern.
- **Security 4688:** `csc.exe` and `cvtres.exe` spawned from `powershell.exe` as SYSTEM indicates in-process C# compilation via `Add-Type`, a common offensive pattern.
- **Security 4672:** Special privilege assignment including `SeDebugPrivilege` to a SYSTEM logon in a batch/service context (logon type 5) warrants investigation when paired with subsequent network activity.
- **PowerShell 4104:** The `TokenAdjuster` class definition with P/Invoke to `advapi32.dll` privilege adjustment APIs is a recognizable offensive pattern in script block logs.
- **PowerShell 4103:** `Invoke-WebRequest` with a GitHub releases URL for a known offensive tool (`EDR-Freeze`) is directly detectable by URL pattern matching.
