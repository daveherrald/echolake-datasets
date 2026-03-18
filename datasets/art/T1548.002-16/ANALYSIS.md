# T1548.002-16: Bypass User Account Control — UACME Bypass Method 59

## Technique Context

T1548.002 (Bypass User Account Control) covers techniques that allow adversaries to silently elevate process privileges without triggering a UAC consent prompt. UACME (User Account Control Method Encyclopedia) is a publicly maintained collection of UAC bypass methods. Method 59 exploits an auto-elevate COM object or application trust relationship to gain elevated execution without a user-visible prompt. The `Akagi64.exe` binary (UACME's test framework) accepts a method number and payload on the command line, implementing the bypass and launching the specified command with elevated integrity.

## What This Dataset Contains

The dataset captures approximately 5 seconds of activity on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local) during the execution of UACME method 59.

**Sysmon Event 1** records the critical launch chain:
- `whoami.exe` spawned by `powershell.exe` (the ART pre-execution check)
- `cmd.exe` with the explicit UACME invocation: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\59 Akagi64.exe"`
  - Parent: `powershell.exe` (SYSTEM, Logon ID `0x3E7`)
  - Hashes: `SHA256=A6E3B3B22B7FE8CE2C9245816126723EAA13F43B9F591883E59959A2D409426A`

**Sysmon Event 10** records `powershell.exe` opening `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF` (full access), flagged under the DLL Injection rule — this is the Invoke-AtomicRedTeam framework creating child processes.

**Sysmon Events 7** (image loads) document DLL loading into the PowerShell process, tagged with rules for T1055 (Process Injection), T1059.001 (PowerShell), and T1574.002 (DLL Side-Loading), as well as `urlmon.dll` loading (no rule match).

**Sysmon Events 11** record file creation of PowerShell startup profile data in `C:\Windows\System32\config\systemprofile\AppData\Local\...`.

**Sysmon Event 17** (named pipe creation): `\PSHost.*.powershell` pipes for each PowerShell instance.

**Security 4688** records `whoami.exe` and `cmd.exe` process creation.

**Security 4689** records `cmd.exe` exiting with status `0x1` (failure), indicating Akagi did not successfully complete the bypass.

**Security 4703** records a token right adjustment on the SYSTEM logon session.

**PowerShell 4104/4103**: Two `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force` invocations from the ART test framework. No UACME-specific script block content — the test framework calls the pre-built Akagi64.exe binary directly via `cmd.exe`.

## What This Dataset Does Not Contain (and Why)

**No Akagi64.exe process creation in Sysmon**: The sysmon-modular include-mode ProcessCreate filter does not match `Akagi64.exe` by name, so it is absent from Sysmon Event 1. However, it would appear in a Security 4688 audit if command-line logging captured it; those events are present but the field rendering was truncated in this capture.

**No elevated process spawned by the bypass**: `cmd.exe` exited with status `0x1`, indicating UACME method 59 failed on this Windows 11 build. No elevated child process (e.g., `cmd.exe` with `TokenElevationTypeFull`) appears.

**No network connections**: This method does not involve network activity. The one Sysmon Event 3 present is a Windows Defender outbound connection captured well outside the test window (~9 hours later) and is unrelated to the test.

**No Sysmon ProcessCreate for Akagi64.exe**: The include-mode filter does not match this binary, demonstrating a coverage gap for unknown binaries deposited into `ExternalPayloads`.

## Assessment

UACME method 59 did not succeed on this Windows 11 22631 build. The `cmd.exe` exit code `0x1` confirms failure. The dataset captures the attempt — including the binary invocation path and the SYSTEM-context process tree — but does not contain post-bypass elevated execution telemetry. The Sysmon include-mode configuration misses Akagi64.exe itself, though the wrapping `cmd.exe` call is visible.

## Detection Opportunities Present in This Data

- **Sysmon Event 1 / Security 4688**: `cmd.exe` launched with a command line referencing `ExternalPayloads\uacme\` or `Akagi64.exe` is a direct signature for this test.
- **File presence**: `C:\AtomicRedTeam\ExternalPayloads\uacme\Akagi64.exe` on disk is a strong indicator; file creation events would appear if Sysmon file rules matched that path.
- **Process lineage**: `powershell.exe` (SYSTEM) → `cmd.exe` → `Akagi64.exe` is an unusual chain for a domain workstation.
- **Hash-based detection**: The SHA256 of `Akagi64.exe` (`A6E3B3B22B7FE8CE2C9245816126723EAA13F43B9F591883E59959A2D409426A` for `cmd.exe` in this event — note this is the cmd.exe wrapper) is logged and can be used for lookups.
- **Security 4689 exit code**: A non-zero exit from `cmd.exe` invoked with a UACME binary path may indicate a blocked or failed bypass attempt worth investigating even when the bypass doesn't succeed.
