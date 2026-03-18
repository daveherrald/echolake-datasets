# T1555.003-17: Credentials from Web Browsers — Dump Chrome Login Data with esentutl

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) includes the use of living-off-the-land binaries (LOLBins) to access locked browser credential files. Chrome's `Login Data` SQLite database is locked by the browser process while Chrome is running. Adversaries use `esentutl.exe` — a legitimate Windows database utility — to bypass this lock by performing a volume-level database copy using the `/y` (copy source) and `/d` (destination) flags. `esentutl.exe` is a signed Microsoft binary present on all Windows systems, making it useful for evading application-control policies.

With Defender disabled, `esentutl.exe` executes without behavioral blocking. In an environment where Chrome is installed and the database path exists, this technique completes successfully and produces a usable copy of the credential database.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 5 seconds. It contains 118 events across three channels: 17 Sysmon, 97 PowerShell, and 4 Security.

**Commands executed (Sysmon EID=1 and Security EID=4688):**

The outer PowerShell command:
```
"cmd.exe" /c esentutl.exe /y "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"
    /d "%temp%\T1555.003_Login_Data.tmp"
```

Which resolved at runtime under SYSTEM context to:
```
esentutl.exe  /y "C:\Windows\system32\config\systemprofile\AppData\Local\
    Google\Chrome\User Data\Default\Login Data"
    /d "C:\Windows\TEMP\T1555.003_Login_Data.tmp"
```

Both the unexpanded (with `%LOCALAPPDATA%` and `%temp%` variables) and expanded forms appear in the Security EID=4688 and Sysmon EID=1 events. The distinction between the `cmd.exe` command line (pre-expansion) and the `esentutl.exe` command line (post-expansion) is forensically informative — you can observe the environment variable resolution that occurs between the cmd wrapper and the launched utility.

**Sysmon EID=1 (Process Create) — esentutl.exe:** Unlike most binaries in this test series, `esentutl.exe` itself appears as a Sysmon EID=1 process create, tagged `technique_id=T1564.004,technique_name=NTFS File Attributes`. The sysmon-modular config matches `esentutl` for its NTFS stream manipulation capability. Process details:
- Image: `C:\Windows\System32\esentutl.exe`
- Parent: `C:\Windows\System32\cmd.exe`
- CommandLine: `esentutl.exe  /y "C:\Windows\system32\config\systemprofile\AppData\Local\Google\Chrome\User Data\Default\Login Data" /d "C:\Windows\TEMP\T1555.003_Login_Data.tmp"`
- User: `NT AUTHORITY\SYSTEM`, IntegrityLevel: System

**Sysmon EID=1 (Process Create) — cmd.exe:** `cmd.exe` launching `esentutl.exe`, tagged `technique_id=T1059.003,technique_name=Windows Command Shell`. Parent: `powershell.exe`.

**Security EID=4688:** Four process creation events capturing `whoami.exe`, `cmd.exe` (with the pre-expansion esentutl command), and `esentutl.exe` (with the fully expanded path).

**PowerShell EID=4104:** 96 script block events containing the ART test framework boilerplate and the cmd invocation block.

**Exit codes:** `esentutl.exe` exited `0xfffffc01` (decimal -1023) — the esentutl error code for source file not found or inaccessible. `cmd.exe` propagated this exit code. The SYSTEM account's `%LOCALAPPDATA%` resolves to `C:\Windows\system32\config\systemprofile\AppData\Local\`, which contains no Chrome installation.

## What This Dataset Does Not Contain

**A successful credential database copy.** `esentutl.exe` failed with exit code `0xfffffc01` because Chrome is not installed in the SYSTEM account's profile. No `T1555.003_Login_Data.tmp` file appears in Sysmon EID=11 events because the copy operation never completed.

**Sysmon EID=11 for the output file.** In a user-context execution where Chrome is installed, EID=11 would capture `C:\Users\<user>\AppData\Local\Temp\T1555.003_Login_Data.tmp` being written. That event is absent here because esentutl failed before writing.

**Defender block.** `esentutl.exe` is a signed Microsoft binary — Defender does not block its execution. The failure is purely due to the missing source file. This is one of the few T1555.003 tests where Defender played no role in either the defended or undefended run.

**Comparison with the defended variant:** The defended dataset (sysmon: 27, security: 14, powershell: 34) and this undefended dataset have very similar structures — because Defender never blocked this test. The primary difference is that the defended run included more security events (14 vs 4), likely reflecting additional process lifecycle events. The esentutl process creation, command line, and failure exit code are present in both variants. The key value of the undefended dataset is confirming that the technique would succeed with Chrome present, and providing the complete process chain without the additional Defender-monitoring overhead.

## Assessment

This dataset provides a complete process execution chain for the esentutl LOLBin abuse pattern. The full esentutl command line — including the expanded Chrome `Login Data` path and the `.tmp` output destination — is preserved in both Sysmon EID=1 and Security EID=4688. The sysmon-modular rule tagging `esentutl` with `T1564.004` demonstrates how this binary is flagged as suspicious regardless of the specific use case.

The key detection value here lies in the command-line arguments: `/y` with a Chrome credential database path and `/d` to a temp file is a precise, unambiguous indicator of credential staging intent.

## Detection Opportunities Present in This Data

**Sysmon EID=1 / Security EID=4688 — esentutl.exe with /y and Chrome Login Data path:** The combination of `esentutl.exe`, the `/y` flag, and a path containing `Google\Chrome\User Data` or `Login Data` is a narrow, high-confidence indicator.

**Security EID=4688 — cmd.exe spawning esentutl.exe:** The process lineage `powershell.exe` → `cmd.exe` → `esentutl.exe` where `cmd.exe`'s command line references `esentutl` and a browser credential path is a meaningful behavioral chain.

**Sysmon EID=1 — esentutl.exe with /d pointing to %temp%:** Copying to a temp file as a staging step (rather than an administrative database operation) is a behavioral differentiator.

**Process parent-child chain:** `cmd.exe` spawned by `powershell.exe` spawning `esentutl.exe` — this specific three-level chain is characteristic of scripted LOLBin abuse.

**Exit code 0xfffffc01 from esentutl.exe in the process termination event:** A non-zero esentutl exit code after a credential-path copy attempt indicates an attempted but failed credential access operation, which may still warrant investigation.
