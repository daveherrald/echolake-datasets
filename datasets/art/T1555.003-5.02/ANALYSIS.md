# T1555.003-5: Credentials from Web Browsers — Simulating Access to Opera Login Data

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) covers staging of browser credential databases for offline decryption. Opera stores saved passwords in a SQLite database at `%APPDATA%\Opera Software\Opera Stable\Login Data`, using the same Chromium-based credential protection scheme (DPAPI encryption) as Google Chrome. Adversaries targeting multi-browser environments stage Opera's credential store alongside Chrome and Firefox databases to maximize credential coverage before exfiltration or local DPAPI decryption.

This test uses PowerShell's `Copy-Item` cmdlet directly — a built-in, LOLBin-style approach that requires no additional tooling and generates minimal behavioral telemetry compared to dedicated credential theft utilities.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 3 seconds. It contains 135 events across three channels: 26 Sysmon, 106 PowerShell, and 3 Security.

**Command executed (Sysmon EID=1 and Security EID=4688):**
```
"powershell.exe" & {Copy-Item "$env:APPDATA\Opera Software\Opera Stable\Login Data"
    -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads"}
```
The full command line appears verbatim in Security EID=4688 and Sysmon EID=1. Running as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`.

**Sysmon EID=1 (Process Create):** Three process creations: two `whoami.exe` instances (tagged T1033) and the child `powershell.exe` executing the Copy-Item staging block (tagged T1059.001).

**Sysmon EID=10 (Process Access):** Three EID=10 events showing `powershell.exe` cross-process handle access at `GrantedAccess: 0x1FFFFF`, tagged `T1055.001`.

**Sysmon EID=11 (File Created):** One event: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` written by the SYSTEM PowerShell process — standard startup artifact.

**Sysmon EID=17 (Pipe Created):** Two named pipe events from PowerShell console host infrastructure.

**PowerShell EID=4104:** 105 script block events capturing the full Copy-Item command with the Opera path `$env:APPDATA\Opera Software\Opera Stable\Login Data` and the `ExternalPayloads` destination.

**Security EID=4688:** Three process creation events (SYSTEM context) capturing `whoami.exe` twice and the child PowerShell with the Opera staging command.

## What This Dataset Does Not Contain

**Actual Opera Login Data staged.** Opera installs per-user under `%APPDATA%`. The SYSTEM account's `%APPDATA%` maps to `C:\Windows\system32\config\systemprofile\AppData\Roaming\`, which contains no Opera installation. `Copy-Item` found no source file and silently completed with exit code `0x0`. No `Login Data` file appears in EID=11 events within the ExternalPayloads directory.

**Defender block.** Staging a browser credential file with Copy-Item is not flagged as malicious by Windows Defender. This technique uses only built-in PowerShell cmdlets — no binary execution, no network activity, no signature-matchable payload. Defender's real-time protection would not have intervened even if enabled. The undefended and defended outcomes for this test are functionally identical in terms of whether the technique succeeded.

**File read events.** Object access auditing is disabled in this environment. Even a successful copy would not generate EID=4663 (File Audit) events.

**Comparison with the defended variant:** In the defended dataset (sysmon: 36, security: 10, powershell: 45), AMSI reduced some PowerShell script block logging. Here the PowerShell count is 106 (vs 45 defended) — the full evaluation of the Copy-Item script block is preserved without AMSI suppression. The Sysmon and Security event structures are otherwise very similar because Defender plays no blocking role in either run for this technique.

## Assessment

This dataset captures the PowerShell-native file-staging approach to Opera credential theft. The `$env:APPDATA\Opera Software\Opera Stable\Login Data` source path and `ExternalPayloads` destination appear in full in both Security EID=4688 and PowerShell EID=4104 events. The technique completed silently with exit code `0x0` — as it would in a user-context execution, making behavioral alerting on exit codes ineffective here.

The dataset's limitation is the absence of an actual credential file being staged — the SYSTEM context means no Opera data was present. For detection development purposes, the command line and script block content are the relevant artifacts.

## Detection Opportunities Present in This Data

**PowerShell EID=4104 — Opera credential path in script block:** The explicit path `$env:APPDATA\Opera Software\Opera Stable\Login Data` in a Copy-Item context is a narrow indicator. Combined with a non-standard destination path, this is a reliable behavioral signal.

**Security EID=4688 — PowerShell command line with Opera path:** The command line in the process creation event contains the full Opera credential store path and the ExternalPayloads staging destination verbatim.

**Sysmon EID=1 — child PowerShell staging from browser profile path:** The process create event captures the same command line with the Opera path.

**Staging destination pattern — ExternalPayloads:** While this is ART-specific, the general pattern of copying from a browser-profile path to a non-standard staging directory (temp, ProgramData, a tool-specific output folder) is detectable from the command line.

**PowerShell EID=4104 — Copy-Item from browser profile directories:** Monitoring for Copy-Item operations targeting paths containing `Opera Software`, `Google\Chrome`, or `Mozilla\Firefox` in script block content provides coverage for this class of file-staging technique across all three major Chromium and Firefox-based browser families.
