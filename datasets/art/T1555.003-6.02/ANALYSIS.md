# T1555.003-6: Credentials from Web Browsers — Simulating Access to Windows Firefox Login Data

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) covers adversary attempts to extract saved credentials from browser profile stores. Firefox stores credentials in `logins.json` and `key4.db` within the user profile under `%APPDATA%\Mozilla\Firefox\Profiles\`. Attackers commonly exfiltrate the entire `Profiles` directory to decrypt credentials offline — `logins.json` contains AES256-encrypted credential entries, and `key4.db` holds the NSS key material needed to decrypt them. Copying the complete directory is a brute-force approach that captures all profiles and credentials without requiring knowledge of the specific profile name.

This test uses PowerShell's `Copy-Item` with `-Force -Recurse` — a built-in, signature-free approach that mirrors real adversary tradecraft observed in post-exploitation scenarios.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 3 seconds. It contains 141 events across three channels: 31 Sysmon, 106 PowerShell, and 4 Security.

**Primary command executed (Sysmon EID=1 and Security EID=4688):**
```
"powershell.exe" & {Copy-Item "$env:APPDATA\Mozilla\Firefox\Profiles\"
    -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads" -Force -Recurse}
```

**Cleanup command also recorded:**
```
"powershell.exe" & {Remove-Item -Path "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Profiles"
    -Force -ErrorAction Ignore -Recurse}
```

Both the staging and the cleanup operations appear in Security EID=4688 and Sysmon EID=1, running as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`. The cleanup command is particularly interesting from a forensic perspective: its presence in logs proves the ART test framework performed a cleanup step, which in a real attack would indicate deliberate artifact removal.

**Sysmon EID=1 (Process Create):** Four process creations: two `whoami.exe` instances (tagged T1033), the Copy-Item staging child PowerShell (tagged T1059.001), and the Remove-Item cleanup child PowerShell (tagged T1059.001).

**Sysmon EID=10 (Process Access):** Four EID=10 events showing PowerShell cross-process handle access at `GrantedAccess: 0x1FFFFF`, tagged `T1055.001`.

**Sysmon EID=11 (File Created):** One file creation event — a PowerShell startup profile artifact under the SYSTEM account.

**Sysmon EID=17 (Pipe Created):** Two named pipe events from PowerShell console host infrastructure.

**PowerShell EID=4104:** 105 script block events capturing both the Copy-Item staging command (with the Firefox Profiles directory path) and the Remove-Item cleanup command.

**Security EID=4688:** Four process creation events (SYSTEM context) capturing both PowerShell child processes — staging and cleanup — with their full command lines.

## What This Dataset Does Not Contain

**Staged Firefox profile files.** Firefox installs per-user. The SYSTEM account's `%APPDATA%\Mozilla\Firefox\Profiles\` contains no Firefox installation. The `-Recurse` Copy-Item silently found nothing to copy. No `logins.json`, `key4.db`, or profile directory structure appears in EID=11 events at the ExternalPayloads destination.

**File access events for the Firefox profile.** Object access auditing is disabled. Even a successful recursive copy would not generate EID=4663 read events for the source files.

**Defender block.** Copy-Item and Remove-Item are built-in PowerShell cmdlets. Defender's real-time protection does not flag this activity as malicious, making this technique one of the few in the T1555.003 series where Defender played no role in either the defended or undefended run.

**Comparison with the defended variant:** In the defended dataset (sysmon: 45, security: 10, powershell: 45), AMSI reduced some script block logging. The PowerShell event count here is 106 (vs 45 defended), reflecting the full evaluation of both the staging and cleanup script blocks without AMSI suppression. Notably, both datasets capture the cleanup command in the process creation events — the cleanup is not hidden from telemetry. The defended run had slightly more Security events (10 vs 4), likely reflecting additional process lifecycle events from Defender monitoring.

## Assessment

This dataset records both phases of the Firefox profile staging operation: the initial recursive copy and the post-execution cleanup. The cleanup step being fully logged in both Security EID=4688 and Sysmon EID=1 is an analytically interesting property — a real attacker performing artifact removal would generate the same cleanup events, and those events are themselves investigative leads.

The technique did not produce credential output due to the SYSTEM context. For detection development purposes, the combination of the Firefox Profiles path in Copy-Item script blocks, the recursive flag, and the ExternalPayloads destination are the primary indicators.

## Detection Opportunities Present in This Data

**PowerShell EID=4104 — Firefox Profiles directory in Copy-Item with -Recurse:** The path `$env:APPDATA\Mozilla\Firefox\Profiles\` combined with `-Force -Recurse` in a Copy-Item block is a highly specific indicator of Firefox profile exfiltration.

**Security EID=4688 / Sysmon EID=1 — two sequential PowerShell children:** The pattern of a parent PowerShell spawning one child to stage files and a second child to remove the staged copy (cleanup) is a behavioral sequence detectable through process correlation.

**PowerShell EID=4104 — Remove-Item on ExternalPayloads\Profiles:** The cleanup command in the script block log, targeting a specific previously staged directory, is itself an indicator of post-operation artifact removal.

**Process timeline correlation — staging followed by cleanup:** The presence of both a copy operation targeting a browser profile path and a subsequent remove operation targeting the staging destination within a short time window is a behavioral chain that distinguishes credential staging with cleanup from benign file management.

**EID=4104 browser profile path monitoring:** Extending monitoring to Copy-Item operations targeting `Mozilla\Firefox\Profiles`, `Google\Chrome\User Data`, and `Opera Software` across all PowerShell script block events provides broad coverage for the file-staging credential theft family.
