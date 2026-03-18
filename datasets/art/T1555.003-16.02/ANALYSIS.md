# T1555.003-16: Credentials from Web Browsers — BrowserStealer (Chrome / Firefox / Microsoft Edge)

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) includes file-staging approaches that copy browser credential files for offline decryption rather than executing a dedicated credential-dumping binary. This test targets Firefox's credential store specifically: `key4.db` (the NSS key database containing the master password and encryption keys) and `logins.json` (the encrypted credential entries). Together these two files contain everything needed to decrypt Firefox saved passwords offline. The test also runs `BrowserCollector.exe` to perform cross-browser credential collection.

With Defender disabled, the full PowerShell staging script runs without AMSI interception, and BrowserCollector.exe can execute without behavioral blocking.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 6 seconds. It contains 155 events across three channels: 26 Sysmon, 126 PowerShell, and 3 Security.

**Command executed (Sysmon EID=1 and Security EID=4688):**
```
"powershell.exe" & {$profile = (Gci -filter "*default-release*"
    -path $env:Appdata\Mozilla\Firefox\Profiles\).FullName
Copy-Item $profile\key4.db -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads" > $null
Copy-Item $profile\logins.json -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads" > $null
Remove-Item $profile\key4.db > $null
Remove-Item $profile\logins.json > $null
Copy-Item "$env:C:\AtomicRedTeam\atomics\T1555.003\src\key4.db" -Destination $profile\ > $null
Copy-Item "$env:C:\AtomicRedTeam\atomics\T1555.003\src\logins.json" -Destination $profile\ > $null
cd "$env:C:\AtomicRedTeam\atomics\T1555.003\bin\"
""|.\BrowserCollector.exe}
```
This appears verbatim in Security EID=4688 and in the PowerShell EID=4104 script block logging. The script: (1) locates the active Firefox profile directory via `*default-release*` wildcard, (2) stages `key4.db` and `logins.json` to `ExternalPayloads`, (3) removes the originals, (4) replaces them with ART-provided test files, and (5) pipes to `BrowserCollector.exe`.

**PowerShell EID=4104:** 125 script block events capturing the full multi-step staging script, the Firefox profile search pattern, both source paths (`key4.db`, `logins.json`), and the BrowserCollector invocation.

**Sysmon EID=10 (Process Access):** Three EID=10 events showing PowerShell cross-process handle acquisition at `GrantedAccess: 0x1FFFFF`, tagged `T1055.001`.

**Sysmon EID=1 (Process Create):** Three process creations: two `whoami.exe` instances (tagged T1033) and the child `powershell.exe` executing the BrowserStealer script (tagged T1059.001).

**Sysmon EID=11 (File Created):** PowerShell startup profile data written to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` — a standard SYSTEM-context PowerShell startup artifact.

**Sysmon EID=17 (Pipe Created):** Two named pipe creations from PowerShell console host infrastructure.

**Security EID=4688:** Three process creation events, all SYSTEM context, capturing `whoami.exe` and the full BrowserStealer script block in the command line.

## What This Dataset Does Not Contain

**Firefox credential files staged to ExternalPayloads.** Firefox installs per user. The SYSTEM account's `%APPDATA%\Mozilla\Firefox\Profiles\` contains no `*default-release*` directory. `Get-ChildItem` returned null, `$profile` was empty, and all `Copy-Item` operations silently failed due to the `> $null` error suppression. No `key4.db` or `logins.json` appear in EID=11 events.

**BrowserCollector.exe in Security EID=4688 or Sysmon EID=1.** The `""|.\BrowserCollector.exe` invocation occurs after the staging logic. Whether BrowserCollector.exe generated its own process creation event or similarly found no browser data to collect is not fully resolved by the available samples, but no explicit BrowserCollector process create appears in the sample set.

**Defender block.** Firefox file staging with Copy-Item uses only built-in PowerShell cmdlets — not a malicious binary. Defender's real-time protection would not have intervened even if enabled. The test outcome here is identical to what would occur in a defended run, which is why the undefended event counts (sysmon: 26, security: 3, powershell: 126) significantly exceed the defended counts (sysmon: 36, security: 10, powershell: 65) in the opposite way from most tests: the PowerShell count is higher here because AMSI in the defended run suppressed some script blocks.

**Comparison with the defended variant:** In the defended dataset, the technique was also a no-op due to the SYSTEM context, but AMSI reduced the observable PowerShell event volume. The key difference in the undefended dataset is the full script block is preserved intact in EID=4104, and the BrowserCollector invocation is visible in the command line.

## Assessment

This dataset cleanly captures the file-staging approach to browser credential theft. The complete multi-step script — Firefox profile location via wildcard, dual-file staging, original removal, replacement with test files, and BrowserCollector invocation — is recorded in full across the PowerShell EID=4104 events and the Security/Sysmon process creation events. The technique did not produce credential output due to the SYSTEM context, but the attack pattern is fully observable.

The significant point for detection development is that this technique uses only built-in PowerShell cmdlets (Copy-Item, Remove-Item, Get-ChildItem), making process-based detection ineffective. The observable indicators are in script block content and the file paths involved.

## Detection Opportunities Present in This Data

**PowerShell EID=4104 — Firefox profile path pattern:** The script block contains `$env:Appdata\Mozilla\Firefox\Profiles\` and the `*default-release*` wildcard filter. References to Firefox profile directories in PowerShell script blocks are a specific indicator.

**PowerShell EID=4104 — key4.db and logins.json file names:** These file names in a Copy-Item or staging context are highly specific to Firefox credential theft and appear verbatim in the EID=4104 logs.

**PowerShell EID=4104 — ExternalPayloads staging directory:** Staging to `C:\AtomicRedTeam\atomics\..\ExternalPayloads` is test-test framework specific, but the general pattern of staging to a non-standard directory is detectable.

**PowerShell EID=4104 — BrowserCollector.exe invocation:** The `.\BrowserCollector.exe` reference in a script block is a specific binary name associated with this technique.

**Security EID=4688 — full script block in command line:** When command-line auditing is enabled, the entire staging script is visible in the 4688 event, including the target file names and destination paths.
