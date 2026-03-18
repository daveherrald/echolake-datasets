# T1555.003-16: Credentials from Web Browsers — Chrome / Firefox / Microsoft Edge

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) includes file-staging approaches that copy browser credential files without executing a dedicated credential-dumping binary. This test targets Firefox's credential store specifically: `key4.db` (the NSS key database containing the master password and encryption keys) and `logins.json` (the encrypted credential entries). Together these two files contain everything needed to decrypt Firefox saved passwords offline. The test uses PowerShell's `Get-ChildItem` to locate the active Firefox profile directory (matching `*default-release*`) and then `Copy-Item` to stage both files.

## What This Dataset Contains

**Command executed (Security 4688 and Sysmon EID=1):**
```
"powershell.exe" & {$profile = (Gci -filter "*default-release*"
    -path $env:Appdata\Mozilla\Firefox\Profiles\).FullName
Copy-Item $profile\key4.db -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads" > $null
Copy-Item $profile\logins.json -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads" > $null
...}
```

**PowerShell 4104 script blocks:**
- The full script block captured verbatim in two events, exposing the Firefox profile path search pattern (`*default-release*`), both target files (`key4.db`, `logins.json`), and the output redirection to suppress errors.

**Sysmon EID=1 (Process Create):**
- `whoami.exe` (T1033) and child `powershell.exe` (T1059.001).

**Sysmon EID=10 (Process Access):**
- Parent PowerShell accessing child process handles — T1055.001 heuristic.

**Sysmon EID=11 (File Created):**
- `StartupProfileData-Interactive` and `StartupProfileData-NonInteractive` under the SYSTEM PowerShell profile — standard startup artifacts only. No `key4.db` or `logins.json` files appear in `ExternalPayloads`, because Firefox is not installed in the SYSTEM account's `%APPDATA%\Mozilla\Firefox\Profiles\` path.

**Security exit codes:** All PowerShell processes exited `0x0` — the script ran without error. The `> $null` redirections and the use of `Gci` (Get-ChildItem) returning nothing silently means PowerShell completed without throwing an exception.

## What This Dataset Does Not Contain (and Why)

**Firefox credential files staged:** The SYSTEM account has no Firefox profile at `%APPDATA%\Mozilla\Firefox\Profiles\`. `Get-ChildItem` returned null; the `$profile` variable was empty; `Copy-Item $null\key4.db` silently failed due to the `> $null` error suppression. No files were copied.

**Defender block:** Firefox file staging with Copy-Item is not a malicious binary execution — Defender's real-time protection did not intervene. This test category is the file-system approach that most AV products do not block because it uses only built-in cmdlets.

**Difference from test 4 (Chrome) and test 5 (Opera):** Tests 4 and 5 use direct paths for Chrome and Opera respectively. Test 16 uses a wildcard profile directory search (`*default-release*`) that is more resilient to Firefox version changes and user-specific profile name variations — a more operationally realistic implementation.

## Assessment

Like tests 4 and 5, this test ran silently against a non-existent target (no Firefox in SYSTEM context). The key telemetry values are the 4104 script blocks exposing both `key4.db` and `logins.json` in the same staging script, and the wildcard-based profile discovery pattern. The `Gci -filter "*default-release*"` profile discovery followed by `Copy-Item $profile\key4.db` is a distinctive behavioral sequence that is directly detectable in PowerShell script block logs.

## Detection Opportunities Present in This Data

- **PowerShell 4104** contains `key4.db` and `logins.json` in the same script block — this combination is a high-confidence indicator of Firefox credential staging. Either string individually warrants attention.
- **PowerShell 4104** shows the profile discovery pattern `Gci -filter "*default-release*" -path $env:Appdata\Mozilla\Firefox\Profiles\` — this specific enumeration of Firefox profile directories is anomalous in most enterprise environments.
- **Security 4688 / Sysmon EID=1** capture the `Copy-Item ... key4.db ... logins.json` command line.
- The `> $null` error suppression in the command line is consistent with adversaries silently handling the case where Firefox is not installed — a sign of a scripted, multi-target operation rather than an opportunistic manual action.
- In a real user-context execution, **EID=11** events would show `key4.db` and `logins.json` appearing in the staging directory — a high-confidence file system indicator. Monitor for copy operations on these specific file names outside of legitimate Firefox backup operations.
- Correlation: PowerShell script block containing `Mozilla\Firefox\Profiles` + `Copy-Item` + `key4.db` or `logins.json` = immediate alert priority.
