# T1547.001-10: Registry Run Keys / Startup Folder — Change Startup Folder (HKLM Modify User Shell Folders Common Startup Value)

## Technique Context

T1547.001 covers Registry Run Keys and Startup Folder persistence. This test exercises a variant that is structurally different from adding a Run key entry: instead of registering a new value under `Run`, the attacker modifies the registry value that tells Windows where the Common Startup folder is. The value `Common Startup` under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` defines the all-users startup directory. Windows Explorer and the logon process consult this path to determine what to execute at logon for all users.

By redirecting this value to an attacker-controlled directory pre-populated with malicious executables, the adversary causes those executables to run at next logon for every user without creating any new Run key entries. Detection tools that focus narrowly on writes to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` will not fire on this modification.

The test creates `C:\Windows\Temp\atomictest\`, copies `calc.exe` into it, and sets `Common Startup` to point to that directory. At next user logon, `calc.exe` would be launched for every user.

In the defended variant, this technique was not blocked. The undefended dataset is essentially identical in structure (30 vs 32 Sysmon events), with the small difference attributable to Defender DLL load activity in the defended environment.

## What This Dataset Contains

The dataset spans 6 seconds (2026-03-17 17:08:44–17:08:50 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`.

**Sysmon (30 events — Event IDs 1, 3, 7, 10, 11, 17, 29):**

Sysmon EID 1 (ProcessCreate, 3 events):

1. `whoami.exe` — test framework context check, tagged `technique_id=T1033`
2. `powershell.exe` — tagged `technique_id=T1083`, full command line:
   ```
   "powershell.exe" & {New-Item -ItemType Directory -path "$env:TMP\atomictest\"
   Copy-Item -path "C:\Windows\System32\calc.exe" -destination "$env:TMP\atomictest\"
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Common Startup" -Value "$env:TMP\atomictest\"}
   ```
3. `whoami.exe` — second context check

Sysmon EID 11 (FileCreate, 3 events):
- `C:\Windows\Temp\atomictest\calc.exe` — the payload binary copied by `powershell.exe` as NT AUTHORITY\SYSTEM
- `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` — standard PowerShell startup artifact

Sysmon EID 29 (FileExecutableDetected) records the creation of `C:\Windows\Temp\atomictest\calc.exe` tagged `technique_id=T1059.001` with full hashes:
- SHA256: `9C2C8A8588FE6DB09C09337E78437CB056CD557DB1BCF5240112CBFB7B600EFB`
- SHA1: `5D77804B87735E66D7D1E263C31C4EF010F16153`
- MD5: `2F82623F9523C0D167862CAD0EFF6806`
- IMPHASH: `8EEAA9499666119D13B3F44ECD77A729`

EID 29 fires when Sysmon detects a new executable written to disk — this provides both the file path and cryptographic identity of the staged payload independent of any process event.

Sysmon EID 3 (NetworkConnection) records an outbound TCP connection from `MsMpEng.exe` (Windows Defender cloud lookup — background activity, not technique-related).

**No Sysmon EID 13 (RegistrySetValue)** for the `Common Startup` modification. The `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Common Startup` key path was not matched by the sysmon-modular include rules. The registry change is documented only via the PowerShell command line in Sysmon EID 1 and Security EID 4688.

**Security (3 events — Event ID 4688):**

Only three process creation events: two `whoami.exe` invocations and one `powershell.exe` with the full command line. Notably lean compared to the defended variant (16 events) — without the additional WMI and logon events that Defender's WMI-based monitoring triggered in the defended environment, only the direct process chain is captured.

**PowerShell (101 events — Event IDs 4103, 4104):**

ScriptBlock logging captures the test payload verbatim, including the `Set-ItemProperty` command targeting `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` with the `Common Startup` value. This is the only channel that directly records the registry modification.

## What This Dataset Does Not Contain

- **No Sysmon EID 13:** The registry change to `Common Startup` is not captured as a registry event. The technique's core persistence artifact is visible only in process command line telemetry (Sysmon EID 1, Security EID 4688) and PowerShell ScriptBlock logging (EID 4104).
- **No logon execution:** The persistence fires at next user logon. No user logged on during this test window, so no execution of the staged `calc.exe` from the redirected startup folder is present.
- **No WMI logon events:** Unlike the defended variant (which had EID 4624 logon events from WMI-triggered execution), this dataset lacks the logon/privilege events because the undefended environment's audit policy or Defender monitoring did not trigger them.

## Assessment

This dataset presents a clean execution chain for the Common Startup folder redirect technique. The most significant artifact visible here — beyond the process creates — is Sysmon EID 29 (FileExecutableDetected) for `calc.exe` written to the redirected directory. EID 29 provides the cryptographic fingerprint of the staged payload and directly links `powershell.exe` to the file creation, independent of EID 11 or EID 1 context.

The absence of Sysmon EID 13 for the `Common Startup` value change is a meaningful coverage gap for registry-based detection. The technique would be missed entirely by detections that rely on EID 13 to identify startup folder path changes.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688:** `powershell.exe` command line containing `Set-ItemProperty` targeting `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` with `-Name "Common Startup"`. This is a specific and rarely-used registry path in normal administration.
- **Sysmon EID 29 (FileExecutableDetected):** An executable file written to `C:\Windows\Temp\atomictest\` (or any Temp-based path) by `powershell.exe`, tagged `technique_id=T1059.001`. A new executable in a temp directory created by a scripting host is a high-priority investigative lead.
- **Sysmon EID 11:** `C:\Windows\Temp\atomictest\calc.exe` created by `powershell.exe`. The combination of a temp-directory path, an executable file named after a system binary, and a scripting host as the creator process is anomalous.
- **PowerShell EID 4104:** `Set-ItemProperty ... "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Common Startup"` in a ScriptBlock. Any modification to startup folder path values via `Set-ItemProperty` from a non-administrative-tooling context should be investigated.
