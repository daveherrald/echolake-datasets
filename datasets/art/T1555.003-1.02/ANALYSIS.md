# T1555.003-1: Credentials from Web Browsers — Run Chrome-password Collector

## Technique Context

T1555.003 covers credential theft specifically from web browsers. Chrome, Chromium-based Edge, and Firefox store saved passwords in local SQLite databases, encrypted with the Windows Data Protection API (DPAPI) under the user's profile. An attacker with access to the victim's user context — or SYSTEM context with the ability to impersonate the target user — can copy the locked database file and decrypt its entries using the DPAPI master key associated with that user.

Chrome stores its login data at `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`. Because Chrome holds an exclusive lock on this file while running, credential collectors typically need to copy the file to a temporary location before reading it. The decryption step requires either the user's DPAPI key (available in the user's context) or access to the master key backup materials.

This ART test (`T1555.003-1`) uses a Chrome password collector that requires `accesschk.exe` (a Sysinternals tool) as a prerequisite — specifically running `accesschk.exe -accepteula .` to silently accept the EULA before the collector can use other Sysinternals tools. The test runs on ACME-WS06 with Defender disabled.

## What This Dataset Contains

The dataset contains 145 total events: 33 Sysmon events, 107 PowerShell operational events, 4 Security events, and 1 Application event.

**Sysmon EID 1 (Process Create)** captures four process creation events. Two are ART test framework `whoami.exe` identity checks. The key attack-related commands are:

```
CommandLine: "powershell.exe" & {Start-Process ""C:\AtomicRedTeam\atomics\..\ExternalPayloads\Sysinternals\accesschk.exe"" -ArgumentList ""-accepteula .""}
CurrentDirectory: C:\Windows\TEMP\
User: NT AUTHORITY\SYSTEM
RuleName: technique_id=T1083,technique_name=File and Directory Discovery
```

```
CommandLine: "powershell.exe" & {Remove-Item ""C:\AtomicRedTeam\atomics\..\ExternalPayloads\Sysinternals"" -Force -Recurse -ErrorAction Ignore}
CurrentDirectory: C:\Windows\TEMP\
User: NT AUTHORITY\SYSTEM
```

The second command is the ART cleanup step, removing the Sysinternals directory after the test. The presence of both the setup (`Start-Process accesschk.exe -accepteula`) and cleanup (`Remove-Item`) commands in the process tree indicates the test ran through its full lifecycle, including teardown.

**Security EID 4688** captures the same four process creation events with full command-line auditing. The complete command lines are visible:

- `"C:\Windows\system32\whoami.exe"` (test framework identity check)
- `"powershell.exe" & {Start-Process ""C:\AtomicRedTeam\atomics\..\ExternalPayloads\Sysinternals\accesschk.exe"" -ArgumentList ""-accepteula .""}`
- `"C:\Windows\system32\whoami.exe"` (second test framework check)
- `"powershell.exe" & {Remove-Item ""C:\AtomicRedTeam\atomics\..\ExternalPayloads\Sysinternals"" -Force -Recurse -ErrorAction Ignore}`

**Sysmon EID 7 (Image Load)** captures 22 events. **EID 10 (Process Access)** captures 4 events. **EID 17 (Pipe Create)** captures 2 events. **EID 11 (File Create)** captures 1 event.

**PowerShell EID 4104** captures 105 script block events. The script block content includes `Set-ExecutionPolicy Bypass -Scope Process -Force` and the ART cleanup invocation:

```
try {
    Invoke-AtomicTest T1555.003 -TestNumbers 1 -Cleanup -Confirm:$false 2>&1 | Out-Null
} catch {}
```

**EID 4100** (PowerShell error) appears 1 time, and **EID 4103** 1 time.

## What This Dataset Does Not Contain

**No Chrome credential collector execution events.** The dataset captures only the `accesschk.exe` prerequisite step and the cleanup, not the actual Chrome password collector tool. Based on the defended analysis (which noted the test failed at this prerequisite step on the ACME-WS02 machine), the Chrome password collector itself — which would access `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` — did not execute or its execution events are not present in this dataset.

**No `accesschk.exe` process creation event.** Despite the command `Start-Process ""...Sysinternals\accesschk.exe"" -ArgumentList ""-accepteula .""`  being captured in Sysmon EID 1, the actual `accesschk.exe` child process creation event is not in the sampled events. The 4 Sysmon EID 1 events account for `whoami` (×2) and both PowerShell invocations, leaving no room for `accesschk.exe`. This could mean `accesschk.exe` was not present in the ExternalPayloads directory, or its execution appeared outside the sample window.

**No file access to Chrome's Login Data.** Sysmon EID 11 (file creation) appears once but no events show access to Chrome profile directories.

**No DPAPI-related events.** There are no events showing DPAPI decryption operations, which would be required for actual credential extraction.

**No credential output.** Whatever the Chrome collector may have found (or failed to find) is not recorded in the event logs.

## Assessment

This dataset primarily captures the ART test infrastructure (prerequisite setup and cleanup) rather than the core credential theft operation. The `accesschk.exe` EULA acceptance step and the subsequent Sysinternals directory cleanup are both recorded, but the Chrome password collection itself leaves no distinct trace in this dataset.

Compared to the defended variant (37 Sysmon, 46 PowerShell, 10 Security), the undefended run has comparable Sysmon counts (33 vs 37) but slightly fewer — consistent with fewer events from Defender's own remediation activity being absent. The PowerShell event count (107 vs 46) is substantially higher in the undefended run, suggesting the ART test framework ran more fully to completion.

The lower Sysmon event count here compared to other T1555 tests (33 vs 40-42) may indicate fewer DLL loads, possibly because the Chrome password collector tool did not fully execute or was not found.

For the dataset to contain the core credential collection activity, `accesschk.exe` would need to be present in the ExternalPayloads directory and the Chrome password collector tool would need to successfully access the Chrome Login Data file.

## Detection Opportunities Present in This Data

**Sysmon EID 1** and **Security EID 4688** capture the `Start-Process accesschk.exe -accepteula` command executed from `C:\Windows\TEMP\` as SYSTEM. While `accesschk.exe` is a legitimate Sysinternals tool, its execution from the ART payload directory under SYSTEM context is unusual and contextually suspicious.

The cleanup command `Remove-Item ""C:\AtomicRedTeam\atomics\..\ExternalPayloads\Sysinternals"" -Force -Recurse` is also recorded in both Sysmon EID 1 and Security EID 4688 — an attacker performing cleanup is itself an observable action that indicates prior tool staging.

**PowerShell EID 4104** captures `Invoke-AtomicTest T1555.003 -TestNumbers 1 -Cleanup` in a script block, which is an ART test framework artifact. In a real attack, cleanup commands would look different but would similarly appear in script block logs.

In environments where Chrome is installed and the Chrome password collector successfully executes, the additional detection opportunities would include: Sysmon EID 11 showing a copy of `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` to a temp directory, Sysmon EID 1 showing the collector tool process, and potentially Sysmon EID 10 showing the collector accessing Chrome's process handle.
