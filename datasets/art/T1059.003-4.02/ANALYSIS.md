# T1059.003-4: Windows Command Shell — Simulate BlackByte Ransomware Print Bombing

## Technique Context

T1059.003 (Windows Command Shell) covers cmd.exe-based execution. This test simulates a technique attributed to BlackByte ransomware: print bombing, which spawns a large number of print jobs by repeatedly launching `wordpad.exe /p <file>` to overwhelm the print spooler and create resource exhaustion. In ransomware operations, print bombing serves two purposes — it disrupts operations by flooding printers, and it acts as a distraction or a signal to victims during the encryption phase.

The core cmd.exe command:
```
for /l %x in (1,1,75) do start wordpad.exe /p C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1059_003note.txt
```

This spawns 75 independent WordPad processes, each printing the same text file. The `start` keyword causes each launch to be non-blocking, so all 75 processes are created rapidly and run concurrently. The note file at `ExternalPayloads\T1059_003note.txt` is the ransom note or victim-facing message that would be printed.

Process creation monitoring is the primary detection mechanism for print bombing: 75 wordpad.exe processes with identical `/p` arguments spawned within seconds from a single cmd.exe parent. This is a trivially obvious anomaly for any process-count or child-spawn-rate threshold. The EID 4688 evidence is similarly clear-cut once the for-loop command line is recorded.

Windows Defender does not block this technique in either the defended or undefended context because it uses only legitimate system functionality — cmd.exe, WordPad, and the print system — to accomplish a denial-of-service.

## What This Dataset Contains

Security EID 4688 is the richest channel here, recording 61 process creation events. The chain is:

1. `"powershell.exe" & {cmd /c "for /l %x in (1,1,75) do start wordpad.exe /p C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1059_003note.txt" | out-null}` — the PowerShell wrapper for the for-loop command.
2. `"C:\Windows\system32\cmd.exe" /c "for /l %x in (1,1,75) do start wordpad.exe /p C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1059_003note.txt"` — the cmd.exe process running the for-loop.
3. 17+ instances of `"C:\Program Files\Windows NT\Accessories\wordpad.exe"  /p C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1059_003note.txt` captured in the 61-event sample (representing a subset of the 75 total spawns).

The full path `C:\Program Files\Windows NT\Accessories\wordpad.exe` and the note file path `ExternalPayloads\T1059_003note.txt` are consistent across all instances.

Sysmon contributes 188 events: 177 EID 7 (ImageLoad), 4 EID 1, 4 EID 10, 2 EID 17, 1 EID 11. The 177 ImageLoad events represent Windows Defender loading `MpOAV.dll` into each spawned WordPad process — with 75 processes and multiple DLL loads each, this is the Defender scanning overhead applied to each instance. EID 1 captures `whoami.exe`, the PowerShell process with the for-loop command, and cleanup. EID 10 shows PowerShell accessing the spawned processes with full access (0x1FFFFF).

The System channel records EID 243: "A desktop heap allocation failed." — the 75 WordPad processes competing for desktop heap space until the system runs out. This is a direct operational impact event confirming the print bombing achieved resource pressure.

The PowerShell channel has 95 EID 4104 events (all 4104, no 4100/4103). The script blocks contain the test framework and the `cmd /c for-loop` invocation.

Compared to the defended version (332 sysmon, 103 security, 36 powershell, 1 system), the undefended version has 188 sysmon, 61 security, 95 powershell, and 1 system event. Notably, the defended version had more events — 332 sysmon vs 188 here. This counterintuitive result reflects that the defended version captured more DLL load activity from the WordPad processes, possibly because Defender was more aggressive in scanning each instance. Both versions ran to completion.

## What This Dataset Does Not Contain

Sysmon EID 1 does not capture all 75 WordPad process creations — only a few appear in the samples, and the sysmon-modular include-mode filter limits EID 1 to known-suspicious process names. WordPad is not on the default suspicious-process list, so the bulk of the process spawning is invisible in Sysmon process-create events. The full 75-instance creation count is only recoverable from Security EID 4688.

No print spooler events — the actual job submissions to the Windows Print Spooler are not recorded here. No EID 3 network events. The text content of `T1059_003note.txt` is not captured in any event channel.

## Assessment

This dataset provides a complete picture of the attack chain — from the PowerShell invocation through the cmd.exe for-loop to the WordPad processes — primarily through Security EID 4688. The System EID 243 desktop heap exhaustion event is a rare and distinctive artifact of a resource-exhaustion attack actually succeeding. The 177 Sysmon EID 7 events from Defender scanning each WordPad instance document the operational cost of bulk process creation on endpoint security tooling.

For detection engineering, the most useful aspects are the processCreate volume (Security EID 4688 with 61 events in a short window) and the for-loop command line pattern. The Sysmon channel's ImageLoad dominance (177/188 events are EID 7) illustrates how bulk process creation shifts the event type distribution in ways that may affect SIEM storage or stream-processing pipelines.

## Detection Opportunities Present in This Data

1. EID 4688 with `cmd.exe` executing `for /l %x in (1,1,75) do start wordpad.exe /p` — the bulk-launch for-loop with a print flag is an unambiguous ransomware-behavior indicator.
2. High count of EID 4688 events for `wordpad.exe` with identical `/p <path>` arguments within a short time window — threshold-based detection on repeated spawns of a document viewer in print mode.
3. System EID 243 "desktop heap allocation failed" — resource exhaustion event indicating an unusually large number of GUI processes have been created.
4. EID 4688 `CommandLine` containing `ExternalPayloads\T1059_003note.txt` — the note file path pattern; in a real attack, substitute with a ransom note file path.
5. Sysmon EID 7 spike from `MpOAV.dll` loads across many process GUIDs in rapid succession — Defender scanning overhead from bulk process creation, visible as an unusual EID 7 volume burst.
6. EID 4688 for `cmd.exe` with `| out-null` piped from a PowerShell context — a common pattern for suppressing console output in automated PowerShell-to-cmd execution.
7. Sysmon EID 10 `GrantedAccess: 0x1FFFFF` from PowerShell to multiple spawned processes — the test framework monitoring the for-loop execution chain.
