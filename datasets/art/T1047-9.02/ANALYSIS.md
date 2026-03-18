# T1047-9: Windows Management Instrumentation — WMI Execute rundll32

## Technique Context

T1047 Windows Management Instrumentation describes adversary use of WMI's process creation facilities to execute arbitrary commands, either locally or remotely. WMI's `Win32_Process.Create()` method — invoked via `wmic` or directly through WMI COM interfaces — creates processes that appear to originate from the WMI service (`WmiPrvSE.exe`) rather than from the attacker's process, providing a degree of process ancestry obfuscation. Combined with `rundll32.exe`, which loads and executes exported functions from arbitrary DLL files, this technique enables code execution through two legitimate-looking Windows components.

This specific test executes: `wmic /node:127.0.0.1 process call create "rundll32.exe \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\calc.dll\" StartW"`. The payload DLL (`calc.dll`) with export `StartW` is a common ART simulation payload that launches the calculator application as a proxy for arbitrary shellcode. The combination of WMI process creation with rundll32 DLL loading represents a Living-off-the-Land pattern used by numerous threat actors including APT29, FIN7, and various ransomware operators.

Detection focuses on `wmic process call create` command lines, `rundll32.exe` executions with non-standard DLL paths (particularly paths outside `System32` or `SysWow64`), process creation events where the parent is `WmiPrvSE.exe`, and the specific `/node:` flag in wmic invocations.

## What This Dataset Contains

With Defender disabled, the WMI execution chain ran and the payload was loaded. The telemetry documents a more complete execution than the defended version, where Defender blocked execution and `cmd.exe` exited with `STATUS_ACCESS_DENIED`.

Security EID 4688 captures the key command sequences. The WMI invocation is visible: `"cmd.exe" /c wmic /node:127.0.0.1 process call create "rundll32.exe \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\calc.dll\" StartW"`. The cleanup sequence is also captured: `"cmd.exe" /c taskkill /f /im calculator.exe` and the corresponding `taskkill /f /im calculator.exe` process. The presence of the `taskkill` cleanup is a strong indicator that the payload executed successfully — `calculator.exe` ran and needed to be terminated.

Sysmon EID 1 confirms the process creation chain: `cmd.exe` spawned from `powershell.exe` for both the wmic invocation and the cleanup, plus `taskkill.exe` spawned from `cmd.exe`.

The most distinctive event in this dataset is Sysmon EID 8 (CreateRemoteThread), tagged by Sysmon with `RuleName: technique_id=T1055,technique_name=Process Injection`. This event records PowerShell (PID 5164, running as `NT AUTHORITY\SYSTEM`) injecting a thread into an unknown process (PID 6500, `<unknown process>`) at start address `0x00007FF7F015F8F0`. The target process is listed as `<unknown process>`, which indicates the target process had already terminated by the time Sysmon resolved it. This CreateRemoteThread event was absent in the defended dataset — Defender blocked execution before this injection activity occurred.

The Application channel EID 15 event again shows `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`, consistent with the test environment's Defender management cycle.

The Sysmon channel includes 1 EID 11 file creation event, likely `calc.dll` or a related artifact being written or accessed. The full dataset has 20 Sysmon events versus 25 in the defended version — fewer events in the undefended run is explained by the defended run generating additional events from Defender's intervention processes (MsMpEng.exe activity, quarantine operations).

## What This Dataset Does Not Contain

No `wmic.exe` or `rundll32.exe` process creation events appear in the Sysmon or Security samples. This is unexpected — the wmic command line is visible in the `cmd.exe` creation event, but the subsequent `wmic.exe` and `rundll32.exe` processes are not in the sampled events. The total of only 4 Sysmon EID 1 events (2x whoami.exe, 1x cmd.exe for wmic invocation, 1x cmd.exe for taskkill) suggests either the sample selection excluded these, or wmic.exe was filtered by the Sysmon configuration. The full event stream should contain wmic.exe process creation.

`WmiPrvSE.exe` process creation, which would appear as the parent of the rundll32 execution when WMI creates processes via `Win32_Process.Create()`, is not present in the samples. The WMI-created process lineage — a key indicator for this technique — may be in the full dataset but is not represented in the samples.

No WMI-Activity/Operational log events appear (this channel is not included in the monitored set). WMI provider host events would document the WMI query execution at the service layer.

## Assessment

This dataset adds meaningful telemetry over the defended version in two ways: the CreateRemoteThread (EID 8) event documenting process injection activity that Defender prevented in the defended run, and the `taskkill /f /im calculator.exe` cleanup sequence confirming payload execution success. The EID 8 event is particularly valuable — it documents a secondary technique (T1055 Process Injection) triggered by the WMI execution workflow, likely from the ART test framework or rundll32 payload interacting with PowerShell process space.

The defended dataset's primary value was the `cmd.exe` exit code `0xC0000022` (STATUS_ACCESS_DENIED) proving Defender blocked execution. The undefended dataset's value is demonstrating what the blocked execution would have produced: a complete WMI invocation, payload execution (calc.exe ran and needed cleanup), and associated injection activity.

## Detection Opportunities Present in This Data

1. Security EID 4688 showing `cmd.exe` with a `CommandLine` containing `wmic` combined with `/node:` and `process call create` followed by `rundll32.exe` with a non-System32 DLL path — this precisely captures the WMI-spawn-rundll32 pattern.

2. Security EID 4688 for `taskkill.exe` with `/im calculator.exe` (or any payload process name) following a `wmic process call create` invocation — the cleanup sequence confirms payload success.

3. Sysmon EID 8 (CreateRemoteThread) where `TargetImage` is `<unknown process>` or a legitimate Windows process and `SourceImage` is `powershell.exe` or a script interpreter — thread injection from script hosts into other processes is a high-confidence indicator.

4. Sysmon EID 8 events with `RuleName: technique_id=T1055` from Sysmon's built-in rule matching — Sysmon's own tagging identifies process injection even when the target process has already exited.

5. Security EID 4688 for `wmic.exe` (when present) with `CommandLine` containing `process call create` regardless of the payload — `wmic process call create` is used almost exclusively for malicious or advanced administrative purposes.

6. Process ancestry showing a process (rundll32, calculator, or any payload) with parent `WmiPrvSE.exe` — WMI-spawned processes inherit WmiPrvSE as parent, which is unusual for most legitimate operations and a strong lateral movement indicator.

7. Sysmon EID 1 for `rundll32.exe` where `Image` path contains a non-standard directory (outside `C:\Windows\System32\`, `C:\Windows\SysWow64\`) — rundll32 loading DLLs from `AtomicRedTeam`, `Users`, `Temp`, or similar paths is anomalous.
