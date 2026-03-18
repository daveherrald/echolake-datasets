# T1559.002-2: Dynamic Data Exchange — Execute PowerShell Script via Word DDE

## Technique Context

T1559.002 covers Dynamic Data Exchange (DDE) as an execution mechanism. DDE is a legacy Windows IPC protocol originally designed for inter-application data sharing. Adversaries abuse DDE fields embedded in Microsoft Office documents to execute arbitrary commands when the document is opened — without requiring macros. The technique gained significant attention in 2017 and was widely exploited in phishing campaigns. Microsoft added warnings and eventually disabled automatic DDE execution in Office by default. Test 2 specifically abuses Word DDE to launch a PowerShell script.

## What This Dataset Contains

The dataset spans just over 2 minutes (01:16:13–01:18:16 UTC) across 29 Sysmon events, 21 Security events, 32 PowerShell events, 1 WMI event, and 1 System event — the broadest event source coverage of any dataset in this series.

The ART test framework opens a pre-built DDE document:
```
"cmd.exe" /c start "C:\AtomicRedTeam\atomics\T1559.002\bin\DDE_Document.docx"
```

This launches `cmd.exe` as a child of the test framework `powershell.exe` (Security 4688), which in turn spawns a second `cmd.exe` (`cmd.exe ` with no arguments, created as a child of the first). The Sysmon EID 1 records confirm the execution chain: `powershell.exe` → `cmd.exe /c start DDE_Document.docx` → `cmd.exe `. The 40-second delay before WMI activity (WmiPrvSE.exe spawning at 01:16:57) reflects the time for Word to load and process the DDE fields.

Security events include 4624 (logon type 5 — service logon for WMI), 4627 (group membership), and 4672 (special privileges assigned to SYSTEM), reflecting the WMI Provider Host initialization. The WMI EID 5858 records a failed `ExecNotificationQuery` for `Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` — an ART test checking for WinRM host startup, with result code `0x80041032` (query cancelled).

The System EID 7040 records the Background Intelligent Transfer Service (BITS) start type changing from automatic to demand start — unrelated OS activity captured in the collection window due to the 2-minute duration.

The Sysmon EID 17 at 01:18:16 captures a `\PSHost.*` pipe created by the ART test framework cleanup PowerShell instance.

## What This Dataset Does Not Contain (and Why)

Word (WINWORD.EXE) itself does not appear in the telemetry. The Sysmon ProcessCreate filter uses include-mode rules targeting known suspicious patterns; `WINWORD.EXE` is not in the filter, and the Security 4688 audit policy would capture it if a process was created, but Word may have been blocked from launching by Defender before creating a Security-auditable process. Alternatively, Word's process creation was captured at a lower level by Defender and the DDE field was not executed.

No PowerShell payload execution from Word is visible. The DDE field in the document is supposed to embed a PowerShell command that executes when the document opens. The absence of any PowerShell script block logging content related to the intended payload (only boilerplate test framework content appears in PS 4104) suggests Defender or Word's Protected View blocked the DDE execution before the embedded command ran.

No network connections appear. The intended DDE payload likely included a download or callback; none occurred.

The Sysmon ProcessCreate filter excluded WINWORD.EXE. Security 4688 captures `cmd.exe`, `whoami.exe`, and `WmiPrvSE.exe`, but not Word itself, suggesting Word's creation was either blocked or fell outside the collection window cleanly.

## Assessment

This dataset captures the *attempt* to exploit DDE in a Word document under active Defender protection. The key telemetry is the `cmd.exe /c start DDE_Document.docx` command chain, the WmiPrvSE.exe startup (reflecting background WMI activity triggered by the test environment), and the WMI query failure. The intended DDE-triggered PowerShell payload never executed. The 2-minute window and multi-source event coverage make this a richer dataset than the pipe tests despite the block outcome.

## Detection Opportunities Present in This Data

- **Security 4688**: `cmd.exe /c start *.docx` from a SYSTEM `powershell.exe` parent; opening a Word document via `cmd.exe /c start` from a non-interactive SYSTEM context is highly anomalous.
- **Sysmon EID 1**: `cmd.exe` spawning a child `cmd.exe` with no arguments; an empty `cmd.exe ` child is unusual and may reflect the DDE field's execution stub.
- **Security 4624/4672**: Service-type logon by SYSTEM with full privilege set in close temporal proximity to document opening.
- **WMI EID 5858**: `ExecNotificationQuery` for `Win32_ProcessStartTrace` watching for `wsmprovhost.exe`; this specific WMI subscription pattern is an ART test framework artifact but resembles legitimate offensive WMI use.
- **Sysmon EID 1**: `WmiPrvSE.exe -Embedding` spawning under `NT AUTHORITY\NETWORK SERVICE`; WMI Provider Host initialization in a non-server context during a file-opening operation is worth investigating.
- **System EID 7040**: BITS service start-type change in the collection window; while likely unrelated, BITS manipulation is a known exfiltration technique (T1197) and the coincidence of timing warrants attention in a real investigation.
