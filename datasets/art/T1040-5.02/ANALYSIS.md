# T1040-5: Network Sniffing — Windows Internal Packet Capture

## Technique Context

T1040 Network Sniffing involves capturing network traffic to intercept credentials, session tokens, and other sensitive data in transit. Windows provides a built-in packet capture capability through the `netsh trace` command, which leverages the Network Diagnostics Framework (NDF) and the NDIS capture provider to write traffic to Event Trace Log (ETL) files. Unlike third-party tools such as Wireshark or tcpdump, `netsh trace` is a signed Windows binary, making it a Living-off-the-Land approach that avoids introducing external tooling.

This technique is relevant in both credential access and discovery contexts. Attackers with local admin or SYSTEM privileges can capture network authentication handshakes (NTLM, Kerberos), cleartext protocol data, or application-layer credentials. The ETL format can be converted to PCAP using Microsoft Message Analyzer or Network Monitor for offline analysis.

Detection approaches focus on process execution telemetry for `netsh.exe` with trace-related arguments, file creation events for `.etl` and `.cab` files in world-writable paths, registry modifications to the NdisCap service indicating driver enablement, and process ancestry showing netsh launched by PowerShell or cmd.exe rather than interactive shell sessions.

## What This Dataset Contains

This dataset captures a complete, unimpeded execution of `netsh trace start capture=yes tracefile=%temp%\trace.etl maxsize=10` followed by a cleanup sequence stopping the trace and removing artifacts. With Windows Defender disabled, the full execution lifecycle is visible across three channels.

The process chain is captured in both the Security and Sysmon channels. Security EID 4688 events record the process creation sequence: PowerShell (PID 0x10cc) spawns `cmd.exe` (PID 0xe5c) with command line `"cmd.exe" /c netsh trace start capture=yes tracefile=%temp%\trace.etl maxsize=10`, which in turn launches `netsh.exe` (PID 0x18dc) with the expanded command `netsh trace start capture=yes tracefile=C:\Windows\TEMP\trace.etl maxsize=10`. This environment-variable expansion — `%temp%` resolved to `C:\Windows\TEMP` — indicates execution under the SYSTEM account (`ACME-WS06$` as SubjectUserName, SID `S-1-5-18`).

Sysmon EID 1 provides parallel confirmation with the identical command lines and SHA256 hashes: `netsh.exe` hashes as `SHA256=3E91414A1A005937925E449627D4634E73B1DA9DC12D1008B1BAA54C77637C44`. A second complete execution sequence is visible for the cleanup phase, where `cmd.exe` runs `"cmd.exe" /c netsh trace stop >nul 2>&1 & TIMEOUT /T 5 >nul 2>&1 & del %temp%\trace.etl >nul 2>&1 & del %temp%\trace.cab >nul 2>&1`, spawning `netsh trace stop` to terminate capture.

Sysmon EID 11 captures the file creation event for `C:\Windows\Temp\trace.etl` by `netsh.exe`, confirming the capture file was written. This is a high-fidelity indicator: legitimate `netsh.exe` rarely writes `.etl` files to `%TEMP%`.

Sysmon EID 17 records a named pipe creation by PowerShell: `\PSHost.134180033946966093.4300.DefaultAppDomain.powershell`, part of standard PowerShell host process infrastructure.

Sysmon EID 7 image load events show `MpOAV.dll` and `MpClient.dll` from `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\` loading into PowerShell — Windows Defender hooks remain active at the image load level despite being disabled at the behavioral blocking level. `urlmon.dll` also loads into PowerShell, consistent with .NET web request initialization.

Sysmon EID 10 process access events capture PowerShell (PID 0x10cc) accessing `whoami.exe` processes, part of the ART test framework identity verification.

The undefended dataset contains 93 PowerShell EID 4104 script block events (vs. 26 in the defended version), 6 Security EID 4688 events (vs. 16 in the defended version — notably fewer here because the defended run included additional process creation events from Defender blocking attempts and service interactions), and 18 Sysmon events (vs. 22 in the defended version).

## What This Dataset Does Not Contain

Registry modifications to the NdisCap service — which the defended dataset noted and which would document NDIS capture driver enablement — are absent from the Sysmon samples in this dataset. The EID 13 registry events referenced in the defended analysis are not represented in the undefended sample set, though the `netsh trace` execution implies the NdisCap service was configured. Sysmon EID 13 events may exist in the full event stream but are not among the sampled events.

The dataset contains no Sysmon EID 3 network connection events showing actual packet capture activity, nor any ETW events from the Network Diagnostics subsystem indicating trace session statistics. The ETL file creation is confirmed, but whether packets were actively captured before cleanup cannot be determined from this telemetry alone.

The PowerShell channel contains only test framework boilerplate in the 20 sampled events (EID 4104 script blocks for `Set-StrictMode` and error formatting helpers). The actual ART invocation script blocks are present in the full 93-event stream but not in the sample.

## Assessment

This dataset provides strong, clean telemetry for detecting Windows built-in packet capture. The combination of Security 4688 command-line auditing and Sysmon EID 1 ProcessCreate events delivers redundant, corroborating process execution evidence. The file creation event for `trace.etl` (Sysmon EID 11) gives a concrete artifact indicator. The full start-and-stop lifecycle is captured, which is unusual for ART datasets — most only capture the attack action, not the cleanup. This makes it useful for modeling complete attacker workflows.

Compared to the defended dataset (22 Sysmon, 16 Security, 26 PowerShell events), the undefended version shows fewer Security events but more PowerShell events. The Security channel difference is counterintuitive — the defended run likely triggered additional process creation events through Defender intervention. The additional PowerShell EID 4104 events in the undefended run reflect script block logging of test framework initialization without Defender truncating execution.

The dataset is suitable for building and validating detection logic targeting `netsh trace` execution with network capture arguments.

## Detection Opportunities Present in This Data

1. Process creation events (Security EID 4688 or Sysmon EID 1) where `NewProcessName` is `C:\Windows\System32\netsh.exe` and `CommandLine` contains both `trace` and `capture=yes` — this combination is a high-confidence indicator with minimal legitimate use cases.

2. File creation events (Sysmon EID 11) where the creating process is `C:\Windows\system32\netsh.exe` and `TargetFilename` ends in `.etl` — legitimate `netsh trace` diagnostics are rarely written to `%TEMP%` paths.

3. Process ancestry chain: `powershell.exe` → `cmd.exe` → `netsh.exe` with `trace start` in the netsh command line. This spawning pattern is not typical of administrative use, which usually invokes netsh directly.

4. Sysmon EID 11 combined with absence of subsequent EID 11 events deleting the `.etl` file — an attacker who forgets cleanup leaves `trace.etl` and `trace.cab` artifacts that serve as persistent indicators.

5. Security EID 4688 showing `cmd.exe` with a compound command line including both `netsh trace stop` and `del %temp%\trace.etl` — the cleanup sequence itself is a behavioral signature of scripted packet capture rather than interactive administrative use.

6. Sysmon EID 7 showing `urlmon.dll` loading into a PowerShell process that subsequently spawns `netsh.exe` — while not definitive alone, this combination (network DLL load followed by capture tool execution) can contribute to a composite detection.
