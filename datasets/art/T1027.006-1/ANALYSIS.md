# T1027.006-1: HTML Smuggling — HTML Smuggling Remote Payload

## Technique Context

HTML Smuggling (T1027.006) is a defense evasion technique where attackers embed malicious payloads within HTML/JavaScript that execute client-side to deliver files or code while bypassing perimeter security controls. Traditional email security and web filters struggle to detect malicious content embedded within legitimate HTML, as the payload is constructed and "smuggled" through standard web protocols. Attackers commonly use this technique in phishing campaigns, embedding JavaScript that builds executables or scripts in the browser's memory before writing them to disk. The detection community focuses on monitoring for suspicious file creation patterns, unusual JavaScript execution, and process chains involving HTML files being executed by system processes or browsers.

## What This Dataset Contains

This dataset captures an Atomic Red Team test executing an HTML file containing smuggled payload content. The key evidence shows:

**Process Chain:** The test executes via PowerShell (PID 6516) spawning a child PowerShell process (PID 7788) with the command line `"powershell.exe" & {& "C:\AtomicRedTeam\atomics\T1027.006\bin\T1027_006_remote.html"}`, demonstrating direct HTML file execution through PowerShell.

**PowerShell Script Block Logging:** EID 4104 events capture the execution command: `& {& "C:\AtomicRedTeam\atomics\T1027.006\bin\T1027_006_remote.html"}` showing PowerShell being used to execute an HTML file directly.

**Process Access Events:** Sysmon EID 10 shows the parent PowerShell process accessing both whoami.exe (PID 6628) and the child PowerShell process (PID 7788) with full access rights (0x1FFFFF), indicating process interaction typical of payload execution.

**System Discovery:** The technique includes a whoami.exe execution (captured in Sysmon EID 1 and Security EID 4688), commonly used by attackers for initial system reconnaissance after payload delivery.

**URL Monitoring DLL Loading:** Sysmon EID 7 shows urlmon.dll being loaded into the PowerShell process, which is significant as this DLL handles URL parsing and web content processing - consistent with HTML content being processed.

## What This Dataset Does Not Contain

**No Browser Activity:** The HTML file is executed directly via PowerShell rather than through a browser, so there are no browser process artifacts, DOM manipulation events, or typical client-side JavaScript execution telemetry.

**No Network Connections:** Despite being labeled as "remote payload," no Sysmon network connection events (EID 3) are present, suggesting the HTML file may contain embedded content rather than fetching remote resources.

**No File Drops:** Sysmon EID 11 shows only PowerShell profile files being created, not suspicious executable or script files typically associated with HTML smuggling payload delivery.

**No Web Content Artifacts:** The dataset lacks evidence of typical HTML smuggling indicators like suspicious blob URLs, JavaScript-generated files, or browser download events since the execution bypassed browser-based delivery mechanisms.

## Assessment

This dataset provides limited value for detecting real-world HTML smuggling attacks. The test executes an HTML file directly through PowerShell rather than simulating the typical attack vector where users receive HTML content through email or web browsing that then executes malicious JavaScript to deliver payloads. The telemetry captures PowerShell execution patterns and basic system discovery but misses the core HTML smuggling behaviors like JavaScript payload construction, client-side file generation, or browser-based delivery mechanisms. For building HTML smuggling detections, datasets showing browser-based execution, JavaScript activity, suspicious file creation from web content, or email-delivered HTML would be more valuable.

## Detection Opportunities Present in This Data

1. **HTML File Execution via PowerShell** - Monitor for PowerShell processes executing HTML files directly through command lines containing `.html` file extensions with execution operators (`&`)

2. **PowerShell Script Block Analysis** - Alert on PowerShell script blocks (EID 4104) containing commands that execute HTML files, particularly with patterns like `& "*.html"`

3. **Suspicious Process Access Patterns** - Detect when PowerShell processes access multiple child processes with full access rights (0x1FFFFF), especially when combined with system discovery tools

4. **URL Monitoring DLL in Non-Browser Contexts** - Flag urlmon.dll loading into processes like PowerShell that don't typically handle web content

5. **System Discovery After HTML Execution** - Correlate HTML file execution events with immediate system discovery commands like whoami.exe to identify post-exploitation reconnaissance

6. **PowerShell Parent-Child Execution Chains** - Monitor for PowerShell spawning child PowerShell processes with HTML file references in the command line, indicating potential payload staging
