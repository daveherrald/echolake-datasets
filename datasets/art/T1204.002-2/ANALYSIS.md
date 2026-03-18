# T1204.002-2: Malicious File — OSTap Payload Download

## Technique Context

T1204.002 (Malicious File) represents user execution of malicious files, a critical initial access and execution vector. This technique encompasses scenarios where users are tricked into opening attachments, downloading files, or executing payloads that appear legitimate. The "OSTap Payload Download" variant specifically emulates the OSTap malware family's method of using JavaScript to download additional payloads from remote sources. Detection engineers focus on identifying suspicious file downloads, script execution patterns, and the process chains that result from user-initiated malicious file execution. This technique is particularly relevant because it represents the human element vulnerability that bypasses many technical controls.

## What This Dataset Contains

This dataset captures a complete OSTap-style payload download simulation executed via PowerShell. The attack chain begins with PowerShell (PID 27344) executing a complex command that creates a JavaScript file and executes it via cscript.exe.

From Security event 4688, we see the full command line that writes a JavaScript downloader: `"cmd.exe" /c echo var url = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt", fso = WScript.CreateObject('Scripting.FileSystemObject'), request, stream; request = WScript.CreateObject('MSXML2.ServerXMLHTTP'); request.open('GET', url, false); request.send(); if (request.status === 200) {stream = WScript.CreateObject('ADODB.Stream'); stream.Open(); stream.Type = 1; stream.Write(request.responseBody); stream.Position = 0; stream.SaveToFile('ostapout.txt', 1); stream.Close();} else {WScript.Quit(1);}WScript.Quit(0); > %TEMP%\OSTapGet.js & cscript //E:Jscript %TEMP%\OSTapGet.js`.

Sysmon captures the complete process chain: PowerShell → cmd.exe (PID 25804) → cscript.exe (PID 24464). The file creation of `C:\Windows\Temp\OSTapGet.js` is captured in Sysmon event 11, and process creation events show cscript.exe executing with `//E:Jscript C:\Windows\TEMP\OSTapGet.js`.

The cscript.exe process loads AMSI (amsi.dll) and Windows Defender components (MpOAV.dll), indicating security product interaction. Notably, cscript.exe exits with status 0x1 (failure), suggesting the download operation was blocked or failed.

## What This Dataset Does Not Contain

The dataset lacks network connection telemetry that would show the actual HTTP request to GitHub, likely because Windows Defender or other security controls blocked the network activity before completion. No Sysmon event 3 (NetworkConnect) events appear for the cscript.exe process.

There's no evidence of the intended output file `ostapout.txt` being created, consistent with the cscript.exe exit code 0x1 indicating failure. The dataset also doesn't contain any DNS resolution events (Sysmon event 22) that would typically accompany the HTTP request attempt.

PowerShell script block logging (event 4104) contains only test framework boilerplate with Set-StrictMode commands rather than the actual malicious script content, indicating the execution was likely wrapped in a test framework rather than containing the raw malicious JavaScript.

## Assessment

This dataset provides excellent telemetry for detecting OSTap-style JavaScript downloaders and the associated process execution chains. The Security 4688 events with full command-line logging capture the complete attack methodology, while Sysmon events provide detailed process relationships and file operations. The combination of cmd.exe writing JavaScript files to temp directories followed by cscript.exe execution represents a high-fidelity detection opportunity.

The failure of the actual download (indicated by the exit code 0x1) doesn't diminish the dataset's value for detection engineering, as the initial execution phases are fully captured. The AMSI and Defender DLL loads in the cscript.exe process show how security products interact with script execution.

## Detection Opportunities Present in This Data

1. **Suspicious JavaScript file creation in temp directories** - Monitor Sysmon event 11 for .js files created in %TEMP% directories by cmd.exe or other shell processes
2. **Cscript execution with JavaScript engine specified** - Alert on Security 4688 or Sysmon event 1 showing cscript.exe with "//E:Jscript" parameters
3. **Command-line detection of MSXML2.ServerXMLHTTP usage** - Parse Security 4688 command lines for references to ServerXMLHTTP and ADODB.Stream objects
4. **Process chain analysis** - Detect PowerShell → cmd.exe → cscript.exe execution chains, especially when cmd.exe creates files in temp directories
5. **Failed script execution correlation** - Correlate cscript.exe process creation with non-zero exit codes (Security 4689) as potential indicators of blocked malicious activity
6. **AMSI integration monitoring** - Track image loads of amsi.dll by script hosts as potential indicators of malicious script examination
7. **Defender component loads** - Monitor for MpOAV.dll loads in script execution processes as evidence of security product inspection
