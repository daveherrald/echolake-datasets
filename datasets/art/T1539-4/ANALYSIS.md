# T1539-4: Steal Web Session Cookie — Steal Chrome v127+ Cookies via Remote Debugging (Windows)

## Technique Context

Chrome v127 introduced App-Bound Encryption for cookies on Windows, encrypting cookie values using a key tied to the browser's install path and bound to the local machine. This broke traditional infostealer approaches that decrypted cookies using `CryptUnprotectData` directly from the cookie database. The remote debugging approach circumvents App-Bound Encryption by launching Chrome with `--remote-debugging-port` and then using Chrome's DevTools Protocol over a WebSocket to call `Network.getAllCookies` — extracting cookies in their decrypted form as Chrome itself handles the decryption. This technique is actively used by advanced infostealers targeting Chrome v127+ and is considered one of the primary evasion paths for modern cookie theft. Detection focuses on: Chrome launched with `--remote-debugging-port`, WebSocket connections to `localhost:9222`, and `Network.getAllCookies` in command lines or script blocks.

## What This Dataset Contains

The test script is fully captured in PowerShell Event ID 4104 (Script Block Logging) and Security 4688 command-line logging. The script:

1. Kills Chrome (`stop-process -name "chrome"`)
2. Launches Chrome with `--remote-debugging-port=9222 --profile-directory=Default`
3. Queries `http://localhost:9222/json` for the WebSocket debugger URL
4. Connects a `System.Net.WebSockets.ClientWebSocket` to the debugger endpoint
5. Sends `{"id": 1, "method": "Network.getAllCookies"}`
6. Reads the response and extracts cookies

The full script block — including the `Network.getAllCookies` DevTools Protocol method — appears in 4104. Security 4688 records the `powershell.exe` child process with the complete multi-line command in the command line field. PowerShell Event ID 4103 module logging would capture individual cmdlet invocations (`Invoke-WebRequest`, `ConvertFrom-Json`, `Start-Process`) if the script ran to completion.

A PowerShell 4100 (Engine Error) event records the failure: `Start-Process "chrome.exe"` returned `InvalidOperationException: This command cannot be run due to the error: The system cannot find the file specified.` Chrome is not installed on this host, so the technique aborted at step 2.

The dataset spans approximately 2 minutes (23:28:10–23:30:16 UTC) because the `Start-Sleep 10` in the script still executed before the failure path was reached. The PowerShell channel contains 18,240 events — extremely high volume driven by the long-running script session with module logging enabled across the sleep period.

Sysmon Event ID 3 (Network Connection) shows `MsMpEng.exe` connecting outbound to `172.178.160.17:443` — Windows Defender cloud lookups triggered by the technique attempt, not the technique itself.

## What This Dataset Does Not Contain

**No Chrome process.** Chrome is not installed, so there is no `chrome.exe` in process creation logs, no `--remote-debugging-port` process, and no actual WebSocket connection to the debugger.

**No network connection from the script.** The `Invoke-WebRequest` to `localhost:9222` was never reached. No Sysmon Event ID 3 for port 9222 appears.

**No successful cookie extraction.** The 4100 error event confirms Chrome was not found; the technique failed before any cookie access occurred.

**No file write.** The script does not write cookies to disk; exfiltration from this technique is entirely in-memory, so even if Chrome were present, there would be no output file artifact.

## Assessment

Despite the failed execution, this dataset is highly valuable. The complete attack script — including the `Network.getAllCookies` DevTools Protocol call, the WebSocket client setup, and the `--remote-debugging-port` launch argument — is captured in a single 4104 event and in the Security 4688 command line. This provides exact string matches for detection rules targeting the remote debugging approach. The 4100 error event showing the Chrome-not-found failure is also realistic telemetry. The dataset is limited by the absence of Chrome and a successful execution path; a companion dataset with Chrome installed would add process creation for `chrome.exe --remote-debugging-port=9222`, Sysmon network events to `localhost:9222`, and potentially DNS queries.

## Detection Opportunities Present in This Data

1. **PowerShell Event ID 4104**: Script block containing `--remote-debugging-port` and `Network.getAllCookies` — definitive indicator of this specific Chrome cookie theft technique.
2. **PowerShell Event ID 4104**: Script block containing `System.Net.WebSockets.ClientWebSocket` combined with `localhost` and a numeric port — WebSocket-based local debugging client.
3. **Security 4688 / Sysmon Event ID 1**: `powershell.exe` command line containing `remote-debugging-port` — Chrome launched for programmatic cookie access.
4. **PowerShell Event ID 4104**: `stop-process -name "chrome"` followed by `Start-Process "chrome.exe"` with `--remote-debugging-port` argument — kill-and-relaunch with debugging enabled.
5. **PowerShell Event ID 4100**: `InvalidOperationException` from `StartProcessCommand` referencing `chrome` — failed Chrome launch attempt, useful as supporting context.
6. **PowerShell Event ID 4104**: `Invoke-WebRequest "http://localhost:9222/json"` — DevTools endpoint enumeration query.
7. **Sysmon Event ID 3 (if Chrome present)**: Network connection from `chrome.exe` to `127.0.0.1:9222` — self-debugging port open signal.
