# T1564.003-2: Hidden Window — Headless Browser Accessing Mockbin

## Technique Context

T1564.003 (Hidden Window) covers techniques that suppress visible UI to avoid alerting an interactive user. This test exercises a specific browser-based variant: launching Google Chrome in headless mode (`--headless --disable-gpu`) to make an outbound HTTP request without a browser window appearing on the desktop. Real-world adversaries use headless browsers to exfiltrate data, beacon to C2, or download payloads while evading casual observation. The technique is notable because it repurposes a fully legitimate, signed binary — the installed browser — for covert network activity.

## What This Dataset Contains

The test executes:
```
cmd.exe /c start "" chrome --headless --disable-gpu https://mockbin.org/bin/f6b9a876-a826-4ac0-83b8-639d6ad516ec
```

**Security log (4688)** records two process creations: `whoami.exe` (ART prerequisite check) and `cmd.exe` with the full headless chrome command. `cmd.exe` exits with status `0x0` — the `start ""` invocation is fire-and-forget, so cmd exits as soon as the browser process is handed to the OS.

**Sysmon EID 1** captures the same two processes with full hashes and parent chain. The parent is `powershell.exe` (the ART test framework), giving a clear `powershell.exe` → `cmd.exe` → `start chrome.exe` lineage visible in the command-line field.

**PowerShell 4104** script block logging captures the ART test framework boilerplate (Set-ExecutionPolicy Bypass, per-process scope) and the outer invocation that dispatched the command. This is standard across all ART tests run by this test framework.

**System EID 7040** records a BITS service start-type change (auto → demand). This is unrelated to the test and reflects OS background activity during the test window.

**WMI EID 5858** records a failed `ExecNotificationQuery` for `Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` (result code `0x80041032` = WBEM_E_TIMED_OUT). This is a WMI operational noise event from the ART execution environment, not part of the technique.

Chrome's actual network connection to mockbin.org is not captured in this dataset (see below), but the 81-second test window (14:22:43–14:24:04) reflects the wait time for Chrome to complete the headless request before cleanup.

## What This Dataset Does Not Contain (and Why)

No Sysmon EID 3 (network connection) event for `chrome.exe` or any browser process appears in this dataset. The Sysmon configuration collects network connection events, but Chrome's headless request may have completed during the collection window gap, or Chrome may have used an already-established socket. No `chrome.exe` process creation appears in the Security log because `start ""` creates the process outside the cmd.exe chain — Chrome is launched as a detached process and its 4688 event occurred outside the per-test collection window, or Chrome was not present on this host and the command failed silently.

No DNS query (Sysmon EID 22) appears for mockbin.org. This is consistent with Chrome operating headlessly without invoking the standard DNS resolution path captured by the Sysmon DNS query event, or with a resolution cache hit.

The actual HTTP response from mockbin.org is not captured. Neither Sysmon nor Windows event logs record HTTP response bodies.

## Assessment

The dataset documents the dispatch of a headless-browser command with full fidelity. The command line is preserved in both Security 4688 and Sysmon EID 1. However, Chrome itself does not appear in either process-creation or network log, which limits the dataset's utility for detecting the browser-side behavior. The test framework-side telemetry (the PowerShell and cmd.exe chain) is complete and well-suited for detecting adversary use of this technique at the launch stage.

## Detection Opportunities Present in This Data

- **4688 / Sysmon EID 1 command line**: `--headless` in a `chrome.exe` or browser invocation is a high-confidence indicator of hidden-window browser abuse, particularly when spawned by a scripting engine.
- **`powershell.exe` → `cmd.exe` → `start ... chrome --headless`**: this process lineage is anomalous in normal enterprise desktop environments and should be prioritized for investigation.
- **`--disable-gpu` combined with `--headless`**: this specific flag combination is characteristic of automated headless browser use and rarely appears in legitimate user-driven browser activity.
- **Outbound connection from a browser spawned by a non-browser parent**: even without the Chrome 4688 event, any Sysmon EID 3 showing `chrome.exe` with a parent of `cmd.exe` or a scripting engine would be a strong detection candidate.
- **WMI 5858 `ExecNotificationQuery` failure**: while a background noise event in this dataset, monitoring for WMI process-watch queries targeting `wsmprovhost.exe` can surface lateral movement or remote execution activity in other contexts.
