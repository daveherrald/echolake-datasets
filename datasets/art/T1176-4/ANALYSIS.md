# T1176-4: Software Extensions — Google Chrome Load Unpacked Extension With Command Line

## Technique Context

T1176 (Browser Extensions) represents a persistence technique where adversaries install malicious browser extensions or leverage legitimate ones to maintain access and execute code within the user's browsing context. This specific test (T1176-4) demonstrates loading an unpacked Chrome extension via command line, simulating how attackers might deploy malicious extensions through automated processes or initial access methods. The technique is particularly valuable for adversaries because browser extensions run with elevated privileges within the browser context, can access web content, intercept network traffic, and persist across browser sessions. Detection teams focus on monitoring browser process command lines for extension loading flags, file system artifacts in extension directories, and network communications from newly loaded extensions.

## What This Dataset Contains

This dataset captures a PowerShell-driven Chrome extension sideloading operation with comprehensive telemetry. The PowerShell script downloads Chromium browser from `commondatastorage.googleapis.com` and uBlock Origin Lite extension from GitHub, extracts both archives to `C:\Windows\Temp\`, and launches Chrome with the `--load-extension` flag: `"C:\Windows\TEMP\chrome-win\chrome.exe" --load-extension=C:\Windows\TEMP\extension\`. 

Security 4688 events capture the complete process chain including the initial PowerShell execution and Chrome launch with the suspicious command line. Sysmon EID 1 events provide additional process creation details with full command line visibility. Network telemetry in Sysmon EID 3 and DNS queries (EID 22) show connections to `commondatastorage.googleapis.com` (142.250.72.219), `github.com` (140.82.114.4), and `release-assets.githubusercontent.com` (185.199.111.133). 

Extensive file creation events (Sysmon EID 11) document the extraction of the Chromium browser binary and all extension files to the Windows temp directory. Sysmon EID 29 events capture executable file creation for Chrome binaries. PowerShell script block logging (EID 4104) preserves the complete attack script showing the download URLs, extraction logic, and Chrome execution with extension loading parameters.

## What This Dataset Does Not Container

The dataset lacks browser-specific telemetry that would typically accompany extension loading in a production environment. There are no Windows Event Log entries for extension registration, Chrome-specific registry modifications, or browser profile changes. The extension loading appears to complete successfully based on the Chrome process creation, but there's no evidence of the extension actually executing JavaScript code, making network requests, or interacting with web content. 

Post-execution persistence mechanisms are not captured - the technique loads the extension for the current session only without installing it permanently. The dataset also doesn't contain evidence of the extension accessing browser APIs, reading stored credentials, or performing other extension-based malicious activities that would occur after successful loading.

## Assessment

This dataset provides excellent coverage for detecting the initial stages of malicious browser extension deployment via command line. The PowerShell script block logging captures the complete attack methodology, while process creation events clearly show the suspicious Chrome command line with extension loading parameters. The network and file creation telemetry provides strong indicators for behavioral detection rules. 

However, the dataset is limited for understanding the full attack lifecycle since it only captures the deployment phase without subsequent extension execution or malicious activities. The lack of browser-internal telemetry means detection teams cannot observe extension registration, permission requests, or runtime behaviors that would be critical for comprehensive detection coverage.

## Detection Opportunities Present in This Data

1. **Chrome Extension Loading Command Line** - Monitor Security 4688 and Sysmon EID 1 for chrome.exe processes with `--load-extension` parameter, particularly from non-standard locations like `%TEMP%`

2. **PowerShell Extension Deployment Scripts** - Detect PowerShell EID 4104 script blocks containing browser extension download/extraction logic combined with browser process execution

3. **Suspicious Browser Binary Downloads** - Alert on network connections to `commondatastorage.googleapis.com` for Chromium downloads, especially when followed by local execution

4. **Temporary Directory Extension Staging** - Monitor Sysmon EID 11 file creation events for browser extension artifacts (manifest.json, JS files) in temporary directories

5. **Browser Process Ancestry** - Identify chrome.exe processes launched by PowerShell or other automation tools rather than normal user interaction

6. **Extension Archive Downloads** - Correlate web requests for .zip files from extension repositories (GitHub releases) with subsequent local extraction and browser execution

7. **Bulk Extension File Creation** - Detect rapid creation of multiple web extension files (_locales directories, CSS, JS, manifest files) in non-standard locations
