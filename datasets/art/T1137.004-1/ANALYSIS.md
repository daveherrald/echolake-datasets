# T1137.004-1: Outlook Home Page — Install Outlook Home Page Persistence

## Technique Context

T1137.004 (Outlook Home Page) is a persistence mechanism that leverages Microsoft Outlook's WebView functionality to execute malicious content when users open specific folders. Attackers modify registry keys under `HKCU\Software\Microsoft\Office\<version>\Outlook\WebView\<folder>` to specify custom HTML files or URLs that get loaded automatically. This technique is particularly effective because it triggers without user interaction beyond normal Outlook usage and can persist across system reboots.

The detection community focuses on monitoring registry modifications to Outlook WebView keys, unusual file:// URLs pointing to suspicious locations, and the creation of custom HTML files in unexpected directories. This technique has been observed in APT campaigns and commodity malware targeting corporate environments where Outlook is prevalent.

## What This Dataset Contains

This dataset captures a successful T1137.004 implementation through the following process chain:

1. **Initial PowerShell execution** — Two PowerShell processes (PIDs 20872, 30340) handle the test framework
2. **Registry modification via cmd/reg.exe** — The technique executes: `"cmd.exe" /c reg.exe add HKCU\Software\Microsoft\Office\16\Outlook\WebView\Inbox /v URL /t REG_SZ /d file://C:\AtomicRedTeam\atomics\T1137.004\src\T1137.004.html /f`
3. **Critical registry write** — Sysmon EID 13 captures the registry modification: `HKU\.DEFAULT\Software\Microsoft\Office\16\Outlook\WebView\Inbox\URL` with value `file://C:\AtomicRedTeam\atomics\T1137.004\src\T1137.004.html`

The Security channel provides complete process creation telemetry (EID 4688) showing the full command line for both cmd.exe and reg.exe. Sysmon captures the reg.exe process creation (EID 1) and the crucial registry value set (EID 13) that implements the persistence mechanism. The PowerShell channel contains only test framework boilerplate.

## What This Dataset Does Not Contain

The dataset lacks several elements that would strengthen T1137.004 analysis:

- **File creation events** — No Sysmon EID 11 events show the creation of the malicious HTML file at `C:\AtomicRedTeam\atomics\T1137.004\src\T1137.004.html`
- **Outlook execution** — The test doesn't include actual Outlook launching or triggering the WebView content
- **Network connections** — If the HTML file contained external references, no network telemetry is captured
- **HTML content analysis** — The actual malicious payload content isn't visible in the logs

This is expected behavior since the test only installs the persistence mechanism without triggering it or creating the referenced HTML file.

## Assessment

This dataset provides excellent detection engineering value for T1137.004. The Sysmon EID 13 registry modification event is the gold standard for detecting this technique, capturing both the exact registry key and the suspicious file:// URL value. The Security channel's process creation events with command-line logging provide additional context and alternate detection paths.

The process chain (powershell.exe → cmd.exe → reg.exe) is clearly documented, and the registry key path follows the known T1137.004 pattern precisely. The dataset would be stronger with file creation events for the HTML payload, but the core persistence installation is comprehensively captured.

## Detection Opportunities Present in This Data

1. **Registry key monitoring** — Alert on Sysmon EID 13 modifications to registry paths matching `*\Software\Microsoft\Office\*\Outlook\WebView\*\URL`

2. **Suspicious file:// URL values** — Detect registry writes where the Details field contains `file://` URLs pointing to unusual locations outside standard Office directories

3. **reg.exe command-line patterns** — Monitor Security EID 4688 for reg.exe executions with command lines containing "Office", "Outlook", "WebView", and "URL" keywords

4. **Process chain analysis** — Alert on cmd.exe spawning reg.exe with Outlook-related registry modifications, especially when the parent is PowerShell or other scripting engines

5. **Office version enumeration** — Track registry modifications targeting specific Office versions (like "Office\16" in this case) to identify version-specific targeting

6. **Persistence mechanism installation** — Combine registry monitoring with process telemetry to detect the complete installation of Outlook WebView persistence
