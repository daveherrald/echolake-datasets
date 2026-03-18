# T1133-1: External Remote Services — Running Chrome VPN Extensions via the Registry 2 vpn extension

## Technique Context

T1133 External Remote Services involves attackers gaining access to systems through legitimate remote access mechanisms like VPNs, terminal services, or cloud infrastructure. While the detection community typically focuses on anomalous authentication patterns, unusual source locations, or compromised credentials, this specific test demonstrates a more subtle approach: using registry modifications to force Chrome to load VPN browser extensions that could establish covert tunnels.

Browser-based VPNs represent an increasingly common attack vector where malicious extensions can proxy traffic, exfiltrate data, or provide persistent access channels. The technique leverages Chrome's extension policy mechanism (`HKLM:\Software\Wow6432Node\Google\Chrome\Extensions`) to force-install extensions without user interaction. The extensions referenced in this test (`fcfhplploccackoneaefokcmbjfbkenj` and `fdcgdnkidjaadafnichfpabhfomcebme`) appear to be VPN-related based on the test's naming, though the actual extension behavior depends on what Chrome would download from the Chrome Web Store.

## What This Dataset Contains

The dataset captures a PowerShell-based attempt to install Chrome VPN extensions through registry manipulation, though the technique ultimately fails because Chrome is not installed on the test system.

**Registry Modification Activity:**
- PowerShell EID 4103/4104 events show creation of registry keys: `New-Item -Path HKLM:\Software\Wow6432Node\Google\Chrome\Extensions\fcfhplploccackoneaefokcmbjfbkenj -Force` and `New-Item -Path HKLM:\Software\Wow6432Node\Google\Chrome\Extensions\fdcgdnkidjaadafnichfpabhfomcebme -Force`
- Registry value creation: `New-ItemProperty -Path "HKLM:\Software\Wow6432Node\Google\Chrome\Extensions\$extension" -Name "update_url" -Value "https://clients2.google.com/service/update2/crx" -PropertyType "String" -Force`

**Process Execution Chain:**
- Security EID 4688 shows the main PowerShell process (PID 20080) with command line containing the full script
- Sysmon EID 1 captures the same PowerShell execution with detailed hashes and parent process information
- The script attempts to start Chrome with `Start chrome`, but fails with "The system cannot find the file specified" (PowerShell EID 4100)

**Network Infrastructure Reference:**
The update URL `https://clients2.google.com/service/update2/crx` is Chrome's legitimate extension update service, making this technique blend with normal Chrome extension management traffic.

## What This Dataset Does Not Contain

The dataset lacks several critical elements that would make this technique fully observable:

**No Actual Chrome Installation:** The test fails because Chrome is not installed on the system, so we don't see the extensions actually being loaded or network connections being established. This means no Sysmon EID 3 (network connections) to the Chrome Web Store or VPN endpoints.

**No Registry Modification Events:** Despite PowerShell showing registry operations, there are no Sysmon EID 13 (registry value set) events, likely because the sysmon-modular configuration doesn't monitor the specific Chrome extension registry keys.

**No Extension Download Activity:** Since Chrome isn't present, there's no attempt to download the actual extension files, missing potential network artifacts and file creation events.

**No Browser Process Telemetry:** We lose visibility into Chrome's process spawning, memory allocation, or extension loading that would occur if the attack succeeded.

## Assessment

This dataset provides moderate value for detection engineering focused on the initial registry manipulation phase of browser-based external access techniques. The PowerShell logging is excellent, capturing both the command invocation (EID 4103) and script block content (EID 4104) with full parameter details. The Security audit events (EID 4688) provide complementary process creation visibility with command lines.

However, the dataset's utility is significantly limited by the failed execution. For comprehensive detection development, analysts would need additional data showing successful Chrome extension installation, the resulting network connections, and browser behavior. The registry modification approach itself is valuable to detect, but the full attack chain remains incomplete in this capture.

The combination of PowerShell script block logging and Security audit events provides strong detection opportunities for the preparatory phase of this technique, even when the final payload fails to execute.

## Detection Opportunities Present in This Data

1. **Chrome Extension Registry Manipulation**: PowerShell commands creating keys under `HKLM:\Software\Wow6432Node\Google\Chrome\Extensions\` with specific extension IDs, particularly when combined with `update_url` values pointing to Chrome Web Store infrastructure.

2. **Suspicious Extension ID Patterns**: Monitor for hardcoded Chrome extension IDs (`fcfhplploccackoneaefokcmbjfbkenj`, `fdcgdnkidjaadafnichfpabhfomcebme`) being written to registry, especially from elevated PowerShell processes.

3. **Administrative PowerShell Registry Operations**: Security EID 4688 and PowerShell EID 4103 showing `New-Item` and `New-ItemProperty` cmdlets targeting browser extension paths from SYSTEM context.

4. **Browser Automation Attempts**: PowerShell scripts that combine registry modification with browser process launching (`Start chrome`) may indicate automated extension deployment.

5. **Chrome Web Store Update URL References**: Scripts or commands referencing `https://clients2.google.com/service/update2/crx` in conjunction with registry operations could indicate extension force-installation attempts.

6. **Failed Browser Execution Patterns**: PowerShell errors like "The system cannot find the file specified" when attempting to launch browsers after registry modification may indicate attack attempts on systems missing target applications.
