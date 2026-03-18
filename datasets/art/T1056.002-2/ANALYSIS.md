# T1056.002-2: GUI Input Capture — PowerShell - Prompt User for Password

## Technique Context

T1056.002 GUI Input Capture represents a form of credential access where adversaries present fake authentication dialogs to users to steal credentials. This technique differs from keylogging in that it actively prompts users rather than passively capturing keystrokes. Attackers commonly use this method in phishing campaigns, social engineering attacks, and as part of post-exploitation credential harvesting operations.

The technique is particularly effective because it leverages the user's trust in legitimate-looking system prompts. PowerShell's `PromptForCredential` method is frequently abused for this purpose, as it creates authentic Windows credential dialogs that are difficult for users to distinguish from legitimate system requests. Detection engineers focus on identifying suspicious PowerShell credential prompt activity, unusual GUI dialog creation, and processes that shouldn't normally request user credentials.

## What This Dataset Contains

This dataset captures a PowerShell-based credential prompt attack that uses the `$host.UI.PromptForCredential()` method to display a fake "Windows Security Update" dialog. The key evidence includes:

**PowerShell Script Block Logging (EID 4104):** Two critical script blocks capture the actual attack payload:
- `$cred = $host.UI.PromptForCredential('Windows Security Update', '',[Environment]::UserName, [Environment]::UserDomainName)`
- `write-warning $cred.GetNetworkCredential().Password`

**Process Creation (Security EID 4688 and Sysmon EID 1):** Shows the PowerShell process spawning with the full command line containing the credential prompt script: `"powershell.exe" & {# Creates GUI to prompt for password. Expect long pause before prompt is available. $cred = $host.UI.PromptForCredential('Windows Security Update', '',[Environment]::UserName, [Environment]::UserDomainName)...}`

**Process Activity:** The dataset shows the parent-child relationship where the initial PowerShell process (PID 40388) launches another PowerShell instance (PID 18692) to execute the credential prompt, followed by a `whoami.exe` execution (PID 41240) to gather system context.

**PowerShell Module Logging (EID 4103):** Captures `Set-ExecutionPolicy` bypass commands that prepare the environment for script execution.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide a complete picture of this attack:

**User Interaction Evidence:** There's no indication whether a user actually responded to the credential prompt or what credentials might have been entered. The technique creates the dialog but we don't see the user's response or the harvested credentials being transmitted or stored.

**GUI Creation Events:** Windows doesn't generate specific event logs when credential dialogs are displayed, so there's no direct evidence of the fake dialog's appearance to the user.

**Network Activity:** If harvested credentials were exfiltrated, there's no network connection evidence from the PowerShell processes themselves (only unrelated mDNS traffic from svchost.exe).

**Process Termination Context:** While we see process exit events (EID 4689), there's no clear indication of whether the credential prompt completed successfully or was cancelled by the user.

## Assessment

This dataset provides excellent detection opportunities for PowerShell-based credential harvesting attempts. The combination of Security audit logs with command-line logging and PowerShell script block logging creates multiple detection vectors. The Security channel's process creation events capture the complete command line, while PowerShell operational logs reveal the exact script content and method calls.

The data quality is strong for building behavioral detections around suspicious credential prompts, though it doesn't capture the user experience or success/failure of the social engineering attempt. For detection engineering purposes, this limitation is less critical since the malicious intent is clear from the process and script evidence.

## Detection Opportunities Present in This Data

1. **PowerShell PromptForCredential Usage** - Monitor PowerShell script blocks (EID 4104) containing `PromptForCredential` method calls, especially when combined with suspicious dialog titles like "Windows Security Update"

2. **Credential Extraction Methods** - Detect PowerShell scripts using `GetNetworkCredential().Password` to extract plaintext passwords from credential objects

3. **Suspicious PowerShell Command Lines** - Alert on process creation (EID 4688/1) where powershell.exe is launched with embedded credential prompt scripts in the command line

4. **PowerShell Execution Policy Bypass** - Monitor for `Set-ExecutionPolicy Bypass` commands (EID 4103) followed by credential-related PowerShell activity

5. **Process Chain Analysis** - Identify PowerShell processes spawning child PowerShell instances with credential harvesting scripts, potentially indicating staged execution

6. **Fake System Dialog Detection** - Look for PromptForCredential calls with titles mimicking legitimate system processes or updates that wouldn't normally prompt for credentials

7. **Credential Prompt Context Anomalies** - Alert when credential prompts occur from processes running as SYSTEM or in unexpected execution contexts where user interaction wouldn't be normal
