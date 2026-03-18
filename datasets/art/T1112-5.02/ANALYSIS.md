# T1112-5: Modify Registry — Add Domain to Trusted Sites Zone

## Technique Context

T1112 (Modify Registry) applied to Internet Explorer's Zone Map is a defense evasion technique that manipulates browser security zones to allow attacker-controlled domains to bypass Internet Explorer's security restrictions. By adding a domain to the Trusted Sites zone (Zone 2) through the registry path `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\`, an attacker can cause Internet Explorer and legacy Windows components that rely on IE's security model (including some .NET WebClient components and certain Windows dialog handlers) to treat the attacker's domain as trusted, suppressing security warnings and enabling active content execution.

Zone 2 (Trusted Sites) applies relaxed security settings: scripts run without prompts, ActiveX loads without confirmation, automatic downloads proceed, and security warnings are suppressed. Malware families use this technique to ensure their infrastructure domains are treated as trusted before delivering payloads via browser or to silently allow scripted downloads.

The test adds `bad-domain.com` with subdomain `bad-subdomain` to the Trusted Sites zone, setting DWORD values of `2` (Zone 2) for `https`, `http`, and `*` (wildcard protocol) handlers. This is implemented purely through PowerShell `New-Item` and `New-ItemProperty` cmdlets, making this dataset particularly interesting for PowerShell-based detection.

In the defended variant, this dataset produced 35 Sysmon, 8 Security, 37 PowerShell, 1 System, and 1 WMI event. The undefended capture produced 26 Sysmon, 3 Security, and 99 PowerShell events. The high PowerShell event count (99) reflects that this technique uses native PowerShell cmdlets rather than `cmd.exe`/`reg.exe`, generating more script block fragments during execution.

## What This Dataset Contains

Unlike most other tests in this batch, this technique is implemented directly in PowerShell using `New-Item` and `New-ItemProperty` rather than through `reg.exe`. This means the malicious content appears in PowerShell telemetry and Security EID 4688 process creation rather than in `reg.exe` command line arguments.

Security EID 4688 records a child PowerShell process (PID 1716) spawned by the ART test framework PowerShell (PID 6524) with the full command line:

```
"powershell.exe" & {$key= "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\bad-domain.com\"
$name ="bad-subdomain"
new-item $key -Name $name -Force
new-itemproperty $key$name -Name https -Value 2 -Type DWORD;
new-itemproperty $key$name -Name http  -Value 2 -Type DWORD;
new-itemproperty $key$name -Name *     -Value 2 -Type DWORD;}
```

Sysmon EID 1 captures the same child PowerShell creation, tagged with `technique_id=T1059.001,technique_name=PowerShell`, with the identical multi-line command line visible.

PowerShell EID 4103 (module logging) records the individual cmdlet executions: `New-Item` creating the registry key and three separate `New-ItemProperty` calls adding the `https`, `http`, and `*` values. Module logging captures the exact parameter bindings — this is one of only two datasets in this batch that includes EID 4103.

PowerShell EID 4104 (script block logging) captures the script block content. The full `New-Item`/`New-ItemProperty` block appears in script blocks recorded during execution.

Sysmon EID 11 records PowerShell writing `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`, the standard profile data file for non-interactive PowerShell sessions.

## What This Dataset Does Not Contain

There are no Sysmon EID 13 events despite multiple registry writes occurring. The `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\` path is not covered by the sysmon-modular registry monitoring configuration. This is a gap — three separate registry values were written (plus a key created), but none appear in Sysmon registry event logs.

The dataset contains no evidence of Internet Explorer activity, no browser process creation events, and no network connections. The domain was added to the Trusted Sites zone but no subsequent access to `bad-domain.com` occurs within this capture window.

The defended variant included a System event and a WMI event not present here — those are likely Defender-related events that fired in response to the IE zone modification, which did not occur in the undefended run.

## Assessment

This dataset demonstrates that PowerShell-native registry manipulation (using `New-Item`/`New-ItemProperty`) produces a distinct telemetry signature compared to `reg.exe`-based approaches. The command line arguments in Security EID 4688 and Sysmon EID 1 contain the target domain name, zone value, and protocol handlers in plain text. PowerShell EID 4103 module logging provides the most granular cmdlet-level evidence.

The absence of Sysmon registry events despite successful writes highlights a coverage gap for HKCU ZoneMap paths in the sysmon-modular configuration. If registry monitoring were the only detection layer, this technique would be invisible. The process-based and PowerShell-based evidence compensates, but this gap would matter in environments without detailed PowerShell logging.

The domain name `bad-domain.com` appears verbatim in multiple log sources — a real attacker would use a domain name that blends with legitimate traffic.

## Detection Opportunities Present in This Data

**PowerShell command line containing `ZoneMap\Domains` and domain names.** The full registry path appears in Security EID 4688 and Sysmon EID 1 process creation events. Any PowerShell invocation setting `ZoneMap\Domains` values with DWORD 2 is unambiguous IE Trusted Sites manipulation.

**PowerShell EID 4104 script blocks with `New-ItemProperty`...`-Value 2` targeting ZoneMap.** Script block logging captures the full intent — target domain, subdomain, protocol handlers, and zone value. The combination of `ZoneMap\Domains`, `New-ItemProperty`, and DWORD value `2` is distinctive.

**PowerShell EID 4103 `New-Item` / `New-ItemProperty` at ZoneMap paths.** Module logging records parameter binding for each cmdlet call. A sequence of `New-Item` plus multiple `New-ItemProperty` calls at `ZoneMap\Domains\...` represents the minimal set of operations needed to add a trusted domain.

**Child PowerShell spawned with inline script block modifying HKCU Internet Settings.** Spawning `powershell.exe` with `& {... new-itemproperty ...ZoneMap\Domains...}` from another PowerShell process is a pattern consistent with automated script execution and worth alerting on regardless of the specific domain targeted.
