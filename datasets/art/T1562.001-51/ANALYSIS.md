# T1562.001-51: Disable or Modify Tools — Delete Microsoft Defender ASR Rules - InTune

## Technique Context

MITRE ATT&CK T1562.001 includes modifying or removing Defender Attack Surface Reduction (ASR) rules. ASR rules block specific high-risk behaviors (e.g., Office spawning child processes, credential theft from LSASS, obfuscated script execution). This test simulates the removal of ASR rules as they would be configured via Microsoft InTune's Mobile Device Management (MDM) policy path: `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager`. The test first creates an `ASRRules` value (simulating an existing MDM-deployed rule), then deletes it. The InTune/MDM policy path is distinct from the Group Policy (GPO) path used in T1562.001-52, and removing rules from this path would disable ASR enforcement for MDM-managed devices.

## What This Dataset Contains

**PowerShell (4104 / 4103):** The technique payload is fully captured in script block logging:
```powershell
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
if (-not (Test-Path $registryPath)) { New-Item -Path $registryPath -Force }
New-ItemProperty -Path $registryPath -Name "ASRRules" -Value "36190899-1602-49e8-8b27-eb1d0a1ce869=1" -PropertyType String -Force
Remove-ItemProperty -Path $registryPath -Name "ASRRules"
```
Module logging (4103) records each cmdlet call: `Test-Path` checking for the `Policy Manager` key and `ASRRules` subkey, `New-ItemProperty` creating the ASR rule value, and `Remove-ItemProperty` deleting it. The Write-Host confirmation messages are also captured: `"Registry value created: ASRRules"` and `"Registry value deleted: ASRRules"`.

**Sysmon:** Event 13 captures the registry value write to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager` with the ASR rule GUID `36190899-1602-49e8-8b27-eb1d0a1ce869=1`. Event 12 (DeleteValue) captures the subsequent removal of the key. Multiple Event 7 (Image Loaded) events show DLL loads into the test framework PowerShell, including a Sysmon 13 for `HKLM\System\CurrentControlSet\Services\WdFilter\Parameters\PreventPagingFileAbuse` — a side effect of the Defender filter driver being queried.

**Security (4688/4689):** Process creation/termination events for the test framework PowerShell, `whoami.exe`, and `conhost.exe`. No additional child processes since the technique uses PowerShell cmdlets exclusively.

## What This Dataset Does Not Contain (and Why)

**No confirmation that ASR was actually enforced before deletion:** The test creates the registry value immediately before deleting it — it does not reflect a real-world scenario where ASR rules were previously deployed and are being removed from an active MDM policy.

**No MDM enrollment or InTune infrastructure events:** The test simulates the registry state change that InTune would produce, but no actual MDM communication, enrollment events, or InTune agent activity is present.

**No Defender service response:** Removing ASR rules from the Policy Manager path while Defender is running does not generate any Defender-specific event log entries in this dataset. The change would require a policy refresh or service restart to take effect.

**No Security 4657 (Registry object access):** Object access auditing is disabled in the audit policy, so no detailed registry access events are present.

## Assessment

The technique completed the full create-then-delete cycle. The Sysmon 12 (DeleteValue) event for the ASR Rules path and the PowerShell 4103 `Remove-ItemProperty` log both confirm the deletion. This dataset is useful for building detections around both ASR rule creation (possibly legitimate MDM deployment) and deletion (possible tampering). The InTune policy path (`Policy Manager`) is distinct from the GPO path (`Windows Defender Exploit Guard\ASR\Rules`) tested in T1562.001-52, making path-specific rules necessary to cover both.

## Detection Opportunities Present in This Data

- **Sysmon 13:** Registry write to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager\ASRRules` — ASR rule creation in the MDM path
- **Sysmon 12 (DeleteValue):** Deletion of a value under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager` — ASR rule removal
- **PowerShell 4104:** Script block text containing `Policy Manager` and `ASRRules` with `Remove-ItemProperty` — clear technique signature
- **PowerShell 4103:** `Remove-ItemProperty` cmdlet with path `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager` and name `ASRRules`
- **Create-then-delete pattern:** Sysmon 13 followed by Sysmon 12 on the same key within seconds — indicative of test or cleanup behavior, but also matches attacker cleanup
