# T1562.001-52: Disable or Modify Tools — Delete Microsoft Defender ASR Rules - GPO

## Technique Context

MITRE ATT&CK T1562.001 includes modifying or removing Defender Attack Surface Reduction (ASR) rules. This test targets the Group Policy Object (GPO) registry path for ASR rules: `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`. ASR rules configured via GPO are stored in this location as named values where each name is a rule GUID and the value (0, 1, or 2) controls the rule state. This test simulates an attacker or insider removing a specific ASR rule (GUID `36190899-1602-49e8-8b27-eb1d0a1ce869`, which corresponds to the "Block abuse of exploited vulnerable signed drivers" rule) by creating it and then deleting it. The GPO path is a commonly targeted ASR configuration mechanism in enterprise environments.

## What This Dataset Contains

**PowerShell (4104 / 4103):** Script block logging captures the full technique payload:
```powershell
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $registryPath)) { New-Item -Path $registryPath -Force }
New-ItemProperty -Path $registryPath -Name "36190899-1602-49e8-8b27-eb1d0a1ce869" -Value 1 -PropertyType String -Force
Remove-ItemProperty -Path $registryPath -Name "36190899-1602-49e8-8b27-eb1d0a1ce869"
```
Module logging (4103) records `Test-Path` for the `ASR\Rules` path, `New-ItemProperty` writing the GUID value, and `Remove-ItemProperty` deleting it. Write-Host confirmation messages are captured: `"Registry value created: 36190899-1602-49e8-8b27-eb1d0a1ce869 with data 1"` and `"Registry value deleted: 36190899-1602-49e8-8b27-eb1d0a1ce869"`.

**Sysmon:** Event 13 records the registry value write for `36190899-1602-49e8-8b27-eb1d0a1ce869 = 1` under the GPO ASR path. Event 12 (DeleteValue) records the subsequent removal. A Sysmon 1 event also shows `wmiprvse.exe -Embedding` being spawned by WMI, which is unrelated test framework infrastructure activity.

**Security:** 10 events covering process lifecycle (4688/4689) for the test framework PowerShell, `whoami.exe`, and `conhost.exe`. No child processes for the registry operations.

## What This Dataset Does Not Contain (and Why)

**No GPO policy application or refresh events:** The test directly writes the registry values rather than applying an actual Group Policy. No `gpupdate.exe`, no Group Policy service events, and no GPMC-related logs are present.

**No Defender service response to rule removal:** Removing ASR rule registry values does not produce a Defender-specific event in this configuration. The change takes effect on the next policy evaluation cycle.

**No Security 4657:** Object access auditing for registry keys is disabled in the audit policy configuration.

**Contrast with T1562.001-51:** The GPO ASR path (`Exploit Guard\ASR\Rules`) is a different registry location from the InTune path (`Policy Manager`). The same GUID appears in both tests, but detection rules must cover both paths to catch both configuration management approaches. A rule covering only one path leaves the other as a blind spot.

## Assessment

The technique completed the full create-then-delete cycle successfully. The specific ASR rule GUID `36190899-1602-49e8-8b27-eb1d0a1ce869` is the "Block abuse of exploited vulnerable signed drivers" rule — a high-value protection for kernel attack chains. Both the Sysmon 12/13 registry events and the PowerShell 4103/4104 logs provide complementary confirmation. This dataset pairs naturally with T1562.001-51 to illustrate the two main enterprise ASR deployment paths and their corresponding registry locations.

## Detection Opportunities Present in This Data

- **Sysmon 13:** Registry write to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\{GUID}` — ASR rule creation under GPO path
- **Sysmon 12 (DeleteValue):** Deletion of any named GUID value under `\ASR\Rules` — ASR rule removal
- **PowerShell 4104:** Script block containing `Exploit Guard\ASR\Rules` with `Remove-ItemProperty` — direct technique signature
- **PowerShell 4103:** `Remove-ItemProperty` with the GPO ASR path and a GUID name — specific and actionable
- **Write-Host 4103:** Module logging captures the confirmation string `"Registry value deleted: 36190899-1602-49e8-8b27-eb1d0a1ce869"` — useful for hunting specific rule GUID removals
- **Cross-source correlation:** Sysmon 12/13 registry events correlated with PowerShell cmdlet invocations for the same key within the same second provides high-confidence attribution
