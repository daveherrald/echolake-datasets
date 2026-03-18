# T1562.001-24: Disable or Modify Tools — Tamper with Windows Defender Evade Scanning - Extension

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes configuring
Windows Defender exclusions by file extension. Adding an extension exclusion instructs
Defender to skip scanning any file with that extension regardless of location. Adversaries
use this to ensure their payloads — often with common executable extensions like `.exe`,
`.dll`, or `.bat` — are never scanned when written to disk or executed. Unlike path-based
exclusions, extension exclusions apply system-wide, making them broader in scope. Using
`Add-MpPreference -ExclusionExtension` with `.exe` essentially disables signature scanning
for all executables on the system.

## What This Dataset Contains

The dataset captures 40 Sysmon events, 12 Security events, and 39 PowerShell events spanning
approximately 9 seconds on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

The attack payload is visible across all three log sources. PowerShell 4104 script block
logging records:

```powershell
$excludedExts= ".exe"
Add-MpPreference -ExclusionExtension $excludedExts
```

Sysmon EID 1 captures the child PowerShell process create with the full command line:

```
"powershell.exe" & {$excludedExts= ".exe"
Add-MpPreference -ExclusionExtension $excludedExts}
```

As with test -23, loading `Add-MpPreference` triggers multi-chunk Defender module logging
in PowerShell 4104 — here 24 chunks covering the complete parameter manifest of the cmdlet.
A WmiPrvSE.exe process exits cleanly in Security 4689, indicating the `Add-MpPreference`
call routed through WMI to apply the configuration. All processes exit with status 0x0.

The duration of this test (9 seconds vs. ~6 seconds for similar tests) reflects the WMI
round-trip time for the exclusion update. This broader window is expected for extension
exclusions, which require a different internal code path than simple path exclusions.

## What This Dataset Does Not Contain (and Why)

**No Sysmon EID 13 (registry write) for the extension exclusion.** Like path exclusions,
extension exclusions are applied via the Defender management interface rather than a direct
registry write observable as a discrete Sysmon EID 13 event. The exclusion is stored under
`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\`, but this write occurs
within the privileged Defender process.

**No Windows Defender operational log entries.** The Defender operational channel
(Microsoft-Windows-Windows Defender/Operational) would log the exclusion change but is
not collected in this dataset.

**No test of `.exe` exclusion effect.** The test adds the exclusion but does not execute
a payload to verify it was bypassed. No file writes or executions under the excluded
extension appear in the logs.

**Sysmon ProcessCreate is filtered.** The WmiPrvSE.exe process that handles the WMI
configuration request is not captured by EID 1 (no matching include rule); it appears
only in Security 4689 as an exit event.

## Assessment

The test succeeded. The `.exe` extension exclusion was applied to Windows Defender and
all processes exited with status 0x0. The WmiPrvSE.exe exit event corroborates that
the WMI management path was used. This is a particularly impactful exclusion: adding
`.exe` to Defender's exclusion list eliminates signature-based scanning for the most
common payload delivery format on Windows.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block containing `Add-MpPreference -ExclusionExtension`**:
  Any exclusion extension value passed to this cmdlet is a detection opportunity. The
  extension `.exe` is especially high-fidelity — there is essentially no legitimate
  administrative reason to exclude all executables from Defender scanning.

- **Security 4688 and Sysmon EID 1 command line**: The full command is captured at the
  process creation layer. Matching on `-ExclusionExtension` in PowerShell invocations
  is reliable and low-noise.

- **WmiPrvSE.exe exit event following `Add-MpPreference`**: The presence of a WmiPrvSE.exe
  process exit immediately after an `Add-MpPreference` command provides corroborating
  context that the WMI route was used for a Defender configuration change.

- **Extension-based exclusion audit**: Organizations that monitor Defender configuration
  changes via the Windows Defender operational channel would see the exclusion addition
  in near-real-time. This channel is absent here but should be considered for collection.
