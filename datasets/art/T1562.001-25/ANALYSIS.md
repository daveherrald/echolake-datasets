# T1562.001-25: Disable or Modify Tools — Tamper with Windows Defender Evade Scanning - Process

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes adding Windows
Defender exclusions scoped to specific process names. A process exclusion instructs Defender
to skip scanning files accessed by the named process, effectively creating a trusted execution
context for that executable. Adversaries use this technique in two ways: adding a malicious
process name before execution to prevent its file activity from being scanned, or adding a
trusted process name (such as `outlook.exe`) to create a channel through which malicious
files can be written without triggering on-access scanning. This is among the more targeted
exclusion methods and is particularly useful for payloads delivered through trusted applications.

## What This Dataset Contains

The dataset captures 36 Sysmon events, 11 Security events, and 40 PowerShell events spanning
approximately 6 seconds on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

The attack payload is clearly visible across all three log sources. PowerShell 4104 script
block logging records:

```powershell
$excludedProcess = "outlook.exe"
Add-MpPreference -ExclusionProcess $excludedProcess
```

Sysmon EID 1 captures the child PowerShell process create with the full command line:

```
"powershell.exe" & {$excludedProcess = "outlook.exe"
Add-MpPreference -ExclusionProcess $excludedProcess}
```

The `Add-MpPreference` call produces 25 chunks of Defender module parameter definitions
in 4104 events — the standard first-time module load behavior seen across tests -23, -24,
and -25. This consistent volume fingerprint (24–28 chunks) is a recognizable pattern when
the Defender management module is loaded fresh in a PowerShell session.

All processes exit with status 0x0. The standard ART test framework preamble is present.
The target process name `outlook.exe` is notable: it represents a plausible real-world
attack scenario where the adversary creates an exclusion for a legitimate productivity
application through which they intend to deliver a payload.

## What This Dataset Does Not Contain (and Why)

**No Sysmon EID 13 (registry write) for the process exclusion.** Process exclusions, like
path and extension exclusions, are applied via the Defender management interface rather than
as directly observable registry write events. The exclusion is stored under
`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\`, but this write is
internal to the Defender service.

**No Windows Defender operational log entries.** The Defender operational channel would
record the exclusion addition but is not collected in this dataset.

**No Outlook process activity.** The test adds the exclusion for `outlook.exe` but Outlook
is not running on this system. The exclusion takes effect for any future `outlook.exe`
process, but no actual Outlook activity or file access under the excluded process appears.

**No verification of exclusion effect.** The test does not follow up with file operations
under `outlook.exe` to confirm Defender skipped scanning. The dataset captures the
configuration change only.

## Assessment

The test succeeded. The process exclusion for `outlook.exe` was applied to Windows Defender
and all processes exited with status 0x0. The choice of `outlook.exe` as the exclusion target
reflects a plausible attack scenario: a phishing lure delivered through Outlook could drop
payloads that Defender would not scan if this exclusion were in place.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block containing `Add-MpPreference -ExclusionProcess`**: This
  is a reliable indicator. The combination of the cmdlet and any process name is suspicious;
  `outlook.exe` targeting a trusted application is especially worth flagging as it suggests
  preparation for a document-based attack vector.

- **Security 4688 and Sysmon EID 1 command line**: The full command is captured at the
  process creation layer. Matching `-ExclusionProcess` in PowerShell command lines is
  effective across all three Defender exclusion tests (-23, -24, -25).

- **Pattern across the exclusion trio**: Tests -23, -24, and -25 each use `Add-MpPreference`
  with one of the three exclusion types. A detection rule that fires on any use of
  `Add-MpPreference` with `-Exclusion*` parameters covers all three variants and any
  combination thereof. The Defender module load chunk pattern (24–28 4104 events following
  the invocation) is a consistent behavioral fingerprint.

- **Process name intelligence**: Alerting when the excluded process name matches a list
  of trusted applications (Outlook, Teams, Office applications, browsers) provides an
  additional layer — these exclusions are particularly valuable to attackers targeting
  those delivery channels.
