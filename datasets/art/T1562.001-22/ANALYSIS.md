# T1562.001-22: Disable or Modify Tools — Uninstall CrowdStrike Falcon on Windows

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes uninstalling
endpoint security products. CrowdStrike Falcon uses a Windows Installer package, and like
most enterprise EDR products, provides an official uninstaller. The ART test locates and
invokes the `WindowsSensor.exe` installer in silent uninstall mode. This technique is
realistic: attackers with sufficient privilege often attempt to remove EDR products
completely rather than just stopping services, as uninstallation removes drivers and prevents
reimport of the kernel sensor on reboot. The test uses authenticode signature verification
to ensure it targets a genuine Falcon installer, reflecting real-world stealth.

## What This Dataset Contains

The dataset captures 46 Sysmon events, 11 Security events, and 39 PowerShell events spanning
approximately 6 seconds on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

The attack payload is visible in multiple forms. Sysmon EID 1 captures the child PowerShell
process create with `RuleName: technique_id=T1083,technique_name=File and Directory Discovery`
(the sysmon-modular rule matched the `Test-Path` / `Get-ChildItem` pattern):

```
CommandLine: "powershell.exe" & {if (Test-Path "C:\ProgramData\Package Cache\
  {7489ba93-b668-447f-8401-7e57a6fe538d}\WindowsSensor.exe") {
    . "C:\ProgramData\Package Cache\...\WindowsSensor.exe" /repair /uninstall /quiet
  } else {
    Get-ChildItem -Path "C:\ProgramData\Package Cache" -Include "WindowsSensor.exe" -Recurse |
    % { $sig=$(Get-AuthenticodeSignature -FilePath $_.FullName);
        if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.DnsNameList -eq
            "CrowdStrike, Inc.") { . "$_" /repair /uninstall /quiet; break;}
    }
  }}
```

PowerShell 4104 script block logging records the same payload in both the wrapped and
unwrapped forms. No `WindowsSensor.exe` was found; the `else` branch executed a file system
walk via `Get-ChildItem` which completed without finding a matching executable. The WmiApSrv
process appears in Security 4689 exit events — incidental WMI activity during PowerShell
module loading. All processes exit with status 0x0.

## What This Dataset Does Not Contain (and Why)

**No CrowdStrike Falcon installation.** `WindowsSensor.exe` is not present in the Package
Cache. Neither the primary path check nor the recursive search located an installer. No
uninstaller was executed; the attack failed silently (exit 0x0 from the PowerShell wrapper's
perspective). This dataset captures the reconnaissance and attempt pattern rather than
successful uninstallation.

**No Windows Installer (msiexec) events.** Because no installer was found and executed,
there are no MSI-related events in Application or Setup logs. The collection configuration
also does not include those channels.

**No file system events for the CrowdStrike install directory.** Without an actual Falcon
installation, the Package Cache path referenced in the script does not exist. No Sysmon
EID 11 (file create) events for Falcon paths appear.

**No Sysmon EID 1 for WindowsSensor.exe.** Since no installer was invoked, there is no
process create for `WindowsSensor.exe`. The only EID 1 events are for `whoami.exe` (test framework
check) and the child `powershell.exe` (attack command).

## Assessment

The test executed and completed without error despite CrowdStrike not being installed.
The detection value lies in the attack payload itself — the specific Package Cache path,
GUID, authenticode signature check, and silent uninstall flags — rather than in successful
execution. This is a realistic representation of how an automated attack tool would probe
for and attempt to remove an EDR product.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block content**: The combination of `Get-AuthenticodeSignature`,
  `WindowsSensor.exe`, `/uninstall /quiet`, and `CrowdStrike, Inc.` in a single script
  block is a very high-fidelity indicator. These tokens together have no legitimate
  administrative interpretation.

- **Security 4688 and Sysmon EID 1 command line**: The full payload string appears in the
  process command line. String matching on `WindowsSensor.exe` combined with `/uninstall`
  in PowerShell argument context is effective.

- **Get-ChildItem on Package Cache with WindowsSensor.exe**: The fallback search of
  `C:\ProgramData\Package Cache` for installer executables is itself detectable as
  security product discovery. This pattern appears in several EDR-targeting attack tools.

- **Authenticode certificate name in PowerShell**: Searching script block logs for
  `CrowdStrike, Inc.` as a string in PowerShell execution context is highly specific
  and reliable.
