# T1564.004-4: NTFS File Attributes — Create ADS via PowerShell

## Technique Context

T1564.004 (NTFS File Attributes) encompasses adversary use of NTFS Alternate Data Streams (ADS) to conceal data. This test demonstrates ADS creation and manipulation using native PowerShell cmdlets — specifically `Set-Content` with the `-Stream` parameter — rather than `cmd.exe` redirection. The PowerShell `-Stream` parameter directly exposes the NTFS named stream interface via the PowerShell provider layer, allowing scripts to read, write, and enumerate streams without relying on any external binary. This approach is notable because it keeps the entire operation within PowerShell, potentially bypassing detection rules that look only for `cmd.exe` ADS syntax.

## What This Dataset Contains

**Security 4688** captures the PowerShell command:
```powershell
& {echo "test" > $env:TEMP\T1564.004_has_ads_powershell.txt | set-content -path test.txt -stream adstest.txt -value "test"
set-content -path $env:TEMP\T1564.004_has_ads_powershell.txt -stream adstest.txt -value "test2"
set-content -path . -stream adstest.txt -value "test3"
...}
```

**PowerShell 4103 (module logging)** captures explicit cmdlet invocations with all parameter bindings:
- `Set-Content` with `-Path "test.txt"`, `-Stream "adstest.txt"`, `-Value "test"`
- `Out-File` with `-FilePath "C:\Windows\TEMP\T1564.004_has_ads_powershell.txt"`
- `Set-Content` with `-Path "C:\Windows\TEMP\T1564.004_has_ads_powershell.txt"`, `-Stream "adstest.txt"`, `-Value "test2"`
- `Set-Content` with `-Path "."`, `-Stream "adstest.txt"`, `-Value "test3"`

This provides a detailed, parameter-level record of each ADS operation.

**Sysmon EID 15 (FileStreamCreate)** fires eight times, recording streams created at:
- `C:\Windows\Temp\T1564.004_has_ads_powershell.txt` (base file, twice)
- `C:\Windows\Temp\T1564.004_has_ads_powershell.txt:adstest.txt` (named stream, twice)
- `C:\Windows\Temp:adstest.txt` (stream on the Temp directory itself, twice)
- `C:\Windows\Temp` (base directory entry, twice)

All eight events show `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` as the creating process — confirming no external binary was involved.

The test completes with `0x0` exit codes, confirming all ADS write operations succeeded.

## What This Dataset Does Not Contain (and Why)

No `cmd.exe` process creation appears anywhere in this dataset. The entire technique is executed within a single PowerShell process using built-in cmdlets, as intended. This is why 4688 only shows the PowerShell invocation and no child cmd.exe.

No Sysmon EID 1 for the secondary PowerShell appears. The sysmon-modular ProcessCreate include rules match the outer test framework PowerShell (tagged `technique_id=T1059.001`) but the inner script block does not spawn a separate process — it runs within the same PowerShell host.

No file execution events appear. The test creates and populates streams but does not attempt to execute them. This is a data-hiding test, not a code-execution test.

## Assessment

The technique executed completely. The PowerShell `-Stream` parameter approach to ADS creation is documented at three layers: Security 4688 (command line), PowerShell 4103 (individual cmdlet parameter bindings), and Sysmon EID 15 (filesystem stream creation events with process attribution). The combination provides richer telemetry than the cmd.exe equivalent because 4103 captures the `-Stream` parameter name explicitly, making detection by log analysis straightforward even without Sysmon.

## Detection Opportunities Present in This Data

- **PowerShell 4103 with `Set-Content` and `-Stream` parameter**: the module logging record explicitly captures the `-Stream` parameter binding with the stream name, providing a clear and specific indicator. Any `Set-Content` call with a `-Stream` argument warrants investigation.
- **PowerShell 4104 script block containing `-stream`**: script block logging captures the command text including the `-stream` parameter, enabling regex detection.
- **Sysmon EID 15 with `:adstest.txt` in TargetFilename, attributed to `powershell.exe`**: a named stream creation by PowerShell is unusual and should be treated as a higher-confidence indicator than the same action by cmd.exe.
- **Sysmon EID 15 on a directory path** (e.g., `C:\Windows\Temp:adstest.txt`): streams attached to directories rather than files are a less common variant that indicates adversary experimentation with stream hiding on container objects.
- **Security 4688 PowerShell command line containing `-stream`**: the `-Stream` parameter appears verbatim in the command line, detectable without Sysmon.
