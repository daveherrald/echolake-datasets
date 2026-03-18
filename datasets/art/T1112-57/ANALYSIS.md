# T1112-57: Modify Registry — Snake Malware Registry Blob

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify the Windows registry to hide configuration information, remove information as part of cleaning up, or to install persistent mechanisms. The detection community focuses on unusual registry modifications, especially to sensitive keys, creation of new values in unexpected locations, and the storage of encoded or binary data that could represent malicious payloads or configuration.

This specific test simulates Snake malware's technique of storing binary blob data in registry values within file association keys. Snake malware is known to hide encrypted configuration or payload data in seemingly legitimate registry locations like file extension handlers, making detection challenging as these locations normally contain binary data. The technique leverages `HKLM:\SOFTWARE\Classes\.wav\OpenWithProgIds` as a hiding spot for a 4KB binary blob.

## What This Dataset Contains

The dataset captures PowerShell-based registry modification activity with excellent telemetry across multiple data sources:

**Security Event Log (EID 4688):** Shows the complete process creation chain with full command lines:
- `"powershell.exe" & {$typicalPath = \"HKLM:\SOFTWARE\Classes\.wav\OpenWithProgIds\"; $randomBytes = New-Object Byte[] 0x1000; (New-Object Random).NextBytes($randomBytes); New-ItemProperty -Path $typicalPath -Name \"AtomicSnake\" -Value $randomBytes -PropertyType Binary -Force | Out-Null}`

**PowerShell Operational Log (EID 4103/4104):** Provides detailed script block logging showing the exact PowerShell commands:
- Script block text captures the complete technique: `{$typicalPath = "HKLM:\SOFTWARE\Classes\.wav\OpenWithProgIds"; $randomBytes = New-Object Byte[] 0x1000; (New-Object Random).NextBytes($randomBytes); New-ItemProperty -Path $typicalPath -Name "AtomicSnake" -Value $randomBytes -PropertyType Binary -Force | Out-Null}`
- Command invocation details show `New-Object` calls with `TypeName="Byte[]"` and `ArgumentList="4096"`
- Registry modification captured via `New-ItemProperty` with parameters: `Path="HKLM:\SOFTWARE\Classes\.wav\OpenWithProgIds"`, `Name="AtomicSnake"`, `PropertyType="Binary"`
- The actual binary data is partially visible: `"34, 45, 143, 2, 204, 52, 43, 85, 14, 197, 245, 203..."`

**Sysmon Events:** Captures process creation (EID 1) showing PowerShell execution with the full command line, plus extensive image load events (EID 7) and named pipe creation (EID 17).

## What This Dataset Does Not Contain

The dataset lacks several key elements for comprehensive registry modification detection:

**Registry Modification Events:** No Sysmon EID 13 (RegistryEvent) or Security audit events for registry modifications. The sysmon-modular configuration may not have registry monitoring enabled, and Windows audit policy shows "object_access: none," meaning registry access auditing is disabled.

**Registry Query Events:** No evidence of subsequent registry reads (Sysmon EID 12) that would show the malware accessing its stored blob.

**File System Activity:** While Sysmon EID 11 shows PowerShell profile file creation, there's no evidence of additional file drops or modifications that might accompany registry-based persistence.

**Network Activity:** No network connections showing potential command and control communication that might trigger after the registry modification.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based registry modification techniques through process creation and PowerShell logging. The command-line arguments in Security 4688 events combined with detailed PowerShell script block logging (EID 4104) give defenders multiple detection opportunities. However, the lack of direct registry modification events (Sysmon EID 13) limits the ability to build detections focused specifically on registry changes rather than the PowerShell execution method. For production environments, enabling Sysmon registry monitoring and Windows registry access auditing would significantly strengthen detection capabilities for this technique.

## Detection Opportunities Present in This Data

1. **PowerShell Binary Registry Value Creation** - Monitor PowerShell script blocks containing `New-ItemProperty` with `-PropertyType Binary` parameters, especially targeting file association registry paths like `SOFTWARE\Classes\.*\OpenWithProgIds`

2. **Large Binary Data in File Association Keys** - Detect creation of binary registry values in file extension handler locations with suspicious sizes (4KB in this case) using the `New-ItemProperty` cmdlet

3. **PowerShell Random Byte Array Generation** - Monitor for PowerShell script blocks creating large byte arrays with `New-Object Byte[]` followed by `NextBytes()` method calls, indicating potential blob generation

4. **Process Command Line Registry Patterns** - Detect command-line arguments containing file extension registry paths combined with binary property creation flags (`-PropertyType Binary -Force`)

5. **PowerShell Module Invocation Sequence** - Monitor PowerShell command invocation logs (EID 4103) for the specific sequence: `New-Object` (Byte[]) → `New-Object` (Random) → `New-ItemProperty` with binary property type

6. **Snake Malware Artifact Names** - Alert on registry value names matching known Snake malware patterns (e.g., "AtomicSnake" or similar identifiers in file association keys)

7. **Registry Path Targeting Legitimate Extensions** - Monitor for registry modifications to common file extensions (.wav, .txt, .doc, etc.) within the `OpenWithProgIds` subkey structure, particularly when combined with binary data storage
