# T1137.001-1: Office Template Macros — Injecting a Macro into the Word Normal.dotm Template for Persistence via PowerShell

## Technique Context

T1137.001 Office Template Macros is a persistence technique where attackers modify Microsoft Office templates to execute malicious code whenever Office applications start or open documents. The Normal.dotm template in Word is particularly attractive because it automatically loads with every new document. This technique allows attackers to establish persistence without requiring elevated privileges or modifying system files, making it relatively stealthy.

The detection community focuses on monitoring for unexpected modifications to Office template files, PowerShell interactions with Office COM objects, and registry changes that enable programmatic access to VBA projects. Since this technique often involves automation through scripting languages, monitoring for Office application launches without user interaction and PowerShell script execution patterns is critical.

## What This Dataset Contains

This dataset captures a failed attempt to inject a VBA macro into Word's Normal.dotm template. The PowerShell script in Security EID 4688 shows the complete attack payload embedded in the command line, revealing a sophisticated automation attempt that would:

1. Set the registry key `HKCU:Software\Microsoft\Office\16.0\Word\Security\AccessVBOM` to enable VBA project access
2. Create a backup of Normal.dotm as Normal1.dotm
3. Load the Word COM object and inject VBA code for a scheduled task creating persistence
4. The embedded VBA macro would create "OpenCalcTask" to run calc.exe daily at 20:04

However, the technique fails because Microsoft Office is not installed on the test system. PowerShell EID 4103 shows `Add-Type -AssemblyName Microsoft.Office.Interop.Word` failing with "Could not load file or assembly" and EID 4100 confirming the terminating error. Similarly, `New-Object -ComObject Word.Application` fails with "Class not registered" (REGDB_E_CLASSNOTREG).

Sysmon captures multiple PowerShell process creations (PIDs 13508, 20324, 29352, 11940) with the full attack script in the command line. The dataset includes rich process telemetry with file operations (EID 11), image loads (EID 7), and pipe creation (EID 17) showing normal PowerShell initialization patterns.

## What This Dataset Does Not Contain

The dataset lacks the core technique artifacts because Office is not installed. Missing elements include:
- Word application process creation and COM object instantiation
- Normal.dotm template modification or backup file creation
- Registry modifications to `HKCU:Software\Microsoft\Office\16.0\Word\Security`
- VBA project manipulation events
- Scheduled task creation from the embedded macro payload

Since the technique fails early in the process due to missing dependencies, we don't see the file system artifacts (T1137-001_Flag2.txt creation fails with "Could not find a part of the path") or any successful Office automation. The Sysmon ProcessCreate events don't capture Word processes because they never start.

## Assessment

This dataset provides excellent visibility into failed Office Template Macro attacks but limited value for understanding successful technique execution. The complete attack script preserved in command line logging (Security EID 4688) is the primary detection value, showing the full attack methodology including registry manipulation, file operations, and VBA injection techniques.

The PowerShell telemetry is comprehensive with detailed script block logging (EID 4104) and command invocation tracking (EID 4103), making this valuable for understanding PowerShell-based Office automation attempts. However, the lack of Office installation means defenders cannot study the technique's success patterns or develop detections for actual template modification.

For detection engineering, this dataset is most useful for building rules around attempted Office COM automation and PowerShell scripts containing Office-related keywords, rather than detecting successful persistence establishment.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Analysis**: Monitor Security EID 4688 for command lines containing `Microsoft.Office.Interop.Word`, `Word.Application`, and VBA-related strings like `VBProject` or `CodeModule.AddFromString`

2. **Failed COM Object Creation**: Alert on PowerShell EID 4100 errors with "REGDB_E_CLASSNOTREG" when combined with Office-related assembly loading attempts in the same process

3. **Registry Path Targeting**: Detect PowerShell script blocks (EID 4104) referencing `Software\Microsoft\Office\*\Security\AccessVBOM` registry paths, indicating VBA access manipulation attempts

4. **Template File Path References**: Monitor for PowerShell accessing paths like `AppData\Roaming\Microsoft\Templates\Normal.dotm` or similar Office template locations

5. **Embedded VBA Code Detection**: Search PowerShell script blocks for VBA syntax patterns like "Sub AutoExec()", "Shell", and "schtasks" commands indicating macro-based persistence payloads

6. **Process Creation Chain Analysis**: Correlate multiple PowerShell processes created in succession with Office automation failure patterns, indicating persistent retry attempts

7. **File Operation Anomalies**: Monitor for failed file operations to Office template directories when combined with PowerShell COM object errors, suggesting blocked Office manipulation attempts
