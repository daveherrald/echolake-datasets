# T1543.003-6: Windows Service — Modify Service to Run Arbitrary Binary (PowerShell)

## Technique Context

T1543.003 also covers modification of existing services rather than creation of new ones. Attackers prefer hijacking existing services because a pre-existing service name attracts less scrutiny than a new one, and because the service is already registered with the SCM. The PowerShell `Set-ServiceBinaryPath` cmdlet (an alias for `sc.exe config`) lets an attacker silently swap the `ImagePath` of any writable service, then start it. Defenders focus on changes to `HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath` for existing services, the use of `Stop-Service` / `Set-ServiceBinaryPath` / `Start-Service` sequences, and services restarted with paths pointing to unusual executables.

## What This Dataset Contains

The test targets the `fax` service (Windows Fax and Scan) but it is not installed on this system, so the attack is partially executed with observable failures. The full script block is captured in the PowerShell channel and the process create chain is visible in Sysmon and Security.

**Sysmon EID=1 (ProcessCreate):** A child PowerShell is spawned from the test framework PowerShell with the complete attack command:
`"powershell.exe" & {Stop-Service -Name "fax" -force -erroraction silentlycontinue | Out-Null; set-servicebinarypath -name "fax" -path "$env:windir\system32\notepad.exe"; start-service -Name "fax" -erroraction silentlycontinue | out-null}`

**PowerShell EID=4104 (ScriptBlock):** The complete attack script block is logged verbatim:
```
Stop-Service -Name "fax" -force -erroraction silentlycontinue | Out-Null
set-servicebinarypath -name "fax" -path "$env:windir\system32\notepad.exe"
start-service -Name "fax" -erroraction silentlycontinue | out-null
```

**PowerShell EID=4103 (Module/CommandInvocation):** Both `Stop-Service` and `Start-Service` invocations are logged, including their `NonTerminatingError`: `"Cannot find any service with service name 'fax'."` — confirming the fax service was absent and the modification did not succeed.

**Security 4688:** The child PowerShell process creation is captured with the full command line including the embedded script.

## What This Dataset Does Not Contain

- No Sysmon EID=13 registry write for the `ImagePath` change — because `fax` service does not exist, `Set-ServiceBinaryPath` fails silently and no registry modification occurs. There is no successful service binary modification in this data.
- No System 7045 or equivalent service modification audit event — again because the target service is absent.
- No `services.exe` spawning a new process — the service was never started with the new binary.
- No Security 4697. The technique nominally produces a service config change audit record, but none was generated here because the operation failed.
- The System log is absent from the dataset — no System 7045 or 7040 events were collected in the filtered window.

## Assessment

This dataset is valuable as a partial-execution case with strong PowerShell coverage. The script block (EID=4104) is the most detection-actionable artifact — `set-servicebinarypath` with a path to a system binary (`notepad.exe`) as a replacement service is a clear indicator regardless of whether the operation succeeded. The failed execution is realistic: in production environments, services are often absent on specific hosts, and the silent error handling (`-erroraction silentlycontinue`) is a hallmark of attacker scripting. For detection engineering that relies on the registry write or a new service process, this dataset is insufficient — add a variant where the fax service is pre-installed, or target a universally present service (e.g., `LanmanWorkstation`).

## Detection Opportunities Present in This Data

1. **PowerShell EID=4104 — `set-servicebinarypath` or `Set-ServiceBinaryPath` in any script block**: This cmdlet has no legitimate administrative use cases that involve replacing an existing service binary with an unrelated executable like `notepad.exe`.
2. **PowerShell EID=4103 — `Stop-Service` / `Set-ServiceBinaryPath` / `Start-Service` in a single pipeline**: The stop-modify-start sequence within a single script block is a strong behavioral indicator.
3. **Sysmon EID=1 — `powershell.exe` command line containing `set-servicebinarypath`**: Even when PowerShell script block logging is disabled, the command line captured by Sysmon EID=1 contains the full attack script.
4. **Security 4688 — PowerShell spawning a child PowerShell with inline service modification**: A parent powershell.exe spawning a child powershell.exe with `& {...}` blocks containing service manipulation cmdlets is suspicious.
5. **Sequence detection — `Stop-Service` error followed immediately by `Set-ServiceBinaryPath`**: The `NonTerminatingError` on Stop-Service followed by the binary path attempt within the same script invocation is detectable via temporal correlation of EID=4103 events.
