# T1098-15: Account Manipulation — Domain Password Policy Check: Only Two Character Classes

## Technique Context

T1098 Account Manipulation encompasses various methods attackers use to modify account properties to maintain persistence or escalate privileges. This specific test (T1098-15) focuses on domain password policy manipulation by attempting to set a weak password that contains only two character classes (uppercase and lowercase letters), violating typical enterprise password complexity requirements.

The detection community primarily focuses on monitoring for unauthorized password changes, especially those that weaken account security. This technique is significant because it can allow attackers to maintain persistence through predictable credentials or facilitate lateral movement with compromised accounts that have weak passwords.

## What This Dataset Contains

The dataset captures a PowerShell-based password change attempt targeting a domain account. The core activity is visible in Security event 4688, which shows the PowerShell command execution with the full command line attempting to change a password to "onlyUPandLowChars":

```
"powershell.exe" & {$credFile = "$env:LOCALAPPDATA\AtomicRedTeam\$env:USERNAME.txt"
if (Test-Path $credFile) {
    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $env:USERNAME, (Get-Content $credFile | ConvertTo-SecureString)
    if($cred.GetNetworkCredential().Password -eq "onlyUPandLowChars"){
      Write-Host -ForegroundColor Yellow "The new password is the same as the password stored in the credential file. Please specify a different new password."; exit -1
    }
    try {
        $newPassword = ConvertTo-SecureString onlyUPandLowChars -AsPlainText -Force
        Set-ADAccountPassword -Identity $env:USERNAME -OldPassword $cred.password -NewPassword $newPassword
    }
    catch { 
        $_.Exception
        $errCode = $_.Exception.ErrorCode
        Write-Host "Error code: $errCode"
        if ($errCode -eq 86) {
            Write-Host -ForegroundColor Yellow "The stored password for the current user is incorrect. Please run the prereq commands to set the correct credentials"
            Remove-Item $credFile
        }
        exit $errCode
    }
    Write-Host -ForegroundColor Cyan "Successfully changed the password to onlyUPandLowChars"
    $newCred = New-Object System.Management.Automation.PSCredential ($env:USERNAME, $(ConvertTo-SecureString "onlyUPandLowChars" -AsPlainText -Force))
    $newCred.Password | ConvertFrom-SecureString | Out-File $credFile
}
else {
    Write-Host -ForegroundColor Yellow "You must store the password of the current user by running the prerequisite commands first"
}}
```

PowerShell script block logging captures the same payload in event 4104. The dataset also contains normal PowerShell initialization activities, DLL loading events in Sysmon, and process termination events showing clean exit codes (0x0), suggesting the technique executed without obvious errors.

## What This Dataset Does Not Contain

The dataset lacks evidence of actual domain controller interaction or password policy enforcement. There are no failed authentication events (Security 4625), no domain controller security events showing password change attempts, and no Group Policy-related events that would indicate policy violations were detected and blocked. The credential file referenced in the script (`$env:LOCALAPPDATA\AtomicRedTeam\$env:USERNAME.txt`) appears to be missing, as evidenced by the script's conditional logic checking for its existence.

Most critically, there are no events showing whether the `Set-ADAccountPassword` cmdlet actually succeeded or failed, which would be the key indicator of whether this password policy bypass attempt was successful.

## Assessment

This dataset provides good visibility into the attempt to manipulate account passwords through PowerShell, particularly the command-line arguments that reveal the weak password being set. However, its value for detection engineering is limited by the lack of domain controller perspective and Active Directory security events that would show the actual success or failure of the password change attempt.

The Security 4688 events with full command-line logging are excellent for detecting this technique, as they capture the plaintext password and the Set-ADAccountPassword cmdlet usage. The PowerShell script block logging provides complementary coverage. However, defenders would need additional telemetry from domain controllers to understand the complete attack chain and its ultimate success.

## Detection Opportunities Present in This Data

1. **PowerShell password manipulation detection** - Monitor Security 4688 events for command lines containing `Set-ADAccountPassword` combined with `ConvertTo-SecureString` and plaintext password patterns

2. **Weak password pattern detection** - Alert on PowerShell executions containing passwords that match simple character class patterns (e.g., only letters, only numbers and letters)

3. **Credential file manipulation** - Detect PowerShell scripts that read, write, or manipulate credential files in `AtomicRedTeam` directories or similar testing paths

4. **Active Directory cmdlet abuse** - Monitor for AD PowerShell module usage (`Set-ADAccountPassword`, `New-Object System.Management.Automation.PSCredential`) in unexpected contexts

5. **Process tree analysis** - Correlate parent-child PowerShell process relationships (PID 24880 spawning PID 9276) that involve credential manipulation activities

6. **Script block content analysis** - Parse PowerShell 4104 events for script blocks containing password change logic combined with weak password validation bypasses
