
#Create Class To Track Results
class LogEvent {
    [String]$action
    [String]$details
    [String]$actor
    [String]$time
  
    LogEvent([String] $action, [String] $details) {
        $this.action = $action
        $this.details = $details
        $this.actor = $(Get-PASSession).User
        $this.time = Get-Date
  
    }
  
    #Account Name, Account Address, PSM Server, Success or Failure, Tester Name, Test Time
    [PSCustomObject] saveResult() {
        return [PSCustomObject]@{
            Action  = $this.action
            Details = $this.details
  
        }
    }
}

#Create Class To Track Results
class ConnectionResult {
    [PSCustomObject]$account
    [PSCustomObject]$server
    [String]$connectionComponent
    [boolean]$result
    [System.DateTime]$testTime


    ConnectionResult(  [PSCustomObject]$account, [PSCustomObject]$server, [String]$connectionComponent, [boolean]$result) {
        $this.account = $account
        $this.server = $server
        $this.connectionComponent = $connectionComponent
        $this.result = $result
        $this.testTime = $(Get-Date)

    }

    #Account Name, Account Address, PSM Server, Success or Failure, Tester Name, Test Time
    [PSCustomObject] saveResult() {
        return [PSCustomObject]@{
            AccountName         = $this.account.userName
            AccountAddress      = $this.account.address
            PSMServer           = $this.server.Address
            ConnectionComponent = $this.connectionComponent
            Result              = if ($this.result -eq $true) { "Success" } else { "Fail" }
            TeterName           = $(Get-PASSession).User
            TestTime            = $this.testTime
        }
    }

}

    
#Create Class To Track Results
class PSMPConnectionResult {
    [String]$username
    [String]$psmpserver
    [String]$address
    [boolean]$result
    [System.DateTime]$testTime


    PSMPConnectionResult(  [String]$username, [String]$psmpserver, [String]$address, [boolean]$result) {
        $this.username = $username
        $this.psmpserver = $psmpserver
        $this.address = $address
        $this.result = $result
        $this.testTime = $(Get-Date)

    }

    #Account Name, Account Address, PSM Server, Success or Failure, Tester Name, Test Time
    [PSCustomObject] saveResult() {
        return [PSCustomObject]@{
            AccountName    = $this.userName
            AccountAddress = $this.address
            PSMPServer     = $this.psmpserver
            Result         = if ($this.result -eq $true) { "Success" } else { "Fail" }
            TeterName      = $(Get-PASSession).User
            TestTime       = $this.testTime
        }
    }

}

function Assert-CYBAUTOSafeName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true)]
        [string]$safeName,
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    Process {
        #TODO: Fix This
        if ($safeName -notmatch $($config.SafeValidationRegex)) {
           throw "Safe Name Does Not Match Naming Convention: $($config.SafeValidationRegex)"
            return
        }
        $existing = Get-PasSafeName -SafeName $safeName
        if ($null -ne $existing) {
            throw "Safe Name Already In Use"
            return
        }
        Write-Output $safeName
            
    }

}

function New-CYBAUTOSafeSingle {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
        [string]$SafeName,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ManagingCPM,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$NumberOfVersionsRetention,
        [Parameter(ValueFromPipelineByPropertyName)]
        [System.Collections.Hashtable[]]$Members,
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$KeepSafeCreatorAsMember,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description
    )
    Process {
        Add-PASSafe -SafeName $SafeName -ManagingCPM $ManagingCPM -NumberOfVersionsRetention $NumberOfVersionsRetention -Description $Description
        foreach ($Member in $Members) {
            Add-PASSafeMember -SafeName $SafeName @Member    
        } 
        if (!$KeepSafeCreatorAsMember) {
            Remove-PASSafeMember -SafeName $SafeName -MemberName $(Get-PASSession).User
        }
    }
}

function New-CYBAUTOSafeBulk {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName)]
        [string]$SafeName,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ManagingCPM,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$NumberOfVersionsRetention,
        [Parameter(ValueFromPipelineByPropertyName)]
        [System.Collections.Hashtable[]]$Members,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description
    )
    Process {

        Add-PASSafe -SafeName $SafeName -ManagingCPM $ManagingCPM -NumberOfVersionsRetention $NumberOfVersionsRetention -Description $Description

        foreach ($Member in $Members) {
            Add-PASSafeMember -SafeName $SafeName @Member    
        } 
    }
}

function Test-CYBAUTOPSM {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )

    #Collect Initial Information
    $platforms = Get-PASPlatform
    $servers = Get-PASPSMServer

    $rdppath = "$($global:targetFolder)\tempRDPFiles"
    if (!$(Test-Path $rdppath)) {
        $rdppath = New-Item -ItemType Directory -Path $rdppath
    }

    $results = New-Object Collections.ObjectModel.Collection[ConnectionResult]
    do {
        if ($null -ne $safeName -and $null -eq $safeObject) {
            Write-Host "Could Not Find a Safe With That Name. Please specify a new Safe"
        }
        $safeName = Read-SingleInputBoxDialog -Message 'Please Enter the Name of the Safe With the Accounts You Wish To Test' -WindowTitle 'Test Safe Name' -DefaultText $config.DefaultTestSafeName #NT_Demo_Safe
        if($null -eq $safeName){
            return
        }
        try{
            $safeObject = Get-PasSafeName -SafeName $safeName -ErrorAction SilentlyContinue
            if ($null -ne $safeObject) {
                $accounts = Get-PASAccount -safeName $safeName
                if ($null -eq $accounts -or $accounts.Length -eq 0) {
                    $safeObject = $null
                }
            }
        }catch{
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }
    while ($null -eq $safeObject)

 
    Write-Host "Please Select the PSM Servers You Wish To Test"
    Write-Host (('      PSM Server', '      ------------') -join [environment]::NewLine) -ForegroundColor Gray
    $menuSelection = Menu -menuItems ([array]$servers.name + 'Quit test' ) -Multiselect
    if($null -eq $menuSelection){
        Write-Host 'No Valid Selection' -ForegroundColor Yellow
        return
    }elseif('Quit test' -in $menuSelection){return}
    $selectedServers = $servers | Where-Object { $menuSelection -contains $_.Name }
    
    $accountsMenu = $accounts | Select-Object -Property UserName, Address, @{label = "LockStatus"; Expression = { Get-PASAccountDetail -id $_.id | Select-Object -Property @{Label = "LockedBy"; Expression = { $_.Details.LockedBy } } | Foreach-Object { if ($null -ne $_.LockedBy -and $_.LockedBy.length -gt 0) { "Locked By $($_.LockedBy)" } else { "Unlocked" } } } }, PlatformID | Format-Table -AutoSize -Wrap| Out-String 
    $accountsMenu = $accountsMenu -split [environment]::NewLine | Where-Object {$_.trim() -ne ''}
    $headerMenu = ($accountsMenu | Select-Object -First 2|ForEach-Object {"      $($_)"}) -join [environment]::NewLine
    $accountsMenu = $accountsMenu | Select-Object -Skip 2
    Write-Host "Please Select the Accounts You Wish To Test"
    Write-Host $headerMenu -ForegroundColor Gray
    $accountSelection = Menu -menuItems ([array]$accountsMenu  + 'Quit test' ) -Multiselect -ReturnIndex
    if($null -eq $accountSelection){
        Write-Host 'No Valid Selection' -ForegroundColor Yellow
        return
    }
    elseif($($accounts|Measure-Object).Count -in $accountSelection){return}
    $selectedAccounts = $accounts[$accountSelection]
    $accountToComponentMap = New-Object Collections.ObjectModel.Collection[Hashtable]

    foreach ($account in $selectedAccounts) {
        Write-Host "Please Select the Platforms You Wish To Test for Account $($account.name)"
        $platform = $platforms | Where-Object { $_.PlatformID -eq $account.platformId }
        $connectionComponents = Get-PASPlatformPSMConfig -ID $platform.Details.ID | Select-Object -ExpandProperty "PSMConnectors" | Where-Object { $_.Enabled -eq 'True' -and $_.PSMConnectorID -notlike "PSMP-*" } | Select-Object -Property PSMConnectorID
        Write-Host (('      PSMConnectorID', '      ---------------') -join [environment]::NewLine) -ForegroundColor Gray
        $componentSelection = Menu -menuItems ([array]$connectionComponents.PSMConnectorID  + 'Quit test') -Multiselect
        if($null -eq $componentSelection){
            Write-Host 'No Valid Selection' -ForegroundColor Yellow
            return
        }
        elseif('Quit test' -in $componentSelection){return}
        $mapping = @{Account = $account; Components = $($connectionComponents|Where-Object {$_.PSMConnectorID -in $componentSelection}) }
        $accountToComponentMap.add($mapping)
    }

    foreach ($targetServer in $selectedServers) {
        foreach ($accountMapping in $accountToComponentMap) {
            Write-Host -ForegroundColor Magenta "`nInitiating analysis of $($accountMapping.account.userName) with address $($accountMapping.account.address) on PSM Server $($targetServer.ID)"
            foreach ($connection in $accountMapping.Components) {
                try {
                    Write-Host "`nTesting Account with Connection Component $($connection.PSMConnectorID)"
                    $rdpfile = New-PASPSMSession -AccountID $accountMapping.account.id -ConnectionComponent $($connection.PSMConnectorID) -Path $rdppath
                    mstsc.exe $rdpfile.FullName "/v:$($targetServer.address)"
                    Start-Sleep 25
                    Write-Host "`nWas this PSM Connection Successful?"
                    $success = Menu -menuItems @("Yes", "No", "Skip This And Remaining Components For This Account") -ReturnIndex
                    
                    if ($success -eq 2) {
                        break;
                    }
                    $result = [ConnectionResult]::new($accountMapping.account, $targetServer, $($connection.PSMConnectorID), $($success -eq 0))
                    $results.Add($result);
                }
                catch {
                    Write-Host -ForegroundColor Red "An Error Occured Calling the API to Initiate a PSM Connection. Automatically Failing"
                    Write-Host -ForegroundColor Red "Error: $_"
                    $result = [ConnectionResult]::new($accountMapping.account, $targetServer, $($connection.PSMConnectorID), $false)
                    $results.Add($result);

                }
            }
        }
        Write-Host "Completed Testing Accounts in $safeName on PSM Server $($targetServer.ID)"
    }
    
    $reportFileName = "$(Get-Date -Format yyyyMMdd-hhmmss)-PSMTestResults.csv"
    $details = "See a Complete Report for the PSM Test in $reportFileName"
    [LogEvent]::new("TestPSMs", $details) | Export-Csv $global:reportFileName -NoTypeInformation -Append
    $results | ForEach-Object { $_.saveResult() } | Export-Csv "$global:targetFolder\$reportFileName" -NoTypeInformation
    
}

function Switch-CYBAUTOUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )

    Write-Host -ForegroundColor DarkYellow "By changing your user context, you will terminate your current session. Continue?"
    $continue = Menu "Y", "N"
    if ($continue -eq "Y") {
        try {
            do {
                if ($null -ne $safeName -and $null -eq $safeObject) {
                    Write-Host "Could Not Find a Safe With That Name. Please specify a new Safe"
                }
                $safeName = Read-Host "Please Enter the Safe Name containing the Account You Wish To Checkout"
                $safeObject = Get-PasSafeName -SafeName $safeName -ErrorAction SilentlyContinue
                if ($null -ne $safeObject) {
                    $accounts = Get-PASAccount -safeName $safeName
                    if ($null -eq $accounts -or $accounts.Length -eq 0) {
                        $safeObject = $null
                    }
                }
            }
            while ($null -eq $safeObject)
            Write-Host "Please Select the CyberArk Account You Wish To Use"
            $accountsMenu = $accounts | Select-Object -Property UserName, Address, @{label = "LockStatus"; Expression = { Get-PASAccountDetail -id $_.id | Select-Object -Property @{Label = "LockedBy"; Expression = { $_.Details.LockedBy } } | Foreach-Object { if ($null -ne $_.LockedBy -and $_.LockedBy.length -gt 0) { "Locked By $($_.LockedBy)" } else { "Unlocked" } } } }, PlatformID | Format-Table | Out-String | Foreach-Object -Begin {} { $_.trim() } { $_.split("`n") } -End {} | Select-Object -Index @(4..$(if ($accounts.count) { $accounts.count + 3 } else { 4 }))    
            $accountSelection = Menu -menuItems $accountsMenu -ReturnIndex
            $selectedAccount = $accounts[$accountSelection]

            $altCred = [System.Management.Automation.PSCredential]::new($($selectedAccount.userName), $(ConvertTo-SecureString -AsPlainText $(Get-PASAccountPassword -AccountID $($selectedAccount.id) | ForEach-Object Password) -Force))
            New-PASSession -Credential $altCred -type CyberArk -BaseURI $config.url -SkipCertificateCheck

        }
        catch {
            $_ >> $global:logFileName
            Write-Host -ForegroundColor Red "Unable to Checkout Account"
            Write-Host -ForegroundColor Red $_
        }
    }
    
}

function Test-CYBAUTOPSMP {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )

    $results = New-Object Collections.ObjectModel.Collection[PSMPConnectionResult]

    do {
        if ($null -ne $safeName -and $null -eq $safeObject) {
            Write-Host "Could Not Find a Safe With That Name. Please specify a new Safe"
        }
        $safeName = Read-SingleInputBoxDialog -Message 'Please Enter the Name of the Safe With the Accounts You Wish To Test' -WindowTitle 'Test Safe Name' -DefaultText $config.DefaultTestSafeName #NT_Demo_Safe
        if($null -eq $safeName){
            return
        }
        try{
            $safeObject = Get-PasSafeName -SafeName $safeName -ErrorAction SilentlyContinue
            if ($null -ne $safeObject) {
                $accounts = Get-PASAccount -safeName $safeName
                if ($null -eq $accounts -or $accounts.Length -eq 0) {
                    $safeObject = $null
                }
            }
        }catch{
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
    }
    while ($null -eq $safeObject)

    $accountsMenu = $accounts | Select-Object -Property UserName, Address, @{label = "LockStatus"; Expression = { Get-PASAccountDetail -id $_.id | Select-Object -Property @{Label = "LockedBy"; Expression = { $_.Details.LockedBy } } | Foreach-Object { if ($null -ne $_.LockedBy -and $_.LockedBy.length -gt 0) { "Locked By $($_.LockedBy)" } else { "Unlocked" } } } }, PlatformID | Format-Table -AutoSize -Wrap| Out-String 
    $accountsMenu = $accountsMenu -split [environment]::NewLine | Where-Object {$_.trim() -ne ''}
    $headerMenu = ($accountsMenu | Select-Object -First 2|ForEach-Object {"  $($_)"}) -join [environment]::NewLine
    $accountsMenu = $accountsMenu | Select-Object -Skip 2
    Write-Host "Please Select the Account You Wish To Test"
    Write-Host $headerMenu -ForegroundColor Gray
    $accountSelection = Menu -menuItems ([array]$accountsMenu + 'Quit test') -ReturnIndex
    if($accountSelection -eq ($accountsMenu|Measure-Object).Count){return}
    $selectedAccount = $accounts[$accountSelection]
    Write-Host "Which PSMPs do you wish to test?"
    Write-Host (('      PSMPs Name', '      -----------') -join [environment]::NewLine) -ForegroundColor Gray
    $selectedpsmps = Menu -menuItems ([array]$config.psmps + 'Quit test') -Multiselect    
    if($null -eq $selectedpsmps){
        Write-Host 'No Valid Selection' -ForegroundColor Yellow
        return
    }
    elseif('Quit test' -in $selectedpsmps ){return}
  
    $user = Read-SingleInputBoxDialog -Message 'Please Enter the Username of the Account You Will Use To Logon To The Vault' -WindowTitle 'Account Username' -DefaultText ''
    if($null -eq $user){
        return
    }
    foreach ($server in $selectedpsmps) {
        Write-Host "Testing the following connection string: $($user)@$($selectedAccount.username)@$($selectedAccount.address)@$($server)"
        try {
            .\Modules\OpenSSH-Win64\ssh.exe "$($user)@$($selectedAccount.username)@$($selectedAccount.address)@$($server)"
        }
        catch {
            ssh.exe "$($user)@$($selectedAccount.username)@$($selectedAccount.address)@$($server)"
        }

        Write-Host "`nWas this PSM Connection Successful?"
        $success = Menu -menuItems @("Yes", "No", "Skip This And Remaining PSMPs") -ReturnIndex
        
        if ($success -eq 2) {
            break;
        }
        $testresult = [PSMPConnectionResult]::new($selectedAccount.username, $server, $selectedAccount.address, $($success -eq 0))
        $results.Add($testresult);
    }

    $reportFileName = "$(Get-Date -Format yyyyMMdd-hhmmss)-PSMPTestResults.csv"
    $results | ForEach-Object { $_.saveResult() } | Export-Csv "$global:targetFolder\$reportFileName" -NoTypeInformation

    
}

function Test-CCPs{

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )

    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-CCPsTestResults.csv"
    
    try{     
        $CCP_URL_List = [array]($config.CCP_URLs | ForEach-Object {$_.trim()}|Select-Object -Unique)
        
        if(($CCP_URL_List|Measure-Object).Count -eq 0){
            Write-Host "There is no CCPs defined in the configuration. " -ForegroundColor Yellow
            return
        }
                                          
        Write-Host "Please Select the CCP You Wish To Test"
        Write-Host (('      CPPs Name', '      ---------') -join [environment]::NewLine) -ForegroundColor Gray
        
        $SelectedCCPs = Menu -menuItems ($CCP_URL_List + 'Quit test') -Multiselect    
                
        if($null -eq $SelectedCCPs){
            Write-Host 'No Valid Selection' -ForegroundColor Yellow
            return
        }
        elseif('Quit test' -in $SelectedCCPs ){return}  
        
        if($config.IsCerificateRequired){
            #Check Required Certificate
            $cert = (Get-ChildItem -Path $config.Certificate_path | Where-Object {$_.Thumbprint -eq $config.Cert_Thumbprint});

            if($null -eq $cert){
                Write-Host "Required certificate to test CCP not found in machine." -ForegroundColor Yellow
                return
            }
        }

        $params = @{ 
                    object = $config.Object_ccp
                    AppID = $config.AppID_ccp
                    Safe = $config.Safe_ccp
                  }

        #CCP uses TLS1.2 This will set protocol if client is not configured for TLS1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        #Clear buffer
        $csv = @() 

        foreach ($Url in $SelectedCCPs)
        {
            try{
                $Result = $null
                # Make the Invoke-RestMethod call using the URL
                if($config.IsCerificateRequired){
                    $Result = Invoke-RestMethod -Uri $Url -Body $params -certificate $cert -Method Get -ErrorAction Stop
                }else{
                    $Result = Invoke-RestMethod -Uri $Url -Body $params -Method Get -ErrorAction Stop
                }
                
            }Catch{
                Write-Host "Warning: Rest call for '$Url' failed with error '$($_.Exception.Message)'." -ForegroundColor Red
            }
                        
            if(($Result|Measure-Object).Count -eq 0){
                Write-Host "Warning: CPP = '$($Url)' did not return any value. "
                #Create CSV object
                $csv += [PsCustomObject]@{
                            Endpoint_Tested = $Url
                            TimeTested = ([DateTime]::Now).ToString('yyyy-MM-ddTHH:mm:ss')
                            AppID = $config.AppID_ccp
                            Result = 'Failed'
                      }
            }else{
                #Create CSV object
                $csv += [PsCustomObject]@{
                            Endpoint_Tested = $Url
                            TimeTested = ([DateTime]::Now).ToString('yyyy-MM-ddTHH:mm:ss')
                            AppID = $config.AppID_ccp
                            Result = 'Success'
                      }
            }
        }

        #Create CSV object
        
        if(($csv|Measure-Object).Count -ne 0){
            try{
                $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Host "Test results saved to '$($Path)'. " -ForegroundColor Green
            }catch{
                Write-Host "Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    catch{
        Write-Host "ERROR: $($_.Exception.Message)."
    }
    # Echo the results

} 

function Test-PVWAs{

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )

    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-PVWAsTestResults.csv"
    
    try{     
        $PVWA_URL_List = [array]($config.PVWA_URLs | ForEach-Object {$_.trim()}|Select-Object -Unique)
        
        if(($PVWA_URL_List|Measure-Object).Count -eq 0){
            Write-Host "There is no PVWAs defined in the configuration. " -ForegroundColor Yellow
            return
        }
                                          
        Write-Host "Please Select the PVWA You Wish To Test"
        Write-Host (('      PVWAs Name', '      ---------') -join [environment]::NewLine) -ForegroundColor Gray
        
        $SelectedPVWAs = Menu -menuItems ($PVWA_URL_List + 'Quit test') -Multiselect    
                
        if($null -eq $SelectedPVWAs){
            Write-Host 'No Valid Selection' -ForegroundColor Yellow
            return
        }
        elseif('Quit test' -in $SelectedPVWAs ){return}  
        
        if($config.IsCerificateRequired){
            #Check Required Certificate
            $cert = (Get-ChildItem -Path $config.Certificate_path | Where-Object {$_.Thumbprint -eq $config.Cert_Thumbprint});

            if($null -eq $cert){
                Write-Host "Required certificate to test PVWA not found in machine." -ForegroundColor Yellow
                return
            }
        }

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        #Clear buffer
        $csv = @() 

        foreach ($Url in $SelectedPVWAs)
        {
            $Success = $true
            try{
                $Result = $null
                # Make the Invoke-RestMethod call using the URL
                if($config.IsCerificateRequired){
                    $Result = Invoke-WebRequest -Uri $Url -certificate $cert -Method Get -ErrorAction Stop
                }else{
                    $Result = Invoke-WebRequest -Uri $Url -Method Get -ErrorAction Stop
                }
                
            }Catch{
                $Success = $false
                Write-Host "Warning: Test for '$Url' failed with error : '$($_.Exception.Message)'." -ForegroundColor Red
            }

            if($Result.StatusCode -eq 200){
                Write-Host -Object "Test for '$Url' was successfull" -ForegroundColor Green
                #Create CSV object
                $csv += [PsCustomObject]@{
                            Endpoint_Tested = $Url
                            TimeTested = ([DateTime]::Now).ToString('yyyy-MM-ddTHH:mm:ss')
                            Result = 'Success'
                      }
            }else{
                if($Success -ne $false){
                    Write-Host "Test for '$Url' failed. Status: '$($Result.StatusCode)' $($Result.StatusDescription)" -ForegroundColor Red
                }
                #Create CSV object
                $csv += [PsCustomObject]@{
                            Endpoint_Tested = $Url
                            TimeTested = ([DateTime]::Now).ToString('yyyy-MM-ddTHH:mm:ss')
                            Result = 'Failed'
                }
            
            }
        }

        #Create CSV object
        
        if(($csv|Measure-Object).Count -ne 0){
            try{
                $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Host "Test results saved to '$($Path)'. " -ForegroundColor Green
            }catch{
                Write-Host "Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    catch{
        Write-Host "ERROR: $($_.Exception.Message)."
    }
    # Echo the results

} 


function Export-CYBAUTOPlatformProperties {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    Write-Progress -Activity "Generating Report..." -PercentComplete -1
    $platforms = Get-PASPlatform 
    $platforms | ForEach-Object { $psmconfig = Get-PASPlatformPSMConfig -ID $_.Details.ID; $_ | Add-Member -NotePropertyName PSMConnectors -NotePropertyValue $($psmconfig.PSMConnectors | Where-Object { $_.Enabled -eq $true } | Select-Object -ExpandProperty PSMConnectorID) }

    $dictionary = @{
        "Active"                                                                                   = "Active"
        "Details.AllowedSafes"                                                                     = "AllowedSafes"
        "Details.CredentialsManagementPolicy.Change.AllowManual"                                   = "ChangeManually"
        "Details.CredentialsManagementPolicy.Change.AutoOnAdd"                                     = "ChangeOnAdd"
        "Details.CredentialsManagementPolicy.Change.PerformAutomatic"                              = "ChangeAutomatically"
        "Details.CredentialsManagementPolicy.Change.RequirePasswordEveryXDays"                     = "PasswordExpireDays"
        "Details.CredentialsManagementPolicy.Reconcile.AllowManual"                                = "ReconManually"
        "Details.CredentialsManagementPolicy.Reconcile.AutomaticReconcileWhenUnsynced"             = "ReconWhenUnsynced"
        "Details.CredentialsManagementPolicy.SecretUpdateConfiguration.ChangePasswordInResetMode"  = "ChangeInResetMode"
        "Details.CredentialsManagementPolicy.Verification.AllowManual"                             = "VerifyManually"
        "Details.CredentialsManagementPolicy.Verification.AutoOnAdd"                               = "VerifyOnAdd"
        "Details.CredentialsManagementPolicy.Verification.PerformAutomatic"                        = "VerifyAutomatically"
        "Details.CredentialsManagementPolicy.Verification.RequirePasswordEveryXDays"               = "PassowrdVerifyDays"
        "Details.ID"                                                                               = "PlatformID"
        "Details.Name"                                                                             = "PlatformName"
        "Details.PrivilegedAccessWorkflows.EnforceCheckinCheckoutExclusiveAccess.IsActive"         = "CheckInOutPolicy"
        "Details.PrivilegedAccessWorkflows.EnforceCheckinCheckoutExclusiveAccess.IsAnException"    = "CheckInOutPolicyIsException"
        "Details.PrivilegedAccessWorkflows.EnforceOnetimePasswordAccess.IsActive"                  = "OnTimePasswordPolicy"
        "Details.PrivilegedAccessWorkflows.EnforceOnetimePasswordAccess.IsAnException"             = "OnTimePasswordPolicyIsException"
        "Details.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval.IsActive"      = "ApprovalPolicy"
        "Details.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval.IsAnException" = "ApprovalPolicyException"
        "Details.PrivilegedAccessWorkflows.RequireUsersToSpecifyReasonForAccess.IsActive"          = "RequireReasonPolicy"
        "Details.PrivilegedAccessWorkflows.RequireUsersToSpecifyReasonForAccess.IsAnException"     = "RequireReasonPolicyException"
        "Details.PrivilegedSessionManagement.PSMServerId"                                          = "PSMServerID"
        "Details.PrivilegedSessionManagement.PSMServerName"                                        = "PSMServerAddress"
        "Details.SystemType"                                                                       = "PlatformType"
        "PlatformID"                                                                               = "PlatformName"
        "PSMConnectors"                                                                            = "PSMConnectors"
    }

    function addprop {
        param ($inputobject, $outputobject, $prefix)
        foreach ($nestedProp in $inputobject | Get-Member) {
            if ($null -ne $prefix) {
                $path = $prefix + "."
            }
            else {
                $path = ""
            }
            if ($nestedProp.MemberType -eq "NoteProperty") {
                if ($nestedProp.Definition.split(" ")[0] -like "*PSCustomObject*") {
                    addprop -inputobject $inputobject.$($nestedProp.Name) -outputobject $output -prefix $($path + $nestedProp.Name)
                }
                elseif ($nestedProp.Definition.split(" ")[0] -like "*Object``[``]*") {
                    $output[$dictionary[$path + $nestedProp.name]] = $inputobject.$($nestedProp.Name) -join ","
                }
                elseif ($null -ne $($inputobject.$($nestedProp.Name))) {
                    $output[$dictionary[$path + $nestedProp.name]] = $inputobject.$($nestedProp.Name)
                }   
            }
        }
    }

    $final = New-Object -TypeName System.Collections.ArrayList

    $platforms | ForEach-Object {

        $output = [Ordered] @{}
        addprop -inputobject $_ -outputobject $output
        $final.add([PSCustomObject]$output) | Out-Null
        Remove-Variable output
    }

    Write-Progress -Activity "Generating Report..." -Completed
    Write-Host "Saving Results To $global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-Platforms.csv"
    $final | Export-Csv -Path "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-Platforms.csv" -NoTypeInformation
    
}

function Import-CYBAUTOSafesCSV {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    Remove-Variable safeFile -ErrorAction SilentlyContinue
    $safeFile = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Safe Definitions File"
    if ($null -eq $safeFile -or $safeFile.Length -eq 0) {
        Write-host "No File Selected" -ForegroundColor Yellow
        return
    }
    $global:AddSafeMemebrsOption = $true
    Import-Csv -Path $safeFile | ForEach-Object {
        try { 
            $SafeValue = $null
            $SafeNameTemp = $_.SafeName
            $SafeValue = Assert-CYBAUTOSafeName -safeName $_.SafeName -config $config 
            if($null -eq $SafeValue){
                continue
            }
            $SafeValue| New-CYBAUTOSafeBulk -Members $config.DefaultSafeMembers -NumberOfVersionsRetention $config.DefaultVersionRetention -Description $_.Description -ManagingCPM $_.ManagingCPM  >> $global:logFileName
            $details = "Created Safe $($_.SafeName)"
            Write-Host $details -ForegroundColor Green
            
            $OwnersList = $_.OwnerGroup -split '&' |ForEach-Object {$_.trim()}|Where-Object {$_ -ne ''}
            Add-AdditionalSafeMembers -SafeName $_.SafeName -MemberList $OwnersList -Permissions $config.SafeMemberPermGroups.OwnerGroup -SearchIn $config.SafeMembersSearchIn -Type 'Owner'   
                                  
            $ApproversList = $_.ApproverGroup -split '&' |ForEach-Object {$_.trim()}|Where-Object {$_ -ne ''}
            Add-AdditionalSafeMembers -SafeName $_.SafeName -MemberList $ApproversList -Permissions $config.SafeMemberPermGroups.ApproverGroup -SearchIn $config.SafeMembersSearchIn -Type 'Approver'   

            $UsersList = $_.UserGroup -split '&' |ForEach-Object {$_.trim()}|Where-Object {$_ -ne ''}
            Add-AdditionalSafeMembers -SafeName $_.SafeName -MemberList $UsersList -Permissions $config.SafeMemberPermGroups.UserGroup -SearchIn $config.SafeMembersSearchIn -Type 'User'   
            
            if($($_.KeepSafeCreatorAsMember -ne "Y")){
                Remove-PASSafeMember -SafeName $_.SafeName -MemberName $(Get-PASSession).User                
            }
        }
        catch { 
            $_ >> $global:logFileName
            $details = "Unable to Create Safe $($SafeNameTemp)" 
            Write-Host -ForegroundColor Red $details
            Write-Host -ForegroundColor Red $_
        }
        finally {
            [LogEvent]::new("AddBulkSafe", $details) | Export-Csv $global:reportFileName -NoTypeInformation -Append
        }
    }
    
}

function Add-AdditionalSafeMembers([String]$SafeName, $MemberList, [Hashtable]$Permissions, [String]$SearchIn, [String]$Type){
    
    foreach ($Member in $MemberList)
    {
        try{   
            if($null -ne $SearchIn -and $SearchIn.Trim() -ne ''){
                try {
                    Add-PASSafeMember -SafeName $SafeName -MemberName $Member -SearchIn $SearchIn @Permissions -ErrorAction Stop|Out-Null                
                }
                catch {
                    Add-PASSafeMember -SafeName $SafeName -MemberName $Member -MemberType Group -SearchIn $SearchIn @Permissions -ErrorAction Stop|Out-Null                
                }
            }else{
                try {
                    Add-PASSafeMember -SafeName $SafeName -MemberName $Member @Permissions -ErrorAction Stop|Out-Null
                }
                catch {
                    Add-PASSafeMember -SafeName $SafeName -MemberName $Member -MemberType Group @Permissions -ErrorAction Stop|Out-Null
                }                
            }
            Write-Host "Member '$($Member)' added in safe '$($SafeName)' with '$($Type)' permissions" -ForegroundColor Green
        }catch{
                    
            if($($_.Exception.Message) -like '*is already a member of safe*'){
                Write-Host "Warning: '$($Member)' is already member of safe '$($SafeName)'." -ForegroundColor Yellow
                                                            
            }elseif($($_.Exception.Message) -like "*Safe * has been deleted or does not exist*"){
                Write-Host "Warning: SafeName '$($SafeName)' is not found, It has been deleted or does not exist. " -ForegroundColor Yellow
                    
            }elseif($($_.Exception.Message) -like "*Member * has not been defined*"){
                Write-Host "Warning: Member '$($Member)' has not been defined, Please provide valid member. " -ForegroundColor Yellow                    
            }
            else{
                Write-Host "Warning: Failed to add member '$($Member)' in '$($SafeName)' safe. ERROR: $($_.Exception.Message) " -ForegroundColor Yellow                    
            }
        }
    }
    
}

function Import-CYBAUTOAccountsCSV {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    Remove-Variable accountsFile -ErrorAction SilentlyContinue
    $accountsFile = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Accounts Definitions File"
    if ($null -eq $accountsFile -or $accountsFile.Length -eq 0) {
        Write-host "No File Selected" -ForegroundColor Yellow
        return
    }
    Import-Csv -Path $accountsFile | ForEach-Object {
        try { 
            $props = @{}
            $platformProps = @{}
            foreach ($argObject in $_.psobject.properties.name ) {
                $arg = [String]$argObject
                if ($_.$arg -ne $null -and $_.$arg.trim().Length -ne 0) {
                    if ($arg -eq "secret") {
                        $props[$arg] = $_.secret | ConvertTo-SecureString -AsPlainText -Force
                    }
                    elseif ($arg.StartsWith("platformAccountProperties.")) {
                        $platformPropertyName = $arg.Substring(26)
                        $platformProps[$platformPropertyName] = $_.$arg
                    }elseif($arg.Trim() -in ('remoteMachines', 'remoteMachinesAccess.remoteMachines')){
                        $props['remoteMachines'] = $_.$arg
                    }elseif($arg.Trim() -in ('accessRestrictedToRemoteMachines', 'remoteMachinesAccess.accessRestrictedToRemoteMachines' )){
                        try{
                            $props['accessRestrictedToRemoteMachines'] = [System.Convert]::ToBoolean($_.$arg)
                        }catch{
                            throw "Invalid value for '$($arg.Trim())', it accepts true/false only. $($_.Exception.Message)"
                        }
                    }elseif($arg.Trim() -in ('SecretManagement.ManualManagementReason', 'manualManagementReason')){
                        $props['ManualManagementReason'] = $_.$arg
                    }elseif($arg.Trim() -in ('SecretManagement.AutomaticManagementEnabled','automaticManagementEnabled')){
                        try{
                            $props['AutomaticManagementEnabled'] = [System.Convert]::ToBoolean($_.$arg)
                        }catch{
                            throw "Invalid value for '$($arg.Trim())', it accepts true/false only. $($_.Exception.Message)"
                        }
                    }
                    else {
                        $props[$arg] = $_.$arg
                    }
                }
            }
            if ($platformProps.Count -gt 0) {
                $props["platformAccountProperties"] = $platformProps
            }
            Add-PASAccount @props >> $global:logFileName
            $details = "Created Account $($_.userName) with Platform $($_.platformID)"
        }
        catch { 
            $_ >> $global:logFileName
            $details = "Unable to Create Account $($_.userName) with Platform $($_.platformID)" 
            Write-Host -ForegroundColor Red $details
            Write-Host -ForegroundColor Red $_
        }
        finally {
            [LogEvent]::new("AddBulkAccount", $details) | Export-Csv $global:reportFileName -NoTypeInformation -Append
        }
    }
    
}

function Export-SafeReport{
<#
    .SYNOPSIS
        Exports all safe list to CSV in the given directory.
    .DESCRIPTION
        It utilises PsPAS module to import safe list and exports it as csv in the given directory. Exported CSV file name will end with "-SafeList.csv". 
    .EXAMPLE
        PS> Export-SafeReport
        Result saved to 'C:\Users\UserName\Desktop\20221212-031402-SafeList.csv'. 
    .EXAMPLE
        PS> Get-Help Export-SafeReport
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 12/12/2022
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Get-PASSafe
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safes%20Web%20Services%20-%20List%20Safes.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-SafeList.csv"

    try{        
        
        Write-Progress -Activity "Generating Report..." -PercentComplete -1
        
        #Fetch SafeList
        $URI = "$($BaseURI.TrimEnd('/'))/PasswordVault/API/Safes?includeAccounts=false&offset=0&limit=25"
        #send request to web service
	    $TempResult = Invoke-PASRestMethod -Uri $URI -Method GET -WebSession $Global:NewSessionObject 
        $Result = $TempResult.value
        $retry = 1

        while($null -ne $TempResult.nextLink){

            try{
                $URL = $BaseUri +'/PasswordVault/'+ $TempResult.nextLink
                $TempResult = Invoke-PASRestMethod -Uri $URL -Method GET -WebSession $Global:NewSessionObject
                $Result += $TempResult.value
            }catch{
                Write-Host "Warning: Error occured. $($_.Exception.Message)" -ForegroundColor Yellow
                if($retry -eq 5){
                    throw "Max Retry Reached. $($_.Exception.Message)"
                }else{
                    Write-Host "Retrying.." -ForegroundColor Cyan
                    New-PASSession -Credential $global:cred -BaseURI $global:BaseURI -type $global:authselection -SkipCertificateCheck            
                }
                $retry += 1
            }
        }
                
        $Date = (Get-Date -Day 1 -Month 1 -Year 1970).Date
                        
        #Create CSV object
        $csv = $Result|ForEach-Object{
                [PsCustomObject]@{
                        SafeUrlId = $_.safeUrlId
                        SafeName = $_.safeName
                        Description = $_.description
                        SafeNumber = $_.safeNumber
                        Location = $_.location
                        Creator_id = $_.creator.id
                        Creator_name = $_.creator.name
                        OlacEnabled = $_.olacEnabled
                        NumberOfVersionsRetention = $_.numberOfVersionsRetention
                        NumberOfDaysRetention = $_.numberOfDaysRetention
                        AutoPurgeEnabled = $_.autoPurgeEnabled
                        CreationTime = $Date.AddSeconds($_.CreationTime).ToString('yyyy-MM-ddTHH:mm:ss')
                        LastModificationTime = $Date.AddMilliseconds($([long]$_.LastModificationTime)/1000).ToString('yyyy-MM-ddTHH:mm:ss.fffK')
                        ManagingCPM = $_.managingCPM
                        IsExpiredMember = $_.isExpiredMember
                    }
        }

        Write-Progress -Activity "Generating Report..." -Complete

        #Export CSV to report path
        try{
            $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
            Write-Host "SUCCESS: Result saved to '$($Path)'. " -ForegroundColor Green
        }catch{
            Write-Host "ERROR: Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
        }

    }catch{
        #Handle exceptions for API failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to generate report. $($_.Exception.Message)" -ForegroundColor Red
    }
    
}

function Update-SafesBulk{
<#
    .SYNOPSIS
        Updates list of safes
    .DESCRIPTION
        It utilises PsPAS module to update list of safes. It takes list of safe details as CSV and updates them one by one.
        Input CSV file should have below columns:

        Mandatory columns - 'SafeName' and 'NumberOfVersionsRetention' or 'NumberOfDaysRetention' (1 of these)        
        Non Mandatory Columns - 'NewSafeName', 'Description', 'location', 'OLACEnabled', 'ManagingCPM'

    .EXAMPLE 
        PS> Update-SafesBulk
    .EXAMPLE
        PS> Get-Help Update-SafesBulk 

    .INPUTS
        CSV
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 23/12/2022
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Update-PASSafe
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Update%20Safe.htm?
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    try{        
       
        Remove-Variable safeFile -Force -ErrorAction SilentlyContinue
        
        $safeFile = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Safe details list"
        
        $InputCsv = Test-SelectedInputCSV -FilePath $safeFile -RequiedColumns @('SafeName')
        
        $Columns = @('NewSafeName', 'Description', 'location', 'ManagingCPM')

        $inputProperties = $InputCsv|Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue|Select-Object -ExpandProperty Name
        
        if($null -eq $InputCsv){
            return
        }else{
            if(('NumberOfDaysRetention' -notin $inputProperties) -and ('NumberOfVersionsRetention' -notin $inputProperties)){
                Write-Host "Selected file does not contains mandatory column 'numberOfVersionsRetention' or 'numberOfDaysRetention' (atleast 1 is mandatory). Please provide correct CSV file." -ForegroundColor Yellow
                return
            }
        }
        
        Write-Progress -Activity "Updating safe..." -PercentComplete -1

        foreach ($item in $InputCsv)
            { 
                
                $Properties = [pscustomObject]@{}
                foreach ($col in $Columns)
                {
                    If($col -in $inputProperties){
                        $Properties | Add-Member -MemberType NoteProperty -Name $col -Value $(""+($item.$col)).trim() -ErrorAction Stop            
                    }
                }
                
                if(('NumberOfDaysRetention' -in $inputProperties) -and ((""+$item.NumberOfDaysRetention).Trim() -ne '')){
                    $Properties | Add-Member -MemberType NoteProperty -Name 'NumberOfDaysRetention' -Value $(""+$item.NumberOfDaysRetention).trim() -ErrorAction Stop            
                }
                                
                try{
                    $OlacEnabled = $null

                    if('OlacEnabled' -in $inputProperties){
                        try{ $OLACEnabled = [System.Convert]::ToBoolean($item.OLACEnabled)}
                        catch{throw "Invalid value for 'OLACEnabled', it should be either 'true' or 'false'. "}
                    }

                    if('olacEnabled' -in $inputProperties){
                        if(($item.numberOfVersionsRetention -as [int])){
                            $Newvalues = $Properties | Set-PASSafe -SafeName $item.SafeName -numberOfVersionsRetention $item.numberOfVersionsRetention -OLACEnabled $OlacEnabled -Confirm:$false -ErrorAction Stop                            
                        }else{
                            $Newvalues = $Properties | Set-PASSafe -SafeName $item.SafeName -OLACEnabled $OlacEnabled -Confirm:$false -ErrorAction Stop                            
                        }
                    }else{
                        if(($item.numberOfVersionsRetention -as [int])){
                            $Newvalues = $Properties | Set-PASSafe -SafeName $item.SafeName -numberOfVersionsRetention $item.numberOfVersionsRetention -Confirm:$false -ErrorAction Stop
                        }else{
                            $Newvalues = $Properties | Set-PASSafe -SafeName $item.SafeName -Confirm:$false -ErrorAction Stop                            
                        }
                    }
                  
                    $message = $Properties | Get-Member -MemberType NoteProperty| ForEach-Object { "$($_.Name) : $($item.($_.Name))"}
                    Write-Host "Safe '$($item.SafeName)' succesfully updated. SafeName : $($Newvalues.SafeName), $($message -join ' , ') . " -ForegroundColor Green

                }catch{
                    if($($_.Exception.Message) -like "*Safe * has been deleted or does not exist.*"){
                        Write-Host "Warning: SafeName '$($item.SafeName)' is not found, It has been deleted or does not exist. " -ForegroundColor Yellow
                        
                    }elseif($($_.Exception.Message) -like '*Cannot process argument transformation on parameter * Cannot convert value * to type "System.Int32"*'){
                        Write-Host "Warning: Invalid input provided for the '$($col)' and Safename = $($item.SafeName). Value '$($item.$col)', it should be an integer. " -ForegroundColor Yellow                        
                    }elseif($($_.Exception.Message) -like "*Invalid value for 'OLACEnabled', it should be either 'true' or 'false'*"){
                        Write-Host "Warning: Invalid value for 'OLACEnabled', it should be either 'true' or 'false'. " -ForegroundColor Yellow  
                    }
                    else{
                        Write-Host "Warning: Failed to update safe '$($item.SafeName)'. ERROR: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        Write-Progress -Activity "Updating safe..." -Complete
        
    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }

    
}

function Export-SafeMemebersList{
<#
    .SYNOPSIS
        Exports list of safe members and their permission to CSV in the given directory.
    .DESCRIPTION
        It utilises PsPAS module to export safe members based on the list of safe names given as input CSV and exports it as CSV in the given directory. 
        Input CSV file should have only 1 column named "SafeName", and based on the list of safe name provided through input CSV, Members list will be
        exported as CSV file named like "-SafeMembersList.csv". 
    .EXAMPLE
        PS> Export-SafeMemebersList
        Result saved to 'C:\Users\UserName\Desktop\20221212-031402-SafeMembersList.csv'. 
    .EXAMPLE
        PS> Get-Help Export-SafeMemebersList
    .INPUTS
        CSV
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 15/12/2022
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Get-PASSafe
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safe%20Members%20WS%20-%20List%20Safe%20Members.htm#
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-SafeMembersList.csv"

    try{        
       
        Remove-Variable inputList -Force -ErrorAction SilentlyContinue
                
        $inputList = Read-MultiLineInputBoxDialog -Message "Please enter Safe names. Multiple Safe names can be provided in separate lines." -WindowTitle "Safe Names List" -DefaultText ""
        $inputList = $inputList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($inputList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        $date = (Get-Date -Day 1 -Month 1 -Year 1970).Date

        Write-Progress -Activity "Getting Information..." -PercentComplete -1

        $ResultList = @()
        foreach ($item in $inputList)
            { 
                $Result = $null
                try{
                    $value = $(""+$item).trim()
                    $Result = Get-PASSafeMember -SafeName $value -ErrorAction Stop
                    if(($Result|Measure-Object).Count -ne 0){
                        $ResultList += $Result                
                    }
                }catch{
                    Write-Host -Object "Warning: $($_.Exception.Message) " -ForegroundColor Yellow
                }
            }

        #Create CSV object
        $csv = $ResultList|ForEach-Object{
                [PsCustomObject]@{
                        SafeName = $_.safeName                        
                        SafeUrlId = $_.safeUrlId
                        SafeNumber = $_.safeNumber
                        MemberId = $_.memberId
                        MemberName = $_.memberName
                        MemberType = $_.memberType
                        MembershipExpirationDate  = if($null -eq $_.membershipExpirationDate -or $_.membershipExpirationDate -eq ''){$_.membershipExpirationDate }else{$date.AddSeconds($_.membershipExpirationDate).ToString('yyyy-MM-dd HH:mm:ss')}
                        IsExpiredMembershipEnable = $_.isExpiredMembershipEnable
                        IsPredefinedUser = $_.isPredefinedUser
                        IsReadOnly = $_.isReadOnly
                        UserName = $_.UserName

                        Perm_useAccounts = $_.permissions.useAccounts
                        Perm_retrieveAccounts = $_.permissions.retrieveAccounts  
                        Perm_listAccounts = $_.permissions.listAccounts
                        Perm_addAccounts = $_.permissions.addAccounts
                        Perm_updateAccountContent = $_.permissions.updateAccountContent 
                        Perm_updateAccountProperties =  $_.permissions.updateAccountProperties 
                        Perm_initiateCPMAccountManagementOperations = $_.permissions.initiateCPMAccountManagementOperations
                        Perm_specifyNextAccountContent = $_.permissions.specifyNextAccountContent
                        Perm_renameAccounts = $_.permissions.renameAccounts
                        Perm_deleteAccounts = $_.permissions.deleteAccounts
                        Perm_unlockAccounts = $_.permissions.unlockAccounts
                        Perm_manageSafe = $_.permissions.manageSafe
                        Perm_manageSafeMembers = $_.permissions.manageSafeMembers
                        Perm_backupSafe = $_.permissions.backupSafe
                        Perm_viewAuditLog = $_.permissions.viewAuditLog
                        Perm_viewSafeMembers = $_.permissions.viewSafeMembers
                        Perm_accessWithoutConfirmation = $_.permissions.accessWithoutConfirmation
                        Perm_createFolders = $_.permissions.createFolders
                        Perm_deleteFolders = $_.permissions.deleteFolders
                        Perm_moveAccountsAndFolders = $_.permissions.moveAccountsAndFolders 
                        Perm_requestsAuthorizationLevel1 = $_.permissions.requestsAuthorizationLevel1 
                        Perm_requestsAuthorizationLevel2 = $_.permissions.requestsAuthorizationLevel2
                    }
        }

        Write-Progress -Activity "Getting Information..." -Complete

        #Export CSV to report path
        if(($csv|Measure-Object).Count -ne 0){
            try{
                $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Host "SUCCESS: Memebers list saved to '$($Path)'. " -ForegroundColor Green
            }catch{
                Write-Host "ERROR: Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
            }
        }

    }catch{
        #Handle exceptions for API failures and otjer failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to generate safe memebers report. $($_.Exception.Message)" -ForegroundColor Red
    }

    
}

function Test-SelectedInputCSV{
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [System.Array]$RequiedColumns
    )

    #Validate File Name
    if ($null -eq $FilePath -or $FilePath.trim().Length -eq 0) {
        Write-host "No File Selected. " -ForegroundColor Yellow
        return $null
    }
    
    $InputCsv = Import-Csv -Path $FilePath -ErrorAction SilentlyContinue

    #Validate Empty CSV
    if($null -eq $InputCsv -or ($InputCsv|Measure-Object).Count -eq 0 ){
        Write-host "Selected file does not contain any rows. Please provide correct CSV file. " -ForegroundColor Yellow
        return $null
    }

    #Validate Columns
    $flag = $true
    foreach ($column in $RequiedColumns)
    {
       if(($InputCsv."$($column)" | Measure-Object).Count -eq 0){
        Write-host "Selected file does not contains mandatory column '$($column)'. " -ForegroundColor Yellow
            $flag = $false
        }
    }

    if($flag -eq $false){
        Write-host "Please provide correct input CSV file." -ForegroundColor Yellow
        return $null
    }

    return $InputCsv
}

function Add-SafeMemebersList{
<#
    .SYNOPSIS
        Adds list of safe members with their permission to the Safe.
    .DESCRIPTION
        It utilises PsPAS module to add safe members based on the list of memebrs given as input CSV. SafeName, MemeberName, Expirartion date and the permission to be set are provided as CSV list.
    .EXAMPLE
        PS> Add-SafeMemebersList 
    .EXAMPLE
        PS> Get-Help Add-SafeMemebersList
    .INPUTS
        CSV
    .NOTES
        Version         : 1.0
        Creation Date   : 21/12/2022
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Add-PASSafeMember
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Add%20Safe%20Member.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $LogPath = "$global:targetFolder\Logs\$(Get-Date -Format yyyyMMdd-hhmmss)-AddSafeMembersLogs.LOG"
    $Logs = ""

    try{        
       
        Remove-Variable safeMemebrsList -Force -ErrorAction SilentlyContinue
        
        $safeMemebrsList = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Safe Members Details"

        $nl  = [environment]::NewLine
        $Logs = "Selected input csv '$safeMemebrsList'. $nl"
        
        $RequiedColumns = @('SafeName','MemberName','Perm_useAccounts', 'Perm_retrieveAccounts', 'Perm_listAccounts', `
                'Perm_addAccounts', 'Perm_updateAccountContent', 'Perm_updateAccountProperties', 'Perm_initiateCPMAccountManagementOperations', `
                'Perm_specifyNextAccountContent', 'Perm_renameAccounts', 'Perm_deleteAccounts', 'Perm_unlockAccounts', 'Perm_manageSafe', 
                'Perm_manageSafeMembers', 'Perm_backupSafe', 'Perm_viewAuditLog', 'Perm_viewSafeMembers', 'Perm_accessWithoutConfirmation', `
                'Perm_createFolders', 'Perm_deleteFolders', 'Perm_moveAccountsAndFolders', 'Perm_requestsAuthorizationLevel1', 'Perm_requestsAuthorizationLevel2' )
    
        $NewMemebersList = Test-SelectedInputCSV -FilePath $safeMemebrsList -RequiedColumns $RequiedColumns

        if($null -eq $NewMemebersList){
            return
        }

        $Logs += "Input CSV imported. $nl"
        $FormattedInputList = Format-AddSafeMembersInput -InputCsv $NewMemebersList -PermissionColumns $RequiedColumns[2..($RequiedColumns.Length)]

        if($null -eq $FormattedInputList){
            return
        }        
    
        $Logs += "Input CSV formatted. $nl"            
        Write-Progress -Activity "Adding Safe Members..." -PercentComplete -1
        
        #Loop through each memebers to add from input
        
        foreach ($Member in $FormattedInputList)
        {
            $Roles = $null
            try{
                $Roles = [PSCustomObject]@{

                    UseAccounts = [System.Convert]::ToBoolean($Member.Perm_useAccounts) 
                    RetrieveAccounts = [System.Convert]::ToBoolean($Member.Perm_retrieveAccounts) 
                    ListAccounts = [System.Convert]::ToBoolean($Member.Perm_listAccounts) 
                    AddAccounts = [System.Convert]::ToBoolean($Member.Perm_addAccounts) 
                    UpdateAccountContent = [System.Convert]::ToBoolean($Member.Perm_updateAccountContent) 
                    UpdateAccountProperties = [System.Convert]::ToBoolean($Member.Perm_updateAccountProperties) 
                    InitiateCPMAccountManagementOperations = [System.Convert]::ToBoolean($Member.Perm_initiateCPMAccountManagementOperations) 
                    SpecifyNextAccountContent = [System.Convert]::ToBoolean($Member.Perm_specifyNextAccountContent) 
                    RenameAccounts = [System.Convert]::ToBoolean($Member.Perm_renameAccounts) 
                    DeleteAccounts = [System.Convert]::ToBoolean($Member.Perm_deleteAccounts) 
                    UnlockAccounts = [System.Convert]::ToBoolean($Member.Perm_unlockAccounts) 
                    ManageSafe = [System.Convert]::ToBoolean($Member.Perm_manageSafe) 
                    ManageSafeMembers = [System.Convert]::ToBoolean($Member.Perm_manageSafeMembers) 
                    ViewSafeMembers = [System.Convert]::ToBoolean($Member.Perm_viewSafeMembers) 
                    BackupSafe = [System.Convert]::ToBoolean($Member.Perm_backupSafe) 
                    MoveAccountsAndFolders = [System.Convert]::ToBoolean($Member.Perm_moveAccountsAndFolders) 
                    CreateFolders = [System.Convert]::ToBoolean($Member.Perm_createFolders) 
                    DeleteFolders = [System.Convert]::ToBoolean($Member.Perm_deleteFolders) 
                    ViewAuditLog = [System.Convert]::ToBoolean($Member.Perm_viewAuditLog) 
                    requestsAuthorizationLevel1 = [System.Convert]::ToBoolean($Member.Perm_requestsAuthorizationLevel1) 
                    requestsAuthorizationLevel2 = [System.Convert]::ToBoolean($Member.Perm_requestsAuthorizationLevel2) 
                    AccessWithoutConfirmation = [System.Convert]::ToBoolean($Member.Perm_accessWithoutConfirmation) 

                }

                if($null -ne $Member.SearchIn -and $Member.SearchIn.trim() -ne ''){
                    $Roles | Add-Member -MemberType NoteProperty -Name 'SearchIn' -Value $Member.SearchIn
                }
               
                if($Member.MembershipExpirationDate -as [dateTime]){
                    try {
                        $Roles | Add-PASSafeMember -SafeName $Member.SafeName -MemberName $Member.MemberName -MembershipExpirationDate $Member.MembershipExpirationDate -ErrorAction Stop|Out-Null
                    }
                    catch {
                        $Roles | Add-PASSafeMember -SafeName $Member.SafeName -MemberType Group -MemberName $Member.MemberName -MembershipExpirationDate $Member.MembershipExpirationDate -ErrorAction Stop|Out-Null
                    }                    
                    $Logs += "Member '$($Member.MemberName)' added in safe '$($Member.SafeName)' with expiration date $($Member.MembershipExpirationDate.toString('yyyy-dd-MM HH:mm:ss')). Permissions : $nl" 
                }else{
                    try {
                        $Roles | Add-PASSafeMember -SafeName $Member.SafeName -MemberName $Member.MemberName -ErrorAction Stop|Out-Null
                    }
                    catch {
                        $Roles | Add-PASSafeMember -SafeName $Member.SafeName -MemberType Group -MemberName $Member.MemberName -ErrorAction Stop|Out-Null
                    }                    
                    $Logs += "Member '$($Member.MemberName)' added in safe '$($Member.SafeName)' with no expiration date. Permissions : $nl" 
                }

                Write-Host "Member '$($Member.MemberName)' added in safe '$($Member.SafeName)'. " -ForegroundColor Green

                $Logs += $($Roles|ConvertTo-Json -Compress)
                $Logs += "$nl"
                  
            }catch{
                if($($_.Exception.Message) -like '*is already a member of safe*'){
                    Write-Host "Warning: '$($Member.MemberName)' is already member of safe '$($Member.SafeName)'." -ForegroundColor Yellow
                    $Logs += "Warning: '$($Member.MemberName)' is already member of safe '$($Member.SafeName)'. $nl"
                                        
                }elseif($($_.Exception.Message) -like "*Safe * has been deleted or does not exist*"){
                    Write-Host "Warning: SafeName '$($Member.SafeName)' is not found, It has been deleted or does not exist. " -ForegroundColor Yellow
                    $Logs += "Warning: SafeName '$($Member.SafeName)' is not found, It has been deleted or does not exist. $nl"

                }elseif($($_.Exception.Message) -like "*Member * has not been defined*"){
                    Write-Host "Warning: Member '$($Member.MemberName)' has not been defined, Please provide valid member. " -ForegroundColor Yellow
                    $Logs += "Warning: Member '$($Member.MemberName)' has not been defined, Please provide valid member. $nl"
                }
                else{
                    Write-Host "Warning: Failed to add member '$($Member.MemberName)' in '$($Member.SafeName)' safe. ERROR: $($_.Exception.Message) " -ForegroundColor Yellow
                    $Logs += "Warning: Failed to add member '$($Member.MemberName)' in '$($Member.SafeName)' safe. $nl"
                    $Logs += $($Roles|ConvertTo-Json -Compress)
                    $Logs += "ERROR: $($_.Exception.Message) $nl"
                }
            }
            $Logs += "$nl ---------------------------------------------------------------------$nl $nl"
        }

        $Logs += "Completed. $nl"
        Write-Progress -Activity "Adding Safe Members..." -Complete

    }catch{
        #Handle exceptions for API failures and otjer failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        "ERROR: $($_.Exception.Message)"  |Out-File -FilePath $LogPath -Append -ErrorAction SilentlyContinue 
        $Logs += "Entered catch. $nl"
        $Logs += "ERROR: $($_.Exception.Message)"

    }finally{
        if(Test-Path -Path $LogPath){
            if($($Logs.Split($nl).Length -gt 2)){
                [void](New-Item -Path $LogPath -ItemType File -Confirm:$false -Force -ErrorAction SilentlyContinue)
                $Logs|Out-File -FilePath $LogPath -Append -ErrorAction SilentlyContinue 
                Write-Host "Check logs for details '$LogPath'. " -ForegroundColor Cyan
            }
        }
    }
    
}

function Update-SafeMemebersList{
<#
    .SYNOPSIS
        Updates list of safe members and their permission to the Safe.
    .DESCRIPTION
        It utilises PsPAS module to updates safe members based on the list of memebrs given as input CSV. SafeName, MemeberName, Expirartion date and the permission to be updated are provided as input CSV list.
    .EXAMPLE
        PS> Update-SafeMemebersList 
    .EXAMPLE
        PS> Get-Help Update-SafeMemebersList
    .INPUTS
        CSV
    .NOTES
        Version         : 1.0
        Creation Date   : 22/12/2022
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Set-PASSafeMember
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/Update%20Safe%20Member.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $LogPath = "$global:targetFolder\Logs\$(Get-Date -Format yyyyMMdd-hhmmss)-UpdateSafeMembersLogs.LOG"
    $Logs = ""

    try{        
       
        Remove-Variable safeMembrsList -Force -ErrorAction SilentlyContinue
        
        $safeMembrsList = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Safe Members Details"

        $nl  = [environment]::NewLine
        $Logs = "Selected input csv '$safeMembrsList'. $nl"
        
        $RequiedColumns = @('SafeName','MemberName','Perm_useAccounts', 'Perm_retrieveAccounts', 'Perm_listAccounts', `
                'Perm_addAccounts', 'Perm_updateAccountContent', 'Perm_updateAccountProperties', 'Perm_initiateCPMAccountManagementOperations', `
                'Perm_specifyNextAccountContent', 'Perm_renameAccounts', 'Perm_deleteAccounts', 'Perm_unlockAccounts', 'Perm_manageSafe', 
                'Perm_manageSafeMembers', 'Perm_backupSafe', 'Perm_viewAuditLog', 'Perm_viewSafeMembers', 'Perm_accessWithoutConfirmation', `
                'Perm_createFolders', 'Perm_deleteFolders', 'Perm_moveAccountsAndFolders', 'Perm_requestsAuthorizationLevel1', 'Perm_requestsAuthorizationLevel2' )
    
        $NewMembersList = Test-SelectedInputCSV -FilePath $safeMembrsList -RequiedColumns $RequiedColumns

        if($null -eq $NewMembersList){
            return 
        }

        $Logs += "Input CSV imported. $nl"
        $FormattedInputList = Format-AddSafeMembersInput -InputCsv $NewMembersList -PermissionColumns $RequiedColumns[2..($RequiedColumns.Length)] -ForUpdate

        if($null -eq $FormattedInputList){
            return 
        }        
    
        $Logs += "Input CSV formatted. $nl"            
        Write-Progress -Activity "Updating Safe Members..." -PercentComplete -1
        
        #Loop through each memebers to update from input
        
        foreach ($Member in $FormattedInputList)
        {
            $Roles = $null
            try{
                $Roles = [PSCustomObject]@{

                    UseAccounts = [System.Convert]::ToBoolean($Member.Perm_useAccounts) 
                    RetrieveAccounts = [System.Convert]::ToBoolean($Member.Perm_retrieveAccounts) 
                    ListAccounts = [System.Convert]::ToBoolean($Member.Perm_listAccounts) 
                    AddAccounts = [System.Convert]::ToBoolean($Member.Perm_addAccounts) 
                    UpdateAccountContent = [System.Convert]::ToBoolean($Member.Perm_updateAccountContent) 
                    UpdateAccountProperties = [System.Convert]::ToBoolean($Member.Perm_updateAccountProperties) 
                    InitiateCPMAccountManagementOperations = [System.Convert]::ToBoolean($Member.Perm_initiateCPMAccountManagementOperations) 
                    SpecifyNextAccountContent = [System.Convert]::ToBoolean($Member.Perm_specifyNextAccountContent) 
                    RenameAccounts = [System.Convert]::ToBoolean($Member.Perm_renameAccounts) 
                    DeleteAccounts = [System.Convert]::ToBoolean($Member.Perm_deleteAccounts) 
                    UnlockAccounts = [System.Convert]::ToBoolean($Member.Perm_unlockAccounts) 
                    ManageSafe = [System.Convert]::ToBoolean($Member.Perm_manageSafe) 
                    ManageSafeMembers = [System.Convert]::ToBoolean($Member.Perm_manageSafeMembers) 
                    ViewSafeMembers = [System.Convert]::ToBoolean($Member.Perm_viewSafeMembers) 
                    BackupSafe = [System.Convert]::ToBoolean($Member.Perm_backupSafe) 
                    MoveAccountsAndFolders = [System.Convert]::ToBoolean($Member.Perm_moveAccountsAndFolders) 
                    CreateFolders = [System.Convert]::ToBoolean($Member.Perm_createFolders) 
                    DeleteFolders = [System.Convert]::ToBoolean($Member.Perm_deleteFolders) 
                    ViewAuditLog = [System.Convert]::ToBoolean($Member.Perm_viewAuditLog) 
                    requestsAuthorizationLevel1 = [System.Convert]::ToBoolean($Member.Perm_requestsAuthorizationLevel1) 
                    requestsAuthorizationLevel2 = [System.Convert]::ToBoolean($Member.Perm_requestsAuthorizationLevel2) 
                    AccessWithoutConfirmation = [System.Convert]::ToBoolean($Member.Perm_accessWithoutConfirmation) 

                }
               
                if($Member.MembershipExpirationDate -as [dateTime]){
                    $Roles | Set-PASSafeMember -SafeName $Member.SafeName -MemberName $Member.MemberName -MembershipExpirationDate $Member.MembershipExpirationDate -ErrorAction Stop|Out-Null
                    $Logs += "Member details '$($Member.MemberName)' is updated in safe '$($Member.SafeName)' with expiration date $($Member.MembershipExpirationDate.toString('yyyy-dd-MM HH:mm:ss')). Permissions : $nl" 
                }else{
                    $Roles | Set-PASSafeMember -SafeName $Member.SafeName -MemberName $Member.MemberName -ErrorAction Stop|Out-Null
                    $Logs += "Member details '$($Member.MemberName)' is updated in safe '$($Member.SafeName)' with no expiration date. Permissions : $nl" 
                }

                Write-Host "Member details '$($Member.MemberName)' is updated in safe '$($Member.SafeName)'. " -ForegroundColor Green

                $Logs += $($Roles|ConvertTo-Json -Compress)
                $Logs += "$nl"
                  
            }catch{
                if($($_.Exception.Message) -like "*Safe * hasn't been defined*"){
                    Write-Host "Warning: SafeName '$($Member.SafeName)' is not found, It has been deleted or does not exist. " -ForegroundColor Yellow
                    $Logs += "Warning: SafeName '$($Member.SafeName)' is not found, It has been deleted or does not exist. $nl"

                }elseif($($_.Exception.Message) -like "*Member * has not been defined*"){
                    Write-Host "Warning: Member '$($Member.MemberName)' has not been defined, Please provide valid member. " -ForegroundColor Yellow
                    $Logs += "Warning: Member '$($Member.MemberName)' has not been defined, Please provide valid member. $nl"
                }
                else{
                    Write-Host "Warning: Failed to update member '$($Member.MemberName)' in '$($Member.SafeName)' safe. ERROR: $($_.Exception.Message) " -ForegroundColor Yellow
                    $Logs += "Warning: Failed to update member '$($Member.MemberName)' in '$($Member.SafeName)' safe. $nl"
                    $Logs += $($Roles|ConvertTo-Json -Compress)
                    $Logs += "ERROR: $($_.Exception.Message) $nl"
                }
            }
            $Logs += "$nl ---------------------------------------------------------------------$nl $nl"
        }

        $Logs += "Completed. $nl"
        Write-Progress -Activity "Updating Safe Members..." -Complete

    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        "ERROR: $($_.Exception.Message)"  |Out-File -FilePath $LogPath -Append -ErrorAction SilentlyContinue 
        $Logs += "Entered catch. $nl"
        $Logs += "ERROR: $($_.Exception.Message)"

    }finally{
        if(Test-Path -Path $LogPath){
            if($($Logs.Split($nl).Length -gt 2)){
                [void](New-Item -Path $LogPath -ItemType File -Confirm:$false -Force -ErrorAction SilentlyContinue)
                $Logs|Out-File -FilePath $LogPath -Append -ErrorAction SilentlyContinue 
                Write-Host "Check logs for details '$LogPath'. " -ForegroundColor Cyan
            }
        }
    }
}

function Remove-SafesBulk{
<#
    .SYNOPSIS
        Removes list of safes
    .DESCRIPTION
        It utilises PsPAS module to remove list of safes. It takes list of safeName as CSV and removes them one by one.
        Input CSV file should have only 1 column named "SafeName".

    .EXAMPLE 
        PS> Remove-SafesBulk
    .EXAMPLE
        PS> Get-Help Remove-SafesBulk 

    .INPUTS
        CSV
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 23/12/2022
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Remove-PASSafe
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Delete%20Safe.htm?
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    try{        
       
        Remove-Variable inputList -Force -ErrorAction SilentlyContinue
           
        $inputList = Read-MultiLineInputBoxDialog -Message "Please enter Safe names. Multiple Safe names can be provided in separate lines." -WindowTitle "Safe Names List" -DefaultText ""
        $inputList = $inputList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($inputList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }
                
        Write-Progress -Activity "Removing safe..." -PercentComplete -1

        foreach ($item in $inputList)
            { 
                try{
                    Remove-PASSafe -SafeName $item -Confirm:$false -ErrorAction Stop
                    Write-Host "Safe '$($item)' succesfully removed. " -ForegroundColor Green
                }catch{
                    if($($_.Exception.Message) -like "*Safe * was not found.*"){
                        Write-Host "Warning: SafeName '$($item)' is not found, It has been already deleted or does not exist. " -ForegroundColor Yellow
                        
                    }
                    else{
                        Write-Host "Warning: Failed to remove safe '$($item)'. ERROR: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        Write-Progress -Activity "Removing safe..." -Complete
        
    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}



function Set-SafeArchive{
    <#
    .SYNOPSIS
        Archives list of safes given as input.
    .DESCRIPTION
        It utilises PsPAS module to Archives list of safes given as input.
        To archive a safe it performs below steps:
            1 - Move safe to location defined in config file.
            2 - Add 'ARCMMDDYY' in safeName and add ' Archive on MM/DD/YY' on description of safe.
            3 - Remove all default members from safe which are defined in config file
            4 - Remove safe
    .EXAMPLE
        PS> Set-SafeArchive 
    .EXAMPLE
        PS> Get-Help Set-SafeArchive
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.2
        Creation Date   : 15/6/2023
        Purpose/Change  : Initial development
           
    .LINK
        https://pspas.pspete.dev/commands/Get-PASSafe
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safes%20Web%20Services%20-%20List%20Safes.htm
    .LINK
        https://pspas.pspete.dev/commands/Set-PASSafe
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/Update%20Safe.htm
    .LINK
        https://pspas.pspete.dev/commands/Set-PASSafeMember
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/Update%20Safe%20Member.htm        
    .LINK
        https://pspas.pspete.dev/commands/Remove-PASSafe
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/Delete%20Safe.htm

#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    try{
        Remove-Variable InputList -Force -ErrorAction SilentlyContinue
    
        $InputList = Read-MultiLineInputBoxDialog -Message "Enter SafeName which needs to be archived. Multiple values can be provided in separate lines." -WindowTitle "List of SafeName to Archive " -DefaultText ""

        $InputList = $InputList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($InputList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        $date = Get-Date
        
        #Start archiving
        Write-Progress -Activity "Archiving Safe..." -PercentComplete -1
        
        foreach ($SafeNameTemp in $InputList)
        { 
            Write-Host ""

        try{
            $Success = $true
            
            #Find the safe
            $SafeItem = Get-PasSafeName -SafeName $SafeNameTemp -ErrorAction SilentlyContinue|Where-Object{$_.SafeName -eq $SafeNameTemp}
            
            if(($SafeItem|Measure-Object).Count -eq 0){
                Write-Host -Object "Warning: No Safe found matching = '$($SafeNameTemp)'. " -ForegroundColor Yellow
                continue
            }else{
                Write-Host -Object "Started archiving = '$($SafeNameTemp)'." -ForegroundColor Cyan
            }

            $MandProperty = $null
            if($null -eq $SafeItem.numberOfVersionsRetention){
                $MandProperty = @{ numberOfDaysRetention = $safeItem.numberOfDaysRetention}
            }else{
                $MandProperty = @{ numberOfVersionsRetention = $safeItem.numberOfVersionsRetention}
            }
            #Step1 Move to new location
            $Result = $null
            $Result = Set-PASSafe -SafeName $SafeItem.safeName -location $config.ArchiveSafeLocation @MandProperty -Confirm:$false -ErrorAction Stop

            if($config.ArchiveSafeLocation -eq $Result.location){
                Write-Host -Object "Updated safe location to '$($Result.location)'" -ForegroundColor Cyan
            }else{
                Write-Host -Object "Warning: Failed to change location of safe from '$($Result.location)' to '$($config.ArchiveSafeLocation)'. " -ForegroundColor Yellow
                $Success = $false
                continue
            }

            #Step 2 and 3 Update Name and Description
            $NewDescription = $SafeItem.description
            $AdditionalDesc = " $($SafeItem.safeName) Archived on $($date.ToString('MM/dd/yy'))"

            if($($NewDescription+$AdditionalDesc).length -gt 100){
                $NewDescription = $NewDescription.Substring(0,$(100 - $AdditionalDesc.Length))+$AdditionalDesc
            }else{
                $NewDescription = $NewDescription + $AdditionalDesc
            }

            $NewDescription =$NewDescription.trim()
            $NewName = $SafeItem.safeName
            $AdditionalName = "ARC$($date.ToString('MMddyy'))"

            if($($SafeItem.safeName+$AdditionalName).length -gt 28){
                $NewName = $SafeItem.safeName.Substring(0,$(28 - $AdditionalName.Length))+$AdditionalName
            }else{
                $NewName = $SafeItem.safeName + $AdditionalName
            }
            
            $AddChar = 65
            while($null -ne $(Get-PasSafeName -SafeName $NewName -ErrorAction SilentlyContinue|Where-Object{$_.SafeName -eq $NewName})){
                if($AddChar -gt 90){throw "Additional character limit is more than allowed. ErrorCode '$AddChar'."}

                if($($SafeItem.safeName+$AdditionalName).length -gt 27){
                    $NewName = $SafeItem.safeName.Substring(0,$(27 - $AdditionalName.Length)) + $AdditionalName + [char]$AddChar
                }else{
                    $NewName = $SafeItem.safeName + $AdditionalName + [char]$AddChar
                }
                $AddChar += 1
            }

            $Result = $null
            Write-Host -Object "Updating safe name to '$NewName'" -ForegroundColor Cyan
            $Result = Set-PASSafe -SafeName $SafeItem.safeName -NewSafeName $NewName -Description $NewDescription @MandProperty -Confirm:$false -ErrorAction Stop
    
            if($NewName -ne $Result.safeName){
                Write-Host -Object "Warning: Failed to change name of safe to '$($NewName)'." -ForegroundColor Yellow                                  
                $Success = $false
                continue
            }else{
                Write-Host -Object "Updated safe name to '$($NewName)'." -ForegroundColor Cyan
            }
            
            if($NewDescription -ne $Result.Description){
                Write-Host -Object "Warning: Failed to update description to '$($NewDescription)'." -ForegroundColor Yellow                    
            }else
            {
                Write-Host -Object "Updated safe description to '$($NewDescription)'." -ForegroundColor Cyan
            }
                

            #Step3 Remove default safe members
            $SafeMembers = $null        
            $SafeMembers = Get-PASSafeMember -SafeName $Result.safeName -ErrorAction Stop
            foreach ($Mem in $SafeMembers)
            {
                if($Mem.memberName -in $config.DefaultSafeMembers.memberName){
                    Remove-PASSafeMember -SafeName $Result.safeName -MemberName $Mem.memberName -Confirm:$false -ErrorAction SilentlyContinue   
                    Write-Host -Object "Removing default member '$($Mem.safeName)'" -ForegroundColor Cyan                
                }
            }
                        
            #Step 4 Remove Safe
            Remove-PASSafe -SafeName $Result.safeName -Confirm:$false -ErrorAction Stop

        }catch{
            if($_.Exception.Message -notlike "[[]409[]] Safe * can not be deleted due to safe retention*"){
                Write-Host -Object "Warning: $($_.Exception.Message)." -ForegroundColor Yellow
                $Success = $false
            }
        }
        finally{
            if($Success -eq $true)
            {   
                Write-Host "Successfully archived safe as '$($Result.safeName)'." -ForegroundColor Green
            }else
            {
                Write-Host "Failed to archive safe '$($SafeItem.safeName)'." -ForegroundColor Red
            }
          }
        }
        Write-Progress -Activity "Archiving Safe..." -Complete
                
    }catch{
        #Handle exceptions for API failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to archive safes. $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Remove-SafeMembersBulk{
<#
    .SYNOPSIS
        Removes list of safe members from the safe
    .DESCRIPTION
        It utilises PsPAS module to removes list of safe members from the safe. It takes list as CSV with columns safeName and memberName and removes them one by one.
        
    .EXAMPLE 
        PS> Remove-SafeMembersBulk -config $config
    .EXAMPLE
        PS> Get-Help Remove-SafeMembersBulk 

    .INPUTS
        CSV
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 23/12/2022
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Remove-PASSafeMember
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Delete%20Safe%20Member.htm?
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    try{        
       
        Remove-Variable safeFile -Force -ErrorAction SilentlyContinue
        
        $safeFile = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Safe Members List"
        
        $InputCsv = Test-SelectedInputCSV -FilePath $safeFile -RequiedColumns @('SafeName','MemberName')

        if($null -eq $InputCsv){
            return
        }
        
        Write-Progress -Activity "Removing safe members..." -PercentComplete -1

        foreach ($item in $InputCsv)
            { 
                try{
                    Remove-PASSafeMember -SafeName $item.SafeName -MemberName $item.MemberName -Confirm:$false -ErrorAction Stop
                    Write-Host "'$($item.MemberName)' succesfully removed from safe '$($item.SafeName)'. " -ForegroundColor Green
                }catch{
                    if($($_.Exception.Message) -like "*Safe * has been deleted or does not exist*"){
                        Write-Host "Warning: SafeName '$($item.SafeName)' is not found, It has been deleted or does not exist. " -ForegroundColor Yellow
                        
                    }elseif($($_.Exception.Message) -like "*Member * has not been defined*"){
                        Write-Host "Warning: Member '$($item.MemberName)' has not been defined, Please provide valid member of safe '$($item.SafeName)'. " -ForegroundColor Yellow
                    }
                    else{
                        Write-Host "Warning: Failed to remove member '$($item.MemberName)' from safe '$($item.SafeName)'. ERROR: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        Write-Progress -Activity "Removing safe members..." -Complete
        
    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Export-PlatformSafeLists{
<#
    .SYNOPSIS
        Exports list of safe in the given directory.
    .DESCRIPTION
        It utilises PsPAS module to export safe list for the given list of platform Ids. 
        Safes list will be exported as CSV file named like "-PlatformSafeLists.csv". 
    .EXAMPLE
        PS> Export-PlatformSafeLists
        Result saved to 'C:\Users\UserName\Desktop\20221212-031402-PlatformSafeLists.csv'. 
    .EXAMPLE
        PS> Get-Help Export-PlatformSafeLists
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 7/1/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Get-PASPlatformSafe
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-get-safe-by-platform.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-PlatformSafeLists.csv"

    try{        
       
        Remove-Variable PlatformIDList -Force -ErrorAction SilentlyContinue
                
        $PlatformIDList = Read-MultiLineInputBoxDialog -Message "Please enter Platform IDs. Multiple IDs can be provided in separate lines." -WindowTitle "Platform IDs List" -DefaultText ""
        $PlatformIDList = $PlatformIDList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($PlatformIDList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        Write-Progress -Activity "Getting Information..." -PercentComplete -1

        $ResultList = @()

        foreach ($item in $PlatformIDList)
            { 
                $Result = $null
                try{
                    $Result = Get-PASPlatformSafe -PlatformID $item -ErrorAction Stop
                    if(($Result|Measure-Object).Count -ne 0){
                        $ResultList += [PsCustomObject]@{
                            Name = $item
                            Value = $Result.SafeName
                        }                
                    }

                }catch{
                    if($($_.Exception.Message -like "*Platform [[]$item[]] is inactive.") ){
                        Write-Host -Object "Warning: Platform [$item] is inactive. " -ForegroundColor Yellow
                    }elseif($($_.Exception.Message -like "*There are some invalid parameters: Platform [[]$item[]] was not found.") ){
                        Write-Host -Object "Warning: Platform [$item] was not found. " -ForegroundColor Yellow
                    }else{
                        Write-Host -Object "Warning: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        #Create CSV object
        $csv = $ResultList|ForEach-Object{
                    ForEach ($v in $_.Value)
                    { 
                        [PsCustomObject]@{
                                SafeName = $v
                                PlatformID  = $_.Name
                             }
                        
                    }
        }

        Write-Progress -Activity "Getting Information..." -Complete

        #Export CSV to report path
        if(($csv|Measure-Object).Count -ne 0){
            try{
                $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Host "SUCCESS: Safe list saved to '$($Path)'. " -ForegroundColor Green
            }catch{
                Write-Host "ERROR: Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
            }
        }else{
            Write-Host "No Safe was found. " -ForegroundColor Green
        }

    }catch{
        #Handle exceptions for API failures and otjer failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to generate safe lists. $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Format-AddSafeMembersInput{
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Array]$InputCsv,
        
        [Parameter(Mandatory)]
        [System.Array]$PermissionColumns,

        [switch]$ForUpdate
    )
    
    $flag = $true

    #For each row in input CSV
    for ($i = 0; $i -lt $InputCsv.Count; $i++)
    { 
        #For each permission property
        foreach ($per in $PermissionColumns)
        { 
            
            #Remove extra spaces
            $InputCsv[$i].$per = $($InputCsv[$i].$per).trim()
            
            if($ForUpdate -ne $true){
                if($InputCsv[$i].$per -notin @('true', 'false','')){
                    Write-host "Input csv has invalid value '$($InputCsv[$i].$per)' for '$per' permission (safe = '$($InputCsv[$i].SafeName)' member = '$($InputCsv[$i].MemberName)'). Valid inputs are 'true' or 'false'. " -ForegroundColor Yellow
                    $flag = $false
                }
                elseif($InputCsv[$i].$per -eq ''){
                    # Make permission column names 'false' which are not true or false
                    $InputCsv[$i].$per = 'False'
                }
            }else{            
                if($InputCsv[$i].$per -notin @('true', 'false')){
                    Write-host "Input csv has invalid value '$($InputCsv[$i].$per)' for '$per' permission (safe = '$($InputCsv[$i].SafeName)' member = '$($InputCsv[$i].MemberName)'). Valid inputs are 'true' or 'false'. " -ForegroundColor Yellow
                    $flag = $false
                }

            }
        }

        # Remove extra spaces in MembershipExpirationDate
        $InputCsv[$i].MembershipExpirationDate = $($InputCsv[$i].MembershipExpirationDate).Trim()
        if($InputCsv[$i].MembershipExpirationDate -ne ''){            
            #Parse the date time
            try{                
                $InputCsv[$i].MembershipExpirationDate = [dateTime]::ParseExact($InputCsv[$i].MembershipExpirationDate, "yyyy-MM-dd",$null)
            }catch{
                try{
                    $InputCsv[$i].MembershipExpirationDate = [dateTime]::ParseExact($InputCsv[$i].MembershipExpirationDate, "yyyy-MM-dd HH:mm:ss",$null)    
                }catch{
                    Write-host "Input csv has invalid value for 'MembershipExpirationDate' (safe = '$($InputCsv[$i].SafeName)' member = '$($InputCsv[$i].MemberName)'). Provide valid date in format 'yyyy-dd-MM HH:mm:ss' or leave it empty. " -ForegroundColor Yellow
                    $flag = $false
                }
            }
        }

        # Trim membername and safename
        $InputCsv[$i].SafeName = $InputCsv[$i].SafeName.trim()
        $InputCsv[$i].MemberName = $InputCsv[$i].MemberName.trim()
    }

    if($flag -ne $true){
        return $null
    }else{
        return $InputCsv
    }            
}

function Export-AccountsListReport{
<#
    .SYNOPSIS
        Exports list Accounts based on platformIds or Safename
    .DESCRIPTION
        It utilises PsPAS module to export Accounts list for the given safe names or platoform IDs and exports it as CSV in the given directory. 
        Exported CSV file will be named like "-AccountsList.csv". 
    .EXAMPLE
        PS> Export-AccountsListReport
        Result saved to 'C:\Users\UserName\Desktop\20221212-031402-AccountsList.csv'. 
    .EXAMPLE
        PS> Get-Help Export-AccountsListReport
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 9/1/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Get-PASAccount
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/GetAccounts.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-AccountsList.csv"

    try{        
       
        Remove-Variable InputList -Force -ErrorAction SilentlyContinue
                
        $InputType = Menu -menuItems @("By PlatformId", "By SafeName", "Cancel")

        if($InputType -eq "By SafeName"){
            $InputList = Read-MultiLineInputBoxDialog -Message "Enter SafeName containing accounts. Multiple values can be provided in separate lines." -WindowTitle "List of SafeName " -DefaultText ""

        }elseif($InputType -eq "By PlatformId"){
            $InputList = Read-MultiLineInputBoxDialog -Message "Enter PlatformId containing accounts. Multiple values can be provided in separate lines." -WindowTitle "List of PlatformId " -DefaultText ""     

        }else{
            return
        }

        $InputList = $InputList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($InputList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        $date = (Get-Date -Day 1 -Month 1 -Year 1970).Date

        Write-Progress -Activity "Getting Information..." -PercentComplete -1
        
        $ResultList = @()

        foreach ($item in $InputList)
            { 
                $Result = $null
                try{
                    if($InputType -eq "By PlatformId"){
                        $Result = Get-PASAccount -search $item -searchType contains -ErrorAction Stop | Where-Object {$_.platformID -eq $item}
                    }else{
                        $Result = Get-PASAccount -safeName $item -ErrorAction Stop                       
                    }

                    if(($Result|Measure-Object).Count -ne 0){
                        $ResultList += $Result              
                    }elseif($InputType -eq "By PlatformId"){
                        Write-Host -Object "Warning: No account matched with platformId = '$item'. " -ForegroundColor Yellow
                    }else{
                        Write-Host -Object "Warning: No account matched with safeName = '$item'. " -ForegroundColor Yellow
                    }
                }catch{
                    Write-Host -Object "Warning: $($_.Exception.Message) " -ForegroundColor Yellow
                }
            }

        $ResultList = $ResultList | Sort-Object -Unique -Property id
        #Create CSV object
        $csv = $ResultList|ForEach-Object{
                [PsCustomObject]@{
                                        
                        AccountId = $_.id                        
                        SafeName = $_.safeName
                        PlatformId = $_.platformId
                        Address = $_.address
                        Name = $_.name
                        UserName = $_.userName
                                                
                        CreatedTime = if($null -eq $_.CreatedTime -or $_.CreatedTime -eq ''){$_.CreatedTime }else{$date.AddSeconds($_.CreatedTime).ToString('yyyy-MM-dd HH:mm:ss')} 
                        
                        PlatformAccountProperties = if($null -ne $_.platformAccountProperties) {$(($_.platformAccountProperties | ConvertTo-Json -Compress).trim('{').trim("}") -replace '"', " ").split(",").trim() -join [environment]::NewLine}else{$null}

                        'AutomaticManagementEnabled' = $_.secretManagement.automaticManagementEnabled
                        'ManualManagementReason' = $_.secretManagement.manualManagementReason
                        'Status' = $_.secretManagement.status                        
                        'LastModifiedTime' = if($null -eq $_.secretManagement.lastModifiedTime -or $_.secretManagement.lastModifiedTime -eq ''){$_.secretManagement.lastModifiedTime }else{$date.AddSeconds($_.secretManagement.lastModifiedTime).ToString('yyyy-MM-dd HH:mm:ss')} 
                        'LastReconciledTime' = if($null -eq $_.secretManagement.lastReconciledTime -or $_.secretManagement.lastReconciledTime -eq ''){$_.secretManagement.lastReconciledTime }else{$date.AddSeconds($_.secretManagement.lastReconciledTime).ToString('yyyy-MM-dd HH:mm:ss')} 
                        'LastVerifiedTime' = if($null -eq $_.secretManagement.lastVerifiedTime -or $_.secretManagement.lastVerifiedTime -eq ''){$_.secretManagement.lastVerifiedTime }else{$date.AddSeconds($_.secretManagement.lastVerifiedTime).ToString('yyyy-MM-dd HH:mm:ss')} 
                        
                }
        }

        Write-Progress -Activity "Getting Information..." -Complete

        #Export CSV to report path
        if(($csv|Measure-Object).Count -ne 0){
            try{
                $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Host "SUCCESS: Accounts list saved to '$($Path)'. " -ForegroundColor Green
            }catch{
                Write-Host "ERROR: Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
            }
        }

    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to export accounts. $($_.Exception.Message)" -ForegroundColor Red
    }
    
}

function Set-AccountsBulk{
<#
    .SYNOPSIS
        Updates list of safes
    .DESCRIPTION
        It utilises PsPAS module to update list of safes. It takes list of safe details as CSV and updates them one by one.
        Input CSV file should have below columns:

        'AccountID' = Account id to be updated
        'Operation' = Operation to be performed 'Update', 'Remove', 'Add'
        'ColumnName' = Column name to be updated e.g. Address, Name, SecretManagement.Status
        'Columnvalue' = Column value to be updated e.g. google.com, test, True

    .EXAMPLE 
        PS> Update-AccountsBulk
    .EXAMPLE
        PS> Get-Help Update-AccountsBulk 

    .INPUTS
        CSV
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 25/1/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Set-PASAccount
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/11.5/en/Content/SDK/UpdateAccount%20v10.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    try{        
       
        Remove-Variable safeFile -Force -ErrorAction SilentlyContinue
        
        $safeFile = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Acounts details list"
        
        $InputCsv = Test-SelectedInputCSV -FilePath $safeFile -RequiedColumns @('AccountID', 'Operation', 'ColumnName', 'ColumnValue')
       
        $PathMaps = @{
            'Name' = '/Name'
            'address' ='/address'
            'userName' = '/userName'
            'platformId' = '/platformId'

            'SecretManagement.AutomaticManagementEnabled' = '/secretManagement/AutomaticManagementEnabled'
            'SecretManagement.ManualManagementReason' =  '/secretManagement/ManualManagementReason'
            'SecretManagement.Status' = '/secretManagement/Status'
            'SecretManagement.LastModifiedTime' = '/secretManagement/LastModifiedTime'
            'SecretManagement.LastReconciledTime' = '/secretManagement/LastReconciledTime'
            'SecretManagement.LastVerifiedTime' ='/secretManagement/LastVerifiedTime'

            'AutomaticManagementEnabled' = '/secretManagement/AutomaticManagementEnabled'
            'ManualManagementReason' =  '/secretManagement/ManualManagementReason'
            'Status' = '/secretManagement/Status'
            'LastModifiedTime' = '/secretManagement/LastModifiedTime'
            'LastReconciledTime' = '/secretManagement/LastReconciledTime'
            'LastVerifiedTime' ='/secretManagement/LastVerifiedTime'

            'remoteMachines' =  '/remoteMachinesAccess/remoteMachines'
            'accessRestrictedToRemoteMachines' =  '/remoteMachinesAccess/accessRestrictedToRemoteMachines'
            'remoteMachinesAccess.remoteMachines' =  '/remoteMachinesAccess/remoteMachines'
            'remoteMachinesAccess.accessRestrictedToRemoteMachines' =  '/remoteMachinesAccess/accessRestrictedToRemoteMachines'
        }
        
        if($null -eq $InputCsv){
            return  
        }

        #Format Inputs
        $flag = $false
        $Operations = @()
        $date = (Get-Date -Day 1 -Month 1 -Year 1970).Date

        foreach ($item in $InputCsv)
            { 
                #Format Id
                $id = "$($item.AccountID)".trim()
                if('' -eq $id){
                    Write-Host "Account id can not be null or empty. Please provide valid Account IDs in input file." -ForegroundColor Yellow
                    $flag = $true
                }
                #Format operation
                $op = $null
                $op = $item.Operation.Trim()
                if($op -in @('Remove','Delete')){
                    $op = 'Remove'
                }elseif($op -in @('set','update','replace')){
                    $op = 'replace'
                }elseif($op -eq 'Add'){
                    $op = 'Add'
                }else{
                    Write-Host "Invalid 'Operation' = '$($op)' defined for Account id = $($id), please provide valid operation Add, Remove or Update. " -ForegroundColor Yellow
                    $flag = $true                    
                }
                #Format Path
                $path = $null
                $temp = $item.ColumnName.trim()
                if($temp -like 'platformAccountProperties.*'){
                    $path = '/'+($temp.Split('.') -join '/')
                }elseif($null -ne $PathMaps[$temp]){
                    $path = $PathMaps[$temp]
                }else{
                    Write-Host "Invalid 'ColumnName' = '$($temp)' defined for Account id = $($id), please provide valid ColumnName as defined in sample input file. " -ForegroundColor Yellow
                    $flag = $true
                }

                #Format boolean values
                $value = $null
                if($path -like '*AutomaticManagementEnabled' -or $path -like '*accessRestrictedToRemoteMachines'){
                    if($item.ColumnValue.Trim() -notin @('true','false')){                        
                        Write-Host "Invalid 'ColumnValue' = '$($item.ColumnValue)' for '$($temp)' defined for Account id = $($id), only 'true' and 'false' are valid values. " -ForegroundColor Yellow
                        $flag = $true
                    }else{  $value =  [System.Convert]::ToBoolean($item.ColumnValue.Trim()) }
                }
                # Format dateTime values
                elseif($path -like '*Time'){            
                    #Parse the date time
                    try{                
                        $value = New-TimeSpan -Start $date -End $([dateTime]::ParseExact($item.ColumnValue.Trim(), "yyyy-MM-dd",$null))|Select-Object -ExpandProperty TotalSeconds
                    }catch{
                        try{
                            $value = New-TimeSpan -Start $date -End $([dateTime]::ParseExact($item.ColumnValue.Trim(), "yyyy-MM-dd HH:mm:ss",$null))|Select-Object -ExpandProperty TotalSeconds 
                        }catch{
                            Write-Host "Invalid 'ColumnValue' = '$($item.ColumnValue)' for '$($temp)' defined for Account id = $($id), please provide valid date time in format 'yyyy-MM-dd HH:mm:ss'. " -ForegroundColor Yellow
                            $flag = $true
                        }
                    }
                }
                else{
                    $value = $item.ColumnValue.Trim()
                }

                $Operations += [psCustomObject]@{
                    'id' = $id
                    'op' = $op
                    'path' = $path
                    'Value' = $value
                }

            }

        if($flag -eq $true){
                return
            }                                              
        #Format Inputs
         
        Write-Progress -Activity "Updating Accounts..." -PercentComplete -1
        foreach ($Oper in $Operations)
        {
                try{
                    $temp = $Oper.path.Substring(1) -split '/'
                    
                    if($Oper.Path -eq '/SecretManagement/AutomaticManagementEnabled' -and $Oper.Value -eq $true){
                        $Newvalues = Enable-PASCPMAutoManagement -AccountID $Oper.id  -ErrorAction Stop
                    }elseif($Oper.Path -eq '/SecretManagement/AutomaticManagementEnabled' -and $Oper.Value -eq $false){
                        $Newvalues = Disable-PASCPMAutoManagement -AccountID $Oper.id -ErrorAction Stop 
                    }else{
                        $Newvalues = Set-PASAccount -AccountID $Oper.id -op $Oper.op -path $Oper.path -value $Oper.Value -ErrorAction Stop
                    }
                
                    if(($temp|Measure-Object).Count -eq 2){
                        $tempMsg = "$($temp[0]).$($temp[1])" 
                        $tempVal = "$($Newvalues.($temp[0]).($temp[1]))"                                                                                                         
                    }else{
                        $tempMsg = "$($temp)"
                        $tempVal = "$($Newvalues.($temp))"                       
                    }

                    if($Oper.op -eq 'remove'){
                        Write-Host "Account '$($Oper.id)', Property '$($tempMsg)' is succesfully removed. " -ForegroundColor Green                         
                    }
                    elseif($tempVal -eq $Oper.Value){
                        Write-Host "Account '$($Oper.id)' succesfully updated with '$($tempMsg) = $($tempVal)'. " -ForegroundColor Green 
                    }else{
                        Write-Host "Account '$($Oper.id)', Property '$($tempMsg)' is not updated with '$($Oper.Value)'. " -ForegroundColor Yellow 
                    }                   

                }catch{
                    if($($_.Exception.Message) -like "*Account * was not found."){
                        Write-Host "Warning: Account with '$($Oper.id)' is not found, It has been deleted or does not exist. " -ForegroundColor Yellow                        
                    }
                    elseif($Oper.op -eq 'Add'){
                        Write-Host "Warning: Failed to add property '$($temp -join '.') = $($($Oper.Value))' in Account '$($Oper.id)'. ERROR: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                    elseif($Oper.op -eq 'Replace'){
                        Write-Host "Warning: Failed to update property '$($temp -join '.') = $($($Oper.Value))' in Account '$($Oper.id)'. ERROR: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                    elseif($Oper.op -eq 'Remove'){
                        Write-Host "Warning: Failed to remove property '$($temp -join '.')' in Account '$($Oper.id)'. ERROR: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                    else{
                        Write-Host "Warning: Failed to update Account '$($Oper.id)'. ERROR: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        Write-Progress -Activity "Updating Accounts..." -Complete
        
    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }

}

function Remove-AccountsbyID{
<#
    .SYNOPSIS
        Removes list of Accounts based on Account IDs or SafeName
    .DESCRIPTION
        It utilises PsPAS module to remove list of accounts based on given Account IDs or SafeName. 
    .EXAMPLE
        PS> Remove-AccountsbyID 
    .EXAMPLE
        PS> Get-Help Remove-AccountsbyID
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.2
        Creation Date   : 29/6/2023
        Purpose/Change  : Added functionality to handle deletion of accounts with ssh via gen1 api call
   
    .LINK
        https://pspas.pspete.dev/commands/Remove-PASAccount
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Delete%20Account.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )

    try{        
       
        Remove-Variable InputList -Force -ErrorAction SilentlyContinue

        $AccountType = Menu -menuItems @("Delete Accounts with Password", "Delete Accounts with SSH", "Cancel")

        $RemoveType = Menu -menuItems @("Delete by Account IDs", "Delete by SafeName", "Cancel")

        if($RemoveType -eq "Delete by SafeName"){
            $InputList = Read-MultiLineInputBoxDialog -Message "Enter SafeName for which Accounts needs to be deleted. Multiple SafeNames can be provided in separate lines." -WindowTitle "SafeName of Accounts to be Deleted " -DefaultText ""
        }elseif($RemoveType -eq "Delete by Account IDs"){
            $InputList = Read-MultiLineInputBoxDialog -Message "Enter Account IDs which needs to be deleted. Multiple account IDs can be provided in separate lines." -WindowTitle "Account IDs to Delete " -DefaultText ""
        }else{
            return
        }

        $InputList = $InputList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($InputList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        $AccountIDsList = @()
                    
        if($RemoveType -eq "Delete by SafeName"){
            #Get Accounts for each safeName           
            $CheckFlag = $false

            foreach ($item in $InputList)
            {
                $Result = $null
                try{
                    
                    $Result = Get-PASAccount -safeName $item -ErrorAction Stop                       
                    
                    if(($Result|Measure-Object).Count -ne 0){
                        $AccountIDsList += $Result.id             
                    }else{
                        Write-Host -Object "Warning: No account found for safeName = '$item'. " -ForegroundColor Yellow
                    }
                }catch{
                    Write-Host -Object "Warning: $($_.Exception.Message) " -ForegroundColor Yellow
                    $CheckFlag = $true
                }
            }

            #Validate inputs
            if($CheckFlag){
                Write-Host "Please validate the inputs. " -ForegroundColor Yellow 
                return
            }
        
            if(($AccountIDsList|Measure-Object).Count -eq 0){
                Write-Host "No Accounts found for given list of SafeName. " -ForegroundColor Yellow 
                return
            }
            
        }else{
            $AccountIDsList = $InputList
        }

        #Delete Accounts
        Write-Progress -Activity "Deleting Accounts..." -PercentComplete -1
        
        foreach ($item in $AccountIDsList)
            { 
                try{
                    if($AccountType -eq 'Delete Accounts with SSH'){
                        Remove-PASAccount -AccountID $item -UseGen1API -Confirm:$false -ErrorAction Stop
                    }else{
                        Remove-PASAccount -AccountID $item -Confirm:$false -ErrorAction Stop
                    }
                    Write-Host "SUCCESS: Account with id $($item) is deleted. " -ForegroundColor Green
                }catch{
                    if($($_.Exception.Message) -like "*Account [[]$($item)[]] was not found." -or $($_.Exception.Message).trim() -like '[[]404[]] Failed to delete account *. Reason: Account not found.'){
                        Write-Host "Warning: Account with id '$($item)' is not found, It has been already deleted or did not exist." -ForegroundColor Yellow                        
                    }elseif($($_.Exception.Message).trim() -eq '[403]'){
                        Write-Host -Object "Warning: Failed to delete account with id '$($item)'. Validate if you have permission to delete this account. Error code [403] " -ForegroundColor Yellow
                    }else{
                        Write-Host -Object "Warning: Failed to delete account with id '$($item)'. $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }
            
        Write-Progress -Activity "Deleting Accounts..." -Complete
        
    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    
}

function Invoke-CredentialsVerifications{
<#
    .SYNOPSIS
        Invokes credentials verification for Accounts based on Account IDs
    .DESCRIPTION
        It utilises PsPAS module to invoke credentials verification for Accounts based on Account IDs.
    .EXAMPLE
        PS> Invoke-CredentialsVerifications
    .EXAMPLE
        PS> Get-Help Invoke-CredentialsVerifications
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 22/1/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Invoke-PASCPMOperation
    .LINK                   
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Verify-credentials-v9-10.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )

    try{        
       
        Remove-Variable InputList -Force -ErrorAction SilentlyContinue

        $InputList = Read-MultiLineInputBoxDialog -Message "Enter Account IDs for which credentials needs to be verified. Multiple account IDs can be provided in separate lines." -WindowTitle "Account IDs to Verify Credentials " -DefaultText ""

        $InputList = $InputList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($InputList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        Write-Progress -Activity "Marking Accounts for Credential Verification..." -PercentComplete -1
        
        foreach ($item in $InputList)
            { 
                $item = $item.trim()
                try{
                    Invoke-PASCPMOperation -AccountID $item -VerifyTask -Confirm:$false -ErrorAction Stop
                    Write-Host "SUCCESS: Account id '$($item)' marked for credentials verification. " -ForegroundColor Green
                }catch{
                    if($($_.Exception.Message) -like "*Account [[]$($item)[]] was not found."){
                        Write-Host "Warning: Account with id '$($item)' is not found, It has been already deleted or did not exist." -ForegroundColor Yellow                        
                    }
                    else{
                        Write-Host -Object "Warning: Failed to mark Account id = '$($item)' for credentials verification . $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }
            
        Write-Progress -Activity "Marking Accounts for Credential Verification..." -Complete
        
    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    
}

function Invoke-ImmediateChangeCreds{
<#
    .SYNOPSIS
        Invokes immediate changes credentials for Accounts based on Account IDs
    .DESCRIPTION
        It utilises PsPAS module to mark accounts for immediate changes credentials based on Account IDs
    .EXAMPLE
        PS> Invoke-ImmediateChangeCreds
    .EXAMPLE
        PS> Get-Help Invoke-ImmediateChangeCreds
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 25/1/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Invoke-PASCPMOperation
    .LINK                   
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Change-credentials-immediately.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )

    try{        
       
        Remove-Variable InputList -Force -ErrorAction SilentlyContinue
        
        # Create the Label2.
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Size(15,182)
        $label.Size = New-Object System.Drawing.Size(100,20)
        $label.AutoSize = $true
        $label.Text = 'Change for all in the same group? '
        $label.Font = [System.Drawing.Font]::new('Arial',8,[System.Drawing.FontStyle]::Bold)

        # Create the Checkbox.
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Checked = $false
        $checkbox.Location = New-Object System.Drawing.Size(203,180)
        $checkbox.Size = New-Object System.Drawing.Size(20,20)
        
        $InputList = Read-MultiLineInputBoxDialog -Message "Enter Account IDs for which credentials change needs to be marked. Multiple account IDs can be provided in separate lines." -WindowTitle "Account IDs to Change Credentials " -DefaultText "" -checkbox $checkbox -label2 $label

        $InputList = $InputList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($InputList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        Write-Progress -Activity "Marking Accounts for Credentials Change..." -PercentComplete -1
        
        foreach ($item in $InputList)
            { 
                $item = $item.trim()
                try{
                    if($checkbox.Checked){
                        Invoke-PASCPMOperation -AccountID $item -ChangeTask -ChangeEntireGroup $true -Confirm:$false -ErrorAction Stop
                        Write-Host "SUCCESS: Account id '$($item)' marked for immediate credentials change along with all the accounts that belong to the same group. " -ForegroundColor Green
                    }else{
                        Invoke-PASCPMOperation -AccountID $item -ChangeTask -ChangeEntireGroup $false -Confirm:$false -ErrorAction Stop
                        Write-Host "SUCCESS: Account id '$($item)' marked for immediate credentials change. " -ForegroundColor Green
                    }
                }catch{
                    if($($_.Exception.Message) -like "*Account [[]$($item)[]] was not found."){
                        Write-Host "Warning: Account with id '$($item)' is not found, It has been already deleted or did not exist." -ForegroundColor Yellow                        
                    }
                    else{
                        Write-Host -Object "Warning: Failed to mark Account id = '$($item)' for credential change. $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }
            
        Write-Progress -Activity "Marking Accounts for Credentials Change..." -Complete
        
    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    
}
 
function Invoke-ReconcileCredentials{
<#
    .SYNOPSIS
        Marks account for credentials reconciliation based on Account IDs
    .DESCRIPTION
        It utilises PsPAS module to mark accounts for credentials reconciliation  based on Account IDs
    .EXAMPLE
        PS> Invoke-ReconcileCredentials
    .EXAMPLE
        PS> Get-Help Invoke-ReconcileCredentials
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 26/1/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Invoke-PASCPMOperation
    .LINK                   
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Reconcile-account.htm?
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )

    try{        
       
        Remove-Variable InputList -Force -ErrorAction SilentlyContinue

        $InputList = Read-MultiLineInputBoxDialog -Message "Enter Account IDs for which credentials needs to be reconciled. Multiple account IDs can be provided in separate lines." -WindowTitle "Account IDs to Reconcile Credentials " -DefaultText ""

        $InputList = $InputList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($InputList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        Write-Progress -Activity "Marking Accounts for Credential Reconciliation..." -PercentComplete -1
        
        foreach ($item in $InputList)
            { 
                $item = $item.trim()
                try{
                    Invoke-PASCPMOperation -AccountID $item -ReconcileTask -Confirm:$false -ErrorAction Stop
                    Write-Host "SUCCESS: Account id '$($item)' marked for credentials reconciliation. " -ForegroundColor Green
                }catch{
                    if($($_.Exception.Message) -like "*Account [[]$($item)[]] was not found."){
                        Write-Host "Warning: Account with id '$($item)' is not found, It has been already deleted or did not exist." -ForegroundColor Yellow                        
                    }
                    else{
                        Write-Host -Object "Warning: Failed to mark Account id = '$($item)' to reconcile credentials. $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }
            
        Write-Progress -Activity "Marking Accounts for Credential Reconciliation..." -Complete
        
    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    
}


function Export-PlatformsZips{
<#
    .SYNOPSIS
        Exports platform as zip containing .xml and .ini files.
    .DESCRIPTION
        It utilises PsPAS module to exports platform as zip containing .xml and .ini files. 
        Zip files will be exported under the current directory in folder like PlatformsZips_20221212-031402.
    .EXAMPLE
        PS> Export-PlatformsZips
        2 platform exported under folder 'C:\Users\UserName\Desktop\PlatformsZips_20221212-031402'. 
    .EXAMPLE
        PS> Get-Help Export-PlatformsZips
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 17/2/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Export-PASPlatform
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/ExportPlatform.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $Path = "$global:targetFolder\PlatformsZips_$(Get-Date -Format yyyyMMdd-hhmmss)"

    try{        
       
        Remove-Variable PlatformIDList -Force -ErrorAction SilentlyContinue
                
        $PlatformIDList = Read-MultiLineInputBoxDialog -Message "Please enter Platform IDs. Multiple IDs can be provided in separate lines." -WindowTitle "Platform IDs List" -DefaultText ""
        $PlatformIDList = $PlatformIDList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($PlatformIDList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        Write-Progress -Activity "Getting Information..." -PercentComplete -1

        $ResultList = @()

        foreach ($item in $PlatformIDList)
            { 
                if(-Not(Test-Path -Path $Path)){
                    New-Item -Path $Path -ItemType Directory -ErrorAction Stop|Out-Null
                }

                $Result = $null
                try{

                    $Result = Export-PASPlatform -PlatformID $item -path $Path -ErrorAction Stop
                    Write-Host -Object "Platform '$item' exported at '$($Result.FullName)'." -ForegroundColor Green
                    $ResultList += $Result

                }catch{
                    if($($_.Exception.Message -like "*Platform [[]$item[]] is inactive.") ){
                        Write-Host -Object "Warning: Platform '$item' is inactive. " -ForegroundColor Yellow
                    }elseif($($_.Exception.Message -like "*There are some invalid parameters: Platform [[]$item[]] was not found.") ){
                        Write-Host -Object "Warning: Platform '$item' was not found. " -ForegroundColor Yellow
                    }else{
                        Write-Host -Object "Warning: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        Write-Progress -Activity "Getting Information..." -Complete

        #Export CSV to report path
        if(($ResultList|Measure-Object).Count -ne 0){
            Write-Host "$(($ResultList|Measure-Object).Count) platform exported under '$($Path)' directory. " -ForegroundColor Green
        }else{
            Write-Host "No platform was found. " -ForegroundColor Green
            Remove-Item -Path $Path -Force -Confirm:$false -ErrorAction SilentlyContinue
        }

    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to export platforms. $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Import-PlatformsZips{
<#
    .SYNOPSIS
        Import platforms as zip files containing .xml and .ini files.
    .DESCRIPTION
        It utilises PsPAS module to import platforms as zip containing .xml and .ini files. 
        input can be single zip file or folder containing multiple zip files 
    .EXAMPLE
        PS> Import-PlatformsZips
    .EXAMPLE
        PS> Get-Help Import-PlatformsZips
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 15/2/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Import-PASPlatform
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/ImportPlatform.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    try{        
        $InputType = Menu -menuItems @("Import single platform", "Import bulk platforms", "Cancel")
        
        Remove-Variable SelectedPath -Force -ErrorAction SilentlyContinue
            
        if($InputType -eq 'Import single platform'){
            $SelectedPath = Get-FileName -InitialDirectory $PWD -Filter "Zip Files (*.zip)|*.zip" -WindowTitle "Platform zip file"            
        }elseif($InputType -eq 'Import bulk platforms'){
            $SelectedPath = Get-FolderName -SelectedPath $PWD -Description "Select the Folder containing platform Zip files." -ShowNewFolderButton            
        }else{
            return
        }      

        $ZipFiles = Get-ChildItem -Path $SelectedPath -Recurse -Include '*.zip' -ErrorAction SilentlyContinue

        if(($ZipFiles|Measure-Object).Count -eq 0){
            Write-host "No zip files found. " -ForegroundColor Yellow
            return
        }

        Write-Progress -Activity "Importing Platform..." -PercentComplete -1

        $ResultList = @()

        foreach ($file in $ZipFiles)
            { 
                $Result = $null
                try{
                    $Result = Import-PASPlatform -ImportFile $file.FullName -Confirm:$false -ErrorAction Stop
                    Write-Host -Object "File '$($file.PSChildName)' is imported with platformID = '$($Result.PlatformID)'." -ForegroundColor Green
                    $ResultList += $Result

                }catch{
                    if($($_.Exception.Message -like "[[]409[]] Failed to import target account platform. Reason: *, Creation of platform * failed because a platform with the same name already exists") ){
                        Write-Host -Object "Warning: Failed to import zip file '$($file.PSChildName)'. Reason: $($_.Exception.Message -split 'Reason:'|Select-Object -Last 1). " -ForegroundColor Yellow
                    }elseif($($_.Exception.Message -like "[[]400[]] Platform zip file does not contain a policy INI file.") ){
                        Write-Host -Object "Warning: Zip file '$($file.PSChildName)' is invalid, Make sure it contains valid policy INI and XML files. " -ForegroundColor Yellow
                    }else{
                        Write-Host -Object "Warning: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        Write-Progress -Activity "Importing Platform..." -Complete

        Write-Host "$(($ResultList|Measure-Object).Count) platform imported. " -ForegroundColor Green
        
    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to import platforms. $($_.Exception.Message)" -ForegroundColor Red
    }
}


function Export-AccountGroupsReport{
<#
    .SYNOPSIS
        Exports list of account groups based on SafeName
    .DESCRIPTION
        It utilises PsPAS module to export account groups list for the given safe names and saves it as CSV in the given directory. 
        Exported CSV file will be named like "-AccountGroupList.csv". 
    .EXAMPLE
        PS> Export-AccountGroupsReport
        Result saved to 'C:\Users\UserName\Desktop\20221212-031402-AccountGroupList.csv'. 
    .EXAMPLE
        PS> Get-Help Export-AccountGroupsReport
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 28/1/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Get-PASAccountGroup
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/GetAccountGroupBySafe.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-AccountGroupList.csv"

    try{        
       
        Remove-Variable InputList -Force -ErrorAction SilentlyContinue

        $InputList = Read-MultiLineInputBoxDialog -Message "Enter SafeName containing account groups. Multiple values can be provided in separate lines." -WindowTitle "List of SafeName " -DefaultText ""

        $InputList = $InputList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($InputList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        Write-Progress -Activity "Getting Information..." -PercentComplete -1
        
        $ResultList = @()

        foreach ($item in $InputList)
            { 
                $Result = $null
                try{
                    
                    $Result =  Get-PASAccountGroup -Safe $item -ErrorAction Stop 

                    if(($Result|Measure-Object).Count -ne 0){
                        $ResultList += $Result              
                    }else{
                        Write-Host -Object "Warning: No account group found for SafeName = '$item'. " -ForegroundColor Yellow
                    }
                }catch{
                    if($($_.Exception.Message) -like "[[]404[]] Account group [[]$item[]] was not found."){
                        Write-Host "Warning: Account group = '$item' is not found. " -ForegroundColor Yellow
                    }elseif($($_.Exception.Message) -like "[[]403[]] Authorization problem while working with Safe $item."){
                        Write-Host -Object "Warning: Validate safename = '$item'.$($_.Exception.Message) " -ForegroundColor Yellow                        
                    }else{
                        Write-Host -Object "Warning: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        #Create CSV object
        $csv = $ResultList|ForEach-Object{
                [PsCustomObject]@{
                                              
                        SafeName = $_.Safe
                        GroupID = $_.GroupID
                        GroupName = $_.GroupName
                        GroupPlatformID = $_.GroupPlatformID                           
                }
        }

        Write-Progress -Activity "Getting Information..." -Complete

        #Export CSV to report path
        if(($csv|Measure-Object).Count -ne 0){
            try{
                $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Host "SUCCESS: Account group list saved to '$($Path)'. " -ForegroundColor Green
            }catch{
                Write-Host "ERROR: Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
            }
        }

    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to export account group. $($_.Exception.Message)" -ForegroundColor Red
    }
    
}

function Export-AccountGroupsMemebrs{
<#
    .SYNOPSIS
        Exports list of account group members based on Account group names
    .DESCRIPTION
        It utilises PsPAS module to export list of account group members for the given Account group names and saves it as CSV in the given directory. 
        Exported CSV file will be named like "-AccountGroupsMemebrs.csv". 
    .EXAMPLE
        PS> Export-AccountGroupsMemebrs
        Result saved to 'C:\Users\UserName\Desktop\20221212-031402-AccountGroupsMemebrs.csv'. 
    .EXAMPLE
        PS> Get-Help Export-AccountGroupsMemebrs
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.1
        Creation Date   : 10/2/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Get-PASAccountGroupMember
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/GetAccountGroupMembers.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-AccountGroupsMemebrs.csv"

    try{        
       
        Remove-Variable InputList -Force -ErrorAction SilentlyContinue

        $InputList = Read-MultiLineInputBoxDialog -Message "Enter Account Group Name containing members. Multiple values can be provided in separate lines." -WindowTitle "List of Account Group Names " -DefaultText ""

        $InputList = $InputList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($InputList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        Write-Progress -Activity "Getting Information..." -PercentComplete -1
        
        #Get Groups List
        $SafesList = Get-PASSafe -ErrorAction Stop
        $TempInputList = @()

        foreach ($Saf in $SafesList)
        {
            $TempInputList += Get-PASAccountGroup -Safe $Saf.safeName -ErrorAction Stop
        }

        $NewInputList = @()

        foreach ($Value in $InputList)
        {
            $tempList = $TempInputList | Where-Object {$_.GroupName -eq $Value}
            if(($tempList|Measure-Object).Count -eq 0){
                Write-host "Warning: No Account Group found for Group Name = '$Value'." -ForegroundColor Yellow 
            }else{
                $NewInputList += $tempList
            }
        }
        
        #Get Account Group Member

        $ResultList = @()

        foreach ($item in $NewInputList)
            { 
                $Result = $null
                try{
                    
                    $Result =  Get-PASAccountGroupMember -GroupID $item.GroupID -ErrorAction Stop
                    $Result | Add-Member -MemberType NoteProperty -Name 'GroupId' -Value $item.GroupID
                    $Result | Add-Member -MemberType NoteProperty -Name 'GroupName' -Value $item.GroupName

                    if(($Result|Measure-Object).Count -ne 0){
                        $ResultList += $Result              
                    }else{
                        Write-Host -Object "Warning: No account group members found for GroupName = '$($item.GroupName)' with GroupID = '$($item.GroupID)'. " -ForegroundColor Yellow
                    }
                }catch{
                    if($($_.Exception.Message) -like "[[]404[]] Account group [[]$($item.GroupID)[]] was not found."){
                        Write-Host "Warning: Account GroupName = '$($item.GroupName)' with GroupID = '$($item.GroupID)' is not found. " -ForegroundColor Yellow
                    }else{
                        Write-Host -Object "Warning: $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        #Create CSV object
        $csv = $ResultList|ForEach-Object{
                [PsCustomObject]@{
                                              
                        GroupID = $_.GroupID
                        GroupName = $_.GroupName
                        AccountID = $_.AccountID  
                        SafeName = $_.SafeName
                        PlatformID = $_.PlatformID  
                        Address = $_.Address
                        UserName = $_.UserName                                                  
                }
        }

        Write-Progress -Activity "Getting Information..." -Complete

        #Export CSV to report path
        if(($csv|Measure-Object).Count -ne 0){
            try{
                $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Host "SUCCESS: Account group members list saved to '$($Path)'. " -ForegroundColor Green
            }catch{
                Write-Host "ERROR: Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
            }
        }

    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to export account group members. $($_.Exception.Message)" -ForegroundColor Red
    }
    
}

function Add-AccountGroupMembers{
<#
    .SYNOPSIS
        Adds list of safe members in Account groups.
    .DESCRIPTION
        It utilises PsPAS module to add list of safe members in Account groups. SafeName, GroupName and Members to add are given as CSV list.
    .EXAMPLE
        PS> Add-AccountGroupMembers 
    .EXAMPLE
        PS> Get-Help Add-AccountGroupMembers
    .INPUTS
        CSV
    .NOTES
        Version         : 1.0
        Creation Date   : 25/03/2023
        Purpose/Change  : Initial development
    
    .LINK
        https://pspas.pspete.dev/commands/Add-PASAccountGroupMember
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Add-account-to-account-group.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    try{        
        
        Remove-Variable InputDetails -Force -ErrorAction SilentlyContinue
        
        $InputDetails = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Account Groups and Members Details"

        $RequiredColumns = @('SafeName','GroupName','AccountName' )
    
        $FormattedInput = Test-SelectedInputCSV -FilePath $InputDetails -RequiedColumns $RequiredColumns

        if($null -eq $FormattedInput){
            return
        }

        $FormattedInput | Foreach-Object {$_.PSObject.Properties | Foreach-Object {$_.Value = $_.Value.Trim()}  }
        
        Write-Progress -Activity "Getting Information..." -PercentComplete -1
        
        #Get Accounts List and Groups
        $AccountsList = @()
        $AccountGroups = @()
        
        foreach ($Safe in ($FormattedInput.SafeName|Select-Object -Unique))
        {
            try{
                $TempAccount = $null
                $TempGroup = $null
                $TempAccount = Get-PASAccount -safeName $Safe -ErrorAction Stop
                $TempGroup = Get-PASAccountGroup -Safe $Safe -ErrorAction Stop
            }catch{
                Write-Host -Object "Warning: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        
            if($null -ne $TempAccount){
                $AccountsList += $TempAccount
            }
            if($null -ne $TempGroup){
                $AccountGroups += $TempGroup
            }
        }
        
        Write-Progress -Activity "Getting Information..." -Completed
        
        Write-Progress -Activity "Adding Accounts..." -PercentComplete -1        
        
        foreach ($item in $FormattedInput)
            { 
                $Result = $null
                try{
                    
                    $Group = $AccountGroups| Where-Object {$_.GroupName -eq $item.GroupName -and $_.Safe -eq $item.SafeName}
                    if(($Group|Measure).Count -eq 0){
                        Write-Host -Object "Warning: No Account group found with name '$($item.GroupName)' under safe '$($item.SafeName)'." -ForegroundColor Yellow
                        continue
                    }elseif(($Group|Measure).Count -gt 1){
                        Write-Host -Object "Warning: Multiple Account group found with name '$($item.GroupName)' under safe '$($item.SafeName)', Found $($($Group|Measure).Count)." -ForegroundColor Yellow
                        continue
                    }

                    
                    $UserAccount = $AccountsList| Where-Object {$_.Name -eq $item.AccountName -and $_.safeName -eq $item.SafeName}
                    if(($UserAccount|Measure).Count -eq 0){
                        Write-Host -Object "Warning: No Account found with name '$($item.AccountName)' under safe '$($item.SafeName)'." -ForegroundColor Yellow
                        continue
                    }elseif(($UserAccount|Measure).Count -gt 1){
                        Write-Host -Object "Warning: Multiple Account found with name '$($item.AccountName)' under safe '$($item.SafeName)', Found $($($UserAccount|Measure).Count)." -ForegroundColor Yellow
                        continue
                    }

                    $Result =  Add-PASAccountGroupMember -GroupID $Group.GroupID -AccountID $UserAccount.id -ErrorAction Stop

                    if(($Result.AccountId|Measure-Object).Count -eq 1){
                        Write-Host -Object "SUCCESS: Account '$($item.AccountName)' is successfully added to Account group '$($item.GroupName)'." -ForegroundColor Green          
                    }elseif(($Result.AccountId|Measure-Object).Count -eq 0){
                        Write-Host -Object "Warning: Failed to add Account '$($item.AccountName)' to Account group '$($item.GroupName)'." -ForegroundColor Yellow          
                    }
                }catch{
                    if($_.Exception.Message -like '*Failed to add member to account group. Reason:*'){
                        Write-Host -Object "Warning: Failed to add Account '$($item.AccountName)' to Account group '$($item.GroupName)'. Reason : $($_.Exception.Message -split 'Reason:'|Select -Last 1) " -ForegroundColor Yellow
                    }else{
                        Write-Host -Object "Warning: Failed to add Account '$($item.AccountName)' to Account group '$($item.GroupName)'. Error : $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        Write-Progress -Activity "Adding Accounts..." -Completed

    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Completed
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        }
    
}

function Remove-AccountGroupMembers{
<#
    .SYNOPSIS
        Removes list of safe members from Account groups.
    .DESCRIPTION
        It utilises PsPAS module to remove list of safe members from Account groups. SafeName, GroupName and Members to add are given as CSV list.
    .EXAMPLE
        PS> Remove-AccountGroupMembers 
    .EXAMPLE
        PS> Get-Help Remove-AccountGroupMembers
    .INPUTS
        CSV
    .NOTES
        Version         : 1.0
        Creation Date   : 27/03/2023
        Purpose/Change  : Initial development
    
    .LINK
        https://pspas.pspete.dev/commands/Remove-PASAccountGroupMember
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/DeleteMemberFromAccountGroup.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    try{        
        
        Remove-Variable InputDetails -Force -ErrorAction SilentlyContinue
        
        $InputDetails = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Account Groups and Members Details"

        $RequiredColumns = @('SafeName','GroupName','AccountName' )
    
        $FormattedInput = Test-SelectedInputCSV -FilePath $InputDetails -RequiedColumns $RequiredColumns

        if($null -eq $FormattedInput){
            return
        }
        
        $FormattedInput | Foreach-Object {$_.PSObject.Properties | Foreach-Object {$_.Value = $_.Value.Trim()}  }

        Write-Progress -Activity "Getting Information..." -PercentComplete -1
        
        #Get Accounts List and Groups
        $AccountsList = @()
        $AccountGroups = @()
        
        foreach ($Safe in ($FormattedInput.SafeName|Select-Object -Unique))
        {
            try{
                $TempAccount = $null
                $TempGroup = $null
                $TempAccount = Get-PASAccount -safeName $Safe -ErrorAction Stop
                $TempGroup = Get-PASAccountGroup -Safe $Safe -ErrorAction Stop
            }catch{
                Write-Host -Object "Warning: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        
            if($null -ne $TempAccount){
                $AccountsList += $TempAccount
            }
            if($null -ne $TempGroup){
                $AccountGroups += $TempGroup
            }
        }
        
        Write-Progress -Activity "Getting Information..." -Completed
        
        Write-Progress -Activity "Removing Accounts..." -PercentComplete -1        
        
        foreach ($item in $FormattedInput)
            { 
                try{
                    
                    $Group = $AccountGroups| Where-Object {$_.GroupName -eq $item.GroupName -and $_.Safe -eq $item.SafeName}
                    if(($Group|Measure).Count -eq 0){
                        Write-Host -Object "Warning: No Account group found with name '$($item.GroupName)' under safe '$($item.SafeName)'." -ForegroundColor Yellow
                        continue
                    }elseif(($Group|Measure).Count -gt 1){
                        Write-Host -Object "Warning: Multiple Account group found with name '$($item.GroupName)' under safe '$($item.SafeName)', Found $($($Group|Measure).Count)." -ForegroundColor Yellow
                        continue
                    }

                    
                    $UserAccount = $AccountsList| Where-Object {$_.Name -eq $item.AccountName -and $_.safeName -eq $item.SafeName}
                    if(($UserAccount|Measure).Count -eq 0){
                        Write-Host -Object "Warning: No Account found with name '$($item.AccountName)' under safe '$($item.SafeName)'." -ForegroundColor Yellow
                        continue
                    }elseif(($UserAccount|Measure).Count -gt 1){
                        Write-Host -Object "Warning: Multiple Account found with name '$($item.AccountName)' under safe '$($item.SafeName)', Found $($($UserAccount|Measure).Count)." -ForegroundColor Yellow
                        continue
                    }
                    
                    Remove-PASAccountGroupMember -AccountID $UserAccount.id -GroupID $Group.GroupID -Confirm:$false -ErrorAction Stop

                    Write-Host -Object "SUCCESS: Account '$($item.AccountName)' Deleted from Account group '$($item.GroupName)'." -ForegroundColor Green          
                    
                }catch{
                    if($_.Exception.Message -like '*Failed to delete member from account group. Reason:*'){
                        Write-Host -Object "Warning: Failed to Delete Account '$($item.AccountName)' from Account group '$($item.GroupName)'. Reason : $($_.Exception.Message -split 'Reason:'|Select -Last 1) " -ForegroundColor Yellow
                    }else{
                        Write-Host -Object "Warning: Failed to Delete Account '$($item.AccountName)' from Account group '$($item.GroupName)'. Error : $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        Write-Progress -Activity "Removing Accounts..." -Completed

    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Completed
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        }
}
    
function Set-LinkedAccountsList{
<#
    .SYNOPSIS
        Associates a linked account to an existing account.
    .DESCRIPTION
        It utilises PsPAS module to Associate a Reconcile account, Logon account, or other type of linked account that is defined in the platform configuration.

        Requires the following Safe member authorizations:

        List accounts
            Required for both the Safe of the linked account and the Safe of the source account.
        Update account properties.
            Require for the Safe of the source account.
    .EXAMPLE
        PS> Set-LinkedAccountsList 
    .EXAMPLE
        PS> Get-Help Set-LinkedAccountsList
    .INPUTS
        CSV
    .NOTES
        Version         : 1.0
        Creation Date   : 30/03/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Set-PASLinkedAccount
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Link-account.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    try{        
       
        Remove-Variable InputDetails -Force -ErrorAction SilentlyContinue
        
        $InputDetails = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Accounts Details To Be Linked"

        $RequiredColumns = @('AccountName','SafeName','LinkedAccountName','LinkedSafeName','LinkedAccountFolder','ExtraPasswordIndex' )
    
        $FormattedInput = Test-SelectedInputCSV -FilePath $InputDetails -RequiedColumns $RequiredColumns
        
        if($null -eq $FormattedInput){
            return
        }

        $FormattedInput | Foreach-Object {$_.PSObject.Properties | Foreach-Object {$_.Value = $_.Value.Trim()}  }
        $FormattedInput | ForEach-Object {if($_.ExtraPasswordIndex -notin @(1,2,3)){ throw "Invalid csv. Column 'ExtraPasswordIndex' only accepts 1, 2 or 3 as valid values." }}
        
        Write-Progress -Activity "Getting Information..." -PercentComplete -1
        
        #Get Accounts List and Groups
        $AccountsList = @()        
        foreach ($Safe in $($FormattedInput.SafeName|Select-Object -Unique))
        {
            $Accounts = $null
            $Accounts = Get-PASAccount -safeName $Safe -ErrorAction SilentlyContinue

            if($null -ne $Accounts){
                $AccountsList += $Accounts
            }
        }

        $LinkedAccountsList = @()
        foreach ($Safe in $($FormattedInput.LinkedSafeName|Select-Object -Unique))
        {
            $Accounts = $null
            $Accounts = Get-PASAccount -safeName $Safe -ErrorAction SilentlyContinue

            if($null -ne $Accounts){
                $LinkedAccountsList += $Accounts
            }
        }

        Write-Progress -Activity "Getting Information..." -Completed
        
        Write-Progress -Activity "Linking Accounts..." -PercentComplete -1        
        
        foreach ($item in $FormattedInput)
            { 
                $Result = $null
                try{
                                        
                    $UserAccount = $AccountsList| Where-Object {$_.Name -eq $item.AccountName -and $_.safeName -eq $item.SafeName}

                    if(($UserAccount|Measure).Count -eq 0){
                        Write-Host -Object "Warning: No Account found with name '$($item.AccountName)' under safe '$($item.SafeName)'." -ForegroundColor Yellow
                        continue
                    }elseif(($UserAccount|Measure).Count -gt 1){
                        Write-Host -Object "Warning: Multiple Account found with name '$($item.AccountName)' under safe '$($item.SafeName)', Found $($($UserAccount|Measure).Count)." -ForegroundColor Yellow
                        continue
                    }

                    $LinkAccount = $LinkedAccountsList| Where-Object {$_.Name -eq $item.LinkedAccountName -and $_.safeName -eq $item.LinkedSafeName}

                    if(($LinkAccount|Measure).Count -eq 0){
                        Write-Host -Object "Warning: No Linked Account found with name '$($item.LinkedAccountName)' under safe '$($item.LinkedSafeName)'." -ForegroundColor Yellow
                        continue
                    }elseif(($LinkAccount|Measure).Count -gt 1){
                        Write-Host -Object "Warning: Multiple Linked Account found with name '$($item.LinkedAccountName)' under safe '$($item.LinkedSafeName)', Found $($($LinkAccount|Measure).Count)." -ForegroundColor Yellow
                        continue
                    }

                    Set-PASLinkedAccount -AccountID $UserAccount.id -safe $LinkAccount.safeName -name $LinkAccount.name -extraPasswordIndex $item.ExtraPasswordIndex -folder $item.LinkedAccountFolder -Confirm:$false -ErrorAction Stop

                    Write-Host -Object "SUCCESS: Account '$($UserAccount.Name)' is successfully associated to linked Account '$($LinkAccount.Name)' with ExtraPasswordIndex '$($item.ExtraPasswordIndex)'." -ForegroundColor Green          
                  
                   }catch{
                        Write-Host -Object "Warning: Failed to associate Account '$($item.AccountName)' with Linked Account '$($item.LinkedAccountName)'. Error : $($_.Exception.Message) " -ForegroundColor Yellow
                }
            }

        Write-Progress -Activity "Linking Accounts..." -Completed

    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Completed
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
     }
    
}

function Set-UnlinkAccountsList{
<#
    .SYNOPSIS
        Removes association between linked account and a source account.
    .DESCRIPTION
        It utilises PsPAS module to enables a user to remove the association between a linked account and a source account.

        To run this service, the user must have the following Safe member authorizations for the Safe where the source account is stored:
            List accounts
            Update account properties
            Manage Safe - This authorization is needed only when RequireManageSafeToClearLinkedAccount is enabled in the configuration
    .EXAMPLE
        PS> Set-UnlinkAccountsList 
    .EXAMPLE
        PS> Get-Help Set-UnlinkAccountsList
    .INPUTS
        CSV
    .NOTES
        Version         : 1.0
        Creation Date   : 31/03/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Clear-PASLinkedAccount
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Link-account-unlink.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    try{        
       
        Remove-Variable InputDetails -Force -ErrorAction SilentlyContinue
        
        $InputDetails = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Accounts Details To Be Linked"

        $RequiredColumns = @('AccountName','SafeName','ExtraPasswordIndex' )
    
        $FormattedInput = Test-SelectedInputCSV -FilePath $InputDetails -RequiedColumns $RequiredColumns
        
        if($null -eq $FormattedInput){
            return
        }

        $FormattedInput | Foreach-Object {$_.PSObject.Properties | Foreach-Object {$_.Value = $_.Value.Trim()}  }
        $FormattedInput | ForEach-Object {if($_.ExtraPasswordIndex -notin @(1,2,3)){ throw "Invalid csv. Column 'ExtraPasswordIndex' only accepts 1, 2 or 3 as valid values." }}
        
        Write-Progress -Activity "Getting Information..." -PercentComplete -1
        
        #Get Accounts List and Groups
        $AccountsList = @()        
        foreach ($Safe in $($FormattedInput.SafeName|Select-Object -Unique))
        {
            $Accounts = $null
            $Accounts = Get-PASAccount -safeName $Safe -ErrorAction SilentlyContinue

            if($null -ne $Accounts){
                $AccountsList += $Accounts
            }
        }
        
        Write-Progress -Activity "Getting Information..." -Completed
        
        Write-Progress -Activity "Unlinking Accounts..." -PercentComplete -1        
        
        foreach ($item in $FormattedInput)
            { 
                $Result = $null
                try{
                                        
                    $UserAccount = $AccountsList| Where-Object {$_.Name -eq $item.AccountName -and $_.safeName -eq $item.SafeName}

                    if(($UserAccount|Measure).Count -eq 0){
                        Write-Host -Object "Warning: No Account found with name '$($item.AccountName)' under safe '$($item.SafeName)'." -ForegroundColor Yellow
                        continue
                    }elseif(($UserAccount|Measure).Count -gt 1){
                        Write-Host -Object "Warning: Multiple Account found with name '$($item.AccountName)' under safe '$($item.SafeName)', Found $($($UserAccount|Measure).Count)." -ForegroundColor Yellow
                        continue
                    }

                    Clear-PASLinkedAccount -AccountID $UserAccount.id -extraPasswordIndex $item.ExtraPasswordIndex -Confirm:$false -ErrorAction Stop

                    Write-Host -Object "SUCCESS: Account '$($UserAccount.Name)' is successfully unlinked with ExtraPasswordIndex '$($item.ExtraPasswordIndex)'." -ForegroundColor Green          
                  
                   }catch{
                        Write-Host -Object "Warning: Failed to unlink Account '$($item.AccountName)'. Error : $($_.Exception.Message) " -ForegroundColor Yellow
                }
            }

        Write-Progress -Activity "Unlinking Accounts..." -Completed

    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Completed
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
     }    
}

function Export-UsersList{
<#
    .SYNOPSIS
        Exports list of users as CSV in the given directory.
    .DESCRIPTION
        It utilises PsPAS module to get the list of all users and exports it as CSV in the given directory. 
        exported CSV file named is like "-UsersList.csv". 
    .EXAMPLE
        PS> Export-UsersList
        Result saved to 'C:\Users\UserName\Desktop\20221212-031402-UsersList.csv'. 
    .EXAMPLE
        PS> Get-Help Export-UsersList
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 16/2/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Get-PASUser
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/get-users-api.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-UsersList.csv"

    try{        
        
        Write-Progress -Activity "Getting Information.." -PercentComplete -1
        
        $UsersList = Get-PASUser -ErrorAction Stop
                
        $Date = (Get-Date -Day 1 -Month 1 -Year 1970).Date

        $ResultList = @()

        foreach ($user in $UsersList)
        {
            $result = $null
            $result = Get-PASUser -id $user.id -ErrorAction Stop  
            if($null -ne $result){       
                $ResultList += $result
            }
        }
                        
        #Create CSV object
        $csv = $ResultList|ForEach-Object{
                [PsCustomObject]@{
                        ID = $_.id
                        Username = $_.username
                        BusinessEmail = $_.internet.businessEmail
                        Source = $_.Source
                        UserType = $_.userType
                        Suspended = $_.suspended
                        LastSuccessfulLoginDate = $(if($null -ne $_.lastSuccessfulLoginDate){$Date.AddSeconds($_.lastSuccessfulLoginDate).ToString('yyyy-MM-ddTHH:mm:ss')}else{''})
                        GroupsMembership = $($_.groupsMembership.groupName -join ', ')
                    }
        }

        Write-Progress -Activity "Getting Information.." -Complete

        #Export CSV to report path
        if(($csv|Measure-Object).Count -ne 0){
            try{
                $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Host "SUCCESS: Result saved to '$($Path)'. " -ForegroundColor Green
            }catch{
                Write-Host "ERROR: Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
            }
        }else{
            Write-Host "SUCCESS: No users found. " -ForegroundColor Green
        }

    }catch{
        #Handle exceptions for API failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to get Users information. $($_.Exception.Message)" -ForegroundColor Red
    }

    
}

function Export-GroupsList{
<#
    .SYNOPSIS
        Exports list of groups as CSV in the given directory.
    .DESCRIPTION
        It utilises PsPAS module to get the list of all groups and exports it as CSV in the given directory. 
        exported CSV file named is like "-GroupsList.csv". 
    .EXAMPLE
        PS> Export-UsersList
        Result saved to 'C:\Users\UserName\Desktop\20221212-031402-GroupsList.csv'. 
    .EXAMPLE
        PS> Get-Help Export-GroupsList
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 20/2/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Get-GroupsList
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/GetGroupsFromVault.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-GroupsList.csv"

    try{        
        
        Write-Progress -Activity "Getting Information.." -PercentComplete -1
        $GroupsList = Get-PASGroup -includeMembers $true -ErrorAction Stop
                                
        #Create CSV object
        $csv = $GroupsList|ForEach-Object{
                [PsCustomObject]@{
                        GroupId = $_.id
                        GroupName = $_.groupName
                        GroupType = $_.groupType
                        Members = $($_.members.UserName -join ', ')
                    }
        }

        Write-Progress -Activity "Getting Information.." -Complete

        #Export CSV to report path
        if(($csv|Measure-Object).Count -ne 0){
            try{
                $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Host "SUCCESS: Result saved to '$($Path)'. " -ForegroundColor Green
            }catch{
                Write-Host "ERROR: Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
            }
        }else{
            Write-Host "SUCCESS: No groups found. " -ForegroundColor Green
        }

    }catch{
        #Handle exceptions for API failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to get Groups information. $($_.Exception.Message)" -ForegroundColor Red
    }

    
}

function Export-ApplicationsList{
<#
    .SYNOPSIS
        Exports list of users as CSV in the given directory.
    .DESCRIPTION
        It utilises PsPAS module to get the list of all applications details and exports it as CSV in the given directory. 
        exported CSV file named is like "-ApplicationsList.csv". 
    .EXAMPLE
        PS> Export-UsersList
        Result saved to 'C:\Users\UserName\Desktop\20221212-031402-ApplicationsList.csv'. 
    .EXAMPLE
        PS> Get-Help Export-ApplicationsList
    .INPUTS
        CSV
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 25/2/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Get-PASApplication        
    .LINK
        https://pspas.pspete.dev/commands/Get-PASApplicationAuthenticationMethod
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/List%20Applications.htm
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/List%20all%20Authentication%20Methods%20of%20a%20Specific%20Application.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-ApplicationsList.csv"

    try{        
        
        Write-Progress -Activity "Getting Information.." -PercentComplete -1
        $AppsList = Get-PASApplication -ErrorAction Stop
               
        $date = (Get-Date -Day 1 -Month 1 -Year 1970).Date
        $ResultList = @()
        $MaxAuthMethods = 0

        foreach ($app in $AppsList)
        {
            $AuthMethod = $null
            $AuthMethod = Get-PASApplicationAuthenticationMethod -AppID $app.AppID -ErrorAction Stop
            if(($AuthMethod|Measure-Object).Count -gt $MaxAuthMethods)
            {
                $MaxAuthMethods = ($AuthMethod|Measure-Object).Count
            }

            $app | Add-Member -MemberType NoteProperty -Name 'AuthMethods' -Value $AuthMethod
            $ResultList += $app
        }
                        
        #Create CSV object
        $csv = @()
        foreach ($result in $ResultList)
        {        
            $row = New-Object -TypeName psobject

            $row | Add-Member -MemberType NoteProperty -Name 'AppID' -Value $result.AppID
            $row | Add-Member -MemberType NoteProperty -Name 'BusinessOwnerEmail' -Value $result.BusinessOwnerEmail
            $row | Add-Member -MemberType NoteProperty -Name 'BusinessOwnerFName' -Value $result.BusinessOwnerFName
            $row | Add-Member -MemberType NoteProperty -Name 'BusinessOwnerLName' -Value $result.BusinessOwnerLName
            $row | Add-Member -MemberType NoteProperty -Name 'BusinessOwnerPhone' -Value $result.BusinessOwnerPhone
            $row | Add-Member -MemberType NoteProperty -Name 'Description' -Value $result.Description            
            $row | Add-Member -MemberType NoteProperty -Name 'Disabled' -Value $result.Disabled
            $row | Add-Member -MemberType NoteProperty -Name 'ExpirationDate' -Value $(if($null -ne $result.ExpirationDate){$Date.AddSeconds($result.ExpirationDate).ToString('yyyy-MM-ddTHH:mm:ss')}else{''})
            $row | Add-Member -MemberType NoteProperty -Name 'Location' -Value $result.Location

            $first = $true
            foreach ($item in $result.AuthMethods)
            { 
                if($first -ne $true)
                {

                    $row = New-Object -TypeName psobject
                    
                    $row | Add-Member -MemberType NoteProperty -Name 'AppID' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'BusinessOwnerEmail' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'BusinessOwnerFName' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'BusinessOwnerLName' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'BusinessOwnerPhone' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'Description' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'Disabled' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'ExpirationDate' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'Location' -Value ''

                }

                $first = $false

                $row | Add-Member -MemberType NoteProperty -Name 'AllowInternalScripts' -Value $item.AllowInternalScripts
                $row | Add-Member -MemberType NoteProperty -Name 'AuthType' -Value $item.AuthType
                $row | Add-Member -MemberType NoteProperty -Name 'AuthValue' -Value $item.AuthValue
                $row | Add-Member -MemberType NoteProperty -Name 'Comment' -Value $item.Comment
            
                $csv += $row

            }
            
            if($first -eq $true){
                $row | Add-Member -MemberType NoteProperty -Name 'AllowInternalScripts' -Value ''
                $row | Add-Member -MemberType NoteProperty -Name 'AuthType' -Value ''
                $row | Add-Member -MemberType NoteProperty -Name 'AuthValue' -Value ''
                $row | Add-Member -MemberType NoteProperty -Name 'Comment' -Value ''
                $csv += $row
            }      
  
        }
        
        Write-Progress -Activity "Getting Information.." -Complete

        #Export CSV to report path
        if(($csv|Measure-Object).Count -ne 0){
            try{
                $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Host "SUCCESS: Result saved to '$($Path)'. " -ForegroundColor Green
            }catch{
                Write-Host "ERROR: Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
            }
        }else{
            Write-Host "SUCCESS: No applications found. " -ForegroundColor Green
        }

    }catch{
        #Handle exceptions for API failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to get application information. $($_.Exception.Message)" -ForegroundColor Red
    }

    
}

function Export-RecordingsDetails{
    <#
    .SYNOPSIS
        Exports list of Recordings Details as CSV in the given directory.
    .DESCRIPTION
        It utilises PsPAS module to get the list of all recordings details and exports it as CSV in the given directory. 
        exported CSV file named is like "-RecordingsDetails.csv". 
    .EXAMPLE
        PS> Export-RecordingsDetails
        Result saved to 'C:\Users\UserName\Desktop\20221212-031402-RecordingsDetails.csv'. 
    .EXAMPLE
        PS> Get-Help Export-RecordingsDetails
    .INPUTS
        CSV
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 25/2/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Get-PASPSMRecording  
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/GetRecordings.htm    
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    #Define CSV file path 
    $Path = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)-RecordingsDetails.csv"

    try{
        Remove-Variable InputList -Force -ErrorAction SilentlyContinue
    
        $InputList = Read-MultiLineInputBoxDialog -Message "Enter SafeName containing recordings. Multiple values can be provided in separate lines." -WindowTitle "List of SafeName " -DefaultText ""

        $InputList = $InputList -split [environment]::NewLine |ForEach-Object {$_.trim().toLower()} | Where-Object {$_.trim() -ne ''} | Select-Object -Unique
        
        if(($InputList|Measure-Object).Count -eq 0){
            Write-host "No valid input provided. " -ForegroundColor Yellow
            return
        }

        $date = (Get-Date -Day 1 -Month 1 -Year 1970).Date

        Write-Progress -Activity "Getting Information..." -PercentComplete -1
        
        $ResultList = @()

        foreach ($item in $InputList)
            { 
                $Result = $null
                try{
                    $Result = Get-PASPSMRecording -Safe $item -ErrorAction Stop

                    if(($Result|Measure-Object).Count -ne 0){
                        $ResultList += $Result              
                    }else{
                        Write-Host -Object "Warning: No recording found associated with safeName = '$item'. " -ForegroundColor Yellow
                    }
                }catch{
                    Write-Host -Object "Warning: $($_.Exception.Message) " -ForegroundColor Yellow
                }
            }

        
        #Create CSV object
        $csv = @()
        foreach ($result in $ResultList)
        {        
            $row = New-Object -TypeName psobject

            $row | Add-Member -MemberType NoteProperty -Name 'SessionID' -Value $result.SessionID
            $row | Add-Member -MemberType NoteProperty -Name 'SafeName' -Value $result.SafeName
            $row | Add-Member -MemberType NoteProperty -Name 'FileName' -Value $result.FileName
            $row | Add-Member -MemberType NoteProperty -Name 'Start' -Value $(if($result.Start -ne $null){$Date.AddSeconds($result.Start).ToString('yyyy-MM-ddTHH:mm:ss')}else{''})
            $row | Add-Member -MemberType NoteProperty -Name 'End' -Value $(if($result.End -ne $null){$Date.AddSeconds($result.End).ToString('yyyy-MM-ddTHH:mm:ss')}else{''})
            $row | Add-Member -MemberType NoteProperty -Name 'Duration' -Value $result.Duration            
            $row | Add-Member -MemberType NoteProperty -Name 'User' -Value $result.User
            $row | Add-Member -MemberType NoteProperty -Name 'RemoteMachine' -Value $result.RemoteMachine
            $row | Add-Member -MemberType NoteProperty -Name 'AccountUsername' -Value $result.AccountUsername
            $row | Add-Member -MemberType NoteProperty -Name 'AccountPlatformID' -Value $result.AccountPlatformID
            $row | Add-Member -MemberType NoteProperty -Name 'AccountAddress' -Value $result.AccountAddress
            $row | Add-Member -MemberType NoteProperty -Name 'ConnectionComponentID' -Value $result.ConnectionComponentID
            $row | Add-Member -MemberType NoteProperty -Name 'FromIP' -Value $result.FromIP

            $first = $true
            foreach ($item in $result.RecordingFiles)
            {
                if($first -ne $true)
                {

                    $row = New-Object -TypeName psobject
                                        
                    $row | Add-Member -MemberType NoteProperty -Name 'SessionID' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'SafeName' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'FileName' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'Start' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'End' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'Duration' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'User' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'RemoteMachine' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'AccountUsername' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'AccountPlatformID' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'AccountAddress' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'ConnectionComponentID' -Value ''
                    $row | Add-Member -MemberType NoteProperty -Name 'FromIP' -Value ''                 
                }

                $first = $false
               
                $row | Add-Member -MemberType NoteProperty -Name 'RecordingFileName' -Value $item.FileName
                $row | Add-Member -MemberType NoteProperty -Name 'RecordingType' -Value $item.RecordingType
                $row | Add-Member -MemberType NoteProperty -Name 'RecordingFileSize' -Value $(""+[Math]::Round($($item.FileSize/1kb),3)+' KB')
                $row | Add-Member -MemberType NoteProperty -Name 'RecordingCompressedFileSize' -Value $(""+[Math]::Round(($item.CompressedFileSize/1kb),3)+' KB')
            
                $csv += $row

            }
            
            if($first -eq $true){
                $row | Add-Member -MemberType NoteProperty -Name 'RecordingFileName' -Value ''
                $row | Add-Member -MemberType NoteProperty -Name 'RecordingType' -Value ''
                $row | Add-Member -MemberType NoteProperty -Name 'RecordingFileSize' -Value ''
                $row | Add-Member -MemberType NoteProperty -Name 'RecordingCompressedFileSize' -Value ''
                
                $csv += $row
             }                              
      
        }

        Write-Progress -Activity "Getting Information.." -Complete
        #Export CSV to report path
        if(($csv|Measure-Object).Count -ne 0){
            try{
                $csv | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
                Write-Host "SUCCESS: Result saved to '$($Path)'. " -ForegroundColor Green
            }catch{
                Write-Host "ERROR: Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
            }
        }else{
            Write-Host "SUCCESS: No recordings found. " -ForegroundColor Green
        }
    }catch{
        #Handle exceptions for API failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to get recordings information. $($_.Exception.Message)" -ForegroundColor Red
    }


}

function Import-ConnectionComponents{
<#
    .SYNOPSIS
        Imports connection components as zip files
    .DESCRIPTION
        It utilises PsPAS module to import connection components as zip files. 
        input can be single zip file or folder containing multiple zip files 
    .EXAMPLE
        PS> Import-ConnectionComponents
    .EXAMPLE
        PS> Get-Help Import-ConnectionComponents
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        Version         : 1.0
        Creation Date   : 26/2/2023
        Purpose/Change  : Initial development
   
    .LINK
        https://pspas.pspete.dev/commands/Import-PASConnectionComponent
    .LINK
        https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/ImportPlatform.htm
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    try{        
        $InputType = Menu -menuItems @("Import single connection component", "Import bulk connection components", "Cancel")
        
        Remove-Variable SelectedPath -Force -ErrorAction SilentlyContinue
            
        if($InputType -eq 'Import single connection component'){
            $SelectedPath = Get-FileName -InitialDirectory $PWD -Filter "Zip Files (*.zip)|*.zip" -WindowTitle "Connection component zip file"            
        }elseif($InputType -eq 'Import bulk connection components'){
            $SelectedPath = Get-FolderName -SelectedPath $PWD -Description "Select the Folder containing connection component Zip files." -ShowNewFolderButton            
        }else{
            return
        }      

        $ZipFiles = Get-ChildItem -Path $SelectedPath -Recurse -Include '*.zip' -ErrorAction SilentlyContinue

        if(($ZipFiles|Measure-Object).Count -eq 0){
            Write-host "No zip files found. " -ForegroundColor Yellow
            return
        }

        Write-Progress -Activity "Importing connection components..." -PercentComplete -1

        $ResultList = @()

        foreach ($file in $ZipFiles)
            { 
                $Result = $null
                try{
                    $Result = Import-PASConnectionComponent -ImportFile $file.FullName -Confirm:$false -ErrorAction Stop
                    Write-Host -Object "File '$($file.PSChildName)' is imported with ConnectionComponentID = '$($Result.ConnectionComponentID)'." -ForegroundColor Green
                    $ResultList += $Result

                }catch{                
                    if($($_.Exception.Message -like "[[]400[]] The import file contains invalid files. Refer to log for more information.") ){
                        Write-Host -Object "Warning: Zip file '$($file.PSChildName)' contains invalid files, provide valid connection components files. " -ForegroundColor Yellow
                    }else{
                        Write-Host -Object "Warning: Importing Zip file '$($file.PSChildName)' failed. $($_.Exception.Message) " -ForegroundColor Yellow
                    }
                }
            }

        Write-Progress -Activity "Importing connection components..." -Complete

        Write-Host "$(($ResultList|Measure-Object).Count) connection components imported. " -ForegroundColor Green
        
    }catch{
        #Handle exceptions for API failures and other failures
        Write-Progress -Activity "Issue Occured..." -Complete
        Write-Host "ERROR: Failed to import connection components. $($_.Exception.Message)" -ForegroundColor Red
    }
}


function Import-CYBAUTOAccountGroupsCSV {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    Remove-Variable groupsFile -ErrorAction SilentlyContinue
    $groupsFile = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "Account Group Definitions File"
    if ($null -eq $groupsFile -or $groupsFile.Length -eq 0) {
        Write-host "No File Selected" -ForegroundColor Yellow
        return
    }
    Import-Csv -Path $groupsFile | ForEach-Object {
        try { 
            $props = @{}
            foreach ( $arg in $_.psobject.properties.name ) {
                $props[$arg] = $_.$arg
            }
            $safeObject = Get-PasSafeName -SafeName $_.Safe -ErrorAction Stop
            $platform = Get-PASPlatform -PlatformID $_.GroupPlatformID  
            New-PASAccountGroup -GroupName $_.GroupName -GroupPlatformID $platform.PlatformID -Safe $safeObject.SafeName >> $global:logFileName
            $details = "Created Account $($_.GroupName) with Platform $($_.GroupPlatformID)"
        }
        catch { 
            $_ >> $global:logFileName
            $details = "Unable to Create Account Group $($props.GroupName) with Platform $($props.GroupPlatformID)" 
            Write-Host -ForegroundColor Red $details
            Write-Host -ForegroundColor Red $_
        }
        finally {
            [LogEvent]::new("AddAccountGroup", $details) | Export-Csv $global:reportFileName -NoTypeInformation -Append
        }
    }

}


function Get-PasSafeName($SafeName){
    try{
        $Safe = Get-PASSafe -SafeName $SafeName -ErrorAction Stop
    }catch{
        if($_.Exception.Message -like '*CyberArk * does not meet the minimum version requirement of * for Get-PasSafe*'){
            try{
                $Safe = Get-PASSafe -SafeName $SafeName -UseGen1API -ErrorAction Stop           
            }
            catch{ throw $_.Exception.Message}
        }elseif($_.Exception.Message -notlike "[[]404[]] Safe * was not found."){
            throw $_.Exception.Message
        }
    }

    return $Safe
}
