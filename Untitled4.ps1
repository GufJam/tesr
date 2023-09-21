
function Initiate-CAOnboarding{

 <#
    .SYNOPSIS
        Onboards list of account given as input csv.
    .DESCRIPTION
        It utilises PsPAS module to onboard list of account given as input csv by performing various steps
        Steps are in following order:
            Check AD for the following from the input file (AD value is in the config file)
                the CA account exists in AD = CA_<NTID>
                The AD Security group exists in AD = CARK_<NTID>
                the AD Security Group only contains the single member which is <NTID>
            CreateSafe - check to see if exist if not create, if exist proceed to Vault Account and note in log file that safe already exists)
            SafeName=NT_CA_<NTID>  (all uppercase)  (make the NT_CA a new param in config)
            Description = <NTID> is the owner of this safe. <ticketsystem> <ticketnumber>
            CPM = CPM_NonTelco (make this a new param in config)
            OLACEnabled = false
            NumVersionRetention = 3 (make this a new param in config)
            Add SafeMembers – if members are already added the note in log and move to next step)
            Default members
            AD security group:  CARK_<ntid>  (make the CARK a new param in config)
            VaultAccount- if account already exists (based on username + address, note in log and end processing for this entry)
            Username = ca_<ntid>  (make sure this value is lowercase)
            Address = gsm1900.org
            PlatformID = TMO_WinDomain_CA
            Recon Account – we need ability to check if recon was successfully if ‘yes’ proceed to VerfiyAccount, if ‘no’ then proceed to remove logged in user. Put a wait of 7 minutes or be able to check the recon status for each account after set amount of time.
            Verify Account – not need to wait for this to complete
            Remove logged in user from safe
    .EXAMPLE
        PS> Initiate-CAOnboarding
    .EXAMPLE
        PS> Initiate-CAOnboarding
    .INPUTS
        CSV
    .NOTES
        Version         : 1.0
        Creation Date   : 20/09/2023
        Purpose/Change  : Initial development
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$config
    )
    
    
    try{        
        #Define CSV file path 
        $Global:LogPath = "$global:targetFolder\Logs\$(Get-Date -Format yyyyMMdd-hhmmss)_CAOnboardingLogs.LOG"
        $ResultPath = "$global:targetFolder\$(Get-Date -Format yyyyMMdd-hhmmss)_CAOnboardingResult.csv"
        Write-Log -Object ("-"*30 + ' Started CA Onboarding ' + "-"*30 ) -NoPrint

        Remove-Variable CAOnboardingInput -Force -ErrorAction SilentlyContinue
        
        Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue
        if($null -eq (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)){
            throw 'ActiveDirectory module not found.'
        }

        $CAOnboardingInput = Get-FileName -InitialDirectory $PWD -Filter "CSV Files (*.csv)|*.csv" -WindowTitle "CA Onboarding Details"

        Write-Log -Object "Selected input csv '$CAOnboardingInput'."
        
        $RequiedColumns = @('NTID','TicketSystem','TicketNumber')
    
        $CAOnboardingList = Test-SelectedInputCSV -FilePath $CAOnboardingInput -RequiedColumns $RequiedColumns

        if($null -eq $CAOnboardingList){
            Write-Log -Object "No inputs in selected CSV."
            return
        }
        
        Write-Log "Input CSV imported."
        #Loop through each memebers to add from input
        $SuccessfulCAAccounts = @()
        $ResultCsv = @()

        $startDateTime = Get-Date
        #Verify accounts
        foreach ($CAItem in $CAOnboardingList)
        {                    
            # Initialize Variables
            $NTID = $CAItem.NTID
            $CA_NTID = ($config.CAUserInitials + $NTID).ToLower()
            $CARK_Group = $config.CAGroupInitials + $NTID
            $SafeName =  ($config.CAGroupInitials + "NT_CA_$NTID").ToUpper()

            Write-Log "-------- Checking account pre-requisits for NTID - $NTID ---------" -ForegroundColor cyan
            # Get AD Objects

            try{
                $DomainServer = $config.DomainServer

                #check $NTID account in ad
                $NTID_Object = $null
                if([String]::IsNullOrWhiteSpace($DomainServer)){
                    $NTID_Object = (Get-ADUser -Identity $NTID -ErrorAction Stop).distinguishedName                    
                }else{
                    $NTID_Object = (Get-ADUser -Identity $NTID -ErrorAction Stop -Server $DomainServer).distinguishedName                    
                }
                if(($NTID_Object|Measure-Object).Count -ne 1){
                    Throw "$(($NTID_Object|Measure-Object).Count) ADUser found for '$NTID'."
                }

                 #check $CA_NTID account in ad
                $CA_NTID_Object = $null
                if([String]::IsNullOrWhiteSpace($DomainServer)){
                    $CA_NTID_Object = Get-ADUser -Filter {samAccountName -eq $CA_NTID} -ErrorAction Stop
                }else{
                    $CA_NTID_Object = Get-ADUser -Filter {samAccountName -eq $CA_NTID} -Server $DomainServer -errorAction Stop
                }

                if(($CA_NTID_Object|Measure-Object).Count -ne 1){
                    Throw "$(($CA_NTID_Object|Measure-Object).Count) ADUser found for '$CA_NTID'."
                }
                
                  #check $CARK_Group Group in ad
                $CARK_Group_Object = $null
                if([String]::IsNullOrWhiteSpace($DomainServer)){
                    $CARK_Group_Object = Get-ADGroup -Filter {samAccountName -eq $CARK_Group} -ErrorAction Stop
                }else{
                    $CARK_Group_Object = Get-ADGroup -Filter {samAccountName -eq $CARK_Group} -Server $DomainServer -ErrorAction Stop
                }    

                if(($CARK_Group_Object|Measure-Object).Count -ne 1){
                    Throw "$(($CARK_Group_Object|Measure-Object).Count) ADGroup found for '$CARK_Group'."
                }

                 #check $CARK_Group Group Members in ad
                $CARK_Group_Members = $null
                if([String]::IsNullOrWhiteSpace($DomainServer)){
                    $CARK_Group_Members = Get-ADGroupMember -Identity $CARK_Group -Server $DomainServer -ErrorAction Stop| Select -ExpandProperty distinguishedName
                }else{
                    $CARK_Group_Members = Get-ADGroupMember -Identity $CARK_Group -Server $DomainServer -ErrorAction Stop| Select -ExpandProperty distinguishedName
                }

                if (($CARK_Group_Members|Measure-Object).Count -ne 1) {                        
                    # Check if CARK group contains exactly one member
                    throw "($(($CARK_Group_Members|Measure-Object).Count)) members found in $CARK_Group Group."
                }
                    
                if ($CARK_Group_Members -inotcontains $NTID_Object) {                    
                    # Check if CARK Group contains the correct member                                  
                    throw "$NTID is not a member of $CARK_Group AdGroup."
                }                    
                
                # Log success or failure                
                Write-Log -Object "All Prerequisit checks passed for $CA_NTID." -ForegroundColor Green
                
                try{
                    $SafeExist = $null
                    $SafeExist = Get-PASSafe -SafeName $SafeName -ErrorAction Stop
                }catch{
                    if($_.Exception.Message -notlike "[[]404[]] Safe * was not found."){
                        throw $_.Exception.Message
                    }  
                }

                if($SafeExist -eq $null){
                    $SafeExist = Add-PASSafe -SafeName $SafeName -Description "$($NTID) is the owner of this safe. $($CAItem.ticketSystem) $($CAItem.ticketNumber)" -OLACEnabled $false -ManagingCPM $config.CASafeCPMUser -NumberOfVersionsRetention $config.CASafeNumVersionRetention -ErrorAction Stop
                    Write-Log "Safe $($SafeName) created successfully "
                }else{
                    Write-Log "Safe $($SafeName) already exist"
                }
                
                Write-Host "Adding Default Safe members to $($SafeName)"
            
                foreach ($Member in $config.DefaultSafeMembers) {
                    try{
                        Add-PASSafeMember -SafeName $SafeName @Member -ErrorAction Stop|Out-Null 
                         Write-Log "Successfully added $($Member.MemberName) member to safe $SafeName."
                           
                    }catch{
                        if($_.Exception.Message -like "[[]409[]]* is already a member of safe *"){
                            Write-Log "$($Member.MemberName) is already a member of safe $SafeName." -ForegroundColor cyan
                        }else{
                            Write-Log "Warning: Failed to add default member $($Member.MemberName) to $SafeName. Error: $($_.Exception.Message)" -ForegroundColor yellow
                        }
                    }
                } 
                                 
                Write-Log "Onboarding $($CA_NTID)"          
                $resultAccount = Get-PASAccount -safeName $SafeName | Where {$_.userName -eq $CA_NTID }      

                if(($resultAccount|Measure).Count -eq 1){
                    Write-Log "Account already exist with Id = $($resultAccount.id), Address = $($resultAccount.address), Username = $($resultAccount.Username), PlatformId =  = $($resultAccount.platformID)."
                }elseif(($resultAccount|Measure).Count -eq 0){                  
                    $resultAccount = Add-PASAccount -SafeName $SafeName -address $config.CAAccountAddress -userName $CA_NTID -platformID $config.CAAccountPlatformID -automaticManagementEnabled $true
                }else{
                    throw "Error : Multiple accounts found. count $(($resultAccount|Measure).Count) "
                }
                                
                $AccountID = $resultAccount.id
                Write-Log "$($CA_NTID) onboarded successfully -- AccountID = $AccountID"            

                Write-Log "Marking $($CA_NTID) for reconciliation"
                Invoke-PASCPMOperation -AccountID $AccountID -ReconcileTask -ErrorAction Stop
                Write-Log "Successfully marked $($CA_NTID) for reconciliation" -ForegroundColor cyan
                                
                $SuccessfulCAAccounts += [PSCustomObject]@{
                    NTID = $NTID
                    CA_NTID = $CA_NTID
                    CARK_Group = $CARK_Group
                    AccountID = $AccountID
                    SafeName = $SafeName
                }


            } catch{
                # Catch any errors from above
                 $ResultCsv += [PSCustomObject]@{
                    NTID = $NTID
                    Result = 'Failed'
                    Reason = "$($_.Exception.Message)"
                }
                Write-Log "Error: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            Write-Log "---------------------------------------------------------" -NoPrint
                                    
        }        
        #----------------------- Sleep for 7 minutes -----------------------

        $sleepTime = 420
        Write-Log ("ATTTENTION: Pausing script for $sleepTime seconds to allow reconciliation to complete. The script will resume at " + (Get-Date).AddSeconds($sleepTime).ToString("HH:mm:ss")) -ForegroundColor Yellow        
        Start-Sleep -Seconds $sleepTime        
        $date = (Get-Date -Day 1 -Month 1 -Year 1970).Date        

        foreach ($account in $SuccessfulCAAccounts)
        {
            try{
                #VerifyRecon
                Write-Host "[NTID - $($account.NTID)] Confirming successful reconciliation for $($account.CA_NTID)"
                $accountDetails = Get-PASAccount -id $account.AccountID -ErrorAction Stop

                $reconcilied = $false
                if(-not([string]::IsNullOrWhiteSpace($accountDetails.secretManagement.lastReconciledTime) )){
                    if($date.AddSeconds($accountDetails.secretManagement.lastReconciledTime) -gt $startDateTime){
                        $reconcilied = $true
                    }
                } 
                
                # Check if reconcilied
                if($reconcilied -ne $true)
                {
                    $Reason = Get-PASAccountActivity -AccountID $account.AccountID -ErrorAction SilentlyContinue| Where{$_.Activity -eq "CPM Reconcile Password Failed" -and $_.Time -gt $startDateTime}|Select -First 1
                    throw "Reconciliation failed for $($account.CA_NTID). Reason - $($Reason.Reason)"
                } else {
                    Write-Log "[$($account.NTID)] Successfully reconciled $($account.CA_NTID)" -ForegroundColor green
                }
                    
                #AddCARKGroup
                Write-Log "Adding $($account.CARK_Group) to safe $($account.SafeName)"
                Add-SafeMember -SafeName $account.SafeName -MemberName $account.CARK_Group -SearchIn $config.SafeMembersSearchIn -UseAccounts $true -ListAccounts $true -ViewAuditLog $true -InitiateCPMAccountManagementOperations $true
                Write-Log "Successfully added $($account.CARK_Group) to $($account.SafeName) safe" -ForegroundColor Cyan

                #RemoveUploadUser
                Write-Log "Removing $($Global:Session.Username) from $($account.SafeName) safe"
                Remove-PASSafeMember -SafeName $account.SafeName -MemberName $(Get-PASSession).User -ErrorAction Stop
                Write-Log "Successfully removed $($(Get-PASSession).User) from $($account.SafeName)" -ForegroundColor Cyan
                $ResultCsv += [PSCustomObject]@{
                    NTID = $account.NTID
                    Result = 'Success'
                    Reason = "Onboarded and reconciled"
                }
            } catch{
                # Catch any errors from above
                $ResultCsv += [PSCustomObject]@{
                    NTID = $account.NTID
                    Result = 'Warning'
                    Reason = "$($_.Exception.Message)"
                }
                Write-Log "Error: [NTID - $($NTID)] $($_.Exception.Message)" -ForegroundColor Yellow
                
            }
            Write-Log "---------------------------------------------------------" -NoPrint              
        }

        if(($ResultCsv|Measure).count -ne 0){
            $ResultCsv | Export-Csv -Path $ResultPath -NoTypeInformation -ErrorAction SilentlyContinue
            Write-Host "Result saved to '$($ResultPath)'. " -ForegroundColor Green
        }

    }catch{
        #Handle exceptions for API failures and otjer failures 
        Write-Log "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    
}

function Write-Log{
    Param([parameter(Position=0)]$Object, [String]$ForegroundColor='White', [Switch]$NoPrint)
    if(-Not($NoPrint.IsPresent -eq $true)){
       Write-Host -Object $Object -ForegroundColor $ForegroundColor
    }
    $(Get-Date).ToString('dd-MM-yyyy HH:mm:ss') + ' - ' + $Object | Add-Content -Path $global:LogPath -Force
}
