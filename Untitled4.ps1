
Need a new module which will vault an account in AD based on input file (sample attached). There is a check of AD to make sure account exists, security group exists and the security group only has one member (NTID in the input file)

 

After the check the safe is created, safe membership set, account vaulted, recon acct, verify acct and lastly remove the logged in TPAS user from the safe

 

Here are the details

 

 

Add a new menu item under Account Management called Onboard CA Domain Accounts

 

(Note:  create new params in config for this module as per below to make sure it is flexible)

 

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
Recon Account – we need ability to check if recon was successfully if ‘yes’ proceed to VerfiyAccount, if ‘no’ then proceed to remove logged in user.  Put a wait of 7 minutes or be able to check the recon status for each account after set amount of time.
Verify Account – not need to wait for this to complete
Remove logged in user from safe
 

For each action we need result logged to log file (success or failure)

 

 

Note:  script below is a reference and what customer is using today.  It looks like to verify that recon account was successfully, script is checking account in AD.  I’d rather check the status in Cyberark.  You may have to get the acctID and then check with another call.

 

 

 

<#

 

HOW TO RUN SCRIPT:

.\Account-OnboardCA_NTID.ps1 -CAENV DEV -UserName ADM_AWERDER1 -InFilePath ..\..\..\InputFiles\Account-OnboardCA_NTID\Account-OnboardCA_InputTemplate.csv

 

#>

 

#------------------------------------------------------------[Initializations and Declarations]------------------------------------------------------------------------------------

 

param(

    # CAENV

    [Parameter(Mandatory=$true)]

    [ValidateNotNullOrEmpty()]

    [string]$CAENV,

 

    # AUTH_METHOD

    [Parameter(Mandatory=$true)]

    [ValidateSet('RADIUS','CyberArk')]

    $AUTH_METHOD='CyberArk',

 

    # UserName

    [ValidateNotNullOrEmpty()]

    [string] $UserName,

 

    # InFilePath

    [Parameter(Mandatory=$true)]

    [ValidateScript({

        if (-Not (Test-Path $_) ) {

            Throw "`nERROR: File '$_' does not exist."

        } else {

            $true

        }

    })]

    [string] $InFilePath

)

 

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

 

# IMPORT

Get-ChildItem -Path ".\_Modules\*" -Include "*.psm1" | Import-Module -Force

$csv = Import-Csv $InFilePath

 

# Get DateTime. Used later to compare to PasswordLastSet AD attribute to verfiy pw reconciliation.

$startDateTime = Get-Date

 

#--------------------------------------------------------------------[Functions]----------------------------------------------------------------------------------------------------

 

# Verfiy AD Module is installed

function Confirm-ScriptPreReqs {

    # Check for ActiveDirectory module

    if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {

        try {

            Add-WindowsFeature RSAT-AD-Powershell

        } catch {

            Write-Host 'ERROR: Failed to install ActiveDirectory module on this host.'

            $_

            return 0

        }

    }

    return 1

}

 

# Verify Account Prerequisits

function Confirm-AccountPreReqs {

    <#

    Verify:

     - the CA account exists in AD

     - the CARK group exists in AD

     - the CARK group only contains the single member of the NTID

    #>

 

    param(

        # Accounts

        [Parameter(

            Mandatory=$true,

            ValueFromPipeline=$true

        )]

        [ValidateNotNullOrEmpty()]

        $Account,

 

        # Path to Logfile

        [Parameter(Mandatory=$true)]

        [ValidateNotNullOrEmpty()]

        [String]$logfile

    )

   

    Process

    {

        # Initialize Variables

        $NTID = $Account.NTID

        $CA_NTID = $Account.CA_NTID

        $CARK_Group = $Account.CARK_Group

 

        Write-Host "[$NTID] Checking account pre-requisits for $NTID"

 

        # Get AD Objects

        try{

            $NTID_Object = (Get-ADUser -Identity $NTID).distinguishedName

            $CA_NTID_Object = Get-ADUser -Filter {samAccountName -eq $CA_NTID}

            $CARK_Group_Object = Get-ADGroup -Filter {samAccountName -eq $CARK_Group}

            $CARK_Group_Members = Get-ADGroupMember -Identity $CARK_Group | Select -ExpandProperty distinguishedName

 

            # Check if CARK Group contains the correct member

            if ($CARK_Group_Members -inotcontains $NTID_Object) {

                $Account.hasError = 1

           

                $message = "$NTID is not a member of $CARK_Group."

 

                Write-Host $message -ForegroundColor Red

                Write-Log -logfile $logfile -type ERROR -message $message

            }

 

 

            # Check if CARK group contains exactly one member

            elseif ([array]$CARK_Group_Members.Count -ne 1) {

                $Account.hasError = 1

           

                $message = "$CARK_Group either has 0 or more than 1 member."

 

                Write-Host $message -ForegroundColor Red

                Write-Log -logfile $logfile -type ERROR -message $message

            }

       

        } catch{

            # Catch any errors from above

            $Account.hasError = 1

 

            Write-Host $_.Exception.Message -ForegroundColor Red

            Write-Log -logfile $logfile -type ERROR -message $_.Exception.Message

        }

 

 

        # Log success or failure

        if ($Account.hasError -eq 1) {

            Write-Host "FAIL" -ForegroundColor Red

 

        } else {

            Write-Host "PASS" -ForegroundColor Green

            Write-Log -logfile $logfile -type SUCCESS -message "All Prerequisit checks passed for $CA_NTID."

        }

    }

}

 

# Wrapper for function calls

function Helper-Function {

    param(

        # action

        [Parameter(Mandatory=$true)]

        [ValidateSet(

                     "CreateSafe",

                     "AddSafeAdmins",

                     "OnboardAccount",

                     "ReconAccount",

                     "VerifyRecon",

                     "AddCARKGroup",

                     "RemoveUploadUser"

                     )]

        [string] $action,

 

        # account

        [Parameter(Mandatory=$true)]

        [ValidateNotNullOrEmpty()]

        $account,

 

        # Path to Logfile

        [Parameter(Mandatory=$true)]

        [ValidateNotNullOrEmpty()]

        [String]$logfile

    )

 

    if ($account.hasError) {

        return

    }

 

    try {

        switch ($action) {

       

            "CreateSafe"

            {

                Write-Host "[$($account.NTID)] Creating safe $($account.SafeName)"

                $result = Add-Safe -SafeName $account.SafeName -Description "$($account.NTID) is the owner of this safe. $($account.ticketSystem) $($account.ticketNumber)" -OLACEnabled $false -CPM "CPM_NonTelco" -NumVersionRetention 3

                $message = "[$($account.NTID)] $($account.SafeName) created successfully -- $($result.AddSafeResult)"

            }

 

            "AddSafeAdmins"

            {

                Write-Host "[$($account.NTID)] Adding Safe Admins to $($account.SafeName)"

                Add-SafeAdmins -SafeName $account.SafeName

                $message = "[$($account.NTID)] Successfully added Safe Admins"

            }

 

            "OnboardAccount"

            {

                Write-Host "[$($account.NTID)] Onboarding $($account.CA_NTID)"

                $result = Add-Account -safeName $account.SafeName -Address "gsm1900.org" -UserName $account.CA_NTID -PlatformID "TMO_WinDomain_CA" -autoManagement $true

                $account.AccountID = $result.id

                $message = "[$($account.NTID)] $($account.CA_NTID) onboarded successfully -- $result"

            }

 

            "ReconAccount"

            {

                Write-Host "[$($account.NTID)] Marking $($account.CA_NTID) for reconciliation"

                Invoke-CPM -accountID $account.AccountID -action Reconcile

                $message = "[$($account.NTID)] Successfully marked $($account.CA_NTID) for reconciliation"

            }

 

            "VerifyRecon"

            {

                Write-Host "[$($account.NTID)] Confirming successful reconciliation for $($account.CA_NTID)"

 

                $reconned_accounts = Get-ADUser -Filter {(SamAccountName -like 'ca_*' ) -and (Enabled -eq $true) -and (PasswordLastSet -gt $startDateTime)} `

                                                -SearchBase 'OU=CA_ManagedAccounts,OU=Administrative Users and Groups,DC=gsm1900,DC=org' `

                                                -Properties PasswordLastSet `

                                                | Select-Object SamAccountName,Enabled,PasswordLastSet `

                                                | Sort-Object samAccountName

 

                $reconcilied = ($account.CA_NTID -in $reconned_accounts.SamAccountName)

 

                # Check if reconcilied

                if(-not $reconcilied)

                {

                    $out = "According to the PasswordLastSet AD attribute, reconciliation failed for $($account.CA_NTID)."

                    Write-Host $out -ForegroundColor Red

                    Log-Result -result "ERROR" -message $out

                } else {

                    $message = "[$($account.NTID)] Successfully reconciled $($account.CA_NTID)"

                }

            }

 

            "AddCARKGroup"

            {

                Write-Host "[$($account.NTID)] Adding $($account.CARK_Group) to $($account.SafeName)"

                Add-SafeMember -SafeName $account.SafeName -MemberName $account.CARK_Group -SearchIn GSM1900 -UseAccounts $true -ListAccounts $true -ViewAuditLog $true -InitiateCPMAccountManagementOperations $true

                $message = "[$($account.NTID)] Successfully added $($account.CARK_Group) to $($account.SafeName)"

            }

 

            "RemoveUploadUser"

            {

                Write-Host "[$($account.NTID)] Removing $($Global:Session.Username) from $($account.SafeName)"

                Remove-SafeMember -SafeName $account.SafeName -MemberName $Global:Session.Username

                $message = "[$($account.NTID)] Successfully removed $($Global:Session.Username) from $($account.SafeName)"

            }

 

        }

    } catch {

        $account.hasError = 1

        $message="Error with $action for $account. `n`n$($_.Exception.Message)`n$($_.ErrorDetails)`n"

       

        Write-Host $message -ForegroundColor Red

        Write-Log -type ERROR -logFile $logfile -message $message

 

        return

    }

   

    Write-Host "SUCCESS" -ForegroundColor Green

    Write-Log -type SUCCESS -logFile $logfile -message $message

   

}

 

# Main process

function Run-Main {

       

    # Confirm session is initialized

    Confirm-StartSession -UserName $UserName -CAENV $CAENV -Auth_Method $AUTH_METHOD

 

    # Init Log

    $logfile = Initialize-Log -scriptName $MyInvocation.ScriptName

   

    $numRows = $csv.Count

    $counter = 1

 

    $error_arr = @()

 

    # BUILD ACCOUNTS ARRAY

    $accounts = @()

 

    foreach ($row in $csv) {

        $NTID = $row.NTID.Trim()

        $CA_NTID = "ca_$NTID".ToLower()

        $CARK_Group = "CARK_$NTID"

        $SafeName = "NT_CA_$NTID"

        $TicketSystem = $row.ticketSystem.Trim()

        $TicketNumber = $row.ticketNumber.Trim()

   

        $accounts += [PSCustomObject]@{

                NTID = $NTID

                CA_NTID = $CA_NTID

                CARK_Group = $CARK_Group

                SafeName = $SafeName

                TicketSystem = $TicketSystem

                TicketNumber = $TicketNumber

                AccountID = $null

                hasError = 0

        }

    }

 

    #----------------------- Onboard Accounts: Phase 1 -----------------------

 

    # Check Pre-Reqs

    $accounts | Confirm-AccountPreReqs -logfile $logfile

 

    # Create Safe

    $accounts | % { Helper-Function -action CreateSafe -account $_ -logfile $logfile }

 

    # Add Safe Admins

    $accounts | % { Helper-Function -action AddSafeAdmins -account $_ -logfile $logfile }

 

    # Onboard Accounts

    $accounts | % { Helper-Function -action OnboardAccount -account $_ -logfile $logfile }

 

    # Reconcile Accounts

    $accounts | % { Helper-Function -action ReconAccount -account $_ -logfile $logfile }

 

 

    #----------------------- Sleep for 7 minutes -----------------------

   

    $sleepTime = 420

    $out = "ATTTENTION: Pausing script for $sleepTime seconds to allow reconciliation to complete. The script will resume at " + (Get-Date).AddSeconds($sleepTime).ToString("HH:mm:ss")

 

    Write-Host $out -ForegroundColor Yellow

    Start-Sleep -Seconds $sleepTime

 

   

    #----------------------- Onboard Accounts: Phase 2 -----------------------

 

    # Verify Reconcile

    $accounts | % { Helper-Function -action VerifyRecon -account $_ -logfile $logfile }

 

    # Add CARK Group

    $accounts | % { Helper-Function -action AddCARKGroup -account $_ -logfile $logfile }

 

    # Remove UploadUser from safe

    $accounts | % { Helper-Function -action RemoveUploadUser -account $_ -logfile $logfile }

 

 

    #----------------------- Closing Matter -----------------------

 

    $errorCount = 0

 

    $accounts | % { if($_.hasError) { $errorCount++ } }

 

    if ($errorCount -gt 0){

        # Export Error CSV

        Write-Host ("`n" + "*"*50)

        $message = "Completed with $errorCount errors. See $logfile for details."

        Write-Host "`n$message" -ForegroundColor RED

 

    } Else {

        # No errors - no error csv created.

        Write-Host ("`n" + "*"*50)

        $message = "Completed with 0 errors!"

        Write-Host "`n$message" -ForegroundColor GREEN

        Write-Log -logFile $logfile -type INFO -message $message

    }

 

    # End Session

    Confirm-StopSession

}

 

#--------------------------------------------------------------------[Execution]----------------------------------------------------------------------------------------------------

 

if (Confirm-ScriptPreReqs) {    

    Run-Main

}

 
