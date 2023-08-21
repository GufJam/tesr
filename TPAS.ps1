using module .\Modules\helpFunctions.psm1
using module .\Modules\CYBAUTOLibrary.psm1
using module .\Modules\TMOLibrary.psm1
using module .\Modules\psPAS\5.2.59\psPAS.psm1

param (
  [string]$commandLineUsername,
  [string]$commandLinePassword
)

Import-Module .\Modules\ps-menu\1.0.8\ps-menu.psm1 -DisableNameChecking
$CurrentVersion = (''+ (Get-Content .\version.txt -ErrorAction SilentlyContinue|Where-Object {$_.trim() -ne ''}|Select-Object -First 1)).Trim()
if($CurrentVersion -eq ''){ $CurrentVersion = 'v1.0'}
Write-Host "`n`n******************** Welcome to TPAS $($CurrentVersion) ********************`n" -ForegroundColor White  -BackgroundColor Black

#Import Configuration
. .\config.ps1
. .\menu-config.ps1

Add-Type -AssemblyName Microsoft.VisualBasic
[Void]([Microsoft.VisualBasic.Interaction]::Msgbox("Click 'Ok' to set working directory for log files and file downloads.","OkOnly,SystemModal,Information","Information"))

$targetFolder = Get-FolderName -SelectedPath $pwd -Description "Select an Output Folder for Reports and Logs" -ShowNewFolderButton
if ($null -eq $targetFolder) {
  $targetFolder = $PWD
}

if (!$(Test-Path "$targetFolder\Logs")) {
  Write-Host "Creating Log Output Folder in $targetFolder"
  New-Item -ItemType Directory -Path "$targetFolder\Logs" | Out-Null
}

if (!$(Test-Path "$targetFolder\Reports")) {
  Write-Host "Creating Reports Output Folder in $targetFolder"
  New-Item -ItemType Directory -Path "$targetFolder\Reports" | Out-Null
}

$global:targetFolder = $targetFolder
$global:logFileName = "$targetFolder\Logs\$(Get-Date -Format yyyyMMdd-hhmmss)-VaultManagementOperations.Log"
$global:reportFileName = "$targetFolder\Reports\$(Get-Date -Format yyyyMMdd-hhmmss)-VaultManagementResults.csv" 
$mainRoutine = $true
$authenticated = $false
$SubMenu = $false
$nl = [environment]::NewLine
$headerSize = 35
$MenuTitle = 'Main Menu'
$global:authselection = "CyberArk"
$global:BaseURI = $config.url

do {
  while (!$authenticated) {
    try {
      if ($commandLineUsername -and $commandLinePassword) {
        Write-Host "Local Auth via Command Line"
        $sec = ConvertTo-SecureString -Verbose $commandLinePassword.Trim()
        $global:cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $commandLineUsername, $sec
        New-PASSession -Credential $global:cred -BaseURI $config.url -type CyberArk -SkipCertificateCheck
      }
      else {
        #Authenticate
        Write-Host "Please Select Your Desired Authentication Method, or specify 'QUIT' to exit"
        $global:authselection = Menu -menuItems @("Radius", "CyberArk", "LDAP", "Quit")
        if ($global:authselection -eq "Quit") {
          exit
        }
        Write-Host "Initiating Session"
        $global:cred = $host.UI.PromptForCredential("CyberArk Credential Collection", "Enter Your Credentials. If you selected RADIUS, be Ready to Accept the Push MFA Request", $null, $null)
        New-PASSession -Credential $global:cred -BaseURI $config.url -type $global:authselection -SkipCertificateCheck
      }
      $authenticated = $true
      Write-Host "Session Initiated."
      Write-Host -ForegroundColor DarkYellow "$($nl)Authenticated as user: $((Get-PASSession).User)"
    }
    catch {
      Write-Error "Unable to Authenticate" 
      Write-Host $Error
      Read-Host -Prompt "Press Enter To Try Again"
    }
  }
  Write-Host -ForegroundColor Cyan "$($nl)Please Select Your Desired Operation"

  $foundCommand = $false
  if($SubMenu -eq $false){
    $menuSelection = 0
    $currentMenuKeys = $menuItems.Keys
    $currentMenu = $menuItems
  }

  do {
    $currentMenuKeys = [Array]($currentMenuKeys|Select-Object -SkipLast 1|Sort-Object) + [Array]($currentMenuKeys|Select-Object -Last 1)
    Write-MenuTitle -menuSelection $MenuTitle -menuSize $headerSize 
    $menuSelection = Menu -menuItems $currentMenuKeys
    if ($menuSelection -eq "Quit") {
      $mainRoutine = $false
      break;
    }
    if ($menuSelection -eq "Back") {
      Write-Host ("-"*$HeaderSize) -ForegroundColor Gray
      $currentMenu = $previousMenu
      $currentMenuKeys = $currentMenu.Keys
      $MenuTitle = 'Main Menu'
    }
    else {
      $menuValue = $currentMenu[$menuSelection]
      if ($menuValue -is [String]) {
        $cmdlet = $menuValue
        $foundCommand = $true
      }
      elseif ($menuValue -is [hashtable]) {
        Write-Host ("-"*$HeaderSize) -ForegroundColor Gray
        $currentMenuKeys = $menuValue.Keys
        $currentMenuKeys += "Back"
        $previousMenu = $currentMenu
        $currentMenu = $menuValue
        $MenuTitle = $menuSelection
      }
    }
  }
  while (!$foundCommand)

  if ($foundCommand) {
    $SubMenu = $true
    $sb = [System.Management.Automation.ScriptBlock]::Create($cmdlet + ' -config $config')
    & $sb -config $config
  }

  if ($null -eq (Get-PASLoggedOnUser).UserName) {
    Write-Host -ForegroundColor DarkYellow "Your Session Has Expired. Please Reauthenticate.$($nl)"
    $authenticated = $false
  }

  Write-Host -ForegroundColor Cyan "Operation Complete"

}
while ($mainRoutine)

Read-Host -Prompt "$($nl)Press Enter To Exit"
