
function Get-FileName
{
<#
.SYNOPSIS
   Show an Open File Dialog and return the file selected by the user

.DESCRIPTION
   Show an Open File Dialog and return the file selected by the user

.PARAMETER WindowTitle
   Message Box title
   Mandatory - [String]

.PARAMETER InitialDirectory
   Initial Directory for browsing
   Mandatory - [string]

.PARAMETER Filter
   Filter to apply
   Optional - [string]

.PARAMETER AllowMultiSelect
   Allow multi file selection
   Optional - switch

 .EXAMPLE
   Get-FileName
    cmdlet Get-FileName at position 1 of the command pipeline
    Provide values for the following parameters:
    WindowTitle: My Dialog Box
    InitialDirectory: c:\temp
    C:\Temp\42258.txt

    No passthru paramater then function requires the mandatory parameters (WindowsTitle and InitialDirectory)

.EXAMPLE
   Get-FileName -WindowTitle MyDialogBox -InitialDirectory c:\temp
   C:\Temp\41553.txt

   Choose only one file. All files extensions are allowed

.EXAMPLE
   Get-FileName -WindowTitle MyDialogBox -InitialDirectory c:\temp -AllowMultiSelect
   C:\Temp\8544.txt
   C:\Temp\42258.txt

   Choose multiple files. All files are allowed

.EXAMPLE
   Get-FileName -WindowTitle MyDialogBox -InitialDirectory c:\temp -AllowMultiSelect -Filter "text file (*.txt) | *.txt"
   C:\Temp\AES_PASSWORD_FILE.txt

   Choose multiple files but only one specific extension (here : .txt) is allowed

.EXAMPLE
   Get-FileName -WindowTitle MyDialogBox -InitialDirectory c:\temp -AllowMultiSelect -Filter "Text files (*.txt)|*.txt| csv files (*.csv)|*.csv | log files (*.log) | *.log"
   C:\Temp\logrobo.log
   C:\Temp\mylogfile.log

   Choose multiple file with the same extension

.EXAMPLE
   Get-FileName -WindowTitle MyDialogBox -InitialDirectory c:\temp -AllowMultiSelect -Filter "selected extensions (*.txt, *.log) | *.txt;*.log"
   C:\Temp\IPAddresses.txt
   C:\Temp\log.log

   Choose multiple file with different extensions
   Nota :It's important to have no white space in the extension name if you want to show them

.EXAMPLE
 Get-Help Get-FileName -Full

.INPUTS
   System.String
   System.Management.Automation.SwitchParameter

.OUTPUTS
   System.String

.NOTESs
  Version         : 1.0
  Author          : O. FERRIERE
  Creation Date   : 11/09/2019
  Purpose/Change  : Initial development

  Based on different pages :
   mainly based on https://blog.danskingdom.com/powershell-multi-line-input-box-dialog-open-file-dialog-folder-browser-dialog-input-box-and-message-box/
   https://code.adonline.id.au/folder-file-browser-dialogues-powershell/
   https://thomasrayner.ca/open-file-dialog-box-in-powershell/
#>
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # WindowsTitle help description
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Message Box Title",
            Position = 0)]
        [String]$WindowTitle,

        # InitialDirectory help description
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Initial Directory for browsing",
            Position = 1)]
        [String]$InitialDirectory,

        # Filter help description
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Filter to apply",
            Position = 2)]
        [String]$Filter = "All files (*.*)|*.*",

        # AllowMultiSelect help description
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Allow multi files selection",
            Position = 3)]
        [Switch]$AllowMultiSelect
    )

    # Load Assembly
    Add-Type -AssemblyName System.Windows.Forms

    # Open Class
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog

    # Define Title
    $OpenFileDialog.Title = $WindowTitle

    # Define Initial Directory
    if (-Not [String]::IsNullOrWhiteSpace($InitialDirectory))
    {
        $OpenFileDialog.InitialDirectory = $InitialDirectory
    }

    # Define Filter
    $OpenFileDialog.Filter = $Filter

    # Check If Multi-select if used
    if ($AllowMultiSelect)
    {
        $OpenFileDialog.MultiSelect = $true
    }
    $OpenFileDialog.ShowHelp = $true    # Without this line the ShowDialog() function may hang depending on system configuration and running from console vs. ISE.
    $OpenFileDialog.ShowDialog() | Out-Null
    if ($AllowMultiSelect)
    {
        return $OpenFileDialog.Filenames
    }
    else
    {
        return $OpenFileDialog.Filename
    }
}

function Read-SingleInputBoxDialog([string]$Message, [string]$WindowTitle, [string]$DefaultText, [Switch]$Password)
{
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $WindowTitle
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.FormBorderStyle = 'FixedSingle'
    $form.StartPosition = "CenterScreen"
    $form.AutoSizeMode = 'GrowAndShrink'
    $form.Topmost = $True
    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $form.ShowInTaskbar = $true
    $form.MaximizeBox = $false
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,120)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,120)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(260,45)
    $label.Text = $Message
    $label.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Center
    $label.Font = [System.Drawing.Font]::new('Arial',8,[System.Drawing.FontStyle]::Bold)

    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10,65)
    $textBox.Size = New-Object System.Drawing.Size(260,25)
    $textBox.Text = $DefaultText
    $textBox.Font = [System.Drawing.Font]::new('Arial',8,[System.Drawing.FontStyle]::Bold)
    if($Password.IsPresent){
        $textBox.PasswordChar = '*'
    }
    $form.Controls.Add($textBox)

    $form.Topmost = $true

    $form.Add_Shown({$form.Activate()})
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        if($Password.IsPresent){
            return $(ConvertTo-SecureString -String $textBox.Text -AsPlainText -Force)
        }else{
            return $textBox.Text
        }
    }else{
        return $null
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

try{
      Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue
      if($null -eq (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)){
            throw 'ActiveDirectory module not found.'
       }
    $CurrPath = $PWD.Path 
    if($CurrPath -eq 'C:\Windows\System32'){ Set-Location -Path "$env:USERPROFILE\downloads"; $CurrPath = "$env:USERPROFILE\downloads" }
    Write-Host 'Please select csv containing list of SamAccountName ' -ForegroundColor Cyan
    #echo $CurrPath
    $FilePath = Get-FileName -WindowTitle 'List of SamAccounts' -InitialDirectory $CurrPath -Filter "CSV Files (*.csv)|*.csv"
    #Validate File Name
    if ($null -eq $FilePath -or $FilePath.trim().Length -eq 0) {
        Write-host "No File Selected. " -ForegroundColor Yellow
        return $null
    }
       
    $InputCsv = Test-SelectedInputCSV -FilePath $FilePath -RequiedColumns 'SamAccountName'
    if($null -eq $InputCsv){return }
    
    #Get domain
    $Domain = Read-SingleInputBoxDialog -Message "Please provide the Domain name for ActiveDirectory." -WindowTitle 'Domain name' 

    $csv = @()
    $properties =  @('PasswordLastSet', 'Description', 'DistinguishedName', 'Enabled', 'MemberOf')
    foreach ($item in $InputCsv)
    {
        if([String]::IsNullOrWhiteSpace($item.SamAccountName)){continue}
        Write-Host "Processing account - $($item.SamAccountName)"
        try{
            $ADUser = $null
            if([String]::IsNullOrWhiteSpace($Domain)){
                $ADUser = Get-ADUser -Identity $item.SamAccountName -Properties $properties -ErrorAction Stop
            }else{
                $ADUser = Get-ADUser -Identity $item.SamAccountName -Properties $properties -Server $Domain -ErrorAction Stop                
            }
        }catch
        {   if($_.Exception.Message -notlike "Cannot find an object with identity:*"){
            	Write-Host $_ -ForegroundColor Red
            }
        }
        if($null -eq $ADUser){
              $csv += [PsCustomObject]@{
                            SamAccountName = $item.SamAccountName
                            DoesExist = 'False'
                            Description = ''
                            DistinguishedName = ''
                            Enabled = ''
                            PasswordLastSet = ''
                            MemberOf = ''
                      }
        }else{
            $pwdtime = ''
            if( $ADUser.PasswordLastSet -as [dateTime]){
                $pwdtime = $ADUser.PasswordLastSet.tostring('o')
            }
            $csv += [PsCustomObject]@{
                    SamAccountName = $ADUser.SamAccountName
                    DoesExist = 'True'
                    Description = $ADUser.Description
                    DistinguishedName = $ADUser.DistinguishedName
                    Enabled = $ADUser.Enabled
                    PasswordLastSet = $pwdtime
                    MemberOf = "$($ADUser.MemberOf|select -First 1)"
                }

                       
           foreach ($mem in $($ADUser.MemberOf|select -Skip 1))
           { 
                $csv += [PsCustomObject]@{
                        SamAccountName = ''
                        DoesExist = ''
                        Description = ''
                        DistinguishedName = ''
                        Enabled = ''
                        PasswordLastSet = ''
                        MemberOf = $mem
                    }
               
           }
        }
    }
    if($csv.count -eq 0){
        Write-Host 'No csv report created.'
    }else{
         try{
            $path = "$CurrPath\$(Get-Date -Format yyyyMMdd-hhmmss)-AdAccountsReport.csv" 
            $csv | Export-Csv -Path $path -NoTypeInformation -ErrorAction Stop
            Write-Host "Results saved to '$((Resolve-Path $Path).Path)'. " -ForegroundColor Green
        }catch{
            Write-Host "Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
}catch{
    Write-Host "ERROR: $_" -ForegroundColor Red
}finally{
    Read-Host "Press enter to exit." 
}
