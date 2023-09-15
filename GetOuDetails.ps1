
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

try{
    Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue
    if($null -eq (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)){
        throw 'ActiveDirectory module not found.'
    }
    $CurrPath = $PWD.Path 
    if($CurrPath -eq 'C:\Windows\System32'){ Set-Location -Path "$env:USERPROFILE\downloads"; $CurrPath = "$env:USERPROFILE\downloads" }
    
    $OUName = Read-SingleInputBoxDialog -Message "Please provide the DistinguishedName of the OU." -WindowTitle 'Organizational Unit'     
    if([String]::IsNullOrWhiteSpace($OUName)){throw 'Input cant be null or empty.'}
    
    #Get domain
    $Domain = $null
    $Domain = Read-SingleInputBoxDialog -Message "Please provide the Domain name for ActiveDirectory." -WindowTitle 'Domain name' 
    try{
        $OU = $null
        if([String]::IsNullOrWhiteSpace($Domain)){
            $OU = Get-ADOrganizationalUnit -Identity $OUName -ErrorAction Stop
        }else{
            $OU = Get-ADOrganizationalUnit -Identity $OUName -Server $Domain -ErrorAction Stop                
        }
    }catch
    {   
        throw $_.Exception.Message
    }
    if($OU -eq $null){throw "No OU found with DN = $OUName" }
    $csvuser = @()
    $csvGroup = @()
    $Userproperties =  @('PasswordLastSet', 'Description', 'DistinguishedName', 'Enabled', 'MemberOf')
    $Groupproperties =  @('MemberOf', 'Description', 'ManagedBy', 'Members', 'DistinguishedName')
    
    #ADUsers
    $ADUsers = $null
    if([String]::IsNullOrWhiteSpace($Domain)){
        $ADUsers = Get-ADUser -SearchBase $ou.DistinguishedName -Filter * -Properties $Userproperties -ErrorAction Stop
    }else{
        $ADUsers = Get-ADUser -SearchBase $ou.DistinguishedName -Filter * -Properties $Userproperties -Server $Domain -ErrorAction Stop                
    }
    foreach ($ADUser in $ADUsers)
    {
        $pwdtime = ''
        if( $ADUser.PasswordLastSet -as [dateTime]){
            $pwdtime = $ADUser.PasswordLastSet.tostring('o')
        }
        $csvuser += [PsCustomObject]@{
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
            $csvuser += [PsCustomObject]@{
                    SamAccountName = $ADUser.SamAccountName
                    DoesExist = ''
                    Description = ''
                    DistinguishedName = ''
                    Enabled = ''
                    PasswordLastSet = ''
                    MemberOf = $mem
                }
               
        }
        
    }
    #ADGroup
    $ADGroups = $null
    if([String]::IsNullOrWhiteSpace($Domain)){
        $ADGroups = Get-ADGroup -SearchBase $ou.DistinguishedName -Filter * -Properties $Groupproperties -ErrorAction Stop
    }else{
        $ADGroups = Get-ADGroup -SearchBase $ou.DistinguishedName -Filter * -Properties $Groupproperties -Server $Domain -ErrorAction Stop                
    }
    foreach ($ADGroup in $ADGroups)
    {
        $ManagedBy = ''
        $ManagedByEnabled = ''
        $ManagedByEmail = ''
        if( $AdGroup.ManagedBy -ne $null){
            $ManagedBy = $AdGroup.ManagedBy
            $tempAdUser = Get-ADUser -Identity $ManagedBy -Properties Enabled, EmailAddress 
            $ManagedByEnabled =$tempAdUser.Enabled 
            $ManagedByEmail =$tempAdUser.EmailAddress 
        }
        $FirstMember =  "$($AdGroup.Members | Select -First 1)"
        $FirstMemberEnabled = ''
        $FirstMemberType = ''
        if(-Not([String]::IsNullOrWhiteSpace($FirstMember))){
                if([String]::IsNullOrWhiteSpace($Domain)){
                $FirstMemberType = ( Get-ADObject -Identity $FirstMember).ObjectClass 
                }else{
                $FirstMemberType = ( Get-ADObject -Identity $FirstMember -Server $Domain).ObjectClass 
                }
            if($FirstMemberType -eq 'user'){
                if([String]::IsNullOrWhiteSpace($Domain)){
                    $FirstMemberEnabled = Get-ADUser -Identity $FirstMember -Properties Enabled|Select -ExpandProperty Enabled                        
                    }else{
                    $FirstMemberEnabled = Get-ADUser -Identity $FirstMember -Properties Enabled -Server $Domain|Select -ExpandProperty Enabled
                    }
            }
        }
        $csvGroup += [PsCustomObject]@{
                        SamAccountName = $AdGroup.SamAccountName
                        DoesExist = 'True'
                        Description = $AdGroup.Description
                        DistinguishedName = $AdGroup.DistinguishedName
                        ManagedBy = $ManagedBy
                        ManagedByEnabled = $ManagedByEnabled
                        Members = $FirstMember
                        MemberType = $FirstMemberType
                        MemberEnabled = $FirstMemberEnabled
                        ManagedByEmail = $ManagedByEmail
                    }
        foreach ($mem in $($AdGroup.Members | Select -Skip 1))
        {
            $MemEnabled = ''
            $MemType = ''
            if([String]::IsNullOrWhiteSpace($Domain)){
                $MemType = ( Get-ADObject -Identity $mem).ObjectClass                                              
            }else{
                $MemType = ( Get-ADObject -Identity $mem -Server $Domain).ObjectClass                         
            }
            if($MemType -eq 'user'){
                if([String]::IsNullOrWhiteSpace($Domain)){
                    $MemEnabled = Get-ADUser -Identity $mem -Properties Enabled|Select -ExpandProperty Enabled
                }else{
                    $MemEnabled = Get-ADUser -Identity $mem -Properties Enabled -Server $Domain|Select -ExpandProperty Enabled
                }
            }
            $csvGroup += [PsCustomObject]@{
                    SamAccountName = $AdGroup.SamAccountName
                    DoesExist = ''
                    Description = ''
                    DistinguishedName =''
                    ManagedBy = ''
                    ManagedByEnabled = ''
                    Members = $mem
                    MemberType = $MemType
                    MemberEnabled = $MemEnabled
                    ManagedByEmail = $ManagedByEmail
                }
        }
    }

    #export result
    if($csvuser.count -eq 0){
        Write-Host "No Accounts found under OU $OuName."
    }else{
         try{
            $path = "$CurrPath\AccountsReport_$(Get-Date -Format yyyyMMdd-hhmmss)_OU_$($OuName).csv" 
            $csvuser | Export-Csv -Path $path -NoTypeInformation -ErrorAction Stop
            Write-Host "Accounts Results saved to '$((Resolve-Path $Path).Path)'. " -ForegroundColor Green
        }catch{
            Write-Host "Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    if($csvGroup.count -eq 0){
        Write-Host "No Groups found under OU $OuName."
    }else{
         try{
            $path = "$CurrPath\GroupReport_$(Get-Date -Format yyyyMMdd-hhmmss)_OU_$($OuName).csv" 
            $csvGroup | Export-Csv -Path $path -NoTypeInformation -ErrorAction Stop
            Write-Host "Groups Results saved to '$((Resolve-Path $Path).Path)'. " -ForegroundColor Green
        }catch{
            Write-Host "Failed to create CSV. $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}catch{
    Write-Host "ERROR: $_" -ForegroundColor Red
}finally{
    Read-Host "Press enter to exit." 
}
