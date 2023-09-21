
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
    
       $Domain = $null
    $Domain = Read-SingleInputBoxDialog -Message "Please provide the Domain name for ActiveDirectory." -WindowTitle 'Domain name' 
    try{
        $OUs = $null
        if([String]::IsNullOrWhiteSpace($Domain)){
            $OUs = Get-ADOrganizationalUnit -SearchBase $OUName -SearchScope Subtree -Filter * -ErrorAction Stop
        }else{
            $OUs = Get-ADOrganizationalUnit -SearchBase $OUName -SearchScope Subtree -Filter * -Server $Domain -ErrorAction Stop                
        }
    }catch
    {   
        throw $_.Exception.Message
    }
    if($OUs -eq $null){throw "No OU found with DN = $OUName" }

    Write-Host "Found $($OUs.Count) results including subOUs" -ForegroundColor Cyan
   
    $csvGroup = @()
    $Groupproperties =  @('MemberOf', 'Description', 'ManagedBy', 'Members', 'DistinguishedName')
        
    #ADGroup
    $ADGroups = $()
    foreach ($ou in $OUs)
    {
        Write-Host "Getting ADGroups from searchbase $($ou.DistinguishedName)" -ForegroundColor Cyan
        $tempGroup = $null
        if([String]::IsNullOrWhiteSpace($Domain)){
            $tempGroup = Get-ADGroup -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Filter * -Properties $Groupproperties -ResultPageSize 1000 -ErrorAction Stop
        }else{
            $tempGroup = Get-ADGroup -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Filter * -Properties $Groupproperties -ResultPageSize 1000 -Server $Domain -ErrorAction Stop                
        }
        if($null -ne $tempGroup){ $ADGroups += $tempGroup}
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
                        $FirstMemberEnabled = Get-ADUser -Identity $FirstMember -Properties Enabled|Select -ExpandProperty Enabled -ErrorAction SilentlyContinue                        
                    }else{
                        $FirstMemberEnabled = Get-ADUser -Identity $FirstMember -Properties Enabled -Server $Domain|Select -ExpandProperty Enabled -ErrorAction SilentlyContinue
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
                        ManagedByEmail = $ManagedByEmail
                        Members = $FirstMember
                        MemberType = $FirstMemberType
                        MemberEnabled = $FirstMemberEnabled
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
                    $MemEnabled = Get-ADUser -Identity $mem -Properties Enabled|Select -ExpandProperty Enabled -ErrorAction SilentlyContinue
                }else{
                    $MemEnabled = Get-ADUser -Identity $mem -Properties Enabled -Server $Domain|Select -ExpandProperty Enabled -ErrorAction SilentlyContinue
                }
            }
            $csvGroup += [PsCustomObject]@{
                    SamAccountName = $AdGroup.SamAccountName
                    DoesExist = ''
                    Description = ''
                    DistinguishedName =''
                    ManagedBy = ''
                    ManagedByEnabled = ''                    
                    ManagedByEmail = ''
                    Members = $mem
                    MemberType = $MemType
                    MemberEnabled = $MemEnabled
                }
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
    Write-Host "ERROR: $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
}finally{
    Read-Host "Press enter to exit." 
}