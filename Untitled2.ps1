using module .\Modules\helpFunctions.psm1
using module .\Modules\CYBAUTOLibrary.ps1
using module .\Modules\TMOLibrary.psm1
using module .\Modules\psPAS\5.2.59\psPAS.psm1

Import-Module .\Modules\ps-menu\1.0.8\ps-menu.psm1 -DisableNameChecking
$CurrentVersion = (''+ (Get-Content .\version.txt -ErrorAction SilentlyContinue|Where-Object {$_.trim() -ne ''}|Select-Object -First 1)).Trim()
if($CurrentVersion -eq ''){ $CurrentVersion = 'v1.0'}
#Invoke-PS2EXE -inputFile .\Untitled2.ps1 -outputFile .\Tpas.exe -iconFile .\Tpas.ico -noConsole -version 2.0.0
#Import Configuration
. .\config.ps1
. .\menu-config.ps1

$mainRoutine = $true
$authenticated = $false
$SubMenu = $false
$nl = [environment]::NewLine
$headerSize = 35
$MenuTitle = 'Main Menu'
$Script:FirstLogin = $true

#region XAML
#Form Start
$FormTemp=(New-Object System.Windows.Forms.Form -Property @{TopMost = $true})
$FormTemp.Show()
$FormTemp.Close()
Add-Type -AssemblyName PresentationFramework, System.Drawing, System.Windows.Forms,WindowsFormsIntegration, WindowsBase

#-----------------------------------
. .\config.ps1
. .\menu-config.ps1

<#$binding = New-Object System.Windows.Data.Binding
$binding.Path = '[0]'
$binding.Mode = [System.Windows.Data.BindingMode]::OneWay
[void][System.Windows.Data.BindingOperations]::SetBinding($Hash.test, [System.Windows.Controls.TextBlock]::TextProperty, $binding) 
#>

$Global:Hash=[Hashtable]::Synchronized(@{})
$Global:Hash.Host = $Host
$Global:Hash.menuItems = $menuItems
$Global:Hash.command = ''
$Global:Hash.newMenuselection  = $null
$Global:Hash.Creds = $null
$Global:Hash.LoginType = $null
$Global:Hash.State = 0

function Write-Progress($Activity, [switch]$Complete){
    if($Complete.IsPresent -eq $true){
        $Global:Hash.XamlForm.Dispatcher.Invoke([action] {
            $Global:Hash.Waittext.text = 'In Progress..'
            $Global:Hash.waitScreen.Visibility = [System.Windows.Visibility]::Hidden
        },'Normal')
    }ELSE{
        $Global:Hash.XamlForm.Dispatcher.Invoke([action] {
            $Global:Hash.Waittext.text = $Activity
            $Global:Hash.waitScreen.Visibility = [System.Windows.Visibility]::Visible 
        },'Normal')       
    }

}

function Write-Host{

    Param([parameter(Position=0)]$Object, [switch]$LoginMessageData, [String]$ForegroundColor='White')
    if($ForegroundColor -eq 'Gray'){
        $Global:Hash.XamlForm.Dispatcher.Invoke([action] { 
            $Column = $global:Hash.MultipleInputBox.View.Columns|select -First 1
            $Column.Header = ($Object -split [environment]::NewLine|select -First 1).trim()
            $Global:Hash.MultipleInputBox.View.Columns
            $global:Hash.MultipleInputBox.View.Columns.Clear()
            $global:Hash.MultipleInputBox.View.Columns.Add($Column)
        },'Normal')
        $Global:isGray = $true
        return
    }

    if($LoginMessageData.IsPresent -eq $false){
        $Global:Hash.XamlForm.Dispatcher.Invoke([action] {
            $Run = New-Object System.Windows.Documents.Run
            $Run.Foreground = $ForegroundColor
            $Run.Text = ("> {0}" -f $Object)
            $Global:Hash.OutputBlock.Inlines.Add($Run)
            $Global:Hash.OutputBlock.Inlines.Add((New-Object System.Windows.Documents.LineBreak))      
        },'Normal')
    }elseif($LoginMessageData.IsPresent -eq $true){
        $Global:Hash.XamlForm.Dispatcher.Invoke([action] {$loginMessage.Content = $Object},'Normal')
    }
}

function Set-ResultButton($Result){
    $Block = {Start-Process -FilePath $Result}.GetNewClosure()
    $Global:Hash.OpenLastFile.add_click($Block)
    $Global:Hash.OpenLastFile.IsEnabled = $true
}

function Menu ([Array]$menuItems, [switch]$Multiselect, [switch]$ReturnIndex){
    $menuItems = $menuItems|where{$_ -ne 'Cancel' -and $_ -notlike '*Quit*'}
   if($Global:isGray){
        $temp = @()
        $menuItems | ForEach{ $temp += [PsCustomObject]@{CollectionName = $_}}

        if($Multiselect.IsPresent -eq $true){$Global:Hash.XamlForm.Dispatcher.Invoke([action] {$Global:Hash.MultipleInputBox.SelectionMode="Multiple"})}
        else{$Global:Hash.XamlForm.Dispatcher.Invoke([action] {$Global:Hash.MultipleInputBox.SelectionMode="Single"}) }

        $Global:Hash.XamlForm.Dispatcher.Invoke([action] {
            $Global:Hash.MultipleInputBox.ItemsSource = $temp            
            $Global:Hash.MultipleInputBox.Visibility = [System.Windows.Visibility]::Visible;
            $Global:Hash.MultipleInputSubmit.Visibility = [System.Windows.Visibility]::Visible;
            $Global:Hash.MultipleInputQuit.Visibility = [System.Windows.Visibility]::Visible;
            $Global:Hash.MultipleInputBoxLabel.Visibility = [System.Windows.Visibility]::Visible
        },'render')    
   }else{
       $Global:Hash.XamlForm.Dispatcher.Invoke([action] {
            $Global:Hash.newMenu.Items.Clear()
            foreach ($item in $menuItems)
            {
                $Global:Hash.newMenu.addtext($item) 
            } },'render')
    
        $Global:Hash.XamlForm.Dispatcher.Invoke([action] {
            $Global:Hash.newMenuLabe.Content = 'Select type'
            $Global:Hash.newMenuLabe.Visibility = [System.Windows.Visibility]::Visible;
            $Global:Hash.newMenu.Visibility = [System.Windows.Visibility]::Visible;
            $Global:Hash.newMenuSubmit.Visibility = [System.Windows.Visibility]::Visible;
            $Global:Hash.newMenuCancel.Visibility = [System.Windows.Visibility]::Visible
        },'render')
    }

    while($Global:Hash.newMenuselection -eq $null){
        [Threading.Thread]::Sleep(500)
    }

    $output = @()
    if($ReturnIndex.IsPresent -eq $true){
        foreach ($item in $Global:Hash.newMenuselection)
        {
            $output += $menuItems.IndexOf($item)
        }
    }else{
        foreach ($item in $Global:Hash.newMenuselection)
        {
            $output += $item
        }
    }
    $Global:Hash.newMenuselection  = $null
    $output | ForEach{Write-Host $_}
    return $output
}

function Invoke-FunCmdlets{   
   $Global:Hash.XamlForm.Dispatcher.Invoke([action] { 
        $Global:Hash.newMenuLabe.Visibility = [System.Windows.Visibility]::Hidden   
        $Global:Hash.newMenu.Visibility = [System.Windows.Visibility]::Hidden   
        $Global:Hash.OpenLastFile.IsEnabled=$false
    },'Normal')
    $sb = [System.Management.Automation.ScriptBlock]::Create($Global:Hash.command + ' -config $config')
    & $sb -config $config
}

function Start-Runspace{
    param($scriptblock)
    $newRunspace2 =[runspacefactory]::CreateRunspace()
    $newRunspace2.ApartmentState = "STA"
    $newRunspace2.ThreadOptions = "ReuseThread"         
    $newRunspace2.Open()
    $newRunspace2.SessionStateProxy.SetVariable("Hash",$global:Hash)
    $psCmd2 = [PowerShell]::Create().AddScript($ScriptBlock)
    $psCmd2.Runspace = $newRunspace2
    $psCMD2.BeginInvoke()|Out-Null
    $psCmd2.Streams.Error
    $psCmd2.Dispose()
}

function Invoke-PWDSetting([switch]$IsFirst) {

    if($IsFirst.IsPresent -eq $true){
        [Void]([Microsoft.VisualBasic.Interaction]::Msgbox("Click 'Ok' to set working directory for log files and file downloads.","OkOnly,SystemModal,Information","Information"))
    }

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

    $targetFolder = $targetFolder
    $logFileName = "$targetFolder\Logs\$(Get-Date -Format yyyyMMdd-hhmmss)-VaultManagementOperations.Log"
    $reportFileName = "$targetFolder\Reports\$(Get-Date -Format yyyyMMdd-hhmmss)-VaultManagementResults.csv" 
    $Global:Hash.XamlForm.Dispatcher.Invoke([action]{$Hash.WorkingDirectory.Text = $targetFolder})
}

function Start-Logging{
   
    try{
        New-PASSession -Credential $Global:Hash.Creds -BaseURI $config.url -type $Global:Hash.logintype -SkipCertificateCheck             
        $Global:Hash.XamlForm.Dispatcher.Invoke([action]{
            $Global:Hash.LoggedInUserName.Content = $(Get-PASSession).User
            $Global:Hash.LoggedInUserName.Foreground = "Red"
            $Global:Hash.loginMessage.Foreground = 'green'
            $Global:Hash.loginMessage.text = "Session Initiated for '$($Global:Hash.LoggedInUserName.Content)'."        
            $Global:Hash.loginPage.Visibility = [System.Windows.Visibility]::Hidden})
            
        if($Script:FirstLogin -eq $true){      
            Invoke-PWDSetting -IsFirst
            $Script:FirstLogin = $false
        }
        $Global:Hash.XamlForm.Dispatcher.Invoke([action]{
            $Global:Hash.Scroller.Visibility = [System.Windows.Visibility]::Visible
            $Global:Hash.MainPage.Visibility = [System.Windows.Visibility]::Visible})
    }
    catch {
        $Global:Hash.XamlForm.Dispatcher.Invoke({ 
            $Hash.loginMessage.Foreground = 'red';
            $Hash.loginMessage.text = "Error: Unable to Authenticate. $($_.Exception.Message)$($_.InvocationInfo.ScriptLineNumber)"})
    } 
}

$newRunspace =[runspacefactory]::CreateRunspace()
$newRunspace.ApartmentState = "STA"
$newRunspace.ThreadOptions = "ReuseThread"         
$newRunspace.Open()

$newRunspace.SessionStateProxy.SetVariable("Hash",$Global:Hash)   
        
$psCmd = [PowerShell]::Create().AddScript({   

    Add-Type -AssemblyName PresentationFramework, System.Drawing, System.Windows.Forms,WindowsFormsIntegration, WindowsBase

[xml]$XamlWindow = @"
<Window x:Name="window"  x:Class="WpfApp1.MainWindow"
        
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:WpfApp1"
        mc:Ignorable="d"
        Title="TPAS" Height="600" Width="800" HorizontalAlignment="Stretch" WindowStartupLocation="CenterScreen" WindowState="Normal" MinHeight="600" MinWidth="800" ResizeMode="CanResize">
    <Grid HorizontalAlignment="Center"  VerticalAlignment="Stretch" MinWidth = "780" MinHeight = "590">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="37*"/>
            <ColumnDefinition Width="63*"/>
        </Grid.ColumnDefinitions>
        <Grid.Background>
            <LinearGradientBrush EndPoint="0.5,1" StartPoint="0.5,0">
                <GradientStop Color="Black"/>
                <GradientStop Color="#FF82E8D5" Offset="1"/>
                <GradientStop Color="#FF09110F" Offset="0"/>
            </LinearGradientBrush>
        </Grid.Background>

        <Grid MinWidth = "380" MinHeight = "530" Margin = "5,31,2,5" Grid.Column="1" >
            <ScrollViewer Name = "Scroller" Visibility="Hidden" Margin = "0,8,4,4" Background = "Black"  MinHeight = "550">
               <StackPanel Orientation="Vertical"  HorizontalAlignment="Stretch" VerticalAlignment="Stretch">                        
                        <TextBlock Name="OutputBlock"  Foreground="White" FontFamily="Consolas" FontSize="16" Padding="10" Text="" TextWrapping="Wrap" />
                    </StackPanel>
            </ScrollViewer >            
            
        </Grid >
        <Viewbox x:Name="MainPage" Stretch="Fill"  Visibility="Visible"  MinWidth="300" MinHeight="550" HorizontalAlignment="Left" Grid.ColumnSpan="2">
            <Grid MinHeight="590">
                <Label x:Name="AuthenticatedAs" Content="Logged In As:" HorizontalAlignment="Left" VerticalAlignment="Top"  Background="#00000000" HorizontalContentAlignment="Left" VerticalContentAlignment="Center" Foreground="#FFEBE607" FontSize="12" Margin="8,1,0,0">
                    <Label.BorderBrush>
                        <LinearGradientBrush EndPoint="0.5,1" StartPoint="0.5,0">
                            <GradientStop Color="Black"/>
                            <GradientStop Color="#FFD74C4C" Offset="1"/>
                        </LinearGradientBrush>
                    </Label.BorderBrush>
                </Label>
                <Label x:Name="MainMenuInfo" Content="Please Select Desired Operation:" HorizontalAlignment="Left" VerticalAlignment="Top"  Height="26" Margin="8,32,0,0" Width="198" FontWeight="Bold" Foreground="#FFF3DF24">
                    <Label.Background>
                        <SolidColorBrush Color="{Binding ElementName=window, Mode=OneWay}"/>
                    </Label.Background>
                </Label>
                <ComboBox x:Name="MainMenuList" HorizontalAlignment="Left" VerticalAlignment="Top"  MinWidth="210" Margin="29,82,0,0" IsReadOnly="True" FontWeight="Bold" SelectedIndex="0" Width="223"/>
                <Label x:Name="LoggedInUserName" HorizontalAlignment="Left" VerticalAlignment="Top"  Content="No User logged In" Margin="90,1,0,0" Background="#00000000" HorizontalContentAlignment="Left" VerticalContentAlignment="Center" Foreground="Red" FontSize="12" Width="127">
                    <Label.BorderBrush>
                        <LinearGradientBrush EndPoint="0.5,1" StartPoint="0.5,0">
                            <GradientStop Color="Black"/>
                            <GradientStop Color="#FFD74C4C" Offset="1"/>
                        </LinearGradientBrush>
                    </Label.BorderBrush>
                </Label>
                <ComboBox x:Name="SubMenuList" HorizontalAlignment="Left" VerticalAlignment="Top" MinWidth="210" Margin="29,128,0,0" IsReadOnly="True" FontWeight="Bold" SelectedIndex="0" Width="223" />

                <Button x:Name="OpenDirectorybutton" HorizontalAlignment="Right" VerticalAlignment="Top" Content="Open Dir." Margin="0,3,1,0" RenderTransformOrigin="0.583,1.704" Background="#FFFCE8A7" Height="25" MinWidth="76"/>
                <Label x:Name="MainMenuLabel" Content="Main menu" HorizontalAlignment="Left" VerticalAlignment="Top"  Height="26" Margin="10,56,588,508" Width="198" FontWeight="Bold" Foreground="#FFC2AEAE">
                    <Label.Background>
                        <SolidColorBrush Color="{Binding ElementName=window, Mode=OneWay}"/>
                    </Label.Background>
                </Label>

                <Label x:Name="SubMenuLabel" Content="Sub menu" HorizontalAlignment="Left" VerticalAlignment="Top" Height="26" Margin="10,102,0,0" Width="198" FontWeight="Bold" Foreground="#FFC2AEAE">
                    <Label.Background>
                        <SolidColorBrush Color="{Binding ElementName=window, Mode=OneWay}"/>
                    </Label.Background>
                </Label>
                <Button x:Name="OpenLastFile" HorizontalAlignment="Left" VerticalAlignment="Top" Content="Open Result" IsEnabled="False" Margin="153,167,0,0" RenderTransformOrigin="0.583,1.704" Background="#FFFCE8A7" Width="73" Height="25"/>
                <Button x:Name="Execute" HorizontalAlignment="Left" VerticalAlignment="Top" Content="Execute" IsEnabled="True" Margin="49,167,0,0" RenderTransformOrigin="0.583,1.704" Background="#FFFCE8A7" Width="73" Height="25"/>

                <TextBox x:Name="WorkingDirectory" VerticalAlignment="Top" Margin="295,4,155,0" TextWrapping="Wrap" Text="Working Directory" Height="23" IsReadOnly="True" MinWidth="340"/>
                <Button x:Name="ChangeDirectorybutton" HorizontalAlignment="Right" VerticalAlignment="Top" Content="Change Dir." Margin="0,3,78,0" RenderTransformOrigin="0.583,1.704" Background="#FFFCE8A7" Height="25" MinWidth="76" Width="60"/>
                <Button x:Name="LoginAgain" HorizontalAlignment="Left" VerticalAlignment="Top" Content="ReLogin" Margin="217,3,0,0" RenderTransformOrigin="0.583,1.704" Background="#FFFCE8A7" Height="25" MinWidth="76" Width="26"/>

                <ComboBox x:Name="newMenu" Visibility="Hidden" HorizontalAlignment="Left" VerticalAlignment="Top"  MinWidth="210" Margin="27,220,0,0" IsReadOnly="True" FontWeight="Bold" SelectedIndex="0" Width="223"/>
                <Label x:Name="newMenuLabe" Visibility="Hidden" Content="Select type" HorizontalAlignment="Left" VerticalAlignment="Top" Height="26" Margin="10,194,0,0" Width="198" FontWeight="Bold" Foreground="#FFC2AEAE">
                    <Label.Background>
                        <SolidColorBrush Color="{Binding ElementName=window, Mode=OneWay}"/>
                    </Label.Background>
                </Label>
                <Button x:Name="newMenuSubmit" Visibility="Hidden" HorizontalAlignment="Left" VerticalAlignment="Top" Content="Submit" Margin="49,252,0,0" RenderTransformOrigin="0.583,1.704" Background="#FFFCE8A7" Width="73" Height="25"/>
                <Button x:Name="newMenuCancel" Visibility="Hidden" HorizontalAlignment="Left" VerticalAlignment="Top" Content="Cancel" Margin="153,252,0,0" RenderTransformOrigin="0.583,1.704" Background="#FFFCE8A7" Width="73" Height="25"/>
                
                <ListView x:Name="MultipleInputBox" Visibility="Hidden" HorizontalAlignment="Left" VerticalAlignment="Top"  MinWidth="210" Margin="6,301,0,0" FontWeight="Bold" SelectedIndex="0" Width="283" Height="217">
                    <ListView.View>
                        <GridView>
                            <GridViewColumn Width="283" Header="CollectionName" DisplayMemberBinding="{Binding CollectionName}" />
                        </GridView>
                    </ListView.View>
                </ListView>
                <Label x:Name="MultipleInputBoxLabel" Visibility="Hidden" Content="Select from below" HorizontalAlignment="Left" VerticalAlignment="Top" Height="26" Margin="10,275,0,0" Width="198" FontWeight="Bold" Foreground="#FFC2AEAE">
                    <Label.Background>
                        <SolidColorBrush Color="{Binding ElementName=window, Mode=OneWay}"/>
                    </Label.Background>
                </Label>
                <Button x:Name="MultipleInputSubmit" Visibility="Hidden" HorizontalAlignment="Left" VerticalAlignment="Top" Content="Submit" IsEnabled="True" Margin="49,528,0,0" RenderTransformOrigin="0.583,1.704" Background="#FFFCE8A7" Width="73" Height="25"/>
                <Button x:Name="MultipleInputQuit" Visibility="Hidden" HorizontalAlignment="Left" VerticalAlignment="Top" Content="Quit" IsEnabled="True" Margin="153,528,0,0" RenderTransformOrigin="0.583,1.704" Background="#FFFCE8A7" Width="73" Height="25"/>


            </Grid>
        </Viewbox>
        <Viewbox x:Name="loginPage" Stretch="Uniform" Visibility="Hidden" MinHeight="550" Grid.ColumnSpan ="2">
            <Grid MinHeight="553">
                <Label x:Name="Title" Content="Welcome to TPAS $($CurrentVersion)" Margin="122,97,113,412" Height="44" Width="322" Background="#00000000" HorizontalContentAlignment="Center" VerticalContentAlignment="Center" Foreground="#FFF10F0F" FontSize="22">
                    <Label.BorderBrush>
                        <LinearGradientBrush EndPoint="0.5,1" StartPoint="0.5,0">
                            <GradientStop Color="Black"/>
                            <GradientStop Color="#FFD74C4C" Offset="1"/>
                        </LinearGradientBrush>
                    </Label.BorderBrush>
                </Label>
                <Label x:Name="username" Content="Username" Margin="242,171,246,359" Height="23" Width="136" MinHeight="23" MinWidth="136" FontWeight="Bold">
                    <Label.Background>
                        <SolidColorBrush Color="{Binding ElementName=window, Mode=OneWay}"/>
                    </Label.Background>
                </Label>
                <TextBox x:Name="Username_box" TextWrapping="Wrap" MaxHeight="26" Margin="244,199,244,330" MaxWidth="136" Height="24" Width="136" Background="#FFDBEBED"/>
                <Label x:Name="password" Content="Password"  Margin="242,223,246,307" MinHeight="23" MinWidth="136" Height="23" Width="136" FontWeight="Bold">
                    <Label.Background>
                        <SolidColorBrush Color="{Binding ElementName=window, Mode=OneWay}"/>
                    </Label.Background>
                </Label>
                <PasswordBox x:Name="Password_box" Margin="244,249,244,280" MaxHeight="24" MaxWidth="136" Height="24" Width="136" Background="#FFDBEBED"/>
                <ComboBox x:Name="login_type" Width="136" Margin="244,148,244,381" IsReadOnly="True" FontWeight="Bold" Text="Select Type" SelectedIndex="0"/>
                <Button x:Name="loginButton" Content="Login" Margin="244,284,316,242" Height="27" Width="64" Background="#FFFCE8A7"/>
                <Button x:Name="logoutButton" Content="Logout" Margin="316,284,244,242" Height="27" Width="64" Background="#FFFCE8A7"/>
                <TextBox x:Name="loginMessage" Text="{Binding ElementName=loginMessage, Mode=OneWay}" Width="632" Height="36" BorderThickness="0" Foreground="red" FontSize="11" FontWeight="Bold" FontFamily="Times New Roman" TextAlignment="Center"  Background="Transparent" IsReadOnly="True" TextWrapping="Wrap" Margin="-4,317,-4,200"/>

            </Grid>
        </Viewbox>

        <Border x:Name="waitScreen" BorderBrush="Black" BorderThickness="1" Background="#80000000" Visibility="Hidden" Grid.ColumnSpan="2">
            <Grid>
                <TextBlock x:Name="Waittext" Margin="0" TextWrapping="Wrap" Text="Please Wait..." HorizontalAlignment="Center" VerticalAlignment="Center" FontSize="24" FontWeight="Bold" Foreground="#7EFFFFFF"/>
            </Grid>
        </Border>

    </Grid>
</Window>
"@ -replace 'mc:Ignorable="d"','' -replace "x:Name",'Name' -replace '^<Win.*', '<Window' -replace 'x:Class="\S+"','' -replace '^<Window.*', '<Window'

    #Read XAML
    $reader2=(New-Object System.Xml.XmlNodeReader $XamlWindow)
    $XamlForm=[Windows.Markup.XamlReader]::Load($reader2)    
    $XamlWindow.SelectNodes("//*[@Name]")|ForEach-Object {$Hash.($_.Name)= $XamlForm.FindName($_.Name)}
    #endregion
    $Hash.XamlForm = $XamlForm
    $Hash.menuItems.Keys | ForEach-Object {$Hash.MainMenuList.addtext($_)}
    $Hash.MainMenuList.SelectedIndex = 0
    $Hash.SelectedItem = $Hash.MainMenuList.SelectedItem
    $Hash.menuItems[$Hash.SelectedItem].Keys | ForEach-Object {$Hash.SubMenuList.addtext($_)}
    ("Cyberark", "Radius", "LDAP") | ForEach-Object {$Hash.login_type.addtext($_)}

# code to run when button is clicked
#-----------------------------------

function Invoke-Login{
        
    if($Hash.Username_box.Text.Trim() -eq ''){
        $Hash.loginMessage.Foreground = 'yellow'
        $Hash.loginMessage.text = "Please Enter UserName." 

    }elseif($Hash.Password_box.Password.Trim() -eq ''){
        $Hash.loginMessage.Foreground = 'yellow'
        $Hash.loginMessage.text = "Please Enter Password."

    }else{
        $Hash.loginMessage.Foreground = 'yellow'    
        $Hash.loginMessage.text = "Logging in.."

        if($Hash.login_type.Text -eq 'Radius'){
            [Void]([Microsoft.VisualBasic.Interaction]::Msgbox("As You have Selected RADIUS, be Ready to Accept the Push MFA Request","OkOnly,SystemModal,Information","Information"))
        }
                
        $sec = ConvertTo-SecureString -AsPlainText $Hash.Password_box.Password.Trim() -Force
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Hash.Username_box.Text.Trim(), $sec
        $Hash.Creds = $cred
        $Hash.LoginType = $Hash.login_type.SelectedItem
        $Hash.State = 2
    }   
}

function Invoke-Logout{
    $Hash.loginPage.Visibility = [System.Windows.Visibility]::Visible           
    $Hash.MainPage.Visibility = [System.Windows.Visibility]::Hidden
    $Hash.Scroller.Visibility = [System.Windows.Visibility]::Hidden
    $Hash.Username_box.Text = ""
    $Hash.Password_box.Password = ""
    $Hash.LoggedInUserName.Content = "No User Logged In"
    $Hash.LoggedInUserName.Foreground = "Red"
    $Hash.loginMessage.text = ""
    $Hash.State = 3
}

function Set-ResultButton($Result){
    $Block = {Start-Process -FilePath $Result}.GetNewClosure()
    $Hash.OpenLastFile.add_click($Block)
    $Hash.OpenLastFile.IsEnabled = $true
}

function Write-Host{

    Param([parameter(Position=0)]$Object, [switch]$LoginMessageData, [String]$ForegroundColor='White')
    
    if($LoginMessageData.IsPresent -eq $false){
        $Global:Hash.XamlForm.Dispatcher.Invoke([action] {
            $Run = New-Object System.Windows.Documents.Run
            $Run.Foreground = $ForegroundColor
            $Run.Text = ("> {0}" -f $Object)
            $Global:Hash.OutputBlock.Inlines.Add($Run)
            $Global:Hash.OutputBlock.Inlines.Add((New-Object System.Windows.Documents.LineBreak))      
        },'Normal')
    }elseif($LoginMessageData.IsPresent -eq $true){
        $Global:Hash.XamlForm.Dispatcher.Invoke([action] {$loginMessage.Content = $Object},'Normal')
    }
}

    $Script:FirstLogin = $true

    $Hash.SubMenuList.Clear()
    $Hash.MainMenuList.add_SelectionChanged({
        $Hash.SubMenuList.Items.Clear()
        $Hash.SelectedItem = $Hash.MainMenuList.SelectedItem
        $Hash.menuItems[$Hash.SelectedItem].Keys | ForEach-Object {$Hash.SubMenuList.addtext($_)}
        $Hash.SubMenuList.SelectedIndex = 0
})

    $Hash.loginButton.add_click({Invoke-Login})
    $Hash.LoginAgain.add_click({Invoke-Logout})
    $Hash.ChangeDirectorybutton.add_click({$Hash.State = 4})
    $Hash.logoutButton.add_click({Invoke-Logout})
        
    $Hash.Execute.add_click({$Hash.command=$($Global:Hash.menuItems[$Global:Hash.MainMenuList.SelectedIndex])[$Global:Hash.SubMenuList.SelectedItem] ; $Hash.State = 1; Write-Host "Running $($Hash.command)" ;$Global:Hash.Execute.IsEnabled=$false})
    $Hash.loginMessage.text = ""
    $Hash.OpenDirectorybutton.add_click({Start-Process -FilePath $Hash.WorkingDirectory.Text})

    $Hash.newMenuSubmit.add_click({
        $Hash.newMenuLabe.Visibility = [System.Windows.Visibility]::Hidden ;  
        $Hash.newMenu.Visibility = [System.Windows.Visibility]::Hidden;
        $Hash.newMenuSubmit.Visibility = [System.Windows.Visibility]::Hidden;
        $Hash.newMenuCancel.Visibility = [System.Windows.Visibility]::Hidden
        $Hash.newMenuselection  = $Hash.newMenu.SelectedItem
})
    $Hash.newMenuCancel.add_click({
        $Hash.newMenuLabe.Visibility = [System.Windows.Visibility]::Hidden ;  
        $Hash.newMenu.Visibility = [System.Windows.Visibility]::Hidden;
        $Hash.newMenuSubmit.Visibility = [System.Windows.Visibility]::Hidden;
        $Hash.newMenuCancel.Visibility = [System.Windows.Visibility]::Hidden
        $Hash.newMenuselection  = $Hash.newMenu.SelectedItem
})

    $Hash.MultipleInputSubmit.add_click({
        $Hash.MultipleInputBox.Visibility = [System.Windows.Visibility]::Hidden;
        $Hash.MultipleInputSubmit.Visibility = [System.Windows.Visibility]::Hidden;
        $Hash.MultipleInputQuit.Visibility = [System.Windows.Visibility]::Hidden;
        $Hash.MultipleInputBoxLabel.Visibility = [System.Windows.Visibility]::Hidden;        
        $Hash.newMenuselection  = @()
        $Hash.MultipleInputBox.SelectedItems| ForEach{ $Hash.newMenuselection += $_.CollectionName }
})
    $Hash.MultipleInputQuit.add_click({
        $Hash.MultipleInputBox.Visibility = [System.Windows.Visibility]::Hidden;
        $Hash.MultipleInputSubmit.Visibility = [System.Windows.Visibility]::Hidden;
        $Hash.MultipleInputQuit.Visibility = [System.Windows.Visibility]::Hidden;
        $Hash.MultipleInputBoxLabel.Visibility = [System.Windows.Visibility]::Hidden;        
        $Hash.newMenuselection  = @('Quit')
})
    $Hash.loginPage.Visibility = [System.Windows.Visibility]::Hidden           
    $Hash.MainPage.Visibility = [System.Windows.Visibility]::Visible
    $Hash.Scroller.Visibility = [System.Windows.Visibility]::Visible
    # code to run before button click event
    $null = $XamlForm.ShowDialog();
    $XamlForm.Close()
    #Get-Runspace |Where{$_.RunspaceAvailability -eq $true}|ForEach{$_.Dispose()}
})
$psCmd.Runspace = $newRunspace
$data = $psCmd.BeginInvoke()

while(-Not($Global:Hash.XamlForm.IsVisible)){[Threading.Thread]::Sleep(500)}

while($Global:Hash.XamlForm.IsVisible){    
    #Write-Host $($Global:Hash.State)
    $Global:isGray = $false
    if($Global:Hash.State -eq 1){
        Invoke-FunCmdlets
        $Global:Hash.XamlForm.Dispatcher.Invoke([action] { $Global:Hash.Execute.IsEnabled=$true},'Normal')
        $Global:Hash.State = -1    
    }elseif($Global:Hash.State -eq 0){
        Write-Host 'Waiting for command.'
        $Global:Hash.State = -1 
    }elseif($Global:Hash.State -eq 2){ 
        Start-Logging        
        $Global:Hash.State = -1  
    }elseif($Global:Hash.State -eq 3){
        Close-PASSession -ErrorAction SilentlyContinue
        $Global:Hash.State = -1 
    }elseif($Global:Hash.State -eq 4){
        Invoke-PWDSetting
        $Global:Hash.State = -1 
    }

    [Threading.Thread]::Sleep(500)
}

[environment]::Exit(0)