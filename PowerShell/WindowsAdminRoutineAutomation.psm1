### if you wanna do separate on remote server you need import this part of code ###

function New-LocalUser {
<#
.SYNOPSIS
Create local user using ADSI.
.DESCRIPTION
New-LocalUser works much quicker than net user. You can use New-LocalUser to create local user with PasswordNeverExpired flag (default value).
.PARAMETER UserName
Specifies the Security Account Manager (SAM) account name of the user, to be compatible with older operating systems, create a SAM account name that is 20 characters or less.
.PARAMETER Password
Specifies a new password value for an account.
.PARAMETER Desc
 Specifies a description of the object. This parameter sets the value of the Description property for the object.
.PARAMETER Expired
Specifies password expiration date based on domain password change policy.
.PARAMETER ServerName
Greate local user on the specified computers. The default is the local computer.
.EXAMPLE
New-LocalUser -UserName "WASUSER" -Password "Qq123456"
This command creates a new local user named WASUSER with Qq123456 password and PasswordNeverExpired flag.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$True,Position=0)][string]$UserName,
    [Parameter(Mandatory=$True,Position=1)][string]$Password,
    
    [Parameter()]
    [Alias('ServerName')]
    [string[]]$ComputerName = [environment]::MachineName,
    
    
    [string]$Desc,
    [switch]$Expired
    )

  foreach ($entity in $ComputerName){
    $cn = [ADSI]"WinNT://$entity"
    $user = $cn.Create("User",$UserName)
    $user.SetPassword($Password)
    
    if ($Expired){
      $user.PasswordExpired=1
      $user.SetInfo()
      }
    else{
      $user.UserFlags.value = $user.UserFlags.value -bor 0x10000
      $user.CommitChanges()
      $user.SetInfo()
      }
   
    if (![string]::IsNullOrEmpty($Desc)){
      $user.description = "$Desc"
      $user.SetInfo()
    }
  }
} 

function Remove-LocalUser {
<#
.SYNOPSIS
Delete local user using ADSI.
.DESCRIPTION
Remove-LocalUser is PowerShell version of net user /delete.
.PARAMETER UserName
Specifies the Security Account Manager (SAM) account name of the local user.
.PARAMETER ComputerName
Delete local user on the specified computers. The default is the local computer.
.EXAMPLE
 Remove-LocalUser -UserName cbusers180
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$True,Position=1)][string]$UserName,
    
    [Parameter()]
    [Alias('ServerName')]
    [string[]]$ComputerName = [environment]::MachineName
    )

  $cn = [ADSI]"WinNT://$ComputerName"
  $user = $cn.delete("User",$UserName)
  }

function Get-LocalGroupMember { 
 <#
.SYNOPSIS
Get local group members on the local computer or a remote computer.
.DESCRIPTION
Get-LocalGroupMember uses ADSI to retrieve the local group members.
.PARAMETER GroupName
Specifies a local group object. 
.PARAMETER Custom
.PARAMETER ComputerName
Gets the local group member on the specified computers. The default is the local computer.
.EXAMPLE
Get-LocalGroupMember -GroupName "Administrators"
This command gets all the group members of the Administrators group.
.EXAMPLE
Get-LocalGroupMember -GroupName "Remote Desktop Group" -ServerName sbt-osa-212
This command gets all the group members of the "Remote Desktop Group" on sbt-osa-212
#>
    [CmdletBinding()]
    param (
      [parameter(ParameterSetName= "Standard",Mandatory=$true,Position=0)]
      [Alias('StandardGroup')]
      [ValidateSet('Administrators',
                   'Remote Desktop Users',
                   'IBM_Admins',
                   'IBM_Logs_Read',
                   'IBM_Config_Read',
                   'AllowRemoteReboot',
                   'Performance Monitor Users',
                   'Event Log Readers',
                   'Performance Log Users')]
      [string]$GroupName,

      [parameter(ParameterSetName= "Custom",Mandatory=$true)]
      [Alias('CustomGroup')]
      [string]$Custom,      

      [parameter(Mandatory=$False,Position=1)]
      [Alias('ServerName')]
      [string[]]$ComputerName = [environment]::MachineName
      )

    foreach ($Item in $ComputerName){
      if ($PSCmdlet.ParameterSetName -eq "Standard"){
        $OperatingSystem = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Item
        $Language = $OperatingSystem.MUILanguages
        
        if ($Language -eq "ru-RU"){
          switch($GroupName){
            "Administrators"            {$Identity = "Администраторы"}
            "Remote Desktop Users"      {$Identity = "Пользователи удаленного рабочего стола"}
            "Performance Monitor Users" {$Identity = "Пользователи системного монитора"}
            "Performance Log Users"     {$Identity = "Пользователи журналов производительности"}
            "Event Log Readers"         {$Identity = "Читатели журнала событий"} 
          }         
        }
        else {
          $Identity  = $GroupName
        }             
      }

      else {
        $Identity = $Custom
      }
      
      $Item = $Item.ToUpper()
      $Group = [ADSI]"WinNT://$Item/$Identity"
      $Members = $Group.Invoke("Members")
      
      foreach ($Entity in $Members){
        $ADSI = [ADSI]$Entity
        [array]$SplitPath = $ADSI.path -split "/"
        $Name = $SplitPath[-1]
        $Domain = $SplitPath[-2]
        if ($Domain -eq $Item){
          $Type = "Local"
        }
        else {
          $Type = "$Domain"
        }
        
        $res = [ordered]@{ 
          Name                 = $Name
          SchemaClassName      = $ADSI.SchemaClassName
          Domain               = $Type
          ServerName           = $Item
          GroupName            = $Identity
        }        
        
        $GroupMember = New-Object PSObject -Property $res
        $GroupMember
      }        
    }
}

function Add-LocalGroupMember {
 <#
.SYNOPSIS
Add user or group object to local group on the local computer or a remote computer.
.DESCRIPTION
Add-LocalGroupMember uses ADSI to add object to local group.
.PARAMETER objName
Specifies a set of user or group objects in a comma-separated list to add to a group.
.PARAMETER GroupName
Specifies a local group object. 
.PARAMETER Custom
.PARAMETER ComputerName
Add members to the local group on the specified computers. The default is the local computer.
.PARAMETER Domain
Specifies domain for user account. The default value for this parameter is determined by using the domain of the computer running Windows PowerShell.
.EXAMPLE
Add-LocalGroupMember -objName sbt-kopytov-ds,sbt-alan-miller -GroupName "Administrators"
This command adds user accounts with SamAccountNames sbt-kopytov-ds and sbt-alan-miller to the group Administrators.
.EXAMPLE
Get-LocalGroupMember -GroupName "Remote Desktop Users" | Add-LocalGroupMember -GroupName "IBM_Admins" -Verbose
Get members from local group Remote Desktop Users then add to group IBM_Admins
#>
    [CmdletBinding()]
    param (
      [parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
      [Alias('Member','objName')]
      [string[]]$Name,
      
      [parameter(ParameterSetName= "Standard",Mandatory=$true,Position=1)]
      [Alias('StandardGroup')]
      [ValidateSet('Administrators',
                   'Remote Desktop Users',
                   'IBM_Admins',
                   'IBM_Logs_Read',
                   'IBM_Config_Read',
                   'AllowRemoteReboot',
                   'Performance Monitor Users',
                   'Event Log Readers',
                   'Performance Log Users','')]
      [string]$GroupName,
      
      [parameter(ParameterSetName= "Custom",Mandatory=$true)]
      [Alias('CustomGroup')]
      [string]$Custom,

      [parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
      [Alias('ServerName')]
      [string[]]$ComputerName = [environment]::MachineName,
       
      [parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
      [ValidateSet('Local','ALPHA','SIGMA','OMEGA')]
      [string]$Domain = [environment]::UserDomainName
      )
  
  Process{
    foreach ($Item in $ComputerName){ 
      $Item = $Item.ToUpper()
      
      if(!(Test-Connection -ComputerName $Item -Count 1 -Quiet)){
        Write-Output "ERROR: Testing connection to computer $Item failed"
        continue 
      }
      
      if ($PSCmdlet.ParameterSetName -eq "Standard"){
        $OperatingSystem = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Item
        $Language = ($OperatingSystem.MUILanguages)[0]

        if ($Language -eq "ru-RU"){
          switch($GroupName){
            "Administrators"            {$Identity = "Администраторы"}
            "Remote Desktop Users"      {$Identity = "Пользователи удаленного рабочего стола"}
            "Performance Monitor Users" {$Identity = "Пользователи системного монитора"}
            "Performance Log Users"     {$Identity = "Пользователи журналов производительности"}
            "Event Log Readers"         {$Identity = "Читатели журнала событий"} 
          }         
        }
        else {
          $Identity  = $GroupName
        }             
      }
      else {
        $Identity = $Custom
      }

      $LocalGroup = [ADSI]"WinNT://$Item/$Identity,group" 
      
      foreach ($Entity in $Name){  
        $Entity = $Entity.trim()
        if ($Domain -eq "Local"){
          $FQDN = "$Item\$Entity"
        }
        else{
          $FQDN = "$Domain\$Entity"
        }
        
        Write-Verbose "Adding $FQDN to localgroup $Identity on $Item"
        
        trap [System.Management.Automation.MethodInvocationException] {
          [string]$str = $_
          $dots = $str.LastIndexOf("`:")
          $message = $str.Substring(($dots+3))
          $srtArr = $message -split '\r'
          $script:trap = $srtArr[0]
          ;continue
        }
        trap [System.Management.Automation.RuntimeException] {
          [string]$str = $_
          $dots = $str.LastIndexOf("`:")
          $message = $str.Substring(($dots+3))
          $srtArr = $message -split '\r'
          $script:trap = $srtArr[0]
          ;continue
        }

        if ($Domain -eq "Local"){
          #Получаем объект
          $obj=[ADSI]"WinNT://$Item/$Entity,user"
          
          if ($obj.Path){
            $LocalGroup.Add($obj.Path)
          }        
          else {
            $errorout = "local user $Entity not found on $Item"
          }
        }  
        
        else{
          $obj=[ADSI]"WinNT://$env:USERDNSDOMAIN/$Entity,group"
          if (!$obj.Path){
            $obj=[ADSI]"WinNT://$env:USERDNSDOMAIN/$Entity,user"
          }
          if ($obj.Path){
            $LocalGroup.Add($obj.Path)
          }
          else{
            $errorout = "$Entity not found in $env:USERDNSDOMAIN"
          }
        }
        
        if ($LocalGroup -and $obj.Path -and !($trap)){
          Write-Output "SUCCESS: $FQDN added to group $Identity on $Item"  
        }
        elseif ($trap){
          Write-Output "ERROR: $trap"
          Remove-Variable trap -Scope script -Force -ErrorAction SilentlyContinue
        }
        elseif ($errorout) {
          Write-Output "ERROR: $errorout"
          Remove-Variable errorout -Force -ErrorAction SilentlyContinue
          }
        else{
          Write-Output "ERROR: something was wroaddng" 
        }     
      }
    }
  }
  End{
    Remove-Variable trap -Scope script -Force -ErrorAction SilentlyContinue
  }
}

function Remove-LocalGroupMember {
 <#
.SYNOPSIS
Remove user or group object from local group on the local computer or a remote computer.
.DESCRIPTION
Remove-LocalGroupMember uses ADSI to remove object from local group.
.PARAMETER Name
Specifies a set of user or group objects in a comma-separated list to add to a group.
.PARAMETER GroupName
Specifies a local group object.
.PARAMETER Custom
.PARAMETER SchemaClassName
Specifies type of object: group or user. The default value is user.
.PARAMETER ComputerName
Add members to the local group on the specified computers. The default is the local computer.
.PARAMETER Domain
Specifies domain for user account. The default value for this parameter is determined by using the domain of the computer running Windows PowerShell.
.EXAMPLE
Remove-LocalGroupMember -objName sbt-kopytov-ds -GroupName "Perfomance Log Users"
Tihs command remove user with name sbt-kpoytov-ds from Administrators group.
.EXAMPLE
Get-LocalGroupMember "Administrators" | Remove-LocalGroupMember -Verbose
Remove all members from local group Administrators.
#>
    [CmdletBinding()]
    param (
      [parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
      [Alias('User','Group','objName','Member')]
      [string[]]$Name,
      
      [parameter(ParameterSetName= "Standard",Mandatory=$true,Position=1)]
      [Alias('StandardGroup')]
      [ValidateSet('Administrators',
                   'Remote Desktop Users',
                   'IBM_Admins',
                   'IBM_Logs_Read',
                   'IBM_Config_Read',
                   'AllowRemoteReboot',
                   'Performance Monitor Users',
                   'Event Log Readers',
                   'Performance Log Users','')]
      [string]$GroupName,
      
      [parameter(ParameterSetName= "Custom",Mandatory=$true)]
      [Alias('CustomGroup')]
      [string]$Custom,
      
      [parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
      [Alias('ServerName')]
      [string[]]$ComputerName = [environment]::MachineName,
      
      [parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
      [Alias('UserOrGroup')]
      [ValidateSet('User','Group')]
      [string]$SchemaClassName = "User",
      
      [parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
      [ValidateSet('Local','ALPHA','SIGMA','OMEGA')]
      [string]$Domain = [environment]::UserDomainName
      )

    Process{
    
    foreach ($Item in $ComputerName){
      $Item = $Item.ToUpper()
      if ($PSCmdlet.ParameterSetName -eq "Standard"){
        $OperatingSystem = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Item
        $Language = ($OperatingSystem.MUILanguages)[0]

        if ($Language -eq "ru-RU"){
          switch($GroupName){
            "Administrators"            {$Identity = "Администраторы"}
            "Remote Desktop Users"      {$Identity = "Пользователи удаленного рабочего стола"}
            "Performance Monitor Users" {$Identity = "Пользователи системного монитора"}
            "Performance Log Users"     {$Identity = "Пользователи журналов производительности"}
            "Event Log Readers"         {$Identity = "Читатели журнала событий"} 
          }         
        }
        else {
          $Identity  = $GroupName
        }             
      }
      else {
        $Identity = $Custom
      }
      
      $LocalGroup = [ADSI]"WinNT://$Item/$Identity,group" 
      foreach ($Entity in $Name){
        if ($Domain -eq "Local"){
          $obj = [ADSI]"WinNT://$Item/$Entity,$SchemaClassName"
        }
        else{
          $obj=[ADSI]"WinNT://$env:USERDNSDOMAIN/$Entity,$SchemaClassName"
        }
      
      Write-Verbose "Deleting something with name $Entity from $Item"
      $LocalGroup.remove($obj.Path)
      }      
    }
  } 
}

function Set-RightToRegistry {
 <#
.SYNOPSIS
Changes the security descriptor of a specified regestry key.
.DESCRIPTION
Changes the security descriptor of the specified item. 
.PARAMETER Key
Enter the path to a registry key.
.PARAMETER Right
This parameter takes one of file system rights: ReadKey or FullControl. The default is ReadKey.
.PARAMETER SamAccountName
Specifies the Security Account Manager (SAM) account name.
.EXAMPLE
Set-RightToRegistry -Key "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg" -SamAccountName sbt-osa-admins
#>
      [CmdletBinding()]
      param(
      [parameter(Mandatory=$true)]$Key,
      
      [parameter()]
      [ValidateSet('ReadKey','FullControl')]
      $Right = 'ReadKey',
      
      [parameter(Mandatory=$true)]
      [Alias('Group','User')]
      $SamAccountName
      )
      
      if (Test-Path $key){
        Write-Host "Добавляем $SamAccountName для ветки реестра:" -ForegroundColor green
        Write-Host $key -ForegroundColor White
        $ACL= Get-ACL "$key" 
        $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit 
        $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        $ar = New-Object System.Security.AccessControl.RegistryAccessRule($SamAccountName,$right,$InheritanceFlag,$PropagationFlags,"Allow") 
        $ACL.SetAccessRule($ar) 
        $ACL |Set-Acl -Path "$key" 
        Remove-Variable -Name key,ar,right,ACL -Confirm:$false
        }
      else{
        Write-Host -ForegroundColor black -BackgroundColor Yellow "Ключ: $key - не найден!" 
      }
}

function Set-RightToService {
 <#
.SYNOPSIS
Set full right to service for specified user or group.
.DESCRIPTION
Set 'CCDCLCSWRPWPDTLOCRSDRCWDWO' rights uses sc.exe.
.PARAMETER ServiceName
Specifies service name. Wildcards are permitted.
.PARAMETER SamAccountName
Specifies the Security Account Manager (SAM) account name.
.PARAMETER log
If Log, create text file with current right of service to C:\temp directory.
.EXAMPLE
#Set-RightToService -ServiceName "Transact_Prodc*" -SamAccountName "ALPHA\$ADGroup"
#>
     [CmdletBinding()]
     param(
     [parameter(Mandatory=$true,Position=0)]
     [string[]]$ServiceName,
        
     [parameter(Mandatory=$true,Position=1)]
     [Alias('Group','User')]
     $SamAccountName,
     
     [switch]$log
     )

     #получаем SID группы
     $obj = New-Object System.Security.Principal.NTAccount($SamAccountName)
     $strSID = $obj.Translate([System.Security.Principal.SecurityIdentifier])
     $groupSID = $strSID.Value
     
     #проверка директории для логов
     if($log){
       if(!(Test-Path C:\temp))
         {&mkdir C:\temp}
       }
     
     $FinalList = @()
     $FinalList += "SCMANAGER"

     foreach ($Service in $ServiceName){
       $Entity = Get-Service -Name $Service -ErrorAction SilentlyContinue
       if(!([string]::IsNullOrEmpty($Entity))){
         foreach($Item in $Entity){
           $FinalList += $Item.Name
         }
       }   
       
       else{
         Write-Verbose "$service doesn't exist on server $env:COMPUTERNAME" 
       } 
     }

     foreach ($Name in $FinalList){
       #генерируем новые права
       if ($Name -eq "SCMANAGER"){
         [string]$DeltaString = "(A`;`;DCSWWPSDWDWO`;`;`;$GroupSID)"
       }
       else{
         [string]$DeltaString = "(A`;`;CCDCLCSWRPWPDTLOCRSDRCWDWO`;`;`;$GroupSID)"
       }
       
       #получаем исходную строку прав на службу
       [string]$DefString = sc.exe sdshow "$Name"
       
       #пишем исходные права в файл
       if($log){
         "$Name,$DefString" |out-file "C:\temp\ServiceRightsBkp.txt" -Append
       }

       #очищаем строку от ранее выданных прав содержащих $groupSID
       #SAR
       $open = $DefString.indexof("S:")
       $close = $DefString.lastindexof("`)")
       $dif = ($close - $open) + 1
       [String]$SAR = $DefString.Substring($open,$dif)

       #DAR
       $left = $DefString.Remove($open)
       $left = $left.substring(4)
       $left = $left.replace("(","")

       $arrofAR = $left.split(")")
       $CleanAR =@()
       foreach ($AR in $arrofAR){
         if(!($AR -match $GroupSID )){
           $CleanAR += $AR
         }
       }
      
      [String]$DAR = "D:"
      foreach ($AR in $CleanAR){
        if(![string]::IsNullOrEmpty($AR)){
          $DAR +="($AR)"
        }
      }
      
      #формируем чистую строку
      [string]$VirginString = $DAR + $SAR
      
      #формируем итоговую строку
      [string]$finalString = $virginString.Insert(2,$deltaString)
      
      #изменяем права на службу
      Write-Verbose "Set AR to service: $Name"
      & sc.exe sdset "$Name" "$finalString"
    }
  }

function Set-RightToFolder {
<#
.SYNOPSIS
Changes the security descriptor of a specified  directory.
.DESCRIPTION
Changes the security descriptor of the specified item.
.PARAMETER Path
Enter the path to a directory.
.PARAMETER Right
This parameter takes one of file system rights:'R','RX','RW','WRX','MWRX','F'.The default is 'R'
-- R - read
-- X - execute
-- W - write
-- M - modify
-- F - full
.PARAMETER SamAccountName
Specifies the Security Account Manager (SAM) account name.
.EXAMPLE
Set-RightToFolder -Path "d:\transact" -SamAccountName $ADGroup -Right "MWRX" 
#>
   [CmdletBinding()]
   param(
   [parameter(Mandatory=$true, Position=0)]$Path,

   [parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
   [ValidateSet('Local','ALPHA','SIGMA','OMEGA')]
   [string]$Domain = [environment]::UserDomainName,
   
   [parameter(Mandatory=$true)]
   [Alias('Group','User')]
   $SamAccountName,
   
   [parameter()]
   [ValidateSet('R','RX','RW','WRX','MWRX','F')]
   $Right = 'R'
   )
   #written by Alan Miller
   

   if (test-path $Path){
     if ($Domain -ne "local"){
       &icacls $Path /grant $Domain\$SamAccountName`:`(OI`)`(CI`)$Right /T /C /Q
       }
     else{
       &icacls $Path /grant $SamAccountName`:`(OI`)`(CI`)$Right /T /C /Q
       }
     }
   else{
     Write-Error "Cannot find path $Path because it does not exist." 
     }
   }

function Set-ShareCatalog { 
<#
.SYNOPSIS
Share specified directory and grant EVERYONE:CHANGE permissions.
.DESCRIPTION
.PARAMETER Path
Enter the path to a directory.
.PARAMETER SMBName
Specifies SMB name for shared catalog.
.PARAMETER $Right
.PARAMETER $MaximumAllowed
.PARAMETER $Description
.EXAMPLE
Set-ShareCatalog -Path "D:\IBM\WebSphere\AppServer\profiles\dmgr\config" -SMBName "config" -Right Full
#>
    param (
      [parameter(Mandatory=$true,Position=1,ParameterSetName= "New")]
      [string]$Path,

      [parameter(Mandatory=$true,Position=2,ParameterSetName= "New")]
      [string]$SMBName,

      [parameter(Mandatory=$true,Position=3,ParameterSetName= "New")]
      [ValidateSet("Full","Change","Read")]
      [string]$Right,

      [parameter(Mandatory=$false,ParameterSetName= "New")]
      [string]$MaximumAllowed,
      [parameter(Mandatory=$false,ParameterSetName= "New")]
      [string]$Description,

      [parameter(ParameterSetName= "ReCreate")]
      [bool]$recreate
      )

     if ($recreate){
       $objWMI= Get-WmiObject -class Win32_Share | sort type, name | ?{$_.Name -notlike "*`$"}
       if ($objWMI){
         foreach ($obj in $objWMI){
           $obj.Delete()
           Start-Sleep -Seconds 8

           $SMBName = $obj.Name
           $Path = $obj.Path 
           Start-Process net -ArgumentList "share $SMBName=$Path  `/grant`:EVERYONE`,CHANGE"
           }
         }
       }
     else{
       #Path, Name, Access, Type, MaximumAllowed,Description,Password,Access
       $objWMI=[WMICLASS]"Win32_share"
       $sd = ([WMIClass] "Win32_SecurityDescriptor").CreateInstance()
       $ACE = ([WMIClass] "Win32_ACE").CreateInstance()
       $Trustee = ([WMIClass] "Win32_Trustee").CreateInstance()
       $Trustee.Name = "Everyone"
       $Trustee.Domain = $Null 
      
       #AccessMasks:
       if ($Right -eq "Full"){$ace.AccessMask = 2032127}
       if ($Right -eq "Change"){$ace.AccessMask = 1245631}
       if ($Right -eq "Read"){$ace.AccessMask = 1179817}
       $ace.AceFlags = 3 
       $ace.AceType = 0 # 0 = allow, 1 = deny
       $ACE.Trustee = $Trustee 
       $sd.DACL += $ACE.psObject.baseobject 
       if (Test-Path $Path){
         Write-Verbose "Создаем сетевой каталог `[SMBName`] по пути `[$Path`]"
         $objWMI.create($Path,$SMBName,0,$null,$Description,$MaximumAllowed,$sd )
         }
       else{
         Write-Verbose "Каталог `[$Path`]-не найден"
         }
       }   
}

function Set-StartServiceAt {
<#
.SYNOPSIS
Set specified service to start at specified account.
.DESCRIPTION
.PARAMETER UserName
Specifies the Security Account Manager (SAM) account name.
.PARAMETER Password
Specifies a password value for an account. Wildcards are permitted.
.PARAMETER Service
Specifies service name.
.PARAMETER RestartService
If RestartService, specified service will be restarted.
.EXAMPLE
Set-StartServiceAt -Service IBMWAS* -UserName "WASUSER" -Password "Qq123456"
#>
   [CmdletBinding()]
    param(
    [parameter(Mandatory=$true)]$UserName, 
    [parameter(Mandatory=$true)]$Password,
    [parameter(Mandatory=$true)]$Service,
    [switch]$RestartService
    )
    #written by Alan Miller
     
     Get-Service -Name $Service | % {$_.Name;  &sc.exe config $_.Name obj= $username password= $password}
     if ($RestartService){
       Get-Service -Name $Service | where {$_.Status -like "Running"} | Restart-Service -Confirm:$false
     }
   }

function Get-IBMFolders {
<#
.SYNOPSIS
Search IBM WebSphere profiles, logs and config path.
.DESCRIPTION
.PARAMETER $StartPath
Enter the path to a directory IBM. The default is D:\IBM.
.EXAMPLE
Get-IBMFolders
#>
     [CmdletBinding()]
     param(
     [parameter()]
     $StartPath = "D:\IBM"
     )

     $ReturnList=@()
     $ReturnListII=@()
     $CH = Get-ChildItem -Path $StartPath -Recurse | where {$_.Attributes -match "Directory"} | select -ExpandProperty FullName
     foreach ($path in $ch){
       if ($path -match ".*\\profiles\\[A-Za-z0-9`_`-]+\\logs$"`
       -or $path -match ".*\\profiles\\[A-Za-z0-9`_`-]+\\config$"`
       -or $path -match ".*\\profiles\\[A-Za-z0-9`_`-]+$"){
         $ReturnList +=$path
       }
     }

     foreach ($str in $ReturnList){ 
       if ($str -like "*logs*") {$obj= New-Object PSObject -Property @{Folder="logs";Path=$str};$ReturnListII +=$obj} 
       elseif ($str -like "*config*") {$obj= New-Object PSObject -Property @{Folder="config";Path=$str};$ReturnListII +=$obj} 
       else {$obj= New-Object PSObject -Property @{Folder="WASprofile";Path=$str};$ReturnListII +=$obj} 
     }
     if (test-path "D:\Disk_D\bird.config"){$obj= New-Object PSObject -Property @{Folder="bird.config";Path="D:\Disk_D\bird.config"};$ReturnListII +=$obj}
     if (test-path "D:\bird.config"){$obj= New-Object PSObject -Property @{Folder="bird.config";Path="D:\bird.config"};$ReturnListII +=$obj}
     return $ReturnListII 
}

function Get-LocalGroup {
<#
#>
     [CmdletBinding()]
     param(
     [Alias('ServerName')]
     [parameter(Mandatory=$false,Position = 0)]
     $ComputerName = [Environment]::MachineName
     )
     #written by Alan Miller
     
     $grouplist = gwmi win32_group -ComputerName $ComputerName -filter "Domain = '$ComputerName'"
     return $grouplist
}

function Set-Separation {
 <#
.SYNOPSIS
Function sets almost everything about stand seporation.
.DESCRIPTION
For full description visit gitlab page.
.EXAMPLE
#>
    [CmdletBinding()]
    param(
    [parameter(Mandatory=$true,Position = 0,ParameterSetName = "NotWAS")]$AdminGroup,
    [parameter(ParameterSetName= "WAS")][switch]$CreateWASuser,
    [parameter(ParameterSetName= "WAS")][switch]$CreateIBMGroups,
    [parameter(ParameterSetName= "WAS")][switch]$SetNTFSPermission,
    [parameter(ParameterSetName= "WAS")][switch]$RDUtoIBM_Admins,
    [parameter(ParameterSetName= "WAS")][switch]$SetServicePermission,
    [parameter(ParameterSetName= "WAS")][switch]$RestartService,
    [parameter(ParameterSetName= "WAS")][switch]$StartServiceAt,
    [parameter(ParameterSetName= "WAS")][switch]$CreateShare,
    [parameter(ParameterSetName= "WAS")][switch]$RemoveFromAdminGroup,
    [parameter(ParameterSetName= "WAS")][switch]$bird,
    [parameter(ParameterSetName= "NotWAS")][switch]$OS,
    [parameter(ParameterSetName= "NotWAS")][switch]$IIS,
    [parameter(ParameterSetName= "WAS")]$Wuser = "WASUSER",
    [parameter(ParameterSetName= "WAS")]$Wpassword = "Qq123456",
    [parameter(ParameterSetName= "WAS")]$Service = "IBMWAS*"
    )
    
    if($CreateIBMGroups){
    #2 #######Создаем 3 локальных группы IBM 

    $logsRead = &net localgroup IBM_Logs_Read /add /COMMENT:"Доступ на чтение IMB логов" 2>&1
    if ($logsRead -eq "The command completed successfully."){Write-Verbose "IBM_Logs_Read created successfully"}
    else {Write-Verbose $logsRead[-1]}

    $configRead = &net localgroup IBM_Config_Read /add /COMMENT:"Доступ на чтение IMB файлов конфигураций" 2>&1
    if ($configRead -eq "The command completed successfully."){Write-Verbose "IBM_Config_Read created successfully"}
    else {Write-Verbose $configRead[-1]}

    $Admins = &net localgroup IBM_Admins /add /COMMENT:“Администраторы приложений IBM” 2>&1
    if ($Admins -eq "The command completed successfully."){Write-Verbose "IBM_Admins created successfully"}
    else {Write-Verbose $Admins[-1]}
    }
    
    if($CreateWASUser){
    #1 #######Создаем локального пользователя с транспортным паролем 
    New-LocalUser -UserName $Wuser -Password $Wpassword -Desc "Пользователь для запуска служб WAS"
    
    #6 #######Разрешаем пользователю WASUSER выполнять вход в систему, как сервис 
    Add-AccountToLogonAsService -accountToAdd $Wuser

    #8 #######Добавляем пользователя WASUSER в локальные группы
    Add-LocalGroupMember -User $Wuser -GroupName "Remote Desktop Users" -Domain Local
    Add-LocalGroupMember -User $Wuser -GroupName "IBM_Admins" -Domain Local
    Add-LocalGroupMember -User $Wuser -GroupName "Performance Log Users" -Domain Local
    Add-LocalGroupMember -User $Wuser -GroupName "Event Log Readers" -Domain Local
    }

    if($bird){
    $BirdPath = "D:\Disk_D\bird.config"
    mkdir $BirdPath -force
    }

    if($SetNTFSPermission){
    #3 #######Делегируем права на каталоги IBM 
    $catalogs = Get-IBMFolders
    $catalogs = $catalogs | Sort-Object -Property folder -Descending

    foreach ($i in $catalogs){ 
      switch($i.folder){
        "WASprofile"{
          & icacls $i.path /reset /T /C /Q
          & icacls $i.path /grant IBM_Admins`:`(OI`)`(CI`)MWRX
          if ($CreateWASUser -or ([ADSI]"WinNT://$env:COMPUTERNAME/$Wuser").path -eq "WinNT://$env:COMPUTERNAME/$Wuser"){
            &icacls $i.path /setowner $Wuser /T /C /Q
            &icacls $i.path /grant $Wuser`:`(OI`)`(CI`)F
            }
          }
        "logs"{
          & icacls $i.path /grant IBM_Admins`:`(OI`)`(CI`)MWRX
          & icacls $i.path /grant IBM_Logs_Read`:`(OI`)`(CI`)RX
          }
        "config"{
          & icacls $i.path /grant IBM_Admins`:`(OI`)`(CI`)MWRX
          & icacls $i.path /grant IBM_Config_Read`:`(OI`)`(CI`)RX   
          }
        "bird.config" {
          & icacls $i.path /grant IBM_Admins`:`(OI`)`(CI`)MWRX
          & icacls $i.path /grant IBM_Config_Read`:`(OI`)`(CI`)RX 
          } 
        }
      }
    }

    if($RDUtoIBM_Admins){
    #4 #######Наполняем группу IBM_Admins администраторами КЭ ИР 
    Get-LocalGroupMember "Remote Desktop Users" | Add-LocalGroupMember -GroupName "IBM_Admins"    
    } 

    if($SetServicePermission){
    #5 #######Делегируем права FULL на управление сервисами IBMWAS* для группы IBM_Admins 
    Set-RightToService $Service -Group IBM_Admins
    }

    if($StartServiceAt){
    #7 #######Запускаем службы IBMWAS* от имени WASUSER, запущенные службы – перезапускаем 
    Set-StartServiceAt -service $Service -username ".`\$Wuser" -password $Wpassword
    }

    if($CreateShare){
    #9 #######Создаем сетевые каталоги LOGS, CONFIG, bird.config. Права SMB - EVERYONE, CHANGE. Доступы разграничиваются на уровне NTFS 
    [int]$nl=0
    [int]$nc=0
    if ($catalogs -eq $null){
      $catalogs = Get-IBMFolders
      $catalogs = $catalogs | Sort-Object -Property folder -Descending
      }
    foreach ($i in $catalogs){
      switch($i.folder){
        "logs"{
          if ($nl -eq "0"){Set-ShareCatalog -SMBName "logs" -Path $i.path -Right Full ;$nl++}
          else {Set-ShareCatalog -SMBName "logs$nl" -Path $i.path -Right Full ;$nl++}
          }
        "config"{
          if ($nc -eq "0"){Set-ShareCatalog -SMBName "config" -Path $i.path -Right Full;$nc++}
          else {Set-ShareCatalog -SMBName "config$nc" -Path $i.path -Right Full ;$nc++}
          }
        "bird.config"{
          Set-ShareCatalog -SMBName "bird.config" -Path $i.path -Right Full
          }
        }
      }
    }

    if($RestartService){
    Get-Service -Name $Service | where {$_.Status -like "Running"} | Restart-Service -Confirm:$false
    }

    if($RemoveFromAdminGroup){
    Get-LocalGroupMember -GroupName "Administrators" |`
     ?{($_.ObjName -ne "AdminUras" -and`
        $_.ObjName -ne "AdminOSA" -and`
        $_.ObjName -ne "SBT-OSA-Admins" -and`
        $_.ObjName -ne "STR-GR-Windows-Admins" -and`
        $_.ObjName -ne "MaxPatrol-Scan" -and`
        $_.ObjName -ne "Domain Admins")} |
    Remove-LocalGroupMember -Verbose
    }

    if($OS){
    Add-LocalGroupMember -Group $AdminGroup -GroupName "Performance Monitor Users" -Domain ALPHA
    Add-LocalGroupMember -Group $AdminGroup -GroupName "Event Log Readers" -Domain ALPHA
    Add-LocalGroupMember -Group $AdminGroup -GroupName "Performance Log Users" -Domain ALPHA
    Add-LocalGroupMember -Group $AdminGroup -GroupName "Remote Desktop Users" -Domain ALPHA
    #Add-LocalGroupMember -Group $AdminGroup -GroupName "IBM_Admins" -Domain ALPHA
      if($WASUSER -or ([ADSI]"WinNT://$env:COMPUTERNAME/$Wuser").path -eq "WinNT://$env:COMPUTERNAME/$Wuser"){
        Add-LocalGroupMember -User $Wuser -GroupName "Performance Log Users" -Domain Local
        Add-LocalGroupMember -User $Wuser -GroupName "Event Log Readers" -Domain Local
        Add-LocalGroupMember -User $Wuser -GroupName "Performance Monitor Users" -Domain Local 
      }
   

    Set-RightToRegistry -key "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg" -SamAccountName "Performance Monitor Users"
    Set-RightToRegistry -key "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg" -SamAccountName "Performance Log Users"
    }

    if($IIS){
    $user = [environment]::UserName
    $domain = [environment]::UserDomainName

    &icacls "C:\Windows\System32\inetsrv\" /setowner $domain\$user /T /C /Q
    &icacls "C:\Windows\System32\inetsrv\" /grant $domain\$AdminGroup`:`(OI`)`(CI`)MWRX /T /C /Q
    }
  }

### end ###

function Get-Signature {
 <#
.SYNOPSIS
Function for lazy admins, generate string like "Копытов Д.С. (30.03.16):"
.DESCRIPTION
.EXAMPLE
Get-Signature
#>
    [CmdletBinding()]
    param(
    [switch]$clip
    )

    
    $Date = Get-Date -UFormat "%d.%m.%y"
    $FullName = ([adsi]"WinNT://$($env:userdomain)/$($env:username),user").fullname
    $split = $FullName -split " "
    $Name  = $split[0] + " " + $split[1].Chars(0) + "." + $split[2].Chars(0) + "."
    $NamePlusDate = "$Name ($date):"
    $NamePlusDate

    if($clip){
      [windows.clipboard]::SetText($NamePlusDate)
    }
}

function Enable-SecondHop {
<#
.SYNOPSIS
Delegates the user's credentials from the local computer to a remote computer. This type of authentication is designed for commands that create a remote session from within another remote session.
.DESCRIPTION
.PARAMETER ComputerName
Allows the client credentials to be delegated to the server or servers that are specified by this parameter. The value of this parameter should be a fully qualified domain name.
.PARAMETER ImportMiniModule
If ImportMiniModule, import module to remote server from 
ALPHA "\\10.68.194.200\Share$\PowerShell\miniModule\miniModule.psm1"
SIGMA "\\10.21.25.200\Share$\MiniModule\miniModule.psm1"
.EXAMPLE
Enable-SecondHop -DelegateComputer sbt-osa-212.ca.sbrf.ru -ImportMiniModule
#>

    [CmdletBinding()]
    param(
    [parameter(Mandatory=$true,Position=0)]
    [string[]]$ComputerName,
    
    [switch]$ImportMiniModule
    )

    
    Enable-WSManCredSSP -Role Client -DelegateComputer $ComputerName -Force |Out-Null
    foreach ($computer in $ComputerName){ 
      Connect-WSMan -ComputerName $computer
      Set-Item "WSMAN:\$computer\service\auth\credssp" -Value $true 
      }
    
    if($ImportMiniModule){
      switch ([environment]::UserDomainName){
        "ALPHA"{
          $code = {
            $CurrentPolicy = Get-ExecutionPolicy
            Set-ExecutionPolicy Bypass
            Import-Module "\\10.68.194.200\Share$\PowerShell\miniModule\miniModule.psm1" -Force -DisableNameChecking
            }
          }
        "SIGMA"{
          $modulePath = 
          $code = {
            $CurrentPolicy = Get-ExecutionPolicy
            Set-ExecutionPolicy Bypass
            Import-Module "\\10.21.25.200\Share$\PowerShell\miniModule\miniModule.psm1" -Force -DisableNameChecking
            }
          }
        }
      
      $crd = Get-Credential -UserName $([environment]::username) -Message "PSSWRD?"
      $script:sessions = @()
      foreach ($computer in $ComputerName){ 
      $session = New-PSSession -Name $computer -ComputerName $computer -Authentication Credss -Credential $crd 
      $script:sessions += $session
        }
      Invoke-Command -Session $sessions -ScriptBlock $code
      }
$script:sessions
}

function Disable-SecondHop {
<#
.SYNOPSIS
Disables CredSSP authentication on a client and on a server computer.
.DESCRIPTION
.PARAMETER DelegateComputer
Specify the server or servers. The value of this parameter should be a fully qualified domain name.
.EXAMPLE
Disable-SecondHop -DelegateComputer sbt-osa-212.ca.sbrf.ru
#>

    [CmdletBinding()]
    param(
    [parameter(Position=0)][string[]]
    $ComputerName = $sessions.ComputerName
    )

    foreach ($computer in $ComputerName){ 
      Connect-WSMan -ComputerName $computer
      Set-Item "WSMAN:\$computer\service\auth\credssp" -Value $false
      }
      Disable-WSManCredSSP -Role Client

    if($sessions -ne $null){
      Remove-PSSession $sessions
      Remove-Variable sessions -Scope Script
      }
}

function Approve-Update {
<#
.SYNOPSIS
Approve security updates specified by MSRCNembers.
.DESCRIPTION
Should be execute directly on WSUS server. Approve-Update get only security updates uses module UpdateServices.
.PARAMETER MSRCNumber
Specifies MSRC number, range or both in a comma-separated string.
WARNING! 
-- Input must be in single quatation marks.
-- Parameter accept only MSRC number without year and other leters.
.PARAMETER Year
Specifies year of MSRC. The default is the current year. 
.EXAMPLE
Approve-Update -MSRCNumber '8,11..13'
This command approve update MS16-008, S16-011, MS16-012, MS16-012.
.EXAMPLE
$wsus = New-PSSession -ComputerName STR-VOT-WSUS001.omega.sbrf.ru -Name "WSUS"
Enter-PSSession $wsus
[string]$MSRC= '1,2,3,4..7,8,9'
Approve-Update -MSRCNumber $MSRC
Create PSsession to WSUS server. Approve update MS16-...
#>
      [CmdletBinding()]
      param(
      [parameter(Mandatory=$true)]
      [string]$MSRCNumber,
      
      [parameter()]
      [ValidatePattern("\d{2}")]
      [int]$Year = (Get-Date -UFormat %y)
      )

      [array]$strArr = $MSRCNumber -split ","
      $numArr = @()
      foreach($str in $strArr){
        if ($str -notmatch "\.\."){
          $numArr += $str -as [int]
          }
        else{
          $two = $str -split "\.\."
          $first = $two[0] -as [int]
          $last = $two[1] -as [int]
          while($first -le $last){
            $numArr += $first -as [int]
            $first++
            }
          }
        }
      
      $MSRC = $numArr | Sort-Object
      [string]$query = $null  
      [string]$out = $null
      foreach($i in $MSRC){
        $i = “{0:D3}” -f $i 
        [string]$out += "MS$Year-$i; "
        }
      
      Write-Verbose $out

      foreach ($i in $MSRC){
        $i = “{0:D3}” -f $i
        if($i -lt “{0:D3}” -f $MSRC[-1]){
          $where = "`$_.MsrcNumbers -eq `"MS$Year-$i`" -or "
          [string]$query += $where
          }
        else{
          $where = "`$_.MsrcNumbers -eq `"MS$Year-$i`""
          [string]$query += $where
          }   
        }

      Write-Verbose "долгая операция: запрос списка всех обновлений безопасности"
      $UnapprovedSecurityUpdates = Get-WsusUpdate -Approval Unapproved -Classification Security 
      $toApprove = $UnapprovedSecurityUpdates |?{iex $query}

      $toApprove | Approve-WsusUpdate -TargetGroupName "Unassigned Computers"-Action Install -Verbose
      $toApprove | Approve-WsusUpdate -TargetGroupName "SBT_AUTO"-Action Install -Verbose
      $toApprove | Approve-WsusUpdate -TargetGroupName "SBT_MANUAL"-Action Install -Verbose
      $toApprove | Approve-WsusUpdate -TargetGroupName "SBT_DENYUPDATES" -Action NotApproved -Verbose
}

function Encoding-It {
    [CmdletBinding()]
    Param(
    [string]$From = 'cp866',
    [string]$To = 'windows-1251'
    )

    Begin{
    $encFrom = [System.Text.Encoding]::GetEncoding($from)
    $encTo = [System.Text.Encoding]::GetEncoding($to)
    }
    Process{
    $bytes = $encTo.GetBytes($_)
    $bytes = [System.Text.Encoding]::Convert($encFrom, $encTo, $bytes)
    $encTo.GetString($bytes)
    }
}

### WOSA ###

function Clear-ComputerName {
<#
.SYNOPSIS
.DESCRIPTION
.PARAMETER ServerList
.PARAMETER VMM
.PARAMETER Clip
.EXAMPLE
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$True,Position=0)]
    [Alias('ComputerName')]
    [string]$ServerList,
     
    [switch]$VMM,  
    [switch]$Clip
    )

  begin {}

  process {
    $serverArr = $ServerList.split("[,;`n`" `"`/]`t")
    $serverArr = $serverArr -replace "`"", "" `
                            -replace "`<", "" `
                            -replace "`>", "" `
                            -replace "\[", "" `
                            -replace "\]", ""
  
    $cleanArr = @()
    foreach ($i in $serverArr){
      $i = $i.Trim()
      if ($i -match '^[A-Za-z]+\-.+\d{1,4}$'){
        $cleanArr += $i
      }  
    }
        
    if($VMM){
      [string]$OutputString = $cleanArr -join "," 
      
      if($Clip){
      #[windows.clipboard]::SetText($OutputString)
      $OutputString | clip
      }
    
    $OutputString
    }

    else {     
      if($Clip){
      $cleanArr | clip
      }
    
    $cleanArr
    }
  }

  end {
    Remove-Variable  ServerList, serverArr, cleanArr -ErrorAction SilentlyContinue
    
    if($VMM){
      Remove-Variable OutputString
    }  
  }
}

function Set-UserRightAssigment {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$True,Position=0)]
    [Alias('Account','UaserName','Name')]
    [string]$SamAccountName,
    
    [Parameter(Mandatory=$True,Position=1)]
    [ValidateSet('Log on as a batch job',
                 'Log on as a service',
                 'Force shutdown from a remote system',
                 'Create global objects',
                 'Shut down the system')]
    $Assigment   
    )
  
  #based on script written by Ingo Karstein
  begin {
    try {
      $ntprincipal = new-object System.Security.Principal.NTAccount "$SamAccountName"
      $sid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
      $sidstr = $sid.Value.ToString()    
    }
    catch {
      $sidstr = $null
    }
    
    switch($Assigment){
      'Log on as a batch job'               {$Privilege = [pscustomobject]@{"Description" = 'Log on as a batch job';"Config" = 'SeBatchLogonRight'}}
      'Log on as aservice'                  {$Privilege = [pscustomobject]@{"Description" = 'Log on as aservice';"Config" = 'SeServiceLogonRight'}}
      'Force shutdown from a remote system' {$Privilege = [pscustomobject]@{"Description" = 'Force shutdown from a remote system';"Config" = 'SeRemoteShutdownPrivilege'}}
      'Shut down the system'                {$Privilege = [pscustomobject]@{"Description" = 'Shut down the system';"Config" = 'SeShutdownPrivilege'}}
      'Create global objects'               {$Privilege = [pscustomobject]@{"Description" = 'Create global objects';"Config" = 'SeCreateGlobalPrivilege'}}
    }
  }
  
  process {
    Write-Verbose "Account: $($SamAccountName)"
    
    if([string]::IsNullOrEmpty($sidstr)){
      Write-Output "Account not found!"
      exit -1
    }

     Write-Verbose "Account SID: $($sidstr)"

     $tmp = [System.IO.Path]::GetTempFileName()
     Write-Verbose "Export current Local Security Policy"
     secedit.exe /export /cfg "$($tmp)"
     $c = Get-Content -Path $tmp
     $currentSetting = ""

     Write-Verbose "$($Privilege.Config)*"
     foreach ($s in $c){
       if ($s -like "$($Privilege.Config)*"){
         $x = $s.split("=", [System.StringSplitOptions]::RemoveEmptyEntries)
         $currentSetting = $x[1].Trim()
       }
     }
     if ($currentSetting -notlike "*$($sidstr)*"){
       Write-Verbose "Modify setting $($Privilege.Description)"
       
       if ([string]::IsNullOrEmpty($currentSetting)){
         $currentSetting = "*$($sidstr)"
       }
       else{
         $currentSetting = "*$($sidstr),$($currentSetting)"
       }
             
       Write-Verbose "$currentSetting"
             
       $outfile = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$($Privilege.Config) = $($currentSetting)
"@     
       
       $tmp2 = [System.IO.Path]::GetTempFileName()
             
       Write-Verbose "Import new settings to Local Security Policy"
       $outfile | Set-Content -Path $tmp2 -Encoding Unicode -Force
       Push-Location (Split-Path $tmp2)
             
       try{
         secedit.exe /configure /db "secedit.sdb" /cfg "$($tmp2)" /areas USER_RIGHTS
       }
       finally{
         Pop-Location
       }
     }
     else {
       Write-Output "NO ACTIONS REQUIRED! Account already in $($Privilege.Description)"
       }
       
      Write-Output "Done."

  }

  end {
    Remove-Variable Privilege, sidstr -Force -ErrorAction SilentlyContinue
  }

}

function Set-RemoteRebootSettings {
  [CmdletBinding()]
  param(
    [parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
    [string[]]$ComputerName  
    )
  
  begin {
    $code = {
          function Set-UserRightAssigment {
            [CmdletBinding()]
             param(
            [Parameter(Mandatory=$True,Position=0)]
            [Alias('Account','UaserName','Name')]
            [string]$SamAccountName,
    
            [Parameter(Mandatory=$True,Position=1)]
            [ValidateSet('Log on as a batch job',
                        'Log on as aservice',
                        'Force shutdown from a remote system',
                        'Create global objects',
                        'Shut down the system')]
            $Assigment   
            )
  
        #based on script written by Ingo Karstein
        begin {
         try {
           $ntprincipal = new-object System.Security.Principal.NTAccount "$SamAccountName"
            $sid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
            $sidstr = $sid.Value.ToString()    
           }
           catch {
             $sidstr = $null
           }
    
          switch($Assigment){
            'Log on as a batch job'               {$Privilege = [pscustomobject]@{"Description" = 'Log on as a batch job';"Config" = 'SeBatchLogonRight'}}
            'Log on as aservice'                  {$Privilege = [pscustomobject]@{"Description" = 'Log on as aservice';"Config" = 'SeServiceLogonRight'}}
            'Force shutdown from a remote system' {$Privilege = [pscustomobject]@{"Description" = 'Force shutdown from a remote system';"Config" = 'SeRemoteShutdownPrivilege'}}
            'Shut down the system'                {$Privilege = [pscustomobject]@{"Description" = 'Shut down the system';"Config" = 'SeShutdownPrivilege'}}
            'Create global objects'               {$Privilege = [pscustomobject]@{"Description" = 'Create global objects';"Config" = 'SeCreateGlobalPrivilege'}}
         }
       }
  
        process {
          Write-Verbose "Account: $($SamAccountName)"
    
          if([string]::IsNullOrEmpty($sidstr)){
            Write-Output "Account not found!"
            exit -1
          }

          Write-Verbose "Account SID: $($sidstr)"

          $tmp = [System.IO.Path]::GetTempFileName()
          Write-Verbose "Export current Local Security Policy"
          secedit.exe /export /cfg "$($tmp)"
          $c = Get-Content -Path $tmp
          $currentSetting = ""

          Write-Verbose "$($Privilege.Config)*"
          foreach ($s in $c){
            if ($s -like "$($Privilege.Config)*"){
            $x = $s.split("=", [System.StringSplitOptions]::RemoveEmptyEntries)
            $currentSetting = $x[1].Trim()
          }
        }
       
         if ($currentSetting -notlike "*$($sidstr)*"){
           Write-Verbose "Modify setting $($Privilege.Description)"
       
           if ([string]::IsNullOrEmpty($currentSetting)){
             $currentSetting = "*$($sidstr)"
           }
           else{
             $currentSetting = "*$($sidstr),$($currentSetting)"
           }
             
           Write-Verbose "$currentSetting"
             
           $outfile = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$($Privilege.Config) = $($currentSetting)
"@     
       
            $tmp2 = [System.IO.Path]::GetTempFileName()
             
            Write-Verbose "Import new settings to Local Security Policy"
            $outfile | Set-Content -Path $tmp2 -Encoding Unicode -Force
            Push-Location (Split-Path $tmp2)
             
            try{
                secedit.exe /configure /db "secedit.sdb" /cfg "$($tmp2)" /areas USER_RIGHTS
            }
            finally{
              Pop-Location
            }
          }
          
          else {
            Write-Output "NO ACTIONS REQUIRED! Account already in $($Privilege.Description)"
          }
       
          Write-Output "Done."

       }

        end {
          Remove-Variable Privilege, sidstr -Force -ErrorAction SilentlyContinue
        }
      }
          Set-UserRightAssigment -Assigment "Force shutdown from a remote system" -SamAccountName "AllowRemoteReboot"
        }
  }
  process {
    foreach ($cmp in $ComputerName){
      $check = [ADSI]"WinNT://$cmp/AllowRemoteReboot"
      if("$($check.Name)" -eq "AllowRemoteReboot") {
        Write-Output "Группа AllowRemoteReboot уже есть на сервере [$cmp]"
        break
      }
      else{
        $cn = [ADSI]"WinNT://$cmp"
        $group = $cn.Create("Group","AllowRemoteReboot")
        $group.setinfo()
        $group.description="Members of this group can remotely reboot operating system"
        $group.setinfo()
        
        $SID = (gwmi win32_group -ComputerName $cmp -filter "Domain = '$cmp' and Name = 'AllowRemoteReboot'").SID

        #Изменение прав на root/cimv2
        $SDDL = "A;;CCDCWP;;;$sid"
        $DCOMSDDL = "A;;CCDCRP;;;$sid"
  
        $Reg = [WMIClass]"\\$cmp\root\default:StdRegProv"
        $DCOM = $Reg.GetBinaryValue(2147483650, "software\microsoft\ole", "MachineLaunchRestriction").uValue
        $security = Get-WmiObject -ComputerName $cmp -Namespace root/cimv2 -Class __SystemSecurity
        $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
        $binarySD = @($null)
        $result = $security.PsBase.InvokeMethod("GetSD", $binarySD)
        $outsddl = $converter.BinarySDToSDDL($binarySD[0])
        $outDCOMSDDL = $converter.BinarySDToSDDL($DCOM)
        $newSDDL = $outsddl.SDDL += "(" + $SDDL + ")"
        $newDCOMSDDL = $outDCOMSDDL.SDDL += "(" + $DCOMSDDL + ")"
        $WMIbinarySD = $converter.SDDLToBinarySD($newSDDL)
        $WMIconvertedPermissions =, $WMIbinarySD.BinarySD
        $DCOMbinarySD = $converter.SDDLToBinarySD($newDCOMSDDL)
        $DCOMconvertedPermissions =, $DCOMbinarySD.BinarySD
        $result = $security.PsBase.InvokeMethod("SetSD", $WMIconvertedPermissions)
        $result = $Reg.SetBinaryValue(2147483650, "software\microsoft\ole", "MachineLaunchRestriction", $DCOMbinarySD.binarySD)

        Invoke-Command -ComputerName $cmp -ScriptBlock $code -Verbose
      }
    }
  }
  end {
    Remove-Variable code
  }
}


Export-ModuleMember New-LocalUser 
Export-ModuleMember Remove-LocalUser
Export-ModuleMember Get-LocalGroupMember
Export-ModuleMember Add-LocalGroupMember
Export-ModuleMember Remove-LocalGroupMember
Export-ModuleMember Approve-Update
Export-ModuleMember Add-AccountToLogonAsService
Export-ModuleMember Set-RightToRegistry
Export-ModuleMember Set-RightToService
Export-ModuleMember Set-RightToFolder
Export-ModuleMember Set-ShareCatalog
Export-ModuleMember Set-StartServiceAt
Export-ModuleMember Get-Signature
Export-ModuleMember Get-IBMFolders
Export-ModuleMember Set-Separation
Export-ModuleMember Enable-SecondHop
Export-ModuleMember Disable-SecondHop 
Export-ModuleMember Clear-ComputerName
Export-ModuleMember Encoding-It
Export-ModuleMember Get-LocalGroup
Export-ModuleMember Set-UserRightAssigment