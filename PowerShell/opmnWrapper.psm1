function Set-opmnPath {
<#
.SYNOPSIS
Set opmn path to system variable "Path"
#>

  [CmdletBinding()]
  param (
    [switch]$Permanent
  )

  begin {
    $already = $env:Path -like "*OracleAS_1`\opmn`\bin*"

    [array]$disk = Get-WmiObject -Class win32_logicalDisk | ?{$_.DriveType -eq '3'} | Select-Object -ExpandProperty DeviceID 
    $lastOne = $disk[-1]
    $opmn = "\product\10.1.3\OracleAS_1\opmn\bin"
    $exists = Test-Path ($lastOne + $opmn)
  }

  process {
    if ($already){
      Write-Output "путь до директории ..\OracleAS_1\opmn\bin есть в системной переменной path. настройка не требуется"
    }

    elseif (!($exists)){
      Write-Output "путь $lastOne + $opmn не найден"
    }

    else {
      $currentPath =  $env:Path
      $newPath = $env:Path + ";" + "$($lastOne + $opmn)" 
      
      if ($Permanent){
        [Environment]::SetEnvironmentVariable("Path", "$newPath", "Machine")
        Write-Output "путь $lastOne + $opmn добавлен в системную переменную path"
      }
      
      else {
        $env:Path = "$env:Path;$($lastOne + $opmn)"
        Write-Output "путь $lastOne + $opmn добавлен в переменные текущей сессии"
      }   
    }
  }

  end {
    Remove-Variable -Name already, exists, currentPath, lasOne, opmn, newPath -Force -Confirm:$false -ErrorAction SilentlyContinue
  }
}


function Get-opmnStatus {
<#
.SYNOPSIS
Get opmnctl status as a PowerSell object
#>

  [CmdletBinding()]
  param (
    [switch]$Simple
  )

  begin {
    $opmnctl = &opmnctl status
    $status = $opmnctl[5..(($opmnctl.count) -2)]
  }

  process {
    if ($Simple){
      foreach ($line in $status){
        $prop = $null
        [array]$prop = $line -split '\|'
      
        if ($prop[0] -like "*:*"){
          $component = ($prop[0].trim() -split ":")[1]
        }
        else{
          $component = $prop[0].trim()
        }
      
        if ($prop[1] -like "*:*"){
          $process = ($prop[1].trim() -split ":")[1]
        }
        else{
          $process = $prop[1].trim()
        }

        $hash = @{
          "ias-component"  = $component
          "process-type"   = $process
          "pid"            = ($prop[2].trim())
          "status"         = ($prop[3].trim())
        }
  
        $iasComponent = New-Object PSObject -Property $hash
        $iasComponent
      }
    }
    
    else {
      foreach ($line in $status){
        $prop = $null
        [array]$prop = $line -split '\|'
          $hash = @{
          "ias-component"  = ($prop[0].trim())
          "process-type"   = ($prop[1].trim())
          "pid"            = ($prop[2].trim())
          "status"         = ($prop[3].trim())
        }
  
        $iasComponent = New-Object PSObject -Property $hash
        $iasComponent
      }
    }
  }

  end {
    Remove-Variable -Name opmnctl, status, prop, hash, iasComponent, process, component -Force -Confirm:$false -ErrorAction SilentlyContinue
  }
}


function Set-cpSettings {
<#
.SYNOPSIS
Generate conntction settings to data-sources.xml
#>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$True)][string]$dataBase,
    [Parameter(Mandatory=$True)][string]$connectionPoolName,
    [Parameter(Mandatory=$True)][string]$jndiName, 
    [Parameter(Mandatory=$True)][string]$managedDataSourceName
  )

  begin {
    if (!(Test-Path "$env:ORACLE_HOME\j2ee\$oc4j\config\data-sources.xml")){
      Write-Output "Configuration file not found"
      break
    }

    else {
      Write-Verbose "$env:ORACLE_HOME\j2ee\$oc4j\config\data-sources.xml"
    }
    
    $raw = $dataBase -split ';' 
    
    $hash = @{
      "username" = ($raw[0]).trim()
      "password" = ($raw[1]).trim()
      "host"     = ($raw[2]).trim()
      "port"     = ($raw[3]).trim()
      "instance" = ($raw[4]).trim()
    }

    $db = New-Object PSObject -Property $hash
    Write-Verbose $db
  }

  process {
    $mds = $dataSource.CreateElement('managed-data-source')
    $mds.SetAttribute('connection-pool-name',"$connectionPoolName")
    $mds.SetAttribute('jndi-name',"$jndiName")
    $mds.SetAttribute('name',"$managedDataSourceName")
    ($dataSource."data-sources").AppendChild($mds) | Out-Null

    $cp = $dataSource.CreateElement('connection-pool')
    $cp.SetAttribute('name',"$connectionPoolName")
    ($dataSource."data-sources").AppendChild($cp) | Out-Null

    $cf = $dataSource.CreateElement('connection-factory')
    $cf.SetAttribute('factory-class','oracle.jdbc.xa.client.OracleXADataSource')
    $cf.SetAttribute('user',"$($DB.username)")
    $cf.SetAttribute('password',"$($DB.password)")
    $cf.SetAttribute('url',"jdbc:oracle:thin:@//$($db.host)`:$($db.port)/$($db.instance)")
    $cf.SetAttribute('commit-record-table-name',"")
    ($dataSource."data-sources"."connection-pool" | ?{$_.name -eq "$connectionPoolName"}).AppendChild($cf) | Out-Null
  
  }

  end {
    Remove-Variable -Name raw, hash, db, mds, cp, cf -Force -Confirm:$false -ErrorAction SilentlyContinue
  }
  
}


function Set-j2eeCommonSettings {
<#
.SYNOPSIS
Block of common settings for all j2ee containers
#>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$True)]$source,
    [Parameter(Mandatory=$True)]$oc4j,
    [Parameter()]$lib = "EPSJ"
  )

  $err = $false

  # копируем библиотеки applib и sharedlib с диска
  Write-miniLog -oc4j $oc4j -message "[копирование библиотек applib и sharedlib с диска]"

  if ((Test-Path "$source\ADD_Files\$lib") -and (Test-Path "$env:ORACLE_HOME\j2ee\$oc4j")){
    # shared-lib
    if(!(Test-Path "$env:ORACLE_HOME\j2ee\$oc4j\shared-lib") -or (Compare-Object (Get-ChildItem "$source\ADD_Files\$lib\shared-lib" | select -ExpandProperty Name) (Get-ChildItem "$env:ORACLE_HOME\j2ee\$oc4j\shared-lib" | select -ExpandProperty Name))){
      try {
        Copy-Item -Path "$source\ADD_Files\$lib\shared-lib" -Destination "$env:ORACLE_HOME\j2ee\$oc4j\" -Recurse -Force | Out-Null
        Write-miniLog -oc4j $oc4j -message "shared-lib. файлы успешно скопированы"
      }
      catch [system.exception] {
        Write-miniLog -oc4j $oc4j -message "$($error[0])" -type ERROR
        $err = $true
        break
      }
    }

    else {
      Write-miniLog -oc4j $oc4j -message "shared-lib. библиотеки актуальны, копирование данных не требуется"
    }
    
    #applib
    if((Compare-Object (Get-ChildItem "$source\ADD_Files\$lib\applib" | select -ExpandProperty Name) (Get-ChildItem "$env:ORACLE_HOME\j2ee\$oc4j\applib" | select -ExpandProperty Name))){
      try {
        Copy-Item -Path "$source\ADD_Files\$lib\applib" -Destination "$env:ORACLE_HOME\j2ee\$oc4j\" -Recurse -Force | Out-Null
        Write-miniLog -oc4j $oc4j -message "applib. файлы успешно скопированы"
      }
      catch [system.exception] {
        Write-miniLog -oc4j $oc4j -message "$($error[0])" -type ERROR
        $err = $true
        break
      }
    }

    else {
      Write-miniLog -oc4j $oc4j -message "applib. библиотеки актуальны, копирование данных не требуется"
    }     
  }

  elseif (!(Test-Path "$source\ADD_Files\$lib")){
    Write-miniLog -oc4j $oc4j -message "не найден путь до библиотек на диске" -type ERROR
    $err = $true
    break
  }

  else {
    Write-miniLog -oc4j $oc4j -message "не найден путь до целевого каталога $("$env:ORACLE_HOME\j2ee\$oc4j")" -type ERROR
    $err = $true
    break
  }


  # настройка библиотек shared lib в файле server.xml
  Write-miniLog -oc4j $oc4j -message "[настройка библиотек shared lib в файле в файле конфигурации ..\j2ee\$($oc4j)\config\server.xm]"
  
  $configFile = $null
  $chg = $false

  $configFile = Get-Item "$env:ORACLE_HOME\j2ee\$oc4j\config\server.xml"
  [XML]$serverXml = Get-Content $configFile.FullName

  # apache.xml
  $sharedLib = "apache.xml"
  if(!($serverXml."application-server"."shared-library" | ?{$_.name -eq $sharedLib})){
    try {
      $apacheXml = $serverXml.CreateElement('shared-library')
      $apacheXml.SetAttribute('name',"$sharedLib")
      $apacheXml.SetAttribute('version','2.7')
      ($serverXml."application-server").AppendChild($apacheXml) | Out-Null

      $apacheXmlNode = $serverXml."application-server"."shared-library" | ?{$_.name -eq $sharedLib}

      $sources = 'xercesImpl.jar',`
                 'xml-apis.jar'

      foreach ($sourcePath in $sources){
        $codeSourcePath = $serverXml.CreateElement('code-source')
        $codeSourcePath.SetAttribute('path',"$sourcePath")
        $apacheXmlNode.AppendChild($codeSourcePath) | Out-Null
      }

      Write-miniLog -oc4j $oc4j -message "набор библиотек $($sharedLib). успешно сконфигурирован"
      $chg = $true
    }

    catch [system.exception] {
      Write-miniLog -oc4j $oc4j -message "набор библиотек $($sharedLib). $($error[0])" -type ERROR
      $err = $true
      break
    }

  }

  else {
    Write-miniLog -oc4j $oc4j -message  "набор библиотек $($sharedLib). настройка не требуется"
  }


  ### apache.commons
  $sharedLib = "apache.commons"
  if(!($serverXml."application-server"."shared-library" | ?{$_.name -eq $sharedLib})){
    try {
      $apacheCommons = $serverXml.CreateElement('shared-library')
      $apacheCommons.SetAttribute('name',"$sharedLib")
      $apacheCommons.SetAttribute('version','1.0')
      ($serverXml."application-server").AppendChild($apacheCommons) | Out-Null

      $apacheCommonsNode = $ServerXml."application-server"."shared-library" | ?{$_.name -eq $sharedLib}

      $sources = 'commons-codec-1.4.jar',`
                 'commons-collections-3.2.1.jar',`
                 'commons-dbcp-1.3.jar',`
                 'commons-fileupload-1.2.2.jar',`
                 'commons-io-2.0.1.jar',`
                 'commons-pool-1.3.jar',`
                 'commons-transaction-1.2.jar',`
                 'commons-logging-1.1.1.jar',`
                 'aopalliance-1.0.jar',`
                 'commons-management-1.0.jar',`
                 'connector-1.0.jar',`
                 'slf4j-api-1.6.1.jar',`
                 'slf4j-log4j12-1.6.1.jar',`
                 'log4j-1.2.16.jar',`
                 'apache-log4j-extras-1.1.jar'

      foreach ($sourcePath in $sources){
        $codeSourcePath = $serverXml.CreateElement('code-source')
        $codeSourcePath.SetAttribute('path',"$sourcePath")
        $apacheCommonsNode.AppendChild($codeSourcePath) | Out-Null
      }

      Write-miniLog -oc4j $oc4j -message "набор библиотек $($sharedLib). успешно сконфигурирован"
      $chg = $true
    }

    catch [system.exception] {
      Write-miniLog -oc4j $oc4j -message "набор библиотек $($sharedLib). $($error[0])" -type ERROR
      $err = $true
      break
    }
  }

  else {
    Write-miniLog -oc4j $oc4j -message  "набор библиотек $($sharedLib). настройка не требуется"
  }

  # joda-time
  $sharedLib = "joda-time"
  if(!($serverXml."application-server"."shared-library" | ?{$_.name -eq $sharedLib})){
    try {
      $jodaTime = $serverXml.CreateElement('shared-library')
      $jodaTime.SetAttribute('name',"$sharedLib")
      $jodaTime.SetAttribute('version','2.0')
      ($serverXml."application-server").AppendChild($jodaTime) | Out-Null

      $jodaTimeNode = $serverXml."application-server"."shared-library" | ?{$_.name -eq "$sharedLib"}

      $sources = 'joda-time-2.0.jar'

      foreach ($sourcePath in $sources){
        $codeSourcePath = $serverXml.CreateElement('code-source')
        $codeSourcePath.SetAttribute('path',"$sourcePath")
        $jodaTimeNode.AppendChild($codeSourcePath) | Out-Null
      }

      Write-miniLog -oc4j $oc4j -message "набор библиотек $($sharedLib). успешно сконфигурирован"
      $chg = $true
    }

    catch [system.exception] {
      Write-miniLog -oc4j $oc4j -message "набор библиотек $($sharedLib). $($error[0])" -type ERROR
      $err = $true
      break
    }
  }

  else {
    Write-miniLog -oc4j $oc4j -message  "набор библиотек $($sharedLib). настройка не требуется"
  }

  # бэкап и сохранение изменений
  if($chg){
    $enc = Get-FileEncoding $configFile.FullName
    Save-File -path $configFile.FullName -difference $serverXml -encoding $enc
  }

  # настройка log4j.xml
  Write-miniLog -oc4j $oc4j -message "[настройка ..\j2ee\$($oc4j)\config\log4j.xml]"

  $configFile = $null
  $configFile = Get-Item $source\ADD_Files\log4j.xml
  $enc = Get-FileEncoding $configFile.FullName
  
  if(!(Test-Path  "$env:ORACLE_HOME\j2ee\$oc4j\config\log4j.xml")) {
    try {
      $log4jText = ((Get-Content $configFile.FullName) -replace "PLACEHOLDER","$($lastOne)/$($oc4j)")
      Out-File -FilePath "$env:ORACLE_HOME\j2ee\$oc4j\config\log4j.xml" -InputObject $log4jText -Encoding $enc -Force | Out-Null
      Write-miniLog -oc4j $oc4j -message "log4j. успешно сконфигурирован"
    }

    catch [system.exception] {
      Write-miniLog -oc4j $oc4j -message "log4j. $($error[0])" -type ERROR
      $err = $true
      break
    }
  }

  else {
    Write-miniLog -oc4j $oc4j -message "log4j. настройка не требуется"
  }
  

  # настройка imported-shared-libraries в файле application.xml
  Write-miniLog -oc4j $oc4j -message "[настройка imported-shared-libraries в файле ..\j2ee\$($oc4j)\config\application.xml]"

  $configFile = $null
  $chg = $false

  $configFile = Get-Item "$env:ORACLE_HOME\j2ee\$oc4j\config\application.xml"
  [XML]$applicationXml = Get-Content $configFile.FullName

  $importedSharedLibraries = $applicationXML."orion-application"."imported-shared-libraries" 

  $libraries = 'oracle.ifs.client',`
               'apache.commons',`
               'global.libraries'

  foreach ($sharedLib in $libraries){
    if(!($importedSharedLibraries | select -ExpandProperty "import-shared-library" |?{$_.name -like "*$($sharedLib)*"})) {
      try {
        $library = $applicationXML.CreateElement('import-shared-library')
        $library.SetAttribute('name',"$sharedLib")
        $importedSharedLibraries.AppendChild($library) | Out-Null
        Write-miniLog -oc4j $oc4j -message "библиотека $($sharedLib). успешно сконфигурирована"
        $chg = $true
      }

      catch [system.exception] {
        Write-miniLog -oc4j $oc4j -message "библиотека $($lib). $($error[0])" -type ERROR
        $err = $true
        break
      }
    }
    
    else {
      Write-miniLog -oc4j $oc4j -message  "библиотека $($sharedLib). настройка не требуется"
    }
  }

  # бэкап и сохранение изменений
  if($chg) {
    Start-Sleep -Seconds 1
    $enc = Get-FileEncoding $configFile.FullName
    Save-File -path $configFile.FullName -difference $applicationXML -encoding $enc
  }

  # настройка transaction-manager.xml
  Write-miniLog -oc4j $oc4j -message "[настройка imported-shared-libraries в файле ..\j2ee\$($oc4j)\config\transaction-manager.xml]"

  $configFile = $null
  $chg = $false

  $configFile = Get-Item "$env:ORACLE_HOME\j2ee\$oc4j\config\transaction-manager.xml"
  [XML]$transactionManagerXml = Get-Content $configFile.FullName

  if ($transactionManagerXml."transaction-manager"."transaction-timeout" -ne "3000") {
    try {
      $transactionManagerXml."transaction-manager"."transaction-timeout" = "3000"
      Write-miniLog -oc4j $oc4j -message "transaction-manager. успешно сконфигурирован"
      $chg = $true
    }

    catch [system.exception] {
      Write-miniLog -oc4j $oc4j -message "transaction-manager. $($error[0])" -type ERROR
      $err = $true
      break
    }
  }

  else {
    Write-miniLog -oc4j $oc4j -message "transaction-manager. настройка не требуется"
  }
  
  # бэкап и сохранение изменений
  if ($chg) {
    $enc = Get-FileEncoding $configFile.FullName
    Save-File -path $configFile.FullName -difference $transactionManagerXml -encoding $enc
  }

  $script:CSerr = $err
}


function Set-javaOptions {
<#
.SYNOPSIS
Set start-parameters and oc4j-options for container in opmn.xml
#>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$True)]$oc4j,
    [Parameter()][int]$Xmx = 512,
    [Parameter()][int]$Xms = 512,
    [Parameter()]$ServerID,
    [Parameter()]$externalBeans,
    [Parameter()]$externalSecurity,
    [Parameter()]$externalConfiguration,
    [switch]$string
  )

  begin {}

  process {
    #common <start-parameters>
    #java-options

    [array]$startParam = @(
      "-server",`
      "-Xmx$($Xmx)M",`
      "-Xms$($Xms)M",`
      "-Dlog4j.configuration=file:///`$ORACLE_HOME/j2ee/$oc4j/config/log4j.xml",`
      "-Djava.security.policy=`$ORACLE_HOME/j2ee/$oc4j/config/java2.policy",`
      "-Djava.awt.headless=true",`
      "-Dhttp.webdir.enable=false",`
      "-XX:MaxPermSize=256M",`
      "-XX:AppendRatio=3",`
      "-XX:+UseConcMarkSweepGC",`
      "-XX:+CMSClassUnloadingEnabled",`
      "-XX:+CMSPermGenSweepingEnabled",`
      "-Doc4j.jmx.security.proxy.off=true",`
      "-Doc4j.userThreads=true",`
      "-Dstdstream.rotatetime=00:01",`
      "-Dstdstream.filenumber=7"
    )

    if ($externalBeans){
      $startParam += "-Dexternal.beans=file:///$($externalBeans)"
    }

    if ($externalSecurity){
      $startParam += "-Dexternal.security=file:///$($externalSecurity)"
    }

    if ($externalConfiguration){
      $startParam += "-Dexternal.configuration=file:///$($externalConfiguration)"
    }

    if ($ServerID){
      $startParam += "-DServerId=$($ServerID)"
    }

    if(!$string){
      $componentNode = $opmnXml.opmn."process-manager"."ias-instance"."ias-component" | ?{$_.id -eq "$oc4j"}
      $startParamNode = $componentNode."process-type"."module-data"."category" | ?{$_.id -eq "start-parameters"}

      ($startParamNode.data | ?{$_.id -eq 'java-options'}).value = ($startParam  -join ' ')


      #oc4j-options
      $oc4jOptions = ($startParamNode.data | ?{$_.id -eq 'java-options'}).clone()
      $oc4jOptions.id = 'oc4j-options'
      $oc4jOptions.value = "-out `$ORACLE_HOME/opmn/logs/$oc4j.out -err `$ORACLE_HOME/opmn/logs/$oc4j.err"
      $startParamNode.AppendChild($oc4jOptions) | Out-Null
    }

    else {
      $startParam  -join ' '
    }
  }

  end {}
}


function Set-resourceProvider {
<#
.SYNOPSIS
Set resource-provider in configuration file application.xml
#>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$True)]$name,
    [Parameter(Mandatory=$True)]$config,
    [Parameter()]$disk = $lastone,
    [Parameter()]$module = $oc4j,
    [Parameter()]$description
  )

  begin {}

  process {
    $provider = $applicationXML.CreateElement('resource-provider')
    $provider.SetAttribute('class','com.evermind.server.deployment.ContextScanningResourceProvider')
    $provider.SetAttribute('name',"$($name)")
    ($applicationXML."orion-application").AppendChild($provider) | Out-Null

    $providerNode = $applicationXML."orion-application"."resource-provider" | ?{$_.name -eq "$($name)"}

    $providerDE = $applicationXML.CreateElement('description')
    $providerDV = $applicationXML.CreateTextNode("$description resource provider")

    $providerNode.AppendChild($providerDE) | Out-Null
    $providerDE.AppendChild($providerDV) | Out-Null

    $providerFI = $applicationXML.CreateElement('property')
    $providerFI.SetAttribute('name',"java.naming.factory.initial")
    $providerFI.SetAttribute('value',"com.sun.jndi.fscontext.RefFSContextFactory")
    $providerNode.AppendChild($providerFI) | Out-Null

    $providerPU = $applicationXML.CreateElement('property')
    $providerPU.SetAttribute('name',"java.naming.provider.url")
    $providerPU.SetAttribute('value',"file:/$($disk)/$($module)/Config/$($config)")
    $providerNode.AppendChild($providerPU) | Out-Null
  }

  end {}
}


function Save-File {
<#
.SYNOPSIS
Backup and save changes into configuration file
#>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$True)]$difference,
    [Parameter(Mandatory=$True)]$path,
    [Parameter()]$encoding = "ASCII"
  )
  
  begin {
    $cult = (Get-Culture).Name

    switch ($cult){
      "ru-RU" {$delimiter = ","}
      "en-US" {$delimiter = "\."}
      default {$delimiter = "\."}
    }

    $timeStamp = ((Get-Date -uFormat %s) -split "$delimiter")[0]
  }

  process {
    $tmp = [System.IO.Path]::GetTempFileName()
    $difference.Save("$tmp")
    $chg = Get-Content "$tmp"

    if (Test-Path $path){
      $file = Get-Item $path
      Rename-Item -Path $file -NewName ($file.BaseName + "." + $timeStamp + $file.Extension) -Force
      Out-File -FilePath $file.FullName -InputObject $chg  -Encoding $encoding -Force
    }

    else {
      Write-Output "file $path doesn't exist, please check path"
    }

    Remove-Item -Path $tmp -Force
  }

  end {
    Remove-Variable tmp, difference, chg, file, path, timeStamp -Force -Confirm:$false -ErrorAction SilentlyContinue
  }
}


function Write-miniLog {
<#
.SYNOPSIS
Write simple log of creating and configuration process 
#>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$True,Position=1)]$message,
    [Parameter(Mandatory=$True,Position=0)]$oc4j,
    [Parameter()]$logfile = "$lastOne\$oc4j\logs\cofiguration.log",    
    [Parameter()] [ValidateSet("INFO","WARNING","ERROR")]$type = "INFO"
  )

  begin {
    if(!(Test-Path "$lastOne\$oc4j\logs")){
      New-Item -Path "$lastOne\$oc4j\logs" -ItemType Directory | Out-Null
    } 
  }
  
  process {
    $dt = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
    $msg = $dt + "`t" + "[$($oc4j)]" + "`t" + "[$($type)]" + "`t" + $message
    Out-File -FilePath $logfile -InputObject $msg -Append -encoding unicode
  }
  
  end {}
}


### not main
function Get-FileEncoding {
  [CmdletBinding()] 
  Param (
    [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)] 
    [string]$Path
  )

  [byte[]]$byte = get-content -Encoding byte -ReadCount 4 -TotalCount 4 -Path $Path
  #Write-Host Bytes: $byte[0] $byte[1] $byte[2] $byte[3]

  # EF BB BF (UTF8)
  if ( $byte[0] -eq 0xef -and $byte[1] -eq 0xbb -and $byte[2] -eq 0xbf )
  { Write-Output 'UTF8' }

  # FE FF  (UTF-16 Big-Endian)
  elseif ($byte[0] -eq 0xfe -and $byte[1] -eq 0xff)
  { Write-Output 'Unicode UTF-16 Big-Endian' }

  # FF FE  (UTF-16 Little-Endian)
  elseif ($byte[0] -eq 0xff -and $byte[1] -eq 0xfe)
  { Write-Output 'Unicode UTF-16 Little-Endian' }

  # 00 00 FE FF (UTF32 Big-Endian)
  elseif ($byte[0] -eq 0 -and $byte[1] -eq 0 -and $byte[2] -eq 0xfe -and $byte[3] -eq 0xff)
  { Write-Output 'UTF32 Big-Endian' }

  # FE FF 00 00 (UTF32 Little-Endian)
  elseif ($byte[0] -eq 0xfe -and $byte[1] -eq 0xff -and $byte[2] -eq 0 -and $byte[3] -eq 0)
  { Write-Output 'UTF32 Little-Endian' }

  # 2B 2F 76 (38 | 38 | 2B | 2F)
  elseif ($byte[0] -eq 0x2b -and $byte[1] -eq 0x2f -and $byte[2] -eq 0x76 -and ($byte[3] -eq 0x38 -or $byte[3] -eq 0x39 -or $byte[3] -eq 0x2b -or $byte[3] -eq 0x2f) )
  { Write-Output 'UTF7'}

  # F7 64 4C (UTF-1)
  elseif ( $byte[0] -eq 0xf7 -and $byte[1] -eq 0x64 -and $byte[2] -eq 0x4c )
  { Write-Output 'UTF-1' }

  # DD 73 66 73 (UTF-EBCDIC)
  elseif ($byte[0] -eq 0xdd -and $byte[1] -eq 0x73 -and $byte[2] -eq 0x66 -and $byte[3] -eq 0x73)
  { Write-Output 'UTF-EBCDIC' }

  # 0E FE FF (SCSU)
  elseif ( $byte[0] -eq 0x0e -and $byte[1] -eq 0xfe -and $byte[2] -eq 0xff )
  { Write-Output 'SCSU' }

  # FB EE 28  (BOCU-1)
  elseif ( $byte[0] -eq 0xfb -and $byte[1] -eq 0xee -and $byte[2] -eq 0x28 )
  { Write-Output 'BOCU-1' }

  # 84 31 95 33 (GB-18030)
  elseif ($byte[0] -eq 0x84 -and $byte[1] -eq 0x31 -and $byte[2] -eq 0x95 -and $byte[3] -eq 0x33)
  { Write-Output 'GB-18030' }

  else
  { Write-Output 'ASCII' }
}