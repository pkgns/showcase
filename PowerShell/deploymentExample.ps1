$source = "path/to/source/folder"
$oc4jPassword = "***"


# имя контейнера
$oc4j = "MINIJ"


# ПРИМЕР:
# MINIUSER; MINIPASSWORD; 127.0.0.1; 1521; PROD

# учетные данные для подключения к БД 
$MINIcurrent = 'MINITEST; MINITEST; vm-mini-db.kontur; 1521; prod'

# учетные данные для подключения к оперативной БД 
$MINIoper = 'Ousername; Opassword; Ohost; Oport; Oinstance'

# учетные данные для подключения к архивной БД
$MINIarch = 'Ausername; Apassword; Ahost; Aport; Ainstance'


# создаем oc4j контейнер
# проверка на существование одноименного контейнера
$exists = $false
$err = $false

foreach ($process in (Get-opmnStatus -Simple | Select-Object -Property "process-type")){
  if (($process | Select-Object -ExpandProperty "process-type") -eq $oc4j){
    $exists = $true
  }
}


if(!($exists)){
  # создаем контейнер
  cd $env:ORACLE_HOME\BIN
  & createinstance -instanceName $oc4j -groupName $oc4j -defaultAdminPass

  cd $env:ORACLE_HOME\j2ee\home\
  Start-Process java -ArgumentList "-Doracle.j2ee.home=../$oc4j/", "-jar", "jazn.jar", "-activateadmin", "$oc4jPassword"

}

else {
  # создаем дерево каталогов
  Write-miniLog -oc4j $oc4j -message "[создание каталогов]"
  
  $oc4jPath = "$lastOne\$oc4j"
  [array]$DirList = "\logs\Archive",`
                    "\Config\jndi-MINI-mq",`
                    "\Config\MINI-configs"

  $DirList| %{
    if (!(Test-Path "$oc4jPath\$_")){
      try {
        New-Item -Path "$oc4jPath\$_" -ItemType Directory -Force| Out-Null
        Write-miniLog -oc4j $oc4j -message "создан каталог $oc4jPath$($_)"      
      }

      catch [system.exception] {
        Write-miniLog -oc4j $oc4j -message "$($error[0])" -type ERROR
        $err = $true
        break
      }
    }

    else {
      Write-miniLog -oc4j $oc4j -message "каталог $oc4jPath$($_) существует. настройка не требуется"
    }
  }


  # настройки подключения к базе данных data-source.xml
  Write-miniLog -oc4j $oc4j -message "[настройка подключения к базе данных в фйле конфигурации ..\j2ee\$($oc4j)\config\data-source.xml]"
  
  $configFile = $null
  $chg = $false

  $configFile = Get-Item -Path "$env:ORACLE_HOME\j2ee\$oc4j\config\data-sources.xml"
  [XML]$dataSource = Get-Content $configFile.FullName

  # настройка conntction-poll'a для текущего экземпляра БД
  if ($MINIcurrent){
    $pool = "MINIDatabasePool"
    if(!(($dataSource."data-sources"."connection-pool" | ?{$_.name -eq "$pool"}))){
      try {
        Set-cpSettings -dataBase $MINIcurrent -connectionPoolName "$pool" -jndiName "MINIBusinessProcess" -managedDataSourceName "MINIDatabaseSource"
        Write-miniLog -oc4j $oc4j -message "$pool. успешно сконфигурирован"
        $chg = $true
      }

      catch [system.exception] {
        Write-miniLog -oc4j $oc4j -message "$pool. $($error[0])" -type ERROR
        $err = $true
        break
      }
    }
  
    else {
      Write-miniLog -oc4j $oc4j -message "$pool. настройка не требуется"
    }
  }

  # настройка conntction-poll'a для оперативного экземпляра БД
  if ($MINIoper){
    $pool = "OperativDatabasePool"
    if(!(($dataSource."data-sources"."connection-pool" | ?{$_.name -eq "$pool"}))){
      try {
        Set-cpSettings -dataBase $MINIoper -connectionPoolName "$pool" -jndiName "OperativDS" -managedDataSourceName "MINIDatabaseSourceOperativ"
        Write-miniLog -oc4j $oc4j -message "$pool. успешно сконфигурирован"
        $chg = $true
      }

      catch [system.exception] {
        Write-miniLog -oc4j $oc4j -message "$pool. $($error[0])" -type ERROR
        $err = $true
        break
      }
    }
  
    else {
      Write-miniLog -oc4j $oc4j -message "$pool. настройка не требуется"
    }
  }

  # настройка conntction-poll'a для архивного экземпляра БД
  if ($MINIarch){
    $pool = "ArchiveDatabasePool"
    if(!($dataSource."data-sources"."connection-pool" | ?{$_.name -eq "$pool"})){
      try {
        Set-cpSettings -dataBase $MINIarch -connectionPoolName "$pool"  -jndiName "ArchiveDS" -managedDataSourceName "MINIDatabaseSourceArchive"
        Write-miniLog -oc4j $oc4j -message "$pool. успешно сконфигурирован"
        $chg = $true
      }

      catch [system.exception] {
        Write-miniLog -oc4j $oc4j -message "$pool. $($error[0])" -type ERROR
        $err = $true
        break
      }
    }
  
    else {
      Write-miniLog -oc4j $oc4j -message "$pool. настройка не требуется"
    }
  }

  # бэкап и сохранение изменений
  if ($chg){
    $enc = Get-FileEncoding $configFile.FullName
    Save-File -path $configFile.FullName -difference $dataSource -encoding $enc
  }

  # настройки параметров запуска java для контейнера в фйле конфигурации opmn.xml
  Write-miniLog -oc4j $oc4j -message "[настройка параметров запуска java для контейнера в фйле конфигурации ..\opmn\config\opmn.xml]"

  $configFile = $null
  $chg = $false

  $configFile = Get-Item "$env:ORACLE_HOME\opmn\conf\opmn.xml"
  [XML]$opmnXml = Get-Content $configFile.FullName

  $componentNode = $opmnXml.opmn."process-manager"."ias-instance"."ias-component" | ?{$_.id -eq "$oc4j"}
  $startParamNode = $componentNode."process-type"."module-data"."category" | ?{$_.id -eq "start-parameters"}


  if((($startParamNode.data | ?{$_.id -eq 'java-options'}).value) -ne (Set-javaOptions -oc4j $oc4j -string)) {
    try {
      Set-javaOptions -oc4j $oc4j
      Write-miniLog -oc4j $oc4j -message "start-parameters. успешно сконфигурирован"
      $chg = $true
    }

    catch [system.exception] {
      Write-miniLog -oc4j $oc4j -message "start-parameters. $($error[0])" -type ERROR
      $err = $true
      break
    } 
  }

  else {
    Write-miniLog -oc4j $oc4j -message "start-parameters. настройка не требуется"
  }

  # бэкап и сохранение изменений
  if($chg) {
    $enc = Get-FileEncoding $configFile.FullName
    Save-File -path $configFile.FullName -difference $opmnXml -encoding $enc
  }

  # настройка resource-provider в файле application.xml
  Write-miniLog -oc4j $oc4j -message "[настройка resource-provider в файле конфигурации ..\j2ee\$($oc4j)\config\application.xml]"

  $configFile = $null
  $chg = $false

  $configFile = Get-Item "$env:ORACLE_HOME\j2ee\$oc4j\config\application.xml"
  [XML]$applicationXml = Get-Content $configFile.FullName

  # MINI2config
  $provider = "MINI2config"
  if(!($applicationXML."orion-application"."resource-provider" | ?{$_.name -eq "$($provider)"})) {
    try {
      Set-resourceProvider -name $provider -config "jndi-MINI-mq" -module $oc4j -description "MINI-2"
      Write-miniLog -oc4j $oc4j -message "$($provider). успешно сконфигурирован"
      $chg = $true
    }

    catch [system.exception] {
      Write-miniLog -oc4j $oc4j -message "start-parameters. $($error[0])" -type ERROR
      $err = $true
      break
    } 
  }

  else {
    Write-miniLog -oc4j $oc4j -message "$($provider). настройка не требуется"
  }

  # MINI2jconfig
  $provider = "MINI2jconfig"
  if(!($applicationXML."orion-application"."resource-provider" | ?{$_.name -eq "$($provider)"})) {
    try {
      Set-resourceProvider -name "$provider" -config "MINI-configs" -module $oc4j -description "MINI-2"
      Write-miniLog -oc4j $oc4j -message "$($provider). успешно сконфигурирован"
      $chg = $true
    }

    catch [system.exception] {
      Write-miniLog -oc4j $oc4j -message "start-parameters. $($error[0])" -type ERROR
      $err = $true
      break
    } 
  }

  else {
    Write-miniLog -oc4j $oc4j "$($provider). настройка не требуется"
  }

  # бэкап и сохранение изменений
  if($chg) {
    $enc = Get-FileEncoding $configFile.FullName
    Save-File -path $configFile.FullName -difference $applicationXML -encoding $enc
  }

  # базовые настройки контейнера
  Set-j2eeCommonSettings -oc4j $oc4j -source $source

  if(!$err -and !$CSerr){
    Write-Output "конфигурация контейнера $($oc4j) успешно завершена"
  }

  else {
    Write-Output "в процессе конфигурации контейрена $($oc4j) произошла ошибка, подробная информация в лог файле $lastOne\$oc4j\logs\cofiguration.log"
  }

  Remove-Variable CSerr -Scope script -Force -ErrorAction SilentlyContinue
}
