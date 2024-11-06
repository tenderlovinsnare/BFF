<#

    ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗ ██████╗ ██████╗      ██████╗██╗     ██╗███████╗███╗   ██╗████████╗
    ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗    ██╔════╝██║     ██║██╔════╝████╗  ██║╚══██╔══╝
    ██████╔╝███████║██║     █████╔╝ ███████╗   ██║   ██║   ██║██████╔╝    ██║     ██║     ██║█████╗  ██╔██╗ ██║   ██║
    ██╔══██╗██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██║   ██║██╔═══╝     ██║     ██║     ██║██╔══╝  ██║╚██╗██║   ██║
    ██████╔╝██║  ██║╚██████╗██║  ██╗███████║   ██║   ╚██████╔╝██║         ╚██████╗███████╗██║███████╗██║ ╚████║   ██║
    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝          ╚═════╝╚══════╝╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝
            
      ██████╗ ██████╗ ██████╗ ███████╗    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗
     ██╔════╝██╔═══██╗██╔══██╗██╔════╝    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝
     ██║     ██║   ██║██████╔╝█████╗      █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗
     ██║     ██║   ██║██╔══██╗██╔══╝      ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║
     ╚██████╗╚██████╔╝██║  ██║███████╗    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║███████║
      ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝


    .SYNOPSIS
      Defines a common set of security and logging functions for easy integration into other PowerShell scripts.


    .DESCRIPTION
      This is a general purpose PowerShell module which contain functions such as logging, easier code verification and 
      other functions. For more details including versions and release notes, please see the individual functions and 
      their documentation below.


    .NOTES   
      Project:                Backstop Flexibility Framework (BFF)
      Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
      Copyright:              ©TenderLovinSnare
      Contact:                TenderLovinSnare@gmail.com
      License:                MIT (https://opensource.org/license/mit)
      Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
      Major Release Name:     Tender Lovin' Snare
      █ Last Updated By:      TenderLovinSnare
      █ Release Stage:        BETA
      █ Version:              0.2
      █ Last Update:          26-October-2024
      █ Latest Release Notes:
      ↪ 

#>




##############################################################################################################################################################################
#region   PARAMETERS   #######################################################################################################################################################
##############################################################################################################################################################################

    # Define standard parameters so we can use -Verbose, etc. with this script
    [CmdletBinding()]
    param()

#endregion PARAMETERS




##############################################################################################################################################################################
#region  VERSION INFO  #######################################################################################################################################################
##############################################################################################################################################################################

    # Script Version
    [System.Version]$moduleVersion = "0.2.0"

    # Breakout the Version info for easier parsing
    $moduleVersionMajor = ($moduleVersion).Major
    $moduleVersionMinor = ($moduleVersion).Minor
    $moduleVersionBuild = ($moduleVersion).Build
    $moduleVersionString = "$moduleVersionMajor.$moduleVersionMinor.$moduleVersionBuild"

#endregion VERSION INFO




##############################################################################################################################################################################
#region  VARIABLES  ##########################################################################################################################################################
##############################################################################################################################################################################

    # Silence the yellow progress bar at the top of the screen
    $Global:ProgressPreference = 'SilentlyContinue'

    # Create script correlation GUID to link all Splunk messages together for this run
    $scriptCorrelationId = [guid]::NewGuid()
    
    # Get most of the general asset info once vs. numerous queries
    $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
    $osInfo = Get-CimInstance -Class Win32_OperatingSystem
    $cpuInfo = Get-CimInstance -Class CIM_Processor
    $diskInfo = Get-CimInstance -ClassName win32_logicaldisk 

    # Get discrete variables for asset info
    $Global:adDomain = ($computerInfo).Domain

    # Extract basic user info
    if($computerInfo.UserName)
    {
        $Global:localUserDomain = $computerInfo.UserName.Split('\')[0]
        $Global:localUser =  $computerInfo.UserName.Split('\')[1]

    } Else {

        $Global:localUserDomain = "blank"
        $Global:localUser =  "blank"
    }

    # Get remaining general asset variables
    $Global:cpuArch = ($osInfo).OSArchitecture
    $Global:cpuName = ($cpuInfo).Name | Get-Unique
    $Global:cpuMaxClockSpeedInMhz = ($cpuInfo).MaxClockSpeed | Get-Unique
    $Global:cpuNumberOfLogicalCores = (($cpuInfo).NumberOfLogicalProcessors | Measure-Object -Sum).Sum
    $Global:cpuNumberOfPhysicalCores = (($cpuInfo).NumberOfCores | Measure-Object -Sum).Sum
    $Global:totalMemoryRaw = ($osInfo).TotalVisibleMemorySize
    $totalMemoryInGB = $totalMemoryRaw / 1024 /1024
    $Global:totalMemoryInGB = [math]::Round($totalMemoryInGB)
    $availableMemoryRaw = $osInfo.FreePhysicalMemory
    $availableMemoryInGB = $availableMemoryRaw /1024 /1024
    $Global:availableMemoryInGB = [math]::Round($availableMemoryInGB,1)
    $dotnetVer = (Get-ChildItem "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" | Get-ItemProperty -Name Version).Version
    $diskCFreeSpaceInGB = ($diskinfo | Where-Object {$_.DeviceID -match "C"}).freespace/1024/1024/1024
    $Global:diskCFreeSpaceInGB = [math]::Round($diskCFreeSpaceInGB,2)
    $Global:osBuild = ($osInfo).BuildNumber
    $Global:osName = ($osInfo).Caption
    $Global:osRelease = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    $Global:osVer = ($osInfo).Version
    $Global:osVersionName = (($osInfo.Caption | Select-String -Pattern "\d{1,5}.+").Matches.Value).Replace(" ","")
    $Global:osLocale = (Get-WinSystemLocale).Name
    $Global:pcSystemType = ($computerInfo).PCSystemType
    $Global:assetManufacturer = $computerInfo.Manufacturer
    $assetModel = $computerInfo.Model
    $psMajorVer = ($PSVersionTable.PSVersion).Major
    $psMinorVer = ($PSVersionTable.PSVersion).Minor
    [System.Decimal]$Global:psVer = "$psMajorVer.$psMinorVer"
    [System.String]$lastBootUpTime = ($osInfo).LastBootUpTime.tostring()

    # Define General Asset Type
    #REF: https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
    $domainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
    if($domainRole -eq 0) {$assetType = "standaloneWorkstation"}
    if($domainRole -eq 1) {$assetType = "memberWorkstation"}
    if($domainRole -eq 2) {$assetType = "standaloneServer"}
    if($domainRole -eq 3) {$assetType = "memberServer"}
    if($domainRole -eq 4) {$assetType = "backupDomainController"}
    if($domainRole -eq 5) {$assetType = "primaryDomainController"}

    # Determine OS Type
    if($osName -match "server")
    {
        $Global:osClass = "server"

    } Else {

        $Global:osClass = "workstation"
    }

    # Overide osClass as "domainController" if asset is a domain controller. Open to better ideas but typically only DC's listen on 3268 for LDAP/Global Catalog port.
    # For the second check, we look at the domainRole. If it's either 4 or 5, it's a DC.
    # REF: https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
    if((Get-NetTCPConnection -State listen | Where-Object {$_.LocalPort -eq "3268"}) -or ($domainRole -match "4|5"))
    {
        $Global:osClass = "domainController"
    }

    # Conditional variables based on PowerShell version of 5.0 and above.
    if($psVer -ge "5.0")
    {
        # Get additional asset details for feedback function
        $Global:assetDN = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine' | Get-ItemPropertyValue -Name 'Distinguished-Name'
        $assetTimezone = (Get-TimeZone).Id

        # Get Active IP Adress
        $activeAdapters = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"})
        $localActiveMacs = (Get-NetAdapter -Name $activeAdapters.InterfaceAlias).MacAddress
        $localActiveIps = ($activeAdapters).IPv4Address.IPAddress

    }

    # If the relayHostname variable populated by a calling script, let's check to see if the relay is reachable
    if(Get-Variable relayHostname -ErrorAction SilentlyContinue)
    {
        # Check to see if the Splunk HEC relay is reachable
        if(($relayHostname)   -and   ((Test-NetConnection -ComputerName $relayHostname -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded))
        {
            $Global:relayReachable = $true

        } else {

            $Global:relayReachable = $false
        }

    }

    # Check to see if the Splunk HEC is reachable directly (on network)
    if((Test-NetConnection -ComputerName example.com -Port 8088 -WarningAction SilentlyContinue).TcpTestSucceeded)
    {
        $Global:splunkHECReachable = $true

    } else {

        $Global:splunkHECReachable = $false
    }

    # Determine Switch Used in Script
    $scriptSwitchUsed = $MyInvocation.BoundParameters.Keys

    # Determine what the asset's business unit is based on w/e logic you want.
    if(($adDomain -like "*EXAMPLE*") -or ($adDomain -like "*EXAMPLE*"))
    {
        # Set to EXAMPLE
        $Global:businessUnit = "EXAMPLE"

        # Set feedback token to example company. Note that the Splunk HEC token isn't generally secret as it's used for logging just about everywhere and needs to be constrainded
        # to only certain indexes and souretypes server-side.
        $splunkHecToken = "EXAMPLE"

        # Set feedback index to EXAMPLE
        $splunkIndex = "EXAMPLE"
        $splunkIndexC2 = "EXAMPLE2"
        $splunkIndexC3 = "EXAMPLE3"

    } else {

        # Set to EXAMPLE2
        $Global:businessUnit = "EXAMPLE2"

        # Set feedback token to commercial
        $splunkHecToken = "EXAMPLE"

        # Set feedback index to EXAMPLE
        $splunkIndex = "EXAMPLE"
        $splunkIndexC2 = "EXAMPLE2"
        $splunkIndexC3 = "EXAMPLE3"
    }

    # Define who script is running as
    $scriptRunningAs = whoami

    # Dynamically determine the calling script name: The name of this script that called this module.
    if($MyInvocation.PSCommandPath)
    {
        # Get calling script name and path
        $scriptPath = $MyInvocation.PSCommandPath
        $scriptName = Split-Path $scriptPath -leaf
    
        # Get file hash of the calling script
        $scriptFileHashSHA256 = (Get-FileHash $scriptPath -Algorithm SHA256 -ErrorAction SilentlyContinue).hash
    }

#endregion VARIABLES




##############################################################################################################################################################################
#region  FUNCTIONS  ##########################################################################################################################################################
##############################################################################################################################################################################




#endregion DEFINE FUNCTIONS




##############################################################################################################################################################################
#region   SIGNATURE   ########################################################################################################################################################
##############################################################################################################################################################################


