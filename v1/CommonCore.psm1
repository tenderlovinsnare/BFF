<#

     ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗ ██████╗ ██████╗      ██████╗ ██████╗ ███╗   ███╗███╗   ███╗ ██████╗ ███╗   ██╗
     ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗    ██╔════╝██╔═══██╗████╗ ████║████╗ ████║██╔═══██╗████╗  ██║
     ██████╔╝███████║██║     █████╔╝ ███████╗   ██║   ██║   ██║██████╔╝    ██║     ██║   ██║██╔████╔██║██╔████╔██║██║   ██║██╔██╗ ██║
     ██╔══██╗██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██║   ██║██╔═══╝     ██║     ██║   ██║██║╚██╔╝██║██║╚██╔╝██║██║   ██║██║╚██╗██║
     ██████╔╝██║  ██║╚██████╗██║  ██╗███████║   ██║   ╚██████╔╝██║         ╚██████╗╚██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║╚██████╔╝██║ ╚████║
     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝          ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                                                                     
              ██████╗ ██████╗ ██████╗ ███████╗    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗         
             ██╔════╝██╔═══██╗██╔══██╗██╔════╝    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝         
             ██║     ██║   ██║██████╔╝█████╗      █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗         
             ██║     ██║   ██║██╔══██╗██╔══╝      ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║         
             ╚██████╗╚██████╔╝██║  ██║███████╗    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║███████║         
              ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝         


    .SYNOPSIS
      Defines a common set of security and logging functions for easy integration into other PowerShell scripts.


    .DESCRIPTION
      This is a general purpose PowerShell module which contains many common functions such as logging, easier code verification, encrpytion and 
      many other functions. For more details including versions and release notes, please see the individual functions and their documentation below. 


    .NOTES
      Project:                Backstop Flexibility Framework (BFF)
      Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
      Copyright:              ©TenderLovinSnare
      Contact:                TenderLovinSnare@gmail.com
      License:                MIT (https://opensource.org/license/mit)
      Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
      █ Last Updated By:      TenderLovinSnare
      █ Release Stage:        BETA
      █ Version:              0.2
      █ Last Update:          26-November-2024
      █ RELEASE NOTES:
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
    if((Test-NetConnection -ComputerName $serverFQDN -Port 8088 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue).TcpTestSucceeded)
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
  
    function Compare-Times
    {
      <#
          .SYNOPSIS
            Determines if an action is ready to run or not by comparing the delta between the last time the action ran against the current time. 
            If that time delta exceeds the the variable runIntervalInSeconds, the action is marked as ready to run again. You need to supply this
            function with the LastRunDateTime parameter from another script which tells it the last time the action ran. The output of this function
            will be '$readyToRun = $true' if it's ready to run. Else, it does nothing and flushes the readyToRun variable to be safe.


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          1-August-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .PARAMETER LastRunDateTime
            Take the input of the lastRunTime of the given action. The data passed here MUST be in [System.DateTime] format. 


          .EXAMPLE
            Compare-Times -LastRunDateTime $lastRunTime
      #>




      #region  DEFINE PARAMETERS  ##########################################################################################################################################

          Param
          (
              [parameter(Mandatory=$true)]
              [System.DateTime]
              $LastRunDateTime
          )

      #endregion DEFINE PARAMETERS


      #region  COMPARE TIMES  ##############################################################################################################################################
      
          # Perform test if the difference between the last time the test ran and the current time exceeds the variable runIntervalInSeconds
          $currentTime = Get-Date

          # Get the amount of time between now and the last run time so it can be compared
          $timeDeltaInSeconds = ($currentTime - $LastRunDateTime).TotalSeconds

          # Round it to the nearest second so there's no decimal place
          $timeDeltaInSeconds = [math]::Round($timeDeltaInSeconds)

          # Set the variable to run if the amount of time since the last run time exceeds what's set in runIntervalInSeconds or if lastRunTime was blank
          if(($timeDeltaInSeconds -ge $runIntervalInSeconds) -or (-not($LastRunDateTime)))
          {
              # Set the global variable that the action can run. You need to key off of this in your other script (if readyToRun = true, do something)
              $Global:readyToRun = $True

          } else {

              # Set the global variable to $False
              $Global:readyToRun = $False
          }

      #endregion COMPARE TIMES
    }




    function Set-FileSignature
    {
      <#
          .SYNOPSIS
            Signs scripts (ps1, psm1, ps1xml) and binaries (including DLL's) based on two levels of trust: low and high. There are
            other file types it can sign as well - see REF: https://www.leeholmes.com/which-files-support-authenticode-signatures/        


          .DESCRIPTION
            This script relies on having both High trust and Low trust Backstop signing certs installed depending on which you'd like
            to call. While both certs must be heavily guarded, the high trust cert is the most important. These certs are used to 
            verify code prior to execution and must be highly secured.


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        BETA
            █ Version:              0.2
            █ Last Update:          1-August-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .PARAMETER Path
            Specify the full path to the file you want to sign


          .PARAMETER TrustLevel
            Specify either low or high:

            ↪ Low:  Only use for low-risk files where, if they were compromised, the damage is minimal.
                    
                EXAMPLE:
                File transferes to a server where you don't dare host the high-trust keys on an internal server and
                the server has full "fail and alert if invalid" checks for the signature on the file you're sending.
            
            ↪ High: Use for anything else where, if the file were compromised, the damage would be major to catastrophic.
                    
                EXAMPLE:
                Any code, scripts, binaries or modules that endpoints may get from our server to execute locally. 
                If the cert is compromised, the business may suffer catastrophic loss which will generate additional
                resume writing experience for you. Also... "buying the dip" after it happens is NOT a good insurance 
                policy nor a personal compensating control!


          .PARAMETER CertStoreLocation
            Specify the location of the certificate store. If you installed the cert on your local profile, it's CurrentUser.
            If you installed the cert on the local computer, specify LocalMachine


          .PARAMETER QuietMode
            That mute button that certain someone doesn't have.


          .EXAMPLE
            Set-FileSignature -Path "C:\Path\to\your\file.ps1" -TrustLevel High -CertStoreLocation CurrentUser
          
      #>




      # Define script parameters (arguments to the script)
      Param
      (
          # The path to the file to sign
          [parameter(Mandatory=$True)]
          [System.IO.FileInfo]$Path,

          # Specify the trust level
          [parameter(Mandatory=$True)]
          [ValidateSet('Low', 'High')]
          [String]$TrustLevel,
          
          # Allow for a filename to be specific which we can call later.
          [parameter(Mandatory=$True)]
          [ValidateSet('CurrentUser', 'LocalMachine')]
          [String]$CertStoreLocation,

          # Quiet the "SIGNING SUCCESSFUL" message
          [parameter(Mandatory=$false)]
          [Switch]$QuietMode
      )


      ######################################################################################################################################################################
      #region   VARIABLES AND VERIFICATIONS   ##############################################################################################################################
      ######################################################################################################################################################################

          # Capture the correct certificate thumbprint (the hash of the entire cert itself) based on the option selected
          if($TrustLevel -eq "Low")
          {
              $thumbprint = 'EXAMPLE_HERE'
          }

          if($TrustLevel -eq "High")
          {
              $thumbprint = 'EXAMPLE_HERE'
          }

          # Verify that the script can access the cert by its thumbprint (meaning THAT SPECIFIC CERT) and that we have the corresponding private key to that cert as well
          # To explain a bit more, if $thumbprint doesn't match above then the IF will eval to false. Also, since we're looking at "HasPrivateKey", it must = true if we have it.
          # If the value for HasPrivateKey then the overall statement will eval to false.
          if((Get-ChildItem Cert:\$CertStoreLocation\My | Where-Object {$_.Thumbprint -eq "$thumbprint"}).HasPrivateKey)
          {
              # Select the right cert to sign the file with
              $cert = Get-ChildItem cert:\$CertStoreLocation\My -codesigning | Where-Object {$_.Thumbprint -eq "$thumbprint"}

          } Else {

              Write-Host "You either do not have the needed $TrustLevel Trust cert or if you do, you do not have the private key for it." -ForegroundColor Red

              Exit
          }

      #endregion VARIABLES AND VERIFICATIONS 


      ######################################################################################################################################################################
      #region   SIGN FILE   ################################################################################################################################################
      ######################################################################################################################################################################

          # Sign the file with the corporate signing certificate and also reach out to Verisign to have them timestamp it as well until we get our own PKI.
          # The reason why we need to timestamp the code as well is that, among many other reasons, even if the signing cert/CA expires, the code still runs and is considered valid.
          # REF (Public Timestamping Servers): https://gist.github.com/Manouchehri/fd754e402d98430243455713efada710
          try {

              Set-AuthenticodeSignature -FilePath $File -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.globalsign.com/?signature=sha2" -Force -ErrorVariable certError | Out-Null

          } Catch {

              Write-Error "Signing Error: $certError"
          }

      #endregion SIGN FILE


      ######################################################################################################################################################################
      #region   VERIFY SIGNED FILE   #######################################################################################################################################
      ######################################################################################################################################################################

          # Check that the file has a timestamp signature applied
          if( -not (Get-AuthenticodeSignature -FilePath $File).TimeStamperCertificate)
          {
              Write-Host "WARNING: Unable to aquire timestamp signature. File may be correctly signed with the corporate cert and work but it's not optimal. Fix this!" -ForegroundColor Yellow
          }

          # Ensure that the cert was signed properly: Valid status and correct SignerCertificate (signing cert thumbprint)
          if(((Get-AuthenticodeSignature -FilePath $File).Status -eq "Valid")   -and   ((Get-AuthenticodeSignature -FilePath $File).SignerCertificate.Thumbprint -eq "$thumbprint"))
          {
              if(!$QuietMode)
              {
                  Write-Host "File(s) successfully signed" -ForegroundColor Green
              }

          } Else {

              # Collect Details
              $fileSignedStatus = (Get-AuthenticodeSignature -FilePath $File -ErrorAction SilentlyContinue).Status
              $fileStatusMessage = (Get-AuthenticodeSignature -FilePath $File -ErrorAction SilentlyContinue).StatusMessage
              $certSigningCertificate = ((Get-AuthenticodeSignature -FilePath $File -ErrorAction SilentlyContinue).SignerCertificate).Subject
              $timeStamperCertificateSubject = (Get-AuthenticodeSignature -FilePath $File -ErrorAction SilentlyContinue).TimeStamperCertificate.Subject
              $certErrorMessage = $certError.Message

              Write-Host "

              ErrorMessage = $certErrorMessage
              
              Additional Details:
              -------------------
              fileSignedStatus = $fileSignedStatus
              fileStatusMessage = $fileStatusMessage
              certSigningCertificate = $certSigningCertificate
              timeStamperCertificateSubject = $timeStamperCertificateSubject        
              "
              Exit
          }

      #endregion VERIFY SIGNED FILE
    }




    function Confirm-Authenticode
    {
      <#
          .SYNOPSIS
            Verifies the integrity of internal PowerShell scripts


          .DESCRIPTION
            Helps to ensure that PowerShell scripts haven't been tampered with by validating that they 
            are not only signed but signed by the expected certificated (i.e. cert pinning)


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          1-August-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .EXAMPLE
            Confirm-Authenticode -FilePath "C:\Path\example.psm1" -Thumbprint 3a9e16b8c2d1f24e8a5b9c7d02e456b3d8f27c41

      #>

      #region  DEFINE PARAMETERS  ##########################################################################################################################################
          
          Param
          (
              [parameter(Mandatory=$true)]
              [System.IO.FileInfo]$FilePath,

              [parameter(Mandatory=$true)]
              [String]$Thumbprint
          )

      #endregion DEFINE PARAMETERS


      #region  CONFIRM AUTHENTICODE  #######################################################################################################################################

          # Confirm if file exists
          if(Test-Path -Path $FilePath)
          {
              # Define Signature Variables for Later Validation
              $Global:fileSignatureStatus = (Get-AuthenticodeSignature -FilePath $FilePath).Status.ToString()
              $Global:fileSignatureThumbprint = ((Get-AuthenticodeSignature -FilePath $FilePath).SignerCertificate).Thumbprint

              # Clear variable prior to setting it again for added security. If something happens and it's not set again, it may pre-exist from another run.
              Remove-Variable signatureVerified

              # Certificate validation and pinning check: Check that the file has a valid digital signature AND that it has the correct thumbprint for the specific certificate you want.
              if(($fileSignatureStatus -eq "Valid") -and ($fileSignatureThumbprint -eq "$Thumbprint"))
              {
                  $Global:signatureVerified = $True

              } else {

                  Write-Error "Signature failed for file $FilePath. DETAILS: fileSignatureStatus=$fileSignatureStatus fileSignatureThumbprint=$fileSignatureThumbprint"
                  $Global:signatureVerified = $False
              }

          } Else {

              Write-Error "Check the file path. The path specified does not exist."
          }

      #endregion CONFIRM AUTHENTICODE
    }




    function Invoke-AESEncryption
    {
      <#
          .SYNOPSIS
            Encryptes or Decrypts Strings or Files with AES256. 

              CREDIT: All Credit for the original implimentation goes to David Retzer (DR Tools)
              REF: https://www.powershellgallery.com/packages/DRTools/4.0.3.4/Content/Functions%5CInvoke-AESEncryption.ps1
              NOTES: TenderLovinSnare modified a few sections below for added security such as padding changes, adding PBKDF2 for key hashing
                    among many others. As ALWAYS, bug fix suggestions are always fine.


          .DESCRIPTION
            Takes a String or File and a Key and encrypts or decrypts it with AES256 (CBC) using PBKDF2 with HMAC-SHA-256 for key derivation.


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            Credit:                 Mixed: Major re-write by TenderLovinSnare but original credit again goes back to David Retzer (DR Tools)
            Major Release Name:     Tender Lovin' Snare
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        PROD
            █ Version:              1.0
            █ Last Update:          27-October-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .PARAMETER Mode
            Encryption or Decryption Mode


          .PARAMETER EnvVariableKeyName
            Specify variable name that contains the key you want to pass to this function. This is used in automation where you'd have
            another process to extract an encrypted string into a plaintext variable by whatever name you want. In this manner you can 
            just have the script use that variable as the encryption/decryption key. You can use whatever valid variable name you want.

            ▶ NOTICE ◀
            *DO NOT* use $ENV:varName, just use the name of the variable itself without ENV: - so just 'varName'. The ENV: is implied!


          .PARAMETER String
            String value to encrypt or decrypt


          .PARAMETER Path
            Filepath for file to encrypt or decrypt


          .PARAMETER NumberOfIterations
            How many iterations the PBKDF2 will use to hash the hash. This helps by making it way more computationally expensive
            to try and brute force the password. However, if you're using a long complex password, less rounds are probably fine.


          .PARAMETER Quiet
            Just be quiet and do it. If only children came with this option sometimes.


          .PARAMETER Force
                🗸
            Just do it.


          .EXAMPLE
          
            STRINGS
            -------

              MANUAL
              ------
              $encryptedString = Invoke-AESEncryption -Mode Encrypt -String "my secret string" 
              Invoke-AESEncryption -Mode Decrypt -String $encryptedString


              AUTOMATED
              ---------
              $encryptedString = Invoke-AESEncryption -Mode Encrypt -String "my secret string" -EnvVariableKeyName nameOfEnvKeyWithSecretValue
              Invoke-AESEncryption -Mode Decrypt -String $encryptedString -EnvVariableKeyName nameOfEnvKeyWithSecretValue


            FILES
            -----

              MANUAL
              ------
              Invoke-AESEncryption -Mode Encrypt -Path fileName.csv
              Invoke-AESEncryption -Mode Decrypt -Path fileName.csv


              AUTOMATED
              ---------
              Invoke-AESEncryption -Mode Encrypt -Path fileName.csv -EnvVariableKeyName nameOfEnvKeyWithSecretValue
              Invoke-AESEncryption -Mode Decrypt -Path fileName.csv -EnvVariableKeyName nameOfEnvKeyWithSecretValue

      #>

      [CmdletBinding(SupportsShouldProcess)]
      [OutputType([string])]
      Param
      (
          [Parameter(Mandatory = $true)]
          [ValidateSet('Encrypt', 'Decrypt')]
          [String]$Mode,

          # Use environmental variables wherever possible!
          [Parameter(Mandatory = $false)]
          [String]$EnvVariableKeyName,

          # Ensure that this is mutually exclusive (can't be used with -Path)
          [Parameter(Mandatory = $true, ParameterSetName = "EncryptString")]
          [String]$String,

          # Ensure that this is mutually exclusive (can't be used with -String)
          [Parameter(Mandatory = $true, ParameterSetName = "EncryptFile")]
          [System.IO.FileInfo]$Path,

          # To make the number of PBKDF2 iterations not a problem to remember, constrain the number of iterations to the following options below
          # ITERATIONS      THE LABEL              DESCRIPTION
          # ----------      --------------------   -------------------------------------------------------------------------------------------------
          # 1               APATHY INTERNATIONAL   I don't care - speed is what matters. My password is so long/complex good luck cracking it anyway
          # 10,000          COMPLIANCE             I believe that compliance = security and I mean... at least we checked the box right?
          # 100,000         COMPLIANCE++           But we're doing more than the nebulous non-specific compliance rules state... right?
          # 600,000         BEST PRACTICE          Went with a standards-based number of iterations backed up by OWASP (600k as of 2024) for SHA256
          # 1,000,000       PARANOID               It just "feewls better" and hey... it's work that pays for compute anyway, not me!
          # 10,000,000      TAO IS AFTER YOU!      They're watchin' me man! They're watchin' me! They're talkin' to me through my fillin's!
          # 111,111,111     SPINAL TAP             Why not just make 10 the top number...   ponders it...   these go to 11"
          [Parameter(Mandatory = $false)]
          [ValidateSet(1, 10000, 100000, 600000, 1000000, 10000000, 111111111)]
          [Int32]$NumberOfIterations,

          [Parameter(Mandatory = $false)]
          [Switch]$Quiet,

          [Parameter(Mandatory = $false)]
          [Switch]$Force
      )

      Begin {

          # For automation, you need a way to pass a key to this function without having to manually type, and 100% expose, the key
          # at command line. Let's say you already have another process to securely populate a varable called $myKey with a value 
          # of "mySecret" in memory. Here, we simply tell Invoke-AESEncryption which variable has the secret key we want to use for 
          # encrypting and decrypting. Otherwise, just type a key manually at the command line via SecureString so it's not logged
          # with PowerShell logging or other tools. For a way to extract encrypted strings to variables, see Get-SimpleVaultSecret.
          if($EnvVariableKeyName)
          {
              # Ensure that the key exists because it's likely not "default" to have all your variables as an environmental variables
              if((Get-Item "Env:$EnvVariableKeyName").Value)
              {
                $ENV:InvokeAESEncryptionKey = (Get-Item "Env:$EnvVariableKeyName").Value

              } Else {

                  Write-Error "It looks like $ENV:EnvVariableKeyName doesn't exist or has no value."
                  Break
              }

          } Else {

              # Enter the key and mask it while typing to not have it logged. Such things are very naughty! Understand that we should use -AsSecureString
              # but we'd have to decrypt it anyway right afterwards so the below can actually you know... ready the real string to hashipitate it. Therefore,
              # will at least store it as an environmental variable for a very brief time being being flushed for added freshness. Also note that I don't know
              # of a way to NOT show the "*" when typing - I think it's kindof a PowerShell thing I can't change.
              $ENV:Key1 = Read-Host "Carefully enter the key (will not be displayed)" -MaskInput
              $ENV:Key2 = Read-Host "Carefully re-enter the key (will not be displayed)" -MaskInput

              # Compare the two to ensure they match
              if($ENV:Key1 -eq $ENV:Key2)
              {
                  # Define the common key var used throughout the rest of the script and remove the old ones
                  $ENV:InvokeAESEncryptionKey = $ENV:Key1
                  Remove-Item ENV:Key1 -Force
                  Remove-Item ENV:Key2 -Force

              } Else {

                  Write-Error "Was that a typo or just `"limited-edition spelling`"? Either way, they didn't match so try again!"
                  Break
              }
          }

          # Check the length of the key
          $keyLength = $ENV:InvokeAESEncryptionKey.Length

          # Break if key length is <12 characters unless -Force is used
          if(($keyLength -lt 12)   -and   (-not($Force)))
          {
              Write-Error "You specified a key length of $keyLength that is <12 characters. If you think this is fine, be sure to check out jobs.mchire.com. Otherwise, if you know what you're doing, use -Force"
              Break
          }

          # Initialize AES
          $aesManaged = New-Object System.Security.Cryptography.AesManaged
          $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
          $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
          $aesManaged.BlockSize = 128
          $aesManaged.KeySize = 256

          # Generate a random salt (16 bytes)
          $salt = New-Object byte[] 16
          [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)

          # Normally your password is hashed once with SHA1 or SHA256 and that hash is used in making the real AES key.
          # However, if someone puts in a stupid and easily guessable password like "racecar", it's easier/faster to crack
          # it by using a single round of SHA1 or SHA256. However, with PBKDF2 we hash the hash N number of times to get the 
          # resulting hash/key material to actually decrypt the target. This makes it WAY more computationally expensive to 
          # brute force password guessing. Don't let this be a crutch for making stupid passwords - ALWAYS use long/complex 
          # passwords!

          # Default to 600k iterations of PBKDF2 with HMAC-SHA-256 to get the REAL AES key from the key you supplied.
          # REF: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
          if(-Not $NumberOfIterations)
          {
              $iterations = 600000

          } Else {

              # Honor what the user supplied
              $iterations = $NumberOfIterations

              if((-Not $Quiet)   -and   ($Mode -eq "Encrypt"))
              {
                  Write-Warning "Please be sure to remember what number of iterations you chose ($NumberOfIterations). Otherwise, even with the correct key, decryption will fail!"
              }
          }

          # Use PBKDF2 with HMAC-SHA-256 to get the AES key from the user-supplied provided key. This is the ACTUAL AES key!
          $key_pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::New($ENV:InvokeAESEncryptionKey, $salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)

          # Get the 256-bit decryption key
          $aesManaged.Key = $key_pbkdf2.GetBytes(32)
      }

      Process {
          switch ($Mode) {
              'Encrypt' {
                  if ($String) {
                      $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($String)
                  }

                  if ($Path) {
                      $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                      if (-Not $File.FullName) {
                          Write-Error -Message "File not found!"
                          break
                      }
                      $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                      $outPath = $File.FullName + ".aes"
                  }

                  # Generate a random IV for AES encryption
                  $aesManaged.GenerateIV()
                  $encryptor = $aesManaged.CreateEncryptor()

                  # Encrypt the data
                  $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

                  # Prepend the salt and IV to the ciphertext for storage
                  $encryptedBytes = $salt + $aesManaged.IV + $encryptedBytes
                  $aesManaged.Dispose()

                  if ($String) {
                      Write-Output -InputObject ([System.Convert]::ToBase64String($encryptedBytes))
                  }

                  if ($Path) {
                      if ($PSCmdlet.ShouldProcess($outPath, "write encrypted file")) {
                          [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                          (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                      }
                      Write-Verbose -Message "File encrypted to $outPath"
                  }
              }

              'Decrypt' {
                  try {
                      if ($String) {
                          $cipherBytes = [System.Convert]::FromBase64String($String)
                      }

                      if ($Path) {
                          $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                          if (-Not $File.FullName) {
                              Write-Error -Message "File not found!"
                              break
                          }
                          $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                          $outPath = $File.FullName -replace ".aes"
                      }

                      # Ensure the ciphertext has a valid length for salt + IV + data
                      if ($cipherBytes.Length -lt 32) {
                          throw "Invalid ciphertext. The length is too short to contain necessary salt and IV."
                      }

                      # Extract the salt and IV from the ciphertext
                      $salt = $cipherBytes[0..15]
                      $iv = $cipherBytes[16..31]

                      # Derive the AES key again using PBKDF2 with the extracted salt
                      $key_pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::New($ENV:InvokeAESEncryptionKey, $salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
                      $aesManaged.Key = $key_pbkdf2.GetBytes(32)
                      $aesManaged.IV = $iv

                      # Decrypt the data
                      $decryptor = $aesManaged.CreateDecryptor()
                      $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 32, $cipherBytes.Length - 32)
                      $aesManaged.Dispose()

                      if ($String) {
                          Write-Output -InputObject ([System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0))
                      }

                      if ($Path) {
                          if ($PSCmdlet.ShouldProcess($outPath, "write decrypted file")) {
                              [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                              (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                          }
                          Write-Verbose -Message "File decrypted to $outPath"
                      }
                  }
                  catch {

                      # Gracefully handle decryption errors
                      Write-Error "DECRYPTION FAILED! Check the key and/or number of iterations. Insert coins to continue >:) $_"
                  }
              }
          }
      }

      End {
          
          # Uhg, it's Wednesday again, don't want to forget to take out the trash
          $aesManaged.Dispose()
          Remove-Item ENV:InvokeAESEncryptionKey -Force
      }
    }




    function Get-StringHash
    {
        <#
            .SYNOPSIS
              Outputs a certain type of hash for a given string        


            .DESCRIPTION
              Living off the land, this function makes it easier to get a hash for a given string. This function provides the ability to hash
              based on SHA256, SHA512 or PBKDF2 and provides some basic configuration options where needed.


            .NOTES
              Project:                Backstop Flexibility Framework (BFF)
              Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
              Copyright:              ©TenderLovinSnare
              Contact:                TenderLovinSnare@gmail.com
              License:                MIT (https://opensource.org/license/mit)
              █ Last Updated By:      TenderLovinSnare
              █ Release Stage:        BETA
              █ Version:              0.2
              █ Last Update:          21-December-2024
              █ RELEASE NOTES:
              ↪ Alpha Release


            .PARAMETER String
              This is the textual string that you want to hash


            .PARAMETER HashType
              The type of hash you want. While SHA256 and SHA512 are fairly obvious, PBKDF2 (Password-Based Key Derivation Function 2) is an
              algorithm to derive a secure cryptographic key from a string. It incorporates a salt (in order to prevent rainbow table attacks) 
              and iterates the hashing process multiple times in order to make brute-force attacks more difficult thus enhancing the security 
              of stored text or passwords or otherwise generating encryption keys from user input.


            .PARAMETER PBKDF2Iterations
              How many times you want to "hash the hash". The more you iterations, the more computationally expensive to perform the function.
              By default, since we're using SHA512, we'll use 210,000 iterations per OWASP.
              REF: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2


            .PARAMETER PBKDF2Salt
              It's critical (mandatory) to add salt into the mix to prevent rainbow table attacks.


            .EXAMPLE
              Get-StringHash -String "Test String" -HashType SHA256

        #>


        # Define script parameters
        Param
        (
            [parameter(Mandatory=$True)]
            [AllowEmptyString()] # Did this or purpose for better messaging below vs. boring error of nag
            [String]$String,

            [parameter(Mandatory=$True)]
            [ValidateSet('SHA256', 'SHA512', 'PBKDF2')]
            [String]$HashType,

            # To make the number of PBKDF2 iterations less of a problem to remember, constrain the number of iterations to the following options below.
            # Without doing this, you'd have to remember how many iterations you used and if you're off even by one, the hashes won't match.

            # ITERATIONS      THE LABEL              DESCRIPTION
            # ----------      --------------------   -------------------------------------------------------------------------------------------------
            # 1               APATHY INTERNATIONAL   I don't care - speed is what matters. My password is so long/complex good luck cracking it anyway
            # 10,000          COMPLIANCE             I believe that compliance = security and I mean... at least we checked the box right?
            # 100,000         COMPLIANCE++           But we're doing more than the nebulous non-specific compliance rules state... right?
            # 600,000         BEST PRACTICE          Went with a standards-based number of iterations backed up by OWASP (600k as of 2024) for SHA256
            # 1,000,000       PARANOID               It just "feewls better" and hey... it's work that pays for compute anyway, not me!
            # 10,000,000      TAO IS AFTER YOU!      They're watchin' me man! They're watchin' me! They're talkin' to me through my fillin's!
            # 111,111,111     SPINAL TAP             Why not just make 10 the top number...   ponders it...   these go to 11"
            [Parameter(Mandatory = $false)]
            [ValidateSet(1, 10000, 100000, 600000, 1000000, 10000000, 111111111)]
            [Int32]$PBKDF2Iterations,
            
            [parameter(Mandatory=$False)]
            [String]$PBKDF2Salt,

            [parameter(Mandatory=$False)]
            [Switch]$Quiet
        )

        # Warn if params for PBKDF2 specified with a SHA-like hash
        if(($HashType -match "SHA")   -and   ($PBKDF2Iterations -or $PBKDF2Salt))
        {
            Write-Warning -Message "No need to use either -PBKDF2Iterations or -PBKDF2Salt when specifying a SHA256 or SHA512 HashType"
        }

        # Output either a SHA256 or SHA512 hash for a given string
        if($HashType -match "SHA256|SHA512")
        {
            # If the string is NOT null (blank), process it. Else, warn unless told to be quiet.
            if($String -ne $null)
            {
                # Convert the string to a binary stream
                $stringByteStream = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($String))

                # Convert the byte stream of the string to a hash
                $stringHash = (Get-FileHash -InputStream $stringByteStream -Algorithm $HashType).Hash

                # Close out the bytestream
                $stringByteStream.Close()

                # Output the hash
                $stringHash

            } Else {

                Write-Error "IFYKYK: Your string was EMPTY so this is kinda pointless! Why? Well because things that are not can't be! Why? Because then nothing wouldn't be, you can't have nothing isn't! Everything is! Why? Because if nothing wasn't there would be all kinds of stuff because like giant ants with tophats dancing around there's no room for all that stuff. Why? OHHH JUST SHUT UP AND EAT YOUR FRENCH FRIES!!!"
            }

        # Output a PBKDF2 hash for a given string
        } elseif($HashType -match "PBKDF2"){

            if(-Not $PBKDF2Salt)
            {
                Write-Error "You must use -PBKDF2Salt and specify a salt. Salt appears to be null - check it."
                break
            }

            # Default to N number of hash iterations consistent with OWASP if not specified otherwise by -PBKDF2Iterations
            if(-Not $PBKDF2Iterations)
            {
                # This is how many iterations the string is hashed in order to increase the computational power it takes to crack it.
                # REF: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2  (SHA256 used so 600,000)
                $PBKDF2Iterations = 600000
            }

            # If the string is NOT null (blank), process it. Else, warn unless told to be quiet. In this case, a blank would be if someone used double quotes (why... I don't know but handle it!)
            if($String -ne $null)
            {
                # For a 256-bit key, divided by 8 to convert bits to bytes. Makes it easier to read from a bit perspective.
                $keyLength = 256 / 8

                # Use the salt specified in -PBKDF2Salt. This converts the salt string to bytes which is what's needed
                $PBKDF2SaltBytes = [System.Text.Encoding]::UTF8.GetBytes($PBKDF2Salt)

                # Create an Rfc2898DeriveBytes object. To ensure that SHA256 is being used for PBKDF2, check $pbkdf2.HashAlgorithm
                $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($String, $PBKDF2SaltBytes, $PBKDF2Iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)

                # Get the bytes for the key
                $key = $pbkdf2.GetBytes($keyLength)

                # Convert the key to a readable base64 string. Also ensure it's a string type or it will cause issues removing below
                [string]$pbkdf2Base64Hash = [Convert]::ToBase64String($key)

                # Output the key
                return $pbkdf2Base64Hash

                # Securely overwrite the variable(s) and then remove. PowerShell may only dereference var in memory with Remove-Variable so being safe.
                $String = $(Get-RandomString -Length 1024); Remove-Variable -Name String -Force
                $PBKDF2Salt = $(Get-RandomString -Length 1024); Remove-Variable -Name PBKDF2Salt -Force
                $pbkdf2 = $(Get-RandomString -Length 1024); Remove-Variable -Name pbkdf2 -Force
                $key = $(Get-RandomString -Length 1024); Remove-Variable -Name key -Force
                $pbkdf2Base64Hash = $(Get-RandomString -Length 1024); Remove-Variable -Name pbkdf2Base64Hash -Force
                [string]$PBKDF2Iterations = $(Get-RandomString -Length 1024); Remove-Variable -Name PBKDF2Iterations -Force

            } Else {

                if(-NOT $Quiet)
                {
                    Write-Warning "Kinda need a string to hash here. Please don't bother signing up for that Mensa meeting. Insert coins to continue..."
                }
            }
        }
    }




    function Get-RandomString
    {
        <#
            .SYNOPSIS
              Via the .NET RandomNumberGenerator class, create a random string for passwords, etc. that you can capture as a variable for use elsewhere.
              The RandomNumberGenerator class replaces the legacy RNGCryptoServiceProvider class.

            .NOTES
              Project:                Backstop Flexibility Framework (BFF)
              Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
              Copyright:              © 2024 TenderLovinSnare (Unless Otherwise Noted)
              Contact:                TenderLovinSnare@gmail.com
              License:                MIT (https://opensource.org/license/mit)
              █ Last Updated By:      TenderLovinSnare
              █ Release Stage:        BETA
              █ Version:              0.2
              █ Last Update:          22-December-2024
              █ RELEASE NOTES:
              ↪ Alpha Release


            .PARAMETER Length
              Specify the length of the string. Default is 15 characters with an insane max of 9999


            .PARAMETER Base64
              Converts the output to a Base64 string.


            .PARAMETER BasicCharacterSet
              Uses a basic alphanumeric character set. This should NOT be used for secrets/passwords. Use for session ID's or elsewhere where
              security isn't the principle concern but just having a decent chance of uniqueness.


            .EXAMPLE
              # Creates a new random string with a default of 15 characters. NOTE: This is spit out at commandline so BE CAREFUL with this!
              # Remember PowerShell logging may certainly be enabled and will record the string.
              
              PS> Get-RandomString

        #>


        param (

            # If desired, specify how many characters are needed but also ensure that minimum is 15 by default if nothing else is picked.
            # Also, prohibit people from making the Length something stupid like 8 charcters. OWASP standard last I checked was 12.
            [parameter(Mandatory=$false)]
            [ValidateRange(8, 9999)]
            [int]$Length = 15,

            # Output random string as base64 
            [parameter(Mandatory=$false)]
            [Switch]$Base64,

            # Generate a basic alpha-numeric string
            [parameter(Mandatory=$false)]
            [Switch]$BasicCharacterSet,

            # Generates just a number at the given length specified (or the default)
            [parameter(Mandatory=$false)]
            [Switch]$NumberOnly

        )


        # Create blank array
        $characterArray = @()

        # Set the character sets based on option selected. Default is almost the full set of characters but if basic alphanumic is needed, use those instead.
        if($BasicCharacterSet)
        {
            # Loop through the ASCII codes for alphanumeric characters
            for ($i = 48; $i -le 122; $i++) {
              
              # Add only numbers (48-57), uppercase letters (65-90), and lowercase letters (97-122)
              if (($i -ge 48 -and $i -le 57) -or ($i -ge 65 -and $i -le 90) -or ($i -ge 97 -and $i -le 122)) {
                  $characterArray += [char]$i
              }
            }

        } Elseif ($NumberOnly) {

            # Loop through the ASCII codes for numbers only
            for ($i = 48; $i -le 57; $i++) {
              $characterArray += [char]$i
            }

        } Else {

            # Define the set of characters to use in making the random string itself. Note that this will use the almost full set of ASCII printable characters
            # here by calling out ASCII character codes 33 through 126. Note that if you need to go with a less complex password, just modify my code. Also, skip
            # ASCII code 32 (space - so starts at 33 vs. 32) and 39 (single quote) to make it easier to deal with. Other than this, use any other character.
            # REF: https://www.ascii-code.com/
            for ($i = 33; $i -le 126; $i++) {

                # Skip single quote but use anything else
                if ($i -ne 39){
                    $characterArray += [char]$i
                }
            }
        }

        # Create initial blank string variable
        $randomString = ""

        # Initialize the CRNG
        $randomNumberGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()

        # Iterate through the length selected to get a random string
        for ($i = 0; $i -lt $Length; $i++) {

          # Generate a single random byte
          $randomByte = [byte[]]::new(1)
          $randomNumberGenerator.GetBytes($randomByte)

          # Map the random byte to an index in the character array
          $index = $randomByte[0] % $characterArray.Length
          $randomString += $characterArray[$index]
        }

        # Flush the cryptoProvider and give the string back to the user
        $randomNumberGenerator.Dispose()

        # Convert to Base64 if called, else return normal random string
        if($Base64)
        {
          $randomStringBytes = [System.Text.Encoding]::UTF8.GetBytes($randomString)
          $randomString = [System.Convert]::ToBase64String($randomStringBytes)
          return $randomString

        } Else {
          
          return $randomString
        }

        # Securely overwrite the variable(s) and then remove. PowerShell may only dereference var in memory with Remove-Variable so being safe.
        $randomString = $(Get-RandomString -Length 1024); Remove-Variable -Name randomString -Force
    }




    function New-SimpleVault
    {
      <#
          .SYNOPSIS
            Creates a simple JSON secrets vault if you don't already have one. When you invoke this, it will create the vault
            on disk (or warn if a file already exists there). Note that you'll need to use the Open-Vault to read it into memory 
            and once in memory, use the other functions below to manipulate the vault such as adding or removing named secrets. 
            The vault is mainly for local, non-domain accounts.


          .DESCRIPTION
            This is a simple user/machine-specific "vault" for service accounts in a simple key/value JSON format store. The
            JSON vault is easily readable and keys are easily retrievable based on a friendly key name. You can store as many
            keys in the vault as you want BUT there is a trade-off which is generally ok for smaller applications. Since we 
            are using the DPAPI functionality (which takes care of the complexities of key management for us), you need to be 
            logged in as the user (typically a service account) on the same machine which are you going to use the secrets. 
            For example, you want to ensure that you're NOT stupidly putting API keys into a scripts since they'd be plaintext
            and, depending on the DACL/access, could be easily compromised. You need to run-as pwsh as the service account which
            will be running this code.
    
            Simple Vault is meant for local user (non-domain) service accounts on the same machine. It's purpose is to secure secrets
            via DPAPI. Instead of putting secrets (i.e. API keys, passwords, etc.) directly and stupidly in your scripts in plaintext,
            these functions allow you to easily and with a fair amount of security, store your secrets in an easy to manipulate JSON
            "Vault" file. To have your scripts get the secrets they need (after creating the vault), you simply have the script open
            the vault with the Open-SimpleVault cmdlet and then get the secret by a friendly name with Get-SimpleVaultSecret command.
            If you have no idea what you're doing, start with New-SimpleVault first to create it. 


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        PROD
            █ Version:              1.0
            █ Last Update:          25-October-2024
            █ RELEASE NOTES:
            ↪ Alpha Release

            RELEASE NOTES
            -------------
            - 1.0 Alpha Release


          .PARAMETER Path
            Path to the vault which you want to create


          .PARAMETER Force
                🗸
            Just do it.


          .EXAMPLE
            PS> New-SimpleVault -Path "C:\Path\to\your\vault.json"

      #>


      param(
          [Parameter(Mandatory=$True)]
          [System.IO.FileInfo]$VaultPath,
          
          [Parameter(Mandatory=$false)]
          [Switch]$Force
      )

      if(-Not($Force))
      {
          # Advise the admin that they need to be running as the user which intends to use the creds
          Write-Host "
          READ, UNDERSTAND AND ACKNOWLEDGE:
          ---------------------------------

          1.  You are currently logged in as "$env:USERDOMAIN\$env:USERNAME". In order to add decryptable secrets to the 
              vault, you must be logged in as the user/service account which will be using them. If this is not the case
              then simply open another pwsh session as the service account and run this command again.

          2.  You should only use domain accounts as the service account IF AND ONLY IF you need access to domain resources.
              If you fully trust AD, you are a fool and probably just don't know it. Use local accounts wherever possible or
              if you must use a domain account, at least try to use a GMSA (auto-rotates password for you). There are more 
              security risks to using domain accounts as the DPAPI keys can/are backed up in AD and can be recovered if the 
              domain is compromised.

          3.  If you force-reset a password (Example: Computer Management > Users > Right Click > Set Password) for an account
              that uses this vault, then all your secrets will become undecryptable. When rotating a password, do the normal 
              reset process and login as that user, reset their password that way. Basically, if you have to enter your old 
              password to rotate to a new one, you're good. If you force reset it in any manner without entering the old password
              then you're screwed.

          4.  For local accounts, this vault is non-portable. It must be used with the same credentials on the same machine which
              is generally ok for smaller applications. This function seeks to only be `"good enough`".

          5.  Ensure you have a backup of your secrets in a secure password manager (sigh... no, not LastPass either). DO NOT be
              a shining example of apathetic incompetence by not backing up your secrets or, unforgivably worse, storing your 
              secrets in other non-encrypted formats like scripts, text files or spreadsheets.

          " -ForegroundColor Yellow

          $acknowledgment = Read-Host -Prompt "If you've read and understand the above, type `"UNDERSTOOD`""
      }

      # Warn if path exists already
      if((Test-Path -Path $VaultPath)   -and   (-not($Force)))
      {
          $userFeedback = Read-Host -Prompt "WARNING: The path you specified already exists. Type 'OVERWRITE' to overwrite it. Else CTRL+C to quit."
      }

      # If userFeedback doesn't exist (no existing file) or they typed "OVERWRITE" AND they answered 'UNDERSTOOD', create the vault. If they just forced it, just do it.
      if(((-Not($userFeedback))   -or   ($userFeedback -eq "OVERWRITE"))   -and   ($acknowledgment -eq "UNDERSTOOD")   -or   ($Force))
      {
          # Create the Metadata hash table which will help us determine when it was created, on which machine and for which user
          $Metadata = [Ordered]@{
              "ForMachineName" = "$env:COMPUTERNAME"
              "ForUser" = "$env:USERDOMAIN\$env:USERNAME"
              "CreationDateInUTC" = "$((get-date -AsUTC).ToString())"
              "Description" = "This vault uses DPAPI and it will only work with the user on the machine specified below. If you need to move the vault to another machine, you'll need to re-create it again. Also, if you see [Domain]\COMPUTERNAME$ it indicates that the SYSTEM account was used."
          }

          # Create an initial blank secrets hash table
          $Secrets = @{}

          # Create the parent hash table
          $Vault = [Ordered]@{
              "Metadata" = $Metadata
              "Secrets" = $Secrets
          }

          # Export the vault to disk. Note that it will be blank until the Save-SimpleVault function is used.
          $Vault | ConvertTo-Json | Out-File "$VaultPath"

      } Else {

          Write-Host "Maybe try typing that again? Insert coins to continue."; Break
      }
    }




    function Open-SimpleVault
    {
      <#
          .SYNOPSIS
            Opens the vault in for use or to manipulate.        


          .DESCRIPTION
            This is used to open the vault in memory in order to add or remove objects


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        BETA
            █ Version:              0.2
            █ Last Update:          20-July-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .PARAMETER Path
            Path to the vault which you want to open


          .EXAMPLE
            PS> Open-SimpleVault -Path "C:\Path\to\your\vault.json"
          
      #>


      param(
          [Parameter(Mandatory=$True)]
          [string]$VaultPath
      )

      # Do some basic verifications when opening the vault
      if((Test-Path $VaultPath)   -and   (Get-Content $VaultPath -Raw | Test-Json))
      {
          # Convert the hashtable to JSON and save it to a file
          $Global:Vault = Get-Content -Path $VaultPath | ConvertFrom-Json
          $Global:VaultPath = $VaultPath

          # Gather important details to determine if you're even able to get the keys
          $currentRunningUser = "$env:USERDOMAIN\$env:USERNAME"
          $vaultForUser = $vault.Metadata.ForUser
          $vaultForMachine = $vault.Metadata.ForMachineName

          # Error if you aren't running with the right user on the right machine
          if(($currentRunningUser -ne $vaultForUser)   -or   ($env:COMPUTERNAME -ne $vaultForMachine))
          {
              Write-Error "Vault requires you to be running from the context of user $vaultForUser on endpoint $vaultForMachine.
                  However, you're running as $currentRunningUser on machine $env:COMPUTERNAME. Please run from correct user and machine."

              #Break
          }

      } Else {

          Write-Error "The file path specified doesn't exist or it's not a valid JSON file. To create a new vault use New-SimpleVault."
      }
    }




    function Add-SimpleVaultSecret
    {
      <#
          .SYNOPSIS
            Function to add a secret to the vault


          .DESCRIPTION
            Add secrets by name to the vault and saves the vault file on disk


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        PROD
            █ Version:              1.0
            █ Last Update:          23-October-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .PARAMETER Name
            Specify the friendly name of the secret.


          .PARAMETER EnvVariableKeyName
            Specify variable name that contains the key you want to pass to this function. This is used in automation where you'd have
            another process to extract an encrypted string into a plaintext variable by whatever name you want. In this manner you can 
            just have the script use that variable as the encryption/decryption key. You can use whatever valid variable name you want.


          .PARAMETER NoAutoSave
            Use this if you want to add items in memory but not save it to disk. If you want to save it to disk
            afterwards, simply use the Save-SimpleVault command.


          .PARAMETER Force
                🗸
            Just do it.


          .PARAMETER Update
            Replaces the secret for the given name


          .PARAMETER Quiet
            Supresses certain nagging messages


          .EXAMPLE
            PS> Add-SimpleVaultSecret -Name "WhateverKeyNameYouWant"

      #>


      param(
          [Parameter(Mandatory=$True)]
          [string]$Name,

          [Parameter(Mandatory=$False)]
          [String]$EnvVariableKeyName,

          [Parameter(Mandatory=$False)]
          [Switch]$Update,
          
          [Parameter(Mandatory=$False)]
          [Switch]$NoAutoSave,

          [Parameter(Mandatory=$False)]
          [Switch]$Force,
          
          [Parameter(Mandatory=$False)]
          [Switch]$Quiet
      )

        if($Vault)
        {
            # Ensure the key name isn't already in use or if -Update is used, overwrite it of it does.
            if(($vault.Secrets.PSObject.Properties.Name -notcontains $Name)   -or   ($Update))
            {
                # For automation, you need a way to pass a key to this function without having to manually type, and 100% expose, the key
                # at command line. Let's say you already have another process to securely populate a varable called $ENV:myKey with a value 
                # of "mySecretKey" in memory. Here, we simply tell Invoke-AESEncryption which variable has the secret we want to use for 
                # encrypting and decrypting. Otherwise, just type a key manually at the command line via SecureString so it's not logged
                # with PowerShell logging or other tools. For a way to extract encrypted strings to variables, see Get-SimpleVaultSecret.
                if($EnvVariableKeyName)
                {
                    $secureString = (Get-Item Env:\$EnvVariableKeyName).Value | ConvertTo-SecureString -AsPlainText -Force

                } Else {

                    # Use Read-Host so ensure that the plaintext secret isn't recorded in PowerShell logging
                    $secureString = Read-Host -Prompt "Type the secret you want to protect for $name. TYPE CAREFULLY!" -AsSecureString
                }

                # See how long the secret is (clearly not a complexity check)
                $secretLength = $secureString.Length

                if($secretLength -eq 0)
                {
                    Write-Error "Either you actually type something for a secret or our relationship status changes to `"It's Complicated`""
                    Break
                }

                # Berate and break if secret is <8 characters unless -Force is used
                if(($secretLength -lt 12)   -and   (-not($Force)))
                {
                    Write-Error "You specified a key length of $keyLength that is <12 characters. If you think this is fine, be sure to check out jobs.mchire.com. Otherwise, if you know what you're doing, use -Force"
                    Break
                }

                # Convert the secureString in memory an encrypted Secure-String that we can write to the vault
                $encryptedSecureString = $secureString | ConvertFrom-SecureString

                # Securely overwrite the variable(s) and then remove. PowerShell may only dereference var in memory with Remove-Variable so being safe.
                $secureString = $(Get-RandomString -Length 1024); Remove-Variable -Name secureString -Force
                $secretLength = $(Get-RandomString -Length 1024); Remove-Variable -Name secretLength -Force
                
                # Ensure that the encryptedSecureString is > 292 bytes long: Basically <12 characters
                if(($encryptedSecureString.Length -lt 256)   -and   (-Not $Quiet))
                {
                    Write-Error "The encrypted form of the secret is somehow less than the minimum byte length of 256. Somehow, something went wrong and may be in plaintext. Stopping prior to writing to modifying the vault or writing to disk."
                    Break
                }

                # Add secret to the vault or update it if -Update was called
                $vault.Secrets | Add-Member -MemberType NoteProperty -Name "$name" -Value "$encryptedSecureString" -Force

                # Save to disk unless -NoAutoSave was specified
                if(-Not($NoAutoSave))
                {
                    $Vault | ConvertTo-Json | Out-File -Path "$VaultPath"
                }

            } Else {

                Write-Error "Name is already in the vault. Please pick a different name, use -Update with this command or just use Remove-SimpleVaultSecret -Name $Name"
            }

        } Else {

            Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet?"
        }
    }




    function Remove-SimpleVaultSecret
    {
      <#
          .SYNOPSIS
            Function to remove a secret from the vault


          .DESCRIPTION
            Removes a secret from the vault by the friendly name specified in -Name. Also, it saves the vault file on disk


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        BETA
            █ Version:              0.2
            █ Last Update:          20-July-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .PARAMETER Name
            Specify the friendly name of the secret you want to remove from the vault.


          .EXAMPLE
            PS> Remove-SimpleVaultSecret -Name "FriendlyKeyName"

      #>


      param(
          [Parameter(Mandatory=$True)]    
          [string]$Name,
          [Switch]$NoAutoSave
      )

      if($Vault)
      {
          # Annoyingly, there's no Remove-Member so need to do it this way
          $vault.Secrets.PSObject.Properties.Remove($Name)

          # Save to disk unless -NoAutoSave was specified
          if(-Not($NoAutoSave))
          {
              $Vault | ConvertTo-Json | Out-File -Path "$VaultPath"
          }

      } Else {

          Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet?"
      }
    }




    function Get-SimpleVaultNames
    {
      <#
          .SYNOPSIS
            Just gets the friendly names of the secrets in the vault


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        BETA
            █ Version:              0.2
            █ Last Update:          20-July-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .PARAMETER Name
            Specify the friendly name of the secret you want to remove from the vault.


          .EXAMPLE
            PS> Get-SimpleVaultNames -Name "FriendlyKeyName"

      #>


      if($Vault)
      {
          $Vault.Secrets.PSObject.Properties.Name

      } Else {

          Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet?"
      }
    }




    function Get-SimpleVaultDetails
    {
      <#
          .SYNOPSIS
            Retrieves the vault details in the metadata


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        BETA
            █ Version:              0.2
            █ Last Update:          20-July-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .EXAMPLE
            PS> Get-SimpleVaultDetails

      #>

      if($Vault)
      {
          $Vault.Metadata

      } Else {

          Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet?"
      }
    }




    function Get-SimpleVaultSecret
    {
        <#
            .SYNOPSIS
            Retrieves the plaintext secret from the vault to use in scripts, etc. and places them in an environmental variable called 
            $varName_vaultSecret where 'varName' is whatever the name for your secret is. For example, if you had a secret with the 
            name of 'foo' and a secret value of 'bar' , this will add $ENV:foo_vaultSecret to the environmental variables with a value
            of 'bar'. Simply call $ENV:foo_vaultSecret as the secret going forward. Obvisouly use something a bit longer for the secret.


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        PROD
            █ Version:              1.0
            █ Last Update:          25-October-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


            .PARAMETER Name
            Specify the friendly name of the secret. 


            .EXAMPLE
            PS> Get-SimpleVaultSecret -Name "FriendlyKeyName"

        #>


        param(
            [Parameter(Mandatory=$True)]    
            [string]$Name
        )


        if($Vault)
        {
            # Gather important details to determine if you're even able to get the keys
            # NOTE: The SYSTEM user isn't listed as "NT AUTHORITY\SYSTEM" as you may expect. It's [DOMAIN/WORKGROUP]\[COMPUTERNAME]$.
            $currentRunningUser = "$env:USERDOMAIN\$env:USERNAME"
            $vaultForUser = $vault.Metadata.ForUser
            $vaultForMachine = $vault.Metadata.ForMachineName

            # Error if you aren't running with the right user on the right machine (can't even decrypt the string anyway)
            if(($currentRunningUser -ne $vaultForUser)   -or   ($env:COMPUTERNAME -ne $vaultForMachine))
            {
                Write-Error "Vault requires you to be running from the context of user $vaultForUser on endpoint $vaultForMachine.
                    However, you're running as $currentRunningUser on machine $env:COMPUTERNAME. Please run from correct user and machine."

                Break
            }

            # If the specified name exists, get the secret
            if(($Vault.Secrets.PSObject.Properties | Where-Object {$_.Name -eq $Name}))
            {
                # Get the encrypted value of the Secure-String
                $encryptedSecureString = ($Vault.Secrets.PSObject.Properties | Where-Object {$_.Name -eq $Name}).Value

                # Convert that to a binary in-memory securestring
                $encryptedSecureString = $encryptedSecureString | ConvertTo-SecureString

                # Convert the encryptedSecureString variable back into plaintext via DPAPI
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encryptedSecureString)
                $plaintextSecureString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
               
                # Append _vaultSecret to the variable name
                $varName = "${name}_vaultSecret"

                # Set the environment variable dynamically with the modified name
                Set-Item -Path "Env:$varName" -Value $plaintextSecureString

                # Securely overwrite the variable and then remove it. PowerShell may only dereference the var with Remove-Variable so being safe.
                $plaintextSecureString = $(Get-RandomString -Length 1024); Remove-Variable -Name plaintextSecureString -Force
                
                # Ensure that we have something for the secret. Not really a good way to verify it other than it exists since it's arbitrary.
                if((Get-Item -Path "Env:$varName").Value)
                {
                    Write-Verbose "Populated Env:$varName as an environmental variable."

                } Else {

                    Write-Error "Unable to populate Env:$varName as an environmental variable."
                }

            } Else {

                Write-Error "The name of the key $name doesn't appear in the vault. Maybe you typed something wrong?"
            }
    
        } Else {

            Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet?"
        }
    }




    function Get-AllSimpleVaultSecrets
    {
        <#
            .SYNOPSIS
            With a single command, retrieves all of the plaintext secrets from the vault to use in scripts, etc. and places them in an
            environmental variable called $varName_vaultSecret where 'varName' is whatever the name for your secret is. This is basically
            the same as Get-SimpleVaultSecret but a one-liner to extract them all at the same time.
    
    
            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        PROD
            █ Version:              1.0
            █ Last Update:          25-October-2024
            █ RELEASE NOTES:
            ↪ Alpha Release
    
    
            .EXAMPLE
            PS> Get-SimpleVaultSecret -Name "FriendlyKeyName"
    
        #>
    
    
        if($Vault)
        {
            # Gather important details to determine if you're even able to get the keys
            # NOTE: The SYSTEM user isn't listed as "NT AUTHORITY\SYSTEM" as you may expect. It's [DOMAIN/WORKGROUP]\[COMPUTERNAME]$.
            $currentRunningUser = "$env:USERDOMAIN\$env:USERNAME"
            $vaultForUser = $vault.Metadata.ForUser
            $vaultForMachine = $vault.Metadata.ForMachineName
    
            # Error if you aren't running with the right user on the right machine (can't even decrypt the string anyway)
            if(($currentRunningUser -ne $vaultForUser)   -or   ($env:COMPUTERNAME -ne $vaultForMachine))
            {
                Write-Error "Vault requires you to be running from the context of user $vaultForUser on endpoint $vaultForMachine.
                    However, you're running as $currentRunningUser on machine $env:COMPUTERNAME. Please run from correct user and machine."
    
                Break
            }
    
            $VaultSecretNames = Get-SimpleVaultNames
            
            foreach($Name in $VaultSecretNames)
            {
                # If the specified name exists, get the secret
                if(($Vault.Secrets.PSObject.Properties | Where-Object {$_.Name -eq $Name}))
                {
                    # Get the encrypted value of the Secure-String
                    $encryptedSecureString = ($Vault.Secrets.PSObject.Properties | Where-Object {$_.Name -eq $Name}).Value
    
                    # Convert that to a binary in-memory securestring
                    $encryptedSecureString = $encryptedSecureString | ConvertTo-SecureString
    
                    # Convert the encryptedSecureString variable back into plaintext via DPAPI
                    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encryptedSecureString)
                    $plaintextSecureString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    
                    # Append _vaultSecret to the variable name
                    $varName = "${name}_vaultSecret"
    
                    # Set the environment variable dynamically with the modified name
                    Set-Item -Path "Env:$varName" -Value $plaintextSecureString
    
                    # Securely overwrite the variable(s) and then remove. PowerShell may only dereference var in memory with Remove-Variable so being safe.
                    $plaintextSecureString = $(Get-RandomString -Length 1024); Remove-Variable -Name plaintextSecureString -Force
    
                    # Ensure that we have something for the secret. Not really a good way to verify it other than it exists since it's arbitrary.
                    if((Get-Item -Path "Env:$varName").Value)
                    {
                        Write-Verbose "Populated Env:$varName as an environmental variable."
    
                    } Else {
    
                        Write-Error "Unable to populate Env:$varName as an environmental variable."
                    }
                }
            }
    
        } Else {
    
            Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet?"
        }
    }




    function Save-SimpleVault
    {
      <#
          .SYNOPSIS
            Saves the vault to the file on disk. This is only really used if you specified -NoAutoSave.


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        BETA
            █ Version:              0.2
            █ Last Update:          20-July-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .EXAMPLE
            PS> Save-SimpleVault

      #>


      if($Vault   -and   $VaultPath)
      {
          # Save the contents to disk
          $Vault | ConvertTo-Json | Out-File "$VaultPath"

      } Else {

          Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet? Also, ensure that `$VaultPath` variable is present and correct"
      }
    }




    function Write-Log
    {
      <#
          .SYNOPSIS
            Sends logging data to Splunk HEC and to a local log file.


          .DESCRIPTION
            Writes script logging to Splunk HEC in JSON format if asset has connectivity to the corporate network and also logs to a log file in Windows temp ($localLogFilePath)
            in JSON format as well.


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        BETA
            █ Version:              0.2
            █ Last Update:          31-July-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .PARAMETER eventTag
            The tag should be the major reagion of code you're in.


          .PARAMETER eventSubTag
            The subtag should be the minor reagion of code you're in.


          .PARAMETER severityLevel
            Entirly somewhat fully mostly follows syslog severity level standard keywords
            REF: https://en.wikipedia.org/wiki/Syslog#Severity_level


          .PARAMETER messages
            The log message or messages you'd like to send. If sending multiple message, group them in a hash table.


          .PARAMETER ClassificationLevel
            This is the classification level of the index to send to. Here we can default to classification levels C1 (default) to C2 or C3. This is totally up to you.


          .PARAMETER RedactNames
            This option redacts module names and script names for added obfuscational security.


          .PARAMETER Relay
            This option send the logs to the relay server to relay to Splunk HEC.


          .EXAMPLE
            Command: Write-Log -eventTag "Example Tag Name" -eventSubTag "Example SubTag Name" -severityLevel info -messages "Say something"

      #>


      #region  DEFINE PARAMETERS  ##########################################################################################################################################

          Param
          (
              [parameter(Mandatory=$true)]
              [String]$eventTag,

              [parameter(Mandatory=$true)]
              [String]$eventSubTag,
      
              [parameter(Mandatory=$true)]
              [ValidateSet('Debug', 'Info', 'Notice', 'Warn', 'Error', 'Critical', 'Test')]
              [String]$severityLevel,

              [parameter(Mandatory=$true)]
              [System.Object]$messages,

              [parameter(Mandatory=$false)]
              [System.IO.FileInfo]$CustomLocalLogPath,

              [parameter(Mandatory=$false)]
              [Switch]$WriteHost,

              [parameter(Mandatory=$false)]
              [Switch]$DoNotLogToLocalFile,

              [parameter(Mandatory=$false)]
              [Switch]$DoNotLogToSplunkHec,

              [Parameter(Mandatory = $false)]
              [ValidateSet('C2', 'C3')]
              [String]$ClassificationLevel,

              [parameter(Mandatory=$false)]
              [Switch]$RedactNames,

              [parameter(Mandatory=$false)]
              [Switch]$Relay
          )

      #endregion DEFINE PARAMETERS


      #region  LOG TO SPLUNK VIA HEC  ######################################################################################################################################

          # Determine index classification level (will overide what the variable above)
          if($ClassificationLevel -eq "C2"){$splunkIndex = $splunkIndexC2}
          if($ClassificationLevel -eq "C3"){$splunkIndex = $splunkIndexC3}

          # Redact script filenames
          if($RedactNames)
          {
              $moduleName = '[REDACTED]'
              $scriptName = '[REDACTED]'
          }

          # Only send to Splunk HEC if the -DoNotLogToSplunkHec is not set
          if(-not($DoNotLogToSplunkHec))
          {
              # Create the Splunk HEC Header
              $splunkHecHeader = @{Authorization = "Splunk $splunkHecToken"}

              # Specify the Splunk HEC Feedback Body
              $splunkHecBody = @{
                  host="$env:computername"
                  index="$splunkIndex"
                  sourcetype="feedback"
                  source="splunk-hec"
                  event = @{
                      eventMessages = $messages
                      eventTag = $eventTag
                      eventSubTag = $eventSubTag
                      severityLevel = $severityLevel
                      sendingMethod = "notYetSet"
                      assetInfo = @{
                          adDomain = $adDomain
                          businessUnit = $businessUnit
                          localActiveMacs = $localActiveMacs
                          localActiveIps = $localActiveIps
                          assetDN = $assetDN
                          assetTimezone = $assetTimezone
                          assetType = $assetType
                          localUser = $localUser
                          cpuArch = $cpuArch
                          cpuName = $cpuName
                          cpuMaxClockSpeedInMhz = $cpuMaxClockSpeedInMhz
                          cpuNumberOfLogicalCores = $cpuNumberOfLogicalCores
                          cpuNumberOfPhysicalCores = $cpuNumberOfPhysicalCores
                          totalMemoryInGB = $totalMemoryInGB
                          availableMemoryInGB = $availableMemoryInGB
                          dotnetVer = $dotnetVer
                          domainRole = $domainRole
                          diskCFreeSpaceInGB = $diskCFreeSpaceInGB
                          osBuild = $osBuild
                          osName = $osName
                          osRelease = $osRelease
                          osClass = $osClass
                          osVer = $osVer
                          osLocale = $osLocale
                          pcSystemType = $pcSystemType
                          assetManufacturer = $assetManufacturer
                          assetModel = $assetModel
                          psMajorVer = $psMajorVer
                          psMinorVer = $psMinorVer
                          psVer = $psVer
                          lastBootUpTime = $lastBootUpTime
                      }
                      scriptInfo = @{
                          scriptName = $scriptName
                          scriptVer = $runningScriptVerString
                          scriptSwitchUsed = $scriptSwitchUsed
                          scriptCorrelationId = $scriptCorrelationId
                          scriptFileHashSHA256 = $scriptFileHashSHA256
                          scriptRunningAs = $scriptRunningAs
                          moduleName = $moduleName
                          functionVersion = $functionVersion
                          functionName = $functionName
                      }
                  }
              }

              # Try to Send to Splunk HEC directy (more efficient vs. Relay), *IF* it's reachable. Otherwise, try and send it via relay if it's available 
              if($splunkHECReachable)
              {
                  Write-Verbose "Will send direct to Splunk HEC as it is reachable"

                  # Set sendingMethod
                  $splunkHecBody.event.sendingMethod = "direct"

                  # Convert splunkHecBody to raw JSON
                  $splunkHecBody = ConvertTo-Json -InputObject $splunkHecBody -Depth 9 -WarningAction SilentlyContinue

                  # Send directly to Splunk
                  Invoke-RestMethod -Method Post -Uri "https://example.com:8088/services/collector" -Headers $splunkHecHeader -Body $splunkHecBody -DisableKeepAlive -ErrorAction SilentlyContinue | out-null

              } Else {

                  # Send to the Splunk via the relay if it's available and we have the right API key. Else, error out.
                  if($relayReachable   -and   $splunkHECRelayApiKey)
                  {
                      Write-Verbose "Matched Relay Option"

                      # Set sendingMethod
                      $splunkHecBody.event.sendingMethod = "relayed"

                      # Convert splunkHecBody to raw JSON
                      $splunkHecBody = ConvertTo-Json -InputObject $splunkHecBody -Depth 9 -WarningAction SilentlyContinue

                      # Send to relay server (external-facing)
                      Invoke-RestMethod -Method Post -Uri "https://$relayHostname/backstop/relay/v1" -Headers @{apiKey = "$splunkHECRelayApiKey"; clientHostname = $env:COMPUTERNAME; scriptHash = $scriptFileHashSHA256; "Accept-Encoding"="gzip"} -Body $splunkHecBody -UserAgent "$userAgent" -ErrorVariable webRequestError

                  } Else {

                      $Global:errorMessage = "ERROR: Splunk HEC relay was unreachable and sending directly via Splunk HEC also unavailable or your API key was missing. Unable to send message to Splunk."
                      Write-Log -eventTag "Write-Log" -eventSubTag "-" -severityLevel "error" -messages $errorMessage -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec -WriteHost
                  }
              }
          }

      #endregion LOG TO SPLUNK VIA HEC


      #region  LOG TO LOCAL FILE  ##########################################################################################################################################

          # Log to local file so long as -DoNotLogToLocalFile wasn't specified 
          if(-not($DoNotLogToLocalFile))
          {
              # Default to "C:\Windows\Temp\$scriptName.log" but allow a custom log path if requested.
              if($CustomLocalLogPath)
              {
                  # Write to the log path that was specified with argument -CustomLocalLogPath "PATH_TO_LOG_FILE"
                  $Global:localLogFilePath = $CustomLocalLogPath

              } Else {

                  # Define default local log file path
                  $Global:localLogFilePath = "C:\Windows\Temp\$scriptName.log"
              }

              # If the file does not exist, create it in the correct format
              if(-Not(Test-Path -Path $localLogFilePath))
              {
                  # Add the initial header to the log file
                  Add-Content -Path $localLogFilePath -Value "timestamp,eventTag,eventSubTag,severityLevel,messages,scriptName,runningScriptVerString,scriptSwitchUsed,scriptCorrelationId"
              }

              # Refresh Timestamp
              $timestamp = (Get-Date).ToString()

              # Craft the following log line for the CSV log file
              $logLine = "`"$timestamp`",$eventTag,$eventSubTag,$severityLevel,$messages,$scriptName,$runningScriptVerString,$scriptSwitchUsed,$scriptCorrelationId"

              # Write the log line to the log file
              Add-Content -Path $localLogFilePath -Value "$logLine"
          }

      #endregion LOG TO LOCAL FILE


      #region  WRITE HOST  #################################################################################################################################################

          # Write error message to local PowerShell window if the -WriteHost switch was called with a severityLevel of 'Error'. 
          if(($WriteHost)   -and   ($severityLevel -match "(Error)|(Critical)|(Emergency)"))
          {
              Write-Error -Message "$messages"
          }

          # Write warning message to local PowerShell window if the -WriteHost switch was called with a severityLevel of 'Warn'. 
          if(($WriteHost)   -and   ($severityLevel -match "(Notice)|(Warn)"))
          {
              Write-Warning "$messages"
          }

          # Write verbose message to local PowerShell window if the -WriteHost switch was called with a severityLevel of 'Debug'. 
          if(($WriteHost)   -and   ($severityLevel -match "Debug"))
          {
              Write-Verbose "$messages" -Verbose
          }

          # For anything else, write a normal message
          if(($WriteHost)   -and   ($severityLevel -notmatch "(Debug)|(Notice)|(Warn)|(Error)|(Critical)|(Emergency)"))
          {
              Write-Host "$messages"
          }

      #endregion WRITE HOST
    }
  
  
  
  
    function Get-Metrics
    {
      <#
          .SYNOPSIS
            Provides metrics on latency, runtime, CPU and memory usage to troubleshoot performance issues
            and to further optomize scripts/modules in the future.


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          1-August-2024
            █ RELEASE NOTES:
            ↪ Alpha Release


          .PARAMETER Start
            Starts the metrics timer


          .PARAMETER Stop
            Stops the timer and collects metrics to send back to Splunk


          .EXAMPLE
            Get-Metrics -Start
            Get-Metrics -Stop 


      #>
      
      


      #region  DEFINE PARAMETERS  ##########################################################################################################################################

          Param(
              [Parameter(Mandatory=$False,Position=0)]
                  [Switch]$Start,
              [Parameter(Mandatory=$False,Position=1)]
                  [switch]$Stop
          )

      #endregion DEFINE PARAMETERS


      #region  DEFINE METRICS FUNCTIONS  ###################################################################################################################################

          function Start-Metrics
          {
              # Start a stopwatch timer to see how long this script is taking to run. Measure-command would work but with odd workaround with 
              # $scriptName. Doing this way vs. measure-command as it gives same result in a simpler fashion. Simpler is almost always better!
              $Global:perfTimer = [system.diagnostics.stopwatch]::startNew()
          }


          function Stop-Metrics
          {
              ## Collect Script Performance Stats

              # Get memory usage for this specific PowerShell PID
              # NOTE: In single-machine testing, this number was +/- ~10MB's of true (what task manager shows for private working set) and it changes a bit.
              # Getting the private working set of a specific PID in get-counter isn't possible and get-process doesn't show private working set so this may be my 
              # only/closest option to measure private working set mem usage for a specific PID
              $Global:memoryUsageInMB = (Get-CimInstance -Class Win32_PerfFormattedData_PerfProc_Process | Where-Object {$_.IDProcess -eq $PID}).WorkingSetPrivate

              # Breakdown above into MB's
              $Global:memoryUsageInMB = $memoryUsageInMB /1024/1024

              # Round above into non-decimal value to make it an easier to read number
              $Global:memoryUsageInMB = [math]::Round($memoryUsageInMB,0)

              # Kill the stopwatch
              $Global:perfTimer.Stop()

              # Capture how many seconds the script took to run but to keep it honest, add +3 seconds to account for feedback and writing to state file.
              $Global:runTimeInSeconds = $perfTimer.ElapsedMilliseconds/1000 + 3

              # Round the number to the closest second
              $Global:runTimeInSeconds = [math]::Round($runTimeInSeconds,1)

              # Get CPU ticks but divide by 1000 twice to get number in millions
              $Global:cpuTicksInMillions = (Get-Process -Id $PID).TotalProcessorTime.Ticks/1000/1000

              # Round the number to the closest million
              $Global:cpuTicksInMillions = [math]::Round($cpuTicksInMillions,0)

              # Capture details about this  PowerShell process
              $Global:thisPowerShellProcess = Get-Process -Id $PID

              # Create message body for sending data back to Splunk
              $messages = @{
                  runTimeInSeconds = $runTimeInSeconds
                  memoryUsageInMB = $memoryUsageInMB
                  scriptCpuPriorityClass = $thisPowerShellProcess.PriorityClass.tostring()
                  scriptProcessorAffinity = $thisPowerShellProcess.ProcessorAffinity.tostring()
                  cpuTicksInMillions = $cpuTicksInMillions
              }

              # Send performance beacon back to Splunk
              Write-Log -eventTag "Performance Beacon" -eventSubTag "-" -severityLevel info -messages $messages -CustomLocalLogPath $CustomLocalLogPath -ClassificationLevel $classificationLevel
          }

      #endregion DEFINE METRICS FUNCTIONS


      #region  SWITCH ACTIONS  #############################################################################################################################################

          if($Start)
          { 
              # Start metrics timer
              Start-Metrics
          }

          if($Stop)
          { 
              # Stop timer, collect metrics and send to Splunk
              Stop-Metrics
          }

          If(-not($Start) -and (-not($Stop)))
          {
              Write-Host "ERROR: You need to specify either -Start or -Stop."
          }

      #endregion SWITCH ACTIONS

    }




    function Search-ItemName
    {
      <#
          .SYNOPSIS
            Searches for a regex pattern in a file or directory name and reports it. This is just the name of it, not the contents.


          .DESCRIPTION
            Searches through a given path for any file or directory names which match a specific regex pattern that you specify and 
            optionally recurses the folder structure and sends the data back to Splunk.


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        BETA
            █ Version:              0.1
            █ Last Update:          3-August-2024
            █ RELEASE NOTES:
            ↪ Alpha Release
          

          .PARAMETER Path
            Specify the path to search in


          .PARAMETER Pattern
            Specify the regex pattern to search for. If you need help with Regex, go to https://regexr.com/ and/or use ChatGPT. All
            regex patterns are generally perl compatible and, by default, are not case-sensitive in PowerShell.


          .PARAMETER Recurse
            Optionally set this switch to recurse through sub-directories.


          .PARAMETER SendToSplunk
            Optionally set this switch to send the data to Splunk. Use tag=feedback host=YOUR_HOSTNAME_HERE to search for the logs in Splunk


          .PARAMETER NoBeacon
            Do not beacon to Splunk on initial search

      #>


      param(
          [Parameter(Mandatory=$true)]
          [System.IO.FileInfo]$Path,

          [Parameter(Mandatory=$true)]
          [string]$Pattern,

          [Parameter(Mandatory=$false)]
          [switch]$Recurse,

          [Parameter(Mandatory=$false)]
          [switch]$SendToSplunk,

          [Parameter(Mandatory=$false)]
          [switch]$NoBeacon            
      )

      # Beacon back to Splunk to indicate that search started if -SendToSplunk switch specified.
      if(($SendToSplunk)   -and   (-Not($NoBeacon)))
      {
          Write-Log -eventTag "Search-ItemName" -eventSubTag "Beacon" -severityLevel "info" -messages "Search kicked off on asset for pattern `"$Pattern`" in path `"$Path`""
      }

      # Search for pattern in the name of the file or directory
      $items = if ($Recurse) {
          Get-ChildItem -Path $Path -Recurse | Where-Object { $_.Name -match $Pattern }
      } else {
          Get-ChildItem -Path $Path | Where-Object { $_.Name -match $Pattern }
      }

      foreach ($item in $items)
      {
          $finding = [PSCustomObject]@{
              fullPath = $item.FullName
              itemName = $item.Name
              itemType = if ($item.PSIsContainer) {'Directory'} else {'File'}
              fileType = if (-Not($item.PSIsContainer)) {$item.Name.Split(".")[1]} else {"N/A"}
          }

          if($SendToSplunk)
          {
              Write-Log -eventTag "Search-ItemName" -eventSubTag "-" -severityLevel "info" -messages $finding

          } Else {

              # Print the finding
              $finding
          }
      }
    }




    function Search-ItemContent
    {
      <#
          .SYNOPSIS
            Searches for a regex pattern within files and reports the findings back.


          .DESCRIPTION
            Searches through a given file or directory for files which contain a specific regex pattern within the contents of the file.
            optionally recurses the folder structure and sends the data back to Splunk.


          .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              ©TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        BETA
            █ Version:              0.1
            █ Last Update:          3-August-2024
            █ RELEASE NOTES:
            ↪ Alpha Release
          

          .PARAMETER Path
            Specify the path to search in


          .PARAMETER Pattern
            Specify the regex pattern to search for. If you need help with Regex, go to https://regexr.com/ and/or use ChatGPT. All
            regex patterns are generally perl compatible and, by default, are not case-sensitive in PowerShell.


          .PARAMETER Recurse
            Optionally set this switch to recurse through sub-directories


          .PARAMETER SendToSplunk
            Optionally set this switch to send the data to Splunk.


          .PARAMETER NoBeacon
            Do not beacon to Splunk on initial search

      #>


      param(
          [Parameter(Mandatory=$true)]
          [System.IO.FileInfo]$Path,

          [Parameter(Mandatory=$true)]
          [string]$Pattern,

          [Parameter(Mandatory=$false)]
          [switch]$Recurse,
          
          [Parameter(Mandatory=$false)]
          [switch]$SendToSplunk,

          [Parameter(Mandatory=$false)]
          [switch]$NoBeacon
      )

      # Beacon back to Splunk to indicate that search started if -SendToSplunk switch specified.
      if(($SendToSplunk)   -and   (-Not($NoBeacon)))
      {
          Write-Log -eventTag "Search-ItemName" -eventSubTag "Beacon" -severityLevel "info" -messages "Search kicked off on asset for pattern `"$Pattern`" in path `"$Path`""
      }

      $listOfFiles = Get-ChildItem -Path $Path -Recurse:$Recurse -File

      # Search for pattern in the contents of the files in the path specified
      foreach ($file in $listOfFiles)
      {
          # Search through the content of each file
          $matches = Select-String -Path $file.FullName -Pattern $Pattern
          if ($matches)
          {
              foreach ($match in $matches)
              {
                  $finding = [PSCustomObject]@{
                      fullPath = $file.FullName
                      fileName = $file.Name
                      lineNumberInFile = $match.LineNumber
                      matchingPattern = $match.Line
                      fileType = $file.Name.Split(".")[1]
                  }

                  if($SendToSplunk)
                  {
                      Write-Log -eventTag "Search-ItemNContent" -eventSubTag "-" -severityLevel "info" -messages $finding

                  } Else {

                      # Print the finding
                      $finding
                  }
              }
          }
      }
    }




    function Test-CIDR
    {
        <#
            .SYNOPSIS
                Tests a CIDR notated subnet to ensure that it's a valid subnet and not something like 86.7.53.0/9 which has an invalid mask.
    
    
            .DESCRIPTION
                This code modified from Google Gemini and this fixed by ChatGPT. It's late, I'm sleepy and since I don't validate subnets much,
                just need something good enough that works to ensure subnets aren't typoed. If it's good, it returns true and if it's bad it 
                returns... drum roll please.... false. Since one obviously can't rely on AI, I needed to fix several issues with it until I 
                finally got it right. Ran a random sampling of 10k invalid subnets and 10k valid subnets through this functions and both lists
                are finally parsing correctly making this function good enough for now. Yes, I used AI to generate the lists and even that had
                to be fixed several times to get those lists right and run them through the function again to be sure. 
    
    
            .NOTES
                Project:                Backstop Flexibility Framework (BFF)
                Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
                Copyright:              © 2024 | TenderLovinSnare
                Contact:                TenderLovinSnare@gmail.com
                License:                MIT (https://opensource.org/license/mit)
                █ Last Updated By:      TenderLovinSnare
                █ Release Stage:        BETA
                █ Version:              0.1
                █ Last Update:          23-December-2024
    
        #>
    
        param
        (
            # Test a CIDR notated subnet such as 1.2.3.0/24 (valid) or 86.7.53.0/9 (invalid)
            [Parameter(Mandatory=$false)]
            [string]$CIDR,

            # Test an IP address such as 1.2.3.4 (valid) or 1.2.3.444 (invalid)
            [Parameter(Mandatory=$false)]
            [string]$IPAddress
        )


        # Ensure either one or the other param was called
        if(((-Not($CIDR))  -and  (-Not($IPAddress)))   -or   ((($CIDR))  -and  ($IPAddress)))
        {
            Write-Error "You must specify either -CIDR or -IPAddress and also not both at the same time."
        }

        try {

            # Check for a single subnet
            if($CIDR)
            {
                # Split the CIDR into IP and prefix length
                $ip, $prefixLength = $CIDR.Split('/')
                $prefixLength = [int]$prefixLength

                # Validate prefix length
                if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
                    throw "Invalid prefix length. Must be between 0 and 32."
                }

                # Validate IP address format
                [System.Net.IPAddress]$ipAddress = [System.Net.IPAddress]$ip

                # Convert IP to decimal
                $ipBytes = $ipAddress.GetAddressBytes()
                $ipDecimal = [BitConverter]::ToUInt32($ipBytes[3..0], 0)

                # Generate subnet mask
                $maskDecimal = ([math]::Pow(2, $prefixLength) - 1) -band 0xFFFFFFFF
                $maskDecimal = $maskDecimal -shl (32 - $prefixLength)

                # Calculate the network address
                $networkDecimal = $ipDecimal -band $maskDecimal

                # Verify that the IP aligns with the network boundary
                if ($networkDecimal -ne $ipDecimal) {
                    throw "IP address $ip is not aligned with subnet boundary for /$prefixLength."
                }

                return $true
            }

            # Check for a single IP address
            if($IPAddress)
            {  
                [void][System.Net.IPAddress]::Parse($IPAddress)
                return $true
            }
    
        } catch {

            return $false
        }
    }




    function Write-Fail
    {
        <#
            .SYNOPSIS
              Displays a fail message when it's obvious that either the dev or the user did something dumb. Do not over-use this as there's better ways to
              do proper error handling. Just here for fun if you'd like to use it in very select use-cases for the comedic value. Totally used ChatGPT for
              the animations as I'm already waisting enough of my time adding this anyway.
    
    
            .NOTES
              Project:                Backstop Flexibility Framework (BFF)
              Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
              Copyright:              © 2024 TenderLovinSnare (Unless Otherwise Noted)
              Contact:                TenderLovinSnare@gmail.com
              License:                MIT (https://opensource.org/license/mit)
              █ Last Updated By:      TenderLovinSnare
              █ Release Stage:        GA
              █ Version:              1.0
              █ Last Update:          26-December-2024
    
    
            .PARAMETER MessageOfShame
              Type whatever message you'd like to display back
    
    
            .PARAMETER FailType
              Specify which type of failure you'd like to portray


            .PARAMETER RandomFailType
              Just pick a random failType, I don't care, whatever.


            .PARAMETER DelayOfShame
              In addtion to the five yard penalty, specify the banner animation delay, in milliseconds, where the slower it goes, the more annoying it is 
              and the larger the smile you, as the person setting it, has. Just be reasonable. Default is 10ms.


            .Example
              PS C:\> Write-Fail -MessageOfShame -FailType Facepalm
        #>
    
    
    
    
        ##########################################################################################################################################################################
        #region   PARAMETERS   ###################################################################################################################################################
        ##########################################################################################################################################################################
    
            Param
            (
                # The name of the user, up-to N characters below and also only allow alphanumeric, @, _, ., - characters
                [parameter(Mandatory=$true)]
                [String]$MessageOfShame,
    
                # What type of failure 
                [parameter(Mandatory=$false)]
                [ValidateSet('Facepalm', 'FailWhale')]
                [String]$FailType = 'FailWhale',

                # What type of failure 
                [parameter(Mandatory=$false)]
                [Switch]$RandomFailType,

                # The amount of time, in milliseconds, it takes the banner to animate
                [parameter(Mandatory=$false)]
                [Int32]$DelayOfShame = 10
            )
    
        #endregion PARAMETERS
    
    
    
    
        ##########################################################################################################################################################################
        #region   WRITE FAIL   ###################################################################################################################################################
        ##########################################################################################################################################################################

            # Specify an offset so the text alings with the banner then add it to w/e they typed
            $offset = '   '
            $MessageOfShame = $offset + $MessageOfShame

            # Pick a random FailType if requested
            if($RandomFailType)
            {
                $failTypes = ('Facepalm', 'FailWhale')
                $FailType = Get-Random $failTypes
            }

            if($FailType -eq 'Facepalm')
            {
                # The banner lines to randomly animate (no blank "" lines!)
                $bannerLines = @(
                "   ╭┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈╮",
                "     🤦 THE FAIL IS STRONG TODAY 🤦  ",
                "   ╰┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈╯"
                )

                Write-Host "`r"

                # Animation logic
                foreach ($bannerLine in $bannerLines) {

                    $output = " " * $bannerLine.Length
                    $charArray = $bannerLine.ToCharArray()
                    $indices = @(0..($charArray.Length - 1)) | Get-Random -Count $charArray.Length

                    foreach ($index in $indices) {
                        $output = $output.Substring(0, $index) + $charArray[$index] + $output.Substring($index + 1)
                        Write-Host -NoNewline "`r$output" -ForegroundColor Red
                        Start-Sleep -Milliseconds $DelayOfShame
                    }
                    Write-Host
                }

                Write-Host "`r"

                # Show the animated MessageOfShame going left to right
                $output = ""
                foreach ($char in $MessageOfShame.ToCharArray()) {
                    $output += $char
                    Write-Host -NoNewline "`r$output" -ForegroundColor Red
                    Start-Sleep -Milliseconds 50
                }

                Write-Host "`n"

            } elseif($FailType -eq 'FailWhale'){

                # The banner lines to randomly animate (no blank "" lines!)
                $bannerLines = @(
                    "   ▄██████████████▄ ▐█▄▄▄▄█",
                    "   ██████▌▄▌▄▐▐▌███▌ ▀▀██▀▀",
                    "   ██▄███▌▄▌▄▐▐▌▀███▄▄▄█▌",
                    "   ▄▄▄▄▄██████████████"
                )

                Write-Host "`r"
                
                # Animation logic
                foreach ($bannerLine in $bannerLines) {

                    $output = " " * $bannerLine.Length
                    $charArray = $bannerLine.ToCharArray()
                    $indices = @(0..($charArray.Length - 1)) | Get-Random -Count $charArray.Length

                    foreach ($index in $indices) {
                        $output = $output.Substring(0, $index) + $charArray[$index] + $output.Substring($index + 1)
                        Write-Host -NoNewline "`r$output" -ForegroundColor Red
                        Start-Sleep -Milliseconds $DelayOfShame
                    }
                    Write-Host
                }

                Write-Host "`r"

                # Show the animated MessageOfShame going left to right
                $output = ""
                foreach ($char in $MessageOfShame.ToCharArray()) {
                    $output += $char
                    Write-Host -NoNewline "`r$output" -ForegroundColor Red
                    Start-Sleep -Milliseconds 50
                }

                Write-Host "`n"
            }

            Remove-Variable -Name MessageOfShame

        #endregion WRITE FAIL
    }

#endregion DEFINE FUNCTIONS




##############################################################################################################################################################################
#region   SIGNATURE   ########################################################################################################################################################
##############################################################################################################################################################################

