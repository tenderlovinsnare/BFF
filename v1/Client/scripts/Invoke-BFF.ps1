<#
    .SYNOPSIS
      This is the main script for the Backstop Flexibility Framework or "BFF". This script launches the BFF payload modules.


    .DESCRIPTION
      The Backstop Flexibility Framework acts both as a cyber deception deployment solution and a back door of last resort for management if other solutions are compromised such 
      as SCCM and/or CrowdStrike. This script acts as a downloader and launcher for PowerShell functions via PowerShell modules. These modules may gather and report on the state 
      of the endpoint, support hardening or deception projects, may update security components or look for suspicious activity for automated threat hunting and reporting back to
      Splunk. While it may do some of these, the primary role is that of an early warning system to detect when threat actors have compromised our networks. This script is well 
      commented and documentation should also be found within each module as well. Note that efforts were made to obfuscate and hide this functionality but nothing is perfect and
      it certainly can be found. At best, the obfuscation techniques used will simply buy us some time and with it, additional access and that's about it.


    .NOTES
      Project:                Backstop Flexibility Framework (BFF)
      Public GitHub Repo:     https://github.com/humblecyberdude/BFF
      Copyright:              HumbleCyberDude@gmail.com
      License:                MIT (https://opensource.org/license/mit)
      Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
      Major Release Name:     Tender Lovin' Snare
      █ Last Updated By:      HumbleCyberDude
      █ Release Stage:        ALPHA
      █ Version:              0.1
      █ Last Update:          9-August-2024


    .EXAMPLE
      .\Invoke-BFF.ps1

#>




##############################################################################################################################################################################
#region   PARAMETERS   #######################################################################################################################################################
##############################################################################################################################################################################

    # Define standard parameters so we can use -Verbose, etc. with this script
    [CmdletBinding()]
    param ()

#endregion PARAMETERS




##############################################################################################################################################################################
#region   SCRIPT INFO   ######################################################################################################################################################
##############################################################################################################################################################################

    # Script Version
    [System.Version]$runningScriptVer = "0.1.0"

    # Breakout the Version info for easier parsing
    $runningScriptVerMajor = ($runningScriptVer).Major
    $runningScriptVerMinor = ($runningScriptVer).Minor
    $runningScriptVerBuild = ($runningScriptVer).Build

    # Ensure that this script version gets passed to ClientCore functions module
    $Global:runningScriptVerString = "$runningScriptVerMajor.$runningScriptVerMinor.$runningScriptVerBuild"

    Write-Host "`r"
    Write-Host "`e[38;2;255;255;50m                     (                                            "  
    Write-Host "`e[38;2;255;255;50m        (            )\ )                                         " 
    Write-Host "`e[38;2;255;240;50m      ( )\     (    (()/(      (     )    (            (          "
    Write-Host "`e[38;2;255;220;50m      )((_)   ))\    /(_))    ))\   /((   )\    (     ))\   (     "
    Write-Host "`e[38;2;255;200;50m      ((_)_  /((_)   (_))    /((_) (_))\ ((_)   )\   /((_)  )\    "
    Write-Host "`e[38;2;255;180;50m      | _ ) (_))     |   \  (_))  (_)((_) (_)  ((_) (_))() ((_)   "
    Write-Host "`e[38;2;255;160;50m      | _ \ / -_)    | |) | / -_)  \ V /  | | / _ \ | || | (_-<   "
    Write-Host "`e[38;2;255;140;50m      |___/ \___|    |___/  \___|   \_/   |_| \___/  \_,_| /__/   "
    Write-Host "`r                                                                                   "
    Write-Host "`e[38;2;255;110;50m                                                                  "
    Write-Host "`e[38;2;255;90;50m             <<< The Backstop Flexibility Framework >>>            "
    Write-Host "`r                                                                                   "
    Write-Host "`e[38;2;255;80;50m                        BFF Version: $runningScriptVer             "
    Write-Host "`r`n                                                                                 "

#endregion SCRIPT INFO




##############################################################################################################################################################################
#region   VARIABLES   ########################################################################################################################################################
##############################################################################################################################################################################

    # Supress progress bars to reduce odd artifacts when running in console mode.
    $Global:ProgressPreference = 'SilentlyContinue'
    
    # Define script name and hash
    $scriptPath = $MyInvocation.MyCommand.Source
    $scriptName = Split-Path $scriptPath -leaf

    # Get file hash of the calling script
    $Global:scriptFileHashSHA256 = (Get-FileHash $scriptPath -Algorithm SHA256).hash
    
    # Define the Backstop API server host URL
    $backstopAPIServerName = 'EXAMPLE FQDN'

    # Define the relay hostname (same as above). This is needed by the ClientCore module for those hosts which aren't on the internal network.
    $Global:relayHostname = $backstopAPIServerName

    # Determine if Backstop API server is reachable
    $backstopServerIsReachable = (Test-NetConnection -ComputerName "$backstopAPIServerName" -Port "443").TcpTestSucceeded

    # Define the valid certificate thumbprint that to match against to ensure that it's your signed code running.
    $Global:validBackstopCodeSigningThumbprint = 'EXAMPLE'

    # Define the valid thumbprints. We want to create an array so we can add additional ones later. The certificate thumbpint isn't contained within the cert but instead,
    # is the SHA256 hash of the entire cert, allowing anyone to more easiliy compare the cert.
    $Global:validBackstopAPICertThumbprints = @('EXAMPLE')

    # Determine this scripts directory (random on each machine). This will get the full path to this script but we need to get the root path (one directory back)
    $rootPath = split-path -parent $MyInvocation.MyCommand.Path

    # Since this script is running in \scripts, we need to remove that to make it generic. For example, if the directory comes back as C:\hidden_directory\scripts, we want
    # to have this variable go back to C:\hidden_directory. Then we can say -Path $rootPath\bin for C:\hidden_directory\bin.
    $rootPath = $rootPath.Replace("\scripts","")

    # Define the custom local log path for this script
    $Global:CustomLocalLogPath = "$rootPath\logs\messages.log"

    # Define PowerShell version string
    $Global:psVerString = (Get-Host).version.ToString()

    # Define the Splunk HEC Classification Level
    $Global:classificationLevel = "C3"

    # Define the user agent for Backstop server API requests
    $Global:userAgent = "Backstop ($scriptName/$runningScriptVerString) (PowerShell/$psVerString)"

#endregion VARIABLES




##############################################################################################################################################################################
#region   DEPENDANCIES   #####################################################################################################################################################
##############################################################################################################################################################################

    Write-Host "Checking dependencies..."

    # Ensure that we're running in at least PowerShell 7
    if((get-host).version.Major -lt 7)
    {
        $message = "DEPENDANCIES: Welcome to the modern world. Must be running at least PowerShell 7. Exiting..."

        # Write Local Log File
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
        Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

        Write-Error $message

        # Exit
        Exit
    }

#endregion DEPENDANCIES




##############################################################################################################################################################################
#region   CERTIFICATE PINNING CHECK   ########################################################################################################################################
##############################################################################################################################################################################

    # We need to ensure that we're not getting MiTM'd - even if we trust the intercept cert. Therefore, we need to check the certificate thumbprint to ensure that it's ours.
    if($backstopServerIsReachable)
    {
        # Get the cert so we can compare it. CREDIT: Faris Malaeb (CertifcateScanner: https://www.powershellcenter.com/2021/12/23/sslexpirationcheck/)
        $socket = New-Object Net.Sockets.TcpClient($backstopAPIServerName, 443)
        $stream = $socket.GetStream()
        $sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]))
        $ProtocolVersion = 'Tls12'
        $sslStream.AuthenticateAsClient($backstopAPIServerName,$null,[System.Security.Authentication.SslProtocols]$ProtocolVersion,$false)
        $cert = $sslStream.RemoteCertificate
        $serverThumbprint = $cert.Thumbprint

        # Fail if the validBackstopAPICertThumbprints array doesn't contain a valid thumbprint. Update the CustomLocalLogPath so we can generically pull it from Splunk UF.
        if($validBackstopAPICertThumbprints -notcontains $serverThumbprint)
        {
            $CustomLocalLogPath = 'C:\Windows\Temp\generalLog.log'
            $subject = $cert.Subject
            $issuer = $cert.Issuer
            $validFrom = $cert.NotBefore
            $validTo = $cert.NotAfter

            # Write Local Log File
            $message = "CERT PINNING: Certificiate pinning check failed so script exited. Traffic interception may have been performed. Bad Cert Info: subject=$subject issuer=$issuer invalidServerThumbprint=$serverThumbprint validFrom=$validFrom validTo=$validTo"
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
            Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"
            Write-Error -Message $message

            # EJECT! EJECT!
            Exit
        }
    }

#endregion CERTIFICATE PINNING CHECK 




##############################################################################################################################################################################
#region   EXTRACT SECRETS   ##################################################################################################################################################
##############################################################################################################################################################################

    # Extract the Backstop API key first as we'll need it to authenticate to the Backstop server. This uses DPAPI and is populated with the SimpleVault functions in the
    # ClientCore module. Only the SYSTEM account of the machine is able to decrypt the credentials in the vault. We could just import the ClientCore module and
    # use the SimpleVault functions but it's less code to just extract here first vs. having to run the SimpleVault functions AND, if the ClientCore module is missing,
    # have to run the below code anyway.

    # Get the JSON content of the vault and read it in as an object
    $Global:Vault = Get-Content -Path "$rootPath\etc\vault.json" -Raw | ConvertFrom-Json

    # Get the encrypted value of the Secure-String
    $encryptedSecureString = ($Vault.Secrets.PSObject.Properties | Where-Object {$_.Name -eq 'backstopCommonApiKey'}).Value

    # Convert that to a binary in-memory securestring
    $encryptedSecureString = $encryptedSecureString | ConvertTo-SecureString

    # Convert the encryptedSecureString variable back into plaintext via DPAPI
    $binaryString = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encryptedSecureString)
    $backstopCommonApiKey_vaultSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($binaryString)

    # Set the splunkHECRelayApiKey with the same as the backstopCommonApiKey_vaultSecret. I don't want to put the words "BFF" or "Backstop" in the functions modules 
    # however, that module does require an API key to relay back to Splunk through the Backstop server. That API key name it needs is splunkHECRelayApiKey.
    $Global:splunkHECRelayApiKey = $backstopCommonApiKey_vaultSecret

    # Verify we have the key
    if($backstopCommonApiKey_vaultSecret)
    {
        # Write Local Log File
        $message = "EXTRACT SECRETS: Successfully extracted the Backstop API key"
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
        Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=info message=$message"

    } Else {

        # Write Local Log File
        $message = "EXTRACT SECRETS: Unable to extract the Backstop API key. Unable to authenticate to Backstop. Exiting!"
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
        Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"
        Write-Error -Message $message

        Exit
    }

#endregion EXTRACT SECRETS




##############################################################################################################################################################################
#region   IMPORT CLIENT CORE FUNCTIONS MODULE   ##############################################################################################################################
##############################################################################################################################################################################

    Write-Host "IMPORT: Importing the Client Core Functions Module..."

    # Define function to download the Client Core Functions module when needed. This code is needed in the case that the file is either missing or it has a bad signature and we 
    # most certainly don't want to write the same download code twice.
    function Get-ClientCore
    {
        # Mark that this function ran already (we only want to run it once)
        $Global:getClientCoreAlreadyRan = $true

        # Download the latest version of ClientCore if Backstop server is reachable. This module gives us the ability to send data back to Splunk and easily test signatures.
        if($backstopServerIsReachable)
        {
            try
            {
                Invoke-RestMethod -Method GET -Uri "https://$backstopAPIServerName/backstop/getfiles/v1" -Headers @{apiKey = "$backstopCommonApiKey_vaultSecret"; clientHostname = $env:COMPUTERNAME; scriptHash = $scriptFileHashSHA256; "Accept-Encoding"="gzip"; fileName = "ClientCore.psm1"} -OutFile "$rootPath\modules\ClientCore.psm1" -UserAgent $userAgent -ErrorVariable webRequestError

            } catch {

                # Parse out just the status code text for the specific error
                $webRequestError = $webRequestError.InnerException.Response.StatusCode

                $message = "FILE DOWNLOAD: The Backstop server was reachable but we're unable to download ClientCore.psm1. Will attempt to use a local copy instead if it's available. Additional Info: backstopServerIsReachable=$backstopServerIsReachable webRequestError=$webRequestError"

                # Write Local Log File
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                Add-Content -Path "$rootPath\logs\$scriptName.log" -Value "$timestamp scriptName=$scriptName severity=warn message=$message"
        
                Write-Host $message -ForegroundColor Yellow
            }

        } Else {

            $message = "FILE DOWNLOAD: Tried to download ClientCore.psm1 but the Backstop server was unreachable. Additional Info: backstopServerIsReachable=$backstopServerIsReachable"

            # Write Local Log File
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
            Add-Content -Path "$rootPath\logs\$scriptName.log" -Value "$timestamp scriptName=$scriptName severity=error message=$message"
    
            Write-Error $message
        }
    }

    # The Backstop Function module contains many functions we need such as the ability to send logs to Splun HEC (Write-Log) and more quickly authenticate code signatures 
    # (Confirm-Authenticode) among other functions.
    if(-not(Test-Path -Path "$rootPath\modules\ClientCore.psm1"))
    {
        $message = "IMPORT: Unable to find local copy of ClientCore.psm1. Attempt to download it if Backstop server reachable..."

        Write-Host $message -ForegroundColor Yellow

        # Write Local Log File
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
        Add-Content -Path "$rootPath\logs\$scriptName.log" -Value "$timestamp scriptName=$scriptName severity=warn message=$message"

        # Call Get-ClientCore to download the missing file
        Get-ClientCore
    }

    # If the file exists, check its signature and run if signature is valid. Note that it will still execute even if the Backstop server is unreachable so long as it's correctly signed. Again, this is by design.
    if(Test-Path -Path "$rootPath\modules\ClientCore.psm1")
    {
        # Get the file signature status for ClientCore
        $scriptSignatureStatus = (Get-AuthenticodeSignature -FilePath "$rootPath\modules\ClientCore.psm1").Status.ToString()
        $scriptSignatureThumbprint = ((Get-AuthenticodeSignature -FilePath "$rootPath\modules\ClientCore.psm1").SignerCertificate).Thumbprint

        # Import only if it is correctly signed and signed by the Backstop code signing certificate
        if(($scriptSignatureStatus -eq "Valid") -and ($scriptSignatureThumbprint -eq "$validBackstopCodeSigningThumbprint"))
        {
            # We force it for added freshness. If we're testing and want to test updates to the module, -Force will ensure we get the latest version loaded in memory.
            Import-Module "$rootPath\modules\ClientCore.psm1" -Force

            if(Get-Module -Name ClientCore)
            {
                $message = "SIGNATURE VALIDATION: Successfully verified scriptSignatureStatus and imported the ClientCore module. Additional Info: scriptSignatureStatus=$scriptSignatureStatus scriptSignatureThumbprint=$scriptSignatureThumbprint"

                # Write Local Log File
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                Add-Content -Path "$rootPath\logs\$scriptName.log" -Value "$timestamp scriptName=$scriptName severity=info message=$message"

            } Else {

                $message = "IMPORT: Something went wrong loading the ClientCore module. This is an unlikely event and needs to be troubleshooted manually."

                # Write Local Log File
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                Add-Content -Path "$rootPath\logs\$scriptName.log" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

                Write-Error -Message $message

                Exit
            }

        } Else {

            # If not already done, call the Get-ClientCore to download a fresh (and hopefully correctly signed) copy
            if(-Not($getClientCoreAlreadyRan))
            {
                $message = "SIGNATURE VALIDATION: We have the ClientCore file but it's not correctly signed. Will attempt to download the the latest copy..."

                # Write Local Log File
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                Add-Content -Path "$rootPath\logs\$scriptName.log" -Value "$timestamp scriptName=$scriptName severity=warn message=$message"

                Write-Host $message -ForegroundColor Yellow
                
                # Call Get-ClientCore to download a fresh (and hopefully correctly signed) copy
                Get-ClientCore

                # Again, get the file signature status for ClientCore
                $scriptSignatureStatus = (Get-AuthenticodeSignature -FilePath "$rootPath\modules\ClientCore.psm1").Status.ToString()
                $scriptSignatureThumbprint = ((Get-AuthenticodeSignature -FilePath "$rootPath\modules\ClientCore.psm1").SignerCertificate).Thumbprint

                # Import only if it is correctly signed and signed by the Backstop code signing certificate
                if(($scriptSignatureStatus -eq "Valid") -and ($scriptSignatureThumbprint -eq "$validBackstopCodeSigningThumbprint"))
                {
                    # We force it for added freshness. If we're testing and want to test updates to the module, -Force will ensure we get the latest version loaded in memory.
                    Import-Module "$rootPath\modules\ClientCore.psm1" -Force

                    if(Get-Module -Name ClientCore)
                    {
                        $message = "IMPORT: Successfully verified scriptSignatureStatus and imported the ClientCore module. Additional Info: scriptSignatureStatus=$scriptSignatureStatus scriptSignatureThumbprint=$scriptSignatureThumbprint"
        
                        # Write Local Log File
                        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                        Add-Content -Path "$rootPath\logs\$scriptName.log" -Value "$timestamp scriptName=$scriptName severity=info message=$message"
        
                    } Else {
        
                        $message = "IMPORT: Something went wrong loading the ClientCore module. This is an unlikely event and needs to be troubleshooted manually."
        
                        # Write Local Log File
                        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                        Add-Content -Path "$rootPath\logs\$scriptName.log" -Value "$timestamp scriptName=$scriptName severity=error message=$message"
        
                        Write-Error -Message $message
        
                        Exit
                    }

                } Else {

                    # Move the old copy to temp in case we want to look at it later for forensics
                    Move-Item -Path "$rootPath\Modules\ClientCore.psm1" -Destination "$rootPath\Temp\ClientCore.psm1.BADSIG" -Force

                    $message = "SIGNATURE VALIDATION: We have the ClientCore file but even after trying to download the latest copy, it still has a bad signature. Will remove module from Modules directory and try again next time. Additional Info: validBackstopCodeSigningThumbprint=$validBackstopCodeSigningThumbprint scriptSignatureThumbprint=$scriptSignatureThumbprint scriptSignatureStatus=$scriptSignatureStatus."

                    # Write Local Log File
                    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                    Add-Content -Path "$rootPath\logs\$scriptName.log" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

                    Write-Error $message

                    # Exit Script
                    Exit
                }
            }
        }

    } Else {

        $message = "FILE MISSING: The ClientCore.psm1 file is missing locally and script was unable to download a copy. Script will exit now since we can't verify code integrity. Additional Info: backstopServerIsReachable=$backstopServerIsReachable webRequestError=$webRequestError"

        # Write Local Log File
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
        Add-Content -Path "$rootPath\logs\$scriptName.log" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

        Write-Error $message

        # Exit Script
        Exit
    }

#endregion IMPORT CLIENT CORE FUNCTIONS MODULE




##############################################################################################################################################################################
#region   IMPORT MANIFEST FILE   #############################################################################################################################################
##############################################################################################################################################################################

    Write-Host "IMPORT: Importing the Manifest file..."

    # Download the latest manifest file if the Backstop API server is reachable.
    if($backstopServerIsReachable)
    {
        try
        {
            # Download manifest file and but put it in the temp directory until we validate it
            Invoke-RestMethod -Method GET -Uri "https://$backstopAPIServerName/backstop/getfiles/v1" -Headers @{apiKey = "$backstopCommonApiKey_vaultSecret"; clientHostname = $env:COMPUTERNAME; scriptHash = $scriptFileHashSHA256; "Accept-Encoding"="gzip"; fileName = "manifest.ps1xml"} -OutFile "$rootPath\temp\manifest.ps1xml" -UserAgent $userAgent -ErrorVariable webRequestError

        } catch {

            # Parse out just the status code text for the specific error
            $webRequestError = $webRequestError.InnerException.Response.StatusCode

            # Log Event
            Write-Log -eventTag "Import Manifest File" -eventSubTag "-" -severityLevel "error" -messages "IMPORT: Backstop API server was reachable but unable to download manifest.ps1xml. Will try and use local copy instead if it exists. Additional Info: webRequestError=$webRequestError" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost
        }

        # If there was no error caught in the above attempt to download manifest.ps1xml, verify the file first and then only if valid, move to etc.
        if(-not($webRequestError))
        {
            # Verify code signature
            Confirm-Authenticode -FilePath "$rootPath\temp\manifest.ps1xml" -Thumbprint $validBackstopCodeSigningThumbprint

            if($signatureVerified)
            {
                # Move from temp to etc
                Move-Item -Path "$rootPath\temp\manifest.ps1xml" -Destination "$rootPath\etc\manifest.ps1xml" -Force

                # Log event
                Write-Log -eventTag "Import Manifest File" -eventSubTag "Manifest Signature Check" -severityLevel "info" -messages "SIGNATURE VALIDATION: The manifest file signature was successfully verified and valid. Moved downloaded manifest file to etc directory." -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -DoNotLogToSplunkHec

            } Else {

                # Log event
                Write-Log -eventTag "Import Manifest File" -eventSubTag "Manifest Signature Check" -severityLevel "error" -messages "SIGNATURE VALIDATION: The manifest file signature was NOT valid. Will not import the downloaded manifest file and will use local copy instead." -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost
            }

        } Else {

            # Log event
            Write-Log -eventTag "Import Manifest File" -eventSubTag "Manifest File Download Check" -severityLevel "error" -messages "FILE DOWNLOAD: Error downloading manifest file. Will still attempt to use local copy in order to proceed. Additional Info: HTTP response code was "$manifestRequestResponse.StatusCode"" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel
        }
    }

    # Exit and log event if the manifest file is somehow missing
    if(-not(Test-Path -Path "$rootPath\etc\manifest.ps1xml"))
    {
        # Log Event
        Write-Log -eventTag "Import Manifest File" -eventSubTag "-" -severityLevel "error" -messages "FILE MISSING: The manifest file is missing" -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel 

        # Exit Script
        Exit
    }

    # Import the manifest file. The manifest object has two separate branches: moduleList and hashList
    # - moduleList: Contains a simple array of module names that will be executed so long as they're not disabled within the module itself (i.e. moduleEnabled=$false)
    # - hashList: Since these scripts and binaries don't change often, we want to keep the API load down and only request files if and when the local file hashes do not match what's on the server.
    $manifest = Import-Clixml -Path "$rootPath\etc\manifest.ps1xml"

#endregion IMPORT MANIFEST FILE




##############################################################################################################################################################################
#region   PERFORMANCE CONSTRAINTS   ##########################################################################################################################################
##############################################################################################################################################################################

    # We designs scripts to take as few cycles as possible so even without the mitigations below, CPU shouldn't be a problem anyway. Our goal is to launch this script, quickly
    # complete it and generally stay under the radar. However, if this script takes up more CPU resources than intended, we need another automatic safeguard, enabled first, to 
    # ensure that we're running at a lower CPU priority in order to respect the asset, the user, the OPS team and the business by not significantly impacting asset resources. 

    # Lower CPU priority giving just about anything else on the system higher priority.
    # REF: https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.processpriorityclass?view=netcore-3.1
    $thisPowerShellProcess = Get-Process -Id $PID
    $thisPowerShellProcess.PriorityClass = "Idle"
    $thisProcessId = $thisPowerShellProcess.Id

    # Let's check to ensure that these basic performance constraints are actually in place
    if($thisPowerShellProcess.PriorityClass -eq "Idle")
    {
        # Log Event-
        Write-Log -eventTag "Performance Constraints" -eventSubTag "-" -severityLevel "info" -messages "PERF CONSTRAINTS: Verified this process is set to a low CPU priority (PID $thisProcessId)" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost -DoNotLogToSplunkHec

    } Else {
        
        # Log Event
        Write-Log -eventTag "Performance Constraints" -eventSubTag "-" -severityLevel "warn" -messages "PERF CONSTRAINTS: Something went wrong setting process ID $thisProcessId to a low CPU priority. Script still running but you'll want to see if this is a larger issue. Additional Info: priorityClass="$thisPowerShellProcess.PriorityClass" processorAffinity="$thisPowerShellProcess.ProcessorAffinity"" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost
    }

#endregion PERFORMANCE CONSTRAINTS




##############################################################################################################################################################################
#region   PERSONA TARGETTING   ###############################################################################################################################################
##############################################################################################################################################################################

    # Here's how this works. We want some modules to only run on certain types of machines. Certain types of machines means we may only want to run modules on an HR machine, 
    # an IT machine or an accounting machine, etc. Many companies don't have a better way of quickly and easily determining the role of the asset. The best generic way to 
    # determine this is to understand who the primary user of the machine is and from there determine which function and department that individual is from. Once we know the 
    # user, we can ask the Backstop server the hashed values of the business function, the department and the title of that user so we can key off any of them to make more 
    # targetted deployments. In this way, we can say "well the primary user of the machine is from Accounting, so there's at least a good chance that this is an Accounting 
    # machine". It's not perfect and users move around but while I'm open to better options, this is the best way I can think of to key off of the type of machine generically.
    # Also, it's important to stess that all of these values are hashed, including the username and all of the results coming back. I don't want the Backstop server having an
    # easy list of identify mappings. This approach assumes 

    # Check if we have the persona.json file and check if it's in a valid JSON format. If either are untrue, create a new one.
    if((Test-Path -Path "$rootPath\etc\persona.json")   -and   ([System.String](Get-Content -Path "$rootPath\etc\persona.json" -Raw) | Test-Json -ErrorAction SilentlyContinue))
    {
        # Import the persona.json file if they file is a valid JSON file
        $persona = Get-Content -Path "$rootPath\etc\persona.json" | ConvertFrom-Json

        # Log Event
        Write-Log -eventTag "Persona Import" -eventSubTag "-" -severityLevel "info" -messages "IMPORT: Found persona.json and imported it" -DoNotLogToSplunkHec

    } Else {

        # Create the initial persona array (blank)
        $persona = @()

        # Define an old date so the persona will be updated
        $oldDate = (Get-Date).AddDays(-90)

        # Update the persona file to (basically blank)
        $localPersonaDetails = [PSCustomObject][ordered]@{
            personaLastCheckedDate = "$oldDate"
            determinedByLogonType = "firstRunNothingPopulated"
            primaryUsernameHash = "firstRunNothingPopulated"
            primaryUserFunctionHash = "firstRunNothingPopulated"
            primaryUserDepartmentHash = "firstRunNothingPopulated"
            primaryUserJobTitleHash = "firstRunNothingPopulated"
            primaryUserManager1Hash = "firstRunNothingPopulated"
            primaryUserManager2Hash =  "firstRunNothingPopulated"
        }

        # Add localPersonaDetails to the persona array we can call later
        $persona += $localPersonaDetails
    }

    # Define today's date
    $todaysDate = Get-Date

    # Update the persona if it hasn't been updated in the last N number of days (will also run for new persona files as well)
    if(($todaysDate - [datetime]$persona.personaLastCheckedDate).Days -ge 15)
    {
        # Get the most recent 10,000 log events and within that, look for type 7 (Windows unlock events). Type 7 logon events are better than type 2 (initial console logons)
        # since there's more of them and we can better deduce who's actually using the machine the most. The user who uses the machine the most will be the primary user.
        # Usually this takes ~15-20 seconds to pull depending on the amount of logs and the machine.
        $logonEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 10000 -ErrorAction SilentlyContinue | Where-Object {$_.Properties[8].Value -eq 7}

        # We can usually assume that the type 7 logon search will work more often than not but if it doesn't, try via type 2 instead.
        if($logonEvents)
        {
            # Define how the primary user was determined
            $determinedByLogonType = 7

        } Else {

            Write-Log -eventTag "Persona Creation" -eventSubTag "-" -severityLevel "warn" -messages "Unable to get any type 7 (screen unlock) logins. Trying for type 2's instead..." -DoNotLogToSplunkHec -WriteHost
            $logonEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 10000 | Where-Object {$_.Properties[8].Value -eq 2}

            # Define how the primary user was determined
            $determinedByLogonType = 2
        }

        # Process the logonEvents
        if($logonEvents)
        {
            # Extract usernames from the events and group them
            $userCounts = $logonEvents | Where-Object {$_.Properties[5].Value -ne "ANONYMOUS LOGON"} | Group-Object {$_.Properties[5].Value}

            # Sort the groups by count in descending order and get the top user. Also remove service account names like DWM-14, UMFD-4 or lenovo_tmp_tblwD49. Finally, ensure that 
            # the user matches YOUR naming format. Will vary from company to company.
            $localUser = ($userCounts | Where-Object {$_.Name -notmatch "[a-zA-Z]{1,10}\-\d{1,3}|lenovo|dell"   -and   $_.Name -match "\."} | Sort-Object Count -Descending | Select-Object -First 1).Name

            # Switch $localUser to lowercase
            $localUser = $localUser.ToLower()

            if($localUser)
            {
                # Get hash of the primary local user
                $primaryUsernameHash =  Get-StringHash -String "$localUser" -HashType PBKDF2 -PBKDF2Salt "backstop"

                # Get additional details from the Backstop server for Function, Department and Job Title hashes.
                $serverPersonaDetails = Invoke-RestMethod -Method GET -Uri "https://$backstopAPIServerName/backstop/getPersona/v1" -Headers @{apiKey = "$backstopCommonApiKey_vaultSecret"; clientHostname = $env:COMPUTERNAME; scriptHash = $scriptFileHashSHA256; hashedUsername = "$primaryUsernameHash"} -UserAgent $userAgent -ErrorVariable webRequestError

                # Define the last checked date. This command is somewhat expensive so we don't want to run it all the time.
                $personaLastCheckedDate = (Get-date).ToString()

                # Update the persona file
                $localPersonaDetails.personaLastCheckedDate = $personaLastCheckedDate
                $localPersonaDetails.determinedByLogonType = $determinedByLogonType
                $localPersonaDetails.primaryUsernameHash = $primaryUsernameHash
                $localPersonaDetails.primaryUserFunctionHash = $serverPersonaDetails.hashedFunction
                $localPersonaDetails.primaryUserDepartmentHash = $serverPersonaDetails.hashedDepartment
                $localPersonaDetails.primaryUserJobTitleHash = $serverPersonaDetails.hashedTitle
                $localPersonaDetails.primaryUserManager1Hash = $serverPersonaDetails.hashedManager1
                $localPersonaDetails.primaryUserManager2Hash = $serverPersonaDetails.hashedManager2

                # Export to persona file and overwrite it if it already exists (likely bad format for some reason)
                $persona | ConvertTo-Json | Out-File -Path "$rootPath\etc\persona.json" -Force
            }
        }

        # If we're unable to aquire the logonEvents or the localUser from those events, mark as such in the persona JSON file.
        if((-Not $logonEvents)   -or   (-Not $localUser))
        {
            # Define the last checked date. This command is somewhat expensive so we don't want to run it all the time.
            $personaLastCheckedDate = (Get-date).ToString()

            # Update the persona file
            $localPersonaDetails.personaLastCheckedDate = "$personaLastCheckedDate"
            $localPersonaDetails.determinedByLogonType = "unableToAquire"
            $localPersonaDetails.primaryUsernameHash = "unableToAquire"
            $localPersonaDetails.primaryUserFunctionHash = "unableToAquire"
            $localPersonaDetails.primaryUserDepartmentHash = "unableToAquire"
            $localPersonaDetails.primaryUserJobTitleHash = "unableToAquire"
            $localPersonaDetails.primaryUserManager1Hash = "unableToAquire"
            $localPersonaDetails.primaryUserManager2Hash = "unableToAquire"

            # Export to persona file and overwrite it if it already exists (likely bad format for some reason)
            $persona | ConvertTo-Json | Out-File -Path "$rootPath\etc\persona.json" -Force
        }
    }

#endregion PERSONA TARGETTING




##############################################################################################################################################################################
#region   FILE UPDATE CHECK   ################################################################################################################################################
##############################################################################################################################################################################

    # Iterate through the manifest hash list to check if we should download new versions of scripts or binaries
    foreach ($item in $manifest.hashList.Values)
    {
        # Extract the variables we need from each individual item
        $fileName = $item.fileName
        $localDirectoryName = $item.localDirectoryName
        $remoteSHA256FileHash = $item.remoteSHA256FileHash

        # If Invoke-BFF.ps1 needs to be updated, we'll do this at the very end of this script (less risky).
        if($fileName -eq "Invoke-BFF.ps1")
        {
            # Break out of loop
            Continue
        }

        # Get the local hash of the file if it exists. We'll need this so we can compare our local hash to that of the remote file hash. Here we assume that the remote file
        # hash is the correct and most up-to-date one. The API server knows where the local path should be (along with the download path if it needs to be downloaded) and is
        # provided as part of the   manifest file.
        if(Test-Path -Path "$rootPath\$localDirectoryName\$fileName")
        {
            # This should only be referenced if there's a hash mismatch
            $fileDisposition = "localFileNeedsUpdate"
            $localSHA256FileHash = (Get-FileHash -Path "$rootPath\$localDirectoryName\$fileName" -Algorithm SHA256).Hash

        } Else {

            $fileDisposition = "localFileWasMissing"
            $localSHA256FileHash = "missing" 
        }

        # OK we need to be careful here because we can't get into a loop of constantly downloading bad files. We're going to check if the file (first downloaded to the temp directory)
        # has a correct signature. If it doesn't this script will just keep trying to download the bad file over and over again on each run. While alerting should be setup for this, 
        # we need to think about needless extra cycles and certainly the load on the API server. Let's look to see if the file is still in temp folder and if so, what the last write
        # time of the file is. If a file wasn't moved out of the temp folder, it likely means that it's bad. Ok well if it's bad, let's wait a day before trying to download it again.
        if(Test-Path -Path "$rootPath\temp\$fileName")
        {
            # Get current date + the last write date on the file found. Note that we care more about the day vs. the actual time.
            $today = (Get-Date).date
            $tempFileLastWriteDate = (Get-ChildItem -Path "$rootPath\temp\$fileName").LastWriteTime

            if($tempFileLastWriteDate -eq $today)
            {
                # Log Event
                Write-Log -eventTag "File Update Check" -eventSubTag "Break Loop" -severityLevel "warn" -messages "LOOP CHECK: File $fileName still in temp directory found to be bad and will not be downloaded again today. Additional Info: localSHA256FileHash=$localSHA256FileHash" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel  -WriteHost

                # Break out of loop for this specific item and continue to the next item (skip this specific file until tomorrow)
                Continue
            }
        }

        # If the hashes don't match or if the file was missing locally, download the file if $backstopServerIsReachable 
        if((($localSHA256FileHash -ne $remoteSHA256FileHash)   -or   ($fileDisposition -eq "localFileWasMissing"))   -and   ($backstopServerIsReachable))
        {
            # Download file
            try
            {
                # Log Event
                Write-Log -eventTag "File Update Check" -eventSubTag "-" -severityLevel "info" -messages "FILE DOWNLOAD: Downloading $fileName since it was missing or has been updated - see fileDisposition for which. Additional Info: fileDisposition=$fileDisposition localSHA256FileHash=$localSHA256FileHash remoteSHA256FileHash=$remoteSHA256FileHash" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -DoNotLogToSplunkHec -WriteHost

                # Download manifest file and overwrite local copy if present. Also, capture the response to see if we get a 200 OK. This ensures the file was downloaded.
                Invoke-RestMethod -Method GET -Uri "https://$backstopAPIServerName/backstop/getfiles/v1" -Headers @{apiKey = "$backstopCommonApiKey_vaultSecret"; clientHostname = $env:COMPUTERNAME; scriptHash = $scriptFileHashSHA256; "Accept-Encoding"="gzip"; fileName =$fileName} -OutFile "$rootPath\temp\$fileName" -UserAgent $userAgent -ErrorVariable webRequestError

            } catch {

            # Parse out just the status code text for the specific error
            $webRequestError = $webRequestError.InnerException.Response.StatusCode
    
                # Log Event
                Write-Log -eventTag "File Update Check" -eventSubTag "-" -severityLevel "error" -messages "FILE DOWNLOAD: Backstop API server was reachable but unable to download manifest.ps1xml. Will try and use local copy instead if it exists. Additional Info: webRequestError=$webRequestError" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel  -WriteHost
            }

            # If no webRequestError, confirm signature
            if(-not($webRequestError))
            {
                Confirm-Authenticode -FilePath "$rootPath\temp\$fileName" -Thumbprint $validBackstopCodeSigningThumbprint

                # If signature valid, move file to correct directory and overwrite existing file
                if($signatureVerified)
                {
                    # Move file
                    Move-Item -Path "$rootPath\temp\$fileName" -Destination "$rootPath\$localDirectoryName\$fileName" -Force

                    # Log Event
                    Write-Log -eventTag "File Update Check" -eventSubTag "File Moved" -severityLevel "info" -messages "FILE UPDATED: File $fileName was successfully downloaded and signature verified. File has been moved from temp to \$localDirectoryName" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -DoNotLogToSplunkHec

                } Else {

                    # Log Event
                    Write-Log -eventTag "File Update Check" -eventSubTag "File Verification Failed" -severityLevel "error" -messages "SIGNATURE VALIDATION: File $fileName signature invalid. Keeping in temp directory." -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel
                }
            }
        }
    }

#endregion FILE UPDATE CHECK




##############################################################################################################################################################################
#region   IMPORT & EXECUTE MODULES   #########################################################################################################################################
##############################################################################################################################################################################

    # Define the path to the state file
    $stateFilePath = "$rootPath\etc\state.json"

    # Create a simple and empty state array which we can add PSCustomObject's to
    $state = @()

    # It's crucial to know the last time the module ran so we can honor the settings in the modules which tell this script how often the modules should be run. Here's where 
    # we import the local state file which acts as a memory for this script which would otherwise be stateless. If it doesn't exist, no problem, we'll just create it later. 
    # Also, we need to test the state variable to ensure that it's in a valid JSON format.
    if((Test-Path -Path $stateFilePath) -and ([System.String](Get-Content -Path $stateFilePath -Raw) | Test-Json -ErrorAction SilentlyContinue))
    {
        # Capture it as a variable
        $importedStateFile = Get-Content -Path $stateFilePath

        # Import the string as JSON but this makes it a PSCustomObject
        $importedStateFile = $importedStateFile | ConvertFrom-Json

        # Add to $state array
        $state += $importedStateFile

    } Else {

        # Log Event
        Write-Log -eventTag "Import and Execute Modules" -eventSubTag "-" -severityLevel "warn" -messages "IMPORT: The state file was either missing or corrupt. Will create it from scratch." -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel
    }

    # Get the module names
    $moduleNames = ($manifest.hashList.Values | Where-Object {$_.localDirectoryName -eq "modules"}).fileName -replace('.psm1','')

    # Iterate through each module in the manifest list
    foreach ($Global:moduleName in $moduleNames)
    {
        # Confirm module is correctly signed and signed by the Backstop cert
        if($moduleName -like "ClientCore*")
        {
            # This is a support module we don't want to execute. Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any
            Continue
        }

        # Confirm module is correctly signed and signed by the Backstop cert
        if(Test-Path -Path "$rootPath\modules\$moduleName.psm1")
        {
            Confirm-Authenticode -FilePath "$rootPath\modules\$moduleName.psm1" -Thumbprint $validBackstopCodeSigningThumbprint

        } Else {

            # Log Event
            Write-Log -eventTag "Import and Execute Modules" -eventSubTag "-" -severityLevel "warn" -messages "FILE MISSING: Module $moduleName.psm1 not found on disk so skipping it." -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel

            # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any
            Continue
        }

        # Execute the function if correctly signed. Note that the variable signatureVerified comes from function Confirm-Authenticode within the ClientCore module if the file is correctly signed. 
        if($signatureVerified)
        {
            # Import the module. This will also import all the module option variables as well such as if Splunk HEC is required or only run it once, etc. The -Force flag is critical (especially for testing) as it overwrites the existing module if present. 
            Import-Module "$rootPath\modules\$moduleName.psm1" -Force

            # Check if the imported state file has information about this module in it already. If not, just add it dynamically.
            if(($state | Where-Object {$_.moduleName -eq $moduleName}) -and (($state | Where-Object {$_.moduleName -eq $moduleName}).lastRunTime))
            {
                # Looks like the state file knows about the module already and has a lastRunTime. Now, extract the last run time from the state file. Here we'll key off of the module 
                # name to ensure we get the right lastRunTime for the right module. Also grab the executionCount as well - critical for runOnce functionality.
                $lastRunTime = ($state | Where-Object {$_.moduleName -eq $moduleName}).lastRunTime
                $executionCount = ($state | Where-Object {$_.moduleName -eq $moduleName}).executionCount

            } Else {

                # Set an older date where it likely won't exceed the runIntervalInSeconds variable.
                $lastRunTime = (Get-Date).AddDays(-14)

                # Create a new object for this module but note that for safety, we'll require it to have connectivity back to the Backtop API server by default. Again, this is to ensure that if something
                # goes wrong (we need to update the module due to bugs) we not only want to ensure that we have a chance to pickup the updated copy but also get telemetry about it centrally in Splunk.
                $stateProperty = New-Object -TypeName PSCustomObject -Property @{moduleName="$moduleName";lastRunTime="$lastRunTime";executionCount=0}
                $requireBackstopAPIReachability = $True

                # Add the above module to the $state variable. Later, we'll write that back out to disk to be picked up on the next run
                $state += $stateProperty
            }

            # Use the Compare-Times function found in the ClientCore module to see if this module should run or not. This function compares the time delta between now and the 
            # variable lastRunTime. After it figures out the time delta (how much time, in seconds, between the two), it then sees if the that time delta is > the runIntervalInSeconds
            # variable. If it is, the Compare-Times function sets the variable $readyToRun to $true.
            Compare-Times -LastRunDateTime $lastRunTime


            ##################################################################################################################################################################
            #region   OPTIONS AND CONSTRAINTS   ##############################################################################################################################
            ##################################################################################################################################################################

                # Ok, this gets complicated so let's break it down. Remember, all these variables come from only two places: the module itself (via Export-ModuleMember -Variable *) 
                # and the variable that comes back from the function Compare-Times called $readyToRun. We only want to run the modules function(s) in the following conditions:
                # 1. First group BEFORE the OR: If it's ready to run but does not have runOnce set to 1 (see below for how we handle runOnce functions)
                # 2. Second group AFTER the OR: If it's ready to run and has runOnce set to 1 (see below for how we handle runOnce functions) and an 
                #    executionCount value of "0" indicating that it hasn't run yet.
                if((($readyToRun) -and (-not($runOnce)))   -or   (($readyToRun) -and ($runOnce) -and ($executionCount -lt 1)))
                {

                    ##########################################################################################################################################################
                    #region   THE RULES   ####################################################################################################################################
                    ##########################################################################################################################################################

                        # Now we get to "the rules". Conceptually, this is fairly simple. We're going to run the module UNLESS one of these rules or "gate keepers" gets in the
                        # way and skips it ("Continue"). The rules are designed to enforce the constraints set within the module itself. For example, if you only want to run a 
                        # module on an asset that matches a "businessUnitScope" of "EXAMPLE" then a rule below will see that "businessUnitScope" is not equal to "any" and will
                        # then see if the local asset matches the businessUnitScope of "EXAMPLE". If not, skip the module and move on the next module.

                        # Ensure that if we require the Backstop API server to be reachable (requireBackstopAPIReachability) that it IS reachable (backstopServerIsReachable)
                        if(($requireBackstopAPIReachability)   -and   ($backstopServerIsReachable -eq $false))
                        {
                            # Log Event
                            Write-Log -eventTag "Import and Execute Modules" -eventSubTag "-" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped. Additional Info: moduleName=$moduleName requireBackstopAPIReachability=$requireBackstopAPIReachability backstopServerIsReachable=$backstopServerIsReachable" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel

                            # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any. Even though this would be the end of the code anyway (as originally written), putting this in anyway in case more is added below.
                            Continue
                        }


                        # Randomization Check. If module wants to be run at random, perform a randomization lottery check and only run if the result is $True.
                        if($enableRandomization)
                        {
                            # Define the winning number - if lotteryTicketNumber matches winningNumber, module will run. winningNumber always set to 1 since maxRandomEntropy (also 
                            # set in the backstop module) should be a minimum of 100.
                            $winningNumber = 1

                            # The maxRandomEntropy variable is populated from the module itself. Each module has it's own custom settings, this being one of them.
                            $lotteryTicketNumber = Get-Random -Minimum 0 -Maximum $maxRandomEntropy

                            if($lotteryTicketNumber -ne $winningNumber)
                            {
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "Randomization Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 did NOT win the lottery during randomization check and will NOT be executed. Additional Info: winningNumber=$winningNumber lotteryTicketNumber=$lotteryTicketNumber maxRandomEntropy=$maxRandomEntropy" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "Randomization Check" -severityLevel "info" -messages "MODULE WON: Module $moduleName.psm1 won the lottery during randomization check and will be executed if no other options deny it. Additional Info: winningNumber=$winningNumber lotteryTicketNumber=$lotteryTicketNumber maxRandomEntropy=$maxRandomEntropy" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                            }
                        }


                        # Scope Check. If osClass is anything other than "any", break out of the loop if it's not what the module wants. Here, the singular osClass variable comes from the ClientCore module.
                        if($osClass -ne "any")
                        {
                            # Workstation Scope check
                            if(($osClass -eq "workstation") -and ($osClass -ne "workstation"))
                            {
                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: $moduleName.psm1 was skipped since it didn't pass the general workstation scope check. Additional Info: osClass=$osClass osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the general workstation scope check. Additional Info: osClass=$osClass osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
                            }

                            # Server Scope check
                            if(($osClass -eq "server") -and ($osClass -ne "server"))
                            {
                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped since it didn't pass the general server scope check. Additional Info: osClass=$osClass osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the general server scope check. Additional Info: osClass=$osClass osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                            }

                            # Hostname Check. Here we can match based on a partial match or the whole hostname. For example, if the generalScope value is "WKS-US-TX-Arlington-" then the hostname of of the asset must at least *start with* that
                            # or this script will skip this module and go on to the next. If there is a match, the module will be processed (won't break out of the loop). This will also work with the whole hostname as well if you want 
                            # to target something more specifically.
                            if(($osClass -notmatch "workstation|server") -and ("$env:COMPUTERNAME" -notmatch "^$osClass(.+){0,15}"))
                            {
                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped since it didn't pass the general hostname scope check. Additional Info: osClass=$osClass osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the general hostname scope check. Additional Info: osClass=$osClass osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                            }
                        }


                        # Domain Scope check. Here, we're saying "if you specified a specific domain (it's not "any" but something else), break out of the loop if the domain you specified doesn't match the assets domain. This is just a "break things if no match" rule.
                        if($adDomain -ne "any")
                        {
                            # Domain Scope check.
                            if($adDomain -ne $adDomain)
                            {
                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "Domain Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped since it didn't pass the domain scope check. Additional Info: adDomain=$adDomain adDomain=$adDomain" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the domain scope check. Additional Info: adDomain=$adDomain adDomain=$adDomain" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
                            }
                        }


                        # Business unit scope check. 
                        if($businessUnitScope -ne "any")
                        {
                            # Business unit scope check. If the businessUnitScope specified in the module is not equal to the businessUnit that the asset is on, skip it. Else proceed to try and execute the module.
                            if($businessUnitScope -ne $businessUnit)
                            {
                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "Business Unit Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped since it didn't pass the business unit scope check. Additional Info: businessUnitScope=$businessUnitScope businessUnit=$businessUnit" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "Business Unit Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the business unit scope check. Additional Info: businessUnitScope=$businessUnitScope businessUnit=$businessUnit" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
                            }
                        }


                        # primaryUserFunctionHash hash scope check
                        if($primaryUserFunctionHash -ne "any")
                        {
                            # If the hash doesn't match the local persona hash, skip it. Else proceed to try and execute the module.
                            if($primaryUserFunctionHash -ne $persona.primaryUserFunctionHash)
                            {
                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUserFunctionHash Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped because a specific hash was specified but the hashes didn't match. Additional Info: primaryUserFunctionHash=$primaryUserFunctionHash persona.primaryUserFunctionHash=$($persona.primaryUserFunctionHash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUserFunctionHash Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the specific hash specified. Additional Info: primaryUserFunctionHash=$primaryUserFunctionHash persona.primaryUserFunctionHash=$($persona.primaryUserFunctionHash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
                            }
                        }


                        # primaryUserDepartmentHash hash scope check
                        if($primaryUserDepartmentHash -ne "any")
                        {
                            # If the hash doesn't match the local persona hash, skip it. Else proceed to try and execute the module.
                            if($primaryUserDepartmentHash -ne $persona.primaryUserDepartmentHash)
                            {
                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUserDepartmentHash Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped because a specific hash was specified but the hashes didn't match. Additional Info: primaryUserDepartmentHash=$primaryUserDepartmentHash persona.primaryUserDepartmentHash=$($persona.primaryUserDepartmentHash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUserDepartmentHash Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the specific hash specified. Additional Info: primaryUserDepartmentHash=$primaryUserDepartmentHash persona.primaryUserDepartmentHash=$($persona.primaryUserDepartmentHash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
                            }
                        }


                        # primaryUserJobTitleHash hash scope check
                        if($primaryUserJobTitleHash -ne "any")
                        {
                            # If the hash doesn't match the local persona hash, skip it. Else proceed to try and execute the module.
                            if($primaryUserJobTitleHash -ne $persona.primaryUserJobTitleHash)
                            {
                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUserJobTitleHash Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped because a specific hash was specified but the hashes didn't match. Additional Info: primaryUserJobTitleHash=$primaryUserJobTitleHash persona.primaryUserJobTitleHash=$($persona.primaryUserJobTitleHash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUserJobTitleHash Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the specific hash specified. Additional Info: primaryUserJobTitleHash=$primaryUserJobTitleHash persona.primaryUserJobTitleHash=$($persona.primaryUserJobTitleHash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
                            }
                        }


                        # primaryUsernameHash hash scope check
                        if($primaryUsernameHash -ne "any")
                        {
                            # If the hash doesn't match the local persona hash, skip it. Else proceed to try and execute the module.
                            if($primaryUsernameHash -ne $persona.primaryUsernameHash)
                            {
                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUsernameHash Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped because a specific hash was specified but the hashes didn't match. Additional Info: primaryUsernameHash=$primaryUsernameHash persona.primaryUsernameHash=$($persona.primaryUsernameHash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUsernameHash Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the specific hash specified. Additional Info: primaryUsernameHash=$primaryUsernameHash persona.primaryUsernameHash=$($persona.primaryUsernameHash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
                            }
                        }


                        # primaryUserManager1Hash hash scope check
                        if($primaryUserManager1Hash -ne "any")
                        {
                            # If the hash doesn't match the local persona hash, skip it. Else proceed to try and execute the module.
                            if($primaryUserManager1Hash -ne $persona.primaryUserManager1Hash)
                            {
                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUserManager1Hash Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped because a specific hash was specified but the hashes didn't match. Additional Info: primaryUserManager1Hash=$primaryUserManager1Hash persona.primaryUserManager1Hash=$($persona.primaryUserManager1Hash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUserManager1Hash Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the specific hash specified. Additional Info: primaryUserManager1Hash=$primaryUserManager1Hash persona.primaryUserManager1Hash=$($persona.primaryUserManager1Hash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
                            }
                        }


                        # primaryUserManager2Hash hash scope check
                        if($primaryUserManager2Hash -ne "any")
                        {
                            # If the hash doesn't match the local persona hash, skip it. Else proceed to try and execute the module.
                            if($primaryUserManager2Hash -ne $persona.primaryUserManager2Hash)
                            {
                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUserManager2Hash Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped because a specific hash was specified but the hashes didn't match. Additional Info: primaryUserManager2Hash=$primaryUserManager2Hash persona.primaryUserManager2Hash=$($persona.primaryUserManager2Hash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec

                                # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                                Continue

                            } Else {

                                # Log Event
                                Write-Log -eventTag "Import and Execute Modules" -eventSubTag "primaryUserManager2Hash Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the specific hash specified. Additional Info: primaryUserManager2Hash=$primaryUserManager2Hash persona.primaryUserManager2Hash=$($persona.primaryUserManager2Hash)" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
                            }
                        }

                    #endregion THE RULES


                    # Dynamically determine the function name(s)
                    $Global:functionNames = (Get-Command -Module $moduleName | Where-Object {$_.CommandType -eq "Function"}).name

                    #Execute each function within the module and consider their constraints.
                    foreach ($functionName in $functionNames)
                    {
                        # Ensure functionName is global so it's correctly picked up by Write-Log function
                        $Global:functionName = $functionName

                            # Log Event
                            Write-Log -eventTag "Import and Execute Modules" -eventSubTag "Executing Module" -severityLevel "info" -messages "EXECUTING MODULE: $moduleName.psm1" -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel

                            # Start Metrics
                            Get-Metrics -Start

                            # Execute: It's About Time!
                            & $functionName

                            # Stop Metrics and Send to Splunk
                            Get-Metrics -Stop

                        # Update last run time with the current data and increment by one for the execution counts
                        ($state | Where-Object {$_.moduleName -eq $moduleName}).lastRunTime = get-date
                        
                        # Update executionCount key value to int32 so we can add to it
                        ($state | Where-Object {$_.moduleName -eq $moduleName}).executionCount = [Int32]($state | Where-Object {$_.moduleName -eq $moduleName}).executionCount 

                        # Increment count by one
                        ($state | Where-Object {$_.moduleName -eq $moduleName}).executionCount += 1
                    }

                # Didn't match initial check
                } Else {

                    # Log Event
                    Write-Log -eventTag "Import and Execute Modules" -eventSubTag "-" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped. Additional Info: moduleName=$moduleName executionCount=$executionCount moduleEnabled=$moduleEnabled readyToRun=$readyToRun runOnce=$runOnce runIntervalInSeconds=$runIntervalInSeconds lastRunTime=$lastRunTime" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel

                    # Skip this itteration and go on to next module in the loop
                    Continue
                }

            #endregion OPTIONS AND CONSTRAINTS

            # Flush all the variables from this module so they won't in any way persist to the next module in the loop.
            $moduleVariables = (Get-Module $moduleName).ExportedVariables.Keys

            # Perform courtesy flush for each variable the module imported
            foreach ($moduleVariable in $moduleVariables)
            {
                Remove-Variable $moduleVariable
            }

        } Else {

            # Log Event
            Write-Log -eventTag "Import and Execute Modules" -eventSubTag "-" -severityLevel "error" -messages "SIGNATURE VALIDATION: Found missing or incorrect Backstop cert thumbprint for module $moduleName. Skipping this module. Additional Info: validBackstopCodeSigningThumbprint=$validBackstopCodeSigningThumbprint fileSignatureThumbprint=$fileSignatureThumbprint fileSignatureStatus=$fileSignatureStatus." -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel 

            # Skip this itteration and go on to next module in the loop
            Continue
        }
    }

#endregion IMPORT & EXECUTE MODULES




##############################################################################################################################################################################
#region   UPDATE STATE FILE   ################################################################################################################################################
##############################################################################################################################################################################

    # Cleanup items in the state file that haven't run in the last N number days starting by defining how old you want any item to be in the state file before it's removed.
    $maxStateItemAgeInDays = 45

    # Define the cutoff date (anything older will be dropped)
    $45DaysAgo = (Get-Date).AddDays(-$maxStateItemAgeInDays)

    # Make a fresh state file that doesn't contain the old items and then write that back to disk. The reason why this is done is that we want the ability to forget things 
    # from N number of days ago. If something shouldn't be running, it needs to be taken out of the manifest file.
    $freshStateFile = $state | Where-Object {[DateTime]$_.lastRunTime -gt $45DaysAgo}

    # Define the module(s) being removed if any
    $removedModules = (Compare-Object $state $freshStateFile | Where-Object {$_.SideIndicator -eq "<="}).InputObject

    # Log each removal if there are any
    if($removedModules)
    {
        foreach ($module in $removedModules)
        {
            # Define the name of the module and it's last run time
            $moduleName = $module.moduleName
            $moduleLastRunTime = $module.lastRunTime

            # Log Event
            Write-Log -eventTag "Update State File" -eventSubTag "-" -severityLevel "info" -messages "CLEANUP: Module $moduleName with last run time of $moduleLastRunTime have been removed from the state file as they were older than $maxStateItemAgeInDays days." -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
        }
    }

    # Update State File
    $freshStateFile | ConvertTo-Json | Out-File -FilePath "$rootPath\etc\state.json" -Force

#endregion UPDATE STATE FILE  




##############################################################################################################################################################################
#region   LOG ROTATE   #######################################################################################################################################################
##############################################################################################################################################################################

    # Define the maximum file size you want the primary messages.log file to be. After this limit, the file will be rotated.
    $maxFileSizeInMB = 20

    # Rotate if file exceeds maxFileSizeInMB. First we need to check it's length (in bytes) then devide by 1024 twice to get the MB's
    if((Get-ChildItem $CustomLocalLogPath).Length /1024/1024 -gt $maxFileSizeInMB)
    {
        # Check if the path exists (won't on first time rotate) and if so, remove the old rotated file.
        if(Test-Path "$CustomLocalLogPath.rolled")
        {
            # Remove the old backup first
            Remove-Item "$CustomLocalLogPath.rolled" -Force
        }

        # Rotate even though we didn't hit V1
        Rename-Item -Path $CustomLocalLogPath -NewName "$CustomLocalLogPath.rolled"
    }

#endregion LOG ROTATE  




##############################################################################################################################################################################
#region   UPDATE INVOKE-BFF   ################################################################################################################################################
##############################################################################################################################################################################

    # Here, we update this script itself. So it's going to seem really strange to replace the script we're running - as it's running but this has been tested extensively. 
    # Another mitigating factor is that we're running this as the last part of the script. We don't want to update it mid way through.

    # Get the local file hash of Invoke-BFF.ps1
    $localSHA256FileHash = (Get-FileHash -Path "$rootPath\scripts\Invoke-BFF.ps1" -Algorithm SHA256).Hash

    # Get the remote hash of Invoke-BFF.ps1
    $remoteSHA256FileHash = ($manifest.hashList.Values | Where-Object {$_.fileName -eq "Invoke-BFF.ps1"}).remoteSHA256FileHash

    # Compare and download updated file if hash mismatch
    if($localSHA256FileHash -ne $remoteSHA256FileHash)
    {       
        # Download file
        try
        {
            # Log Event
            Write-Log -eventTag "File Update Check" -eventSubTag "-" -severityLevel "info" -messages "FILE DOWNLOAD: Local hash for Invoke-BFF.ps1 different from server hash. Downloading Invoke-BFF.ps1" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost

            # Download manifest file and overwrite local copy if present. Also, capture the response to see if we get a 200 OK. This ensures the file was downloaded.
            Invoke-RestMethod -Method GET -Uri "https://$backstopAPIServerName/backstop/getfiles/v1" -Headers @{apiKey = "$backstopCommonApiKey_vaultSecret"; clientHostname = $env:COMPUTERNAME; scriptHash = $scriptFileHashSHA256; "Accept-Encoding"="gzip"; fileName = "Invoke-BFF.ps1"} -OutFile "$rootPath\temp\Invoke-BFF.ps1" -UserAgent $userAgent -ErrorVariable webRequestError

        } catch {

            # Parse out just the status code text for the specific error
            $webRequestError = $webRequestError.InnerException.Response.StatusCode

            # Log Event
            Write-Log -eventTag "File Update Check" -eventSubTag "-" -severityLevel "error" -messages "FILE DOWNLOAD: Backstop API server was reachable but unable to download updated version of Invoke-BFF.ps1. Additional Info: webRequestError=$webRequestError" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost
        }

        # If no webRequestError, confirm signature
        if(-not($webRequestError))
        {
            Confirm-Authenticode -FilePath "$rootPath\temp\Invoke-BFF.ps1" -Thumbprint $validBackstopCodeSigningThumbprint

            # If signature valid, move file to correct directory and overwrite existing file
            if($signatureVerified)
            {
                # Move file
                Move-Item -Path "$rootPath\temp\Invoke-BFF.ps1" -Destination "$rootPath\scripts\Invoke-BFF.ps1" -Force

                # Log Event
                Write-Log -eventTag "File Update Check" -eventSubTag "File Moved" -severityLevel "info" -messages "FILE UPDATED: File Invoke-BFF.ps1 was successfully downloaded and signature verified. File has been moved from temp to \scripts" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost

                # Verify hashes match now
                $localSHA256FileHash = (Get-FileHash -Path "$rootPath\scripts\Invoke-BFF.ps1" -Algorithm SHA256).Hash

                if($localSHA256FileHash -ne $remoteSHA256FileHash)
                {
                    # Log Event
                    Write-Log -eventTag "File Update Check" -eventSubTag "BFF Update" -severityLevel "info" -messages "FILE UPDATED: File Invoke-BFF.ps1 was successfully updated with the new version" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel
                }

            } Else {

                # Log Event
                Write-Log -eventTag "File Update Check" -eventSubTag "File Verification Failed" -severityLevel "error" -messages "SIGNATURE VALIDATION: File Invoke-BFF.ps1 signature invalid. Keeping in temp directory." -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel
            }
        }
    }

#endregion UPDATE INVOKE-BFF




##############################################################################################################################################################################
#region   SIGNATURE BLOCK   ##################################################################################################################################################
##############################################################################################################################################################################


