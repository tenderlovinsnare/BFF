<#
                        ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗ ██████╗ ██████╗      █████╗ ██████╗ ██╗                     
                        ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗    ██╔══██╗██╔══██╗██║                     
                        ██████╔╝███████║██║     █████╔╝ ███████╗   ██║   ██║   ██║██████╔╝    ███████║██████╔╝██║                     
                        ██╔══██╗██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██║   ██║██╔═══╝     ██╔══██║██╔═══╝ ██║                     
                        ██████╔╝██║  ██║╚██████╗██║  ██╗███████║   ██║   ╚██████╔╝██║         ██║  ██║██║     ██║                     
                        ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝         ╚═╝  ╚═╝╚═╝     ╚═╝                     
                                                                                                                                    
    ███████╗███╗   ██╗██████╗ ██████╗  ██████╗ ██╗███╗   ██╗████████╗███████╗    ███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗██╗     ███████╗
    ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║████╗  ██║╚══██╔══╝██╔════╝    ████╗ ████║██╔═══██╗██╔══██╗██║   ██║██║     ██╔════╝
    █████╗  ██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║██╔██╗ ██║   ██║   ███████╗    ██╔████╔██║██║   ██║██║  ██║██║   ██║██║     █████╗  
    ██╔══╝  ██║╚██╗██║██║  ██║██╔═══╝ ██║   ██║██║██║╚██╗██║   ██║   ╚════██║    ██║╚██╔╝██║██║   ██║██║  ██║██║   ██║██║     ██╔══╝  
    ███████╗██║ ╚████║██████╔╝██║     ╚██████╔╝██║██║ ╚████║   ██║   ███████║    ██║ ╚═╝ ██║╚██████╔╝██████╔╝╚██████╔╝███████╗███████╗
    ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝    ╚═╝     ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝


    .SYNOPSIS
      Contains all the API endpoints for the Backstop Flexibility Framework


    .DESCRIPTION
      Contains all the Baclstop API endpoints defined as discrete functions vs. separate HTTP listeners.


    .NOTES
      Project:                Backstop Flexibility Framework (BFF)
      Public GitHub Repo:     https://github.com/humblecyberdude/BFF
      Copyright:              © 2024 | TenderLovinSnare
      Contact:                TenderLovinSnare@gmail.com
      License:                MIT (https://opensource.org/license/mit)
      █ Last Updated By:      HumbleCyberDude
      █ Release Stage:        ALPHA
      █ Version:              0.1
      █ Last Update:          31-July-2024
      █ Latest Release Notes:
      ↪ Alpha Release

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
#region FUNCTIONS  ###########################################################################################################################################################
##############################################################################################################################################################################

    function Get-Test
    {
        # Send back a test response
        Send-APIResponse -StatusCode 200 -GeneralContentType Text -Body "Testing123" -LogComments "Test API Hit"
    }




    function New-TOTP
    {
        # Define the normal Base32 character set
        $Script:Base32Charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

        # Generate the Google Authenticator TOTP and place the variables:
        $googleTOTPDetails = New-GoogleAuthenticatorSecret -Name "Admin TOTP" -Issuer "Backstop API Server" -SecretLength 140
        $googleTOTPSecretKey = $googleTOTPDetails.Secret
        $googleTOTPKeyUri = $googleTOTPDetails.keyUri

        # Generate a random filename for the file
        & $rootPath\Server\bin\qrencode.exe -o "$rootPath\Server\temp\QR-Codes\qrcode.png" $googleTOTPKeyUri





<#
    # Update the admin DB with the QRcode Secret    
    What about using invoke-aes encryption to decrypt the secret in the db with ENV decrypt key?
#>




        # Flush variables right away for added freshness
        Remove-Variable googleTOTPDetails -Force
        Remove-Variable googleTOTPSecretKey -Force
        Remove-Variable googleTOTPKeyUri -Force

        # Ensure that the file exists at all
        if(Test-Path -Path "$rootPath\Server\temp\QR-Codes\qrcode.png")
        {
            # Start a secure delete job to remove the QR code from the directory 30 seconds after this endpoint has been accessed
            Start-Job -Name "RemoveQRCode" -ScriptBlock {

                # Pass the $rootPath variable so we can use it in this job
                param ($rootPath)

                # Spcify the log source for logging
                $LogSource = "Job-RemoveQRCode"

                Import-Module "$rootPath\Server\modules\ServerCore.psm1" -Force

                # Wait N seconds before file is deleted
                Start-Sleep -Seconds 5

                # Remove the file with 64 passes of overwrite
                & $rootPath\Server\bin\sdelete.exe -q -nobanner -p 64 "$rootPath\Server\temp\QR-Codes\qrcode.png"

                # Ensure file is gone
                if(-Not(Test-Path -Path "$rootPath\Server\temp\QR-Codes\qrcode.png"))
                {
                    Write-ApiLog -LogType Server -SeverityLevel Info -eventTag "QRCode" -LogComments "Successfully deleted `"$rootPath\Server\temp\QR-Codes\qrcode.png`""

                } Else {

                    Write-ApiLog -LogType Server -SeverityLevel Error -eventTag "QRCode" -LogComments "Unable to delete `"$rootPath\Server\temp\QR-Codes\qrcode.png`""
                }

            } -ArgumentList $rootPath

            # Send back the URI to hit via browser
            Send-APIResponse -StatusCode 200 -GeneralContentType JSON -Body "https://$serverFQDN/v1/admin/qrcode" -LogComments "Sent QR code URI back to client"

        } Else {

            Send-APIResponse -StatusCode 404 -GeneralContentType Text -Body "API: Unable to find QR code" -LogComments "Unable to find `"$rootPath\Server\temp\QR-Codes\qrcode.png`" - nothing to give back!"
        }
    }




    function Get-AdminTOTP
    {
        # Ensure that the file exists at all
        if(Test-Path -Path "$rootPath\Server\temp\QR-Codes\qrcode.png")
        {
            Send-APIResponse -StatusCode 200 -GeneralContentType PNG -SendFilePath "$rootPath\Server\temp\QR-Codes\qrcode.png" -LogComments "Gave TOTP file to client."

        } Else {

            Send-APIResponse -StatusCode 404 -GeneralContentType Text -Body "API: Unable to find QR code" -LogComments "Unable to find `"$rootPath\Server\temp\QR-Codes\qrcode.png`" - nothing to give or delete!"
        }
    }




    function Confirm-AdminTOTP
    {



    }




    function Set-AdminPassword
    {
        # Enforces non-stupid passwords
        

    }




    function New-AdminAuthToken
    {
        # Generate a session ID GUID
        $sessionID = [System.Guid]::NewGuid().ToString()

        # We don't want to store auth tokens in plaintext in memory to the extent we can help it
        $encryptedAuthToken = Invoke-AESEncryption -Mode Encrypt -String (Get-RandomPassword -Length 64) -EnvVariableKeyName dbDecryptionKey -NumberOfIterations 1000000 -Quiet
        Invoke-AESEncryption -Mode Decrypt -String $encryptedAuthToken -EnvVariableKeyName dbDecryptionKey -NumberOfIterations 1000000

        $issuedDateTime = (Get-Date).ToString()
        $expireDateTime = (Get-Date).AddMinutes(60).ToString()



        sessionID TEXT,
        username TEXT,  
        authToken TEXT,
        issuedDateTime TEXT,
        expireDateTime TEXT,
        lastAccessed TEXT,
        clientIP TEXT,
        currentNonce TEXT


    }




    function Send-File
    {
        <#
            .SYNOPSIS
            Used for the endpoint URI https://FQDN/v[1]/files if the method is a GET. Sends files back
            to the client for download.


            .DESCRIPTION
            Gives the client the ability to download files from the API server. Clients can download files such
            as configurations, binaries, scripts or modules IF the request is of course valid and the file is 
            also correctly signed with the correct code-signing cert. 


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/humblecyberdude/BFF
            Copyright:              © 2024 | TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
            Major Release Name:     Tender Lovin' Snare
            █ Last Updated By:      HumbleCyberDude
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          31-July-2024
            █ Latest Release Notes:
            ↪ Alpha Release


            .PARAMETER FileName
            Specifies the filename that the client wants to download

            
            .EXAMPLE
            Invoke-RestMethod -Uri https://FQDN/v[1]/endpoints/files

        #>




        ##########################################################################################################################################################################
        #region   PARAMETERS   ###################################################################################################################################################
        ##########################################################################################################################################################################

            Param
            (
                # Pass the name of the file to the function
                [parameter(Mandatory=$true)]
                [String]$FileName
            )

        #endregion PARAMETERS




        ##########################################################################################################################################################################
        #region   VARIABLES   ####################################################################################################################################################
        ##########################################################################################################################################################################

            # Dynamically get the function name for logging
            $Global:functionName = (Get-PSCallStack)[0].FunctionName

            # Specify the correct certificate thumbprint you want to trust for validating code integrity
            $Global:correctCertThumbprint = "TEST MODE: REPLACE ME"
            
        #endregion VARIABLES




        ##########################################################################################################################################################################
        #region   SERVICE REQUEST   ##############################################################################################################################################
        ##########################################################################################################################################################################

            # The client needs to specify what file they want in the header. The $fileName variable is captured, like all other request variables in the Receive-Request function.
            if(-not($fileName))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -LogComments "Missing fileName in the request header"
            }

            # First, parse extension of the file. First, we need to split the filename into different parts, splitting based on "." which will create a list of items (usually two). 
            # Second, we need to pick the the last item in the list. Doing "-1" will pick the last one automatically. This is important if somehow the filen has multiple "." in the name.
            $fileExention = $fileName.Split(".")[-1]

            # Define the file retrieval path and the content type for each type of file extension.
            if($fileExention -eq "ps1")
            {
                $filePath = "$rootPath\Client\scripts"
            }

            if($fileExention -eq "psm1")
            {
                $filePath = "$rootPath\Client\modules"
            }

            if($fileExention -match "ps1xml")
            {
                $filePath = "$rootPath\Client\etc"
            }

            if($fileExention -match "exe|msi|zip")
            {
                $filePath = "$rootPath\Client\bin"
            }
            
            # Verify that the file exists, else return 404. Also, as an added safety, ensure that the filePath matches anything in the Client directory.
            if((Test-Path -Path "$filePath\$fileName")   -and   ($filePath -match "\\Backstop\\Instances\\v\d{1,2}\\Client"))
            {
                # Get the file signature status for each file
                $fileSignatureStatus = (Get-AuthenticodeSignature -FilePath "$filePath\$fileName").Status.ToString()
                $fileSignatureThumbprint = ((Get-AuthenticodeSignature -FilePath "$filePath\$fileName").SignerCertificate).Thumbprint

                # Give the file back to the client if it's got a valid siganture and it's signed by the trusted thumbprint
    if(($fileSignatureStatus -ne "Valid")   -and   ($fileSignatureThumbprint -ne "$correctCertThumbprint"))
                {
                    # Give file back to the client
                    $rawFile = [IO.File]::ReadAllBytes("$filePath\$fileName")

                    # Capture the response for logging variables; send response back to client; log event
                    Send-APIResponse -StatusCode 200 -GeneralContentType Binary -SendFilePath "$filePath\$fileName" -LogComments "Gave file $filePath\$fileName back to client. Signature was verified successfully."

                } Else {

                    Send-APIResponse -StatusCode 500 -GeneralContentType Text -LogComments "File at $filePath\$fileName has an incorrect trusted cert thumbprint. Additional Info: correctCertThumbprint=$correctCertThumbprint fileSignatureThumbprint=$fileSignatureThumbprint fileSignatureStatus=$fileSignatureStatus."
                }

            } Else {

                Send-APIResponse -StatusCode 404 -GeneralContentType Text -LogComments "The file $fileName requested by the client does not exist or the filepath $filePath is incorrect"
            }
    }




    function Get-DBEntry
    {
        
        # TEST ONLY 

        # Dynamically get the function name for logging
        $Global:functionName = (Get-PSCallStack)[0].FunctionName

        $foo = invoke-sQLiteQuery -Connection $dbConnection -Query "SELECT randomName FROM randomNames ORDER BY RANDOM() LIMIT 1"
        
        Send-APIResponse -StatusCode 200 -GeneralContentType Json -Body $foo
        
    }




    function Register-Endpoint
    {
        <#
        
        
        
        
        
        


        
        
            DO NOT USE YET - TO BE CONVERTED FROM POWERSHELL UNIVERSAL/RE-WRITTEN
        
        
        
        
        
        
        
        
        
        
        
        
            .SYNOPSIS
            UPDATE ME


            .DESCRIPTION
            UPDATE ME


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/humblecyberdude/BFF
            Copyright:              © 2024 | TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
            Major Release Name:     Tender Lovin' Snare
            █ Last Updated By:      HumbleCyberDude
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          1-August-2024
            █ Latest Release Notes:
            ↪ Alpha Release

        #>




        ##########################################################################################################################################################################
        #region   SERVICE REQUEST   ##############################################################################################################################################
        ##########################################################################################################################################################################

            # Attempt to service the API request if the client has successfully authenticated.
            if($authenticationPassed)
            {
                # Define the needed host headers as variables
                $clientHostname = $Headers.clientHostname
                $clientSalt = $headers.clientSalt
                $clientState = $headers.clientState

                # Import PSSQLite module if it's not already imported
                if(-not(Get-Module -Name PSSQLite))
                {
                    # Import the module
                    Import-Module -Name PSSQLite -Force
                }

                # We need to ensure that the client hostname is present so we can document that in the registration process
                if(-not($clientHostname -or $clientSalt -or $clientState))
                {
                    # Capture the response for logging variables; send response back to client; log event
                    $Global:response = New-PSUApiResponse -StatusCode 400; $response; Write-EndpointLog -LogType Access -severityLevel "error" -eventTag "registerEndpoint" -LogComments "Missing headers"; Break
                }

                # Check to see if the host is in the valid hostnames list. If not, deny the registration.
                $inValidHostnames = (Invoke-SQLiteQuery -Connection $cache:dbConnection -Query "SELECT * FROM ValidHostnames WHERE ValidHostname = `"$clientHostname`"").ValidHostname
                
                if(-Not $inValidHostnames)
                {
                    $Global:response = New-PSUApiResponse -StatusCode 404; $response; Write-EndpointLog -LogType Access -severityLevel "error" -eventTag "registerEndpoint" -LogComments "Client $clientHostname attempted to register but was not found in the ValidHostnames table"; Break
                } 

                # Refreshes Client Registration Data
                $clientRegData = Invoke-SqliteQuery -SQLiteConnection $cache:dbConnection -Query "SELECT * FROM registrations WHERE clientHostname = `"$clientHostname`""

                # Check if the client is already installed
                if($clientRegData.clientstate -eq "installed")
                {
                    # Provide failure code below but don't give away info about the client already being installed
                    $Global:response = New-PSUApiResponse -StatusCode 400; $response; Write-EndpointLog -LogType Access -severityLevel "error" -eventTag "registerEndpoint" -LogComments "Endpoint already installed"; Break
                }

                # Set to installing if the client is still installing it but ensure that if it's already installing, don't add another entry.
                if($clientState -eq "installing")
                {
                    # Get random names for clients and also grab a timestamp so we can document the registration time in the correct format
                    $directoryName = (Invoke-SqliteQuery -SQLiteConnection $cache:dbConnection -Query "SELECT * FROM randomNames" | get-random).randomName
                    $taskPathName = (Invoke-SqliteQuery -SQLiteConnection $cache:dbConnection -Query "SELECT * FROM randomNames" | get-random).randomName
                    $dateTime = Get-Date -AsUTC -Format "yyyy-MM-dd HH:mm:ss K"

                    # Define the common HMAC secret which will be used for subsequent API requests
                    $apiKeyHmacSecret = 'EXAMPLE'

                    # Combine the salt + the computername as the input for the HMAC in addition to the secret. This will ensure a per-machine and per-install instance key and also ensure that
                    # another client can't just register using the hostname and get its API key as they'd have to know the salt as well.
                    $apiKeyCombinedInput = "$clientSalt|$clientHostname"

                    # Do an HMAC function to create the API key for the client. The key is derived from the HMAC secret and the client's hostname
                    $apiKeyHmacSHA256 = New-Object System.Security.Cryptography.HMACSHA256
                    $apiKeyHmacSHA256.key = [Text.Encoding]::ASCII.GetBytes($apiKeyHmacSecret)
                    $newClientApiKey = $apiKeyHmacSHA256.ComputeHash([Text.Encoding]::ASCII.GetBytes($apiKeyCombinedInput))
                    $newClientApiKey = [Convert]::ToBase64String($newClientApiKey)

                    # Create the removal key. While NewGuid is shmaybe "good enough", let's also add some flavor and then hash that. Now it's "more betterer" vs. "good enough"
                    $guid = ([guid]::NewGuid()).Guid
                    $saltyGuid = "$clientSalt|$guid"
                    $removalTokenStream = [IO.MemoryStream]::new([byte[]][char[]]$saltyGuid)
                    $removalToken = (Get-FileHash -InputStream $removalTokenStream -Algorithm SHA256).Hash

                    # Build the JSON response for the client
                    $jsonResponse = [ordered]@{
                        directoryName = $directoryName
                        taskPathName = $taskPathName
                        newClientApiKey = $newClientApiKey
                    }

                    # Convert it to a JSON string (required to stuff in the body)
                    $jsonResponse = $jsonResponse | ConvertTo-Json

                    # Update the existing entry if it already existed. Else, create a new one
                    if($clientRegData)
                    {
                        # Update the existing record and use paramaters for any client supplied data
                        $query = "UPDATE registrations
                            SET
                            clientStateLastModified = `"$dateTime`",
                            clientHostname = @clientHostname,
                            clientState = @clientState,
                            clientSalt = @clientSalt,
                            directoryName = `"$directoryName`",
                            taskPathName = `"$taskPathName`",
                            removalToken = `"$removalToken`"
                            WHERE clientHostname = @clientHostname;"

                        Invoke-SqliteQuery -SQLiteConnection $cache:dbConnection -Query $query -SqlParameters @{
                            clientHostname = $clientHostname
                            clientState   = $clientState
                            clientSalt = $clientSalt}

                    } Else {

                        # Create new record and use paramaters for client supplied data
                        $query = "INSERT INTO registrations (clientStateLastModified, clientHostname, clientState, directoryName, taskPathName, removalToken, clientSalt)
                        VALUES (`"$dateTime`", @clientHostname, @clientState, `"$directoryName`", `"$taskPathName`", `"$removalToken`", @clientSalt)"

                        Invoke-SqliteQuery -SQLiteConnection $cache:dbConnection -Query $query -SqlParameters @{
                            clientHostname = $clientHostname
                            clientState   = $clientState
                            clientSalt = $clientSalt}
                    }

                    # Capture the response for logging variables; send response back to client; log event
                    $Global:response = New-PSUApiResponse -StatusCode 200 -Body $jsonResponse; $response; Write-EndpointLog -LogType Access -severityLevel "info" -eventTag "registerEndpoint" -LogComments "Gave client the random directory and task path names"; Break
                }


                # Set to clientState to 'installed' if the client reported back that Backstop was successfully installed
                if($clientState -eq "installed")
                {
                    # Get updated dateTime stamp and set clientState to 'installed'
                    $dateTime = Get-Date -AsUTC -Format "yyyy-MM-dd HH:mm:ss K"

                    # Update the existing record and use paramaters for any client supplied data (some sanatized anyway but doing best practice anyway)
                    $query = "UPDATE registrations
                        SET
                        clientStateLastModified = `"$dateTime`",
                        clientState = @clientState
                        WHERE clientHostname = @clientHostname"

                    Invoke-SqliteQuery -SQLiteConnection $cache:dbConnection -Query $query -SqlParameters @{
                        clientHostname = $clientHostname
                        clientState   = $clientState}

                    # Capture the response for logging variables; send response back to client; log event
                    $Global:response = New-PSUApiResponse -StatusCode 200; $response; Write-EndpointLog -LogType Access -severityLevel "info" -eventTag "registerEndpoint" -LogComments "Client should now be installed"; Break
                }
                
                # Disconnect from the DB
                $cache:dbConnection.Close()
            }

        #endregion SERVICE REQUEST
    }




    function Remove-Endpoint
    {
        <#
        
        
        
        
        
        


        
        
            DO NOT USE YET - TO BE CONVERTED FROM POWERSHELL UNIVERSAL/RE-WRITTEN
        
        
        
        
        
        
        
        
        
        
        
        
            .SYNOPSIS
            UPDATE ME


            .DESCRIPTION
            UPDATE ME


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/humblecyberdude/BFF
            Copyright:              © 2024 | TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
            Major Release Name:     Tender Lovin' Snare
            █ Last Updated By:      HumbleCyberDude
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          1-August-2024
            █ Latest Release Notes:
            ↪ Alpha Release

        #>




        ##########################################################################################################################################################################
        #region   SERVICE REQUEST   ##############################################################################################################################################
        ##########################################################################################################################################################################

            # Attempt to service the API request if the client has successfully authenticated.
            if($authenticationPassed)
            {
                # Define the needed host headers as variables
                $clientHostname = $Headers.clientHostname
                $clientSalt = $headers.salt
                $clientState = $headers.clientState

                # Import PSSQLite module if it's not already imported
                if(-not(Get-Module -Name PSSQLite))
                {
                    # Import the module
                    Import-Module -Name PSSQLite -Force
                }

                # We need to ensure that the client hostname is present so we can document that in the registration process
                if(-not($clientHostname -or $clientSalt -or $clientState))
                {
                    # Capture the response for logging variables; send response back to client; log event
                    $Global:response = New-PSUApiResponse -StatusCode 400; $response; Write-EndpointLog -LogType Access -severityLevel "error" -eventTag "removeEndpoint" -LogComments "Client request missing headers"; Break
                }

                # Refreshes Client Registration Data
                $query = "SELECT * FROM registrations WHERE clientHostname = @clientHostname"
                $clientRegData = Invoke-SqliteQuery -SQLiteConnection $cache:dbConnection -Query $query -SqlParameters @{clientHostname = $clientHostname}

                # Log event if there's nothing in the DB for this client
                if(-not($clientRegData))
                {
                    New-PSUApiResponse -StatusCode 404; Write-EndpointLog -LogType Access -severityLevel "error" -eventTag "removeEndpoint" -LogComments "An uninstall attempt was made for a client not found in the database"; Break
                }

                # If the client gives us the state of "uninstalling", ensure that the reason has this string below anywhere within the reason (TNG) and also ensure that the current state is installed
                if(($clientState -eq "uninstalling")   -and   ($reason -match "EXAMPLE"))
                {
                    if($clientRegData.clientState -eq "installed")
                    {
                        $directoryName = $clientRegData.directoryName
                        $taskPathName = $clientRegData.taskPathName

                        # Get updated dateTime stamp
                        $dateTime = Get-Date -AsUTC -Format "yyyy-MM-dd HH:mm:ss K"

                        # Update the existing record and use paramaters for any client supplied data (some sanatized anyway but doing best practice anyway)
                        $query = "UPDATE registrations
                            SET
                            clientStateLastModified = `"$dateTime`",
                            clientState = @clientState
                            WHERE clientHostname = @clientHostname;"

                        Invoke-SqliteQuery -SQLiteConnection $cache:dbConnection -Query $query -SqlParameters @{
                            clientHostname = $clientHostname
                            clientState = $clientState}

                        # Build the JSON response for the client
                        $jsonResponse = @{
                            directoryName = $directoryName
                            taskPathName = $taskPathName
                        }

                        # Flush Variables
                        Remove-Variable directoryName
                        Remove-Variable taskPathName

                        # Convert it to a JSON string (required to stuff in the body)
                        $jsonResponse = $jsonResponse | ConvertTo-Json

                        # Capture the response for logging variables; send response back to client; log event
                        $Global:response = New-PSUApiResponse -StatusCode 200 -Body $jsonResponse; $response; Write-EndpointLog -LogType Access -severityLevel "info" -eventTag "removeEndpoint" -LogComments "Gave client back the directory and task names for removal"; Break

                    } Else {

                        $Global:response = New-PSUApiResponse -StatusCode 400 -Body "Bad request"; $response; Write-EndpointLog -LogType Access -severityLevel "error" -eventTag "removeEndpoint" -LogComments "An uninstall attempt was made for this client but Backstop DB didn't show this client had Backstop installed at all"; Break
                    }
                }


                # Ensure that the reason has this string below anywhere within the reason
                if(($clientState -eq "uninstalled")   -and   ($reason -match "EXAMPLE"))
                {
                    # Get updated dateTime stamp
                    $dateTime = Get-Date -AsUTC -Format "yyyy-MM-dd HH:mm:ss K"
                    
                    # Update the existing record and use paramaters for any client supplied data (some sanatized anyway but doing best practice anyway)
                    $query = "UPDATE registrations
                        SET
                        clientStateLastModified = `"$dateTime`",
                        clientState = @clientState
                        WHERE clientHostname = @clientHostname;"

                    Invoke-SqliteQuery -SQLiteConnection $cache:dbConnection -Query $query -SqlParameters @{
                        clientHostname = $clientHostname
                        clientState = $clientState}

                    # Add old API key to the revocation list. No reason why an API key from an uninstalled endpoint would still be used.
                    $apiKey = $Headers.apikey
                    Add-Content -Value "$apiKey" -Path "YOUR_PATH_HERE\db\revocationList.txt"
                }


                # Send backstop deceive signal (client keys off of the "=") if reason incorrect
                if($reason -notmatch "EXAMPLE")
                {
                    $encryptedDirectoryName = "EXAMPLE"
                    $encryptedTaskPathName = "EXAMPLE"

                    # Build the JSON response for the client
                    $jsonResponse = @{
                        encryptedDirectoryName = $encryptedDirectoryName
                        encryptedTaskPathName = $encryptedTaskPathName
                    }
                    
                    # Flush Variables
                    Remove-Variable encryptedDirectoryName
                    Remove-Variable encryptedTaskPathName

                    # Convert it to a JSON string (required to stuff in the body)
                    $jsonResponse = $jsonResponse | ConvertTo-Json

                    # Capture the response for logging variables; send response back to client; log event
                    $Global:response = New-PSUApiResponse -StatusCode 200 -Body $jsonResponse; $response; Write-EndpointLog -LogType Access -severityLevel "warn" -eventTag "removeEndpoint" -LogComments "Fake Uninstall"; Break
                }
            }

        #endregion SERVICE REQUEST
    }




    function Send-SplunkHEC
    {
        <#
        
        
        
        
        
        


        
        
            DO NOT USE YET - TO BE CONVERTED FROM POWERSHELL UNIVERSAL/RE-WRITTEN
        
        
        
        
        
        
        
        
        
        
        
        
            .SYNOPSIS
            UPDATE ME


            .DESCRIPTION
            UPDATE ME


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/humblecyberdude/BFF
            Copyright:              © 2024 | TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
            Major Release Name:     Tender Lovin' Snare
            █ Last Updated By:      HumbleCyberDude
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          1-August-2024
            █ Latest Release Notes:
            ↪ Alpha Release

        #>






        ##########################################################################################################################################################################
        #region   SERVICE REQUEST   ##############################################################################################################################################
        ##########################################################################################################################################################################

            # Attempt to service the API request if the client has successfully authenticated.
            if($authenticationPassed)
            {
                # Create the Splunk HEC Header
                $splunkHecHeader = @{Authorization = "Splunk $splunkHecToken"}

                # Test to ensure that the JSON is valid
                if(-not(Test-JSON $Body -ErrorAction SilentlyContinue))
                {
                    $Global:response = New-PSUApiResponse -StatusCode 400 -Body "JSON body was invalid"; $response; Write-EndpointLog -LogType Access -severityLevel "error" -eventTag "relay" -LogComments "Client tried to relay a message to Splunk HEC but the JSON body was invalid"; Break
                }
                
                # Take client POST request and send to Splunk
                $splunkHecBody = $Body

                # Send data to Backstop Server
                Invoke-RestMethod -Uri "https://FQDN:8088/services/collector" -Method Post -Headers $splunkHecHeader -Body $splunkHecBody -DisableKeepAlive -ErrorAction SilentlyContinue | out-null

                Write-EndpointLog -LogType Access -severityLevel "info" -eventTag "relay" -LogComments "Message relayed to Splunk"; break
            }

        #endregion SERVICE REQUEST
    }




    function Update-Backstop
    {
        <#
        
        
        
        
        
        


        
        
            DO NOT USE YET - TO BE CONVERTED FROM POWERSHELL UNIVERSAL/RE-WRITTEN
        
        
        
        
        
        
        
        
        
        
        
        
            .SYNOPSIS
            UPDATE ME


            .DESCRIPTION
            UPDATE ME


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/humblecyberdude/BFF
            Copyright:              © 2024 | TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
            Major Release Name:     Tender Lovin' Snare
            █ Last Updated By:      HumbleCyberDude
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          1-August-2024
            █ Latest Release Notes:
            ↪ Alpha Release

        #>



        ##########################################################################################################################################################################
        #region   SERVICE REQUEST   ##############################################################################################################################################
        ##########################################################################################################################################################################

            # There's only these possibilites as specified by the updateType variable:
            # - Database: Used to refresh the Backstop database with valid hostnames (those that are able to register) or hashed user details
            # - Files: New or updated files, scripts and/or executables for Backstop itself

            # Attempt to service the API request if the client has successfully authenticated.
            if($authenticationPassed)
            {
                #region   DATABASE UPDATE PROCESS   ##############################################################################################################################
                if($updateType -eq 'database')
                {
                    # Write the upoaded file here
                    [System.IO.File]::WriteAllBytes("YOUR_PATH_HERE\tmp\$fileName", $Data)

                    # Get hash and write to the log file
                    $uploadedFileSHA256 = (Get-FileHash -Path "YOUR_PATH_HERE\tmp\$fileName" -Algorithm SHA256).hash
                    Write-EndpointLog -LogType Access -LogComments -severityLevel "info" -eventTag "update" "Processed file upload $fileName with a SHA256 hash of $uploadedFileSHA256 from $clientHostname"

                    # Ensure that the file is correctly signed and valid (and signed only by us)
                    if((Get-AuthenticodeSignature -FilePath "YOUR_PATH_HERE\tmp\$fileName").SignerCertificate.Thumbprint -eq $correctBackstopLowTrustCertThumbprint)
                    {
                        # Remove older files
                        Remove-Item -Path "YOUR_PATH_HERE\tmp\validEndpointList.txt" -Force -ErrorAction SilentlyContinue
                        Remove-Item -Path "YOUR_PATH_HERE\tmp\hashedUserData.csv" -Force -ErrorAction SilentlyContinue

                        <# Extract the contents
                            Command Breakdown: "X" is extract
                            ↪   x:      Extract the contents of the file
                            ↪   -o:     Output directory (can't contain a space because... reasons)
                            ↪   -bso0:  Set standard output to quiet (i.e. SHUT UP!)
                            ↪   -y:     Automatically accept all prompts as yes (i.e. just freegin' DO IT!)
                        #>
                        & "C:\Program Files\7-Zip\7z.exe" x "YOUR_PATH_HERE\tmp\$fileName" -o"YOUR_PATH_HERE\tmp" -bso0 -y

                        #region   UPDATE VALID ENDPOINTS LIST IN DB   ############################################################################################################

                            # Update process for valid endpoint list (valid hostnames that are able to be registered)
                            if(Test-Path -Path "YOUR_PATH_HERE\tmp\validEndpointList.txt")
                            {
                                # Read the data into a variable
                                $validEndpoints = Get-Content -Path "YOUR_PATH_HERE\tmp\validEndpointList.txt"

                                # Get the data into an insertable format
                                $validEndpoints = $validEndpoints -join "'),('"

                                # Begin a transaction (allows us to test and rollback if there's issues)
                                $transaction = $cache:dbConnection.BeginTransaction()

                                try {

                                    # Flush the old data from the ValidHostnames table: Keep it simple by just blowing it away and bulk reloading in a second or two
                                    Invoke-SQLiteQuery -Connection $cache:dbConnection -Query "DELETE FROM ValidHostnames"

                                    # Bulk insert the valid endpoint hostnames all at once
                                    Invoke-SQLiteQuery -Connection $cache:dbConnection -Query "INSERT INTO ValidHostnames (ValidHostname) VALUES ('$validEndpoints')"

                                    # Commit the transaction to the database
                                    $transaction.Commit()

                                } catch {

                                    # Rollback the changes if there's any errors found. By default, any error since we're not specifying what to look for here.
                                    $transaction.Rollback()

                                    Write-EndpointLog -LogType Access -severityLevel "error" -eventTag "update" -LogComments "Database load error! Should add more details here... Error: $_" 

                                } finally {

                                    # Close cache:dbConnection
                                    $cache:dbConnection.Close()
                                }
                            }

                        #endregion UPDATE VALID ENDPOINTS LIST IN DB

                        #region   UPDATE HASHED USER DATA IN DB   ################################################################################################################

                        # Update process for valid endpoint list (valid hostnames that are able to be registered)
                        if(Test-Path -Path "YOUR_PATH_HERE\tmp\hashedUserData.csv")
                        {
                            # Connect to the SQLite Database
                            $dbPath = "YOUR_PATH_HERE\db\backstop.db"
                            $cache:dbConnection = New-SQLiteConnection -DataSource $dbPath

                            # Begin a transaction (allows us to test and rollback if there's issues)
                            $transaction = $cache:dbConnection.BeginTransaction()

                            try {

                                # Flush the old data from the ValidHostnames table: Keep it simple by just blowing it away and bulk reloading in a second or two
                                Invoke-SQLiteQuery -Connection $cache:dbConnection -Query "DELETE FROM PersonaData"

                                # Capture the data in the CSV as an object
                                $hashedUserDataCsv = Import-Csv "D:\Apps\Backstop\prod\tmp\hashedUserData.csv"

                                # Load the rows into the Backstop DB
                                foreach ($row in $hashedUserDataCsv)
                                {
                                    # Make that 'custom crafted' query
                                    #$query = "INSERT INTO UserData (hashedUsername, hashedTitle, hashedDepartment, hashedFunction)
                                    #VALUES (`"$($row.hashedUsername)`", `"$($row.hashedTitle)`", `"$($row.hashedDepartment)`", `"$($row.hashedFunction)`")"

                                    # Make that 'custom crafted' query
                                    $query = "INSERT INTO PersonaData (hashedUsername, hashedTitle, hashedDepartment, hashedFunction, hashedManager1, hashedManager2)
                                    VALUES (`"$($row.hashedUsername)`", `"$($row.hashedTitle)`", `"$($row.hashedDepartment)`", `"$($row.hashedFunction)`", `"$($row.hashedManager1)`", `"$($row.hashedManager2)`")"

                                    # Insert the records into the DB
                                    Invoke-SqliteQuery -SQLiteConnection $cache:dbConnection -Query $query 
                                }

                                # Commit the transaction to the database
                                $transaction.Commit()

                            } catch {

                                # Rollback the changes if there's any errors found. By default, any error since we're not specifying what to look for here.
                                $transaction.Rollback()

                                Write-EndpointLog -LogType Access -severityLevel "error" -eventTag "update" -LogComments "Database load error! Should add more details here... Error: $_" 

                            } finally {

                                # Close cache:dbConnection
                                $cache:dbConnection.Close()
                            }
                        }

                    #endregion UPDATE HASHED USER DATA IN DB

                    } Else {

                        # BAD CERT HANDLING HERE
                        Write-EndpointLog -LogType Access -severityLevel "error" -eventTag "update" -LogComments "bad sig" 
                    }
                }
                #endregion DATABASE UPDATE PROCESS


                #region   FILE UPDATE PROCESS   ##################################################################################################################################
                    
                    if($updateType -eq 'files')
                    {
                        $Global:response = New-PSUApiResponse -StatusCode 501 -Body "Not implemented yet"; $response; Write-EndpointLog -LogType Access -severityLevel "error" -eventTag "update" -LogComments "Client tried to update files but that function hasn't been implemented yet"; Break
                    }

                #endregion FILE UPDATE PROCESS 
            }
        #endregion SERVICE THE REQUESTs
    }




    function Get-Tokens
    {
        <#
        
        
        
        
        
        


        
        
            DO NOT USE YET - TO BE CONVERTED FROM POWERSHELL UNIVERSAL/RE-WRITTEN
        
        
        
        
        
        
        
        
        
        
        
        
            .SYNOPSIS
            UPDATE ME


            .DESCRIPTION
            UPDATE ME


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/humblecyberdude/BFF
            Copyright:              © 2024 | TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
            Major Release Name:     Tender Lovin' Snare
            █ Last Updated By:      HumbleCyberDude
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          1-August-2024
            █ Latest Release Notes:
            ↪ Alpha Release

            .EXAMPLE
            Invoke-RestMethod -Method GET -Uri "https://FQDN/common/v1/tokens" -Headers @{apiKey = "$apiKey"; clientHostname = $env:COMPUTERNAME; kind = "aws-id"; memo = "Host=$env:COMPUTERNAME User=$localUser DIR=YOUR_DIR_HERE NOTES=Your Notes Here"} -UserAgent "Backstop"

        #>




        ##########################################################################################################################################################################
        #region   SERVICE THE REQUEST   ##########################################################################################################################################
        ##########################################################################################################################################################################

            # Attempt to service the API request if the client has successfully authenticated.
            if($authenticationPassed)
            {
                if($kind -eq "aws-id")
                {
                    # Create the body of the request specific to the kind
                    $canaryApiBody = @{auth_token = "$canaryApiKey"
                        kind ="aws-id"
                        memo = "$memo"
                        flock_id = "flock:REPLACE_ME"}

                    # Fetch the token
                    $tokenResponse = Invoke-RestMethod -Uri "https://REPLACE_ME.canary.tools/api/v1/canarytoken/create" -Method Post -Body $canaryApiBody

                    # Extract the text we'll need to write the data to a file
                    $canaryTokenRenders = $tokenResponse.canarytoken.renders

                    # Build the JSON response for the client
                    $jsonResponse = [ordered]@{
                        canaryTokenRenders = $canaryTokenRenders
                    }

                    # Convert it to a JSON string (required to stuff in the body)
                    $jsonResponse = $jsonResponse | ConvertTo-Json

                    # Capture the response for logging variables; send response back to client; log event
                    $Global:response = New-PSUApiResponse -StatusCode 200 -Body $jsonResponse; $response; Write-EndpointLog -LogType Access -severityLevel "info" -eventTag "getCanaryTokens" -LogComments "Gave client the $kind token"; Break

                }
            }

        #region SERVICE THE REQUEST
    }




    function Get-Persona
    {
        <#
        
        
        
        
        
        


        
        
            DO NOT USE YET - TO BE CONVERTED FROM POWERSHELL UNIVERSAL/RE-WRITTEN
        
        
        
        
        
        
        
        
        
        
        
        
            .SYNOPSIS
            UPDATE ME


            .DESCRIPTION
            UPDATE ME


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/humblecyberdude/BFF
            Copyright:              © 2024 | TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
            Major Release Name:     Tender Lovin' Snare
            █ Last Updated By:      HumbleCyberDude
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          1-August-2024
            █ Latest Release Notes:
            ↪ Alpha Release

        #>





        ######################################################################################################################################
        #region   SERVICE THE REQUEST   ######################################################################################################
        ######################################################################################################################################

            # Attempt to service the API request if the client has successfully authenticated.
            if($authenticationPassed)
            {
                # Grab the hashed user details
                $personaUserDetails = Invoke-SQLiteQuery -Connection $cache:dbConnection -Query "SELECT hashedUsername, hashedTitle, hashedDepartment, hashedFunction, hashedManager1, hashedManager2 FROM PersonaData WHERE hashedUsername = '$hashedUsername'" | ConvertTo-Json

                if($personaUserDetails)
                {
                    # Give persona details back to the client
                    $Global:response = New-PSUApiResponse -StatusCode 200 -Body $personaUserDetails; $response; Write-EndpointLog -LogType Access -severityLevel "info" -eventTag "getPersona" -LogComments "Gave client the persona info"; Break

                } Else {

                    # Update the persona file to (basically blank)
                    $personaUserDetails = [PSCustomObject][ordered]@{
                        hashedUsername = "notFoundOnServerBasedOnHashedUsernameSupplied"
                        hashedTitle = "notFoundOnServerBasedOnHashedUsernameSupplied"
                        hashedDepartment = "notFoundOnServerBasedOnHashedUsernameSupplied"
                        hashedFunction = "notFoundOnServerBasedOnHashedUsernameSupplied"
                        hashedManager1 = "notFoundOnServerBasedOnHashedUsernameSupplied"
                        hashedManager2 =  "notFoundOnServerBasedOnHashedUsernameSupplied"
                    }

                    # Add personaUserDetails to the persona array we can call later
                    $personaUserDetails = $personaUserDetails | ConvertTo-Json

                    # Give persona details back to the client
                    $Global:response = New-PSUApiResponse -StatusCode 200 -Body "$personaUserDetails"; $response; Write-EndpointLog -LogType Access -severityLevel "info" -eventTag "getPersona" -LogComments "Unable to find persona details based on hashed username supplied. Hash supplied was $hashedUsername"; Break
                }
            }

        #region SERVICE THE REQUEST
    }




    function Get-Manifest
    {
        <#
            .SYNOPSIS
              Dynamically generates the manifest for the client. The manifest tells the client the details about which lure files or other files it needs to run along with their
              hashes. It's dynamic because we don't have a need to give all of the lures to all of the clients. Instead we just give them what they're scoped for within the module.
    
    
            .DESCRIPTION
              Tells the clients specific details for each file it needs by filename, the general directory it needs to go in and the remote hash of that file on the server. If the 
              hash value on the client doesn't match what's on the server, the client assumes it needs to be updated and downloads the file via the /common/v1/files endpoint.
              The client will check the file signature first to ensure that it is correctly signed and if so, replace and possibly run the file if needed.
    
    
            .NOTES
              Project:                Backstop Flexibility Framework (BFF)
              Public GitHub Repo:     https://github.com/humblecyberdude/BFF
              Copyright:              © 2024 | TenderLovinSnare
              Contact:                TenderLovinSnare@gmail.com
              License:                MIT (https://opensource.org/license/mit)
              Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
              Major Release Name:     Tender Lovin' Snare
              █ Last Updated By:      HumbleCyberDude
              █ Release Stage:        ALPHA
              █ Version:              0.1
              █ Last Update:          10-August-2024
              █ Latest Release Notes:
              ↪ Alpha Release
    
                      1. Manifest request comes in with the correct headers and is authenticated, etc.
            2. For-each module, check if it's relavant for the client. If not, skip it.
            3. If module is relevant, gather name, directory and hash of the module into array
            4. Give array back to the client in the form of JSON as usual
            5. Client then stores it locally in case the server is down so it knows what to run
    
            # moduleEnabled
            # osClass
            # assetName
            # adDomain
            # businessUnit
            # primarySubnet
            # primaryUserFunctionHash
            # primaryUserDepartmentHash
            # primaryUserJobTitleHash
            # primaryUsernameHash
            # primaryUserManager1Hash
            # primaryUserManager2Hash
    
        #>
    
    
    
    
    
    
    
    
        ##########################################################################################################################################################################
        #region   BUILD CLIENT MANIFEST   ########################################################################################################################################
        ##########################################################################################################################################################################
    
            # Create initial nested manifest object broken out between support modules and the lures
            $manifest = [ordered]@{
                modules = @()
                lures = @()
            }
    
            ######################################################################################################################################################################
            #region   POPULATE SUPPORT MODULES   #################################################################################################################################
            ######################################################################################################################################################################
    
    
                function Update-Manifest
                {
                    Param
                    (
                        # Specifies the filename to add to the manifest. The file must be in the form of a FileInfo object (what you'd get from Get-ChildItem)
                        [parameter(Mandatory=$true)]
                        [FileInfo]$File,
    
                        # Specifies the directory the file belongs in
                        [parameter(Mandatory=$true)]
                        [String]$Directory
                    )
                    
                    # Ensure that we have the manifest array created and if not, just create it
                    if(-Not($manifest))
                    {
                        $Global:manifest = [ordered]@{
                            modules = @()
                            lures = @()
                        }
                    }
    
                    # Define our variables to add
                    $fileName = $File.Name
                    $directory = $Directory
                    $remoteSHA256FileHash = (Get-FileHash -Path $File -Algorithm SHA256).Hash
    
                    # Group the details for the module into the object below
                    $moduleDetails = @{fileName = $fileName; directory = $Directory; remoteSHA256FileHash = $remoteSHA256FileHash}
    
                    # Add the module details to the manifest
                    $manifest.modules += $moduleDetails
    
    
                }
    
    
    
    
    
    
    
    
    
    
    
    
                # Get the hash details of all the files in the modules directory. As these are support modules, they should always be there for all clients.
                $modules = Get-ChildItem -Path "D:\Apps\Backstop\v1\Client\modules"
    
                # For each support module, get its hash value to let the clients know if there were changes to the file. If so, the client can then download the latest copy.
                foreach ($module in $modules)
                {
                    # Define our variables to add
                    $fileName = $module.Name
                    $localDirectoryName = "modules"
                    $remoteSHA256FileHash = (Get-FileHash -Path $module -Algorithm SHA256).Hash
    
                    # Group the details for the module into the object below
                    $moduleDetails = @{fileName = $fileName; localDirectoryName = $localDirectoryName; remoteSHA256FileHash = $remoteSHA256FileHash}
    
                    # Add the module details to the manifest
                    $manifest.modules += $moduleDetails
                }
    
            #endregion POPULATE SUPPORT MODULES
    
    
    
                # Extract variable names and values
                foreach ($line in $fileContent) {
    
                    if($line | Select-String -Pattern '\$Global\:[a-zA-Z0-9_]{1,35}')
                    {
                        # Extract the variable name from the value
                        $modVarName = ($line -split '=')[0] -replace ' ', '' -replace '\$Global\:', ''
                        $modVarValue = ($line -split '=')[1] -replace '"', '' -replace ' ', ''
    
                        $lureConstraintsingleVars = @{$modVarName = $modVarValue}
    
                        $lureConstraints += $lureConstraintsingleVars
    
                    }
                }
            
    
    
    
    
    
    
    
    
    
        # Define the path to your lures
        $lures = Get-ChildItem -Path "D:\Apps\Backstop\v1\Client\lures"
    
        # Create a blank array to store the lures server-side constraint variables
        $lureConstraints = @()
    
        # For each module, see if it applies to the client or not. If it does, add it to the manifest array
        foreach ($module in $lures)
        {
            
            write-host "NAME=$module" -ForegroundColor Green
            
            # Read the file content
            $fileContent = Get-Content "$module"
    
            # Extract variable names and values
            foreach ($line in $fileContent) {
    
                if($line | Select-String -Pattern '\$Global\:[a-zA-Z0-9_]{1,35}')
                {
                    # Extract the variable name from the value
                    $modVarName = ($line -split '=')[0] -replace ' ', '' -replace '\$Global\:', ''
                    $modVarValue = ($line -split '=')[1] -replace '"', '' -replace ' ', ''
    
                    $lureConstraintsingleVars = @{$modVarName = $modVarValue}
    
                    $lureConstraints += $lureConstraintsingleVars
    
                }
            }
        }
    
    
    
    
    
    
    
    
    
    
    
    
            foreach($module in $modules)
            {
    
    
    
    
            }
    
            $manifest.hashList.$fileName = [PSCustomObject]@{fileName=$fileName; localDirectoryName=$localDirectoryName; remoteSHA256FileHash=$localSHA256FileHash}
    
    
    
    
            # Here we simply take what the client provided in the headers to see if it matches what's specified within the lure. 
            # Import the previous environments manifest file and warn if it's not there. We need to do this so we can compare files that changed from last time to now. If the files
            # haven't changed, we just re-hash them without re-signing them (which would change their hash value). If the hash values don't change, they won't be downloaded which is 
            # what we want in order to reduce load on the server. We just want files to be downloaded only when they're changed. The files we're talking about here are the ones in 
            # the bin, modules and scripts directories.
            if((Test-Path -Path "$customPath\ToServer\$Environment\etc\manifest.ps1xml"))
            {
                # Import the current manifest file in the build directory. This is used to help understand what's already been signed
                $previousManifest = Import-Clixml -Path "$customPath\ToServer\$Environment\etc\manifest.ps1xml"
    
            } Else {
    
                Write-Warning -Message "No manifest file found in $customPath\ToServer\$Environment\etc\. Will assume all files are new and build from scratch. WARNING: This means that clients will re-download all files again!"
            }
    
            # Create initial manifest object
            $newManifest = [ordered]@{
                hashList = @{}
            }
    
            # Define the names of the items to process.
            $directoryNames = @('bin','modules','scripts')
    
            # Remove any items (old or not) from the directory
            Remove-Item -Path "$customPath\ToServer\$Environment\*" -Recurse -Force
    
            foreach ($directoryName in $directoryNames)
            {
                # Recreate the needed directory
                New-Item -ItemType Directory "$customPath\ToServer\$Environment\$directoryName" -Force | Out-Null
    
                # Copy fresh files over from Backstop build environment to this directory
                Copy-Item -Path "$customPath\SourceFiles\$Environment\$directoryName\*" -Recurse -Destination "$customPath\ToServer\$Environment\$directoryName" -Force
    
                # Capture all the files we may want to hash in this directory IF they have changed since last time.
                $directoryItems = Get-ChildItem -Force -Path "$customPath\ToServer\$Environment\$directoryName" -File
    
                foreach ($file in $directoryItems)
                {
                    # Get the specific name of the file with the name attribute. Something like example.txt.
                    $fileName = $file.Name
    
                    # Get the local file hash of the file and, if possible, the previous hash of the same file in the old manifest file
                    $localSHA256FileHash = (Get-FileHash -Path "$customPath\ToServer\$Environment\$directoryName\$fileName" -Algorithm SHA256).Hash
                    $previousSHA256FileHash = ($previousManifest.hashList.Values | Where-Object {$_.localDirectoryName -eq "$directoryName"   -and   $_.fileName -eq "$fileName"}).remoteSHA256FileHash
    
                    # If we have the previous manifest file but the file wasn't listed, then it's missing and we just need to add it.
                    if(($previousManifest)   -and   (-not($previousSHA256FileHash)))
                    {
                        $updateReason = "fileMissing"
                    }
    
                    # IF we have the previous hash but it does not equal the new hash, we need to update it
                    if(($previousSHA256FileHash)   -and   ($localSHA256FileHash)   -and   ($previousSHA256FileHash -ne $localSHA256FileHash))
                    {
                        $updateReason = "hashMismatch"
                    }
    
                    # Update everything if the manifest is missing
                    if(-not($previousManifest))
                    {
                        $updateReason = "manifestMissing"
                    }
    
                    # If file doesn't exist in the previous manifest file (we assume it's new in such a case), sign the file and add the file + hash to the new manifest file
                    if($updateReason)
                    {
                        Write-host "NEW/CHANGED FILE: Adding $fileName to the new manifest file and signing it. Reason: $updateReason" -ForegroundColor Green
    
                        # Sign files
                        Set-FileSignature -File "$customPath\ToServer\$Environment\$directoryName\$fileName" -TrustLevel High -CertStoreLocation CurrentUser -QuietMode
    
                        # Define the variables needed for the itemProperties object
                        $localDirectoryName = "$directoryName"
    
                        # Update the local hash value again, now that it should be signed
                        $localSHA256FileHash = (Get-FileHash -Path "$customPath\ToServer\$Environment\$directoryName\$fileName" -Algorithm SHA256).Hash
    
                        # Create the object to be added to the object
                        # Remember, even though we're calling the "local" file hash here, we're prepping the manifest file the clients will download from the server. 
                        $newManifest.hashList.$fileName = [PSCustomObject]@{fileName=$fileName; localDirectoryName=$localDirectoryName; remoteSHA256FileHash=$localSHA256FileHash}
    
                        # Flush the variable so it's not picked up again on subsequent passes
                        Remove-Variable updateReason
    
                    } Else {
    
                        Write-host "EXISTING/UNCHANGED FILE: Adding $fileName to the new manifest file without updating its signature" -ForegroundColor Cyan
    
                        # Define the variables needed for the itemProperties object
                        $localDirectoryName = "$directoryName"
    
                        # Create the object to be added to the object
                        # Remember, even though we're calling the "local" file hash here, we're prepping the manifest file the clients will download from the server. 
                        $newManifest.hashList.$fileName = [PSCustomObject]@{fileName=$fileName; localDirectoryName=$localDirectoryName; remoteSHA256FileHash=$localSHA256FileHash}
                    }
                }
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
                }
            }
    
    
            # Scope Check. If generalScope is anything other than "any", break out of the loop if it's not what the module wants. Here, the singular osClass variable comes from the ClientCore functions module.
            if($generalScope -ne "any")
            {
                # Workstation Scope check
                if(($generalScope -eq "any-workstation") -and ($osClass -ne "workstation"))
                {
                    # Log Event
                    Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: $moduleName.psm1 was skipped since it didn't pass the general workstation scope check. Additional Info: generalScope=$generalScope osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
    
                    # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                    Continue
    
                } Else {
    
                    # Log Event
                    Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the general workstation scope check. Additional Info: generalScope=$generalScope osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
                }
    
                # Server Scope check
                if(($generalScope -eq "any-server") -and ($osClass -ne "server"))
                {
                    # Log Event
                    Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped since it didn't pass the general server scope check. Additional Info: generalScope=$generalScope osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
    
                    # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                    Continue
    
                } Else {
    
                    # Log Event
                    Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the general server scope check. Additional Info: generalScope=$generalScope osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
    
                }
    
                # Hostname Check. Here we can match based on a partial match or the whole hostname. For example, if the generalScope value is "WKS-US-TX-Arlington-" then the hostname of of the asset must at least *start with* that
                # or this script will skip this module and go on to the next. If there is a match, the module will be processed (won't break out of the loop). This will also work with the whole hostname as well if you want 
                # to target something more specifically.
                if(($generalScope -notmatch "any-workstation|any-server") -and ("$env:COMPUTERNAME" -notmatch "^$generalScope(.+){0,15}"))
                {
                    # Log Event
                    Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped since it didn't pass the general hostname scope check. Additional Info: generalScope=$generalScope osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
    
                    # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                    Continue
    
                } Else {
    
                    # Log Event
                    Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the general hostname scope check. Additional Info: generalScope=$generalScope osClass=$osClass" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
    
                }
            }
    
    
            # Domain Scope check. Here, we're saying "if you specified a specific domain (it's not "any" but something else), break out of the loop if the domain you specified doesn't match the assets domain. This is just a "break things if no match" rule.
            if($domainScope -ne "any")
            {
                # Domain Scope check.
                if($domainScope -ne $adDomain)
                {
                    # Log Event
                    Write-Log -eventTag "Import and Execute Modules" -eventSubTag "Domain Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped since it didn't pass the domain scope check. Additional Info: domainScope=$domainScope adDomain=$adDomain" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
    
                    # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                    Continue
    
                } Else {
    
                    # Log Event
                    Write-Log -eventTag "Import and Execute Modules" -eventSubTag "General Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the domain scope check. Additional Info: domainScope=$domainScope adDomain=$adDomain" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
                }
            }
    
    
            # Business unit scope check. 
            if($businessUnitScope -ne "any")
            {
                # Business unit scope check. If the businessUnitScope specified in the module is not equal to the assetBusinessUnit that the asset is on, skip it. Else proceed to try and execute the module.
                if($businessUnitScope -ne $assetBusinessUnit)
                {
                    # Log Event
                    Write-Log -eventTag "Import and Execute Modules" -eventSubTag "Business Unit Scope Check" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped since it didn't pass the business unit scope check. Additional Info: businessUnitScope=$businessUnitScope assetBusinessUnit=$assetBusinessUnit" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
    
                    # Break out of loop (stop here, do not process this module any further) and continue to the next module if there are any.
                    Continue
    
                } Else {
    
                    # Log Event
                    Write-Log -eventTag "Import and Execute Modules" -eventSubTag "Business Unit Scope Check" -severityLevel "info" -messages "RULE MATCHED: Module $moduleName.psm1 matched the business unit scope check. Additional Info: businessUnitScope=$businessUnitScope assetBusinessUnit=$assetBusinessUnit" -CustomLocalLogPath "$CustomLocalLogPath" -DoNotLogToSplunkHec
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
    
    
    
    
    
        #    } Else {
    
                # Log Event
        #        Write-Log -eventTag "Import and Execute Modules" -eventSubTag "-" -severityLevel "info" -messages "MODULE SKIPPED: Module $moduleName.psm1 was skipped. Additional Info: moduleName=$moduleName executionCount=$executionCount readyToRun=$readyToRun runOnce=$runOnce runIntervalInSeconds=$runIntervalInSeconds lastRunTime=$lastRunTime" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel
    
                # Skip this itteration and go on to next module in the loop
        #        Continue
        #    }
    
            #endregion OPTIONS AND CONSTRAINTS
    
    
        #}
    }

#endregion FUNCTIONS




##############################################################################################################################################################################
#region   SIGNATURE   ########################################################################################################################################################
##############################################################################################################################################################################


