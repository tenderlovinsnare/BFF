<#
                ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗ ██████╗ ██████╗ 
                ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
                ██████╔╝███████║██║     █████╔╝ ███████╗   ██║   ██║   ██║██████╔╝
                ██╔══██╗██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██║   ██║██╔═══╝ 
                ██████╔╝██║  ██║╚██████╗██║  ██╗███████║   ██║   ╚██████╔╝██║     
                ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝     
                                                        
             █████╗ ██████╗ ██╗    ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗            
            ██╔══██╗██╔══██╗██║    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗           
            ███████║██████╔╝██║    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝           
            ██╔══██║██╔═══╝ ██║    ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗           
            ██║  ██║██║     ██║    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║           
            ╚═╝  ╚═╝╚═╝     ╚═╝    ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝           

    .SYNOPSIS
      This is the API server for the Backstop Flexibility Framework platform


    .DESCRIPTION
      This API server was designed to sit directly on the internet and to handle the normal internet background
      radiation like port scans, scanners, bots, etc. The Backstop API server handles customizable input sanatization, 
      rate-limiting, and authentication. The Backstop API server is an integration platform in 
      
      Other than this script, this server is comprised of four components below:

      ↪ ServerSettings Module
        ----------------------
        The ServerCore module contains the primary working functions for the API server itself such as receiving requests, 
        how to respond back to API requests, logging, authentication rate-limiting, input sanitization, etc.


      ↪ ServerCore Functions Module
        ----------------------------
        The ServerCore module contains the primary working functions for the API server itself such as receiving requests, 
        how to respond back to API requests, logging, authentication rate-limiting, input sanitization, etc.


      ↪ BFFEndpoints Module
        --------------------
        This module contains all the individual endpoints in the form of functions which are called via this API server.


      ↪ CommonCore Functions Module
        ----------------------------
        The CommonCore module contains shared functions which both the client and the server can utilize to ensure that
        we're not duplicating code. These are functions such as logging to Splunk, encryption, hashing and many other common
        functions which can be used by either the client or the server.


    .NOTES
      Project:                Backstop Flexibility Framework (BFF)
      Public GitHub Repo:     https://github.com/humblecyberdude/BFF
      Copyright:              © 2024 TenderLovinSnare
      License:                MIT (https://opensource.org/license/mit)
      █ Last Updated By:      HumbleCyberDude
      █ Release Stage:        ALPHA
      █ Version:              0.1
      █ Last Update:          5-November-2024
      █ Latest Release Notes:
      ↪ Alpha Release

#>




##############################################################################################################################################################################
#region   INITIALIZE API SERVER   ############################################################################################################################################
##############################################################################################################################################################################

    #region IMPORT CORE SETTINGS AND MODULES #################################################################################################################################

        # Dynamically figure out the rootPath which should be something like E:\Apps\Backstop\Instances\v1
        $rootPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
        $rootPath = Split-Path -Path $rootPath -Parent
        $Global:rootPath = $rootPath

        Write-Host "Initializing API Server..."

        # Define a pseudo function name for this script simply for logging
        $Global:LogSource = "BFFApiServer"

        # Import initial settings variables
        Import-Module "$rootPath\server\ServerSettings.psm1" -Force

        # Define the shortname of the modules to import
        $modules = ('CommonCore','PSSQLite','ServerCore','BFFEndpoints')

        # Import each of the modules
        foreach ($moduleName in $modules)
        {
            # Pull the modules from the needed directories
            if ($moduleName -eq "PSSQLite")
            {
                $modulePath = "$rootPath\server\modules\PSSQLite\1.1.0"

            } Elseif($moduleName -eq "CommonCore"){

                $modulePath = "$rootPath\shared\modules"
            
            } Else {

                $modulePath = "$rootPath\server\modules"
            }

            # Import the modules we need so we can get things running
            Import-Module "$modulePath\$moduleName.psm1" -Force

            # Ensure that the API core functions module was imported correctly
            if(-Not(Get-Module -Name $moduleName))
            {
                # Refresh Timestamp
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MMM-dd HH:mm:ss.ffff UTC")

                # Create the log line in field="value" format.
                $logLine = "$timestamp eventTag=`"IMPORT CORE MODULES`" severityLevel=`"CRITICAL`" Comments=`"Unable to load module $moduleName. Exiting!`""

                # Write log to disk
                Add-Content -Path $consoleLogPath -Value "$logLine"

                # Eject! Eject!
                Break
            }
        }

    #endregion IMPORT CORE SETTINGS AND MODULES


    #region CONNECT TO DATABASE ##############################################################################################################################################

        # Open the database connection for the endpoints to use
#$backstopDatabasePath = "$rootPath\Server\db\backstop.db"
#$Global:dbConnection = New-SQLiteConnection -DataSource $backstopDatabasePath

    #endregion CONNECT TO DATABASE


    #region IMPORT SECRETS ###################################################################################################################################################

        # Import Secrets and open the vault in memory. This will aquire the variable $Vault.
        Open-SimpleVault -VaultPath "$rootPath\Server\etc\secrets.json"

        # If the vault was able to be opened, aquire the secrets and cache them.
        if($Vault)
        {
            # Aquire the secrets from the vault using DPAPI to decrypt them and add to general variable names
            Get-SimpleVaultSecret -Name dbDecryptionKey
            Get-SimpleVaultSecret -Name hmacSecretStandardKey
            Get-SimpleVaultSecret -Name hmacSecretRegistrationKey
            Get-SimpleVaultSecret -Name hmacSecretRemovalKey
            Get-SimpleVaultSecret -Name hmacSecretAdminKey
            Get-SimpleVaultSecret -Name canaryApiKey
            Get-SimpleVaultSecret -Name splunkHecToken

            # Do a basic check to ensure that you have at least 5 vault secrets
            if((Get-Item -Path ENV:*_vaultSecret).count -lt 5)
            {
                Write-ApiLog -LogType Server -SeverityLevel Error -eventTag "Get Vault Secrets" -LogComments "Unable to get at least five vault secrets!"

                # Break since we can't authenticate anyway
                Break
            }

        } Else {

            Write-ApiLog -LogType Server -SeverityLevel Error -eventTag "Open Vault" -LogComments "Unable to open vault!"

            # Break since we can't authenticate anyway
            Break
        }

    #endregion IMPORT SECRETS

#endregion INITIALIZE API SERVER




##############################################################################################################################################################################
#region   START API SERVER   #################################################################################################################################################
##############################################################################################################################################################################

    #region START LISTENER ###################################################################################################################################################

        # Using HTTP.SYS, start our HTTP listener on the loopback IP on TCP port 
        $Global:listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("https://+:443/")
        $listener.Start()

        if($listener.IsListening)
        {
            Write-Host "Server online and listening" -ForegroundColor Green
            Write-ApiLog -LogType Server -SeverityLevel Info -eventTag "Server Start/Stop" -LogComments "Server online and listening"

        } Else {

            Write-Error "Unable to start listener!"
            Write-ApiLog -LogType Server -SeverityLevel Error -eventTag "Server Start/Stop" -LogComments "Unable to start listener!"
        }
        

    #endregion START LISTENER


    #region SERVICE REQUESTS #################################################################################################################################################

        # Start the API server listener and apply a loop label to it so we can call it for terminating requests. The reason for the label is to ensure that we always 
        # return to this specific point if we want to terminate a request such as when using Send-APIResponse for example. If we just used "continue" it only breaks 
        # out of the inner-most loop and may not be enough to fully terminate the request so we generically call ApiServerLoop so it's "set and forget".
        :ApiServerLoop while ($true)
        {

            # Capture the initial request so we can parse it and get ready to respond if it's valid
            Receive-Request

            # Confirm that the inputs provided by the clients are in correct formats
            Confirm-Inputs


            ##################################################################################################################################################################
            #region   VERIFY AND AUTHENTICATE REQUESTS   #####################################################################################################################
            ##################################################################################################################################################################

                # Standard rate-limiting and authentication for endpoint requests
                if(($uriPath -like "/$instanceVersion/endpoints/*")   -and   ($uriPath -notmatch "^/$instanceVersion/endpoints/(register|unregister)"))
                {
                    #Limit-Requests -MaxRequests  -TimespanInMin 
                    #Confirm-Authentication -AuthType Standard

                # Standard rate-limiting and authentication for endpoint requests
                } Elseif($uriPath -eq "/$instanceVersion/endpoints/register"){

                    #Limit-Requests -MaxRequests  -TimespanInMin 
                    #Confirm-Authentication -AuthType Register

                # Standard rate-limiting and authentication for endpoint requests
                } Elseif($uriPath -eq "/$instanceVersion/endpoints/unregister"){

                    #Limit-Requests -MaxRequests  -TimespanInMin 
                    #Confirm-Authentication -AuthType Unregister

                } Elseif ($uriPath -like "/$instanceVersion/admin/*"){

                    #Limit-Requests -MaxRequests  -TimespanInMin 
                    #Confirm-Authentication -AuthType Admin

                } Else {

                    Send-APIResponse -StatusCode 401 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client `"$clientHostname`" either not in the DB or has a state other than 'installed'"
                }

            #endregion VERIFY AND AUTHENTICATE REQUESTS


            ##################################################################################################################################################################
            #region   ENDPOINT ROUTING   #####################################################################################################################################
            ##################################################################################################################################################################
                
                # Endpoints > Test
                if(($method -eq "Get")   -and   ($uriPath -eq "/$instanceVersion/endpoints/test"))
                {
                    Get-Test



                # Endpoints > File Downloads
                } ElseIf(($method -eq "Get")   -and   ($uriPath -eq "/$instanceVersion/endpoints/files")){

                    Send-File -FileName $FileName


                # Endpoints > Register Endpoint
                } ElseIf(($method -eq "POST")   -and   ($uriPath -eq "/$instanceVersion/endpoints/register")){

                    <#
                        Register:
                        1. Initial POST request for the registration: Provides full client details needed to populate the DB
                        2. IF SUCCESS: API server responds back with a "201 created" message and the install directories + updates the clientState to "registering"
                        3. IF SUCCESS: Client finishes install process then beacons back with a second and final POST that the install was completed successfully. API server send back a 200 OK and marks clientState as "registered"
                    #>

                   Register-Endpoint


                # Endpoints > Unregister Endpoint
                } ElseIf(($method -eq "POST")   -and   ($uriPath -eq "/$instanceVersion/endpoints/unregister")){

                    <#
                        Unregister:
                        1. Initial POST request to unregister: Provides standard client hostname and correct API key
                        2. IF SUCCESS: API server responds back with a "200 OK" message and the install directories + updates the clientState to "uninstalling"
                        3. IF SUCCESS: Client finishes install process then beacons back with a second and final POST that the install was completed successfully. API server send back a 200 OK and marks clientState as "unregistered"
                    #>

                    Unregister-Endpoint


                # 
                } ElseIf(($method -eq "Post")   -and   ($uriPath -like "/$instanceVersion/admin/qrcode")){

                    New-AdminTOTP


                # Get OTP QR CODE
                } ElseIf(($method -eq "Get")   -and   ($uriPath -like "/$instanceVersion/admin/qrcode")){
                    
                    Get-AdminTOTP


                # 
                } ElseIf(($method -eq "Post")   -and   ($uriPath -like "/$instanceVersion/admin/passwordReset")){

                    Set-AdminPassword


                # This is the initial Admin endpoint to aquire the auth token (username, password + MFA) which allows for subsequent requests without having to use MFA with
                # each request. This endpoint should facilitate a JWT token or similar approach where the client is given a time-based sign bearer token.
                } ElseIf(($method -eq "Get")   -and   ($uriPath -like "/$instanceVersion/admin/authToken")){

                    New-AdminAuthToken


                # Endpoints > Administration
                } ElseIf(($method -eq "Get")   -and   ($uriPath -eq "/$instanceVersion/admin/endpoints")){

                    # New Endpoints Here
                    # MUST HAVE
                    # - MFA 
                    # - ABILITY TO LOCK DOWN TO ONLY CERTAIN SUBNETS

                # Give 404 back for any non-existent endpoint
                } Else {

                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either requested a non-existent endpoint and/or a bad method for that endpoint"
                }

            #endregion ENDPOINT ROUTING
        }

    #endregion SERVICE REQUESTS
#endregion START API SERVER



##############################################################################################################################################################################
#region   SIGNATURE   ########################################################################################################################################################
##############################################################################################################################################################################


