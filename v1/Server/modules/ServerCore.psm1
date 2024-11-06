<#

       ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗ ██████╗ ██████╗     ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗     
       ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗    
       ██████╔╝███████║██║     █████╔╝ ███████╗   ██║   ██║   ██║██████╔╝    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝    
       ██╔══██╗██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██║   ██║██╔═══╝     ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗    
       ██████╔╝██║  ██║╚██████╗██║  ██╗███████║   ██║   ╚██████╔╝██║         ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║    
       ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝         ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝    
                                                                                                                                  
            ██████╗ ██████╗ ██████╗ ███████╗    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗        
           ██╔════╝██╔═══██╗██╔══██╗██╔════╝    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝        
           ██║     ██║   ██║██████╔╝█████╗      █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗        
           ██║     ██║   ██║██╔══██╗██╔══╝      ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║        
           ╚██████╗╚██████╔╝██║  ██║███████╗    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║███████║        
            ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝        


    .SYNOPSIS
      This is the core functionality module specific to the API server.


    .DESCRIPTION
      Separate from the endpoints module, this module contains all the needed elements to run the server itself including how to handle 
      HTTP requests, logging, authentication and rate-limiting among others. See the documentation for each function for further details.


    .NOTES
      Project:                Backstop Flexibility Framework (BFF)
      Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
      Copyright:              © 2024 | TenderLovinSnare
      Contact:                TenderLovinSnare@gmail.com
      License:                MIT (https://opensource.org/license/mit)
      █ Last Updated By:      TenderLovinSnare
      █ Release Stage:        ALPHA
      █ Version:              0.2
      █ Last Update:          26-October-2024
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
#region  FUNCTIONS  ##########################################################################################################################################################
##############################################################################################################################################################################

    Function Write-ApiLog
    {
        <#
            .SYNOPSIS
              Logs operational console logs for the API server itself or access logs for client requests.


            .DESCRIPTION
              Writes two separate logs to disk in a standardized field="value" format for easy ingestion into SIEM's.


            .NOTES
              Project:                Backstop Flexibility Framework (BFF)
              Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
              Copyright:              © 2024 | TenderLovinSnare
              Contact:                TenderLovinSnare@gmail.com
              License:                MIT (https://opensource.org/license/mit)
              █ Last Updated By:      TenderLovinSnare
              █ Release Stage:        ALPHA
              █ Version:              0.1
              █ Last Update:          6-July-2024
    

            .PARAMETER LogType
              Specifies one of the two log types below. The logging fields are different for each.
              ↪ ACCESS: Use this for any API requests from any clients accessing any resources
              ↪ JUNK:   Use this for any garbage HTTP logs that are almost certainly not going to be valid requests (IBR/IBN traffic)
              ↪ SERVER: Use this for any internal server operational logs
              ↪ ADMIN:  Use this for any administrative access logging


            .PARAMETER EventTag
              A logical tag to better categorize the event


            .PARAMETER SeverityLevel
              A roughly standard list of severity levels


            .PARAMETER LogComments
              This should be the "plain-english" wording of what really happened so that even the new guy can get an idea of at least what happened


            .PARAMETER AccessLogPath
              The path to the access log for client requests for visibility and troubleshooting


            .PARAMETER ServerLogPath
              The path to the internal API log for visibility and troubleshooting


            .PARAMETER JunkLogPath
              The path for the junk HTTP request log. Logs are for IBN or "Internet Background Noise" such as port scans, vuln scanners, etc.


            .EXAMPLE
              Write-ApiLog -LogType Server -eventTag "Get Vault Secrets" -SeverityLevel Error -LogComments "Unable to open vault... Exiting"
              ↪ Writes a server log specific to the operation of the API server itself, separate from client requests.
              ↪ Tags it with w/e tag you want to organize your events - usuall based on function or region of code.
              ↪ Simple severity level of the event. NOTE: Check variable DefaultLogLevel if your logs aren't being written. Set DefaultLogLevel to either Debug and Info as needed.
              ↪ Human comments that actually state what's actually going on
      
              Write-ApiLog -LogType Access -eventTag "Endpoint Name Here" -SeverityLevel Info -LogComments "Example: Client requested X and it was successfully served"
              ↪ Same as above, just an access log for a client request

        #>




    ##########################################################################################################################################################################
    #region   PARAMETERS   ###################################################################################################################################################
    ##########################################################################################################################################################################

        Param
        (
            # Access is the access log which includes more details about the specific request whereas Console is more for operational logs for the API server
            [parameter(Mandatory=$true)]
            [ValidateSet('Access', 'Junk', 'Server', 'Admin')]
            [String]$LogType,

            # A general tag for the function, section of code or module name
            [parameter(Mandatory=$false)]
            [String]$EventTag,

            # Specifies the severity of the message            
            [parameter(Mandatory=$true)]
            [ValidateSet('DEBUG', 'INFO', 'NOTICE', 'WARN', 'ERROR', 'CRITICAL')]
            [String]$SeverityLevel,

            # Allows you to put in plain-english comments for the log line
            [parameter(Mandatory=$false)]
            [String]$LogComments,

            # Specify the path for the access log
            [parameter(Mandatory=$false)]
            [String]$AccessLogPath,

            # Specify the path for the internal API server log
            [parameter(Mandatory=$false)]
            [String]$ServerLogPath,

            # Specify the path for the junk HTTP request log
            [parameter(Mandatory=$false)]
            [String]$JunkLogPath
        )

    #endregion PARAMETERS




    ######################################################################################################################################################################
    #region   VARIABLES   ################################################################################################################################################
    ######################################################################################################################################################################

        # Set the default logging level if it's not already defined
        if(-Not($DefaultLogLevel))
        {
            # Set to info as a balanced setting if not specified elsewhere
            $DefaultLogLevel = "Info"
        }

        # Set the default log paths if not already set (rootPath is pulled from Initialize-APIServer on the API server script itself)
        if($LogType -eq "Access")
        {
            $AccessLogPath = "$rootPath\Server\logs\access.log"

        } elseif ($LogType -eq "Junk") {

            $junkLogPath = "$rootPath\Server\logs\junk.log"

        } elseif ($LogType -eq "Server") {

            $serverLogPath = "$rootPath\Server\logs\server.log"

        } elseif ($LogType -eq "Admin") {

            $adminLogPath = "$rootPath\Server\logs\admin.log"
        }
    
        # Set the tags to unspecified if not set
        if(-Not($EventTag))
        {
            $EventTag = "unspecified"
        }

        # Each function should have its own name defined as a variable. If not, log this as the value
        if(-Not($LogSource))
        {
            $LogSource = "UNKNOWN_FIX_ME!"
        }

    #endregion VARIABLES




    ######################################################################################################################################################################
    #region   LOG TO FILE   ##############################################################################################################################################
    ######################################################################################################################################################################

        # Honor the DefaultLogLevel set on the API server. For clarity: 
        # ↪ Problems = Notice or Above      (Any warnings, errors or problems)
        # ↪ Info = Info and Above           (Normal operational or transactional logs + Above)
        # ↪ Debug = Debug and Above         (Verbose logs for troubleshooting + all of above)
        if(($DefaultLogLevel -eq "Debug")   -or   ($DefaultLogLevel -eq "Info" -and $severityLevel -ne "debug")   -or   ($DefaultLogLevel -eq "Problems" -and $severityLevel -notmatch "debug|info"))
        {
            # Set default log paths based on LogType
            if(($LogType -eq "Access")   -or   ($LogType -eq "Junk"))
            {
                # Set the log path set originally in API Server > INITIALIZE API SERVER > SETUP LOGGING
                if($LogType -eq "Access") {$LogPath = $AccessLogPath}
                if($LogType -eq "Junk") {$LogPath = $JunkLogPath}

                # Grab the response code so we can log it
                $statusCode = $response.StatusCode
    
                # Define the Client IP address to compare against the Proxy subnets. Note that this is what's in the XFF header from the reverse proxy.
                [System.Net.IPAddress]$clientIP = $clientIP
    
                # Define Proxy subnets to check the IP address against
                $proxySubnetsSubnets = @{
                    # EXAMPLE: "1.2.3.0" = "255.255.255.0"
                    #REPLACE_ME!
                }
    
                # Define RFC1918 subnets
                $rfc1918Subnets = @{
                    "10.0.0.0" = "255.0.0.0"
                    "172.16.0.0" = "255.240.0.0"
                    "192.168.0.0" = "255.255.0.0"
                }
    
                # On Proxy or Internet Check
                foreach ($item in $proxySubnetsSubnets.GetEnumerator())
                {
                    # Define the subnets (basically each line in the hash table one at a time)
                    [System.Net.IPAddress]$ProxySubnet = $($item.Name)
                    [System.Net.IPAddress]$ProxySubnetMask = $($item.Value)
    
                    # If there's a match (the IP is within one of the Proxy subnets), mark isLocalIP=true. Else isLocalIP=false.
                    if($ProxySubnet.Address -eq ($clientIP.Address -band $ProxySubnetMask.Address))
                    {
                        $clientZone = "proxySubnet"
    
                        # Break out of the loop or else we'll almost certainly hit the else statement below and variable will be wrong.
                        break

                    } Else {

                        $clientZone = "Internet"
                    }
                }

                # RFC1918 Check
                foreach ($item in $rfc1918Subnets.GetEnumerator())
                {
                    # Define the subnets (basically each line in the hash table one at a time)
                    [System.Net.IPAddress]$rfc1918Subnet = $($item.Name)
                    [System.Net.IPAddress]$rfc1918SubnetMask = $($item.Value)
    
                    # If there's a match (the clientIP is within one of the RFC1918 subnets), mark isLocalIP=true. Else isLocalIP=false.
                    If($rfc1918Subnet.Address -eq ($clientIP.Address -band $rfc1918SubnetMask.Address))
                    {
                        $clientZone = "Intranet"
                    }
                }

                # Verify if UserAgent is correct by checking for the presents of either at the start of the agent string
                if($userAgent -match "^Backstop")
                {
                    $userAgentStatus = "Valid"

                } Else {

                    $userAgentStatus = "Invalid"
                }

                # Refresh Timestamp
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MMM-dd HH:mm:ss.ffff UTC")

                # Create the log line in field="value" format.
                $logLine = "$timestamp LogSource=`"$LogSource`" eventTag=`"$eventTag`" severityLevel=`"$severityLevel`" clientIP=`"$clientIP`" clientHostname=`"$clientHostname`" method=`"$method`" uriPath=`"$uriPath`" statusCode=`"$statusCode`" LogComments=`"$LogComments`" inputChecksVerified=`"$inputChecksVerified`" authenticationVerified=`"$authenticationVerified`" rateLimitVerified=`"$rateLimitVerified`" fileName=`"$fileName`" clientZone=`"$clientZone`" serverHost=`"$serverHost`" userAgentStatus=`"$userAgentStatus`" GeneralContentType=`"$GeneralContentType`" userAgent=`"$userAgent`""

                # Write log to disk
                Add-Content -Path $LogPath -Value "$logLine"

            } elseif ($LogType -eq "Server") {

                $LogPath = $ServerLogPath

                # Refresh Timestamp
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MMM-dd HH:mm:ss.ffff UTC")

                # Create the log line in field="value" format.
                $logLine = "$timestamp LogSource=`"$LogSource`" eventTag=`"$eventTag`" severityLevel=`"$severityLevel`" LogComments=`"$LogComments`""

                # Write log to disk
                Add-Content -Path $LogPath -Value "$logLine"
                
            } elseif ($LogType -eq "Admin") {

                $LogPath = $AdminLogPath

                # Refresh Timestamp
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MMM-dd HH:mm:ss.ffff UTC")

                # Create the log line in field="value" format.
                $logLine = "$timestamp LogSource=`"$LogSource`" eventTag=`"$eventTag`" severityLevel=`"$severityLevel`" LogComments=`"$LogComments`""

                # Write log to disk
                Add-Content -Path $LogPath -Value "$logLine"
            }
        }
    #endregion LOG TO FILE
    }




    function Receive-Request
    {
        <#
            .SYNOPSIS
            Captures the initial requests and sets up the variables we need so we can respond back to the request.


            .DESCRIPTION
            The function operates by listening for HTTP requests on the address above. When an HTTP request is received, this function captures
            the details of the request and sets up the right variables to respond back.


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              © 2024 | TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          6-July-2024

        #>


        # Dynamically get the function name for logging
        $LogSource = (Get-PSCallStack)[0].LogSource

        # Get the context of the entire HTTP request
        $Global:context = $listener.GetContext() 

        # Capture all the details about the request such as headers, URL, user-agents, etc. that we can key off of later
        $Global:request = $context.Request

        # Read the request headers to capture them in the variable $requestHeaders
        $Global:requestHeaders = @{}
        $request.Headers.AllKeys | ForEach-Object {
            $Global:requestHeaders[$_] = $request.Headers.Get($_)
        }

        # If the thsis API server isn't behind a load balancer, use the raw source IP. Else, grab the XFF IP as the clientIP.
        if(-not $behindLoadBalancer)
        {
        $RemoteEndPoint = [string]$Request.RemoteEndPoint
        $Global:clientIP = $RemoteEndPoint.Split(':')[0]
        $Global:clientPort = $RemoteEndPoint.Split(':')[1]

        } Else {

            # Get the real clientIP from the XFF header. Note that you may need to change the header name to match the header name
            # given in the request. To see all items and headers in the request, look at $request
            $Global:clientIP = ($requestHeaders)."X-Forwarded-For"
        }

        # Extract critical variables for our other functions to utilize
        $Global:serverHost = ($requestHeaders).Host
        $Global:userAgent = ($requestHeaders)."User-Agent"
        $Global:method = ($request).HttpMethod
        $Global:clientSubmittedApiKey = $requestHeaders.apiKey
        $Global:clientHostname = $requestHeaders.clientHostname
        $Global:scriptFileHashSHA256 = $requestHeaders.scriptFileHashSHA256
        $Global:clientSalt = $requestHeaders.clientSalt
        $Global:fileName = $requestHeaders.fileName
        $Global:contentType = $requestHeaders['Content-Type']
        $Global:acceptEncoding = $requestHeaders['Accept-Encoding']
        $Global:contentLength = $requestHeaders['Content-Length']
        $Global:memo = $requestHeaders.memo
        $Global:kind = $requestHeaders.kind

        # Read the body of the request
        $streamReader = New-Object IO.StreamReader($request.InputStream)
        $Global:requestBody = $streamReader.ReadToEnd()
        $streamReader.Close()

        # Extract portions of the URL
        $Global:fullUrl = $request.Url
        $Global:queryString = [System.Uri]::new($fullUrl).Query
        $Global:uriPath = [System.Uri]::new($fullUrl).AbsolutePath

        # Setup a place to deliver a response
        $Global:response = $context.Response

        # DEBUG
        $requestHeaders | Select-Object *

    }




    function Confirm-Inputs
    {
        <#
            .SYNOPSIS
            Validates input for requests to ensure that they contain the correct headers and that the values are in line with what is expected. 


            .DESCRIPTION
            This function validates the input for requests to ensure that they not only contain the required fields but also that the values for 
            those fields are what's expected. For example, if a value for a given field should be a SHA256 hash, then ensure it matches a 
            fixed-length HEX string. This ensures that the requests are validated and if anything is incorrect, the request will be denied. This
            function has two main parts: 
    
            COMMON INPUT VALIDATION 
            ↪ Validation for any incoming request (i.e. what's common to all)
    
            ENDPOINT SPECIFIC INPUT VALIDATION
            ↪ Validation custom to that specific endpoints unique needs


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              © 2024 | TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          20-July-2024
    
        #>




        ##########################################################################################################################################################################
        #region   VARIABLES   ####################################################################################################################################################
        ##########################################################################################################################################################################

            # Dynamically get the function name for logging
            $Global:LogSource = (Get-PSCallStack)[0].LogSource

        #endregion VARIABLES




        ##########################################################################################################################################################################
        #region   GENERAL INPUT VALIDATION   #####################################################################################################################################
        ##########################################################################################################################################################################

            # This is the general input validation globally for all requests.

            # Check for a valid user-agent. We do this first to more quickly process garbage requests.
            if(-not $behindLoadBalancer)
            {

            # REMOVE: TEST CODE
            # If user-agent doesn't start with "Backstop" then 
            if($userAgent -match "(^Test)|(^Mozilla)")
            {
                return
            }

                # If user-agent doesn't start with "Backstop" then 
                if($userAgent -notmatch "^Backstop")
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -LogTypeOverride Junk -Body "API: Bad Request" -LogComments "Client provided a user-agent of $userAgent which is an invalid request"
                }
            }

            # Define the only valid headers allowed and check each header to ensure they're on the valid headers list
            $validCommonHeaders = ('host', 'Accept-Encoding', 'User-Agent', 'Connection', 'X-ARR-SSL', 'Max-Forwards', 'X-Forwarded-For', 'X-ARR-LOG-ID', 'X-Original-URL', 'apikey', 'clientSalt', 'clientHostname', 'scriptHash', 'acceptEncoding', 'fileName', 'kind', 'memo', 'hashedUsername', 'clientState', 'removalToken', 'clientSalt', 'reason', 'Content-Type', 'updateType', 'Content-Length')

            # Capture all headers in client request as an array
            $requestHeaderNames = $requestHeaders.Keys

            # Itterate through each client-supplied header to ensure that each one is a valid header name as defined in $validHeaders
            foreach($requestHeaderName in $requestHeaderNames)
            {
                if ($validCommonHeaders -notcontains $requestHeaderName)
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client provided headerName `"$requestHeaderName`" which is not allowed"
                }
            }

            # Ensure there are no query string parameters in the URI path. If so, deny the request. Nothing against them but here we just use and prefer headers instead for now.
            if($queryString)
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client provided a query string of `'$queryString`' in the URI path which is not allowed."
            }

            # For valid headers, if they exist, ensure that they match what should be expected. The first part of the regex (prior to the middle '|') is for standard API key's while the second half is for the 
            # removalApiKey which is a different format.
            if((-Not($requestHeaders.apikey))   -or   ($requestHeaders.apikey -notmatch "(^([\+]|[\/]|[a-zA-Z0-9]){43}\=$)|(^[a-fA-F0-9]{64}$)"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the apiKey header and/or the value in that header was not in the correct format. If it exists, the bad value of the apiKey was: "$requestHeaders.apikey""
            }

            # Ensure that the clientHostname matches the correct format
            if((-Not($requestHeaders.clientHostname))   -or   ($requestHeaders.clientHostname -notmatch "^[a-zA-Z0-9\-]{1,30}$"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the clientHostname header and/or the value in that header was not in the correct format. If it exists, the value of the clientHostname was: "$requestHeaders.clientHostname""
            }

            # Ensure that the scriptHash matches the correct format
            if((-Not($requestHeaders.scriptHash))   -or   ($requestHeaders.scriptHash -notmatch "^[a-fA-F0-9]{64}$"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the scriptHash header and/or the value in that header was not in the correct format. If it exists, the value of the scriptHash was: "$requestHeaders.scriptHash""
            }

    # Ensure that gzip is not specified for encoding - WHY!?
    #if($acceptEncoding -notmatch "gzip")
    #{
    #    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request - Must Speciy TransferEncoding gzip" -LogComments "For header acceptEncoding, client provided bad format. Value for header was "$requestHeaders.acceptEncoding" which is not valid - must be gzip."
    #}

            # Ensure that there's no body in get request
            if(($method -eq "Get")   -and   ($requestBody))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client provided data in the body of a GET request."
            }

        #endregion GENERAL INPUT VALIDATION




        ##########################################################################################################################################################################
        #region   ENDPOINT SPECIFIC INPUT VALIDATION   ###########################################################################################################################
        ##########################################################################################################################################################################

            # Start input validation on a per-endpoint basis starting with the most requested items first (first match wins with elseif). Not that most of these checks will check
            # if the header is missing or if it's present, is the values for the data in the correct format.

            if(($method -eq "Get")   -and   ($uriPath -eq "/$instanceVersion/endpoints/ping"))
            {

                # TO BE DONE



            # REMOVE: TEST INPUT VALIDATION RULE
            } elseif ($userAgent -eq "test"){

                # Do nothing

            # Input validation for client file downloads
            } elseif (($method -eq "Get")   -and   ($uriPath -eq "/$instanceVersion/endpoints/files")){

                if((-Not($requestHeaders.fileName))   -or   ($requestHeaders.fileName -notmatch "^[a-zA-Z0-9-_.]{1,50}$"))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the fileName header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.filename""
                }

            # Input validation for Splunk HEC relay
            } elseif (($method -eq "Post")   -and   ($uriPath -eq "/$instanceVersion/endpoints/hecrelay")){

                if((-Not($requestBody))   -or   (-Not($requestBody | Test-Json)))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the fileName header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.filename""
                }

            # Input validation for aquiring Canary tokens
            } elseif (($method -eq "Get")   -and   ($uriPath -eq "/$instanceVersion/endpoints/tokens")){

                if((-Not($requestHeaders.kind))   -or   ($requestHeaders.kind -notmatch "(active\-directory\-login)|(autoreg\-google\-docs)|(autoreg\-google\-sheets)|(aws\-id)|(aws\-s3)|(azure\-id)|(cloned\-web)|(dns)|(doc\-msexcel)|(doc\-msword)|(fast\-redirect)|(gmail)|(google\-docs)|(google\-sheets)|(googledocs\_factorydoc)|(googlesheets\_factorydoc)|(http)|(msexcel\-macro)|(msword\-macro)|(office365mail)|(pdf\-acrobat\-reader)|(qr\-code)|(sensitive\-cmd)|(signed\-exe)|(slack\-api)|(slow\-redirect)|(web\-image)|(windows\-dir)|(wireguard)"))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the kind header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.kind""
                }

                if((-Not($requestHeaders.memo))   -or   ($requestHeaders.memo -notmatch "^Host\=[a-zA-Z0-9\-_]{1,30}\sUser\=[a-zA-Z0-9\-\._\\]{1,30}\sDIR\=[a-zA-Z0-9\:\-\.\s\\_]{1,120}\sNOTES\=[a-zA-Z0-9\-_\.\s]{1,160}$"))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the memo header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.memo""
                }

            # Input validation for clients finding out what the persona of a system is
            } elseif (($method -eq "Get")   -and   ($uriPath -eq "/$instanceVersion/endpoints/persona")){

                if((-Not($requestHeaders.hashedUsername))   -or   ($requestHeaders.hashedUsername -notmatch "^([a-zA-Z]|\d|\+|\/|\=){88}$"))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the hashedUsername header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.hashedUsername""
                }

            # Input validation for installing and registering endpoints
            } elseif (($method -eq "Post")   -and   ($uriPath -eq "/$instanceVersion/endpoints")){

                if((-Not($requestHeaders.clientState))   -or   ($requestHeaders.clientState -notmatch "(installing)|(installed)"))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the clientState header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.clientState""
                }

                if(($requestHeaders.clientState -eq "installing")   -and   (-Not($clientSalt)))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client said that it's installing but is missing clientSalt"
                }

            # Input validation for uninstalling and unregistering endpoints
            } elseif (($method -eq "Delete")   -and   ($uriPath -eq "/$instanceVersion/endpoints")){

                if((-Not($requestHeaders.removalToken))   -or   ($requestHeaders.removalToken -notmatch "^[a-fA-F0-9]{64}$"))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the removalToken header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.removalToken""
                }

                if((-Not($requestHeaders.clientState))   -or   ($requestHeaders.clientState -notmatch "(uninstalling)|(uninstalled)"))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the clientState header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.clientState""
                }

                # Ensure that the clientSalt matches the correct format
                if((-Not($requestHeaders.clientSalt))   -or   ($requestHeaders.clientSalt -notmatch "^[a-zA-Z0-9]{16}$"))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the clientSalt header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.clientSalt""
                }

                if((-Not($requestHeaders.reason))   -or   ($requestHeaders.reason -notmatch "^[a-zA-Z0-9\s]{1,50}$"))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the reason header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.reason""
                }

                # Ensure removal key exists in the Backstop DB
                if(-not($clientRegData.removalToken))
                { 
                    Send-APIResponse -StatusCode 404 -GeneralContentType Text -Body "API: Not Found" -LogComments "Unable to find the removal token in the DB for the client"
                }

            # Input validation for updating the Backstop API server
            } elseif (($method -eq "Post")   -and   ($uriPath -eq "/$instanceVersion/update")){

                if((-Not($requestHeaders.contentType))   -or   ($requestHeaders.contentType -notmatch "^application\/octet-stream$"))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the contentType header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.contentType""
                }

                if((-Not($requestHeaders.updateType))   -or   ($requestHeaders.updateType -notmatch "(^database$)|(^code$)"))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the updateType header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.updateType""
                }

            # Input validation for updating the Backstop API server
            } elseif (($method -eq "Post")   -and   ($uriPath -eq "/$instanceVersion/admin/totp")){

                if(-Not($contentLength -eq 0))
                {
                    Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client appeared to provid information in the POST since contentLength > 0 which is not allowed. Content-Length of header was $contentLength"
                }

            # Input validation for updating the Backstop API server
            } elseif (($method -eq "Get")   -and   ($uriPath -eq "/$instanceVersion/admin/qrcode")){



            }

        #endregion ENDPOINT SPECIFIC INPUT VALIDATION
    }




    function Limit-Requests
    {
    <#
        
    
    
    
    
    
    
    
        1. DO NOT USE YET - TO BE CONVERTED FROM POWERSHELL UNIVERSAL/RE-WRITTEN
        2. Any way to do impossible travel and/or source IP monitoring to ensure that an endpoint isn't logging in from too many different IP's? If so, configuring via settings.
    
    
    
    
    
    
    
    
    
    
        .SYNOPSIS
          A simple, sliding-window rate limiter for requests to the API server.


        .DESCRIPTION
          This is a sliding window rate limiter. Basically, a more granular version of fixed window rate limiter which adjusts the limits over a
          sliding window of time. When clients make a request, they go into a bucket for the last rolling X number of minutes. If you exceed the
          threshold of Y requests in that rolling X period of minutes, your requests will be denied.


        .NOTES
          Project:                Backstop Flexibility Framework (BFF)
          Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
          Copyright:              © 2024 | TenderLovinSnare
          Contact:                TenderLovinSnare@gmail.com
          License:                MIT (https://opensource.org/license/mit)
          █ Last Updated By:      TenderLovinSnare
          █ Release Stage:        ALPHA
          █ Version:              0.1
          █ Last Update:          20-July-2024
  

        .PARAMETER AuthType
          Specifies the type of the endpoint request. For Security, there are different private keys per endpoint. Each endpoint type is described below:
          ↪ STANDARD:   Any general endpoint request post registration. For example, beaconing back, downloading files, etc.
          ↪ REGISTER:   Initial registration request when installing the endpoint. For example, doing a POST request to the ../endpoints (clients) API endpoint.
          ↪ UNREGISTER: Removal request to uninstall the endpoint. For example, doing a DELETE request to the ../endpoints (clients) API endpoint.
          ↪ ADMIN:      Requests to update the Backstop API server. For example, doing a POST request to the ../update API endpoint.
  

        .PARAMETER TimespanInMin
          Specifies the period of time, in minutes, which the rate limit cover. For example, if you only want the endpoint hit
          no more than 30 times in a 60 minute period, specify the TimespanInMin as 60 and the MaxRequests as 30.


        .PARAMETER MaxRequests
          Specifies the maximum number of requests allowed during the given timespan.


        .EXAMPLE
          Limit-Requests -AuthType Standard -TimespanInMin 60 -MaxRequests 30

    #>


    Param
    (
        # Specifies the type of the request
        [parameter(Mandatory=$true)]
        [ValidateSet('Standard', 'Register', 'Unregister', 'Admin')]
        [String]$AuthType,

        # A general tag for the function, section of code or module name
        [parameter(Mandatory=$true)]
        [Int32]$TimespanInMin,

        # Specifies the severity of the message            
        [parameter(Mandatory=$true)]
        [Int32]$MaxRequests
    )


    ##########################################################################################################################################################################
    #region   ENFORCE RATE LIMIT   ###########################################################################################################################################
    ##########################################################################################################################################################################

        # Dynamically get the function name for logging
        $LogSource = (Get-PSCallStack)[0].LogSource

        # Set how many tokens are allowed during what time interval. For example: Only allow 10 requests (tokens) per 1 minute
        # Restrict registration requests
        if($urlDefinition -eq "/registerEndpoint/v1")
        {
            $allowedRequestsPerInterval = 2
            $timeIntervalInMinutes = 60
        }

        # Restrict removal requests
        if($urlDefinition -eq "/removeEndpoint/v1")
        {
            $allowedRequestsPerInterval = 2
            $timeIntervalInMinutes = 60
        }

        # For general API requests (anything else)
        if(($urlDefinition -ne "/registerEndpoint/v1")   -and   ($urlDefinition -ne "/removeEndpoint/v1"))
        {
            $allowedRequestsPerInterval = 60
            $timeIntervalInMinutes = 15
        }
        
        # Get the cache
        [system.array]$rateLimitStateTable = Get-PSUCache -Key "rateLimitStateTable"

        if(-not([system.array]$cache:rateLimitStateTable))
        {
            # Create table if this is the first time the server is starting. 
            Set-PSUCache -Key "rateLimitStateTable" -Value ""

            # Grab the variable just created as a new array variable so we can search it, add new objects to it and modify it.
            [system.array]$cache:rateLimitStateTable = $cache:rateLimitStateTable
        }

        # Grab the object once from memory
        $clientRateLimitValues = ($cache:rateLimitStateTable | Where-Object {$_.clientHostname -eq "$clientHostname"})

        if($clientRateLimitValues)
        {
            # Define current time
            $currentDateTime = Get-Date

            # See if we're in the same minute. If so, just see if there are tokens available and if so, just add to the counter. Else, deny the request.
            [datetime]$usedDateTime = ($clientRateLimitValues).usedDateTime

            # Compare the two times
            $timeDelta = ($currentDateTime - $usedDateTime).TotalMinutes

            # Check if we're within the internval or not
            if($timeDelta -lt $timeIntervalInMinutes)
            {
                # Check if there are tokens available to service the request
                if($clientRateLimitValues.used -lt $clientRateLimitValues.allowedRequestsPerInterval)
                {
                    # Update the counter
                    ($cache:rateLimitStateTable | Where-Object {$_.clientHostname -eq "$clientHostname"}).used += 1

                } Else {

                    # Reply back that the client is over the limit
                    $Global:response = New-PSUApiResponse -StatusCode 401 -Body "Rate limit exceeded"; $response
                    Write-EndpointLog -SeverityLevel Error -LogType Access -LogComments "Rate limit exceeded"
                    Break
                }

            } Else {

                # Reset Counter to 1 and make the usedDateTime stamp the current time
                ($cache:rateLimitStateTable | Where-Object {$_.clientHostname -eq "$clientHostname"}).used = 1
                ($cache:rateLimitStateTable | Where-Object {$_.clientHostname -eq "$clientHostname"}).usedDateTime = get-date
            }

        } Else {

            # Define current time
            $currentDateTime = Get-Date

            # No rate limit info exists so just create one and add to array
            $clientRateLimitState = [pscustomobject]@{clientHostname="$clientHostname";allowedRequestsPerInterval="$allowedRequestsPerInterval";used = 1; usedDateTime="$currentDateTime"}
            [system.array]$cache:rateLimitStateTable += $clientRateLimitState
        }

    #endregion ENFORCE RATE LIMIT
    }




    function Confirm-Authentication
    {
        <#
            .SYNOPSIS
              Authenticate and authorizes clients to the Backstop API


            .DESCRIPTION
              This module seeks to have a balance of performance and security. This module authenticates requests based on the type of authenitcation needed by the 
              endpoint using different HMAC secrets for each diffent type as defined below. 


            .NOTES
              Project:                Backstop Flexibility Framework (BFF)
              Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
              Copyright:              © 2024 | TenderLovinSnare
              Contact:                TenderLovinSnare@gmail.com
              License:                MIT (https://opensource.org/license/mit)
              █ Last Updated By:      TenderLovinSnare
              █ Release Stage:        ALPHA
              █ Version:              0.1
              █ Last Update:          20-July-2024


            .PARAMETER Type
              Specifies the authentication type of the request. For Security, there are different private keys per endpoint. Each endpoint type is described below:
              ↪ Standard:  Any general endpoint request post registration. For example, beaconing back, downloading files, etc.
              ↪ Register:  Initial registration request when installing the endpoint. For example, doing a POST request to the ../endpoints (clients) API endpoint.
              ↪ Remove:    Removal request to uninstall the endpoint. For example, doing a DELETE request to the ../endpoints (clients) API endpoint.
              ↪ Admin:     Requests to update the Backstop API server. For example, doing a POST request to the ../update API endpoint.


            .PARAMETER SkipRegistrationCheck
              By default, the API server will check that the client already has a registration and if not, deny it. However, for certain API endpoints like 
              registration, we can skip it.
    
        #>

        Param
        (
            # Specifies the type of the request
            [parameter(Mandatory=$true)]
            [ValidateSet('Standard', 'Register', 'Unregister', 'Admin')]
            [String]$AuthType,

            # Specifies the type of the request
            [parameter(Mandatory=$false)]
            [Switch]$VerifyClientRegistered
        )

        # Dynamically get the function name for logging
        $LogSource = (Get-PSCallStack)[0].LogSource




        ##########################################################################################################################################################################
        #region   REVOCATION CHECK   #############################################################################################################################################
        ##########################################################################################################################################################################

            # Ensure that the clientAuthenticated and authenticationStatus variable is flushed for added freshness (paranoid)
            Remove-Variable authenticationVerified -Force -ErrorAction SilentlyContinue

            # Check and see if there's a match in the key revocation table
            $query = "SELECT key FROM revokedApiKeys WHERE key = @key"
            $params = @{ key = $clientSubmittedApiKey }
            $keyRevoked = Invoke-SqliteQuery -SQLiteConnection $dbConnection -Query $query -Parameters $params -ErrorAction SilentlyContinue

            # Check the API key against the revocation list. If found, fail the authentication attempt.
            if($keyRevoked)
            {
                # Set authenticationVerified to Failed
                $Global:authenticationVerified = $false

                # Flush the variable
                Remove-Variable keyRevoked

                # Send an HTTP 401 (unauthorized) back to the client
                Send-APIResponse -StatusCode 401 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client `"$clientHostname`"used revoked API key"
            }

            #endregion GENERAL CHECKS




        ##########################################################################################################################################################################
        #region   VERIFY REGISTRATION DATA   #####################################################################################################################################
        ##########################################################################################################################################################################

            # Check that the client has registration data in the DB first unless -SkipRegistrationCheck was called such as during registration
            if(-Not $SkipRegistrationCheck)
            {
                # Capture the client details from the DB if they exist. At this point, the clientHostname should have already been sanitized with Confirm-Inputs.
                $query = "SELECT clientHostname FROM Endpoints WHERE clientHostname = @clientHostname"
                $params = @{ clientHostname = $clientHostname }
                $Global:clientRegData = Invoke-SqliteQuery -SQLiteConnection $dbConnection -Query $query -Parameters $params -ErrorAction SilentlyContinue

                # Reject the request if their is no clientRegData OR if the state is not 'registered'. 
                if((-Not $clientRegData)   -or   (($clientRegData.clientState -ne 'registered')   -and   ($uriPath -notmatch "^/$instanceVersion/endpoints/(register|unregister)")))
                {
                    # Reject the request
                    Send-APIResponse -StatusCode 404 -Body "API: Bad Request" -LogComments "Client attempted to connect but the clientHostname was not found in the database."

                } Else {

                    # Update the lastSeen time in the DB
                    $dateTimeInUTC = Get-Date -AsUTC -Format "yyyy-MM-dd HH:mm:ss K"
                    Invoke-SqliteQuery -SQLiteConnection $dbConnection -Query "UPDATE Endpoints SET lastSeen = `"$dateTimeInUTC`" WHERE clientHostname = `"$clientHostname`""
                }
            }

        #endregion VERIFY REGISTRATION DATA




        ##########################################################################################################################################################################
        #region   AUTHENTICATE REQUEST   #########################################################################################################################################
        ##########################################################################################################################################################################

            # Authenticate typical API requests from endpoints in the order of what's most requested
            if($AuthType -eq "Standard")
            {
                # Get the clientSalclientRegDatat value from the DB for the endpoint
                $clientSalt = $clientRegData.clientSalt

                # Specify the common API request HMAC secret where the clients hostname is used as the public portion
                $hmacSecret = $hmacSecretStandardKey_vaultSecret
                $inputData = "$clientSalt|$clientHostname"

            } Elseif($AuthType -eq "Register"){

                # Use separate HMAC key for registration
                $hmacSecret = "$clientHostname|$hmacSecretRegistration_vaultSecret"

                # Specify the commandline rollout key used during install. 
                $inputData = $cache:registrationKey

            } Elseif($AuthType -eq "Unregister"){

                    # Check that the removal key matches what's in the database. If not, stop immediately as we don't want to give back any installation details without it being correct.
                    if($requestHeaders.removalToken -ne $clientRegData.removalToken)
                    {                   
                        # Capture the response for logging variables; send response back to client; log event
                        Send-APIResponse -StatusCode 401 -GeneralContentType Text -Body "API: Unauthorized" -LogComments "The removal token was incorrect"
                    }

                    # Use separate HMAC key for removal. This is separate from the Removal Token which is an added layer of security. The below just sets the secrets to interact with the API at all.
                    $hmacSecret = "$clientHostname|$hmacSecretRemoval_vaultSecret"

                    # Specify the commandline rollout key used during install. 
                    $inputData = $clientSalt

            } Elseif($AuthType -eq "Admin"){

                    # Specify the upload API request HMAC secret
                    $hmacSecret = $cache:hmacSecretUpdate
                    $inputData = "$clientSalt|$clientHostname"
            }

            # Create HMAC signature to verify the API key submitted
            $hmacSHA256 = New-Object System.Security.Cryptography.HMACSHA256
            $hmacSHA256.key = [Text.Encoding]::ASCII.GetBytes($hmacSecret)
            $computedApiKey = $hmacSHA256.ComputeHash([Text.Encoding]::ASCII.GetBytes($inputData))
            $computedApiKey = [Convert]::ToBase64String($computedApiKey)

            # Check if the API key the client gave matches the correct key
            if($clientSubmittedApiKey -eq "$computedApiKey")
            {
                $Global:authenticationVerified = $true

            } Else {

                $Global:authenticationVerified = $false
    #Send-APIResponse -StatusCode 401 -GeneralContentType Text -Body "API: Unauthorized" -LogComments "Authentication failed as API keys did not match"
                Send-APIResponse -StatusCode 401 -GeneralContentType Text -Body "API: Unauthorized" -LogComments "clientSubmittedApiKey=$clientSubmittedApiKey computedApiKey=$computedApiKey clientSalt=$clientSalt clientHostname=$clientHostname"
            }

        #endregion AUTHENTICATE REQUEST
    }




    function Send-APIResponse
    {
        <#
            .SYNOPSIS
            An easy-to-use function to send HTTP responses back to the client and logs the request


            .DESCRIPTION
            Packages the pedantic fiddly bits of sending an API response into an easy-to-use function


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              © 2024 | TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          23-October-2024


            .PARAMETER StatusCode
            The HTTP status code you want to send back to the client. Maybe there should be a validation set but just forcing it to an Int32 for now.


            .PARAMETER Body
            The payload, as part of the body, to send back to the client. Usually this is a JSON response.


            .PARAMETER GeneralContentType
            Simplified content-type with specific, pre-formatted parameters


            .PARAMETER SendFilePath
            Specify the full file path of the file to send to the client


            .PARAMETER LogComments
            Specify any comments for the access log


            .PARAMETER EventTag
            Specify a tag as a string for the log if desired. This may help group your events and it will get passed to the write-log function.


            .PARAMETER ResponseHeaders
            Specify any headers you desire for the response as a hash table prior to passing to this function. 


            .PARAMETER SeverityLevelOverride
            Override the default severity of the event. Else, 20x and 30x are INFO, 40x are NOTICE and 50x are ERROR by default.


            .PARAMETER LogTypeOverride
            Override the default LogType for the request. Usuallly this is to divert a log to the junk file as the default is the access log.


            .EXAMPLE
            Send a Standard JSON Response:       Send-APIResponse -StatusCode 200 -Body $ObjectYouWantToSend -GeneralContentType JSON
            Send a File Back to the Client:      Send-APIResponse -StatusCode 200 -GeneralContentType Binary -SendFilePath "$filePath\$fileName" -LogComments "Gave file $filePath\$fileName back to client. Signature was verified successfully."
            Standard JSON Response with Headers: Send-APIResponse -StatusCode 200 -Body $ObjectYouWantToSend -GeneralContentType JSON -ResponseHeaders $responseHeaders

        #>

        Param
        (
            [parameter(Mandatory=$true)]
            [Int32]$StatusCode,

            [parameter(Mandatory=$false)]
            $Body,

            [parameter(Mandatory=$true)]
            [ValidateSet('JSON', 'Binary', 'Text', 'PNG', 'JPEG')]
            [String]$GeneralContentType,

            [parameter(Mandatory=$false)]
            $SendFilePath,

            [parameter(Mandatory=$false)]
            [String]$LogComments,

            [parameter(Mandatory=$false)]
            [String]$EventTag,

            [parameter(Mandatory=$false)]
            [Hashtable]$ResponseHeaders,

            [parameter(Mandatory=$false)]
            [ValidateSet('DEBUG,','INFO', 'NOTICE', 'WARN', 'ERROR', 'CRITICAL')]
            [String]$SeverityLevelOverride,

            [parameter(Mandatory=$false)]
            [ValidateSet('Access','Junk','Server','Admin')]
            [String]$LogTypeOverride
        )

        # Set the HTTP status code to give back to the client. Note that $response has already been setup for us in function Receive-Request
        $response.StatusCode = $StatusCode

        # Set the formatting and content-type of the HTTP response in order of what's used the most for slightly better performance
        if ($GeneralContentType -eq 'JSON') {

            # Convert the response body into JSON and set the HTTP content type to JSON
            $body = $body | ConvertTo-Json 
            $response.ContentType = 'application/json'

        } elseif ($GeneralContentType -eq 'Binary') {

            # Set the conte-nt type to application/octet-stream for binary data
            $response.ContentType = 'application/octet-stream'

        } elseif ($GeneralContentType -eq 'Text') {

            # Set the content of the body to a string and set the content type to text/plain
            [string]$body = $body
            $response.ContentType = 'text/plain'

        } elseif ($GeneralContentType -eq 'PNG') {

            # Set the conte-nt type to image/png
            $response.ContentType = 'image/png'

        } elseif ($GeneralContentType -eq 'JPEG') {

            # Set the conte-nt type to image/png
            $response.ContentType = 'image/jpeg'
        }

        # Add the headers to the HTTP response if they were passed to this function with the -Headers parameter
        if($responseHeaders)
        {
            foreach ($key in $responseHeaders.Keys)
            {
                $response.Headers.Add($key, $responseHeaders[$key])
            }
        }

        # If sending a file, populate the buffer with it's binary contents regardless of file format (always convert to binary for simplicity)
        if ($SendFilePath)
        {
            # Read the file into a byte array - specifically the file path specified in the -SendFilePath
            $buffer = [System.IO.File]::ReadAllBytes($SendFilePath)

        } Else {

            # Convert the body of the response to UTF8 bytes
            [byte[]]$buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
        }

        # Set length of response
        $response.ContentLength64 = $buffer.length

        # Send HTTP response and close the connection
        $output = $response.OutputStream
        $output.Write($buffer, 0, $buffer.length)
        $output.Close()

        # Honor the override set for severity level if it exists. Otherwise, automatically set it based on the status code in order of which get hit the most.
        if(-Not $SeverityLevelOverride)
        {
            if ($StatusCode -match "^2\d{2}")
            {
                $SeverityLevel = "INFO"

            } elseif ($StatusCode -match "^4\d{2}") {

                $SeverityLevel = "NOTICE"

            } elseif ($StatusCode -match "^5\d{2}"){

                $SeverityLevel = "ERROR"

            } elseif ($StatusCode -match "^3\d{2}"){

                $SeverityLevel = "INFO"

            } Else {

                $SeverityLevel = "UNKNOWN_FIX_OR_DEFINE"
            }

        } Else {

            $SeverityLevel = $SeverityLevelOverride
        }

        # Log to a different log file if desired
        if(-Not $LogTypeOverride)
        {
            # Log the request
            Write-ApiLog -LogType Access -SeverityLevel $SeverityLevel -eventTag $eventTag -LogComments "$LogComments"

        } Else {

            # Log the request to a different log such as the junk log
            Write-ApiLog -LogType $LogTypeOverride -SeverityLevel $SeverityLevel -eventTag $eventTag -LogComments "$LogComments"
        }

        # Generically stop processing any further and return to the API server loop regardless of any other loop. It is critical to stop processing anything else 
        # after the API response is sent back to the client so the response is final when called.
        Continue ApiServerLoop
    }




    function Get-Config
    {
        <#
            .SYNOPSIS
            Extracts key-value pairs from a configuration file for use as configuration items in your script.


            .DESCRIPTION
            Extracts the variables from an easy to read and configure file on disk. The conf file is a simple
            file that allows you to comment


            .NOTES
            Project:                Backstop Flexibility Framework (BFF)
            Public GitHub Repo:     https://github.com/TenderLovinSnare/BFF
            Copyright:              © 2024 | TenderLovinSnare
            Contact:                TenderLovinSnare@gmail.com
            License:                MIT (https://opensource.org/license/mit)
            Major Release Name:     Tender Lovin' Snare
            █ Last Updated By:      TenderLovinSnare
            █ Release Stage:        ALPHA
            █ Version:              0.1
            █ Last Update:          23-October-2024


            .PARAMETER FilePath
            Specify the full file path to the conf file.


            .EXAMPLE
            Get-Config -FilePath "E:\example\settings.conf"


            .EXAMPLE
            The configuration file format should look like the below and contain just about whatever normal field-value
            pairs you'd like with whichever standard denotation for comments you'd like (//, ; or #). 

                EXAMPLE CONFIG FILE
                -------------------
                
                #### General Settings
                # Any comments you want to add 
                bestToUseCamelcaseForKeyName = but fine to have spaces in values as they often do anyway for paths
                doesNotCareAbout=spacesBetweenEqualsButHarderToRead
                will take it but best not to have spaces in key name = valueXyz

                #### Some Other Logical Section of Settings
                # Any comments you want to add
                whateverKeyNameYouWant1 = value1
                whateverKeyNameYouWant2 = value2
                whateverKeyNameYouWant3 = value3

        #>

        Param(
            [Parameter(Mandatory=$True)]
            [String]$FilePath
        )

        # Create a blank hashtable
        $config = @{}

        # Go through each line of the file, removing the comments or whitespaces and capture the key-value pairs
        foreach ($line in Get-Content $filePath) {

            # Trim any leading or trailing whitespaces
            $line = $line.Trim()

            # Skip the following lines below (comments or empty lines) if any line:
            # ↪ Is an empty line or line only has spaces (double check)
            # ↪ Starts with a semicolon (; Comments)
            # ↪ Starts with a hash (# Comments)
            # ↪ Starts with double slashes (// Comments)
            # ↪ Starts with a dollar sign
            # ↪ Does NOT contain an equals sign
            if ($line -match "^\s*($|;|#|//|\$)")
            {
                # Ignore and skip the line
                continue
            }

            # Match key-value pair lines
            if ($line -match '^(.+?)\s*=\s*(.+)$')
            {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                $config[$key] = $value
            }
        }

        # Return (spit out) the object to the shell so it can be captured as any variable you'd like
        return $config
    }











#using namespace System

$Script:Base32Charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'


function New-GoogleAuthenticatorSecret
{
    <#
        .Synopsis
        Generate an 80-bit key, BASE32 encoded, secret
        and a URL to Google Charts which will show it as a QR code.
        The QR code can be used with the Google Authenticator app

        # https://humanequivalentunit.github.io/Google-Authenticator-In-PowerShell/
        # https://humanequivalentunit.github.io/Google-Authenticator-In-PowerShell/
        # https://github.com/HumanEquivalentUnit/PowerShell-Misc/blob/master/GoogleAuthenticator.psm1
        # https://github.com/google/google-authenticator/wiki/Key-Uri-Format

        .Example
        PS C:\> New-GoogleAuthenticatorSecret

        Secret           QrCodeUri
        ------           ---------
        5WYYADYB5DK2BIOV http://chart.apis.google[..]

        .Example
        PS C:\> New-GoogleAuthenticatorSecret -Online
        # *web browser opens*

        .Example
        # Take a secret code from a real website,
        # but put your own text around it to show in the app

        PS C:\> New-GoogleAuthenticatorSecret -UseThisSecretCode HP44SIFI2GFDZHT6 -Name "me@example.com" -Issuer "My bank XYZ" -Online | fl *


        Secret    : HP44SIFI2GFDZHT6
        KeyUri    : otpauth://totp/me%40example.com?secret=HP44SIFI2GFDZHT6&issuer=My%20bank%20%F0%9F%92%8E

    #>


    [CmdletBinding()]
    Param(
        # Secret length in bytes, must be a multiple of 5 bits for neat BASE32 encoding
        [int]
        [ValidateScript({($_ * 8) % 5 -eq 0})]
        $SecretLength = 20,

        # Use an existing secret code, don't generate one, just wrap it with new text
        [string]
        $UseThisSecretCode = '',
        
        # Launches a web browser to show a QR Code
        [switch]
        $Online = $false,

        # Name is text that will appear under the entry in Google Authenticator app, e.g. a login name
        [string] $Name = 'Example Website:alice@example.com',

        # Issuer is text that will appear over the entry in Google Authenticator app
        [string]
        $Issuer = 'Example Corp'
    )



    # if there's a secret provided then use it, otherwise we need to generate one
    if ($PSBoundParameters.ContainsKey('UseThisSecretCode')) {
    
        $Base32Secret = $UseThisSecretCode
    
    } else {

        # Generate random bytes for the secret
        $byteArrayForSecret = [byte[]]::new($SecretLength)
        [Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($byteArrayForSecret, 0, $SecretLength)


        # BASE32 encode the bytes
        # 5 bits per character doesn't align with 8-bits per byte input,
        # and needs careful code to take some bits from separate bytes.
        # Because we're in a scripting language let's dodge that work.
        # Instead, convert the bytes to a 10100011 style string:
        $byteArrayAsBinaryString = -join $byteArrayForSecret.ForEach{
            [Convert]::ToString($_, 2).PadLeft(8, '0')
        }


        # then use regex to get groups of 5 bits 
        # -> conver those to integer 
        # -> lookup that as an index into the BASE32 character set 
        # -> result string
        $Base32Secret = [regex]::Replace($byteArrayAsBinaryString, '.{5}', {
            param($Match)
            $Script:Base32Charset[[Convert]::ToInt32($Match.Value, 2)]
        })
    }

    # Generate the URI which needs to go to the Google Authenticator App.
    # URI escape each component so the name and issuer can have punctiation characters.
    $otpUri = "otpauth://totp/{0}?secret={1}&issuer={2}" -f @(
                [Uri]::EscapeDataString($Name),
                $Base32Secret
                [Uri]::EscapeDataString($Issuer)
              )


    # Double-encode because we're going to embed this into a Google Charts URI,
    # and these need to still be encoded in the QR code after Charts webserver has decoded once.
    $encodedUri = [Uri]::EscapeDataString($otpUri)


    # Tidy output, with a link to Google Chart API to make a QR code
    $keyDetails = [PSCustomObject]@{
        Secret = $Base32Secret
        KeyUri = $otpUri
        QrCodeUri = "https://chart.apis.google.com/chart?cht=qr&chs=200x200&chl=${encodedUri}"
    }


    # Online switch references Get-Help -Online and launches a system WebBrowser.
    if ($Online) {
        Start-Process $keyDetails.QrCodeUri
    }


    $keyDetails
}




function Get-GoogleAuthenticatorPin
{
    
    <#
    .Synopsis
    Takes a Google Authenticator secret like 5WYYADYB5DK2BIOV
    and generates the PIN code for it
    .Example
    PS C:\>Get-GoogleAuthenticatorPin -Secret 5WYYADYB5DK2BIOV

    372 251
    #>



    [CmdletBinding()]
    Param
    (
        # BASE32 encoded Secret e.g. 5WYYADYB5DK2BIOV
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]
        $Secret,

        # OTP time window in seconds
        $TimeWindow = 30
    )


    # Convert the secret from BASE32 to a byte array
    # via a BigInteger so we can use its bit-shifting support,
    # instead of having to handle byte boundaries in code.
    $bigInteger = [Numerics.BigInteger]::Zero
    foreach ($char in ($secret.ToUpper() -replace '[^A-Z2-7]').GetEnumerator()) {
        $bigInteger = ($bigInteger -shl 5) -bor ($Script:Base32Charset.IndexOf($char))
    }

    [byte[]]$secretAsBytes = $bigInteger.ToByteArray()
    

    # BigInteger sometimes adds a 0 byte to the end,
    # if the positive number could be mistaken as a two's complement negative number.
    # If it happens, we need to remove it.
    if ($secretAsBytes[-1] -eq 0) {
        $secretAsBytes = $secretAsBytes[0..($secretAsBytes.Count - 2)]
    }


    # BigInteger stores bytes in Little-Endian order, 
    # but we need them in Big-Endian order.
    [array]::Reverse($secretAsBytes)
    

    # Unix epoch time in UTC and divide by the window time,
    # so the PIN won't change for that many seconds
    $epochTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    
    # Convert the time to a big-endian byte array
    $timeBytes = [BitConverter]::GetBytes([int64][math]::Floor($epochTime / $TimeWindow))
    if ([BitConverter]::IsLittleEndian) { 
        [array]::Reverse($timeBytes) 
    }

    # Do the HMAC calculation with the default SHA1
    # Google Authenticator app does support other hash algorithms, this code doesn't
    $hmacGen = [Security.Cryptography.HMACSHA1]::new($secretAsBytes)
    $hash = $hmacGen.ComputeHash($timeBytes)


    # The hash value is SHA1 size but we want a 6 digit PIN
    # the TOTP protocol has a calculation to do that
    #
    # Google Authenticator app may support other PIN lengths, this code doesn't
    
    # take half the last byte
    $offset = $hash[$hash.Length-1] -band 0xF

    # use it as an index into the hash bytes and take 4 bytes from there, #
    # big-endian needed
    $fourBytes = $hash[$offset..($offset+3)]
    if ([BitConverter]::IsLittleEndian) {
        [array]::Reverse($fourBytes)
    }

    # Remove the most significant bit
    $num = [BitConverter]::ToInt32($fourBytes, 0) -band 0x7FFFFFFF
    
    # remainder of dividing by 1M
    # pad to 6 digits with leading zero(s)
    # and put a space for nice readability
    $PIN = ($num % 1000000).ToString().PadLeft(6, '0').Insert(3, ' ')

    [PSCustomObject]@{
        'PIN Code' = $PIN
        'Seconds Remaining' = ($TimeWindow - ($epochTime % $TimeWindow))
    }
}





#endregion DEFINE FUNCTIONS




##############################################################################################################################################################################
#region   SIGNATURE   ########################################################################################################################################################
##############################################################################################################################################################################

