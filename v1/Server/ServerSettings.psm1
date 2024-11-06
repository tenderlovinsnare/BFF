<#
    .SYNOPSIS
    BFF API server settings file


    .DESCRIPTION
    


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
    █ Last Update:          23-October-2024

#>

##############################################################################################################################################################################
#region   GENERAL SETTINGS   #################################################################################################################################################
##############################################################################################################################################################################


    # Explanation:   Specify the FQDN for the API server
    # Match Type:    String
    # Default Value: N/A
    # Valid Options: Valid FQDN such as "connect.backstop.cc"
    $serverFQDN = "FQDN"


    # Explanation:   Specify if the API server is behind a load balancer. If yes, the API Server will listen on the 
    # Match Type:    String
    # Default Value: v1 (but don't rotate)
    # Valid Options: v1, v2, etc.
    $instanceVersion = "v1"


    # Explanation:   Specify if the API server is behind a load balancer. If yes, the API Server will listen on the 
    # Match Type:    String
    # Default Value: no
    # Valid Options: "localhost" or "0.0.0.0"
    $listenOn = "0.0.0.0"


    # Explanation:   Specify if the API server is behind a load balancer. If yes, the API Server will listen on the 
    # Match Type:    String
    # Default Value: $False
    # Valid Options: $True or $False
    $behindLoadBalancer = $False


    # Explanation:   Suppress errors to help ensure that information isn't leaked back to the client
    # Match Type:    String
    # Default Value: SilentlyContinue
    # Valid Options: Standard options under the $ErrorActionPreference in PowerShell. Tab $ErrorActionPreference = to see them.
    $ErrorActionPreference = "Continue"


    # Explanation:   Set the logging level for this module. Options are:
    #                ↪ "Problems" - Notice or Above (Any warnings, errors or problems)
    #                ↪ "Info"     - Info and Above (Normal operational or transactional logs + above)
    #                ↪ "Debug"    - Debug and Above (Verbose logs for troubleshooting + all of above)
    #
    #                NOTE: Start in debug or info but best to switch to 'Problems' later, especially at scale, to reduce logging unless needed.
    #
    # Match Type:    String
    # Default Value: Info
    # Valid Options: Problems, Info, Debug
    $DefaultLogLevel = "Info"


    # Explanation:   The sourcetype to use for your Splunk HEC logs
    # Match Type:    String
    # Default Value: Blank (Required if Using Splunk HEC!)
    # Valid Options: The sourcetype of the Splunk HEC logs. Ask your Splunk admin if you don't know.
    $splunkDefaultSourcetype = "changeMe"


    # Explanation:   The index to use for your Splunk HEC logs
    # Match Type:    String
    # Default Value: Blank (Required if Using Splunk HEC!)
    # Valid Options: The index name for the Splunk HEC logs. Ask your Splunk admin if you don't know.
    $splunkDefaultIndex = "changeMe"

#endregion GENERAL SETTINGS




##############################################################################################################################################################################
#region   EXPORT VARIABLES   #################################################################################################################################################
##############################################################################################################################################################################

    Export-ModuleMember -Variable *

#endregion EXPORT VARIABLES

