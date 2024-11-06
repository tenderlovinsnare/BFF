<#############################################################################################################################################################################

                                         ██████╗      █████╗      ██████╗    ██╗  ██╗    ███████╗    ████████╗     ██████╗     ██████╗                                      
                                         ██╔══██╗    ██╔══██╗    ██╔════╝    ██║ ██╔╝    ██╔════╝    ╚══██╔══╝    ██╔═══██╗    ██╔══██╗                                     
                                         ██████╔╝    ███████║    ██║         █████╔╝     ███████╗       ██║       ██║   ██║    ██████╔╝                                     
                                         ██╔══██╗    ██╔══██║    ██║         ██╔═██╗     ╚════██║       ██║       ██║   ██║    ██╔═══╝                                      
                                         ██████╔╝    ██║  ██║    ╚██████╗    ██║  ██╗    ███████║       ██║       ╚██████╔╝    ██║                                          
                                         ╚═════╝     ╚═╝  ╚═╝     ╚═════╝    ╚═╝  ╚═╝    ╚══════╝       ╚═╝        ╚═════╝     ╚═╝                                          
                                                                                                                                                                           
    ██████╗      █████╗     ██╗   ██╗    ██╗          ██████╗      █████╗     ██████╗             ███╗   ███╗     ██████╗     ██████╗     ██╗   ██╗    ██╗         ███████╗
    ██╔══██╗    ██╔══██╗    ╚██╗ ██╔╝    ██║         ██╔═══██╗    ██╔══██╗    ██╔══██╗            ████╗ ████║    ██╔═══██╗    ██╔══██╗    ██║   ██║    ██║         ██╔════╝
    ██████╔╝    ███████║     ╚████╔╝     ██║         ██║   ██║    ███████║    ██║  ██║            ██╔████╔██║    ██║   ██║    ██║  ██║    ██║   ██║    ██║         █████╗  
    ██╔═══╝     ██╔══██║      ╚██╔╝      ██║         ██║   ██║    ██╔══██║    ██║  ██║            ██║╚██╔╝██║    ██║   ██║    ██║  ██║    ██║   ██║    ██║         ██╔══╝  
    ██║         ██║  ██║       ██║       ███████╗    ╚██████╔╝    ██║  ██║    ██████╔╝            ██║ ╚═╝ ██║    ╚██████╔╝    ██████╔╝    ╚██████╔╝    ███████╗    ███████╗
    ╚═╝         ╚═╝  ╚═╝       ╚═╝       ╚══════╝     ╚═════╝     ╚═╝  ╚═╝    ╚═════╝             ╚═╝     ╚═╝     ╚═════╝     ╚═════╝      ╚═════╝     ╚══════╝    ╚══════╝
                                                                                                                                                                           
                                                                          <<< Template Version 0.3 >>>

    INSTRUCTIONS:
    -------------
    STEP 1 - OPTIONS/CONSTRAINTS   Specify options and constraints below. These options apply to THIS specific module only. The default state is disabled: See moduleEnabled
    STEP 2 - DOCUMENT!             Update the function synopsis, description, notes and version info. The module MUST be documented.
    STEP 3 - RENAME FUNCTION       Rename function "Invoke-Module" to something unique. Ensure it starts with "Invoke-" to conform to function naming standards.
    STEP 4 - WRITE CODE            Put your code below "# Put your code below" under functions. Keep your code clean and as minimal. Write to Splunk with Write-Log function.
    STEP 5 - CONSTRAIN TEST CODE   For new code, ensure that you push to only known test machines. For example, see osClass to constrain the module.
    STEP 6 - UPDATE CODE           Use the Update-Backstop command to push the updated code to the Backstop API server.


    SPECIAL NOTE(S):
    ----------------
     - Be sure to use the variable $rootPath if/when putting any files anywhere in the Backstop main directory. Remember, root directoriess are totally different on each host.
     - Again, remember that the module is disabled by default. To enable it, set Global:moduleEnabled = $True.


    QUESTIONS:
    ----------
    For any questions, please contact YOUR_EXAMPLE_HERE

#############################################################################################################################################################################>




##############################################################################################################################################################################
#region   SERVER-SIDE MODULE CONSTRAINTS   ###################################################################################################################################
##############################################################################################################################################################################

    # These options determine which clients get which modules as it doesn't make sense to give all clients all of the modules, files or lures. The options below are evaluated 
    # by the API server in order to generate the manifest for the client - specifically which modules to download including their file hashes and where they should be placed. 

    # Explanation:                  Enable or disable the module
    # Match Type:                   Boolean
    # Default Value:                "$False"
    # Valid Options:                $True or $False
    $Global:moduleEnabled = $False


    # Explanation:                  Specify the scope via the OS for this module. 
    # Match Type:                   Exact String Match
    # Default Value:                "any"
    # Valid Options:
    #   "any"                       Run on any asset with no restrictions (default)
    #   "workstation"               Run on ANY workstations only
    #   "server"                    Run on ANY servers only
    $Global:osClass = "any"


    # Explanation:                  Specify which hostname(s) you'd like this module to apply to. Note that this is a regex match type. You can match any pattern you'd like
    #                               which gives you plenty of flexibility.
    # Match Type:                   Regex
    # Default Value:                "any"
    # Valid Options:
    #   "any"                       Run on any asset with no restrictions (default)
    #   "[YOUR_REGEX_HERE]"         Here, you can specify either a specific hostname like "WKS-US-TX-Arlington-5M5KQH4" or a regex hostname such as "^WKS-US-" for any hostname
    #                               that starts with (^) "WKS-US-". For help with regex patterns, try https://regexr.com. 
    $Global:assetName = "any"


    # Explanation:                  Specify the domain scope of this module. This variable is populated by the ClientCore functions module loaded with Backstop.
    # Match Type:                   Exact String Match
    # Default Value:                "any"
    # Valid Options:
    #   "any"                       Run on an asset on any domain (default)
    #   "[AD_DOMAIN_NAME_HERE]"     Specify the base FQDN of your domain which should include the TLD that you want to target. For example, if your domain is "contoso" but it's 
    #                               actually "contoso.local" then specify "contoso.local" for a more exact match. Remember, this is a "starts with" match so partials will also 
    #                               match "contoso" will also match "contoso.local and contoso.com". Again, note that you DO NOT need to specify any brackets []. Just put the 
    #                               domain in quotes.
    $Global:adDomain = "any"


    # Explanation:                  Specify the business unit scope of this module. This is matched against the businessUnit variable from the ClientCore module. 
    # Match Type:                   Exact String Match
    # Default Value:                "any"
    # Valid Options:
    #   "any"                       Run on any asset with no restrictions (default)
    #   "[YOUR_OTHER_BU_HERE]"      Run only on this specific business units assets
    $Global:businessUnit = "any"


    # Explanation:                  Specify a specific subnet in CIDR format that you'd like to roll this out to. For example, 10.1.2.0/24. NOTE: This only applies to the IP 
    #                               address of the primary adapter which is kinda why it's called the primarySubnet. The Backstop API server will determine if the IP address 
    #                               of the primary network adapter matches the subnet that you specify below.
    # Match Type:                   Exact String Match
    # Default Value:                "any"
    # Valid Options:
    #   "any"                       Any subnet or none at all
    #   "[YOUR_SUBNET_HERE]"        Only run the module if the asset is on this specific subnet. Note: Be sure to set the subnetAdapterScope.
    $Global:primarySubnet = "any"


    # Explanation:                  Option to restrict module to a specific business function. Use the hashMap to reference the PBKDF2 BASE64 hash.
    # Match Type:                   Exact String Match
    # Default Value:                "any"
    # Valid Options:
    #   "any"                       Run on any asset with no restrictions (default)
    #   "[PBKDF2 BASE64 HASH]"      The PBKDF2 BASE64 HASH of the business function name
    $Global:primaryUserFunctionHash = "any"


    # Explanation:                  Option to restrict module to a specific business department. Use the hashMap to reference the PBKDF2 BASE64 hash.
    # Match Type:                   Exact String Match
    # Default Value:                "any"
    # Valid Options:
    #   "any"                       Run on any asset with no restrictions (default)
    #   "[PBKDF2 BASE64 HASH]"      The PBKDF2 BASE64 HASH of the business department name
    $Global:primaryUserDepartmentHash = "any"


    # Explanation:                  Option to restrict module to a specific business title. Use the hashMap to reference the PBKDF2 BASE64 hash.
    # Match Type:                   Exact String Match
    # Default Value:                "any"
    # Valid Options:
    #   "any"                       Run on any asset with no restrictions (default)
    #   "[PBKDF2 BASE64 HASH]"      The PBKDF2 BASE64 HASH of the title of the user
    $Global:primaryUserJobTitleHash = "any"


    # Explanation:                  Option to restrict module to a specific primaryUsernameHash. Use the hashMap to reference the PBKDF2 BASE64 hash.
    # Match Type:                   Exact String Match
    # Default Value:                "any"
    # Valid Options:
    #   "any"                       Run on any asset with no restrictions (default)
    #   "[PBKDF2 BASE64 HASH]"      The PBKDF2 BASE64 HASH of the title of the user
    $Global:primaryUsernameHash = "any"


    # Explanation:                  Option to restrict module to an individuals boss. Use the hashMap to reference the PBKDF2 BASE64 hash.
    # Match Type:                   Exact String Match
    # Default Value:                "any"
    # Valid Options:
    #   "any"                       Run on any asset with no restrictions (default)
    #   "[PBKDF2 BASE64 HASH]"      The PBKDF2 BASE64 HASH of the manager of the user
    $Global:primaryUserManager1Hash = "any"


    # Explanation:                  Option to restrict module to an individuals boss's boss. Use the hashMap to reference the PBKDF2 BASE64 hash.
    # Match Type:                   Exact String Match
    # Default Value:                "any"
    # Valid Options:
    #   "any"                       Run on any asset with no restrictions (default)
    #   "[PBKDF2 BASE64 HASH]"      The PBKDF2 BASE64 HASH of the manager of the user
    $Global:primaryUserManager2Hash = "any"

#endregion SERVER-SIDE MODULE CONSTRAINTS




##############################################################################################################################################################################
#region   CLIENT-SIDE OPTIONS AND CONSTRAINTS   ##############################################################################################################################
##############################################################################################################################################################################

    # The API server, via the manifest, will tell the client which modules and files are applicable to the client. For each of the modules, the client will decide on a 
    # per-module basis whether to run the module based on the settings below.

    # Explanation:                  DO NOT touch this unless you need it for debug/testing. Set if logs sent to Splunk should have their file name and function names redacted.
    # Match Type:                   Boolean
    # Default Value:                "$True"
    # Valid Options:                $True or $False
    $Global:redactNames = $True


    # Explanation:                  How often do you want the code below to run. Best practice is to keep it >=10min (600 seconds). However, setting it to 0 will ensure it runs 
    #                               every time. Pay attention to the fact that Backstop runs randomly roughly every 15min (sometimes less, sometimes more) so understand that 
    #                               this settings really should be something like run it "every 3600 seconds for every hour" or something like "run it every 86400 seconds for 
    #                               every day".
    # Match Type:                   Integer
    # Default Value:                0 (no quotes)
    # Valid Options:                0 (run every time) to Infinate
    $Global:runIntervalInSeconds = 0


    # Explanation:                  This requires that the Backstop API server must be reachable in order to run the module. This not only ensures that the latest code is 
    #                               downloaded but also ensures that the logging relay is working prior to the module executing.
    # Match Type:                   Boolean
    # Default Value:                "$True"
    # Valid Options:                $True or $False
    $Global:requireBackstopAPIReachability = $True


    # Explanation:                  Do you only want to run this code once and never again? Better test it right the first time!
    # Match Type:                   Boolean
    # Default Value:                "$False"
    # Valid Options:                $True or $False
    $Global:runOnce = $False


# NEED TO ENSURE THAT THIS IS STICKY - ONLY EXECUTE ON THOSE SAME MACHINES THAT WON MAX ENTROPY LOTERY! ELSE IT WILL KEEP RANDOMLY EXECUTING RANDOMLY ALL OVER THE PLACE UNTIL EVERYTHING IS RUNNING IT!
    # Explanation:                  Specify if you want this module to execute by random chance. This is good for sample testing where you don't want the entire environment 
    #                               running it but maybe 1 out of 100 (see below). If enabled, the Invoke-BFF script will randomly execute it based on the chances in
    #                               maxRandomEntropy below.
    # Match Type:                   Boolean
    # Default Value:                "$False"
    # Valid Options:                $True or $False
    $Global:enableRandomization = $False


    # Explanation:                  Only valid if enableRandomization (above) is set to "$True". The winning number is always the number "1". If you specify "100" below
    #                               you'll have a 1 in 100 chance of this module executing and so on. Use this option if you'd like to test a script via sampling but note that 
    #                               it could execute on any machine unless it's further scoped below. DO NOT put <10 for the number below (options 0 and 1 won't work anyway) 
    #                               unless you REALLY know what you're doing.
    # Match Type:                   Integer
    # Default Value:                100 (no quotes)
    # Valid Options:                100 to Ran Out of Fingers to Count
    $Global:maxRandomEntropy = 100

#endregion CLIENT-SIDE OPTIONS AND CONSTRAINTS



##############################################################################################################################################################################
#region   FUNCTIONS   ########################################################################################################################################################
##############################################################################################################################################################################

    function Invoke-Module
    {
        <#
        .SYNOPSIS

            FILL THIS IN INCLUDING UPDATING NOTES AND VERSION INFO BELOW


        .DESCRIPTION

            FILL THIS IN INCLUDING UPDATING NOTES AND VERSION INFO BELOW


        .NOTES

            Primary Author:   YOUR_NAME_HERE
            Owning Team:      YOUR_TEAM_NAME_HERE
            Contact:          YOUR_TEAM_EMAIL_HERE
            

            VERSION HISTORY
            ---------------

            Version 1.0 | CURRENT_DATE | YOUR_NAME_HERE
            - RELEASE_NOTES_HERE

        #>




        ######################################################################################################################################################################
        #region   VARIABLES   ################################################################################################################################################
        ######################################################################################################################################################################

            # Function Details
            $Global:functionVersion = "1.0.0"

        #endregion VARIABLES




        ######################################################################################################################################################################
        #region   PAYLOAD CODE ("THE BUSINESS END")   ########################################################################################################################
        ######################################################################################################################################################################

            





        #endregion PAYLOAD CODE ("THE BUSINESS END")
    }

#endregion FUNCTIONS




##############################################################################################################################################################################
#region   EXPORT VARIABLES AND FUNCTIONS   ###################################################################################################################################
##############################################################################################################################################################################

    Export-ModuleMember -Variable *
    Export-ModuleMember -Function *

#endregion  EXPORT VARIABLE




##############################################################################################################################################################################
#region   SIGNATURE BLOCK   ##################################################################################################################################################
##############################################################################################################################################################################


