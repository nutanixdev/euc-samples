<#

.SYNOPSIS
Distributes Recovery Points from a Source VM on a source Prism Central to multiple Clusters and multiple Prism Centrals.
.DESCRIPTION
This script is designed to distribute Recovery Points from a Source VM on a source Prism Central to multiple Clusters and multiple Prism Centrals. 
- It supports both snapshot and template output types, and can handle Citrix environments for catalog updates.
- It is design to compliment and environment where Protection Policy limits do not allow for a simple distribution model.
- Citrix integration is included to update Citrix Catalogs with the latest snapshot created from the Recovery Point. This is an optional component to demonstrate art-of-the-possible and is not mandatory.
- It can be run in a validation mode to ensure that the environment is correctly configured before making any changes.
- It can be exected using parameters provided to the script directly, or by a configuration file. As such, no parameters are mandatory, but the script will not run without a configuration file or parameters provided. 
- The script logic, by default, is designed with a mesh style replication model, meaning that it will query and include all Prism Central and all Cluster. You can control this with exclusion params.

Read the param descriptions closely.
.PARAMETER ConfigPath
Optional. String. Path to a master configuration file to replace all parameters on this script.
.PARAMETER LogPath
Optional. String. Where we log to. Default is C:\Logs\DistributePCRecoveryPoints.log
.PARAMETER LogRollover
Optional. Int. Number of days before logfile rollover occurs. Default is 5.
.PARAMETER SourcePC
Mandatory. String. The Prism Central Instance hosting the Source VM. 
.PARAMETER BaseVM
Mandatory. String. This VM and the associated cluster will be the source of all replication.
.PARAMETER RecoveryPoint
Optional. String. You can choose to use an existing Recovery Point. If not specified, a new Recovery Point will be created and deleted after replication occurs.
.PARAMETER UseLatestRecoveryPoint
Optional. Switch. Use whatever latest recovery point exists on the VM. If not specified, a new Recovery Point will be created and deleted after replication occurs.
.PARAMETER AdditionalPrismCentrals
Optional. Array. Additional Prism Central instances to query. These should align to Availability zone configurations. If not specified, a v3 API call will occurs to learn about the Prism Centrals in the environment.
.PARAMETER ExcludedPrismCentrals
Optional. Array. Excluded Prism Central instances. Used for cases where a PC should not be queried.
.PARAMETER ExcludedClusters
Optional. Array. Excluded clusters. Used for cases where a cluster should not, or could not during validation, be queried.
.PARAMETER VMPrefix
Optional. String. The prefix name to create for the restored entity and the created snapshots or templates. Default is "ctx_".
.PARAMETER TempVMName
Optional. String. The name of the temporary VM created for the snapshot (ctx_TempAPIVM). Default is "TempAPIVM".
.PARAMETER OutputType
Mandatory. String. The output type of the Recovery Point. Either "PE-Snapshot" or "PC-Template". Default is "PC-Template". If you select PE-Snapshot, then all clusters will be processed with a snapshot left.
.PARAMETER ImageSnapsOrTemplatesToRetain
Optional. Int. The number of snapshots or templates to retain. Effectively a cleanup mode. Default is 5. Anything older than this that meets the naming critera (based on VMPrefix) will be deleted.
.PARAMETER UseCustomCredentialFile
Optional. Switch. Specifies that a credential file should be used for storing creds related to Nutanix Auth. See the limitation notes for more info.
.PARAMETER CredPath
Optional. String. Default path for custom credential file. Default is "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials".
.PARAMETER OverrideStorageContainer
Optional. String. If set, will migrate the temp VM to this storage container before the snapshot is created. This is useful if you want to ensure that the snapshot is created in a specific storage container. See the limitation notes for more info.
.PARAMETER DomainUser
Optional. String. The domain user to use for API calls for Citrix processing. If not specified, the script will prompt for credentials.
.PARAMETER DomainPassword
Optional. String. The domain password to use for API calls for Citrix processing. If not specified, the script will prompt for credentials.
.PARAMETER ctx_Catalogs
Optional. Array. Array of catalogs on a single Citrix site to process. If needing to update multiple sites, use the JSON input.
.PARAMETER ctx_AdminAddress
Optional. String. Delivery Controller address on a single Citrix site to process. If needing to update multiple sites, use the JSON input.
.PARAMETER ctx_SiteConfigJSON
Optional. String. JSON input file for multi site (or single site) Citrix site configurations. Catalogs and Delivery Controllers.
[
    {
        "Catalog": "W11-CL1-Test",
        "Controller": "DDC1.domain.com"
    },
    {
        "Catalog": "W11-CL5-Test",
        "Controller": "DDC2.domain.com"
    }
]
.PARAMETER IsCitrixDaaS
Optional. Switch. Defines that we are processing Citrix DaaS environments and not CVAD On Prem.
.PARAMETER CustomerID
Optional. String. The Customer ID to use for DaaS API calls.
.PARAMETER ClientID
Optional. String. The Client ID to use for DaaS API calls.
.PARAMETER ClientSecret
Optional. String. The Client Secret to use for DaaS API calls.
.PARAMETER Region
Optional. String. The Citrix Cloud DaaS Tenant Region. Either AP-S (Asia Pacific), US (USA), EU (Europe) or JP (Japan). Default is "US".
.PARAMETER SecureClientFile
Optional. String. SecureClientFile to use for API calls. Optional in place of credentials being passed.
.PARAMETER SleepTime
Optional. Int. Sleep time operations between task status polling in both v2 and v4 functions. Default is 2 seconds.
.PARAMETER APICallVerboseLogging
Optional. Switch. Show the API calls being made.
.PARAMETER ValidateOnly
Optional. Switch. If set, the script will only validate the environment and not make any changes.
.PARAMETER BypassAllValidationErrors
Optional. Switch. If set, the script will bypass all validation errors and proceed with the script execution. Dangermouse.
.NOTES
#-----------------------------------
Limitations and items of Note
#-----------------------------------
- The script example has been developed, and tested against pc.2024.3.1.4
- The way that Recovery Points are restored when replicated, does not allow a container to be defined. As such, an RP restore outside of its home cluster will land on a container with as close characterstics as its source as possible.
- If you want to override this container location, the script offers the ability to migrate the temp VM before a snapshot or Template is created. All clusters must have the same named container for this to work
- The temp VM when restored will have no NIC. This is fine for MCS provisioning.
- The script requires that all Prism Centrals have the same authentication account (if you need different accounts per PC, update the script logic)
- The script required that all Prism Elements have the same authentication account (if you need different accounts per PE, update the script logic)
- If you choose to use Citrix integration, this integration is currently limited to PE based plugins.
.EXAMPLE
See the README.md file in the same folder as this script for examples of how to use the script.

#>

#region Params
# ============================================================================
# Parameters
# ============================================================================
Param(
    [Parameter(Mandatory = $false)][string]$ConfigPath = "", # path to a master configuration file to replace all parameters on this script.
    [Parameter(Mandatory = $false)][string]$LogPath = "C:\Logs\DistributePCRecoveryPoints.log", # Where we log to
    [Parameter(Mandatory = $false)][int]$LogRollover = 5, # Number of days before logfile rollover occurs
    ###------------- Prism Central Params
    [Parameter(Mandatory = $true)][string]$SourcePC, # The Prism Central Instance hosting the Source VM
    [Parameter(Mandatory = $false)][string]$BaseVM, # The VM entity name of the base VM
    [Parameter(Mandatory = $false)][string]$RecoveryPoint, # The name of the Recovery Point targeted
    [Parameter(Mandatory = $false)][switch]$UseLatestRecoveryPoint, # Use whatever latest recovery point exists on the VM
    [Parameter(Mandatory = $false)][array]$AdditionalPrismCentrals, # Additional Prism Central instances to query. These should align to Availability zone configurations.
    [Parameter(Mandatory = $false)][array]$ExcludedPrismCentrals, # Excluded Prism Central instances. Used for rare cases where a PC should not be queried
    [Parameter(Mandatory = $false)][array]$ExcludedClusters, # Excluded clusters. Used for cases where a cluster should not, or could not during validation, be queried
    [Parameter(Mandatory = $false)][string]$VMPrefix = "ctx_", # The prefix name to create for the restored entity and the created snapshots or templates
    [Parameter(Mandatory = $false)][string]$TempVMName = "TempAPIVM", # The name of the temporary VM created for the snapshot (ctx_TempAPIVM)
    [Parameter(Mandatory = $false)][ValidateSet('PE-Snapshot', 'PC-Template')][string]$OutputType = "PC-Template",
    [Parameter(Mandatory = $false)][int]$ImageSnapsOrTemplatesToRetain = 5, # The number of snapshots to retain. Effectively a cleanup mode
    [Parameter(Mandatory = $false)][switch]$UseCustomCredentialFile, # specifies that a credential file should be used
    [Parameter(Mandatory = $false)][String]$CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials", # Default path for custom credential file
    [Parameter(Mandatory = $false)][string]$OverrideStorageContainer, # If set, will migrate the temp VM to this storage container before the snapshot is created.
    ###------------- Citrix Params
    [Parameter(Mandatory = $false)][string]$DomainUser, # The domain user to use for API calls for Citrix processing
    [Parameter(Mandatory = $false)][string]$DomainPassword, # The domain password to use for API calls for Citrix processing
    [Parameter(Mandatory = $false)][Array]$ctx_Catalogs, # Array of catalogs on a single Citrix site to process. If needing to update multiple sites, use the JSON input
    ###------------- Citrix VAD Params
    [Parameter(Mandatory = $false)][String]$ctx_AdminAddress, # Delivery Controller address on a single Citrix site to process. If needing to update multiple sites, use the JSON input
    [Parameter(Mandatory = $false)][String]$ctx_SiteConfigJSON, # JSON input file for multi site (or single site) Citrix site configurations. Catalogs and Delivery Controllers
    ###------------- Citrix DaaS Params
    [Parameter(Mandatory = $false)][switch]$IsCitrixDaaS, # Defines that we are processing Citrix DaaS environments and not CVAD On Prem
    [Parameter(Mandatory = $false)][string]$CustomerID, # The Customer ID to use for DaaS API calls
    [Parameter(Mandatory = $false)][string]$ClientID, # The Client ID to use for DaaS API calls
    [Parameter(Mandatory = $false)][string]$ClientSecret, # The Client Secret to use for DaaS API calls
    [Parameter(Mandatory = $false)][string]$Region = "US", # The Citrix Cloud DaaS Tenant Region. Either AP-S (Asia Pacific), US (USA), EU (Europe) or JP (Japan)
    [Parameter(Mandatory = $false)][string]$SecureClientFile, # SecureClientFile to use for API calls. Optional in place of credentials being passed.
    ###------------- Misc Params
    [Parameter(Mandatory = $false)][int]$SleepTime = 2, # Sleep time operations between task status polling in both v2 and v4 functions
    [Parameter(Mandatory = $false)][switch]$APICallVerboseLogging, # Show the API calls being made
    [Parameter(Mandatory = $false)][switch]$ValidateOnly, # If set, the script will only validate the environment and not make any changes
    [Parameter(Mandatory = $false)][switch]$BypassAllValidationErrors # used for testing purposes only - bypasses all validation errors and proceeds with the script execution
)

#endregion Params

#region Functions
# ============================================================================
# Functions
# ============================================================================
function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateNotNullOrEmpty()][Alias("LogContent")][string]$Message,
        [Parameter(Mandatory = $false)][Alias('LogPath')][string]$Path = $LogPath,
        [Parameter(Mandatory = $false)][ValidateSet("Error", "Warn", "Info")][string]$Level = "Info",
        [Parameter(Mandatory = $false)][switch]$NoClobber
    )

    Begin {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
        }
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
        }
        else {
            # Nothing to see here yet.
        }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                #Write-Error $Message
                $LevelText = 'ERROR:'
                Write-Host "$FormattedDate $LevelText $Message" -ForegroundColor Red
                
            }
            'Warn' {
                #Write-Warning $Message
                $LevelText = 'WARNING:'
                Write-Host "$FormattedDate $LevelText $Message" -ForegroundColor Yellow
                
            }
            'Info' {
                #Write-Verbose $Message
                $LevelText = 'INFO:'
                Write-Host "$FormattedDate $LevelText $Message" -ForegroundColor White
            }
        }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End {
    }
}

function Start-Stopwatch {
    Write-Log -Message "Starting Timer" -Level Info
    $Global:StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
}

function Stop-Stopwatch {
    Write-Log -Message "Stopping Timer" -Level Info
    $StopWatch.Stop()
    if ($StopWatch.Elapsed.TotalSeconds -le 1) {
        Write-Log -Message "Script processing took $($StopWatch.Elapsed.TotalMilliseconds) ms to complete." -Level Info
    }
    else {
        Write-Log -Message "Script processing took $($StopWatch.Elapsed.TotalSeconds) seconds to complete." -Level Info
    }
}

function RollOverlog {
    $LogFile = $LogPath
    $LogOld = Test-Path $LogFile -OlderThan (Get-Date).AddDays(-$LogRollover)
    $RolloverDate = (Get-Date -Format "dd-MM-yyyy")
    if ($LogOld) {
        Write-Log -Message "$LogFile is older than $LogRollover days, rolling over" -Level Info
        $NewName = [io.path]::GetFileNameWithoutExtension($LogFile)
        $NewName = $NewName + "_$RolloverDate.log"
        Rename-Item -Path $LogFile -NewName $NewName
        Write-Log -Message "Old logfile name is now $NewName" -Level Info
    }    
}

function StartIteration {
    Write-Log -Message "--------Starting Iteration--------" -Level Info
    RollOverlog
    Start-Stopwatch
}

function StopIteration {
    Stop-Stopwatch
    Write-Log -Message "--------Finished Iteration--------" -Level Info
}

#-----------------------------------------
# Auth and Environment Functions
#-----------------------------------------
function Set-CustomCredentials {
    #input: path, credname
    #output: saved credentials file
    <#
    .SYNOPSIS
    Creates a saved credential file using DAPI for the current user on the local machine.
    .DESCRIPTION
    This function is used to create a saved credential file using DAPI for the current user on the local machine.
    .NOTES
    Author: Stephane Bourdeaud
    .PARAMETER path
    Specifies the custom path where to save the credential file. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
    .PARAMETER credname
    Specifies the credential file name.
    .EXAMPLE
    .\Set-CustomCredentials -path c:\creds -credname prism-apiuser
    Will prompt for user credentials and create a file called prism-apiuser.txt in c:\creds
    #>
    param
    (
        [parameter(mandatory = $false)]
        [string]$path,
        
        [parameter(mandatory = $true)]
        [string]$credname
    )

    begin {
        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            }
            else {
                $path = $CredPath
            }
            Write-Log -Message "[Credentials] Set path to $path" -Level Info
        } 
    }
    process {
        #prompt for credentials
        $credentialsFilePath = "$path\$credname.txt"
        $credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
        
        #put details in hashed format
        $user = $credentials.UserName
        $securePassword = $credentials.Password
        
        #convert secureString to text
        try {
            $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Credentials] Could not convert password : $($_.Exception.Message)" -Level Warn
            StopIteration
            Exit 1
        }

        #create directory to store creds if it does not already exist
        if (!(Test-Path $path)) {
            try {
                $result = New-Item -type Directory $path -ErrorAction Stop
            } 
            catch {
                Write-Log -Message "[Credentials] Could not create directory $path : $($_.Exception.Message)" -Level Warn
                StopIteration
                Exit 1
            }
        }

        #save creds to file
        try {
            Set-Content $credentialsFilePath $user -ErrorAction Stop
        } 
        catch {
            Write-Log -Message "[Credentials] Could not write username to $credentialsFilePath : $($_.Exception.Message)" -Level Warn
            StopIteration
            Exit 1
        }
        try {
            Add-Content $credentialsFilePath $password -ErrorAction Stop
        } 
        catch {
            Write-Log -Message "[Credentials] Could not write password to $credentialsFilePath : $($_.Exception.Message)" -Level Warn
            StopIteration
            Exit 1
        }

        Write-Log -Message "[Credentials] Saved credentials to $credentialsFilePath" -Level Info              
    }
    end {}
} # this function is used to create saved credentials for the current user

function Get-CustomCredentials {
    #input: path, credname
    #output: credential object
    <#
    .SYNOPSIS
    Retrieves saved credential file using DAPI for the current user on the local machine.
    .DESCRIPTION
    This function is used to retrieve a saved credential file using DAPI for the current user on the local machine.
    .NOTES
    Author: Stephane Bourdeaud
    .PARAMETER path
    Specifies the custom path where the credential file is. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
    .PARAMETER credname
    Specifies the credential file name.
    .EXAMPLE
    .\Get-CustomCredentials -path c:\creds -credname prism-apiuser
    Will retrieve credentials from the file called prism-apiuser.txt in c:\creds
    #>
    param
    (
        [parameter(mandatory = $false)]
        [string]$path,
        
        [parameter(mandatory = $true)]
        [string]$credname
    )

    begin {
        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            }
            else {
                $path = $Credpath
            }
            Write-Log -Message "[Credentials] Retrieving credentials from $path" -Level Info
        } 
    }
    process {
        $credentialsFilePath = "$path\$credname.txt"
        if (!(Test-Path $credentialsFilePath)) {
            Write-Log -Message "[Credentials] Could not access file $credentialsFilePath : $($_.Exception.Message)" -Level Warn
        }

        $credFile = Get-Content $credentialsFilePath
        $user = $credFile[0]
        $securePassword = $credFile[1] | ConvertTo-SecureString

        $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

        Write-Log -Message "[Credentials] Returning credentials from $credentialsFilePath" -Level Info
    }
    end {
        return $customCredentials
    }
} # this function is used to retrieve saved credentials for the current user

function Set-PoshTls {
    <#
    .SYNOPSIS
    Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

    .DESCRIPTION
    Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

    .NOTES
    Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)

    .EXAMPLE
    .\Set-PoshTls
    Makes sure we use the proper Tls version (1.2 only required for connection to Prism).

    .LINK
    https://github.com/sbourdeaud
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

    param 
    (
        
    )

    begin {
    }

    process {
        Write-Log -Message "[SSL] Adding Tls12 support" -Level Info
        [Net.ServicePointManager]::SecurityProtocol = `
        ([Net.ServicePointManager]::SecurityProtocol -bor `
                [Net.SecurityProtocolType]::Tls12)
    }

    end {

    }
} # this function is used to make sure we use the proper Tls version (1.2 only required for connection to Prism)

#-----------------------------------------
# Citrix API Functions
#-----------------------------------------
function Get-CVADAuthHeadersAPI {

    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential
    )

    Begin {
    }
    Process {
        if ($Global:IsCitrixDaaS) {
            $ClientID = $Global:ClientID
            $ClientSecret = $Global:ClientSecret
            #--------------------------------------------
            # Get the DaaS Access Token
            #--------------------------------------------
            $TokenURL = "https://$($CloudUrl)/cctrustoauth2/root/tokens/clients"
            $Body = @{
                grant_type    = "client_credentials"
                client_id     = $ClientID
                client_secret = $ClientSecret
            }
            try {
                $Response = Invoke-WebRequest $tokenUrl -Method POST -Body $Body -UseBasicParsing -ErrorAction Stop
            }
            catch {
                Write-Log -Message "Failed to return token. Exiting" -Level Error
                Break #Replace with Exit 1
            }

            $AccessToken = $Response.Content | ConvertFrom-Json

            if ([string]::IsNullOrEmpty($AccessToken)) {
                Write-Log -Message "Failed to return token. Exiting" -Level Error
                Break #Replace with Exit 1
            }

            #--------------------------------------------
            # Get the DaaS Site ID
            #--------------------------------------------
            $RequestUri = "https://$($CloudUrl)/cvadapis/me"
            $Headers = @{
                "Accept"            = "application/json";
                "Authorization"     = "CWSAuth Bearer=$($AccessToken.access_token)";
                "Citrix-CustomerId" = "$CustomerID";
            }

            try {
                $Response = Invoke-RestMethod -Uri $RequestUri -Method GET -Headers $Headers -ErrorAction Stop
            }
            catch {
                Write-Log -Message "Failed to return Site ID. Exiting" -Level Error
                Break #Replace with Exit 1
            }

            $SiteID = $Response.Customers.Sites.Id

            if ([String]::IsNullOrEmpty($SiteID)) {
                Write-Log -Message "Failed to return Site ID. Exiting" -Level Error
                Break #Replace with Exit 1
            }

            #--------------------------------------------
            # Set the headers
            #--------------------------------------------
            $Headers = @{
                "Accept"            = "application/json"
                "Authorization"     = "CWSAuth Bearer=$($AccessToken.access_token)"
                "Citrix-CustomerId" = "$CustomerID"
                "Citrix-InstanceId" = "$SiteID"
            }
        }
        else {
            #Process Standard Citrix CVAD On Prem
            #--------------------------------------------
            # Get the CVAD Access Token
            #--------------------------------------------
            $TokenURL = "https://$DDC/cvad/manage/Tokens"
            $Headers = @{
                Accept        = "application/json"
                Authorization = "Basic $EncodedAdminCredential"
            }

            try {
                $Response = Invoke-WebRequest -Uri $TokenURL -Method Post -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
            }
            catch {
                Write-Log -Message "Failed to return token. Exiting" -Level Error
                Break #Replace with Exit 1
            }

            $AccessToken = $Response.Content | ConvertFrom-Json

            if ([string]::IsNullOrEmpty($AccessToken)) {
                Write-Log -Message "Failed to return token. Exiting" -Level Error
                Break #Replace with Exit 1
            }

            #--------------------------------------------
            # Get the CVAD Site ID
            #--------------------------------------------
            $URL = "https://$DDC/cvad/manage/Me"
            $Headers = @{
                "Accept"            = "application/json"
                "Authorization"     = "CWSAuth Bearer=$($AccessToken.Token)"
                "Citrix-CustomerId" = "CitrixOnPremises"
            }

            try {
                $Response = Invoke-WebRequest -Uri $URL -Method Get -Header $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
            }
            catch {
                Write-Log -Message "Failed to return Site ID. Exiting" -Level Error
                Break #Replace with Exit 1
            }

            $SiteID = $Response.Content | ConvertFrom-Json

            if ([String]::IsNullOrEmpty($SiteID)) {
                Write-Log -Message "Failed to return Site ID. Exiting" -Level Error
                Break #Replace with Exit 1
            }

            #--------------------------------------------
            # Set the headers
            #--------------------------------------------
            $Headers = @{
                "Accept"            = "application/json"
                "Authorization"     = "CWSAuth Bearer=$($AccessToken.Token)"
                "Citrix-CustomerId" = "CitrixOnPremises"
                "Citrix-InstanceId" = "$($SiteID.Customers.Sites.Id)"
            }
        }
    }
    end {
        # we need to send back the headers for use in future calls
        return $Headers
    }
} # fix these Kindon

Function Get-CVADCatalogsAPI {
    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set Headers
        #----------------------------------------------------------------------------------------------------------------------------
        $Headers = Get-CVADAuthHeadersAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
    }

    process {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Get"
        $RequestUri = "https://$DDC/cvad/manage/MachineCatalogs/"
        #----------------------------------------------------------------------------------------------------------------------------

        try {
            $catalogs = Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
        }
    }

    end {
        return $catalogs.items
    }
}

function Get-CVADSiteDetailAPI {
    
    [CmdletBinding()]

    param(
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set Headers
        #----------------------------------------------------------------------------------------------------------------------------
        $Headers = Get-CVADAuthHeadersAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
    }
    process {
        # Open Array for All Auth Details
        $cvad_environment_details = @()

        #region Validate Citrix Site Details
        #----------------------------------------------------------------------------------------------------------------------------
        # Validate Citrix Site List
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Get"
        if ($Global:IsCitrixDaaS) {
            $RequestUri = "https://$DDC/cvad/manage/Sites/cloudxdsite"
        } else {
            $RequestUri = "https://$DDC/cvad/manage/Sites/"
        }

        #----------------------------------------------------------------------------------------------------------------------------
        try {
            Write-Log -Message "Getting Citrix Site Info" -Level Info
            if ($Global:IsCitrixDaaS) {
                $cvad_sites = Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
            } else {
                $cvad_sites = (Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop).Items
            }
            $cvad_site_id = $cvad_sites.Id
            
            # Get Site Details
            $cvad_site = Get-CVADSiteAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential -SiteID $cvad_site_id -ErrorAction Stop

            Write-Log -Message "Successfully Returned Citrix Site Detail. Site version is $($cvad_site.ProductVersion)" -Level Info
        }
        catch {
            Write-Log -Message $_ -Level Error
            Break #Replace with Exit 1
        }

        # Add details to custom object
        $cvad_site_Object = [PSCustomObject]@{
            cvad_site = $cvad_site
        }
        $cvad_environment_details += $cvad_site_Object
        #endregion Validate Citrix Site Details
    }
    End {
        return $cvad_environment_details
    }
}

Function Get-CVADSiteAPI {
    [CmdletBinding()]

    param(
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$SiteID,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set Headers
        #----------------------------------------------------------------------------------------------------------------------------
        $Headers = Get-CVADAuthHeadersAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
    }
    process {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Get"
        $RequestUri = "https://$DDC/cvad/manage/Sites/$($SiteID)"
        #----------------------------------------------------------------------------------------------------------------------------

        try {
            $cvad_site = Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
        }
    }
    end {
        return $cvad_site
    }
}

Function Invoke-CVADCatalogUpdateAPI {
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)][string]$DDC,
        [parameter(mandatory = $true)][string]$Catalog,
        [parameter(mandatory = $true)][string]$Image,
        [parameter(mandatory = $true)][string]$EncodedAdminCredential
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set Headers
        #----------------------------------------------------------------------------------------------------------------------------
        $Headers = Get-CVADAuthHeadersAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "POST"
        $RequestUri = "https://$($DDC)/cvad/manage/MachineCatalogs/$($Catalog)/`$UpdateProvisioningScheme"
        $PayloadContent = @{
            MasterImagePath = $Image
        }
        $Payload = $PayloadContent | ConvertTo-Json -Depth 4
        $ContentType = "Application/JSON"
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $update_catalog_image_task = Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -Body $Payload -ContentType $ContentType -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
        }
    }
    end {
        return $update_catalog_image_task
    }
}

Function Invoke-ProcessCitrixCatalogUpdate {
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)][string]$DDC,
        [parameter(mandatory = $true)][string]$Catalog,
        [parameter(mandatory = $true)][string]$Image,
        [parameter(mandatory = $true)][string]$EncodedAdminCredential
    )

    begin {
        
    }
    process {
        try {
            $validate_catalog_exists = Get-CVADCatalogsAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential | Where-Object { $_.Name -eq $Catalog }
            if ([string]::IsNullOrEmpty($validate_catalog_exists)) {
                Write-Log -Message "[Citrix Validation] Failed to validate Catalog: $($Catalog) on Delivery Controller: $($DDC)" -Level Warn
                $Global:TotalCatalogFailureCount ++
                $Global:CurrentCatalogCount ++
            } else {
                Write-Log -Message "[Citrix Validation] Validating Catalog $($Catalog) exists on Delivery Controller: $($DDC)" -Level Info
                if ($validate_catalog_exists.ProvisioningType -ne "MCS") {
                    Write-Log -Message "[Citrix Validation] Catalog is of provisioning type $($validate_catalog_exists.ProvisioningType) and cannot be used on Delivery Controller: $($DDC)" -Level Warn
                    $Global:TotalCatalogFailureCount ++
                    $Global:CurrentCatalogCount ++
                } else {
                    Write-Log -Message "[Citrix Validation] Successfully validated Catalog: $($Catalog) on Delivery Controller: $($DDC)" -Level Info
                    $catalog_current_image = $validate_catalog_exists.ProvisioningScheme.MasterImage
                    if ($catalog_current_image.Name -eq $Image) {
                        Write-Log -Message "[Citrix Validation] Catalog: $($Catalog) is already using the specified image: $($Image)" -Level Info
                        $Global:CurrentCatalogCount ++
                        $Global:TotalCatalogSuccessCount ++
                    } else {
                        Write-Log -Message "[Citrix Validation] Catalog is using $($catalog_current_image.Name). Will be processed." -Level Info
                        $pattern = "(?<=\\)([^\\]+)(?=\.template)"
                        $updated_image = $catalog_current_image.XDPath -replace $pattern,$Image

                        Write-Log -Message "[Citrix Image] Current Image for Catalog: $($Catalog) is: $($catalog_current_image.XDPath)" -Level Info
                        Write-Log -Message "[Citrix Image] New Image for Catalog: $($Catalog) will be: $($updated_image)" -Level Info
                        # Start the update process
                        
                        $update_catalog_image_task = Invoke-CVADCatalogUpdateAPI -DDC $DDC -Catalog $Catalog -Image $updated_image -EncodedAdminCredential $EncodedAdminCredential

                        ## Now go monitor for success depending on task output above
                        if ([string]::IsNullOrEmpty($update_catalog_image_task)) {
                            Write-Log -Message "[Citrix Catalog Update] Failed to update Catalog: $($Catalog) with new image: $($updated_image)" -Level Warn
                            $Global:TotalCatalogFailureCount ++
                            $Global:CurrentCatalogCount ++
                        } else {
                            $cvad_job_completion = Invoke-CVADJobMonitorStatusAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential -JobID $update_catalog_image_task.id
                            if ($cvad_job_completion -eq "Complete") {
                                Write-Log -Message "[Citrix Catalog Update] Successfully updated Catalog: $($Catalog) with new image: $($updated_image)" -Level Info
                                $Global:CurrentCatalogCount ++
                                $Global:TotalCatalogSuccessCount ++
                            } else {
                                Write-Log -Message "[Citrix Catalog Update] Failed to update Catalog: $($Catalog) with new image: $($updated_image)" -Level Warn
                                $Global:TotalCatalogFailureCount ++
                                $Global:CurrentCatalogCount ++
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Log -Message $_ -Level Error
        }
    }
    end {
        return 
    }
}

Function Invoke-CVADJobMonitorStatusAPI {

    [CmdletBinding()]

    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$JobID,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $false)][switch]$HasSubJobs
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set Headers
        #----------------------------------------------------------------------------------------------------------------------------
        $Headers = Get-CVADAuthHeadersAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
    }
    process {
        #----------------------------------------------------------------------------------------------------------------------------
        # Get Job Status
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $target_job_status = Get-CVADJobDetailsAPI -DDC $DDC -JobID $JobID -EncodedAdminCredential $EncodedAdminCredential -ErrorAction Stop

            if (-not $HasSubJobs) {
                # This is a single job with no sub jobs
                while ($target_job_status.Status -ne "Complete") {
                    if ($target_job_status.Status -eq "Failed") {
                        Write-Log -Message "Job Status is $($target_job_status.Status) with Error: $($target_job_status.ErrorString)" -Level Error
                        $target_job_status_result = "Failure"
                        Break #Replace with Exit 1
                    }
                    Write-Log -Message "Job Status is $($target_job_status.Status) and is $($target_job_status.OverallProgressPercent) percent complete" -Level Info
                    Start-Sleep 30
    
                    $target_job_status = Get-CVADJobDetailsAPI -DDC $DDC -JobID $target_job_status.id -EncodedAdminCredential $EncodedAdminCredential
                }
                $target_job_status_result = "Complete"
            }
            else {
                # This job has subjobs
                $completed_jobs = @() #open the array to capture completed jobs
                while ($target_job_status.status -ne "Complete") {
                    foreach ($subjob in $target_job_status.SubJobs) {
                        if ($subjob.Status -ne "Complete") {
                            if ($subjob.Status -eq "Failed") {
                                Write-Log -Message "Job $($subjob.parameters.value) is Failed" -Level Warn
                                $target_job_status_result = "Failure"
                                Break #Replace with Exit 1
                            }
                            Write-Log -Message "Job $($subjob.parameters.value) is $($subjob.Status)" -Level Info
                            Start-Sleep 10
                        }
                        elseif ($subjob.Status -eq "Complete" -and $subjob.parameters.value -notin $completed_jobs) {
                            Write-Log -Message "Job $($subjob.parameters.value) is complete" -Level Info
                            $completed_jobs += $subjob.parameters.value
                        }
            
                        try {
                            $target_job_status = Get-CVADJobDetailsAPI -DDC $DDC -JobID $JobID -EncodedAdminCredential $EncodedAdminCredential
                        }
                        catch {
                            Write-Log -Message $_ -Level Error
                        }
                    }
                }
                $target_job_status_result = "Complete"
            }
        }
        catch {
            Write-Log -Message $_ -Level Error
            $target_job_status_result = "Failure"
        }
    }
    end {
        if ($target_job_status_result -eq "Failure") {
            return "Failure"
        } else {
            return "Complete"
        }
    }

}

function Get-CVADJobDetailsAPI {
    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$JobID,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set Headers
        #----------------------------------------------------------------------------------------------------------------------------
        $Headers = Get-CVADAuthHeadersAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
    }
    process {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Get"
        $RequestUri = "https://$DDC/cvad/manage/Jobs/$($JobID)"
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $job = Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
        }
    }
    end {
        return $job
    }
}

#-----------------------------------------
# Nutanix API v2 Functions
#-----------------------------------------
Function Invoke-PrismAPIv2 {
    param (
        [parameter(mandatory = $true)]
        [ValidateSet("POST", "GET", "DELETE", "PUT")]
        [string]$Method,

        [parameter(mandatory = $true)]
        [string]$Url,

        [parameter(mandatory = $false)]
        [string]$Payload,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    Begin {}
    Process {
        if ($APICallVerboseLogging) { 
            Write-Log -Message "[Prism API Call] Making a $method call to $url" -Level Info
        }
        try {
            #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12 as well as use basic authentication with a pscredential object
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $headers = @{
                    "Content-Type" = "application/json";
                    "Accept"       = "application/json"
                }
                if ($payload) {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                }
                else {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                }
            }
            else {
                $username = $credential.UserName
                $password = $credential.Password
                $headers = @{
                    "Authorization" = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) ));
                    "Content-Type"  = "application/json";
                    "Accept"        = "application/json"
                }
                if ($payload) {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
                }
                else {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
                }
            }
        }
        catch {
            $saved_error = $_.Exception.Message
            # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
            Write-Log -Message "Payload: $payload" -Level Info
            Write-Log -Message "[ERROR] $saved_error" -Level Error
        }
    }
    End {
        return $resp
    }
}

Function Get-PEVMListv2 {
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        [string]$ClusterIP,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$PrismElementCredentials
    )

    begin {
        
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/vms"
        $Payload = $null # we are on a GET run
        #----------------------------------------------------------------------------------------------------------------------------
        
    }
    process {
        Write-Log -Message "[Target Cluster] retrieving virtual machine entities for the target cluster: $($ClusterIP)" -Level Info
        try {
            $VirtualMachines = Invoke-PrismAPIv2 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Target Cluster] Failed to connect to the target cluster: $($ClusterIP)" -Level Warn
        }
    }
    end {
        return $VirtualMachines.entities
    }
}

Function Invoke-PEVMDeletev2 {
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        [string]$ClusterIP,

        [parameter(mandatory = $true)]
        [string]$vm_uuid,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$PrismElementCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "DELETE"
        $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($vm_uuid)"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[VM] Deleting temporary VM on the target cluster: $($ClusterIP)" -Level Info
        try {
            $pe_vm_delete = Invoke-PrismAPIv2 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[VM] Failed to delete temporary VM on the target cluster: $($ClusterIP)" -Level Warn
            $target_cluster_task_failures ++
            Continue
        }
    }
    end {
        return $pe_vm_delete
    }
}

Function Get-PETaskv2 {
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        [string]$ClusterIP,

        [parameter(mandatory = $true)]
        [string]$TaskID,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$PrismElementCredentials,

        [parameter(mandatory = $false)]
        [string]$Phase,

        [parameter(mandatory = $false)]
        [string]$PhaseSuccessMessage,

        [parameter(mandatory = $false)]
        [Int32]$SleepTime
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/tasks/$($TaskId)"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        
        try {
            $pe_task_status = Invoke-PrismAPIv2 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop
            if ($Phase){
                Write-Log -Message "$($Phase) Monitoring task: $($TaskId)"
            } else {
                Write-Log -Message "Monitoring task: $($TaskId)"
            }
            while ($pe_task_status.progress_status -ne "SUCCEEDED") {
                if ($pe_task_status.progress_status -ne "FAILED") {
                    if ($Phase) {
                        Write-Log -Message "$($Phase) Task Status is: $($pe_task_status.progress_status). Waiting for Task completion. Status: $($pe_task_status.percentage_complete)% complete" -Level Info
                    } else {
                        Write-Log -Message "Task Status is: $($pe_task_status.progress_status). Waiting for Task completion. Status: $($pe_task_status.percentage_complete)% complete" -Level Info
                    }
                }
                elseif ($TaskStatus.progress_status -eq "FAILED"){
                    if ($Phase) {
                        Write-Log -Message "$($Phase) Task Status is: FAILED" -level Warn
                    } else {
                        Write-Log -Message "Task Status is: FAILED" -level Warn
                    }
                    #StopIteration
                    #Exit 1                                  
                }
                Start-Sleep $SleepTime
                $pe_task_status = Invoke-PrismAPIv2 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop
            }
            if ($pe_task_status.progress_status -eq "SUCCEEDED") {
                if ($Phase) {
                    Write-Log -Message "$($Phase) Task status is: $($pe_task_status.progress_status). $($PhaseSuccessMessage)" -Level Info
                } else {
                    Write-Log -Message "Task status is: $($pe_task_status.progress_status). $($PhaseSuccessMessage)" -Level Info
                }
            }
        }
        catch {
            if ($Phase) {
                Write-Log -Message "$($Phase) Failed to get task status for task ID: $($TaskId)" -Level Warn
            } else {
                Write-Log -Message "Failed to get task status for task ID: $($TaskId)" -Level Warn
            }
            #StopIteration
            #Exit 1
        }  
    }
    end {
        return $pe_task_status
    }
}

Function New-PESnapshotv2 {
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        [string]$ClusterIP,

        [parameter(mandatory = $true)]
        [string]$vm_uuid,

        [parameter(mandatory = $true)]
        [string]$SnapshotName,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$PrismElementCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "POST"
        $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/snapshots"
        $PayloadContent = @{
            snapshot_specs =  @(
                @{
                    snapshot_name = $SnapshotName
                    vm_uuid = $vm_uuid
                }
            )
        }
        $Payload = (ConvertTo-Json $PayloadContent)
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[VM Snapshot] Creating Snapshot on the target cluster: $($ClusterIP)" -Level Info
        try {
            $pe_snapshot = Invoke-PrismAPIv2 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[VM Snapshot] Failed to create Snapshot on the target cluster: $($ClusterName)" -Level Warn
            Write-Log -Message $_ -Level Warn
            $TotalErrorCount += 1
            Continue
        }
    }
    end {
        return $pe_snapshot
    }
}

Function Get-PESnapshotListv2 {
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        [string]$ClusterIP,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$PrismElementCredentials
    )
    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/snapshots"
        $Payload = $null # we are on a GET run
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log "[Snapshots] Getting an up to date list of snapshots on the target cluster: $($ClusterName)" -Level Info
        try {
            $pe_snapshot_list = Invoke-PrismAPIv2 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Snapshots] Failed to get an up to date list of snapshots on the target cluster: $($ClusterName)" -Level Warn
            $TotalErrorCount += 1
            Continue
        }
    }
    end {
        return $pe_snapshot_list.entities
    }
}

Function Invoke-PESnapshotDeletev2 {
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        [string]$ClusterIP,

        [parameter(mandatory = $true)]
        [string]$Snapshot_uuid,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$PrismElementCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "DELETE"
        $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/snapshots/$($Snapshot_uuid)"
        $Payload = $null # we are on a delete run
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        try {
            $snapshot_delete = Invoke-PrismAPIv2 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Snapshot] Failed to delete snapshot: $($Snapshot_uuid) on the target cluster: $($ClusterIP)" -Level Warn
            $TotalErrorCount += 1
            Continue
        }
    }
    end {
        return $snapshot_delete
    }
}

function Invoke-PEAuthCheckv2 {
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        [string]$ClusterIP,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$PrismElementCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/cluster"
        $Payload = $null # we are on a GET run
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Cluster Validation] Checking authentication to the target cluster: $($ClusterIP)" -Level Info
        try {
            $pe_auth_check = Invoke-PrismAPIv2 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Cluster Validation] Failed to authenticate to the target cluster: $($ClusterIP)" -Level Warn
            $TotalErrorCount += 1
            Continue
        }
    }
    end {
        if ($pe_auth_check) {
            return $true
        } else {
            return $false
        }
    }
}

#-----------------------------------------
# Nutanix API v3 Functions
#-----------------------------------------
function InvokePrismAPIv3 {
    param (
        [parameter(mandatory = $true)]
        [ValidateSet("POST", "GET", "DELETE", "PUT")]
        [string]$Method,

        [parameter(mandatory = $true)]
        [string]$Url,

        [parameter(mandatory = $false)]
        [string]$Payload,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )
    Begin {}
    Process {
        if ($APICallVerboseLogging) { 
            Write-Log -Message "[Prism API Call] Making a $method call to $url" -Level Info
        }
        try {
            #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12 as well as use basic authentication with a pscredential object
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $headers = @{
                    "Content-Type" = "application/json"
                    "Accept"       = "application/json"
                }
                if ($payload) {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                }
                else {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                }
            }
            else {
                $username = $credential.UserName
                $password = $credential.Password
                $headers = @{
                    "Authorization" = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) ))
                    "Content-Type"  = "application/json"
                    "Accept"        = "application/json"
                }
                if ($payload) {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
                }
                else {
                    $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -ErrorAction Stop
                }
            }
        }
        catch {
            $saved_error = $_.Exception.Message
            # Write-Host "$(Get-Date) [INFO] Headers: $($headers | ConvertTo-Json)"
            Write-Log -Message "Payload: $payload" -Level Info
            Write-Log -Message "[ERROR] $saved_error" -Level Error
        }
    }
    end {
        return $resp
    }
} #v3 Function

Function Get-PCAvailabilityZones {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [parameter(mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "POST"
        $RequestUri = "https://$($pc):9440/api/nutanix/v3/availability_zones/list"
        $PayloadContent = @{
            kind = "availability_zone"
        }
        $Payload = (ConvertTo-Json $PayloadContent)
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Querying for Availability Zones under the Prism Central Instance $($pc)" -Level Info
        try {
            $availability_zones = InvokePrismAPIv3 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $availability_zones.entities
    }
 
} #v3 Function

Function Get-PCRemoteConections {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [parameter(mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Post"
        $RequestUri = "https://$($SourcePC):9440/api/nutanix/v3/remote_connections/list"  
        $PayloadContent = @{
            kind   = "remote_connection"
            length = 500
        } 
        $Payload = (ConvertTo-Json $PayloadContent)
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Availability Zones] Querying for Remote Connections under the Prism Central Instance $($pc)" -Level Info
        try {
            $remote_connections = InvokePrismAPIv3 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Availability Zones] Failed to capture remote connect details from the Prism Central Instance $($pc)" -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $remote_connections.entities
    }
} #v3 Function

#-----------------------------------------
# Nutanix API v4 Functions
#-----------------------------------------

function Invoke-PrismAPIv4 {

    [CmdletBinding()]

	param (
		[parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][ValidateSet("POST", "GET", "DELETE", "PUT")][string]$Method,
		[parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$Url, # the full endpoint URL for the API call
		[parameter(ValuefromPipelineByPropertyName = $true, mandatory = $false)][string]$Payload, 
		[parameter(ValuefromPipelineByPropertyName = $true, mandatory = $false)][string]$Etag, # If sending the etag - retrieve it first using a GET with ForEtag switch and parses the returned headers for the etag.
		[parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][System.Management.Automation.PSCredential]$Credential,
		[parameter(ValuefromPipelineByPropertyName = $true, mandatory = $false)][switch]$APICallVerboseLogging,
		[parameter(ValuefromPipelineByPropertyName = $true, mandatory = $false)][switch]$ForEtag # will return only the etag value (returned in headers)
	)

	begin {
		if ($Method -eq "DELETE" -and [string]::IsNullOrEmpty($Etag)) {
			Write-Log -Message "[Prism API v4 Call] Etag is required for DELETE method with v4 API" -Level Error
			Break
		}
		# Set some key error handling variables for rate limiting
		$master_retry_attempts = 5 	# this is the number of times we will retry the API call if we get a rate limiting error (HTTP 429). Handle in the Invoke-RestMethod call
	}

	process {
		if ($APICallVerboseLogging) { 
			Write-Log -Message "[Prism API v4 Call] Making a $method call to $url" -Level Info
		}
		try {
			if ($method -in @("POST", "PUT", "DELETE")) {
                if ($Etag) {
                    $headers = @{
                        "Content-Type"    = "application/json"
                        "Accept"          = "application/json"
                        "If-Match"        = $Etag
                        "NTNX-Request-Id" = [guid]::NewGuid().ToString()
                    }
                }
                else {
                    $headers = @{
                        "Content-Type"    = "application/json"
                        "Accept"          = "application/json"
                        "NTNX-Request-Id" = [guid]::NewGuid().ToString()
                    }
                }
			}
			else {
				# this is just a GET call
				$headers = @{
					"Content-Type" = "application/json"
					"Accept"       = "application/json"
				}
			}
			if ($payload) {	
				$response = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -SkipHeaderValidation -MaximumRetryCount $master_retry_attempts -ResponseHeadersVariable ResponseHeaders -ErrorAction Stop
			}
			else {
				$response = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -SkipHeaderValidation -MaximumRetryCount $master_retry_attempts -ResponseHeadersVariable ResponseHeaders -ErrorAction Stop
			}
		}
		catch {
			$saved_error = $_.Exception.Message
			Write-Log -Message "[ERROR] $($saved_error)" -Level Error
		}
	}

	end {
		if ($ForEtag -eq $true) {
			# return the Etag value, that's all we care about
			$ResponseHeaders.ETag # this is returned by the -ResponseHeadersVariable parameter in Invoke-RestMethod
		}
		else {
			# return the full response
			return $response
		}
	}
}

Function Get-PCClusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [parameter(mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($pc):9440/api/clustermgmt/v4.0/config/clusters"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Querying for Clusters under the Prism Central Instance $($pc)" -Level Info
        try {
            $total_clusters = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $total_clusters.data
    }  
}

Function Get-PCVM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $false)][String]$vmName,
        [Parameter(Mandatory = $false)][int]$limit = 100,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        if (-not $vmName) {
            $RequestUri = "https://$($pc):9440/api/vmm/v4.0/ahv/config/vms/?`$limit=$($limit)"
        } else {
            $RequestUri = "https://$($pc):9440/api/vmm/v4.0/ahv/config/vms/?`$limit=$($limit)&`$filter=name eq '$vmName'"
        }
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Querying for Virtual Machine $($vmName) under the Prism Central Instance $($pc)" -Level Info
        try {
            $virtual_machines = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }

        $total_virtual_machines = [System.Collections.ArrayList]@()
        $total_virtual_machines.AddRange($virtual_machines.data)

        if ($virtual_machines.metadata.totalAvailableResults -gt $limit) {
            $next_url = ($virtual_machines.metadata.links | Where-Object { $_.rel -eq "next" }).href

            while ($next_url) {
                try {
                    $response = Invoke-PrismAPIv4 -Method "GET" -Url $next_url -Credential $PrismCentralCredentials -ErrorAction Stop
                    $total_virtual_machines.AddRange($response.data)
                }
                catch {
                    Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc). Link was $($next_url)" -Level Warn
                    Write-Log $_ -Level Warn
                    StopIteration
                    Exit 1
                }
			
                $next_link = $response.metadata.links | Where-Object { $_.rel -eq "next" }
                if ($next_link) {
                    $next_url = $next_link.href
                }
                else {
                    $next_url = $null
                }
            }
        }
    }
    end {
        return $total_virtual_machines
    } 
}

Function Get-PCRecoveryPoints {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $false)][int]$limit = 100,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($pc):9440/api/dataprotection/v4.0/config/recovery-points/?`$limit=$($limit)"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Querying for Recovery Points under the Prism Central Instance $($pc)" -Level Info
        try {
            $recovery_points = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }

        $total_recovery_points = [System.Collections.ArrayList]@()
        $total_recovery_points.AddRange($recovery_points.data)

        if ($recovery_points.metadata.totalAvailableResults -gt $limit) {
            $next_url = ($recovery_points.metadata.links | Where-Object { $_.rel -eq "next" }).href

            while ($next_url) {
                try {
                    $response = Invoke-PrismAPIv4 -Method "GET" -Url $next_url -Credential $PrismCentralCredentials -ErrorAction Stop
                    $total_recovery_points.AddRange($response.data)
                }
                catch {
                    Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc). Link was $($next_url)" -Level Warn
                    Write-Log $_ -Level Warn
                    StopIteration
                    Exit 1
                }
			
                $next_link = $response.metadata.links | Where-Object { $_.rel -eq "next" }
                if ($next_link) {
                    $next_url = $next_link.href
                }
                else {
                    $next_url = $null
                }
            }
        }
    }
    end {
        return $total_recovery_points
    } 
} 

Function New-PCRecoveryPoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][string]$VMExtId,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials,
        [Parameter(Mandatory = $true)][string]$RecoveryPointName
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "POST"
        $RequestUri = "https://$($pc):9440/api/dataprotection/v4.0/config/recovery-points/"
        $PayloadContent = @{
            name              = $RecoveryPointName
            recoveryPointType = "CRASH_CONSISTENT"
            vmRecoveryPoints  = @(
                @{
                    vmExtId = $VMExtId
                }
            )
        }
        $Payload = (ConvertTo-Json $PayloadContent)
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Creating a new Recovery Point under the Prism Central Instance $($pc)" -Level Info
        try {
            $new_recovery_point = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $new_recovery_point.data
    }
 
}

Function Get-PCTaskv4 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][string]$TaskID,
        [Parameter(Mandatory = $false)][string]$Phase,
        [Parameter(Mandatory = $false)][string]$PhaseSuccessMessage,
        [Parameter(Mandatory = $false)][int]$SleepTime = 5,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($pc):9440/api/prism/v4.0/config/tasks/$($TaskID)"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Querying for Task ($TaskID) under the Prism Central Instance $($pc)" -Level Info
        try {
            $task_detail = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop

            while ($task_detail.data.status -ne "SUCCEEDED") {
                if ($task_detail.data.status -eq "FAILED") {
                    if ($Phase) {
                        Write-Log -Message "$($Phase) Task status is: $($task_detail.data.status)" -Level Warn
                    }
                    else {
                        Write-Log -Message "Task status is: $($task_detail.data.status)" -Level Warn
                    }
                    Write-Log -Message "$($task_detail.data.errorMessages.message)" -Level Warn
                    if ($task_detail.data.legacyErrorMessage) {
                        if ($Phase) {
                            Write-Log -Message "$($Phase): $($task_detail.data.legacyErrorMessage)" -Level Warn
                        }
                        else {
                            Write-Log -Message "$($task_detail.data.legacyErrorMessage)" -Level Warn
                        }
                    }
                    Break
                    #StopIteration
                    #Exit 1
                }
                if ($Phase) {
                    # Report a nicer output if a phase is defined
                    Write-Log -Message "$($Phase) Task status is: $($task_detail.data.status). Waiting for task completion. Status: $($task_detail.data.progressPercentage)% complete" -Level Info
                }
                else {
                    Write-Log -Message "Task status is: $($task_detail.data.status). Waiting for task completion. Status: $($task_detail.data.progressPercentage)% complete" -Level Info
                }
            
                Start-Sleep $SleepTime
                $task_detail = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
            }
            if ($task_detail.data.status -eq "SUCCEEDED") {
                if ($Phase) {
                    Write-Log -Message "$($Phase) Task status is: $($task_detail.data.status). $PhaseSuccessMessage" -Level Info
                }
                else {
                    Write-Log -Message "Task status is: $($task_detail.data.status). $PhaseSuccessMessage" -Level Info
                }
            }
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $task_detail.data
    }	
}

Function Get-PCDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($pc):9440/api/prism/v4.0/config/domain-managers"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Querying for Prism Central Details under the Prism Central Instance $($pc)" -Level Info
        try {
            $pc_details = InvokePrismAPIv3 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $pc_details.data
    }
} #This is going to be used to learn about the Source and Target PC as required

Function Invoke-PCRecoveryPointReplicate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][string]$RecoveryPointExtId,
        [Parameter(Mandatory = $false)][string]$RecoveryPointName,
        [Parameter(Mandatory = $true)][string]$pcExtId,
        [Parameter(Mandatory = $true)][string]$clusterExtId,
        [Parameter(Mandatory = $false)][string]$clusterName,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "POST"
        $RequestUri = "https://$($pc):9440/api/dataprotection/v4.0/config/recovery-points/$($RecoveryPointExtId)/`$actions/replicate"
        $PayloadContent = @{
            pcExtId      = $pcExtId
            clusterExtId = $clusterExtId
        }
        $Payload = (ConvertTo-Json $PayloadContent)
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        if ($RecoveryPointName -and $clusterName) {
            Write-Log -Message "[Prism Central] Replicating Recovery Point $($RecoveryPointName) from Prism Central Instance $($pc) and Cluster $($clusterName)" -Level Info
        } else {
            # If no name is provided, just use the ID
            Write-Log -Message "[Prism Central] Replicating Recovery Point ($RecoveryPointExtId) from Prism Central Instance $($pc) and Cluster $($clusterExtId)" -Level Info
        }
       
        try {
            $replicate_recovery_point = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $replicate_recovery_point.data
    }

} #This might need some updated error handling depending on requirements. What about Cluster Location for this one?

Function Invoke-PCRecoveryPointRestore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][string]$RecoveryPointExtId,
        [Parameter(Mandatory = $false)][string]$RecoveryPointName,
        [Parameter(Mandatory = $true)][string]$VMRecoveryPointExtId,
        [Parameter(Mandatory = $true)][string]$clusterExtId,
        [Parameter(Mandatory = $false)][string]$clusterName,
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "POST"
        $RequestUri = "https://$($pc):9440/api/dataprotection/v4.0/config/recovery-points/$($RecoveryPointExtId)/`$actions/restore"
        $PayloadContent = @{
            clusterExtId                    = $clusterExtId
            vmRecoveryPointRestoreOverrides = @(
                @{
                    vmRecoveryPointExtId = $VMRecoveryPointExtId
                    vmOverrideSpec       = @{
                        '$objectType' = "dataprotection.v4.config.AhvVmOverrideSpec"
                        name          = $VMName
                    }
                }	
            )
        }
        $Payload = (ConvertTo-Json $PayloadContent -Depth 3)
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        if ($RecoveryPointName -and $clusterName) {
            Write-Log -Message "[Prism Central] Restoring Recovery Point $($RecoveryPointName) to Cluster $($clusterName) with vm name $($VMName)" -Level Info
        } else {
            # If no name is provided, just use the ID
            Write-Log -Message "[Prism Central] Restoring Recovery Point ($RecoveryPointExtId) to Cluster $($clusterExtId) with vm name $($VMName)" -Level Info
        }
        
        try {
            $restore_recovery_point = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $restore_recovery_point.data
    }
} 

Function New-PCTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][string]$VMExtId,
        [Parameter(Mandatory = $true)][string]$TemplateName,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "POST"
        $RequestUri = "https://$($pc):9440/api/vmm/v4.0/content/templates"
        $PayloadContent = @{
            templateName        = $TemplateName
            templateDescription = "Created by Recovery Point Replication Script"
            templateVersionSpec = @{
                versionSource = @{
                    '$objectType' = "vmm.v4.content.TemplateVmReference"
                    extId         = $VMExtId
                }	
            }
        }
        $Payload = (ConvertTo-Json $PayloadContent -Depth 3)
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Creating PC Template $($TemplateName) on Prism Central $($PC)" -Level Info
        try {
            $create_pc_template = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $create_pc_template.data
    }

} 

Function Get-PCVMDetailForEtag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][string]$VMExtId,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($pc):9440/api/vmm/v4.0/ahv/config/vms/$($VMExtId)"
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Querying for VM ($VMExtId) on Prism Central $($PC)" -Level Info
        try {
            $vm_details = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials -ForEtag -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $vm_details
    }
}

Function Invoke-PCVMDelete {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][string]$VMExtId,
        [Parameter(Mandatory = $true)][string]$Etag,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "DELETE"
        $RequestUri = "https://$($pc):9440/api/vmm/v4.0/ahv/config/vms/$($VMExtId)"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Deleting VM ($VMExtId) on Prism Central $($PC)" -Level Info

        try {
            $delete_vm = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -Etag $Etag -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            return
            #StopIteration
            #Exit 1
        }
    }
    end {
        return $delete_vm.data
    }
} 

Function Get-PCRecoveryPointDetailForEtag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][string]$RPExtId,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($pc):9440/api/dataprotection/v4.0/config/recovery-points/$($RPExtId)"
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Querying for Recovery Point ($RPExtId) on Prism Central $($PC)" -Level Info
        try {
            $recovery_point_details = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials -ForEtag -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $recovery_point_details
    }

} 

Function Invoke-PCRecoveryPointDelete {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][string]$RPExtId,
        [Parameter(Mandatory = $false)][string]$RPName,
        [Parameter(Mandatory = $false)][string]$ClusterName,
        [Parameter(Mandatory = $true)][string]$Etag,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "DELETE"
        $RequestUri = "https://$($pc):9440/api/dataprotection/v4.0/config/recovery-points/$($RPExtId)"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        if ($RPName -and $ClusterName) {
            Write-Log -Message "[Prism Central] Deleting Recovery Point $($RPName) on Prism Central $($pc) from Cluster $($ClusterName)" -Level Info
        } else {
            # If no name is provided, just use the ID
            Write-Log -Message "[Prism Central] Deleting Recovery Point ($RPExtId) on Prism Central $($PC)" -Level Info
        }
        
        try {
            $delete_recovery_point = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -Etag $Etag -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $delete_recovery_point.data
    }
} 

Function Get-PCTemplates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($pc):9440/api/vmm/v4.0/content/templates"
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Querying for Templates on Prism Central $($PC)" -Level Info
        try {
            $template_list = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $template_list.data
    }
} 

Function Get-PCTemplateDetailForEtag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][string]$TemplateExtId,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($pc):9440/api/vmm/v4.0/content/templates/$($TemplateExtId)"
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Querying for Template ($TemplateExtId) on Prism Central $($PC)" -Level Info
        try {
            $template_details = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials -ForEtag -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $template_details
    }
}

Function Invoke-PCTemplateDelete {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$pc,
        [Parameter(Mandatory = $true)][string]$TemplateExtId,
        [Parameter(Mandatory = $true)][string]$Etag,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "DELETE"
        $RequestUri = "https://$($pc):9440/api/vmm/v4.0/content/templates/$($TemplateExtId)"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Deleting Template $($TemplateExtId) on Prism Central $($PC)" -Level Info
        try {
            $delete_template = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -Etag $Etag -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
    end {
        return $delete_template.data
    }
}

Function Invoke-PCVMDiskMigration {

    [CmdletBinding()]

    Param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$pc,
        [parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$VMExtId,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$ClusterExtId,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $false)][string]$ClusterName,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$ContainerExtId,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $false)][string]$ContainerName,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$Etag
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "POST"
        $RequestUri = "https://$($pc):9440/api/vmm/v4.0/ahv/config/vms/$($VMExtId)/`$actions/migrate-vm-disks"
        $PayloadContent = @{
            migrateDisks = @{
                '$objectType' = 'vmm.v4.ahv.config.AllDisksMigrationPlan'
                storageContainer = @{
                    extId = $ContainerExtId
                }
            }
        }
        $Payload = $PayloadContent | ConvertTo-Json -Depth 10
        #----------------------------------------------------------------------------------------------------------------------------

    }
    process {
        if ($ContainerName -and $ClusterName) {
            Write-Log -Message "[Prism Central] Migrating VM Disks to Container $($ContainerName) on Cluster $($ClusterName)" -Level Info
        } else {
            # If no name is provided, just use the ID
            Write-Log -Message "[Prism Central] Migrating VM Disks to Container $($ContainerExtId) on Cluster $($ClusterExtId)" -Level Info
        }

        try {
            $disk_migration = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -Etag $Etag -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Warn
            Break
        }
    }
    end {
        return $disk_migration.data
    }
}

Function Get-PCStorageContainerList {

    [CmdletBinding()]

    Param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$pc,
        [parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][System.Management.Automation.PSCredential]$PrismCentralCredentials,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $false)][string]$ClusterExtId
    )

    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $limit = 100
        $Method = "GET"
        $RequestUri = "https://$($pc):9440/api/clustermgmt/v4.0/config/storage-containers?`$limit=$($limit)"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
    }
    process {
        Write-Log -Message "[Prism Central] Querying for Storage Containers under the Prism Central Instance $($pc)" -Level Info

        try {
            $storage_containers = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Warn
            Break
        }

        if ([string]::IsNullOrEmpty($storage_containers)) {
            Write-Log -Message "[Prism Central] No data was returned for the Prism Central Instance: $($pc)" -Level Warn
            Break
        }
        
        if ($ClusterExtId) {
            $storage_containers = $storage_containers.data | Where-Object {$_.clusterExtId -eq $ClusterExtId}
        }
        else {
            $storage_containers = $storage_containers.data
        }
    }
    end {
        return $storage_containers
    }
}

#endregion Functions

#region Variables
# ============================================================================
# Variables
# ============================================================================
$RunDate = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -replace ":","-" -replace " ","-" # We want all snapshots across all clusters to have the same timestamp

#region Set variables from JSON to replace all parameters.
#-------------------------------------------------------------
if ($ConfigPath){
    if (Test-path $ConfigPath) {
        Write-Log -Message "Reading configuration from $($ConfigPath)" -Level Info
        try {
            $master_config = Get-Content -Path $ConfigPath | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Write-Log -Message "Failed to read configuration file: $($_.Exception.Message)" -Level Warn
            Exit 1
        }
    } else {
        Write-Log -Message "Configuration file not found at $($ConfigPath)" -Level Warn
        Exit 1
    }
    
    #------------------------------------------ Mapping The JSON to variables ---------------------------------------------#
    #----------------------------------------------------------------------------------------------------------------------#
    #------------------- Logging Variables --------------------------------------------------------------------------------#
    #----------------------------------------------------------------------------------------------------------------------#
    $LogPath                            = $master_config.LoggingParams.LogPath
    $LogRollover                        = $master_config.LoggingParams.LogRollover
    #----------------------------------------------------------------------------------------------------------------------#
    #------------------- Prism Central Variables --------------------------------------------------------------------------#
    #----------------------------------------------------------------------------------------------------------------------#
    $SourcePC                           = $master_config.PrismCentralParams.SourcePC
    $AdditionalPrismCentrals            = $master_config.PrismCentralParams.AdditionalPrismCentrals
    $ExcludedPrismCentrals              = $master_config.PrismCentralParams.ExcludedPrismCentrals
    $ExcludedClusters                   = $master_config.PrismCentralParams.ExcludedClusters
    $OverrideStorageContainer           = $master_config.PrismCentralParams.OverrideStorageContainer
    #----------------------------------------------------------------------------------------------------------------------#
    #------------------- Source VM Variables ------------------------------------------------------------------------------#
    #----------------------------------------------------------------------------------------------------------------------#
    $BaseVM                             = $master_config.SourceVMParams.BaseVM
    #----------------------------------------------------------------------------------------------------------------------#
    #------------------- Recovery Point Variables -------------------------------------------------------------------------#
    #----------------------------------------------------------------------------------------------------------------------#
    $RecoveryPoint                      = $master_config.RecoveryPointParams.RecoveryPoint
    $UseLatestRecoveryPoint             = $master_config.RecoveryPointParams.UseLatestRecoveryPoint
    #----------------------------------------------------------------------------------------------------------------------#
    #-------------------  Output Variables --------------------------------------------------------------------------------#
    #----------------------------------------------------------------------------------------------------------------------#
    $TempVMName                         = $master_config.OutputParams.TempVMName
    $OutputType                         = $master_config.OutputParams.OutputType
    $VMPrefix                           = $master_config.OutputParams.VMPrefix
    $ImageSnapsOrTemplatesToRetain      = $master_config.OutputParams.ImageSnapsOrTemplatesToRetain
    #----------------------------------------------------------------------------------------------------------------------#
    #------------------- Credential Variables -----------------------------------------------------------------------------#
    #----------------------------------------------------------------------------------------------------------------------#
    $UseCustomCredentialFile            = $master_config.CredentialParams.UseCustomCredentialFile
    if ($master_config.CredentialParams.CredPath -like "*%**%*") {
        $CredPath                       = [System.Environment]::ExpandEnvironmentVariables($master_config.CredentialParams.CredPath)
    } else {
        $CredPath                       = $master_config.CredentialParams.CredPath
    }
    #----------------------------------------------------------------------------------------------------------------------#
    #------------------- Citrix Variables ---------------------------------------------------------------------------------#
    #----------------------------------------------------------------------------------------------------------------------#
    $IsCitrixDaaS                       = $master_config.CitrixParams.CitrixCloud.IsCitrixDaaS
    if (-not $master_config.CitrixParams.MultieSite.ctx_SiteConfigJSON) { 
        # Not a multi-site JSON based configuration, use  single site parameters
        if (-not $IsCitrixDaaS) { 
            # Not a DaaS environment, use the single site parameters
            $ctx_Catalogs               = $master_config.CitrixParams.SingleSite.ctx_Catalogs
        } else { 
            # This is Citrix DaaS
            $ctx_Catalogs               = $master_config.CitrixParams.CitrixCloud.ctx_Catalogs
            $CustomerID                 = $master_config.CitrixParams.CitrixCloud.CustomerID
            if ($master_config.CitrixParams.CitrixCloud.SecureClientFile) { 
                # If SecureClientFile is provided, use it
                $SecureClientFile       = $master_config.CitrixParams.CitrixCloud.SecureClientFile
            } else { 
                # No SecureClientFile use params
                $ClientID               = $master_config.CitrixParams.CitrixCloud.ClientID
                $ClientSecret           = $master_config.CitrixParams.CitrixCloud.ClientSecret
            }
            $Region                     = $master_config.CitrixParams.CitrixCloud.Region
        }
        $ctx_AdminAddress               = $master_config.CitrixParams.SingleSite.ctx_AdminAddress
    } else { 
        # A multi-site JSON based configuration, use the ctx_SiteConfigJSON parameter
        $ctx_SiteConfigJSON             = $master_config.CitrixParams.MultieSite.ctx_SiteConfigJSON
    }
    $DomainUser                         = $master_config.CitrixParams.DomainUser
    $DomainPassword                     = $master_config.CitrixParams.DomainPassword
    #----------------------------------------------------------------------------------------------------------------------#
    #------------------- Misc Variables -----------------------------------------------------------------------------------#
    #----------------------------------------------------------------------------------------------------------------------#
    $SleepTime                          = $master_config.MiscParams.SleepTime
    $APICallVerboseLogging              = $master_config.MiscParams.APICallVerboseLogging
    $ValidateOnly                       = $master_config.MiscParams.ValidateOnly
    $BypassAllValidationErrors          = $master_config.MiscParams.BypassAllValidationErrors
    #----------------------------------------------------------------------------------------------------------------------#
}
#endregion Set variables from JSON to replace all parameters.

if ($OutputType -eq "PE-Snapshot") {
    $pe_snapshot_name = $VMPrefix + $BaseVM + "_" + $RunDate
    $name_match_for_deletion = $VMPrefix + $BaseVM + "_"
} 
if ($OutputType -eq "PC-Template") {
    $pc_template_name = $VMPrefix + $BaseVM + "_Template_" + $RunDate
    $name_match_for_deletion = $VMPrefix + $BaseVM + "_Template_"
}

if ($IsCitrixDaaS) {
    $Global:IsCitrixDaaS = $true
} else {
    $Global:IsCitrixDaaS = $false
}

# Fix Header Validation Issues. Specifically the way the ':' value is handled.
$PSDefaultParameterValues['Invoke-RestMethod:SkipHeaderValidation'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipHeaderValidation'] = $true

#endregion Variables

#region Param Validation
#-------------------------------------------------------------
# If Citrix Processing, Must have either Catalogs or SiteConfigJSON
if ($ctx_Catalogs -or $ctx_SiteConfigJSON) {
    if ([string]::IsNullOrEmpty($ctx_Catalogs) -and [string]::IsNullOrEmpty($ctx_SiteConfigJSON)) { Write-Log -Message "[PARAM VALIDATION] Catalogs or SiteConfigJSON is required for Citrix Processing" -Level Error; Exit 1 }
    # If Citrix Processing. If not Citrix DaaS
    if (-not $IsCitrixDaaS -and (-not ($ctx_SiteConfigJSON))) {
        if ([string]::IsNullOrEmpty($ctx_AdminAddress)) { Write-Log -Message "[PARAM VALIDATION] DDC is required for Citrix CVAD" -Level Error; Exit 1 }
    }
    # If CitrixDaaS, Must have CustomerID, ClientID, ClientSecret, and Region
    if ($IsCitrixDaaS) {
        if (-not $SecureClientFile) {
            if ([string]::IsNullOrEmpty($ClientID)) { Write-Log -Message "[PARAM VALIDATION] ClientID is required for Citrix DaaS" -Level Error; Exit 1}
            if ([string]::IsNullOrEmpty($ClientSecret)) { Write-Log -Message "[PARAM VALIDATION] ClientSecret is required for Citrix DaaS" -Level Error; Exit 1 }
        }
        if ([string]::IsNullOrEmpty($CustomerID)) { Write-Log -Message "[PARAM VALIDATION] CustomerID is required for Citrix DaaS" -Level Error; Exit 1 }
        if ([string]::IsNullOrEmpty($Region)) { Write-Log -Message "[PARAM VALIDATION] Region is required for Citrix DaaS" -Level Error; Exit 1 }
    }
    if (-not $IsCitrixDaaS) {
        # Must have either DomainUser and DomainPassword for API access. Means we can use the same functions for CVAD and DaaS.
        if ([string]::IsNullOrEmpty($DomainUser)) { Write-Log -Message "[PARAM VALIDATION] DomainUser is required for Citrix Processing" -Level Error; Exit 1 }
        if ([string]::IsNullOrEmpty($DomainPassword)) { Write-Log -Message "[PARAM VALIDATION] DomainPassword is required for Citrix Processing" -Level Error; Exit 1 }
    }
    
}
#endregion Param Validation

#Region Execute
# ============================================================================
# Execute
# ============================================================================
StartIteration

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 7) { 
    Write-Log -message "[ERROR] This script only supports PowerShell 7." -Level Error 
    Write-Log -Message "[INFO] PowerShell version is: $($PSVersionTable.PSVersion)" -Level Info
    StopIteration
    Exit 1
}

#region Citrix Authentication
#-------------------------------------------------------------
if ($ctx_Catalogs -or $ctx_SiteConfigJSON) {
    if ($IsCitrixDaaS) {
        if ($SecureClientFile) {
                Write-Log -Message "[Citrix Cloud] Importing Secure Client: $($SecureClientFile)" -Level Info
                try {
                    $SecureClient = Import-Csv -Path $SecureClientFile -ErrorAction Stop
                    $Global:ClientID = $SecureClient.ID
                    $Global:ClientSecret = $SecureClient.Secret
                }
                catch {
                    Write-Log -Message "[Citrix Cloud] Failed to import Secure Client File" -Level Warn
                    StopIteration
                    Exit 1
                }
        } else {
            $Global:ClientID = $ClientID
            $Global:ClientSecret = $ClientSecret
        }
        $Global:CustomerID = $CustomerID
        $Global:Region = $Region
        #------------------------------------------------------------
        # Set Cloud API URL based on Region
        #------------------------------------------------------------
        switch ($Global:Region) {
            'AP-S' { 
                $Global:CloudUrl = "api-ap-s.cloud.com"
            }
            'EU' {
                $Global:CloudUrl = "api-eu.cloud.com"
            }
            'US' {
                $Global:CloudUrl = "api-us.cloud.com"
            }
            'JP' {
                $Global:CloudUrl = "api.citrixcloud.jp"
            }
        }
        #Override the DDC with the Cloud URL for API Calls. Set a dumb value for EncodedAdminCredential as it's not needed for DaaS but mandatory on all functions for CVAD
        $Global:DDC = $CloudUrl
        $Global:EncodedAdminCredential = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("ADummyValueBecauseThisIsNotNeededForDaaS"))
    } else {
        $Global:DDC = $ctx_AdminAddress
        # Convert Username and Password to base64. This is used to talk to Citrix API. Note that we set this regardless of DaaS of CVAD so that we can use the same functions.
        $AdminCredential = "$($DomainUser):$($DomainPassword)"
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($AdminCredential)
        $Global:EncodedAdminCredential = [Convert]::ToBase64String($Bytes)
    }
}
#endregion Citrix Authentication

#region Additional Manually defined prism centrals validation
#-------------------------------------------------------------
if (-not [string]::IsNullOrEmpty($AdditionalPrismCentrals) ) {
    $additional_prism_centrals = $AdditionalPrismCentrals
    # Validate that TestAdditionalPrismCentrals contains valid IPv4 addresses
    $valid_ip_regex = '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    foreach ($ip in $additional_prism_centrals) {
        if ($ip -notmatch $valid_ip_regex) {
            Write-Log -Message "[Validation] Invalid IP address found in TestAdditionalPrismCentrals: $ip" -Level Warn
            StopIteration
            Exit 1
        }
    }
    Write-Log -Message "[Validation] Additional $(($additional_prism_centrals | Measure-Object).count) Prism Central IPs have been defined manually" -Level Info
}
#endregion Additional Manually defined prism centrals validation

#region Validate Citrix Environment
#-------------------------------------------------------------
if ($ctx_Catalogs -or $ctx_SiteConfigJSON) {
    # Citrix mode has been enabled by either specifying a list of Catalogs or a JSON input file
    Write-Log -Message "[Citrix Processing] Citrix Processing Mode is enabled" -Level Info
    $Global:CurrentCatalogCount = 1
    $Global:TotalCatalogSuccessCount = 0
    $Global:TotalCatalogFailureCount = 0

    if ($ctx_SiteConfigJSON) {
        #JSON
        Write-Log -Message "[Citrix Validation] Using JSON input file: $($ctx_SiteConfigJSON) for Citrix configuration" -Level Info
        try {
            $CitrixConfig = Get-Content $ctx_SiteConfigJSON | ConvertFrom-Json
        }
        catch {
            Write-Log -Message "[Citrix Validation] Failed to import JSON file" -Level Warn
            Write-Log -Message $_ -Level Warn 
            StopIteration
            Exit 1
        }

        # Grab the unique controllers and test each one
        $UniqeControllers = $CitrixConfig.Controller | Sort-Object -Unique
        Write-Log -Message "[Citrix Validation] There are $($UniqeControllers.Count) unique Controllers (sites) to validate" -Level Info

        # Test access to each defined controller
        foreach ($DDC in $UniqeControllers) {
            
            Write-Log -Message "[Citrix Validation] Validating Citrix Site is contactable at Delivery Controller: $($DDC)" -Level Info
            $cvad_site_details = Get-CVADSiteDetailAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
            if ([string]::IsNullOrEmpty($cvad_site_details)) {
                Write-Log -Message "[Citrix Validation] Failed to validate Citrix Delivery Controller: $($DDC)" -Level Warn
                StopIteration
                Exit 1
            } else {
                Write-Log -Message "[Citrix Validation] Successfully Validated Citrix Site: $($cvad_site_details.cvad_site.name) is contactable at Delivery Controller: $($DDC)" -Level Info
            }  
        }

        # Process the Catalog list from JSON input
        Write-Log -Message "[Citrix Validation] There are $($CitrixConfig.Catalog.Count) Catalogs to validate" -Level Info
        $CatalogCount = $CitrixConfig.Catalog.Count
        foreach ($_ in $CitrixConfig) {
            # Set details
            $Catalog = $_.Catalog
            $DDC = $_.Controller
            Write-Log -Message "[Citrix Validation] Validating Catalog $($CurrentCatalogCount) of $($CatalogCount)" -Level Info
        
            $validate_catalog_exists = Get-CVADCatalogsAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential | Where-Object { $_.Name -eq $Catalog }
            if ([string]::IsNullOrEmpty($validate_catalog_exists)) {
                Write-Log -Message "[Citrix Validation] Failed to validate Catalog: $($Catalog) on Delivery Controller: $($DDC)" -Level Warn
                $Global:TotalCatalogFailureCount++
            } else {
                Write-Log -Message "[Citrix Validation] Validating Catalog $($Catalog) exists on Delivery Controller: $($DDC)" -Level Info
                if ($validate_catalog_exists.ProvisioningType -ne "MCS") {
                    Write-Log -Message "[Citrix Validation] Catalog is of provisioning type $($validate_catalog_exists.ProvisioningType) and cannot be used on Delivery Controller: $($DDC)" -Level Warn
                    $Global:TotalCatalogFailureCount += 1
                } else {
                    if ($validate_catalog_exists.ProvisioningScheme.ResourcePool.Hypervisor.PluginFactoryName -eq "AcropolisFactory") {
                        Write-Log -Message "[Citrix Validation] Successfully validated Catalog: $($Catalog) on Delivery Controller: $($DDC)." -Level Info
                        Write-Log -Message "[Citrix Validation] Provisioning Type: $($validate_catalog_exists.ProvisioningType) and Hypervisor Plugin Type $($validate_catalog_exists.ProvisioningScheme.ResourcePool.Hypervisor.PluginFactoryName)" -Level Info
                        $Global:TotalCatalogSuccessCount ++
                    } else {
                        Write-Log -Message "[Citrix Validation] Catalog is not of type Acropolis and cannot be used on Delivery Controller: $($DDC)" -Level Warn
                        $Global:TotalCatalogFailureCount += 1
                    } 
                }
            }
        }
    }
    else {
        #NO JSON
        $Catalogs = $ctx_Catalogs

        # Test access to the defined controller
        Write-Log -Message "[Citrix Validation] Validating Citrix Site is contactable at Delivery Controller: $($DDC)" -Level Info
        $cvad_site_details = Get-CVADSiteDetailAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
        if ([string]::IsNullOrEmpty($cvad_site_details)) {
            Write-Log -Message "[Citrix Validation] Failed to validate Citrix Delivery Controller: $($DDC)" -Level Warn
            StopIteration
            Exit 1
        } else {
            Write-Log -Message "[Citrix Validation] Successfully Validated Citrix Site: $($cvad_site_details.cvad_site.name) is contactable at Delivery Controller: $($DDC)" -Level Info
        } 

        Write-Log -Message "[Citrix Validation] There are $($Catalogs.Count) Catalogs to Validate" -Level Info
        $CatalogCount = $Catalogs.Count
        foreach ($Catalog in $Catalogs) {
            
            Write-Log -Message "[Citrix Validation] Validating Catalog $($CurrentCatalogCount) of $($CatalogCount)" -Level Info
            $validate_catalog_exists = Get-CVADCatalogsAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential | Where-Object { $_.Name -eq $Catalog }
            if ([string]::IsNullOrEmpty($validate_catalog_exists)) {
                Write-Log -Message "[Citrix Validation] Failed to validate Catalog: $($Catalog) on Delivery Controller: $($DDC)" -Level Warn
                $Global:TotalCatalogFailureCount ++
            } else {
                Write-Log -Message "[Citrix Validation] Validating Catalog $($Catalog) exists on Delivery Controller: $($DDC)" -Level Info
                if ($validate_catalog_exists.ProvisioningType -ne "MCS") {
                    Write-Log -Message "[Citrix Validation] Catalog is of provisioning type $($validate_catalog_exists.ProvisioningType) and cannot be used on Delivery Controller: $($DDC)" -Level Warn
                    $Global:TotalCatalogFailureCount += 1
                } else {
                    if ($validate_catalog_exists.ProvisioningScheme.ResourcePool.Hypervisor.PluginFactoryName -eq "AcropolisFactory") {
                        Write-Log -Message "[Citrix Validation] Successfully validated Catalog: $($Catalog) on Delivery Controller: $($DDC)." -Level Info
                        Write-Log -Message "[Citrix Validation] Provisioning Type: $($validate_catalog_exists.ProvisioningType) and Hypervisor Plugin Type $($validate_catalog_exists.ProvisioningScheme.ResourcePool.Hypervisor.PluginFactoryName)" -Level Info
                        $Global:TotalCatalogSuccessCount ++
                    } else {
                        Write-Log -Message "[Citrix Validation] Catalog is not of type Acropolis and cannot be used on Delivery Controller: $($DDC)" -Level Warn
                        $Global:TotalCatalogFailureCount += 1
                    }                    
                }
            }
            $CurrentCatalogCount ++
        }
    }

    Write-Log -Message "[Citrix Validation] Successfully validated $($TotalCatalogSuccessCount) Catalogs" -Level Info
    if ($TotalCatalogFailureCount -gt 0) {
        Write-Log -Message "[Citrix Validation] Failed to validate $($TotalCatalogFailureCount) Catalogs" -Level Warn
        StopIteration
        Exit 1 # We do not want to proceed with failed validation
    }
}
#endregion Validate Citrix Environment

#region Nutanix Authentication
#------------------------------------------------------------
if ($UseCustomCredentialFile) {
    # credentials for PC
    $PrismCentralCreds = "prism-central-creds"
    Write-Log -Message "[Credentials] UseCustomCredentialFile has been selected. Attempting to retrieve credential object" -Level Info
    try {
        $PrismCentralCredentials = Get-CustomCredentials -credname $PrismCentralCreds -ErrorAction Stop
    }
    catch {
        Set-CustomCredentials -credname $PrismCentralCreds
        $PrismCentralCredentials = Get-CustomCredentials -credname $PrismCentralCreds -ErrorAction Stop
    }
    # credentials for PE
    $PrismElementCreds = "prism-element-creds"
    Write-Log -Message "[Credentials] UseCustomCredentialFile has been selected. Attempting to retrieve credential object" -Level Info
    try {
        $PrismElementCredentials = Get-CustomCredentials -credname $PrismElementCreds -ErrorAction Stop
    }
    catch {
        Set-CustomCredentials -credname $PrismElementCreds
        $PrismElementCredentials = Get-CustomCredentials -credname $PrismElementCreds -ErrorAction Stop
    }
} else {
    # credentials for PC
    Write-Log -Message "[Credentials] Prompting user for Prism Central credentials" -Level Info
    $PrismCentralCredentials = Get-Credential -Message "Enter Credentials for Prism Central Instances"
    if (!$PrismCentralCredentials) {
        Write-Log -Message "[Credentials] Failed to set user credentials" -Level Warn
        StopIteration
        Exit 1
    }
    # credentials for PE
    Write-Log -Message "[Credentials] Prompting user for Prism Element credentials" -Level Info
    $PrismElementCredentials = Get-Credential -Message "Enter Credentials for Prism Element Instances"
    if (!$PrismElementCredentials) {
        Write-Log -Message "[Credentials] Failed to set user credentials" -Level Warn
        StopIteration
        Exit 1
    }
}
#endregion Nutanix Authentication

#------------------------------------------------------------
# Initialise counts and variables
#------------------------------------------------------------
$total_error_count = 0 # start the error count
$total_success_count = 0 # start the succes count
$reporting_total_pre_validated_prism_centrals = 0
$reporting_total_failed_pre_validated_prism_centrals = 0
$reporting_total_processed_clusters = 0
$reporting_total_ignored_clusters = 0
$reporting_total_processed_prism_centrals = 0
$reporting_total_ignored_prism_centrals = 0
$reporting_total_pre_validated_validated_prism_elements = 0
$reporting_total_failed_pre_validated_prism_elements = 0

#region Learn about Nutanix availability zones
#-------------------------------------------------------------
$availability_zones = Get-PCAvailabilityZones -pc $SourcePC -PrismCentralCredentials $PrismCentralCredentials
if (-not [string]::IsNullOrEmpty($availability_zones)) {
    Write-Log -Message "[Availability Zones] Returned $(($Availability_zones | Measure-Object).Count) Availability Zones from pc $($SourcePC)" -Level info
} else {
    Write-Log -Message "[Availability Zones] Returned no Availability Zones from pc $($SourcePC)" -Level info
}
#endregion Learn about Nutanix availability zones

#region Learn about Prism Centrals via remote_connections api.
#-------------------------------------------------------------
#This should only be run if the AdditionAlPrismCentrals parameter is not set
if ([string]::IsNullOrEmpty($AdditionalPrismCentrals)) {
    $prism_centrals = Get-PCRemoteConections -pc $SourcePC -PrismCentralCredentials $PrismCentralCredentials
    if (-not [string]::IsNullOrEmpty($prism_centrals)) {
        foreach ($_ in $prism_centrals.status.resources.remote_address.ip) {
            $remote_ip = $_
            Write-Log -Message "[Availability Zones] Remote PC Connection IP: $($remote_ip)" -level Info
        }
    } else {
        Write-Log -Message "[Prism Central] Returned no Prism Central Instances from pc $($SourcePC)" -Level info
    }
}
#endregion Learn about Prism Centrals via remote_connections api

#region Learn about the Source VM
#-------------------------------------------------------------
$source_vm = Get-PCVM -pc $SourcePC -vmName $BaseVM -PrismCentralCredentials $PrismCentralCredentials
if (-not [string]::IsNullOrEmpty($source_vm)) {
    Write-Log -Message "[VM] Found Source VM: $($source_vm.name) on pc ($SourcePC)" -Level Info
} else {
    Write-Log -Message "[VM] Could not find Source VM: $($BaseVM) on pc ($SourcePC)" -Level Warn
    StopIteration
    Exit 1
}
#endregion Learn about the Source VM

#region Learn about the Source VM Recovery Points
#-------------------------------------------------------------
if ($UseLatestRecoveryPoint -eq $true) {
    $vm_recovery_points_list = Get-PCRecoveryPoints -pc $SourcePC -PrismCentralCredentials $PrismCentralCredentials
    $vm_recovery_point = $vm_recovery_points_list | Where-Object {$_.vmRecoveryPoints.vmExtId -eq $source_vm.extId} | Sort-Object creationTime | Select-Object -Last 1 #This is the latest existing recovery point for the Source VM
    if (-not [string]::IsNullOrEmpty($vm_recovery_point)) {
        Write-Log -Message "[Recovery Point] Using the latest recovery point: $($vm_recovery_point.name) for the Source VM: $($source_vm.name)" -Level Info
    } else {
        Write-Log -Message "[Recovery Point] Could not find a recovery point: $($vm_recovery_point.name) for the Source VM: $($source_vm.name)" -Level Warn
        StopIteration
        Exit 1
    }
} elseif ($RecoveryPoint) {
    $vm_recovery_points_list = Get-PCRecoveryPoints -pc $SourcePC -PrismCentralCredentials $PrismCentralCredentials
    $vm_recovery_point = $vm_recovery_points_list | Where-Object {$_.vmRecoveryPoints.vmExtId -eq $source_vm.extId -and $_.name -eq $RecoveryPoint} #This is the specified recovery point for the Source VM
    if (-not [string]::IsNullOrEmpty($vm_recovery_point)) {
        Write-Log -Message "[Recovery Point] Using the name matched recovery point: $($vm_recovery_point.name) for the Source VM: $($source_vm.name)" -Level Info
    } else {
        Write-Log -Message "[Recovery Point] Could not find a recovery point: $($vm_recovery_point.name) for the Source VM: $($source_vm.name)" -Level Warn
        StopIteration
        Exit 1
    }
}
#endregion Learn about the Source VM Recovery Points

#region Validate Access to Prism Centrals and Clusters
#-------------------------------------------------------------
$prism_central_instances = [System.Collections.ArrayList]@() # Master PC List
$prism_central_instances.Add($SourcePC) | Out-Null

#region Define a list of Prism Centrals
#-------------------------------------------------------------
if (-not [string]::IsNullOrEmpty($AdditionalPrismCentrals)) {
    # Override via parameter 
    Write-Log -Message "[Prism Central] Additional Prism Central Instances have been specified" -Level Info
    $AdditionalPrismCentrals | Where-Object {$_ -notin $ExcludedPrismCentrals} | ForEach-Object { $prism_central_instances.Add($_) | Out-Null } 
} else {
    # we trust the source of truth from PC
    Write-Log -Message "[Prism Central] Using PC remote connections as the source of truth from the Prism Central Instance $($SourcePC)" -Level Info
    $prism_centrals.status.resources.remote_address.ip | Where-Object {$_ -notin $ExcludedPrismCentrals} | ForEach-Object { $prism_central_instances.Add($_) | Out-Null }
}

if (-not [string]::IsNullOrEmpty($ExcludedPrismCentrals)) {
    Write-Log -Message "[Prism Central] Excluded Prism Central Instances have been specified" -Level Info
    $ExcludedPrismCentrals | ForEach-Object { 
        Write-Log -Message "[Prism Central] Excluding Prism Central Instance $_ " -Level Info
        $reporting_total_ignored_prism_centrals ++
     }
}

if (-not [string]::IsNullOrEmpty($ExcludedClusters)) {
    Write-Log -Message "[Prism Central] Excluded Clusters have been specified" -Level Info
    $ExcludedClusters | ForEach-Object { 
        Write-Log -Message "[Prism Central] Excluding Cluster $_ " -Level Info
        $reporting_total_ignored_clusters ++
     }
}
#endregion Define a list of Prism Centrals

$primary_prism_central_processed = $false #set this once, then trigger it once we have hit the source PC

#region Process each PC
#-------------------------------------------------------------
foreach ($pc in $prism_central_instances) {

    if ($primary_prism_central_processed -eq $false) { 
        $pc = $SourcePC 
    } else { 
        $pc = $pc | Where-Object { $pc -ne $SourcePC } 
    }

    $pc_details = Get-PCDetails -pc $pc -PrismCentralCredentials $PrismCentralCredentials
    if ([string]::IsNullOrEmpty($pc_details)) {
        Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
        $reporting_total_failed_pre_validated_prism_centrals ++
    } else {
        Write-Log -Message "[Prism Central] Successfully connected to Prism Central Instance: $($pc)" -Level Info
        Write-Log -Message "[Prism Central] PC $($pc) Version: $($pc_details.config.buildInfo.version) PC Size: $($pc_details.config.size)"  -Level Info
        $reporting_total_pre_validated_prism_centrals ++
    }

    #region Validate the clusters under the Prism Central
    #-------------------------------------------------------------
    $prism_central_owned_clusters = (Get-PCClusters -pc $pc -PrismCentralCredentials $PrismCentralCredentials | Where-Object {$_.name -ne "Unnamed"}).network.externalAddress.IPv4.value
    if ([string]::IsNullOrEmpty($prism_central_owned_clusters)) {
        Write-Log -Message "[Prism Central] Could not find any Clusters under Prism Central Instance: $($pc)" -Level Warn
    } else {
        Write-Log -Message "[Prism Central] Found $(($prism_central_owned_clusters | Measure-Object).Count) Clusters under Prism Central Instance: $($pc)" -Level Info
        $prism_central_owned_clusters_detail = (Get-PCClusters -pc $pc -PrismCentralCredentials $PrismCentralCredentials | Where-Object {$_.name -ne "Unnamed"}) | Where-Object {$_.network.externalAddress.IPv4.value -notin $ExcludedClusters}
        foreach ($cluster in $prism_central_owned_clusters_detail | where-Object {$_ -notin $ExcludedClusters}) {
            Write-Log -Message "[Cluster Validation] Cluster: $($cluster.name) AOS Version: $($cluster.config.buildInfo.version)" -Level Info
        }
    }
    #endregion Validate the clusters under the Prism Central

    #region Validate Container Names are equal across each Cluster under PC
    #-------------------------------------------------------------
    if (-not ([string]::IsNullOrEmpty($OverrideStorageContainer))) {
        Write-Log -Message "[Cluster Validation] Override Storage Container Name: $($OverrideStorageContainer) has been specified" -Level Info
        # Get the StorageContainers
        $storage_container_list = Get-PCStorageContainerList -pc $pc -PrismCentralCredentials $PrismCentralCredentials
        # Validate that there is a Storage Container with the name OverrideStorageContainer per cluster
        $validated_target_storage_containers = 0
        foreach ($cluster in $prism_central_owned_clusters_detail) {
            $target_storage_container = $storage_container_list | Where-Object {$_.name -eq $OverrideStorageContainer -and $_.clusterExtId -eq $cluster.extId}
            if ([string]::IsNullOrEmpty($target_storage_container)) {
                Write-Log -Message "[Cluster Validation] Storage Container: $($OverrideStorageContainer) not found on Cluster: $($cluster.name)" -Level Warn
            } else {
                Write-Log -Message "[Cluster Validation] Successfully validated target Storage Container: $($OverrideStorageContainer) on Cluster: $($cluster.name)" -Level Info
                $validated_target_storage_containers ++
            }
        }
        # validate that the Storage Container is present on all clusters and exit if not
        if ($validated_target_storage_containers -eq $prism_central_owned_clusters_detail.count) {
            Write-Log -Message "[Cluster Validation] Successfully validated target Storage Container: $($OverrideStorageContainer) on all Clusters under PC: $($pc)" -Level Info
        } else {
            Write-Log -Message "[Cluster Validation] Failed to validate target Storage Container: $($OverrideStorageContainer) on all Clusters under PC: $($pc)" -Level Warn
            StopIteration
            Exit 1
        }
    }
    #endregion Validate Container Names are equal across each Cluster under PC

    #region Validate PE Authentication
    #-------------------------------------------------------------
    if ($OutputType -eq "PE-Snapshot") {
        Write-Log -Message "[Cluster Validation] Executing Cluster Validation for PC: $($pc)" -Level Info
        foreach ($cluster in $prism_central_owned_clusters | Where-Object {$_ -notin $ExcludedClusters}) {
            # Validate PE Access with a basic Cluster Get
            if ((Invoke-PEAuthCheckv2 -ClusterIP $cluster -PrismElementCredentials $PrismElementCredentials) -eq $true) {
                Write-Log -Message "[Cluster Validation] Successfully validated access to Cluster: $($cluster)" -Level Info
                $reporting_total_pre_validated_validated_prism_elements ++
            } else {
                Write-Log -Message "[Cluster Validation] Failed to validate access to Cluster: $($cluster)" -Level Warn
                #Add this cluster IP to the ExcludedClusters Array
                $ExcludedClusters += $cluster
                $total_error_count ++
                $reporting_total_failed_pre_validated_prism_elements ++
            }
        }
    } else {
        Write-Log -Message "[Cluster Validation] Skipping Cluster Validation as the output type is PC-Template" -Level Info
    }
    #endregion Validate PE Authentication
    
    if ($pc -eq $SourcePC) {
        $primary_prism_central_processed = $true
    }
}
#endregion Process each PC

#region Report on validation results
#-------------------------------------------------------------
if ($reporting_total_pre_validated_prism_centrals -eq ($prism_central_instances | Measure-Object).Count) {
    Write-Log -Message "[Prism Central] Successfully validated $($reporting_total_pre_validated_prism_centrals) Prism Central Instances" -Level Info
} else {
    if (-not $BypassAllValidationErrors) {
        Write-Log -Message "[Prism Central] Failed to validate $($reporting_total_failed_pre_validated_prism_centrals) Prism Central Instances" -Level Warn
        StopIteration
        Exit 1
    } else {
        Write-Log -Message "[Prism Central] Bypassing validation errors for $($reporting_total_failed_pre_validated_prism_centrals) Prism Central Instances" -Level Warn
    }
}

if ($reporting_total_failed_pre_validated_prism_elements -gt 0) {
    if (-not $BypassAllValidationErrors) {
        Write-Log -Message "[Prism Element] Failed to validate Prism Element access to $($reporting_total_failed_pre_validated_prism_elements)) Clusters" -Level Warn
        StopIteration
        Exit 1
    } else {
        Write-Log -Message "[Prism Element] Bypassing validation errors for $($reporting_total_failed_pre_validated_prism_elements) Clusters" -Level Warn
    }
    
} else {
    Write-Log -Message "[Prism Element] Successfully validated Prism Element access to $($reporting_total_pre_validated_validated_prism_elements) Clusters" -Level Info
}
#endregion Report on validation results

#endregion Validate Access to Prism Centrals and Clusters

if ($ValidateOnly -eq $true) {
    # If ValidateOnly is set, we do not want to proceed with the rest of the script
    Write-Log -Message "[Validation] ValidateOnly is set to true. Exiting script." -Level Info
    StopIteration
    Exit 0
}

#region Create a new Recovery Point for the Source VM
#-------------------------------------------------------------
if (-not $RecoveryPoint -and $UseLatestRecoveryPoint -ne $true) {
    Write-Log -Message "[Recovery Point] Creating a new recovery point for the Source VM: $($source_vm.name)" -Level Info
    $new_recovery_point_task = (New-PCRecoveryPoint -pc $SourcePC -VMExtId $source_vm.extId -PrismCentralCredentials $PrismCentralCredentials -RecoveryPointName "TempRPForReplication").extId
    if ([string]::IsNullOrEmpty($new_recovery_point_task)) {
        Write-Log -Message "[Recovery Point] Could not find the create recovery point task detail on PC: $($SourcePC)" -Level Warn
        StopIteration
        Exit 1
    }
    
    $null = Get-PCTaskv4 -pc $SourcePC -TaskID $new_recovery_point_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Recovery Point]"
    
    $vm_recovery_point_list = Get-PCRecoveryPoints -pc $SourcePC -PrismCentralCredentials $PrismCentralCredentials
    $vm_recovery_point = $vm_recovery_point_list | Where-Object {$_.vmRecoveryPoints.vmExtId -eq $source_vm.extId} | Sort-Object creationTime | Select-Object -Last 1
    
    if ([string]::IsNullOrEmpty($vm_recovery_point)) {
        Write-Log -Message "[Recovery Point] Could not find a recovery point: $($vm_recovery_point.name) for the Source VM: $($source_vm.name)" -Level Warn
        StopIteration
        Exit 1
    } else {
        Write-Log -Message "[Recovery Point] Using the created recovery point: $($vm_recovery_point.name) for the Source VM: $($source_vm.name)" -Level Info
    }
}

#endregion Create a new Recovery Point for the Source VM

#region Process Each PC
#-------------------------------------------------------------
if ($OutputType -eq "PC-Template") {
    
    $primary_prism_central_processed = $false #set this once, then trigger it once we have hit the source PC

    $total_pc_task_failures = 0
    
    foreach ($pc in $prism_central_instances) {
        if ($primary_prism_central_processed -eq $false) { 
            $pc = $SourcePC 
        } else { 
            $pc = $pc | Where-Object { $pc -ne $SourcePC } 
        }
        Write-Log -Message "[Prism Central] ---------------------------------------------------------------------------- " -Level Info
        Write-Log -Message "[Prism Central] ----- Processing Prism Central Instance: $($pc) ---------------- " -Level Info
        Write-Log -Message "[Prism Central] ---------------------------------------------------------------------------- " -Level Info

        #------------------------------------------------------------
        # Process the Source PC
        #------------------------------------------------------------
        if ($pc -eq $SourcePC) {
            #------------------------------------------------------------
            # Get the PC Details
            #------------------------------------------------------------
            $target_pc = Get-PCDetails -pc $pc -PrismCentralCredentials $PrismCentralCredentials 
            #------------------------------------------------------------
            # Get the Cluster Details - We need to know where to send the RP
            #------------------------------------------------------------
            $target_cluster_list = Get-PCClusters -pc $pc -PrismCentralCredentials $PrismCentralCredentials | Where-Object {$_.name -ne "Unnamed"} 
            $target_cluster = $target_cluster_list | Select-Object -First 1 ### //JK How are we going to determine which cluster to use for this? I think we add an Array of Clusters as a Param. If not specified, use the first.
            
            #region Restore the Recovery Point
            #------------------------------------------------------------
            $params = @{
                pc                      = $pc
                RecoveryPointExtId      = $vm_recovery_point.ExtId
                RecoveryPointName       = $vm_recovery_point.name
                VMRecoveryPointExtId    = $vm_recovery_point.vmRecoveryPoints.ExtId
                clusterExtId            = $target_cluster.ExtId
                clusterName             = $target_cluster.name
                VMName                  = $TempVMName
                PrismCentralCredentials = $PrismCentralCredentials
            }
            $restore_recovery_point_task = (Invoke-PCRecoveryPointRestore @params).ExtId
            if ([string]::IsNullOrEmpty($restore_recovery_point_task)) {
                Write-Log -Message "[Recovery Point] Could not find the recovery point restore task detail on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            } else {
                $null = Get-PCTaskv4 -pc $pc -TaskID $restore_recovery_point_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Recovery Point]"
            }
            #endregion Restore the Recovery Point

            #region Learn about the restored VM
            #------------------------------------------------------------
            $restored_vm = Get-PCVM -pc $pc -vmName $TempVMName -PrismCentralCredentials $PrismCentralCredentials # Now we are looking for the restored VM detail
            $restored_vm = $restored_vm | Sort-Object createTime | Select-Object -Last 1    
            if ([string]::IsNullOrEmpty($restored_vm)) {
                Write-Log -Message "[VM] Could not find the restored VM: $($restored_vm.name) on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            }
            #endregion Learn about the restored VM
            
            #region migrate the temp VM to the appropriate storage container
            #------------------------------------------------------------
            if (-not ([String]::IsNullOrEmpty($OverrideStorageContainer))) {
                $target_container = Get-PCStorageContainerList -pc $pc -PrismCentralCredentials $PrismCentralCredentials -ClusterExtId $target_cluster.ExtId | Where-Object {$_.name -eq $OverrideStorageContainer}
                if ($restored_vm.disks[0].backinginfo.storagecontainer.extId -ne $target_container.ContainerExtId) {
                    Write-Log -Message "[Storage Container] Overriding Storage Container to: $($OverrideStorageContainer) for the restored VM: $($restored_vm.name) on PC: $($pc)" -Level Info
                    $Etag = Get-PCVMDetailForEtag -pc $pc -VMExtId $restored_vm.ExtId -PrismCentralCredentials $PrismCentralCredentials
                    if ([string]::IsNullOrEmpty($Etag)) {
                        Write-Log -Message "[Storage Container] Could not find the Etag for the restored VM: $($restored_vm.name) on PC: $($pc)" -Level Warn
                        $total_pc_task_failures ++
                        Continue
                    } else {
                        $Params = @{
                            pc                      = $pc
                            PrismCentralCredentials = $PrismCentralCredentials
                            VMExtId                 = $restored_vm.extId
                            ClusterExtId            = $target_cluster.extId
                            ClusterName             = $target_cluster.name
                            ContainerExtId          = $target_container.ContainerExtId
                            ContainerName           = $target_container.name
                            Etag                    = $Etag
                        }
                        $migration_task = Invoke-PCVMDiskMigration @params
                        $task_status = Get-PCTaskv4 -pc $pc -TaskID $migration_task.extId -PrismCentralCredentials $PrismCentralCredentials -Phase "[Disk Migration]" -SleepTime 45
                        if ($task_status.status -ne "SUCCEEDED") {
                            Write-Log -Message "[Storage Container] Failed to migrate the restored VM: $($restored_vm.name) to the target Storage Container: $($target_container.name) on PC: $($pc). Task Status: $($task_status.status)" -Level Warn
                            Continue
                        }
                    }
                } else {
                    Write-Log -Message "[Storage Container] The restored VM: $($restored_vm.name) is already in the target Storage Container: $($target_container.name) on PC: $($pc)" -Level Info
                }
            }
            #endregion migrate the temp VM to the appropriate storage container

            #region Create a template from the restored VM
            #------------------------------------------------------------
            $create_pc_template_task = (New-PCTemplate -pc $pc -TemplateName $pc_template_name -VMExtId $restored_vm.extId -PrismCentralCredentials $PrismCentralCredentials).ExtId
            if ([string]::IsNullOrEmpty($create_pc_template_task)) {
                Write-Log -Message "[Template] Could not find the create template task on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            } else {
                $null = Get-PCTaskv4 -pc $pc -TaskID $create_pc_template_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Template]"
            }
            #endregion Create a template from the restored VM
            
            #region Delete the temp VM
            #------------------------------------------------------------
            $etag = Get-PCVMDetailForEtag -pc $pc -VMExtId $restored_vm.ExtId -PrismCentralCredentials $PrismCentralCredentials
            if ([string]::IsNullOrEmpty($etag)) {
                Write-Log -Message "[VM] Could not find the Etag for the restored VM: $($restored_vm.name) on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            }
            $vm_delete_task = (Invoke-PCVMDelete -pc $pc -VMExtId $restored_vm.extId -Etag $etag -PrismCentralCredentials $PrismCentralCredentials).ExtId
            if ([string]::IsNullOrEmpty($vm_delete_task)) {
                Write-Log -Message "[VM] Could not find the delete VM task on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            } else {
                $null = Get-PCTaskv4 -pc $pc -TaskID $vm_delete_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[VM]" -SleepTime 10
            }
            #endregion Delete the temp VM
            
            #region Delete older templates
            #------------------------------------------------------------
            if (-not [string]::IsNullOrEmpty($ImageSnapsOrTemplatesToRetain)){
                $template_deleted_success = 0
                Write-Log -Message "[Template] Retaining only the last $($ImageSnapsOrTemplatesToRetain) Templates. Deleting older Templates on pc $($pc)" -Level Info
                $template_list = Get-PCTemplates -pc $pc -PrismCentralCredentials $PrismCentralCredentials
                Write-Log -Message "[Template] There are $(($template_list | Measure-Object).Count) Templates on PC: $($pc)" -Level Info
                $template_list = $template_list | Where-Object{ $_.templateName -like "$($name_match_for_deletion)*" }

                Write-Log -Message "[Template] There are $(($template_list | Measure-Object).Count) Templates matching $($name_match_for_deletion)* on PC: $($pc)" -Level Info

                $templates_to_retain = $template_list | sort-object createTime -Descending | Select-Object -First $ImageSnapsOrTemplatesToRetain 
                if (-not [string]::IsNullOrEmpty($template_list)) {
                    foreach ($template_to_delete in $template_list | Where-Object {$_ -notin $templates_to_retain}) {
                        $etag = Get-PCTemplateDetailForEtag -pc $pc -TemplateExtId $template_to_delete.extId -PrismCentralCredentials $PrismCentralCredentials
                        if ([string]::IsNullOrEmpty($etag)) {
                            Write-Log -Message "[Template] Could not find the Etag for the Template: $($template_to_delete.name) on PC: $($pc)" -Level Warn
                            $total_pc_task_failures ++
                            Continue
                        } else {
                            $template_delete_task = (Invoke-PCTemplateDelete -pc $pc -TemplateExtId $template_to_delete.extId -Etag $etag -PrismCentralCredentials $PrismCentralCredentials).ExtId
                            if ([string]::IsNullOrEmpty($template_delete_task)) {
                                Write-Log -Message "[Template] Could not find the delete Template task on PC: $($pc)" -Level Warn
                                $total_pc_task_failures ++
                                Continue
                            } else {
                                $null = Get-PCTaskv4 -pc $pc -TaskID $template_delete_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Template]" -SleepTime 5
                                $template_deleted_success ++
                            }
                        }
                    }
                    Write-Log -Message "[Template] Successfully deleted $($template_deleted_success) Templates on pc $($pc)" -Level Info
                }
            }
            #endregion Delete older templates
        }

        #------------------------------------------------------------
        # process each Remote PC
        #------------------------------------------------------------
        if ($pc -ne $SourcePC) {
            #------------------------------------------------------------
            # Get the PC Details
            #------------------------------------------------------------
            $target_pc = Get-PCDetails -pc $pc -PrismCentralCredentials $PrismCentralCredentials 
            #------------------------------------------------------------
            # Get the Cluster Details - We need to know where to send the RP
            #------------------------------------------------------------
            $target_cluster_list = Get-PCClusters -pc $pc -PrismCentralCredentials $PrismCentralCredentials | Where-Object {$_.name -ne "Unnamed"} 
            $target_cluster = $target_cluster_list | Select-Object -First 1 ### //JK How are we going to determine which cluster to use for this? I think we add an Array of Clusters as a Param. If not specified, use the first.
            
            #region Replicate the Recovery Point
            #------------------------------------------------------------
            $params = @{
                pc                      = $SourcePC
                RecoveryPointExtId      = $vm_recovery_point.ExtId
                RecoveryPointName       = $vm_recovery_point.name
                pcExtId                 = $target_pc.extId
                clusterExtId            = $target_cluster.ExtId
                clusterName             = $target_cluster.name
                PrismCentralCredentials = $PrismCentralCredentials
            }
            $replicate_recovery_point_task = (Invoke-PCRecoveryPointReplicate @params).ExtId
            if ([string]::IsNullOrEmpty($replicate_recovery_point_task)) {
                Write-Log -Message "[Recovery Point] Could not find recovery point replication task detail on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            } else {
                $null = Get-PCTaskv4 -pc $SourcePC -TaskID $replicate_recovery_point_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Recovery Point]" -SleepTime 20
            }
            #endregion Replicate the Recovery Point
            
            #region Restore the Recovery Point
            #------------------------------------------------------------
            $target_pc_vm_recovery_point_list = Get-PCRecoveryPoints -pc $pc -PrismCentralCredentials $PrismCentralCredentials
            $target_cluster_vm_recovery_point = $target_pc_vm_recovery_point_list | Where-Object { $_.locationAgnosticId -eq $vm_recovery_point.locationAgnosticId -and $_.locationReferences.locationExtId -eq $target_cluster.ExtId }
            if ([string]::IsNullOrEmpty($target_cluster_vm_recovery_point)) {
                Write-Log -Message "[Recovery Point] Could not find the replicated recovery point for the Source VM: $($source_vm.name) on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            }
            $params = @{
                pc                      = $pc
                RecoveryPointExtId      = $target_cluster_vm_recovery_point.ExtId
                RecoveryPointName       = $target_cluster_vm_recovery_point.name
                VMRecoveryPointExtId    = $target_cluster_vm_recovery_point.vmRecoveryPoints.ExtId
                clusterExtId            = $target_cluster.ExtId
                clusterName             = $target_cluster.name
                VMName                  = $TempVMName
                PrismCentralCredentials = $PrismCentralCredentials
            }
            $restore_recovery_point_task = (Invoke-PCRecoveryPointRestore @params).ExtId
            if ([string]::IsNullOrEmpty($restore_recovery_point_task)) {
                Write-Log -Message "[Recovery Point] Could not find restore task detail on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            } else {
                $task_status = Get-PCTaskv4 -pc $pc -TaskID $restore_recovery_point_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Recovery Point]" -SleepTime 20
                if ($task_status.status -eq "FAILED") {
                    Write-Log -Message "[Recovery Point] Restore task failed on PC: $($pc). Task ID: $($restore_recovery_point_task)" -Level Warn
                    $total_pc_task_failures ++
                    StopIteration
                    Exit 1
                }
            }
            #endregion Restore the Recovery Point

            #region Learn about the restored VM
            #------------------------------------------------------------
            $restored_vm = Get-PCVM -pc $pc -vmName $TempVMName -PrismCentralCredentials $PrismCentralCredentials # Now we are looking for the restored VM detail
            $restored_vm = $restored_vm | Sort-Object createTime | Select-Object -Last 1    
            if ([string]::IsNullOrEmpty($restored_vm)) {
                Write-Log -Message "[VM] Could not find the restored VM: $($restored_vm.name) on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                StopIteration
                Exit 1
            }
            #endregion Learn about the restored VM

            #region migrate the temp VM to the appropriate storage container
            #------------------------------------------------------------
            if (-not ([String]::IsNullOrEmpty($OverrideStorageContainer))) {
                $target_container = Get-PCStorageContainerList -pc $pc -PrismCentralCredentials $PrismCentralCredentials -ClusterExtId $target_cluster.ExtId | Where-Object {$_.name -eq $OverrideStorageContainer}
                if ($restored_vm.disks[0].backinginfo.storagecontainer.extId -ne $target_container.ContainerExtId) {
                    Write-Log -Message "[Storage Container] Overriding Storage Container to: $($OverrideStorageContainer) for the restored VM: $($restored_vm.name) on PC: $($pc)" -Level Info
                    $Etag = Get-PCVMDetailForEtag -pc $pc -VMExtId $restored_vm.ExtId -PrismCentralCredentials $PrismCentralCredentials
                    if ([string]::IsNullOrEmpty($Etag)) {
                        Write-Log -Message "[Storage Container] Could not find the Etag for the restored VM: $($restored_vm.name) on PC: $($pc)" -Level Warn
                        $total_pc_task_failures ++
                        Continue
                    } else {
                        $Params = @{
                            pc                      = $pc
                            PrismCentralCredentials = $PrismCentralCredentials
                            VMExtId                 = $restored_vm.extId
                            ClusterExtId            = $target_cluster.extId
                            ClusterName             = $target_cluster.name
                            ContainerExtId          = $target_container.ContainerExtId
                            ContainerName           = $target_container.name
                            Etag                    = $Etag
                        }
                        $migration_task = Invoke-PCVMDiskMigration @params
                        $task_status = Get-PCTaskv4 -pc $pc -TaskID $migration_task.extId -PrismCentralCredentials $PrismCentralCredentials -Phase "[Disk Migration]" -SleepTime 45
                        if ($task_status.status -ne "SUCCEEDED") {
                            Write-Log -Message "[Storage Container] Failed to migrate the restored VM: $($restored_vm.name) to the target Storage Container: $($target_container.name) on PC: $($pc). Task Status: $($task_status.status)" -Level Warn
                            Continue
                        }
                    }
                } else {
                    Write-Log -Message "[Storage Container] The restored VM: $($restored_vm.name) is already in the target Storage Container: $($target_container.name) on PC: $($pc)" -Level Info
                }
            }
            #endregion migrate the temp VM to the appropriate storage container

            #region Create a Template from the restored VM
            #------------------------------------------------------------
            $create_pc_template_task = (New-PCTemplate -pc $pc -TemplateName $pc_template_name -VMExtId $restored_vm.extId -PrismCentralCredentials $PrismCentralCredentials).ExtId
            if ([string]::IsNullOrEmpty($create_pc_template_task)) {
                Write-Log -Message "[Template] Could not find create template task detail on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            } else {
                $null = Get-PCTaskv4 -pc $pc -TaskID $create_pc_template_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Template]" -SleepTime 5
            }
            #endregion Create a Template from the restored VM

            #region Delete the temp VM
            #------------------------------------------------------------
            $etag = Get-PCVMDetailForEtag -pc $pc -VMExtId $restored_vm.ExtId -PrismCentralCredentials $PrismCentralCredentials
            if ([string]::IsNullOrEmpty($etag)) {
                Write-Log -Message "[VM] Could not find the Etag for the restored VM: $($restored_vm.name) on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            }
            $vm_delete_task = (Invoke-PCVMDelete -pc $pc -VMExtId $restored_vm.extId -Etag $etag -PrismCentralCredentials $PrismCentralCredentials).ExtId
            if ([string]::IsNullOrEmpty($vm_delete_task)) {
                Write-Log -Message "[VM] Could not find delete VM task detail on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            } else {
                $null = Get-PCTaskv4 -pc $pc -TaskID $vm_delete_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[VM]" -SleepTime 10
            }
            #endregion Delete the temp VM

            #region Delete the Recovery Point - Only if we created one
            #------------------------------------------------------------
            if (-not [string]::IsNullOrEmpty($RecoveryPoint) -or $UseLatestRecoveryPoint -ne $true) {
                $etag = Get-PCRecoveryPointDetailForEtag -pc $pc -RPExtId $target_cluster_vm_recovery_point.ExtId -PrismCentralCredentials $PrismCentralCredentials
                if ([string]::IsNullOrEmpty($etag)) {
                    Write-Log -Message "[Recovery Point] Could not find the Etag for the replicated recovery point for the Source VM: $($source_vm.name) on PC: $($pc)" -Level Warn
                    $total_pc_task_failures ++
                    Continue
                }
                $params = @{
                    pc                      = $pc
                    RPExtId                 = $target_cluster_vm_recovery_point.ExtId
                    RPName                  = $target_cluster_vm_recovery_point.name
                    ClusterName             = $target_cluster.name
                    Etag                    = $etag
                    PrismCentralCredentials = $PrismCentralCredentials
                }
                $recovery_point_delete_task = (Invoke-PCRecoveryPointDelete @params).ExtId
                if ([string]::IsNullOrEmpty($recovery_point_delete_task)) {
                    Write-Log -Message "[Recovery Point] Could not find delete recovery point task detail on PC: $($pc)" -Level Warn
                    $total_pc_task_failures ++
                } else {
                    $null = Get-PCTaskv4 -pc $pc -TaskID $recovery_point_delete_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Recovery Point]" -SleepTime 10
                }
            }
            #endregion Delete the Recovery Point - Only if we created one

            #region Delete Older Templates if required
            #------------------------------------------------------------
            if (-not [string]::IsNullOrEmpty($ImageSnapsOrTemplatesToRetain)){
                $template_deleted_success = 0
                Write-Log -Message "[Template] Retaining only the last $($ImageSnapsOrTemplatesToRetain) Templates. Deleting older Templates on pc $($pc)" -Level Info
                $template_list = Get-PCTemplates -pc $pc -PrismCentralCredentials $PrismCentralCredentials
                Write-Log -Message "[Template] There are $(($template_list | Measure-Object).Count) Templates on PC: $($pc)" -Level Info
                $template_list = $template_list | Where-Object{ $_.templateName -like "$($name_match_for_deletion)*" }
                Write-Log -Message "[Template] There are $(($template_list | Measure-Object).Count) Templates matching $($name_match_for_deletion)* on PC: $($pc)" -Level Info
                $templates_to_retain = $template_list | sort-object createTime -Descending | Select-Object -First $ImageSnapsOrTemplatesToRetain 
                if (-not [string]::IsNullOrEmpty($templates_to_retain)) {
                    foreach ($template_to_delete in $template_list | Where-Object {$_ -notin $templates_to_retain}) {
                        $etag = Get-PCTemplateDetailForEtag -pc $pc -TemplateExtId $template_to_delete.extId -PrismCentralCredentials $PrismCentralCredentials
                        if ([string]::IsNullOrEmpty($etag)) {
                            Write-Log -Message "[Template] Could not find the Etag for the Template: $($template_to_delete.name) on PC: $($pc)" -Level Warn
                            $total_pc_task_failures ++
                            Continue
                        } else {
                            $template_delete_task = (Invoke-PCTemplateDelete -pc $pc -TemplateExtId $template_to_delete.extId -Etag $etag -PrismCentralCredentials $PrismCentralCredentials).ExtId
                            if ([string]::IsNullOrEmpty($template_delete_task)) {
                                Write-Log -Message "[Template] Could not find delete template task detail on PC: $($pc)" -Level Warn
                                $total_pc_task_failures ++
                            } else {
                                $null = Get-PCTaskv4 -pc $pc -TaskID $template_delete_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Template]" -SleepTime 5
                                $template_deleted_success ++
                            }
                        }
                    }
                    Write-Log -Message "[Template] Successfully deleted $($template_deleted_success) Templates on pc $($pc)" -Level Info
                }
            }
            #endregion Delete Older Templates if required
        }

        # flag the source PC as processed
        if ($pc -eq $SourcePC) {
            $primary_prism_central_processed = $true
        }

        # Report on any failures
        if ($total_pc_task_failures -gt 0) {
            Write-Log -Message "[Prism Central] Failed to process $($total_pc_task_failures) tasks on PC: $($pc)" -Level Warn
        }

        $reporting_total_processed_prism_centrals ++
    }
    
    #region Delete the Recovery Point from the source PC - Only if we created one
    #------------------------------------------------------------
    if (-not [string]::IsNullOrEmpty($RecoveryPoint) -or $UseLatestRecoveryPoint -ne $true) {
        $etag = Get-PCRecoveryPointDetailForEtag -pc $SourcePC -RPExtId $vm_recovery_point.ExtId -PrismCentralCredentials $PrismCentralCredentials
        if ([string]::IsNullOrEmpty($etag)) {
            Write-Log -Message "[Recovery Point] Could not find the Etag for the replicated recovery point for the Source VM: $($source_vm.name) on PC: $($pc)" -Level Warn
        } else {
            $params = @{
                pc                      = $SourcePC
                RPExtId                 = $vm_recovery_point.ExtId
                Etag                    = $etag
                PrismCentralCredentials = $PrismCentralCredentials
            }
            #$recovery_point_delete_task = (Invoke-PCRecoveryPointDelete -pc $SourcePC -RPExtId $vm_recovery_point.ExtId -Etag $etag -PrismCentralCredentials $PrismCentralCredentials).ExtId
            $recovery_point_delete_task = (Invoke-PCRecoveryPointDelete @params).ExtId
            $null = Get-PCTaskv4 -pc $SourcePC -TaskID $recovery_point_delete_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Recovery Point]"
        }
    }
    #endregion Delete the Recovery Point from the source PC - Only if we created one
}

if ($OutputType -eq "PE-Snapshot") {
    $primary_prism_central_processed = $false #set this once, then trigger it once we have hit the source PC

    $total_pc_task_failures = 0
    
    foreach ($pc in $prism_central_instances) {
        if ($primary_prism_central_processed -eq $false) { 
            $pc = $SourcePC 
        } else { 
            $pc = $pc | Where-Object { $pc -ne $SourcePC } 
        }
        Write-Log -Message "[Prism Central] ---------------------------------------------------------------------------- " -Level Info
        Write-Log -Message "[Prism Central] ----- Processing Prism Central Instance: $($pc) ----------------- " -Level Info
        Write-Log -Message "[Prism Central] ---------------------------------------------------------------------------- " -Level Info

        #------------------------------------------------------------
        # Get the PC Details
        #------------------------------------------------------------
        $target_pc = Get-PCDetails -pc $pc -PrismCentralCredentials $PrismCentralCredentials 
        #------------------------------------------------------------
        # Get the Cluster Details - We need to know where to send the RP
        #------------------------------------------------------------
        $target_cluster_list = Get-PCClusters -pc $pc -PrismCentralCredentials $PrismCentralCredentials | Where-Object {$_.name -ne "Unnamed"}
        $target_cluster_list = $target_cluster_list | Where-Object { $_.network.externalAddress.IPv4.value -notin $ExcludedClusters }

        $target_cluster_success_count = 0

        foreach ($target_cluster in $target_cluster_list) {

            Write-Log -Message "[Prism Central] ---------------------------------------------------------------------------- " -Level Info
            Write-Log -Message "[Prism Central] Processing Cluster: $($target_cluster.name) under PC: $($pc)  " -Level Info
            Write-Log -Message "[Prism Central] ---------------------------------------------------------------------------- " -Level Info

            $target_cluster_ip = $target_cluster.network.externalAddress.IPv4.value
            $target_cluster_name = $target_cluster.name

            $target_cluster_task_failures = 0
            
            #region Replicate the Recovery Point
            #------------------------------------------------------------
            if ($target_cluster.ExtId -ne $vm_recovery_point.locationReferences.locationExtId) {
                # No point replicating the Recovery Point to the cluster it already exists on this cluster
                $params = @{
                    pc                      = $SourcePC
                    RecoveryPointExtId      = $vm_recovery_point.ExtId
                    RecoveryPointName       = $vm_recovery_point.name
                    pcExtId                 = $target_pc.extId
                    clusterExtId            = $target_cluster.ExtId
                    clusterName             = $target_cluster_name
                    PrismCentralCredentials = $PrismCentralCredentials
                }
                $replicate_recovery_point_task = (Invoke-PCRecoveryPointReplicate @params).ExtId
                if ([string]::IsNullOrEmpty($replicate_recovery_point_task)) {
                    Write-Log -Message "[Recovery Point] Could not find recovery point replication task detail on PC: $($pc)" -Level Warn
                    $target_cluster_task_failures ++
                    Continue
                } else {
                    $task_status = Get-PCTaskv4 -pc $SourcePC -TaskID $replicate_recovery_point_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Recovery Point]" -SleepTime 20
                }
            } else {
                Write-Log -Message "[Recovery Point] Skipping Recovery Point replication Cluster $($target_cluster.name) as it already owns the Recovery Point" -Level Info
            }
            #endregion Replicate the Recovery Point

            #region Learn about the Replicated Recovery Point
            #------------------------------------------------------------
            $replicated_vm_recovery_point_list = Get-PCRecoveryPoints -pc $pc -PrismCentralCredentials $PrismCentralCredentials
            # Find just the Recovery Points associated with the Source VM, to the targeted recovery point using the locationAgnosticId, filter to the cluster we are targeting using the locationReferences.locationExtId
            $replicated_vm_recovery_point = $replicated_vm_recovery_point_list | Where-Object { $_.vmRecoveryPoints.vmExtId -eq $source_vm.extId }
            $replicated_vm_recovery_point = $replicated_vm_recovery_point | Where-Object { $_.locationAgnosticId -eq $vm_recovery_point.locationAgnosticId }
            $replicated_vm_recovery_point = $replicated_vm_recovery_point | Where-Object { $_.locationReferences.locationExtId -eq $target_cluster.ExtId } | Sort-Object creationTime | Select-Object -Last 1
            # We now have a single entry that matches the Recovery Point we replicated to this cluster. We will use this for restore operations
            if ([string]::IsNullOrEmpty($replicated_vm_recovery_point)) {
                Write-Log -Message "[Recovery Point] Could not find the appropriate replicated recovery point for the Source VM: $($source_vm.name) on PC: $($pc)" -Level Warn
                $target_cluster_task_failures ++
                Continue
            } else {
                Write-Log -Message "[Recovery Point] Found the replicated recovery point for the Source VM: $($source_vm.name) with ID $($replicated_vm_recovery_point.extId) on cluster $($target_cluster_name)" -Level Info
            }
            #endregion Learn about the Replicated Recovery Point

            #region Restore the Recovery Point
            #------------------------------------------------------------
            # This uses the replicated recovery point to restore the VM on the target cluster. The RP is local to the cluster.
            $params = @{
                pc                      = $pc
                RecoveryPointExtId      = $replicated_vm_recovery_point.extId
                RecoveryPointName       = $replicated_vm_recovery_point.name 
                VMRecoveryPointExtId    = $replicated_vm_recovery_point.vmRecoveryPoints.ExtId
                clusterExtId            = $target_cluster.ExtId
                clusterName             = $target_cluster.name
                VMName                  = $TempVMName
                PrismCentralCredentials = $PrismCentralCredentials
            }
            $restore_recovery_point_task = (Invoke-PCRecoveryPointRestore @params).ExtId
            if ([string]::IsNullOrEmpty($restore_recovery_point_task)) {
                Write-Log -Message "[Recovery Point] Could not find the recovery point restore task detail on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            } else {
                $null = Get-PCTaskv4 -pc $pc -TaskID $restore_recovery_point_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Recovery Point]" -SleepTime 5
            }
            #endregion Restore the Recovery Point

            #region Search for the Temporary VM
            #------------------------------------------------------------
            $restored_vm = Get-PCVM -pc $pc -vmName $TempVMName -PrismCentralCredentials $PrismCentralCredentials # Now we are looking for the restored VM detail
            $restored_vm = $restored_vm | Sort-Object createTime | Select-Object -Last 1    
            if ([string]::IsNullOrEmpty($restored_vm)) {
                Write-Log -Message "[VM] Could not find the restored VM: $($restored_vm.name) on PC: $($pc)" -Level Warn
                $total_pc_task_failures ++
                Continue
            }
            #endregion Search for the Temporary VM

            #region migrate the temp VM to the appropriate storage container
            #------------------------------------------------------------
            if (-not ([String]::IsNullOrEmpty($OverrideStorageContainer))) {
                $target_container = Get-PCStorageContainerList -pc $pc -PrismCentralCredentials $PrismCentralCredentials -ClusterExtId $target_cluster.ExtId | Where-Object {$_.name -eq $OverrideStorageContainer}
                if ($restored_vm.disks[0].backinginfo.storagecontainer.extId -ne $target_container.ContainerExtId) {
                    Write-Log -Message "[Storage Container] Overriding Storage Container to: $($OverrideStorageContainer) for the restored VM: $($restored_vm.name) on PC: $($pc)" -Level Info
                    $Etag = Get-PCVMDetailForEtag -pc $pc -VMExtId $restored_vm.ExtId -PrismCentralCredentials $PrismCentralCredentials
                    if ([string]::IsNullOrEmpty($Etag)) {
                        Write-Log -Message "[Storage Container] Could not find the Etag for the restored VM: $($restored_vm.name) on PC: $($pc)" -Level Warn
                        $total_pc_task_failures ++
                        Continue
                    } else {
                        $Params = @{
                            pc                      = $pc
                            PrismCentralCredentials = $PrismCentralCredentials
                            VMExtId                 = $restored_vm.extId
                            ClusterExtId            = $target_cluster.extId
                            ClusterName             = $target_cluster.name
                            ContainerExtId          = $target_container.ContainerExtId
                            ContainerName           = $target_container.name
                            Etag                    = $Etag
                        }
                        $migration_task = Invoke-PCVMDiskMigration @params
                        $task_status = Get-PCTaskv4 -pc $pc -TaskID $migration_task.extId -PrismCentralCredentials $PrismCentralCredentials -Phase "[Disk Migration]" -SleepTime 45
                        if ($task_status.status -ne "SUCCEEDED") {
                            Write-Log -Message "[Storage Container] Failed to migrate the restored VM: $($restored_vm.name) to the target Storage Container: $($target_container.name) on PC: $($pc). Task Status: $($task_status.status)" -Level Warn
                            Continue
                        }
                    }
                } else {
                    Write-Log -Message "[Storage Container] The restored VM: $($restored_vm.name) is already in the target Storage Container: $($target_container.name) on PC: $($pc)" -Level Info
                }
            }
            #endregion migrate the temp VM to the appropriate storage container

            #region Search for the Temporary VM via v2 API
            #------------------------------------------------------------
            $pe_vm_list = Get-PEVMListv2 -ClusterIP $target_cluster_ip -PrismElementCredentials $PrismElementCredentials

            if ([string]::IsNullOrEmpty($pe_vm_list)) {
                Write-Log -Message "[VM] Failed to retrieve virtual machines on the target cluster: $($target_cluster_name)" -Level Warn
                Continue
            } else {
                Write-Log -Message "[VM] There are $(($pe_vm_list | Measure-Object).Count) virtual machines on the target cluster: $($target_cluster_name)" -Level Info

                $temp_vm_detail = $pe_vm_list | Where-Object {$_.uuid -eq $restored_vm.extId}
                if ([string]::IsNullOrEmpty($temp_vm_detail)) {
                    Write-Log -Message "[VM] Failed to retrieve virtual machine $($restored_vm.name) on the target cluster: $($target_cluster_name)" -Level Warn
                    Continue
                } else {
                    Write-Log -Message "[VM] Found virtual machine $($temp_vm_detail.name) on the target cluster: $($target_cluster_name)" -Level Info
                    $pe_vm_uuid = $temp_vm_detail.uuid
                    $pe_vm_name = $temp_vm_detail.name
                }
            }          
            #endregion Search for the Temporary VM via v2 API

            #region Create a PE Snapshot via v2 API
            #------------------------------------------------------------
            $pe_snapshot_task = (New-PESnapshotv2 -ClusterIP $target_cluster_ip -vm_uuid $pe_vm_uuid -SnapshotName $pe_snapshot_name -PrismElementCredentials $PrismElementCredentials).task_uuid
            if ([string]::IsNullOrEmpty($pe_snapshot_task)) {
                Write-Log -Message "[VM Snapshot] Could not find the snapshot task detail on the target cluster: $($target_cluster_name)" -Level Warn
                $target_cluster_task_failures ++
                Continue
            } else {
                $null = Get-PETaskv2 -ClusterIP $target_cluster_ip -TaskID $pe_snapshot_task -PrismElementCredentials $PrismElementCredentials -Phase "[VM Snapshot]" -PhaseSuccessMessage "Snapshot: $($pe_snapshot_name) has been created" -SleepTime 5
            }
            #endregion Create a PE Snapshot via v2 API

            #region Delete the Temporary VM via v2 API
            #------------------------------------------------------------
            $pe_vm_delete_task = (Invoke-PEVMDeletev2 -ClusterIP $target_cluster_ip -vm_uuid $pe_vm_uuid -PrismElementCredentials $PrismElementCredentials).task_uuid
            if ([string]::IsNullOrEmpty($pe_vm_delete_task)) {
                Write-Log -Message "[VM] Could not find the delete VM task detail on the target cluster: $($target_cluster_name)" -Level Warn
                $target_cluster_task_failures ++
                Continue
            } else {
                $null = Get-PETaskv2 -ClusterIP $target_cluster_ip -TaskID $pe_vm_delete_task -PrismElementCredentials $PrismElementCredentials -Phase "[VM]" -PhaseSuccessMessage "Temporary VM: $($pe_vm_name) has been deleted" -SleepTime 5
            }
            #endregion Delete the Temporary VM via v2 API

            #region Delete old snapshots if required via V2 API
            #------------------------------------------------------------
            if (-not [string]::IsNullOrEmpty($ImageSnapsOrTemplatesToRetain)){
                $snapshot_deleted_success = 0
                Write-Log -Message "[VM Snapshot] Retaining only the last $($ImageSnapsOrTemplatesToRetain) snapshots. Deleting older snapshots on cluster $($target_cluster_name)" -Level Info
                $pe_snapshot_list = Get-PESnapshotListv2 -ClusterIP $target_cluster_ip -PrismElementCredentials $PrismElementCredentials
                Write-Log -Message "[VM Snapshot] There are $(($pe_snapshot_list | Measure-Object).Count) snapshots on the target cluster: $($target_cluster_name)" -Level Info
                $pe_snapshot_list = $pe_snapshot_list | Where-Object { $_.snapshot_name -like "$($name_match_for_deletion)*" }
                Write-Log -Message "[VM Snapshot] There are $(($pe_snapshot_list | Measure-Object).Count) snapshots matching $($name_match_for_deletion)* on the target cluster: $($target_cluster_name)" -Level Info
                $snapshots_to_retain = $pe_snapshot_list | sort-object created_time -Descending | Select-Object -First $ImageSnapsOrTemplatesToRetain
                
                if (-not [string]::IsNullOrEmpty($pe_snapshot_list)) {
                    foreach ($snapshot_to_delete in $pe_snapshot_list | Where-Object {$_ -notin $snapshots_to_retain}) {
                        $snapshot_delete_task = (Invoke-PESnapshotDeletev2 -ClusterIP $target_cluster_ip -Snapshot_uuid $snapshot_to_delete.uuid -PrismElementCredentials $PrismElementCredentials).task_uuid
                        if ([string]::IsNullOrEmpty($snapshot_delete_task)) {
                            Write-Log -Message "[Snapshot] Could not find the delete snapshot task on the target cluster: $($target_cluster_name)" -Level Warn
                            $target_cluster_task_failures ++
                            Continue
                        } else {
                            $null = Get-PETaskv2 -ClusterIP $target_cluster_ip -TaskID $snapshot_delete_task -PrismElementCredentials $PrismElementCredentials -Phase "[VM Snapshot]"
                            $snapshot_deleted_success ++
                        }
                    }
                    if ($snapshot_deleted_success -gt 0) {
                        Write-Log -Message "[VM Snapshot] Successfully deleted $($snapshot_deleted_success) Snapshots on the target cluster: $($target_cluster_name)" -Level Info
                    } else {
                        Write-Log -Message "[VM Snapshot] No snapshots matching deletion criteria were deleted on the target cluster: $($target_cluster_name)" -Level Info
                    }
                }
            }
            #endregion Delete old snapshots if required via V2 API

            #region Delete the replicated Recovery Point from the Cluster
            #------------------------------------------------------------
            if ($target_cluster.ExtId -ne $vm_recovery_point.locationReferences.locationExtId) {
                # Don't delete the source Recovery Point from the source cluster until later.
                $etag = Get-PCRecoveryPointDetailForEtag -pc $pc -RPExtId $replicated_vm_recovery_point.extId -PrismCentralCredentials $PrismCentralCredentials
                if ([string]::IsNullOrEmpty($etag)) {
                    Write-Log -Message "[Recovery Point] Could not find the Etag for the replicated recovery point for the Source VM: $($source_vm.name) on PC: $($pc)" -Level Warn
                } else {
                    $params = @{
                        pc                      = $pc
                        RPExtId                 = $replicated_vm_recovery_point.extId
                        RPName                  = $replicated_vm_recovery_point.name
                        clusterName             = $target_cluster_name
                        Etag                    = $etag
                        PrismCentralCredentials = $PrismCentralCredentials
                    }
                    $recovery_point_delete_task = (Invoke-PCRecoveryPointDelete @params).ExtId
                    $null = Get-PCTaskv4 -pc $pc -TaskID $recovery_point_delete_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Recovery Point]"
                }
            }
            
            #endregion Delete the replicate Recovery Point from the Cluster

            If ($target_cluster_task_failures -eq 0) { $target_cluster_success_count ++ }
        }

        $reporting_total_processed_clusters += $target_cluster_success_count

        Write-Log -Message "[Cluster] Successfully processed $($target_cluster_success_count) clusters under PC: $($pc)" -Level Info
        
        # flag the source PC as processed
        if ($pc -eq $SourcePC) {
            $primary_prism_central_processed = $true
        }

        $reporting_total_processed_prism_centrals ++

    }
    
    #region Delete the Recovery Point from the source PC - Only if we created one
    #------------------------------------------------------------
    if (-not [string]::IsNullOrEmpty($RecoveryPoint) -or $UseLatestRecoveryPoint -ne $true) {
        $etag = Get-PCRecoveryPointDetailForEtag -pc $SourcePC -RPExtId $vm_recovery_point.ExtId -PrismCentralCredentials $PrismCentralCredentials
        if ([string]::IsNullOrEmpty($etag)) {
            Write-Log -Message "[Recovery Point] Could not find the Etag for the replicated recovery point for the Source VM: $($source_vm.name) on PC: $($pc)" -Level Warn
        } else {
            $params = @{
                pc                      = $SourcePC
                RPExtId                 = $vm_recovery_point.ExtId
                Etag                    = $etag
                PrismCentralCredentials = $PrismCentralCredentials
            }
            $recovery_point_delete_task = (Invoke-PCRecoveryPointDelete @params).ExtId
            $null = Get-PCTaskv4 -pc $SourcePC -TaskID $recovery_point_delete_task -PrismCentralCredentials $PrismCentralCredentials -Phase "[Recovery Point]"
        }
    } 
    #endregion Delete the Recovery Point from the source PC - Only if we created one

    # Report on any failures
    if ($total_pc_task_failures -gt 0) {
        Write-Log -Message "[Prism Central] Failed to process $($total_pc_task_failures) tasks on PC: $($pc)" -Level Warn
    }
      
}
#endregion Process each PC

Write-Log -Message "[Data] ---------------- Results Outputs ----------------" -Level Info
Write-Log -Message "[Data] Processed a total of $($Reporting_Total_Processed_Prism_Centrals) Prism Centrals" -Level Info
Write-Log -Message "[Data] Ignored a total of $($Reporting_Total_Ignored_Prism_Centrals) Prism Centrals" -Level Info
if ($OutputType -eq "PE-Snapshot") {
    Write-Log -Message "[Data] Processed a total of $($Reporting_Total_Processed_Clusters) Clusters" -Level Info
    Write-Log -Message "[Data] Ignored a total of $($Reporting_Total_Ignored_Clusters) Clusters" -Level Info
    Write-Log -Message "[Data] Successfully processed $($total_success_count) Clusters without error" -Level Info
}
Write-Log -Message "[Data] Encountered $($total_error_count) errors. Please review log file $($LogPath) for failures" -Level Info

#region Process Citrix Environment
#-------------------------------------------------------------
if ($ctx_Catalogs -or $ctx_SiteConfigJSON) {
    # Citrix mode has been enabled by either specifying a list of Catalogs or a JSON input file
    if ($TotalErrorCount -gt 0) {
        # We cannot process, way to risky
        Write-Log -Message "[Citrix Processing] Citrix Environment processing has been enabled, however there are $($TotalErrorCount) errors in the snapshot replication phase. Not processing the Citrix environment" -Level Warn
        StopIteration
        Exit 1
    }
    $Global:CurrentCatalogCount = 1
    $Global:TotalCatalogSuccessCount = 0
    $Global:TotalCatalogFailureCount = 0

    if ($ctx_SiteConfigJSON) {
        #JSON
        $CatalogCount = $CitrixConfig.Catalog.Count
        Write-Log -Message "[Citrix Catalog] There are $($CatalogCount) Catalogs to Process" -Level Info
        foreach ($_ in $CitrixConfig) {
            # Set details
            $Catalog = $_.Catalog
            $DDC = $_.Controller

            Invoke-ProcessCitrixCatalogUpdate -DDC $DDC -Catalog $Catalog -Image $pe_snapshot_name -EncodedAdminCredential $EncodedAdminCredential
        }
    }
    else {
        #NO JSON
        $Catalogs = $ctx_Catalogs # This was set in the validation phase, but resetting here for ease of reading
        $DDC = $ctx_AdminAddress # This was set in the validation phase, but resetting here for ease of reading
        $CatalogCount = $Catalogs.Count

        Write-Log -Message "[Citrix Catalog] There are $($CatalogCount) Catalogs to Process" -Level Info
        foreach ($Catalog in $Catalogs) {
            Invoke-ProcessCitrixCatalogUpdate -DDC $DDC -Catalog $Catalog -Image $pe_snapshot_name -EncodedAdminCredential $EncodedAdminCredential
        }
    }
    Write-Log -Message "[Citrix Catalog] Successfully processed $($TotalCatalogSuccessCount) Catalogs" -Level Info
    if ($TotalCatalogFailureCount -gt 0) {
        Write-Log "[Citrix Catalog] Failed to processed $($TotalCatalogFailureCount) Catalogs" -Level Warn
    }
}
#endregion Process Citrix Environment

#endregion Execute

StopIteration
Exit 0