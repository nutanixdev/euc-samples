<#
.SYNOPSIS
    The script is designed to automate the VM restore and snapshot creation of a Citrix Base Image across multiple Nutanix clusters based on Protection Policy and Recovery Point methodology driven by Prism Centra and optionally update Citrix Catalogs.
.DESCRIPTION
    The script will query a single Prism Central instance of which your Citrix Base Image should be a member of. 
    It will query the specified protection domain and figure out the latest recovery point available across all clusers.
    It will restore a temporary VM on each target cluster defined in the Protection Policy via PC based Recovery Point restoration
    It will connect into each cluster defined under the Protection Policy via Prism Element APIs and create a snapshot of the recovered VM leaving a Citrix ready snapshot for MCS provisioning.
    The script will handle deletion of existing snapshots based on a retention period (effectively a cleanup mode). This is a destructive operation.
    The script assumes that your Protection Policy configurations are setup correctly. It does not alter, modify, create or delete any form of Protection Policy configuration.
    The script by default attempts to use the latest Recovery Point in the Protection Policy.
    The script has optional processing to allow automated Citrix Catalogs across one or many Citrix sites.
.PARAMETER LogPath
    Logpath output for all operations
.PARAMETER LogRollover
    Number of days before logfiles are rolled over. Default is 5.
.PARAMETER pc_source
    Mandatory. The Prism Central Source to target.
.PARAMETER BaseVM
    Mandatory. The name of the Citrix base image VM. This is CASE SENSITIVE.
.PARAMETER ProtectionPolicyName
    Mandatory. The name of the Protection Policy holding the BaseVM
.PARAMETER RecoveryPoint
    Optional. The name of a specific Recovery Point to target. This is an advanced parameter only.
.PARAMETER VMPrefix
    Optional. The prefix used for both the restored VM (temp) and the associated Snapshot. The default is ctx_
.PARAMETER ImageSnapsToRetain
    Optional. The number of snapshots to retain on each target Cluster. This is limited only to snaps meeting the BaseVM and VMPrefix naming patterns (Snapshots the script created).
.PARAMETER SleepTime
    Optional. Sleep time operations between task status polling in both v2 and v3 functions. The default is 2 seconds.
.PARAMETER UseCustomCredentialFile
    Optional. Will call the Get-CustomCredentials function which keeps outputs and inputs a secure credential file base on Stephane Bourdeaud from Nutanix functions
.PARAMETER CredPath
    Optional. Used if using the UseCustomCredentialFile parameter. Defines the location of the credential file. The default is "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
.PARAMETER ctx_Catalogs
    Optional. A list of Citrix Catalogs to update after the Snapshot replication has finished. User running the script must have sufficient rights on the Citrix Site. Single Citrix Site parameter only. For multi-site, use ctx_siteConfigJSON switch.
.PARAMETER ctx_AdminAddress
    Optional. The Delivery Controller to target for Citrix Catalog updates. Single Citrix Site parameter only. For multi-site, use ctx_siteConfigJSON switch.
.PARAMETER ctx_SiteConfigJSON
    Optional. A JSON file containing a list of Catalogs and associated Delivery Controllers for a multi-site environment. This will override the ctx_AdminAddress and ctx_Catalogs parameters
    JSON file must be defined using the following element layout: 
    [
        {
        "Catalog": "Catalog1",
        "Controller": "ctxddc001"
        },
        }
        "Catalog": "Catalog2",
        "Controller": "ctxddc002"
        }
    ]
.PARAMETER ctx_ProcessCitrixEnvironmentOnly
    Optional. Switch parameter to indicate that we are purely updating Citrix Catalogs and not interacting with Nutanix. Used in a scenario where maybe some remediation work as been undertaken and only Citrix needs updating. Advanced Parameter for specific used cases. 
.PARAMETER ctx_Snapshot
    Optional. The name of the snapshot to be used with the ctx_ProcessCitrixEnvironmentOnly switch. This has no validation against Nutanix. Purely used to bring Citrix catalogs into line.
.PARAMETER APICallVerboseLogging
    Optional. Switch to enable logging output for API calls
.EXAMPLE
    .\ReplicateCitrixBaseImageRP.ps1 -pc_source "1.1.1.1" -ProtectionPolicyName "Citrix-Image-Replication" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10 -UseCustomCredentialFile
    Will connect to the Prism Central 1.1.1.1 and look for the Protection Policy named Citrix-Image-Replication and ensures that it holds member CTX-Gold-01
    Will use a custom credential file. If it doesn't exist, it will be prompted for and used next time
    Will retain the last 10 snapshots matching the naming conditions in the script
.EXAMPLE
    .\ReplicateCitrixBaseImageRP.ps1 -pc_source "1.1.1.1" -ProtectionPolicyName "Citrix-Image-Replication" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10 -UseCustomCredentialFile -ctx_SiteConfigJSON "C:\temp\ctx_catalogs.json"
    Will connect to the Prism Central 1.1.1.1 and look for the Protection Policy named Citrix-Image-Replication and ensures that it holds member CTX-Gold-01
    Will use a custom credential file. If it doesn't exist, it will be prompted for and used next time
    Will retain the last 10 snapshots matching the naming conditions in the script
    Will update the Citrix environment based on the ctx_catalogs.json file
.NOTES
    #--------------------------------------------------------------------------------------------------------#
    # Authors and release:
    #--------------------------------------------------------------------------------------------------------#
    # This script is provided as-is to outline capability and methodology for achieving the defined goals.
    # James Kindon - Senior Solutions Architect, EUC - Nutanix
    # 13.06.2023: Initial release
    #--------------------------------------------------------------------------------------------------------#
    ToDo
    - Test against multiple Availability Zone configurations?
 #>

#region Params
# ============================================================================
# Parameters
# ============================================================================
Param(
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\MCSReplicateBaseImagePP.log", # Where we log to

    [Parameter(Mandatory = $false)]
    [int]$LogRollover = 5, # Number of days before logfile rollover occurs

    [Parameter(Mandatory = $true)]
    [string]$pc_source, # The Prism Central Instance hosting the Source VM and associated Protection Policy

    [Parameter(Mandatory = $true)]
    [string]$BaseVM, # The VM entity name of the base VM

    [Parameter(Mandatory = $true)]
    [string]$ProtectionPolicyName, # The name of the protection policy hosting the Base VM

    [Parameter(Mandatory = $false)]
    [string]$RecoveryPoint, # The name of the Recovery Point targeted

    [Parameter(Mandatory = $false)]
    [string]$VMPrefix = "ctx_", # The prefix name to create for the restored entity and the created snapshots

    [Parameter(Mandatory = $false)]
    [int]$ImageSnapsToRetain, # The number of snapshots to retain. Effectively a cleanup mode

    [Parameter(Mandatory = $false)]
    [int]$SleepTime = 2, # Sleep time operations between task status polling in both v2 and v3 functions

    [Parameter(Mandatory = $false)]
    [switch]$UseCustomCredentialFile, # specifies that a credential file should be used

    [Parameter(Mandatory = $false)]
    [String]$CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials", # Default path for custom credential file

    [Parameter(Mandatory = $false)]
    [Array]$ctx_Catalogs, # Array of catalogs on a single Citrix site to process. If needing to update multiple sites, use the JSON input

    [Parameter(Mandatory = $false)]
    [String]$ctx_AdminAddress, # Delivery Controller address on a single Citrix site to process. If needing to update multiple sites, use the JSON input

    [Parameter(Mandatory = $false)]
    [String]$ctx_SiteConfigJSON, # JSON input file for multi site (or single site) Citrix site configurations. Catalogs and Delivery Controllers

    [Parameter(Mandatory = $false)]
    [switch]$ctx_ProcessCitrixEnvironmentOnly, # Defines that we are processing ONLY citrix environments and not Nutanix

    [Parameter(Mandatory = $false)]
    [String]$ctx_Snapshot, # the snapshot to be used to update Citrix Catalogs. Used in conjunction with ctx_ProcessCitrixEnvironmentOnly

    [Parameter(Mandatory = $false)]
    [switch]$APICallVerboseLogging # Show the API calls being made
)
#endregion

#region Functions
# ============================================================================
# Functions
# ============================================================================
function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [Alias('LogPath')]
        [string]$Path = $LogPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warn", "Info")]
        [string]$Level = "Info",
        
        [Parameter(Mandatory = $false)]
        [switch]$NoClobber
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
                Write-Error $Message
                $LevelText = 'ERROR:'
            }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
            }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
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
    end
    {}
} #this function is used to create saved credentials for the current user

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
} #this function is used to retrieve saved credentials for the current user

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
} #this function is used to make sure we use the proper Tls version (1.2 only required for connection to Prism)

function InvokePrismAPI {
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
    BEGIN {}
    PROCESS {
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
            Throw "$(get-date) [ERROR] $saved_error"
        }
        finally {
            #add any last words here; this gets processed no matter what
        }
    }
    END {
        return $resp
    }
}

function GetPrismv2Task {
    param (
        [parameter(mandatory = $true)]
        [string]$TaskID, #ID of the task to grab

        [parameter(mandatory = $true)]
        [string]$Cluster,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $Method = "GET"
    $RequestUri = "https://$($Cluster):9440/PrismGateway/services/rest/v2.0/tasks/$($TaskId)"
    $Payload = $null
    try {
        $TaskStatus = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $Credential -ErrorAction Stop
        Write-Log -Message "$($Phase) Monitoring task: $($TaskId)"
        while ($TaskStatus.progress_status -ne "SUCCEEDED") {
            Write-Log -Message "$($Phase) Task Status is: $($TaskStatus.progress_status). Waiting for Task completion. Status: $($TaskStatus.percentage_complete)% complete" -Level Info
            Start-Sleep $SleepTime
            $TaskStatus = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $Credential -ErrorAction Stop
        }
        if ($TaskStatus.progress_status -eq "SUCCEEDED") {
            Write-Log -Message "$($Phase) Task status is: $($TaskStatus.progress_status). $PhaseSuccessMessage" -Level Info
        }
    }
    catch {
        Write-Log -Message "$($Phase) Failed to get task status for task ID: $($TaskId)" -Level Warn
        Break
    }     
}

function GetPrismv3Task {
    param (
        [parameter(mandatory = $true)]
        [string]$TaskID, #ID of the task to grab

        [parameter(mandatory = $true)]
        [string]$Cluster,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $Method = "GET"
    $RequestUri = "https://$($Cluster):9440/api/nutanix/v3/tasks/$($TaskId)"
    $Payload = $null
    try {
        $TaskStatus = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $Credential -ErrorAction Stop
        Write-Log -Message "$($Phase) Monitoring task: $($TaskId)"
        while ($TaskStatus.Status -ne "SUCCEEDED") {
            if ($TaskStatus.Status -eq "FAILED") {
                Write-Log -Message "$($Phase) Task Status is: $($TaskStatus.Status)" -Level Warn
                Write-Log -Message "$($TaskStatus.error_detail)" -Level Warn
                Break
            }
            Write-Log -Message "$($Phase) Task Status is: $($TaskStatus.Status). Waiting for Task Completion. Status: $($TaskStatus.percentage_complete)% complete" -Level Info
            Start-Sleep $SleepTime
            $TaskStatus = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $Credential -ErrorAction Stop
        }
        if ($TaskStatus.Status -eq "SUCCEEDED") {
            Write-Log -Message "$($Phase) Task Status is: $($TaskStatus.Status). $PhaseSuccessMessage" -Level Info
        }
    }
    catch {
        Write-Log -Message "$($Phase) Failed to get task status for task ID: $($TaskId)" -Level Warn
        Break
    }     
}

function ValidateCitrixController {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AdminAddress
    )

    try {
        Write-Log -Message "[Citrix Validation] Validating Citrix Site is contactable at Delivery Controller: $($AdminAddress)" -Level Info
        $Site = Get-BrokerSite -AdminAddress $AdminAddress -ErrorAction Stop
        Write-Log -Message "[Citrix Validation] Successfully Validated Citrix Site: $($Site.Name) is contactable at Delivery Controller: $($AdminAddress)" -Level Info
    }
    catch {
        Write-Log -Message "[Citrix Validation] Failed to validate Citrix Delivery Controller: $($AdminAddress)" -Level Warn
        Write-Host $_
        StopIteration
        Exit 1
    }
}

function ValidateCitrixCatalog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Catalog,
        [Parameter(Mandatory = $true)]
        [string]$AdminAddress
    )

    Write-Log -Message "[Citrix Validation] Validating Catalog $($CurrentCatalogCount) of $($CatalogCount)" -Level Info
    Write-Log -Message "[Citrix Validation] Validating Catalog $($Catalog) exists on Delivery Controller: $($AdminAddress)" -Level Info
    try {
        $CatalogDetail = Get-BrokerCatalog -Name $Catalog -AdminAddress $AdminAddress -ErrorAction Stop
        Write-Log -Message "[Citrix Validation] Successfully validated Catalog $($Catalog) exists on Delivery Controller: $($AdminAddress)" -Level Info
        if ($CatalogDetail.ProvisioningType -ne "MCS") {
            Write-Log -Message "[Citrix Validation] Catalog is of provisioning type $($CatalogDetail.ProvisioningType) and cannot be used on Delivery Controller: $($AdminAddress)" -Level Warn
            $Global:TotalCatalogFailureCount += 1
            Break # update the fail count, but this is validation so we want to know all failures before killing script
        }
    }
    catch {
        Write-Log -Message "[Citrix Validation] Failed to validate Citrix Catalog $($Catalog) on Delivery Controller: $($AdminAddress)" -Level Warn
        Write-Log -Message $_ -Level Warn
        $Global:TotalCatalogFailureCount += 1
        Break # update the fail count, but this is validation so we want to know all failures before killing script
    }

    $Global:CurrentCatalogCount += 1
    $Global:TotalCatalogSuccessCount += 1
}

function ProcessCitrixCatalog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Catalog,
        [Parameter(Mandatory = $true)]
        [string]$AdminAddress,
        [Parameter(Mandatory = $true)]
        [string]$snapshotName
    )
    Write-Log -Message "[Citrix Catalog] Processing Catalog $($CurrentCatalogCount) of $($CatalogCount)" -Level Info
    #Get the ProvScheme for the catalog
    try {
        Write-Log -Message "[Citrix Catalog] Getting Catalog and Prov Scheme details for Catalog: $($Catalog) on Delivery Controller: $($AdminAddress)" -Level Info
        $CatalogDetail = Get-BrokerCatalog -Name $Catalog -AdminAddress $AdminAddress -ErrorAction Stop
        $ProveSchemeID = $CatalogDetail.ProvisioningSchemeId
        $ProvScheme = Get-ProvScheme -ProvisioningSchemeUid $ProveSchemeID -AdminAddress $AdminAddress -ErrorAction Stop
        Write-Log -Message "[Citrix Catalog] Successfully retrieved details for Catalog: $($Catalog) on Delivery Controller: $($AdminAddress)" -Level Info
    }
    catch {
       Write-Log -Message "[Citrix Catalog] Failed to retrieve details for Catalog: $($Catalog) on Delivery Controller: $($AdminAddress)" -Level Warn
       Write-Host $_
       $Global:TotalCatalogFailureCount += 1
       Break
    }
    
    # Prepare the updates Master Image VM reference
    Write-Log -Message "[Citrix Image] Setting Image details for catalog: $($Catalog) on Delivery Controller: $($AdminAddress)" -Level Info
    $CurrentImage = $ProvScheme.MasterImageVM
    $pattern = "(?<=\\)([^\\]+)(?=\.template)"
    $NewImage = $CurrentImage -replace $pattern,$snapshotName
    Write-Log -Message "[Citrix Image] Current Catalog Image for Catalog: $($Catalog) is: $($CurrentImage)" -Level Info
    Write-Log -Message "[Citrix Image] New Catalog Image for Catalog: $($Catalog) will be: $($NewImage)" -Level Info

    #Start the update process
    try {
        Write-Log -Message "[Citrix Catalog] Starting Catalog update process for Catalog: $($Catalog) on Delivery Controller: $($AdminAddress)" -Level Info

        $PublishTask = Publish-ProvMasterVMImage -ProvisioningSchemeName $ProvScheme.ProvisioningSchemeName -MasterImageVM $NewImage -AdminAddress $AdminAddress -RunAsynchronously -ErrorAction Stop
        $ProvTask = Get-ProvTask -TaskId $PublishTask -AdminAddress $AdminAddress -ErrorAction Stop

        ## Track progress of the image update
        Write-Log -Message "[Citrix Catalog] Tracking progress of the Catalog update task. Catalog update for: $($Catalog) started at: $($ProvTask.DateStarted) on Delivery Controller: $($AdminAddress)" -Level Info
        $totalPercent = 0
        While ( $ProvTask.Active -eq $True ) {
            Try { $totalPercent = If ( $ProvTask.TaskProgress ) { $ProvTask.TaskProgress } Else { 0 } } Catch { }

            Write-Log -Message "[Citrix Catalog] Provisioning image update current operation: $($ProvTask.CurrentOperation) on Provisioning Scheme: $($ProvScheme.ProvisioningSchemeName) is $($totalPercent)% Complete. Last Update Time is: $($ProvTask.LastUpdateTime) on Delivery Controller: $($AdminAddress)" -Level Info
            Start-Sleep 15
            $ProvTask = Get-ProvTask -TaskId $PublishTask -AdminAddress $AdminAddress -ErrorAction Stop
        }
    }
    catch {
        Write-Log -Message "[Citrix Catalog] Failed to start the update process on catalog: $($Catalog) on Delivery Controller: $($AdminAddress)" -Level Warn
        Write-Log -Message $_ -Level Warn
        $Global:TotalCatalogFailureCount += 1
        Break
    }

    Write-Log -Message "[Citrix Catalog] Catalog Update for catalog: $($Catalog) completed at $($ProvTask.DateFinished) with an Active time of $($ProvTask.ActiveElapsedTime) seconds on Delivery Controller: $($AdminAddress)" -Level Info
    $Global:CurrentCatalogCount += 1
    $Global:TotalCatalogSuccessCount += 1
}

function ValidateExclusiveCitrixProcessingCatalog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Catalog,
        [Parameter(Mandatory = $true)]
        [string]$AdminAddress,
        [Parameter(Mandatory = $true)]
        [string]$SnapshotName
    )
    Write-Log -Message "[Citrix Validation] Validating image for Catalog $($CurrentCatalogCount) of $($CatalogCount)" -Level Info
    try {
        $CatalogDetail = Get-BrokerCatalog -Name $Catalog -AdminAddress $AdminAddress -ErrorAction Stop
        $ProveSchemeID = $CatalogDetail.ProvisioningSchemeId
        $ProvScheme = Get-ProvScheme -ProvisioningSchemeUid $ProveSchemeID -AdminAddress $AdminAddress -ErrorAction Stop
        $CurrentImage = $ProvScheme.MasterImageVM
        if ($CurrentImage -Like "*$ctx_Snapshot*") {
            Write-Log -Message "[Citrix Validation] Catalog is already using image: $($ctx_Snapshot). No need to process" -Level Info
            $CurrentCatalogCount += 1
        }
        else {
            Write-Log -Message "[Citrix Validation] Catalog is using $($CurrentImage). Will be processed." -Level Info
            $pattern = "(?<=\\)([^\\]+)(?=\.template)"
            $NewImage = $CurrentImage -replace $pattern,$ctx_Snapshot
            Write-Log -Message "[Citrix Image] Current Catalog Image for Catalog: $($Catalog) is: $($CurrentImage)" -Level Info
            Write-Log -Message "[Citrix Image] New Catalog Image for Catalog: $($Catalog) will be: $($NewImage)" -Level Info

            #start the update process
            try {
                Write-Log -Message "[Citrix Catalog] Starting Catalog update process for Catalog: $($Catalog) on Delivery Controller: $($AdminAddress)" -Level Info
        
                $PublishTask = Publish-ProvMasterVMImage -ProvisioningSchemeName $ProvScheme.ProvisioningSchemeName -MasterImageVM $NewImage -AdminAddress $AdminAddress -RunAsynchronously -ErrorAction Stop
                $ProvTask = Get-ProvTask -TaskId $PublishTask -AdminAddress $AdminAddress -ErrorAction Stop
        
                ## Track progress of the image update
                Write-Log -Message "[Citrix Catalog] Tracking progress of the Catalog update task. Catalog update for: $($Catalog) started at: $($ProvTask.DateStarted) on Delivery Controller: $($AdminAddress)" -Level Info
                $totalPercent = 0
                While ( $ProvTask.Active -eq $True ) {
                    Try { $totalPercent = If ( $ProvTask.TaskProgress ) { $ProvTask.TaskProgress } Else { 0 } } Catch { }
        
                    Write-Log -Message "[Citrix Catalog] Provisioning image update current operation: $($ProvTask.CurrentOperation) on Provisioning Scheme: $($ProvScheme.ProvisioningSchemeName) is $($totalPercent)% Complete. Last Update Time is: $($ProvTask.LastUpdateTime) on Delivery Controller: $($AdminAddress)" -Level Info
                    $ProvTask = Get-ProvTask -TaskId $PublishTask -AdminAddress $AdminAddress -ErrorAction Stop
                }
            }
            catch {
                Write-Log -Message "[Citrix Catalog] Failed to start the update process on catalog: $($Catalog) on Delivery Controller: $($AdminAddress)" -Level Warn
                Write-Log -Message $_ -Level Warn
                $Global:TotalCatalogFailureCount += 1
                Break
            }
        
            Write-Log -Message "[Citrix Catalog] Catalog Update for catalog: $($Catalog) completed at $($ProvTask.DateFinished) with an Active time of $($ProvTask.ActiveElapsedTime) seconds on Delivery Controller: $($AdminAddress)" -Level Info
            $Global:CurrentCatalogCount += 1
            $Global:TotalCatalogSuccessCount += 1

            $CurrentCatalogCount += 1
        }
    }
    catch {
        Write-Log -Message "[Citrix Validation] Failed to validate Citrix Image for Catalog $($Catalog) on Delivery Controller: $($AdminAddress)" -Level Warn
        Write-Log -Message $_ -Level Warn
        $Global:TotalCatalogFailureCount += 1
    }
}

#endregion

#region Variables
# ============================================================================
# Variables
# ============================================================================
$RunDate = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -replace ":","-" -replace " ","-" # We want all snapshots across all clusters to have the same timestamp
#endregion

#Region Execute
# ============================================================================
# Execute
# ============================================================================
StartIteration

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) { throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)" }

#region Modules

#------------------------------------------------------------
# Import Citrix Snapins
#------------------------------------------------------------
if ($ctx_Catalogs -or $ctx_SiteConfigJSON) {
    if ($PSVersionTable.PSedition -eq "Core") { throw "$(get-date) You cannot use snapins with PowerShell Core. You must use PowerShell 5.x" }
    try {
        Write-Log -Message "[Citrix PowerShell] Attempting to import Citrix PowerShell Snapins" -Level Info
        Add-PSSnapin -Name "Citrix.Broker.Admin.V2","Citrix.Host.Admin.V2" -ErrorAction Stop
        Get-PSSnapin Citrix* -ErrorAction Stop | out-null
        Write-Log -Message "[Citrix PowerShell] Successfully imported Citrix PowerShell Snapins" -Level Info
    }
    catch {
        Write-Log -Message "[Citrix PowerShell] Failed to import Citrix PowerShell Module" -Level Warn
        Write-Log -Message $_ -Level Warn
        StopIteration
        Exit 1
    }
}
#endregion Modules

#region Exclusive Citrix Processing Validation
if ($ctx_ProcessCitrixEnvironmentOnly.IsPresent) {
    Write-Log -Message "Exclusive Citrix environment processing enabled" -Level Info
    if (!$ctx_Snapshot) {
        Write-Log -Message "You must define a snapshot when using exlusive Citrix processing" -Level Warn
        StopIteration
        Exit 1
    }
    Write-Log -Message "Custom Snapshot defined: $($ctx_Snapshot)" -Level Warn
}
#endregion Exclusive Citrix Processing Validation

#region Validate Citrix Environment
if ($ctx_Catalogs -or $ctx_SiteConfigJSON) {
    # Citrix mode has been enabled by either specifying a list of Catalogs or a JSON input file
    Write-Log -Message "[Citrix Processing] Citrix Processing Mode is enabled" -Level Info
    if ($ctx_Catalogs -and !$ctx_AdminAddress) {
        Write-Log -Message "You must define a Delivery Controller to Process Citrix Catalogs" -Level Warn
        StopIteration
        Exit 1
    }
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
        foreach ($AdminAddress in $UniqeControllers) {
            ValidateCitrixController -AdminAddress $AdminAddress
        }

        # Process the Catalog list from JSON input
        Write-Log -Message "[Citrix Validation] There are $($CitrixConfig.Catalog.Count) Catalogs to validate" -Level Info
        $CatalogCount = $CitrixConfig.Catalog.Count
        foreach ($_ in $CitrixConfig) {
            # Set details
            $Catalog = $_.Catalog
            $AdminAddress = $_.Controller

            ValidateCitrixCatalog -Catalog $Catalog -AdminAddress $AdminAddress
        }
    }
    else {
        #NO JSON
        $Catalogs = $ctx_Catalogs
        $AdminAddress = $ctx_AdminAddress

        # Test access to the defined controller
        ValidateCitrixController -AdminAddress $AdminAddress

        Write-Log -Message "[Citrix Validation] There are $($Catalogs.Count) Catalogs to Validate" -Level Info
        $CatalogCount = $Catalogs.Count
        foreach ($Catalog in $Catalogs) {
            ValidateCitrixCatalog -Catalog $Catalog -AdminAddress $AdminAddress
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

#region SSL Handling
#------------------------------------------------------------
# Handle Invalid Certs
#------------------------------------------------------------
if ($PSEdition -eq 'Desktop') {
Write-Log -Message "[SSL] Ignoring invalid certificates" -Level Info
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
    $certCallback = @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class ServerCertificateValidationCallback
{
public static void Ignore()
{
    if(ServicePointManager.ServerCertificateValidationCallback ==null)
    {
        ServicePointManager.ServerCertificateValidationCallback += 
            delegate
            (
                Object obj, 
                X509Certificate certificate, 
                X509Chain chain, 
                SslPolicyErrors errors
            )
            {
                return true;
            };
    }
}
}
"@
    Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()
}

Set-PoshTls
#endregion SSL Handling

#region Authentication
#------------------------------------------------------------
# Handle Authentication
#------------------------------------------------------------
if ($UseCustomCredentialFile.IsPresent) {
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
}
else {
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
#endregion Authentication

#region Exclusive Citrix Processing
if ($ctx_ProcessCitrixEnvironmentOnly) {
    $Global:CurrentCatalogCount = 1
    $Global:TotalCatalogSuccessCount = 0
    $Global:TotalCatalogFailureCount = 0

    if ($ctx_SiteConfigJSON) {
        #JSON
        $CatalogCount = $CitrixConfig.Catalog.Count
        Write-Log -Message "[Citrix Validation] There are $($CitrixConfig.Catalog.Count) Catalogs to Process" -Level Info
        foreach ($_ in $CitrixConfig) {
            # Set details
            $Catalog = $_.Catalog
            $AdminAddress = $_.Controller

            ValidateExclusiveCitrixProcessingCatalog -Catalog $Catalog -AdminAddress $AdminAddress -SnapshotName $ctx_Snapshot
        }
    }
    else {
        #NO JSON
        $Catalogs = $ctx_Catalogs # This was set in the validation phase, but resetting here for ease of reading
        $AdminAddress = $ctx_AdminAddress # This was set in the validation phase, but resetting here for ease of reading
        $CatalogCount = $Catalogs.Count
        Write-Log -Message "[Citrix Validation] There are $($Catalogs.Count) Catalogs to Process" -Level Info
        foreach ($Catalog in $Catalogs) {
            ValidateExclusiveCitrixProcessingCatalog -Catalog $Catalog -AdminAddress $AdminAddress -SnapshotName $ctx_Snapshot
        }
    }

    Write-Log -Message "[Citrix Validation] Exclusive Citrix processing complete" -Level Info
    Write-Log -Message "[Citrix Validation] Successfully Processed $($TotalCatalogSuccessCount) Catalogs" -Level Info
    if ($TotalCatalogFailureCount -gt 0) {
        Write-Log -Message "[Citrix Validation] Failed to process $($TotalCatalogFailureCount) Catalogs" -Level Warn
    }

    StopIteration
    Exit 0
}
#endregion Exclusive Citrix Processing

#------------------------------------------------------------
# Initialise counts and variables
#------------------------------------------------------------
$TotalErrorCount = 0 # start the error count
$TotalSuccessCount = 0 # start the succes count

#region Query Prism Central
#------------------------------------------------------------
# Query Prism Central via V3 API
#------------------------------------------------------------
#region get Clusters
#---------------------------------------------
# Get a list of managed clusters under the PC
#---------------------------------------------
Write-Log -Message "[Prism Central] Quering for Clusters under the Prism Central Instance $($pc_source)" -Level Info
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "POST"
$RequestUri = "https://$($pc_source):9440/api/nutanix/v3/clusters/list"
$PayloadContent = @{
    kind = "cluster"
}
$Payload = (ConvertTo-Json $PayloadContent)
#----------------------------------------------------------------------------------------------------------------------------
try {
    $TotalClusters = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
}
catch {
    Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc_source)" -Level Warn
    Write-Log $_ -Level Warn
    StopIteration
    Exit 1
}

$Clusters = $TotalClusters.entities | Where-Object {$_.status.name -ne "Unnamed"}
Write-Log -Message "[Cluster] There are $($Clusters.Count) Clusters under the Prism Central Instance $($pc_source)" -Level Info

foreach ($_ in $Clusters) {
    $cluster_name = $_.status.name
    $cluster_uuid = $_.metadata.uuid
    $cluster_external_ip = $_.status.resources.network.external_ip

    Write-Log -Message "[Cluster] Cluster: $($cluster_name) has uuid: $cluster_uuid and external IP: $($cluster_external_ip)" -Level Info
}
#endregion get Clusters

#region get Availability Zones
#------------------------------------------
# Get Availability Zones
#------------------------------------------
Write-Log -Message "[Prism Central] Quering for Avaliability Zones under the Prism Central Instance $($pc_source)" -Level Info
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "POST"
$RequestUri = "https://$($pc_source):9440/api/nutanix/v3/availability_zones/list"
$PayloadContent = @{
    kind = "availability_zone"
}
$Payload = (ConvertTo-Json $PayloadContent)
#----------------------------------------------------------------------------------------------------------------------------
try {
    $AvailabilityZones = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
    Write-Log -Message "[Availability Zones] There are $($AvailabilityZones.entities.Count) Avaliability Zones under the Prism Central Instance $($pc_source)" -level Info
}
catch {
    Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc_source)" -Level Warn
    Write-Log $_ -Level Warn
    StopIteration
    Exit 1
}

foreach ($_ in $AvailabilityZones.entities) {
    $az_name = $_.status.name
    $az_uid = $_.status.uuid
    Write-Log -Message "[Availability Zones] Availability Zone: $($az_name) has uuid: $az_uid" -level Info
}
#endregion get Availability Zones

#region get the Source VM
#---------------------------------------------
# Get the Source VM
#---------------------------------------------
Write-Log -Message "[Prism Central] Quering for Virtual Machines under the Prism Central Instance $($pc_source)" -Level Info
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "POST"
$RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/list"
$PayloadContent = @{
    kind = "vm"
    filter = "vm_name==$BaseVM"
    length = 10000
}
$Payload = (ConvertTo-Json $PayloadContent)
#----------------------------------------------------------------------------------------------------------------------------
try {
    $VirtualMachines = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
}
catch {
    Write-Log -Message "[Prism Central] Could not retrieve virtual machines under the Prism Central Instance $($pc_source)" -level Warn
    Write-Log $_ -Level Warn
    StopIteration
    Exit 1
}

if ($virtualmachines.entities.count -eq 0) {
    Write-Log -Message "[VM] There are no virtual machines under the Prism Central Instance $($pc_source)" -Level Warn
    StopIteration
    Exit 1
}

# Filter to find the source VM we need
$source_vm = $VirtualMachines.entities
if (!$source_vm) {
    Write-Log -Message "[VM] The specified virtual machine $($BaseVM) was not found under the the Prism Central Instance $($pc_source)" -Level Warn
    StopIteration
    Exit 1
}
else {
    $source_vm_name = $source_vm.status.name
    $source_vm_uuid = $source_vm.metadata.uuid
    Write-Log -Message "[VM] UUID of VM $($source_vm_name) is $($source_vm_uuid)" -Level Info
}

#endregion get the Source VM

#region get Protection Policy Details
#---------------------------------------------
# Get the Protection Policy Details
#---------------------------------------------
Write-Log -Message "[Prism Central] Quering for Protection Policies under the Prism Central Instance $($pc_source)" -Level Info
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "POST"
$RequestUri = "https://$($pc_source):9440/api/nutanix/v3/protection_rules/list"
$PayloadContent = @{
    kind = "protection_rule"
}
$Payload = (ConvertTo-Json $PayloadContent)
#----------------------------------------------------------------------------------------------------------------------------
try {
    $ProtectionRules = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
}
catch {
    Write-Log -Message "[Prism Central] Could not retrieve Protection Policies under the Prism Central Instance $($pc_source)" -level Warn
    Write-Log $_ -Level Warn
    StopIteration
    Exit 1
}

Write-Log -Message "[Protection Policy] Retrieved $($ProtectionRules.Count) Protection Policies under the Prism Central Instance $($pc_source). Filtering for $($ProtectionPolicyName)" -level Info
$ProtectionRule = $ProtectionRules.entities | Where-Object {$_.status.name -eq "$ProtectionPolicyName"}

if ($ProtectionRule) {
    Write-Log -Message "[Protection Policy] Found Protection Policy: $($ProtectionPolicyName) under the Prism Central Instance $($PC_Source)" -level Info
    $ProtectionPolicyTargetClusterCount = ($ProtectionRule.status.resources.ordered_availability_zone_list.cluster_uuid).Count
    Write-Log -Message "[Protection Policy] There are $($ProtectionPolicyTargetClusterCount) Cluster Entities in the Protection Policy" -level Info
}
else {
    Write-Log -Message "[Protection Policy] Failed to find Protection Policy: $($ProtectionPolicyName) under the Prism Central Instance $($PC_Source)" -Level Warn
    StopIteration
    Exit 1
}

$ClustersInProtectionRule = $ProtectionRule.status.resources.ordered_availability_zone_list.cluster_uuid #set the included cluster details for cluster processing filtering later on
#endregion get Protection Policy Details

#region get and select recovery points
#---------------------------------------------
# Get the Recovery Points available 
#---------------------------------------------
Write-Log -Message "[Prism Central] Querying for Recovery Points under the Prism Central Instance $($pc_source)" -Level Info
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "POST"
$RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vm_recovery_points/list"
$PayloadContent = @{
    kind = "vm_recovery_point"
}
$Payload = (ConvertTo-Json $PayloadContent)
#----------------------------------------------------------------------------------------------------------------------------
try {
    $RecoveryPoints = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
}
catch {
    Write-Log -Message "[Prism Central] Could not retrieve Recovery Points under the Prism Central Instance $($pc_source)" -level Warn
    Write-Log $_ -Level Warn
    StopIteration
    Exit 1
}

Write-Log -Message "[Recovery Point] There are $($RecoveryPoints.entities.Count) Recovery Points under the Prism Central Instance $($pc_source)" -Level Info
$Target_RecoveryPoints = $RecoveryPoints.entities | Where-Object {$_.status.resources.parent_vm_reference.uuid -eq $source_vm_uuid}
if (!$Target_RecoveryPoints) {
    Write-Log -Message "[Recovery Point] There are no Recovery Points matching $($source_vm_name) with uuid: $($source_vm_uuid) under the Prism Central Instance $($pc_source)" -Level Warn
    StopIteration
    Exit 1
}
Write-Log -Message "[Recovery Point] There are $($target_recoverypoints.Count) Recovery Points matching $($source_vm_name) with uuid: $($source_vm_uuid) under the Prism Central Instance $($pc_source)" -Level Info

if ($RecoveryPoint) {
	# we specified a Recovery Point by name
    Write-Log -Message "[Recovery Point] Filtering Recovery Points based on custom input name: $($RecoveryPoint) time under the Prism Central Instance $($pc_source)" -Level Info
    $Target_RecoveryPoints = $Target_RecoveryPoints | Where-Object {$_.status.name -eq $RecoveryPoint}
}
else {
	#Get the latest by creation date
    Write-Log -Message "[Recovery Point] Filtering Recovery Points for the latest creation time under the Prism Central Instance $($pc_source)" -Level Info
    $LatestCreationDate = $Target_RecoveryPoints.status.resources.creation_time | Sort-Object creation_time | Select-Object -last 1
    #Match all RPs to that creation date and grab a count. Line this up against the entities in the Policy to make sure distribution has occured to all targets
    $Target_RecoveryPoints = $Target_RecoveryPoints | Where-Object {$_.status.resources.creation_time -match $LatestCreationDate}
}

if ($Target_RecoveryPoints.Count -eq $ProtectionPolicyTargetClusterCount) {
    Write-Log -Message "[Recovery Point] Recovery Point is on all target clusters under the Prism Central Instance $($pc_source)" -Level Info
} 
else {
    Write-Log -Message "[Recovery Point] Recovery Point is not on all target clusters. Present on $($target_recoverypoints.Count) of $($ProtectionPolicyTargetClusterCount) targets under the Prism Central Instance $($pc_source)" -Level Warn
    StopIteration
    Exit 1
}

$RecoveryPointTotalCount = $Target_RecoveryPoints.Count #total count for our looping operation below
$RecoveryPointActionCount = 1 #starting count for our loop operation below

foreach ($_ in $Target_RecoveryPoints) {
    Write-Log -Message "[Recovery Point Validation] Processing Recovery Cluster $($RecoveryPointActionCount) of $($RecoveryPointTotalCount)" -Level Info
    $uuid = $_.metadata.uuid
    $createtime = $_.metadata.creation_time

    #---------------------------------------------
    # Validate the ability to recover
    #---------------------------------------------
    Write-Log -Message "[Recovery Point Validation] Validating Recovery Point with ID: $($uuid) restoration capability" -Level Info
    $vm_RecoveryPointID = $uuid
    #----------------------------------------------------------------------------------------------------------------------------
    # Set API call detail
    #----------------------------------------------------------------------------------------------------------------------------
    $Method = "POST"
    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vm_recovery_points/$($vm_RecoveryPointID)/validate_restore"
    $PayloadContent = @{
        kind = "vm_recovery_point"
    }
    $Payload = (ConvertTo-Json $PayloadContent)
    #----------------------------------------------------------------------------------------------------------------------------
    # validation will only return data is there is a failure. Fail one, fail all. Exit on fail.
    $rp_RecoveryDetails = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
    if ($rp_RecoveryDetails) {
        Write-Log -Message "[Recovery Point Validation] Validation Errors have occured for VM Recovery Point: $($vm_RecoveryPointID) under the Prism Central Instance $($pc_source)" -Level Warn
        Write-Log -Message "$($rp_RecoveryDetails)" -Level Warn
        StopIteration
        Exit 1
    }
    else {
        Write-Log -Message "[Recovery Point Validation] No validation errors reported for VM Recovery Point: $($vm_RecoveryPointID) under the Prism Central Instance $($pc_source)" -Level Info
        $RecoveryPointActionCount += 1
    }
}
#endregion get and select recovery points

#region clone the recovery points
#---------------------------------------------
# Restore (clone) the Recovery Point to a VM in each Target Cluster
#---------------------------------------------
Write-Log -Message "[Prism Central] Restoring VMs on each cluster from the Recovery Point" -Level Info

$RecoveryPointTotalCount = $Target_RecoveryPoints.Count #total count for our looping operation below
$RecoveryPointActionCount = 1 #starting count for our loop operation below

$TempVMName = $VMPrefix + $BaseVM
Write-Log -Message "[Recovery Point Clone] Temp virtual machine name is $($TempVMName)"

$TempVMCreationDetails = @() # temp VM created uuid array
foreach ($_ in $Target_RecoveryPoints) {
    Write-Log -Message "[Recovery Point Clone] Processing Cluster $($RecoveryPointActionCount) of $($RecoveryPointTotalCount) under the Prism Central Instance $($pc_source)" -Level Info
    # Loop through the list of UIDs of the RP clone then recover the VM to the cluster. The recovery will be based on the RP location
    $vm_RecoveryPointID = $_.metadata.uuid
    #----------------------------------------------------------------------------------------------------------------------------
    # Set API call detail
    #----------------------------------------------------------------------------------------------------------------------------
    $Method = "POST"
    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vm_recovery_points/$($vm_RecoveryPointID)/restore"

    $PayloadContent = @{
        vm_override_spec = @{
            name = $TempVMName
        }
    }
    $Payload = (ConvertTo-Json $PayloadContent)
    #----------------------------------------------------------------------------------------------------------------------------
    try {
        Write-Log -Message "[Recovery Point Clone] Restoring Recovery Point to temporary Virtual Machine: $($TempVMName) under the Prism Central Instance $($pc_source)" -Level Info
        $VMCreated = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop

        #Get the status of the task above
        $TaskId = $VMCreated.task_uuid
        $Phase = "[Recovery Point Clone]"
        $PhaseSuccessMessage = "VM has been created"

        GetPrismv3Task -TaskID $TaskId -Cluster $pc_source -Credential $PrismCentralCredentials
    }
    catch {
        # Fail one fail all. Exit on fail
        Write-Log -Message "[Recovery Point Clone] Failed to restore Recovery Point to temporary Virtual Machine: $($TempVMName) under the Prism Central Instance $($pc_source)" -Level Warn
        StopIteration
        Exit 1
    }

    # Get machine creation details which will be matched in the target cluster loops in PE
    Write-Log -Message "[Recovery Point Clone] Capturing VM creation details from the Prism Central Instance $($pc_source)" -Level Info
    #----------------------------------------------------------------------------------------------------------------------------
    # Set API call detail
    #----------------------------------------------------------------------------------------------------------------------------
    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$TaskId"
    $Method = "GET"
    $Payload = $null # we are on a get run
    #----------------------------------------------------------------------------------------------------------------------------
    try {
        $TempVMCreationDetail = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        $TempVMCreationDetails += $TempVMCreationDetail.entity_reference_list.uuid # add per run after getting task    
    }
    catch {
        # Fail one fail all. Exit on fail
        Write-Log -Message "[Recovery Point Clone] Failed to capture virtual machine creation details from the Prism Central Instance $($pc_source)" -Level Warn
        StopIteration
        Exit 1
    }
    
    $RecoveryPointActionCount += 1
}
#endregion clone the recovery points

#endregion Query Prism Central

#region Prism Element Loops
#------------------------------------------------------------
# Query Prism Element via V2 API
#------------------------------------------------------------
$ClustersTotalCount = $Clusters.Count
$ClustersActionCount = 1
$SnapshotName = $VMPrefix + $BaseVM + "_" + $RunDate

foreach ($_ in $Clusters) {
    if ($_.metadata.uuid -notin $ClustersInProtectionRule) {
        Write-Log -Message "Cluster is listed under the Prism Central Instance $($pc_source) but is not included in the Protection Policy $($ProtectionPolicyName) so will not be processed" -Level Info
        Continue
    }
    $ClusterIP = $_.status.resources.network.external_ip
    $ClusterName = $_.status.name
    Write-Log -Message "[Target Cluster] Processing Cluster $($ClustersActionCount) of $($ClustersTotalCount): $($ClusterName)" -Level Info

    #region Get VM
    #---------------------------------------------
    # Get the VM in PE 
    #---------------------------------------------
    Write-Log -Message "[Target Cluster] retrieving virtual machine entities for the target cluster: $($ClusterName)" -Level Info
    #----------------------------------------------------------------------------------------------------------------------------
    # Set API call detail
    #----------------------------------------------------------------------------------------------------------------------------
    $Method = "GET"
    $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/vms"
    $Payload = $null # we are on a GET run
    #----------------------------------------------------------------------------------------------------------------------------
    try {
        $VirtualMachines = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop
    }
    catch {
        Write-Log -Message "[Target Cluster] Failed to retrieve virtual machines from the target cluster: $($ClusterName)" -Level Warn
        $TotalErrorCount += 1
        Continue
    }

    Write-Log -Message "[VM] There are $($VirtualMachines.entities.Count) virtual machines on the target cluster: $($ClusterName)" -Level Info

    $TempVMDetail = $VirtualMachines.entities | where-Object {$_.uuid -in $TempVMCreationDetails}
    if ($TempVMDetail) {
        Write-Log -Message "Found virtual machine $($TempVMDetail.name) on the target cluster: $($ClusterName)" -Level Info
        $vm_uuid = $TempVMDetail.uuid
        $vm_name = $TempVMDetail.name
    }
    else {
        Write-Log -Message "[VM] Failed to retrieve virtual machines on the target cluster: $($ClusterName)" -Level Warn
        $TotalErrorCount += 1
        Continue
    }

    #endregion Get VM

    #region create Snapshot
    #---------------------------------------------
    # Create a Snapshot of the VM from the temp VM
    #---------------------------------------------
    Write-Log -Message "[VM Snapshot] Creating Snapshot on the target cluster: $($ClusterName)" -Level Info
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
    try {
        $Snapshot = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop

        #Get the status of the task above
        $TaskId = $Snapshot.task_uuid
        $Phase = "[VM Snapshot]"
        $PhaseSuccessMessage = "Snapshot: $($SnapshotName) has been created"
        GetPrismv2Task -TaskID $TaskId -Cluster $ClusterIP -Credential $PrismElementCredentials
    }
    catch {
        Write-Log -Message "[VM Snapshot] Failed to create Snapshot on the target cluster: $($ClusterName)" -Level Warn
        Write-Log -Message $_ -Level Warn
        $TotalErrorCount += 1
        Continue
    }

    #endregion create Snapshot

    #region delete Snapshot
    #---------------------------------------------
    # Clean up snapshots based on retention
    #---------------------------------------------
    if ($ImageSnapsToRetain) {
        Write-Log "[Snapshots] Getting an up to date list of snapshots on the target cluster: $($ClusterName)" -Level Info
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/snapshots"
        $Payload = $null # we are on a GET run
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $Snapshots = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Snaphots] Failed to get an up to date list of snapshots on the target cluster: $($ClusterName)" -Level Warn
            $TotalErrorCount += 1
            Continue
        }

        Write-Log -Message "[VM Snapshot] There are $($Snapshots.entities.Count) snapshots on the target cluster: $($ClusterName)" -Level Info

        $MatchedSnapshots = $Snapshots.entities | Where-Object {$_.snapshot_name -like "$($VMPrefix + $BaseVM)*"}
        Write-Log -Message "[VM Snapshot] There are $($MatchedSnapshots.Count) snapshots matching on the target cluster: $($ClusterName)" -Level Info
    
        $SnapsToRetain = $MatchedSnapshots | Sort-Object -Property created_time -Descending | Select-Object -First $ImageSnapsToRetain

        $SnapsToDelete = @() # Initialise the delete array
        foreach ($Snap in $MatchedSnapshots) {
            # loop through each snapshot and add to delete array if not in the SnapsToRetain array
            if ($Snap -notin $SnapsToRetain) {
                Write-Log -Message "[VM Snapshot] Adding Snapshot: $($snap.snapshot_name) to the delete list" -Level Info
                $SnapsToDelete += $snap
            }
        }

        $SnapShotsDeleted = 0 #start the deletion count
        $SnapShotsFailedToDelete = 0 #start the deletion fail count

        if ($SnapsToDelete.Count -gt 0) {
            $SnapshotsToDeleteCount = 1
            Write-Log -Message "[VM Snapshot] There are $($SnapsToDelete.Count) Snapshots to delete based on a retention value of $($ImageSnapsToRetain) on the target cluster: $($ClusterName)" -Level Info
            foreach ($Snap in $SnapsToDelete) {
                # process the snapshot deletion
                Write-Log -Message "[VM Snapshot] Processing Snapshot $($SnapshotsToDeleteCount) of $($SnapsToDelete.Count). Processing deletion of Snapshot: $($snap.snapshot_name) on the target cluster: $($ClusterName)" -Level Info            
                $snap_id = $Snap.uuid
                try {
                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Method = "DELETE"
                    $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/snapshots/$($snap_id)"
                    $Payload = $null # we are on a delete run
                    #----------------------------------------------------------------------------------------------------------------------------
                    $SnapShotDelete = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop
        
                    #Get the status of the task above
                    $TaskId = $SnapShotDelete.task_uuid
                    $Phase = "[VM Snapshot]"
                    $PhaseSuccessMessage = "Snapshot: $($snap.snapshot_name) has been deleted"
        
                    GetPrismv2Task -TaskID $TaskId -Cluster $ClusterIP -Credential $PrismElementCredentials
        
                    $SnapShotsDeleted += 1
                }
                catch {
                    Write-Log -Message "[VM Snapshot] Failed to delete Snapshot: $($snap.snapshot_name) on the target cluster: $($ClusterName)" -Level Warn
                    $SnapShotsFailedToDelete += 1
                    $TotalErrorCount += 1
                    Continue
                }
                $SnapshotsToDeleteCount += 1
            }
        }
        else {
            Write-Log -Message "[VM Snapshot] There are no Snapshots to delete based on the retention value of: $($ImageSnapsToRetain) on the target cluster: $($ClusterName)" -Level Info 
        }
    }
    #endregion delete Snapshot

    #region delete Temp VM
    #---------------------------------------------
    # Delete the Temp VM 
    #---------------------------------------------
    Write-Log -Message "[VM Delete} Deleting VM $($vm_name) with ID: $($vm_uuid) on cluster: $($ClusterName)" -Level Info
    #----------------------------------------------------------------------------------------------------------------------------
    # Set API call detail
    #----------------------------------------------------------------------------------------------------------------------------
    $Method = "DELETE"
    $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$vm_uuid"
    $Payload = $null # we are on the a DELETE run
    #----------------------------------------------------------------------------------------------------------------------------
    try {
        $VMDeleted = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismElementCredentials -ErrorAction Stop

        # Get the status of the task above
        $TaskId = $VMDeleted.task_uuid
        $Phase = "[VM Delete]"
        $PhaseSuccessMessage = "VM $($vm_name) has been deleted"

        GetPrismv2Task -TaskID $TaskId -Cluster $ClusterIP -Credential $PrismElementCredentials
    }
    catch {
        Write-Log -Message "[VM Delete] Failed to Delete VM $($vm_name) with ID: $($vm_uuid) on cluster: $($ClusterName)" -Level Warn
        $TotalErrorCount += 1
        Continue
    }

    #endregion delete Temp VM

    $ClustersActionCount += 1
    $TotalSuccessCount += 1
}

#endregion Prism Element Loops

Write-Log -Message "[Data] Processed a total of $($ClustersTotalCount) Clusters" -Level Info
Write-Log -Message "[Data] Successfully processed $($TotalSuccessCount) Clusters without error" -Level Info
Write-Log -Message "[Data] Encountered $($TotalErrorCount) errors. Please review log file $($LogPath) for failures" -Level Info

#region Process Citrix Environment
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
        Write-Log -Message "[Citrix Catalog] There are $($CitrixConfig.Catalog.Count) Catalogs to Process" -Level Info
        foreach ($_ in $CitrixConfig) {
            # Set details
            $Catalog = $_.Catalog
            $AdminAddress = $_.Controller

            ProcessCitrixCatalog -Catalog $Catalog -AdminAddress $AdminAddress -snapshotName $snapshotName # Snapshot is set in the Nutanix phase
        }
    }
    else {
        #NO JSON
        $Catalogs = $ctx_Catalogs # This was set in the validation phase, but resetting here for ease of reading
        $AdminAddress = $ctx_AdminAddress # This was set in the validation phase, but resetting here for ease of reading
        $CatalogCount = $Catalogs.Count

        Write-Log -Message "[Citrix Catalog] There are $($Catalogs.Count) Catalogs to Process" -Level Info
        foreach ($Catalog in $Catalogs) {
            ProcessCitrixCatalog -Catalog $Catalog -AdminAddress $AdminAddress -snapshotName $snapshotName # Snapshot is set in the Nutanix phase
        }
    }
    Write-Log -Message "[Citrix Catalog] Successfully processed $($TotalCatalogSuccessCount) Catalogs" -Level Info
    if ($TotalCatalogFailureCount -gt 0) {
        Write-Log "[Citrix Catalog] Failed to processed $($TotalCatalogFailureCount) Catalogs" -Level Warn
    }
}
#endregion Process Citrix Environment

StopIteration
Exit 0
#endregion
