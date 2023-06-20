<#
.SYNOPSIS
    The script is designed to automate the VM restore and snapshot creation of a Citrix Base Image across multiple Nutanix clusters based on Protection Domain methodology and optionally update Citrix Catalogs.
.DESCRIPTION
    The script will query a single Source Cluster and Protection Domain of which your Citrix Base Image should be a member of. 
    It will figure out all target clusters based on protection Domain remote sites and attempt to restore, snapshot, and delete the protected VM instance leaving a Citrix ready snapshot for MCS provisioning.
    The script will handle deletion of existing snapshots based on a retention period (effectively a cleanup mode). This is a destructive operation.
    The script assumes that your Protection Domain configurations are setup correctly. It does not alter, modify, create or delete any form of PD outside of triggering an out of band replication.
    The script by default attempts to use the latest snapshot on the PD. It compares both source and target to ensure these are inline. You can override this behaviour with SnapShotID parameter.
    The script has optional processing to allow automated Citrix Catalogs across one or many Citrix sites.
.PARAMETER LogPath
    Logpath output for all operations
.PARAMETER LogRollover
    Number of days before logfiles are rolled over. Default is 5.
.PARAMETER SourceCluster
    Mandatory. The source Nutanix PE instance which holds the Citrix base image VM.
.PARAMETER pd
    Mandatory. The Protection Domain on the Source Cluster.
.PARAMETER BaseVM
    Mandatory. The name of the Citrix base image VM. This is CASE SENSITIVE.
.PARAMETER VMPrefix
    Optional. The prefix used for both the restored VM (temp) and the associated Snapshot. The default is ctx_
.PARAMETER SnapshotID
    Optional. If you do not want to use the latest snapshot, specify the appropriate Protection Domain Snapshot ID from the Source Clusters.
.PARAMETER ImageSnapsToRetain
    Optional. The number of snapshots to retain on each target Cluster. This is limited only to snaps meeting the BaseVM and VMPrefix naming patterns (Snapshots the script created).
.PARAMETER SleepTime
    Optional. The amount of time to sleep between VM creation and Snapshot creation tasks. Default is 10 seconds.
.PARAMETER UseCustomCredentialFile
    Optional. Will call the Get-CustomCredentials function which keeps outputs and inputs a secure credential file base on Stephane Bourdeaud from Nutanix functions
.PARAMETER CredPath
    Optional. Used if using the UseCustomCredentialFile parameter. Defines the location of the credential file. The default is "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
.PARAMETER ExcludeSourceClusterFromProcessing
    Optional. By default the Source Cluster is also processed to ensure consistency of snapshots available to Citrix. This switch allows to the Source Cluster to be ignored incase the VM snaps have already been handled and snap naming consistency doesn't matter.
.PARAMETER TriggerPDReplication
    Optional. Will trigger an out of band replication for the Protection Domain and query the PD events for success. Snapshot will expire after 1 hour (3600 seconds)
.PARAMETER MaxReplicationSuccessQueryAttempts
    Optional. An advanced parameter to alter the number of successful PD query events. Defaults to 10. Time between those queries is an advanced variable in the script which you should be careful with (10 seconds).
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
.EXAMPLE
    .\ReplicateCitrixBaseImageVM.ps1 -SourceCluster 1.1.1.1 -pd "PD-Citrix-Base-Image" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10 -UseCustomCredentialFile -TriggerPDReplication
    This will connect to the specified source cluster, look for the specified protection domain, look for the specified base VM entity
    A Protection Domain Out of Band replicate will be triggered.
    Any target snapshots outside of the last 10 will be deleted on the target clusters.
    A custom credential file will be created and consumed.
.EXAMPLE
    .\ReplicateCitrixBaseImageVM.ps1 -SourceCluster 1.1.1.1 -pd "PD-Citrix-Base-Image" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10 -ctx_Catalogs "Catalog1","Catalog2" -ctx_adminAddress "ctxddc001" -UseCustomCredentialFile -TriggerPDReplication
    This will connect to the specified source cluster, look for the specified protection domain, look for the specified base VM entity
    A Protection Domain Out of Band replicate will be triggered.
    Any target snapshots outside of the last 10 will be deleted on the target clusters.
    A custom credential file will be created and consumed.
    The Citrix Catalogs "Catalog1" and "Catalog2" will be processed on the Citrix Delivery Controller "ctxddc001"
.EXAMPLE
    .\ReplicateCitrixBaseImageVM.ps1 -SourceCluster 1.1.1.1 -pd "PD-Citrix-Base-Image" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10 -ctx_SiteConfigJSON "c:\temp\ctx_catalogs.json" -UseCustomCredentialFile -TriggerPDReplication
    This will connect to the specified source cluster, look for the specified protection domain, look for the specified base VM entity
    A Protection Domain Out of Band replicate will be triggered.
    Any target snapshots outside of the last 10 will be deleted on the target clusters.
    A custom credential file will be created and consumed.
    A JSON file including the appropriate Catalogs and Delivery Groups will be processed.
.EXAMPLE
    .\ReplicateCitrixBaseImageVM.ps1 -SourceCluster 1.1.1.1 -pd "PD-Citrix-Base-Image" -BaseVM "CTX-Gold-01" -SnapshotID 353902
    This will connect to the specified source cluster, look for the specified protection domain, look for the specified base VM entity, and attempt to use the specified Protection Domain snapshotID for all operations. 
    Credentials will be prompted for.
.EXAMPLE
    .\ReplicateCitrixBaseImageVM.ps1 -SourceCluster 1.1.1.1 -pd "PD-Citrix-Base-Image" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10
    This will connect to the specified source cluster, look for the specified protection domain, look for the specified base VM entity, select the latest available Protection Domain Snapshot.
    Any target snapshots outside of the last 10 will be deleted on the target clusters.
    Credentials will be prompted for.
.EXAMPLE
    .\ReplicateCitrixBaseImageVM.ps1 -SourceCluster 1.1.1.1 -pd "PD-Citrix-Base-Image" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10 -UseCustomCredentialFile
    This will connect to the specified source cluster, look for the specified protection domain, look for the specified base VM entity, select the latest available Protection Domain Snapshot.
    Any target snapshots outside of the last 10 will be deleted on the target clusters.
    A custom credential file will be created and consumed.
.EXAMPLE
    .\ReplicateCitrixBaseImageVM.ps1 -SourceCluster 1.1.1.1 -pd "PD-Citrix-Base-Image" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10 -UseCustomCredentialFile -TriggerPDReplication
    This will connect to the specified source cluster, look for the specified protection domain, look for the specified base VM entity, select the latest available Protection Domain Snapshot.
    Any target snapshots outside of the last 10 will be deleted on the target clusters.
    A custom credential file will be created and consumed. 
    a Protection Domain Out of Band replicate will be triggered.
.EXAMPLE
    .\ReplicateCitrixBaseImageVM.ps1 -SourceCluster 1.1.1.1 -pd "PD-Citrix-Base-Image" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10 -UseCustomCredentialFile -TriggerPDReplication -MaxReplicationSuccessQueryAttempts 20
    This will connect to the specified source cluster, look for the specified protection domain, look for the specified base VM entity, select the latest available Protection Domain Snapshot.
    Any target snapshots outside of the last 10 will be deleted on the target clusters.
    A custom credential file will be created and consumed. 
    a Protection Domain Out of Band replicate will be triggered.
    The Maximum number of attempts to query the Source PD for replication success will be doubled to 20.
.EXAMPLE
    .\ReplicateCitrixBaseImageVM.ps1 -SourceCluster 1.1.1.1 -pd "PD-Citrix-Base-Image" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10 -UseCustomCredentialFile -TriggerPDReplication -ExcludeSourceClusterFromProcessing
    This will connect to the specified source cluster, look for the specified protection domain, look for the specified base VM entity, select the latest available Protection Domain Snapshot.
    Any target snapshots outside of the last 10 will be deleted on the target clusters   . 
    A custom credential file will be created and consumed. 
    a Protection Domain Out of Band replicate will be triggered.
    The Source cluster will be exlcuded from having a snapshot created of the base VM.
.EXAMPLE
    .\ReplicateCitrixBaseImageVM.ps1 -SourceCluster 1.1.1.1 -pd "PD-Citrix-Base-Image" -BaseVM "CTX-Gold-01" -ctx_ProcessCitrixEnvironmentOnly -ctx_Snapshot "snapshotname" -ctx_SiteConfigJSON "c:\temp\ctx_catalogs.json"
    This mode will bring only the Citrix environment into line based ont the provided snapshot and the Catalogs defined in the ctx_catalogs.json file
    All Nutanix processing will be ignored
    SourceCluster, pd, BaseVM params required, but ignored.
.NOTES
    The script is built on the lowest common version of Nutanix PowerShell capability
    The script uses Citrix Powershell snapins for Citrix tasks
    The script assumes the same username and password on all PE instances - This should be a service account
    The script assumes that the user/account executing the script has the required permissions in Citrix sites
    #--------------------------------------------------------------------------------------------------------#
    # Authors and release:
    #--------------------------------------------------------------------------------------------------------#
    # This script is provided as-is to outline capability and methodology for achieving the defined goals.
    # James Kindon - Senior Solutions Architect, EUC - Nutanix
    # 23.05.2023: Initial release
    #--------------------------------------------------------------------------------------------------------#
#>

#region Params
# ============================================================================
# Parameters
# ============================================================================
Param(
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\MCSReplicateBaseImage.log", # Where we log to

    [Parameter(Mandatory = $false)]
    [int]$LogRollover = 5, # Number of days before logfile rollover occurs

    [Parameter(Mandatory = $true)]
    [string]$SourceCluster, # The source cluster holding the VM base image

    [Parameter(Mandatory = $true)]
    [string]$pd, # The protection domain holding the base VM

    [Parameter(Mandatory = $true)]
    [string]$BaseVM, # The VM entity name of the base VM

    [Parameter(Mandatory = $false)]
    [string]$VMPrefix = "ctx_", # The prefix name to create for the restored entity and the created snapshots

    [Parameter(Mandatory = $false)]
    [string]$SnapshotID, # The source ID (numerical) of the snapshot to replicate

    [Parameter(Mandatory = $false)]
    [int]$ImageSnapsToRetain, # The number of snapshots to retain. Effectively a cleanup mode

    [Parameter(Mandatory = $false)]
    [int]$SleepTime = 10, # Sleep time operations for VM and snapshot operations

    [Parameter(Mandatory = $false)]
    [switch]$UseCustomCredentialFile, # specifies that a credential file should be used

    [Parameter(Mandatory = $false)]
    [String]$CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials", # Default path for custom credential file
    
    [Parameter(Mandatory = $false)]
    [switch]$ExcludeSourceClusterFromProcessing, # do not process the source cluster

    [Parameter(Mandatory = $false)]
    [switch]$TriggerPDReplication, # Triggers an out of band protection domain replication

    [Parameter(Mandatory = $false)]
    [int]$MaxReplicationSuccessQueryAttempts = 10, # configures the number of attempts to query the PD for replication success to all remote clusters

    [Parameter(Mandatory = $false)]
    [Array]$ctx_Catalogs, # Array of catalogs on a single Citrix site to process. If needing to update multiple sites, use the JSON input

    [Parameter(Mandatory = $false)]
    [String]$ctx_AdminAddress, # Delivery Controller address on a single Citrix site to process. If needing to update multiple sites, use the JSON input

    [Parameter(Mandatory = $false)]
    [String]$ctx_SiteConfigJSON, # JSON input file for multi site (or single site) Citrix site configurations. Catalogs and Delivery Controllers

    [Parameter(Mandatory = $false)]
    [switch]$ctx_ProcessCitrixEnvironmentOnly, # Defines that we are processing ONLY citrix environments and not Nutanix

    [Parameter(Mandatory = $false)]
    [String]$ctx_Snapshot # the snapshot to be used to update Citrix Catalogs. Used in conjunction with ctx_ProcessCitrixEnvironmentOnly
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
            #Write-LogOutput -Category INFO -Message "$(get-date) [INFO] Set path to $path"
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
$EventCheckInterval = 10 # Controls the interval between checking for success query on Protection Domain replication
$TimeBeforeEventSearch = 5 # Time to wait between triggering the PD replication and searching for events

#endregion

#Region Execute
# ============================================================================
# Execute
# ============================================================================
StartIteration

if ($PSVersionTable.PSVersion.Major -lt 5) { throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)" }

if ($PSVersionTable.PSedition -eq "Core") { throw "$(get-date) You cannot use snapins with PowerShell Core. You must use PowerShell 5.x" }
#region Modules
#------------------------------------------------------------
# Import Nutanix PowerShell Modules
#------------------------------------------------------------
try {
    Write-Log -Message "[Nutanix PowerShell] Attempting to import Nutanix PowerShell Module" -Level Info
    & 'C:\Program Files (x86)\Nutanix Inc\NutanixCmdlets\powershell\import_modules\ImportModules.PS1' -ErrorAction Stop
    Write-Log -Message "[Nutanix PowerShell] Successfully imported Nutanix PowerShell Module" -Level Info 
}
catch {
    Write-Log -Message "[Nutanix PowerShell] Failed to import Nutanix PowerShell Module" -Level Warn
    Write-Log -Message $_ -Level Warn
    StopIteration
    Exit 1
}

#------------------------------------------------------------
# Import Citrix Snapins
#------------------------------------------------------------
if ($ctx_Catalogs -or $ctx_SiteConfigJSON) {
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

#region Authentication
#------------------------------------------------------------
# Handle Authentication
#------------------------------------------------------------
if ($UseCustomCredentialFile.IsPresent) {
    $PrismCreds = "prism-creds"
    Write-Log -Message "[Credentials] UseCustomCredentialFile has been selected. Attempting to retrieve credential object" -Level Info
    try {
        $PrismCredentials = Get-CustomCredentials -credname $PrismCreds -ErrorAction Stop
    }
    catch {
        Set-CustomCredentials -credname $PrismCreds
        $PrismCredentials = Get-CustomCredentials -credname $PrismCreds -ErrorAction Stop
    }
}
else {
    Write-Log -Message "[Credentials] Prompting user for Prism credentials" -Level Info
    $PrismCredentials = Get-Credential -Message "Enter Credentials for Prism Element Instances"
    if (!$PrismCredentials) {
        Write-Log -Message "[Credentials] Failed to set user credentials" -Level Warn
        StopIteration
        Exit 1
    }
}
#endregion Authentication

#region Connect to Source Cluster
#------------------------------------------------------------
# Connect to the Source Cluster
#------------------------------------------------------------
try {
    Write-Log -Message "[Source Cluster] Connecting to the source Cluster: $($SourceCluster)" -Level Info
    Connect-NTNXCluster -Server $SourceCluster -UserName $PrismCredentials.Username -Password $PrismCredentials.Password -AcceptInvalidSSLCerts -ErrorAction Stop | Out-null
    Write-Log -Message "[Source Cluster] Successfully connected to the source Cluser: $($SourceCluster)" -Level Info
}
catch {
    Write-Log -Message "[Source Cluster] Could not connect to the source Cluster: $($SourceCluster) " -Level Warn
    Write-Log -Message $_ -Level Warn
    StopIteration
    Exit 1
}
#endregion Connect to Source Cluster

#region Get Protection Domain
#------------------------------------------------------------
# Get the protection domain
#------------------------------------------------------------
try {
    Write-Log -Message "[Protection Domain] Getting Protection Domain details for: $($pd) in the source Cluster: $($SourceCluster)" -Level Info
    $ProtectionDomain = Get-NTNXProtectionDomain -Name $pd -Server $SourceCluster -ErrorAction Stop
    
    if ($ProtectionDomain) {
        # may not respond with an error so capturing empty variable
        Write-Log -Message "[Protection Domain] Sucessfully retrieved Protection Domain details for: $($pd) in the source Cluster: $($SourceCluster)" -Level Info
    }
    else {
        Write-Log -Message "[Protection Domain] Failed to get no Protection Domain named: $($pd) on the source Cluster: $($SourceCluster)" -Level Warn
        StopIteration
        Exit 1
    }
}
catch {
    Write-Log -Message "[Protection Domain] Failed to get Protection Domain details for: $($pd) in the source Cluster: $($SourceCluster)" -Level Warn
    Write-Log -Message $_ -Level Warn
    StopIteration
    Exit 1
}
#endregion Get Protection Domain

#region Find Remote Sites
#------------------------------------------------------------
# Find the remote sites
#------------------------------------------------------------
$RemoteSites = Get-NTNXRemoteSite -Server $SourceCluster | Where-Object {$_.name -in ($ProtectionDomain).remoteSiteNames}

if (!$RemoteSites) {
    Write-Log -Message "[Remote Sites] There are no Remote Sites defined for: $($pd) in the source Cluster: $($SourceCluster)" -Level Warn
    StopIteration
    Exit 1
}

# get a list of the IP addresses
$RemoteSiteIPS = ($remoteSites.remoteIpPorts).Keys

$TotalRemoteClusterCount = $RemoteSiteIPS.Count
Write-Log -Message "[Remote Sites] Remote Clusters to process: $($TotalRemoteClusterCount)" -Level Info
#endregion Find Remote Sites

#region Protection Domain Replication
#------------------------------------------------------------
# Trigger Protection Domain Replication
#------------------------------------------------------------
if ($TriggerPDReplication.IsPresent) {
    # Kick off the replication
    Write-Log -Message "[PD Replication] Protection Domain replication has been selected. Attempting to initiate an out of band Protection Domain replication to all remote clusters from the source Cluster: $($SourceCluster)" -Level Info
    try {
        $NewOOBReplication = Add-NTNXOutOfBandSchedule -PdName $pd -RemoteSiteNames $RemoteSites.name -SnapshotRetentionTimeSecs 3600 -Server $SourceCluster -ErrorAction Stop
        if ($NewOOBReplication) {
            Write-Log -Message "[PD Replication] Initiated a replication with scheduleId: $($NewOOBReplication.scheduleId) from the source Cluster: $($SourceCluster)" -Level Info
        }
        else {
            Write-Log -Message "[PD Replication] Failed to initiate an out of band replication for Protection Domain: $($pd) from the source Cluster: $($SourceCluster)" -Level Warn
            StopIteration
            Exit 1
        }
    }
    catch {
        Write-Log -Message "[PD Replication] Failed to initiate out of band replication for Protection Domain: $($pd) from the source Cluster: $($SourceCluster)" -Level Warn
        StopIteration
        Exit 1
    }

    ## Get Snapshot ID based on Protection Domain Events
    Write-Log -Message "[PD Replication] Waiting $($TimeBeforeEventSearch) seconds for Events to be logged on the source Cluster: $($SourceCluster)" -Level Info
    Start-Sleep $TimeBeforeEventSearch
    $MessageMatchString = "*created for protection domain $($pd)*"
    $SnapshotIDOfOOBReplication = Get-NTNXProtectionDomainEvent -Server $SourceCluster -PdName $pd | Where-Object {$_.message -like $MessageMatchString} | Sort-Object createdTimeStampInUsecs -Descending | Select-Object -First 1

    if (!$SnapshotIDOfOOBReplication) {
        # report on fail and quit
        Write-Log -Message "[PD Replication] Cannot find any events indicating the snapshot ID on the source Cluster: $($SourceCluster)" -Level Warn
        StopIteration
        Exit 1
    }
    else {
        # report on success and set variables
        $Pattern = "\d+" # finds numerical value of the snapshot in the message
        $SnapID = $SnapshotIDOfOOBReplication.message | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.matches } | Sort-Object -Descending | Select-Object -First 1
        Write-Log -Message "[PD Replication] Got snapshot ID reference: $($SnapID). Checking for replication finish events on the source Cluster: $($SourceCluster)" -Level Info
    }

    # Check replication status based on event messages
    Write-Log -Message "[PD Replication] Waiting $($TimeBeforeEventSearch) seconds for Events to be logged on the source Cluster: $($SourceCluster)" -Level Info
    Start-Sleep $TimeBeforeEventSearch
    $MessageMatchString = "*Replication completed for Protection Domain $($pd) to remote* *$($SnapID.Value)*"
    $ReplicationSuccessQueryAttempts = 1  # Initialise the attempt count

    $CompletionMessageofOOBReplication = Get-NTNXProtectionDomainEvent -Server $SourceCluster -PdName $pd | Where-Object {$_.Message -like $MessageMatchString} | Sort-Object createdTimeStampInUsecs -Descending
    if ($CompletionMessageofOOBReplication.Count -eq $RemoteSites.count) {
        Write-Log -Message "[PD Replication] Cluster replication complete. Found replication finished events for $($CompletionMessageofOOBReplication.Count) out of $($RemoteSites.count) remote Clusters" -Level Info
    }
    else {
        while ($CompletionMessageofOOBReplication.Count -ne $RemoteSites.count) {
            if ($ReplicationSuccessQueryAttempts -eq $MaxReplicationSuccessQueryAttempts) {
                Write-Log -Message "[PD Replication] Max Replication Query for Success ($($MaxReplicationSuccessQueryAttempts)) has been reached. Assuming failed replication on the source Cluster: $($SourceCluster)" -Level Warn
                StopIteration
                Exit 1
            }
            else {
                if ($ReplicationSuccessQueryAttempts -ne 1) {
                    Write-Log -Message "[PD Replication] Attempting to retrieve replication complete events. Attempt $($ReplicationSuccessQueryAttempts) of a maximum $($MaxReplicationSuccessQueryAttempts)" -Level Info
                }
                $CompletionMessageofOOBReplication = Get-NTNXProtectionDomainEvent -Server $SourceCluster -PdName $pd | Where-Object {$_.Message -like $MessageMatchString} | Sort-Object createdTimeStampInUsecs -Descending
                Write-Log -Message "[PD Replication] Found replication finished events for $($CompletionMessageofOOBReplication.Count) out of $($RemoteSites.count). Checking again in $($EventCheckInterval) seconds." -Level Info
                $ReplicationSuccessQueryAttempts += 1
                Start-Sleep $EventCheckInterval
            }
        }
        Write-Log -Message "[PD Replication] Cluster replication complete. Found replication finished events for $($CompletionMessageofOOBReplication.Count) clusters" -Level Info
    }
}
#endregion Protection Domain Replication

#region Get PD Snapshots
#------------------------------------------------------------
# Get a list of snapshots from the Source
#------------------------------------------------------------
Write-Log -Message "[PD Snapshot] Getting Snapshots on the source Cluster $($SourceCluster)" -Level Info
try {
    $SourceSnaps = Get-NTNXProtectionDomainSnapshot -Servers $SourceCluster -PdName $pd -ErrorAction Stop | Where-Object {$_.State -ne "EXPIRED"}
    if (!$SourceSnaps) {
        # can't process an empty array
        Write-Log -Message "[PD Snapshot] There are no Snapshots on the specified Protection Domain $($pd) in the source Cluster: $($SourceCluster). Terminating" -Level Warn
        StopIteration
        Exit 1
    }
}
catch {
    Write-Log -Message "[PD Snapshot] Failed to retrieve Snapshots on the source Cluster $($SourceCluster)" -Level Warn
    Write-Log -Message $_ -Level Warn
    StopIteration
    Exit 1
}

#------------------------------------------------------------
# Validate the snapshot exists (if specified)
#------------------------------------------------------------
if ($SnapshotID) {
    $SourceSnapExists = $SourceSnaps | where-Object {$_.SnapshotId -like $SnapshotID}
    if ($SourceSnapExists) {
        Write-Log -Message "[PD Snapshot] Snapshot with ID: $($SnapshotID) has been found on the source Cluster: $($SourceCluster)" -Level Info
    }
    else {
        # the snapshot doesnt exist in the source
        Write-Log -Message "[PD Snapshot] Could not find the defined Snapshot on the source Cluster: $($SourceCluster). Terminating" -Level Warn
        StopIteration
        Exit 1
    }
}
#endregion Get PD Snapshots

#------------------------------------------------------------
# Initialise counts and variables
#------------------------------------------------------------
$CurrentClusterCount = 1
$TotalErrorCount = 0 # start the error count
$TotalSuccessCount = 0 # start the succes count

#region process local cluster
#------------------------------------------------------------
# Process the local cluster
#------------------------------------------------------------
if (!$ExcludeSourceClusterFromProcessing) {
    Write-Log -Message "[Source Cluster: Start] Processing source Cluster: $($SourceCluster)" -Level Info
    #------------------------------------------------------------
    # Find the local VM
    #------------------------------------------------------------
    Write-Log -Message "[VM] Looking for base VM $($BaseVM) on the source Cluster: $($SourceCluster)" -Level Info
    $vm = Get-NTNXVM -SearchString ($BaseVM) -Server $SourceCluster
    if (!$vm) {
        #couldn't find the VM
        Write-Log -Message "[VM] Could not find the VM: $($BaseVM) on the source Cluster: $($SourceCluster)" -Level Warn
        StopIteration
        Exit 1
    }

    # handle multiple vm match
    if ($vm.count -gt 1) {
        Write-Log -Message "[VM] There are $($vm.Count) vm entities found. Doing a direct name match to identify VM" -Level Info
        $vm = $vm | where-Object { $_.vmName -eq $BaseVM }
    }

    #------------------------------------------------------------
    # Take a snapshot
    #------------------------------------------------------------
    $IterationErrorCount = 0 # start the iteration error count
    # start count for snapshots (how many currently exist)
    Write-Log -Message "[VM Snapshot] There are $((Get-NTNXSnapshot -Server $SourceCluster | Where-Object {$_.snapshotName -like ($VMPrefix + "$BaseVM*")}).Count) Snapshots matching: $($VMPrefix + $BaseVM) on the source Cluster: $($SourceCluster)" -Level Info

    if ($vm) {
        # create snapshot config
        Write-Log -Message "[VM Snapshot] Creating Snapshot spec and creating Snapshot on the source Cluster: $($SourceCluster)" -Level Info
        $snapshotName = $VMPrefix + $vm.vmName + "_" + $RunDate
        $newSnapshot = New-NTNXObject -Name SnapshotSpecDTO
        $newSnapshot.vmuuid = $vm.uuid
        $newSnapshot.snapshotname = $snapshotName
        # take the snapshot
        try {
            New-NTNXSnapshot -SnapshotSpecs $newSnapshot -Server $SourceCluster -ErrorAction Stop | Out-Null
            Write-Log -Message "[VM Snapshot] Waiting $($SleepTime) seconds for Snapshot creation of: $($snapshotName) to finalise on the source Cluster: $($SourceCluster)" -Level Info
            Start-Sleep $SleepTime
            Write-Log -Message "[VM Snapshot] Sucessfully created Snapshot: $($snapshotName) on the source Cluster: $($SourceCluster)" -Level Info
        }
        catch {
            Write-Log -Message "[VM Snapshot] Failed to create Snapshot: $($snapshotName) on the source Cluster: $($SourceCluster) " -Level Warn
            Write-Log -Message $_ -level Warn
            StopIteration
            Exit 1
        }
    }

    # end count for snapshots (how many currently exist)
    Write-Log -Message "[VM Snapshot] There are now: $((Get-NTNXSnapshot -Server $SourceCluster | Where-Object {$_.snapshotName -like ($VMPrefix + "$BaseVM*")}).Count) Snapshots matching $($VMPrefix + $BaseVM) on the source cluster $($SourceCluster)" -Level Info

    #------------------------------------------------------------
    # Handle the deletion of snapshot retention if set
    #------------------------------------------------------------
    if ($ImageSnapsToRetain) {
        Write-Log -Message "[VM Snapshot] Removing Snapshots that do not meet the retention value: $($ImageSnapsToRetain) on the source Cluster: $($SourceCluster)" -Level Info

        $ImageSnapsOnSource = Get-NTNXSnapshot -Server $SourceCluster | Where-Object { $_.snapshotName -like ($VMPrefix + "$BaseVM*") }
        $ImageSnapsOnSourceToRetain = $ImageSnapsOnSource | Sort-Object -Property createdTime -Descending | Select-Object -First $ImageSnapsToRetain

        $ImageSnapsOnSourceToDelete = @() #Initialise the delete array
        foreach ($snap in $ImageSnapsOnSource) {
            # loop through each snapshot and add to delete array if not in the ImageSnapsOnTargetToRetain array
            if ($snap -notin $ImageSnapsOnSourceToRetain) {
                Write-Log -Message "[VM Snapshot] Adding Snapshot: $($snap.snapshotName) to the delete list" -Level Info
                $ImageSnapsOnSourceToDelete += $snap
            }
        }

        $SnapShotsDeletedOnSource = 0
        $SnapShotsFailedToDeleteOnSource = 0
        if ($ImageSnapsOnSourceToDelete.Count -gt 0) {
            Write-Log -Message "[VM Snapshot] There are $($ImageSnapsOnSourceToDelete.Count) Snapshots to delete based on a retention value of $($ImageSnapsToRetain) on the source Cluster: $($SourceCluster)" -Level Info
            foreach ($Snap in $ImageSnapsOnSourceToDelete) {
                # process the snapshot deletion
                Write-Log -Message "[VM Snapshot] Processing deletion of Snapshot: $($snap.snapshotName) on the source Cluster: $($SourceCluster)" -Level Info
                try {
                    Remove-NTNXSnapshot -Uuid $snap.uuid -Server $SourceCluster -ErrorAction Stop | Out-Null
                    Write-Log -Message "[VM Snapshot] Successfully deleted Snapshot: $($snap.snapshotName) on the source Cluster: $($SourceCluster)" -Level Info
                    $SnapShotsDeletedOnSource += 1
                }
                catch {
                    Write-Log -Message "[VM Snapshot] Failed to delete vm Snapshot: $($snap.snapshotName) on the source Cluster: $($SourceCluster)" -Level Warn
                    Write-Log -Message $_ -level Warn
                    $SnapShotsFailedToDeleteOnSource += 1
                    Break
                }
            }
        }
        else {
            Write-Log -Message "[VM Snapshot] There are no Snapshots to delete based on the retention value of: $($ImageSnapsToRetain) on the source Cluster: $($SourceCluster)" -Level Info
        }

        Write-Log "[Data] Successfully deleted: $($SnapShotsDeletedOnSource) Snapshots on the source Cluster: $($SourceCluster)" -Level Info
        if ($SnapShotsFailedToDeleteOnSource -gt 0) {
            Write-Log -Message "[Data] Encountered $($SnapShotsFailedToDeleteOnSource.Count) VM Snapshot deletion errors. Please review log file $($LogPath) for failures" -Level Info
        }
    }
    else {
        Write-Log -Message "[VM Snapshot] Cleanup (ImageSnapsToRetain) not specified. Nothing to process." -Level Info
    }

    #------------------------------------------------------------
    # Update the processed cluster counts
    #------------------------------------------------------------
    if ($IterationErrorCount -eq 0) {
        $ProcessedSourceCluster = $True #identify that we procesed the source cluster
    }

    Write-Log -Message "[Source Cluster: Complete] Finished processing source Cluster: $($SourceCluster)" -Level Info
}
else {
    Write-Log -Message "[Source Cluster] Source cluster: $($SourceCluster) is excluded from processing" -Level Info
}

#endregion process local cluster

#region process remote clusters
#------------------------------------------------------------
# Process each Target Cluster
#------------------------------------------------------------
foreach ($Site in $RemoteSiteIPS){
    $IterationErrorCount = 0 # start the iteration error count

    #region Connect to the Target Cluster
    #------------------------------------------------------------
    # Process the target cluster
    #------------------------------------------------------------
    Write-Log -Message "[Target Cluster: Start] Processing Cluster $($CurrentClusterCount) of $($TotalRemoteClusterCount)" -Level Info
    $TargetCluster = $Site
    Write-Log -Message "[Target Cluster] Connecting to the target Cluster: $($TargetCluster)" -Level Info
    try {
        Connect-NTNXCluster -Server $TargetCluster -UserName $PrismCredentials.Username -Password $PrismCredentials.Password -AcceptInvalidSSLCerts -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Log -Message "[Target Cluster] Could not connect to the target Cluster: $($TargetCluster) " -Level Warn
        Write-Log -Message $_ -Level Warn
        $IterationErrorCount += 1
        $TotalErrorCount += 1
        Break
    }
    #endregion Connect to the Target Cluster
    
    # start count for snapshots (how many currently exist)
    Write-Log -Message "[VM Snapshot] There are $((Get-NTNXSnapshot -Server $TargetCluster | Where-Object {$_.snapshotName -like ($VMPrefix + "$BaseVM*")}).Count) Snapshots matching: $($VMPrefix + $BaseVM) on the target Cluster: $($TargetCluster)" -Level Info
    
    #region Get PD Snapshots on target
    #------------------------------------------------------------
    # Get PD snapshots
    #------------------------------------------------------------
    Write-Log -Message "[PD Snapshot] Getting Snapshots on the target Cluster $($TargetCluster)" -Level Info
    try {
        $TargetSnaps = Get-NTNXProtectionDomainSnapshot -Servers $TargetCluster -PdName $pd -ErrorAction Stop | Where-Object {$_.State -ne "EXPIRED"}
        if (!$TargetSnaps) {
            # can't process an empty array
            Write-Log -Message "[PD Snapshot] There are no Snapshots on the specified Protection Domain $($pd) in the target Cluster: $($TargetCluster)" -Level Warn
            $IterationErrorCount += 1
            $TotalErrorCount += 1
            Break
        }
    }
    catch {
        Write-Log -Message "[PD Snapshot] Failed to retrieve Snapshots on the target Cluster: $($TargetCluster)" -Level Warn
        $IterationErrorCount += 1
        $TotalErrorCount += 1
        Break
    }
        
    if ($SnapshotID) {
        # we specified a specific Snapshot ID - Validate Destination Snaps
        $TargetSnapExists = $TargetSnaps | where-Object {$_.SnapshotId -like "*:$SnapshotID"}
        if ($TargetSnapExists) {
            Write-Log -Message "[PD Snapshot] Snapshot with ID: $($SnapshotID) has been found on the target Cluster: $($TargetCluster)" -Level Info
            $SelectedSnapshot = $TargetSnapExists.snapshotId
        }
        else {
            # the snapshot doesnt exist in the target
            Write-Log -Message "[PD Snapshot] Could not find defined Snapshot on the target Cluster: $($TargetCluster). Terminating" -Level Warn
            $IterationErrorCount += 1
            $TotalErrorCount += 1
            Disconnect-NTNXCluster -Server $TargetCluster
            Break
        }
    }
    else {
        # we are using the most recent snapshot matching the name pattern
        Write-Log -Message "[PD Snapshot] Comparing latest PD Snapshot ID in the source: $($SourceCluster) and target: $($TargetCluster) Clusters" -Level Info
        $LatestSourceSnap = $SourceSnaps[0].snapshotId 
        $LatestTargetSnap = ($TargetSnaps[0].snapshotId -split ":")[1]

        if ($LatestTargetSnap -eq $LatestSourceSnap) {
            Write-Log -Message "[PD Snapshot] The latest PD Snapshot ID: $($LatestTargetSnap) on the target Cluster: $($TargetCluster) matches the latest PD Snapshot ID: $($LatestSourceSnap) on the source cluster: $($SourceCluster)" -Level Info
            $SelectedSnapshot = $TargetSnaps[0].snapshotId
        }
        else {
            # snapshots exist in both source and target
            Write-Log -Message "[PD Snapshot] The latest PD Snapshot ID: $($LatestTargetSnap) on the target Cluster: $($TargetCluster) does not match the latest PD Snapshot ID: $($LatestSourceSnap) on the source cluster: $($SourceCluster)" -Level Warn
            Write-Log -Message "[PD Snapshot] Please check Protection Domain replication status for Snapshot consistency. Terminating PD: $($pd) processing on target Cluster $($TargetCluster)" -Level Warn
            $IterationErrorCount += 1
            $TotalErrorCount += 1
            Disconnect-NTNXCluster -Server $TargetCluster
            Break
        }
    }
    #endregion Get PD Snapshots on target

    #region Restore the Instance on target
    #------------------------------------------------------------
    # Restore the instance
    #------------------------------------------------------------
    Write-Log -Message "[VM] Restoring VM: $($BaseVM) from Protection Domain: $($pd) on target Cluster: $($TargetCluster) from Snapshot ID: $($SelectedSnapshot)" -Level Info
    try {
        Restore-NTNXEntity -VmNames $BaseVM -pdName $pd -SnapshotId $SelectedSnapshot -VmNamePrefix $VMPrefix -Server $TargetCluster -ErrorAction Stop | Out-Null
        # wait due to delay
        Write-Log -Message "[VM] Waiting $($SleepTime) seconds for VM creation of: $($VMPrefix + $BaseVM) to finalise on target Cluster: $($TargetCluster)" -Level Info
        Start-Sleep $SleepTime
        Write-Log -Message "[VM] Successfully restored VM: $($VMPrefix + $BaseVM) on target Cluster: $($TargetCluster)" -Level Info
    }
    catch {
        Write-Log -Message "[VM] Failed to restore VM: $($BaseVM) from Protection Domain: $($pd) on target Cluster: $($TargetCluster) from Snapshot ID: $($SelectedSnapshot)" -Level Warn
        Write-Log -Message $_ -level Warn
        $IterationErrorCount += 1
        $TotalErrorCount += 1
        Disconnect-NTNXCluster -Server $TargetCluster
        Break
    }
    #endregion Restore the Instance on target

    #region VM Snapshot on target
    #------------------------------------------------------------
    # Take a snaphot
    #------------------------------------------------------------
    $vm = Get-NTNXVM -SearchString ($VMPrefix + $BaseVM) -Server $TargetCluster
    if (!$vm) {
        #couldn't find the VM
        Write-Log -Message "[VM] Could not find the VM: $($VMPrefix + $BaseVM) on the target Cluster: $($TargetCluster)" -Level Warn
        $IterationErrorCount += 1
        $TotalErrorCount += 1
        Disconnect-NTNXCluster -Server $TargetCluster
        Break
    }

    # handle multiple vm match
    if ($vm.count -gt 1) {
        Write-Log -Message "[VM] There are $($vm.Count) vm entities found. Doing a direct name match to identify VM" -Level Info
        $vm = $vm | where-Object {$_.vmName -eq $VMPrefix + $BaseVM}
    }

    # create snapshot config
    Write-Log -Message "[VM Snapshot] Creating Snapshot spec and creating Snapshot on the target Cluster: $($TargetCluster)" -Level Info
    $snapshotName = $vm.vmName + "_" + $RunDate
    $newSnapshot = New-NTNXObject -Name SnapshotSpecDTO
    $newSnapshot.vmuuid = $vm.uuid
    $newSnapshot.snapshotname = $snapshotName
    # take the snapshot
    try {
        New-NTNXSnapshot -SnapshotSpecs $newSnapshot -Server $TargetCluster -ErrorAction Stop | Out-Null
        Write-Log -Message "[VM Snapshot] Waiting $($SleepTime) seconds for Snapshot creation of: $($snapshotName) to finalise on the target Cluster: $($TargetCluster)" -Level Info
        Start-Sleep $SleepTime
        Write-Log -Message "[VM Snapshot] Sucessfully created Snapshot: $($snapshotName) on the target Cluster: $($TargetCluster)" -Level Info
    }
    catch {
        Write-Log -Message "[VM Snapshot] Failed to create Snapshot: $($snapshotName) on the target Cluster: $($TargetCluster) " -Level Warn
        Write-Log -Message $_ -level Warn
        $IterationErrorCount += 1
        $TotalErrorCount += 1
        Disconnect-NTNXCluster -Server $TargetCluster
        Break
    }
    #endregion VM Snapshot on target

    #region VM Removal on target
    #------------------------------------------------------------    
    # Remove the VM
    #------------------------------------------------------------
    Write-Log -Message "[VM] Removing Temp VM: $($vm.vmName) on the target Cluster: $($TargetCluster)" -Level Info
    try {
        Remove-NTNXVirtualMachine -Vmid $vm.uuid -Server $TargetCluster -ErrorAction Stop | Out-Null
        Write-Log -Message "[VM] Successfully removed Temp VM: $($vm.vmName) on the target Cluster: $($TargetCluster)" -Level Info
    }
    catch {
        Write-Log -Message "[VM] Failed to remove Temp VM: $($vm.vmName) on the target Cluster: $($TargetCluster)" -Level Warn
        Write-Log -Message $_ -level Warn
        $IterationErrorCount += 1
        $TotalErrorCount += 1
        Disconnect-NTNXCluster -Server $TargetCluster
        Break
    }
    #endregion VM Removal on target

    # end count for snapshots (how many currently exist)
    Write-Log -Message "[VM Snapshot] There are now: $((Get-NTNXSnapshot -Server $TargetCluster | Where-Object {$_.snapshotName -like ($VMPrefix + "$BaseVM*")}).Count) Snapshots matching $($VMPrefix + $BaseVM) on the target cluster $($TargetCluster)" -Level Info

    #region Snapshot Deletion on target
    #------------------------------------------------------------
    # Handle the deletion of snapshot retention if set
    #------------------------------------------------------------

    if ($ImageSnapsToRetain) {
        Write-Log -Message "[VM Snapshot] Removing Snapshots that do not meet the retention value: $($ImageSnapsToRetain) on the target Cluster: $($TargetCluster)" -Level Info

        $ImageSnapsOnTarget = Get-NTNXSnapshot -Server $TargetCluster | Where-Object { $_.snapshotName -like ($VMPrefix + "$BaseVM*") }
        $ImageSnapsOnTargetToRetain = $ImageSnapsOnTarget | Sort-Object -Property createdTime -Descending | Select-Object -First $ImageSnapsToRetain

        $ImageSnapsOnTargetToDelete = @() #Initialise the delete array
        foreach ($snap in $ImageSnapsOnTarget) {
            # loop through each snapshot and add to delete array if not in the ImageSnapsOnTargetToRetain array
            if ($snap -notin $ImageSnapsOnTargetToRetain) {
                Write-Log -Message "[VM Snapshot] Adding Snapshot: $($snap.snapshotName) to the delete list" -Level Info
                $ImageSnapsOnTargetToDelete += $snap
            }
        }

        $SnapShotsDeletedOnTarget = 0
        $SnapShotsFailedToDeleteOnTarget = 0
        if ($ImageSnapsOnTargetToDelete.Count -gt 0) {
            Write-Log -Message "[VM Snapshot] There are $($ImageSnapsOnTargetToDelete.Count) Snapshots to delete based on a retention value of $($ImageSnapsToRetain) on the target Cluster: $($TargetCluster)" -Level Info
            foreach ($Snap in $ImageSnapsOnTargetToDelete) {
                # process the snapshot deletion
                Write-Log -Message "[VM Snapshot] Processing deletion of Snapshot: $($snap.snapshotName) on the target Cluster: $($TargetCluster)" -Level Info
                try {
                    Remove-NTNXSnapshot -Uuid $snap.uuid -Server $TargetCluster -ErrorAction Stop | Out-Null
                    Write-Log -Message "[VM Snapshot] Successfully deleted Snapshot: $($snap.snapshotName) on the target Cluster: $($TargetCluster)" -Level Info
                    $SnapShotsDeletedOnTarget += 1
                }
                catch {
                    Write-Log -Message "[VM Snapshot] Failed to delete vm Snapshot: $($snap.snapshotName) on the target Cluster: $($TargetCluster)" -Level Warn
                    Write-Log -Message $_ -level Warn
                    $SnapShotsFailedToDeleteOnTarget += 1
                    Break
                }
            }
        }
        else {
            Write-Log -Message "[VM Snapshot] There are no Snapshots to delete based on the retention value of: $($ImageSnapsToRetain) on the target Cluster: $($TargetCluster)" -Level Info
        }

        Write-Log "[Data] Successfully deleted: $($SnapShotsDeletedOnTarget) Snapshots on the target Cluster: $($TargetCluster)" -Level Info
        if ($SnapShotsFailedToDeleteOnTarget -gt 0) {
            Write-Log -Message "[Data] Encountered $($SnapShotsFailedToDeleteOnTarget.Count) VM Snapshot deletion errors. Please review log file $($LogPath) for failures" -Level Info
        }
    }
    else {
        Write-Log -Message "[VM Snapshot] Cleanup (ImageSnapsToRetain) not specified. Nothing to process." -Level Info
    }
    
    #endregion Snapshot Deletion on target

    #------------------------------------------------------------
    # Disconnect from the cluster
    #------------------------------------------------------------
    Write-Log -Message "[Target Cluster] Disconnecting from the target Cluster: $($TargetCluster)" -Level Info
    Disconnect-NTNXCluster -Server $TargetCluster

    #------------------------------------------------------------
    # Update the processed cluster counts
    #------------------------------------------------------------
    if ($IterationErrorCount -eq 0) {
        $TotalSuccessCount += 1
    }
    $CurrentClusterCount += 1

    Write-Log -Message "[Target Cluster: Complete] Finished processing target Cluster: $($TargetCluster)" -Level Info
}
#endregion process remote clusters

Write-Log -Message "[Data] Successfully processed $($TotalSuccessCount) remote Clusters" -Level Info
if ($ProcessedSourceCluster) {
    $TotalSuccessCount += 1
    Write-Log -Message "[Data] Successfully processed $($TotalSuccessCount) total Clusters" -Level Info
}

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
