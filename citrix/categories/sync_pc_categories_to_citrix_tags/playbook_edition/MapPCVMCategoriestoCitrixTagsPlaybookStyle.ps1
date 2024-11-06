<#
.SYNOPSIS
    This script is designed to map the Categories from a Nutanix Prism Central to a Citrix Tag.
.DESCRIPTION
    The script supports a single PC and either Citrix Virtual Apps and Desktops or Citrix DaaS. The script can also create Categories in Nutanix Prism Central based on Citrix Tags.
.PARAMETER LogPath
    Optional. The path to the log file. Default is C:\Logs\MapPCVMCategoriestoCitrixTags.log
.PARAMETER LogRollover
    The number of days before the log file rolls over. Default is 5 days.
.PARAMETER pc_source
    The Prism Central instance hosting the Source VM and associated Protection Policy.
.PARAMETER UseCustomCredentialFile
    Optional. Specifies that a credential file should be used.
.PARAMETER CredPath
    Optional. The path to the custom credential file.
.PARAMETER Whatif
    Optional. Will process in a whatif mode without actually altering anything.
.PARAMETER TagPrefix
    Optional. Prefix to add to the Citrix Tag when mapped from Nutanix Categories. Default is Nutanix_.
.PARAMETER RemoveOrphanedTags
    Optional. Remove Tags from Citrix Machines that are not present in Nutanix if they match $TagPrefix.
.PARAMETER DDC
    Optional. The Citrix Delivery Controller to connect to.
.PARAMETER Catalog
    Optional. The Citrix Catalog to source machines from. If not used, all machines will be returned.
.PARAMETER Mode
    The mode to run the script in. PrismToCitrix or CitrixToPrism.
.PARAMETER CitrixDaaS
    Optional. Specifies that the script is to be run against Citrix DaaS.
.PARAMETER SecureClientFile
    Optional. Path to the Citrix Cloud Secure Client CSV. Mandatory if CitrixDaaS is specified.
.PARAMETER Region
    Optional. The Citrix Cloud DaaS Tenant Region. Either AP-S (Asia Pacific), US (USA), EU (Europe) or JP (Japan). Mandatory if CitrixDaaS is specified.
.PARAMETER CustomerID
    Optional. The Citrix Cloud Customer ID. Mandatory if CitrixDaaS is specified.
.PARAMETER PlaybookMode
    Optional. Switch. Specifies that the script is to be run in Playbook mode.
.PARAMETER PrismUser
    Optional. The Prism Central User to use for Playbook mode. Mandatory if PlaybookMode is specified.
.PARAMETER PrismPass
    Optional. The Prism Central Password to use for Playbook mode. Mandatory if PlaybookMode is specified.
.PARAMETER cvadUser
    Optional. The Citrix Virtual Apps and Desktops User to use for Playbook mode. Mandatory if PlaybookMode is specified.
.PARAMETER cvadPass
    Optional. The Citrix Virtual Apps and Desktops Password to use for Playbook mode. Mandatory if PlaybookMode is specified.
.NOTES
.EXAMPLE
    .\MapPCVMCategoriestoCitrixTagsPlaybookStyle.ps1 -Mode "PrismToCitrix" -pc_source "1.1.1.1" -TagPrefix "Nutanix_" -RemoveOrphanedTags -DDC "2.2.2.2" -Catalog "Catalog" -Whatif
.EXAMPLE
    .\MapPCVMCategoriestoCitrixTagsPlaybookStyle.ps1 -Mode "PrismToCitrix" -pc_source "1.1.1.1" -TagPrefix "Nutanix_" -RemoveOrphanedTags -CitrixDaaS -CustomerID "fake_cust_id" -SecureClientFile "c:\temp\fakesecret.csv" -Region "US" -Catalog "Catalog" -Whatif
.EXAMPLE
    .\MapPCVMCategoriestoCitrixTagsPlaybookStyle.ps1 -Mode "CitrixToPrism" -pc_source "1.1.1.1" -TagPrefix "Nutanix_" -DDC "2.2.2.2" -Catalog "Catalog" -Whatif
#>
#region Params
# ============================================================================
# Parameters
# ============================================================================
Param(
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\MapPCVMCategoriestoCitrixTags.log", # Where we log to

    [Parameter(Mandatory = $false)]
    [int]$LogRollover = 5, # Number of days before logfile rollover occurs

    [Parameter(Mandatory = $true)]
    [string]$pc_source, # The Prism Central Instance hosting the Source VM and associated Protection Policy

    [Parameter(Mandatory = $false)]
    [switch]$UseCustomCredentialFile, # specifies that a credential file should be used

    [Parameter(Mandatory = $false)]
    [String]$CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials", # Default path for custom credential file

    [Parameter(Mandatory = $false)]
    [switch]$Whatif, # will process in a whatif mode without actually altering anything

    [Parameter(Mandatory = $false)]
    [string]$TagPrefix = "Nutanix_", # Prefix to add to the Nutanix Categories

    [Parameter(Mandatory = $false)]
    [switch]$RemoveOrphanedTags, # Remove Tags from Citrix that are not present in Nutanix if they match $TagPrefix

    [Parameter(Mandatory = $false)]
    [string]$DDC, # The Citrix Delivery Controller to connect to

    [Parameter(Mandatory = $false)]
    [string]$Catalog, # The Citrix Catalog to source machines from

    [Parameter(Mandatory = $true)]
    [ValidateSet("PrismToCitrix", "CitrixToPrism")]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [switch]$CitrixDaaS,

    [Parameter(Mandatory = $false)]
    [ValidateSet("AP-S", "EU", "US", "JP")]
    [string]$Region, # The Citrix DaaS Tenant region

    [Parameter(Mandatory = $false)]
    [string]$CustomerID, # The Citrix DaaS Customer ID

    [Parameter(Mandatory = $false)]
    [string]$SecureClientFile, # Path to the Citrix Cloud Secure Client CSV.

    #------------------------------------------------------------------------------------------------------
    # Nutanix Playbook Logic
    [Parameter(Mandatory = $false)]
    [switch]$PlaybookMode,

    [Parameter(Mandatory = $false)]
    [string]$PrismUser,

    [Parameter(Mandatory = $false)]
    [string]$PrismPass,

    [Parameter(Mandatory = $false)]
    [string]$cvadUser,

    [Parameter(Mandatory = $false)]
    [string]$cvadPass
    # Nutanix Playbook Logic
    #------------------------------------------------------------------------------------------------------

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
            #Write-Log -Message "Payload: $payload" -Level Info
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

function Get-Prismv3Task {
    param (
        [parameter(mandatory = $true)]
        [string]$TaskID, #ID of the task to grab

        [parameter(mandatory = $true)]
        [string]$pc_source,

        [parameter(mandatory = $false)]
        [int]$Sleeptime = 5,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $Method = "GET"
    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($TaskId)"
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

function Get-PCVMIncrements {
    param (
        [parameter(mandatory = $true)][int]$offset,
        [parameter(mandatory = $true)][int]$length
    )

    begin {
        Write-Log -Message "[VM Retrieval] Retrieving machines from offset $($offset) under PC: $($pc_source)" -Level Info
    }
    process {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "POST"
        $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/list"
        $PayloadContent = @{
            kind   = "vm"
            length = $length
            offset = $offset
        }
        $Payload = (ConvertTo-Json $PayloadContent)
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $vm_list = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
            $vm_list = $vm_list.entities
            Write-Log -Message "[VM Retrieval] Retrieved $($vm_list.Count) virtual machines from offset $($Offset) under PC: $($pc_source)" -Level Info
        }
        catch {
            Write-Log -Message "[VM Retrieval] Failed to retrieve virtual machines from $($pc_source)" -Level Warn
            StopIteration
            Exit 1
        }

        }
    end {
        return $vm_list
    }

}

function Get-PCCategoryIncrements {
    param (
        [parameter(mandatory = $true)][int]$offset,
        [parameter(mandatory = $true)][int]$length
    )

    begin {
        Write-Log -Message "[Category Retrieval] Retrieving Categories from offset $($offset) under PC: $($pc_source)" -Level Info
    }

    process {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "POST"
        $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/categories/list"
        $PayloadContent = @{
            kind   = "category"
            length = $length
            offset = $offset
        }
        $Payload = (ConvertTo-Json $PayloadContent)
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $category_list = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
            $category_list = $category_list.entities.name
            Write-Log -Message "[Category Retrieval] Retrieved $($category_list.Count) Categories from offset $($Offset) under PC: $($pc_source)" -Level Info
        }
        catch {
            Write-Log -Message "[Category Retrieval] Failed to retrieve Categories from $($pc_source)" -Level Warn
            StopIteration
            Exit 1
        }
    }

    end {
        return $category_list
    }
}

function Get-CVADAuthDetailsAPI {
    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential
    )

    #--------------------------------------------
    # Get the CVAD Access Token
    #--------------------------------------------
    Write-Log -Message "[CVAD Auth] Retrieving CVAD Access Token" -Level Info
    $TokenURL = "https://$DDC/cvad/manage/Tokens"
    $Headers = @{
        Accept = "application/json"
        Authorization = "Basic $EncodedAdminCredential"
    }

    try {
        $Response = Invoke-WebRequest -Uri $TokenURL -Method Post -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        Write-Log -Message "[CVAD Auth] Failed to return token. Exiting" -Level Error
        Exit 1
    }
    
    $AccessToken = $Response.Content | ConvertFrom-Json

    if (-not ([string]::IsNullOrEmpty($AccessToken))) {
        Write-Log -Message "[CVAD Auth] Successfully returned Token" -Level Info
    }
    else {
        Write-Log -Message "[CVAD Auth] Failed to return token. Exiting" -Level Error
        Exit 1
    }

    #--------------------------------------------
    # Get the CVAD Site ID
    #--------------------------------------------
    Write-Log -Message "[CVAD Auth] Retrieving CVAD Site ID" -Level Info

    $URL = "https://$DDC/cvad/manage/Me"
    $Headers = @{
        "Accept"            = "application/json";
        "Authorization"     = "CWSAuth Bearer=$($AccessToken.Token)";
        "Citrix-CustomerId" = "CitrixOnPremises";
    }

    try {
        $Response = Invoke-WebRequest -Uri $URL -Method Get -Header $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        Write-Log -Message "[CVAD Auth] Failed to return Site ID. Exiting" -Level Error
        Exit 1
    }

    $SiteID = $Response.Content | ConvertFrom-Json

    if (-not ([String]::IsNullOrEmpty($SiteID))) {
        Write-Log -Message "[CVAD Auth] Successfully returned CVAD Site ID: $($SiteID.Customers.Sites.Id)" -Level Info
    }
    else {
        Write-Log -Message "[CVAD Auth] Failed to return Site ID. Exiting" -Level Error
        Exit 1
    }

    #--------------------------------------------
    # Set the headers
    #--------------------------------------------

    Write-Log -Message "[CVAD Auth] Set Standard Auth Headers for CVAD API Calls" -Level Info
    $Headers = @{
        "Accept"            = "application/json";
        "Authorization"     = "CWSAuth Bearer=$($AccessToken.Token)";
        "Citrix-CustomerId" = "CitrixOnPremises";
        "Citrix-InstanceId" = "$($SiteID.Customers.Sites.Id)";
    }

    # we need to send back the headers for use in future calls
    Return $Headers
}

function Get-CVADTagsAPI {
    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][Hashtable]$Headers
    )

    $BrokerTagsTotal = [System.Collections.ArrayList] @()
    $ContinuationToken = $null

    do {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Get"
        $RequestUri = "https://$DDC/cvad/manage/Tags?limit=1000"
        if ($ContinuationToken) {
            $RequestUri += "&continuationToken=$($ContinuationToken)"
        }
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            if (-not $ContinuationToken) {
                Write-Log -Message "[CVAD Tag] Getting Broker Tags from $($DDC)" -Level Info
            } else {
                Write-Log -Message "[CVAD Tag] Getting additional Broker Tags from $($DDC) with continuation token" -Level Info
            }
            
            $BrokerTags = Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
            $BrokerTagsTotal.AddRange($BrokerTags.Items)

            if ($BrokerTags.ContinuationToken) {
                $ContinuationToken = $BrokerTags.ContinuationToken
            } else {
                $ContinuationToken = $null
            }
        }
        catch {
            Write-Log -Message $_ -Level Error
            Break
        }

    } while ($ContinuationToken)

    # Return the list of Tags
    if (($BrokerTagsTotal | Measure-Object).Count -gt 0) {
        Write-Log -Message "[CVAD Tag] Retrieved $(($BrokerTagsTotal | Measure-Object).Count) Tags from $($DDC)" -Level Info
        return $BrokerTagsTotal
    }
    else {
        Write-Log -Message "[CVAD Tag] No Tags returned from $($DDC)" -Level Warn
        return $null
    }
}

function Add-NewCVADTagAPI {
    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][Hashtable]$Headers,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$Tag
    )

    #----------------------------------------------------------------------------------------------------------------------------
    # Set API call detail
    #----------------------------------------------------------------------------------------------------------------------------
    $Method = "Post"
    $RequestUri = "https://$DDC/cvad/manage/Tags"
    $ContentType = "application/json"
    $PayloadContent = @{
        Name = $Tag
        Description = "Nutanix Prism Central Category"
    }
    $Payload = (ConvertTo-Json $PayloadContent -Depth 4)
    #----------------------------------------------------------------------------------------------------------------------------

    try {
        Write-Log -Message "[CVAD Tag] Attempting to create Tag $($Tag) on Delivery Controller $($DDC)" -Level Info
        $TagCreated = Invoke-RestMethod -Method $Method -Headers $Headers -Body $Payload -Uri $RequestUri -SkipCertificateCheck -ContentType $ContentType -TimeoutSec 2400 -ErrorAction Stop
    }
    catch {
        Write-Log -Message $_ -Level Error
        Break
    }

    return $TagCreated
}

function Get-CVADVMListAPI {
    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][Hashtable]$Headers,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $false)][string]$Catalog
    )

    $BrokerVMsTotal = [System.Collections.ArrayList] @()
    $ContinuationToken = $null

    do {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Get"
        if ($Catalog) {
            $RequestUri = "https://$DDC/cvad/manage/MachineCatalogs/$($Catalog)/Machines?limit=1000"
            if ($ContinuationToken) {
                $RequestUri += "&continuationToken=$($ContinuationToken)"
            }
        } else {
            $RequestUri = "https://$DDC/cvad/manage/Machines?limit=1000"
            if ($ContinuationToken) {
                $RequestUri += "&continuationToken=$($ContinuationToken)"
            }
        }
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            if (-not $ContinuationToken) {
                Write-Log -Message "[CVAD Machines] Getting Broker VMs from $($DDC)" -Level Info
            } else {
                Write-Log -Message "[CVAD Machines] Getting additional Broker VMs from $($DDC) with continuation token" -Level Info
            }
            
            $BrokerVMs = Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
            $BrokerVMsTotal.AddRange($BrokerVMs.Items)
    
            if ($BrokerVMs.ContinuationToken) {
                $ContinuationToken = $BrokerVMs.ContinuationToken
            } else {
                $ContinuationToken = $null
            }
        }
        catch {
            Write-Log -Message $_ -Level Error
            Break
        }
    } while ($ContinuationToken)

    # Return the list of VMs
    if ($BrokerVMsTotal.Count -gt 0) {
        Write-Log -Message "[CVAD Machines] Retrieved $($BrokerVMsTotal.Count) machines from $($DDC)" -Level Info
        return $BrokerVMsTotal
    } else {
        Write-Log -Message "[CVAD Machines] No machines returned from $($DDC)" -Level Warn
        return $null
    }

}

function Set-CVADVMTagAPI {
    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][Hashtable]$Headers,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$VMID,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$Tag,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][ValidateSet("Add", "Remove")][string]$Mode
    )

    if ($Mode -eq "Add") {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Post"
        $RequestUri = "https://$DDC/cvad/manage/Machines/$VMID/Tags/$Tag"
        $ContentType = "application/json"
        #----------------------------------------------------------------------------------------------------------------------------

        try {
            $TagAssigned = Invoke-RestMethod -Method $Method -Headers $Headers -Uri $RequestUri -SkipCertificateCheck -ContentType $ContentType -TimeoutSec 2400 -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
            Break
        }

        return $TagAssigned

    } elseif ($Mode -eq "Remove") {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Delete"
        $RequestUri = "https://$DDC/cvad/manage/Machines/$VMID/Tags/$Tag"
        $ContentType = "application/json"
        #----------------------------------------------------------------------------------------------------------------------------

        try {
            $TagRemoved = Invoke-RestMethod -Method $Method -Headers $Headers -Uri $RequestUri -SkipCertificateCheck -ContentType $ContentType -TimeoutSec 2400 -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
            Break
        }

        return $TagRemoved
    }
    
}

function ValidateCitrixCloud {
    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][Hashtable]$Headers

    )

    try {
        Write-Log -Message "[Cloud Site Handling] Testing Site Access" -Level Info
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Get"
        $RequestUri = "https://$($CloudUrl)/cvadapis/Sites/cloudxdsite"
        #----------------------------------------------------------------------------------------------------------------------------
        $cloud_site = Invoke-RestMethod -Method $Method -Headers $headers -Uri $RequestUri -ErrorAction Stop
        Write-Log -Message "[Cloud Site Handling] Retreived Cloud Site details for $($cloud_site.Name)" -Level Info
    }
    catch {
        Write-Log -Message "[Cloud Site Handling] Failed to retrieve cloud site details" -Level Warn
        Write-Log -Message $_ -Level Warn
        StopIteration
        Exit 1
    }
}

function Get-CCAccessToken {
    param (
        [string]$ClientID,
        [string]$ClientSecret
    )
    $TokenURL = "https://$($CloudUrl)/cctrustoauth2/root/tokens/clients"
    $Body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientID
        client_secret = $ClientSecret
    }
    $Response = Invoke-WebRequest $tokenUrl -Method POST -Body $Body -UseBasicParsing
    $AccessToken = $Response.Content | ConvertFrom-Json
    return $AccessToken.access_token
}

function Get-CCSiteID {
    param (
        [Parameter(Mandatory = $true)]
        [string] $AccessToken,
        [Parameter(Mandatory = $true)]
        [string] $CustomerID
    )
    $RequestUri = "https://$($CloudUrl)/cvadapis/me"
    $Headers = @{
        "Accept"            = "application/json";
        "Authorization"     = "CWSAuth Bearer=$AccessToken";
        "Citrix-CustomerId" = $CustomerID;
    }
    $Response = Invoke-RestMethod -Uri $RequestUri -Method GET -Headers $Headers
    return $Response.Customers.Sites.Id
}

#endregion

#region Variables
$length = 500 # How many items to pull back on VM and Category API calls
$api_batch_increment = $length # The batch increment to use when pulling back VMs and Categories
$SleepTime = 5 # The time to wait between API retry on category assign fail
#endregion Variables

#Region Execute
# ============================================================================
# Execute
# ============================================================================
StartIteration

#region script parameter reporting
# ============================================================================
# Script processing detailed reporting
# ============================================================================
Write-Log -Message "[Script Params] Logging Script Parameter configurations" -Level Info
Write-Log -Message "[Script Params] Script LogPath = $($LogPath)" -Level Info
Write-Log -Message "[Script Params] Script LogRollover = $($LogRollover)" -Level Info
Write-Log -Message "[Script Params] Script Whatif = $($Whatif)" -Level Info
Write-Log -Message "[Script Params] Nutanix pc_source = $($pc_source)" -Level Info
Write-Log -Message "[Script Params] Nutanix UseCustomCredentialFile = $($UseCustomCredentialFile)" -Level Info
Write-Log -Message "[Script Params] Nutanix CredPath = $($CredPath)" -Level Info
Write-Log -Message "[Script Params] Nutanix TagPrefix = $($TagPrefix)" -Level Info
if ($DDC) {
    Write-Log -Message "[Script Params] DDC = $($DDC)" -Level Info
}
Write-Log -Message "[Script Params] Citrix DaaS = $($CitrixDaaS)" -Level Info
if ($CitrixDaaS){
    Write-Log -Message "[Script Params] Citrix DaaS Region = $($Region)" -Level Info
    Write-Log -Message "[Script Params] Citrix DaaS SecureClientFile = $($SecureClientFile)" -Level Info
    Write-Log -Message "[Script Params] Citrix DaaS CustomerID = $($CustomerID)" -Level Info
}
if ($Catalog) {
    Write-Log -Message "[Script Params] Catalog = $($Catalog)" -Level Info
}
Write-Log -Message "[Script Params] RemoveOrphanedTags = $($RemoveOrphanedTags)" -Level Info
Write-Log -Message "[Script Params] Script Mode = $($Mode)" -Level Info
#------------------------------------------------------------------------------------------------------
# Nutanix Playbook Logic
Write-Log -Message "[Script Params] Playbook Mode = $($PlaybookMode)" -Level Info
Write-Log -Message "[Script Params] Prism User = $($PrismUser)" -Level Info
if ($DDC) {
    Write-Log -Message "[Script Params] CVAD User = $($cvadUser)" -Level Info
}
# Nutanix Playbook Logic
#------------------------------------------------------------------------------------------------------

#endregion script parameter reporting

#region parameter validation
if ($Mode -eq "CitrixToPrism" -and $RemoveOrphanedTags) {
    Write-Log -Message "[PARAM ERROR]: You cannot use RemoveOrphanedVMTags when executing script in CitrixToPrism Mode. Invalid parameter options" -Level Warn; StopIteration; Exit 1
}
if ($DDC -and $CitrixDaaS) {
    Write-Log -Message "[PARAM ERROR]: You cannot use CitrixDaaS and DDC parameters together. Invalid parameter options" -Level Warn; StopIteration; Exit 1
}
if ((-not $DDC) -and (-not $CitrixDaaS)) {
    Write-Log -Message "[PARAM ERROR]: You must provide either a DDC or CitrixDaaS parameter. Invalid parameter options" -Level Warn; StopIteration; Exit 1
}
if ($CitrixDaaS -and (-not $SecureClientFile)) {
    Write-Log -Message "[PARAM ERROR]: You must provide a SecureClientFile when using CitrixDaaS parameter. Invalid parameter options" -Level Warn; StopIteration; Exit 1
}
if ($CitrixDaaS -and (-not $Region)) {
    Write-Log -Message "[PARAM ERROR]: You must provide a Region when using CitrixDaaS parameter. Invalid parameter options" -Level Warn; StopIteration; Exit 1
}
if ($CitrixDaaS -and (-not $CustomerID)) {
    Write-Log -Message "[PARAM ERROR]: You must provide a CustomerID when using CitrixDaaS parameter. Invalid parameter options" -Level Warn; StopIteration; Exit 1
}
#------------------------------------------------------------------------------------------------------
# Nutanix Playbook Logic
if ($PlaybookMode ) {
    if ($DDC -and (-not $CVADUser -or -not $CVADPass)) {
        Write-Log -Message "[PARAM ERROR]: You must provide a CVADUserName and CVADPassword when using DDC parameter. Invalid parameter options" -Level Warn; StopIteration; Exit 1
    }
    if (-not $PrismUser -or -not $PrismPass) {
        Write-Log -Message "[PARAM ERROR]: You must provide a PrismUser and PrismPassword. Invalid parameter options" -Level Warn; StopIteration; Exit 1
    }
}
# Nutanix Playbook Logic
#------------------------------------------------------------------------------------------------------
#endregion parameter validation

#check PoSH version - Update this to 7
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Log -Message "This script requires PowerShell 7 or later. Please upgrade your PowerShell version." -Level Error
    StopIteration
    Exit 1
}

#------------------------------------------------------------
# Common Execution Components
#------------------------------------------------------------

#region Section Common Execution Components

#region Prism Authentication
#------------------------------------------------------------
# Handle Authentication - Prism Central
#------------------------------------------------------------

#------------------------------------------------------------------------------------------------------
# Nutanix Playbook Logic
if ($PlaybookMode) {
    $securePrismPass = $PrismPass | ConvertTo-SecureString -AsPlainText -Force
    # Create the credential object
    $PrismCentralCredentials = New-Object System.Management.Automation.PSCredential ($PrismUser, $securePrismPass)
} else {
    # Nutanix Playbook Logic
    #------------------------------------------------------------------------------------------------------

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
    } else {
        # credentials for PC
        Write-Log -Message "[Credentials] Prompting user for Prism Central credentials" -Level Info
        $PrismCentralCredentials = Get-Credential -Message "Enter Credentials for Prism Central" -Title "Prism Central Credentials for PC: $($pc_source)"
        if (!$PrismCentralCredentials) {
            Write-Log -Message "[Credentials] Failed to set user credentials" -Level Warn
            StopIteration
            Exit 1
        }
    }
}

#endregion Prism Authentication

#region Citrix Cloud Setup
if ($CitrixDaaS){
    #------------------------------------------------------------
    # Set Cloud API URL based on Region
    #------------------------------------------------------------
    switch ($Region) {
        'AP-S' { 
            $CloudUrl = "api-ap-s.cloud.com"
        }
        'EU' {
            $CloudUrl = "api-eu.cloud.com"
        }
        'US' {
            $CloudUrl = "api-us.cloud.com"
        }
        'JP' {
            $CloudUrl = "api.citrixcloud.jp"
        }
    }

    Write-Log -Message "[Citrix Cloud] Resource URL is $($CloudUrl)" -Level Info

    #region Citrix Auth
    #------------------------------------------------------------
    # Handle Secure Client CSV Input
    #------------------------------------------------------------
    if ($SecureClientFile) {
        Write-Log -Message "[Citrix Cloud] Importing Secure Client: $($SecureClientFile)" -Level Info
        try {
            $SecureClient = Import-Csv -Path $SecureClientFile -ErrorAction Stop
            $ClientID = $SecureClient.ID
            $ClientSecret = $SecureClient.Secret
        }
        catch {
            Write-Log -Message "[Citrix Cloud] Failed to import Secure Client File" -Level Warn
            Exit 1
            StopIteration
        }
    }

    #------------------------------------------------------------
    # Authenticate against Citrix Cloud DaaS and grab Site info
    #------------------------------------------------------------
    Write-Log -Message "[Citrix Cloud] Creating Citrix Cloud acccess token" -Level Info
    $AccessToken = Get-CCAccessToken -ClientID $ClientID -ClientSecret $ClientSecret

    Write-Log -Message "[Citrix Cloud] Getting Citrix Cloud Site ID" -Level Info
    $SiteID = Get-CCSiteID -CustomerID $CustomerID -AccessToken $AccessToken 
    Write-Log -Message "[Citrix Cloud] Citrix Cloud Site ID is: $($SiteID)" -Level Info

    #------------------------------------------------------------
    # Set Auth Headers for Citrix DaaS API calls
    #------------------------------------------------------------
    $daas_headers = @{
        Authorization       = "CwsAuth Bearer=$($AccessToken)"
        'Citrix-CustomerId' = $CustomerID
        Accept              = 'application/json'
        'Citrix-InstanceId'   = $SiteID
    }
    #endregion Citrix Auth

    ValidateCitrixCloud -Headers $daas_headers
}
#endregion Citrix Cloud Setup

#region CVAD Authentication
if ($DDC) {
    #------------------------------------------------------------
    # Handle Authentication - Citrix Virtual Apps and Desktops
    #------------------------------------------------------------

    #------------------------------------------------------------------------------------------------------
    # Nutanix Playbook Logic
    if ($PlaybookMode) {
        $secureCvadPass = $cvadPass | ConvertTo-SecureString -AsPlainText -Force
        # Create the credential object
        $cvad_credentials = New-Object System.Management.Automation.PSCredential ($cvadUser, $secureCvadPass)

        $cvad_pw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cvad_credentials.password))
        $AdminCredential = "$($cvad_credentials.username):$($cvad_pw)"
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($AdminCredential)
        $EncodedAdminCredential = [Convert]::ToBase64String($Bytes)

        # Check Citrix API accessible
        $cvad_headers = Get-CVADAuthDetailsAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential

    } else {
        # Nutanix Playbook Logic
        #------------------------------------------------------------------------------------------------------
        if ($UseCustomCredentialFile) {
            # credentials for CVAD
            $cvad_creds = "cvad-creds"
            Write-Log -Message "[Credentials] UseCustomCredentialFile has been selected. Attempting to retrieve credential object" -Level Info
            try {
                $cvad_credentials = Get-CustomCredentials -credname $cvad_creds  -ErrorAction Stop
            }
            catch {
                Set-CustomCredentials -credname $cvad_creds 
                $cvad_credentials = Get-CustomCredentials -credname $cvad_creds  -ErrorAction Stop
            }
            $cvad_pw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cvad_credentials.password))
            $AdminCredential = "$($cvad_credentials.username):$($cvad_pw)"
            $Bytes = [System.Text.Encoding]::UTF8.GetBytes($AdminCredential)
            $EncodedAdminCredential = [Convert]::ToBase64String($Bytes) 
        } else {
            # credentials for CVAD
            Write-Log -Message "[Credentials] Prompting user for CVAD credentials" -Level Info
            $cvad_credentials = Get-Credential -Message "Enter Credentials for Citrix Virtual Apps and Desktops" -Title "CVAD Credentials for DDC: $($DDC)"
            if (!$cvad_credentials) {
                Write-Log -Message "[Credentials] Failed to set user credentials" -Level Warn
                StopIteration
                Exit 1
            }
            $cvad_pw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cvad_credentials.password))
            $AdminCredential = "$($cvad_credentials.username):$($cvad_pw)"
            $Bytes = [System.Text.Encoding]::UTF8.GetBytes($AdminCredential)
            $EncodedAdminCredential = [Convert]::ToBase64String($Bytes)
        }

        # Check Citrix API accessible
        $cvad_headers = Get-CVADAuthDetailsAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
    }
    
}
#endregion CVAD Authentication

#region Get VM list - Prism Central
#---------------------------------------------
## Get the list of VMs based on name match
#---------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "POST"
$RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/list"
$PayloadContent = @{
    kind   = "vm"
    length = $length
}
$Payload = (ConvertTo-Json $PayloadContent)
#----------------------------------------------------------------------------------------------------------------------------

try {
    $VirtualMachines = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
    $vm_total_entity_count = $VirtualMachines.metadata.total_matches
}
catch {
    Write-Log -Message "[VM Retrieval] Failed to retrieve virtual machines from $($pc_source)" -Level Warn
    Break
}

$VirtualMachines = $VirtualMachines.entities

if ($null -ne $VirtualMachines) {
    Write-Log -Message "[VM Retrieval] Retrieved $($VirtualMachines.Count) virtual machines under PC: $($pc_source)" -Level Info
} else {
    Write-Log -Message "[VM Retrieval] Failed to retrieve virtual machine info from $($pc_source)" -Level Error
    StopIteration
    Exit 1
}

#region bulk machine retrieval from PC

# Configuration Limit reached - bail
if ($vm_total_entity_count -gt 25000) {
    Write-Log -Message "[VM Retrieval] 25K VM limit reached. This is not a supported configuration. Exiting script." -Level Warn
    StopIteration
    Exit 1
}

if ($vm_total_entity_count -gt $length) {

    Write-Log -Message "[VM Retrieval] $($vm_total_entity_count) virtual machines exist under PC: $($pc_source). Looping through batch pulls" -Level Info

    $VirtualMachinesMasterList = [System.Collections.ArrayList] @()
    $VirtualMachinesMasterList.AddRange(@($VirtualMachines)) 

    # iterate through increments of 500 ($api_batch_increment) until the offset reaches or exceeds the value of $vm_total_entity_count.
    for ($offset = $api_batch_increment; $offset -lt $vm_total_entity_count; $offset += $api_batch_increment) {
        $vm_offset = $offset
        $AdditionalVirtualMachines = Get-PCVMIncrements -offset $vm_offset -length $length
        $VirtualMachinesMasterList.AddRange(@($AdditionalVirtualMachines))

        Write-Log -Message "[VM Retrieval] Retrieved VM Count is $($VirtualMachinesMasterList.Count) under PC: $($pc_source)" -Level Info
    }

    $VirtualMachines = $VirtualMachinesMasterList
}
#endregion bulk machine retrievale from PC

$TargetCount = ($VirtualMachines.status.name).count

if (-not ($TargetCount -gt 0)) {
    Write-Log -Message "[VM Retrieval] Failed to retrieve any machines from $($pc_source)" -Level Warn
    StopIteration
    Exit 0
}
#endregion Get VM list  - Prism Central

#region Get Citrix Tags
#------------------------------------------------------------------------------------------

$CitrixTagMasterList = [System.Collections.ArrayList] @()

if ($DDC){
    $CitrixTags = Get-CVADTagsAPI -DDC $DDC -Headers $cvad_headers
} elseif ($CitrixDaaS) {
    $CitrixTags = Get-CVADTagsAPI -DDC $CloudUrl -Headers $daas_headers
}

if ($null -eq $CitrixTags) {
    Write-Log -Message "[CVAD Tag] No Citrix Tags found" -Level Warn
    StopIteration
    Exit 0
}

$CitrixTagMasterList.AddRange(@($CitrixTags.Name)) # Ensure the item is treated as a collection

#endregion Get Citrix Tags

#region Get VM list - Citrix API
#------------------------------------------------------------------------------------------

$CitrixVMMasterList = [System.Collections.ArrayList] @()

if ($DDC) {
    if ($Catalog) {
        $CitrixMachines = Get-CVADVMListAPI -DDC $DDC -Headers $cvad_headers -Catalog $Catalog
    } else {
        $CitrixMachines = Get-CVADVMListAPI -DDC $DDC -Headers $cvad_headers
    }
} elseif ($CitrixDaaS) {
    if ($Catalog) {
        $CitrixMachines = Get-CVADVMListAPI -DDC $CloudUrl -Headers $daas_headers -Catalog $Catalog
    } else {
        $CitrixMachines = Get-CVADVMListAPI -DDC $CloudUrl -Headers $daas_headers
    }
}

if ($null -eq $CitrixMachines) {
    Write-Log -Message "No Citrix Machines found" -Level Warn
    StopIteration
    Exit 0
}

$CitrixVMMasterList.AddRange($CitrixMachines)

#endregion Get VM list - Citrix API

#region Filter VMs to a target list
#------------------------------------------------------------------------------------------
$vm_list = $VirtualMachines | Where-Object {$_.status.name -in $CitrixVMMasterList.Hosting.HostedMachineName} 
#endregion Filter VMs to a target list

#endregion Section Common Execution Components

#------------------------------------------------------------
# Prism Central Category to Citrix Tag Mapping
#------------------------------------------------------------

#region Section: Prism to Citrix Tag Mapping

if ($Mode -eq "PrismToCitrix") {
    #region sort out unique Nutanix categories

    # Initialize an array to hold the values
    $NutanixCategoriesMasterList = [System.Collections.ArrayList] @()

    # Get the Categories List from all VMs. This will be made unique shortly and used to look at Citrix Tags
    $categoriesMapping = ($vm_list | Where-Object { $_.metadata.categories_mapping -ne $null -and $_.metadata.categories_mapping.PSObject.Properties.Count -gt 0 }).metadata.categories_mapping

    # Loop through the object and collect the values
    foreach ($Mapping in $categoriesMapping) {
        $Mapping.PSObject.Properties | ForEach-Object {
            $propertyName = $_.Name 
            foreach ($value in $_.Value) { # values can be an array, build a nice paired object entry
                $CategoryObject = @{
                    "Pairing" = $TagPrefix + $propertyName + "_" + $value
                }
                [void]$NutanixCategoriesMasterList.Add($CategoryObject)
            }
        }
    }

    Write-Log -Message "[Nutanix Categories] Found $($NutanixCategoriesMasterList.Count) Nutanix Category pairings across $($vm_list.Count) VMs" -Level Info
    $UniqueNutanixCategories = $NutanixCategoriesMasterList.Values | Sort-Object -Unique 
    Write-Log -Message "[Nutanix Categories] Found $($UniqueNutanixCategories.Count) unique Nutanix Category pairings across $($vm_list.Count) VMs" -Level Info

    #endregion sort out unique Nutanix categories

    #region Map Nutanix Categories to Citrix Tags and Create Citrix Tags
    #------------------------------------------------------------------------------------------
    foreach ($NutanixCat in $UniqueNutanixCategories) {
        if ($CitrixTagMasterList -notcontains $NutanixCat) {
            if ($Whatif) {
                # we are in whatif Mode
                Write-Log -Message "[WHATIF] No match found for Nutanix Category: $($NutanixCat) in Citrix Tags. Would create Tag in Citrix" -Level Info
                [void]$CitrixTagMasterList.Add($NutanixCat)
            }
            else {
                # we are processing
                Write-Log -Message "No match found for Nutanix Category: $($NutanixCat) in Citrix Tags. Creating Tag in Citrix" -Level Info
                if ($DDC) {
                    $CreateTag = Add-NewCVADTagAPI -DDC $DDC -Headers $cvad_headers -Tag $NutanixCat
                } elseif ($CitrixDaaS) {
                    $CreateTag = Add-NewCVADTagAPI -DDC $CloudUrl -Headers $daas_headers -Tag $NutanixCat
                }
                
                if ($null -ne $CreateTag) {
                    Write-Log -Message "Successfully created Tag: $($NutanixCat) in Citrix" -Level Info
                    # Add the new Tag Name to the existing Array
                    [void]$CitrixTagMasterList.Add($CreateTag.Name)
                }
                else {
                    Write-Log -Message "Failed to create Tag: $($NutanixCat) in Citrix" -Level Error
                }
            } 
        }
    }
    #endregion Map Nutanix Categories to Citrix Tags and Create Citrix Tags

    #region Assign Citrix Tags to VMs
    #------------------------------------------------------------------------------------------
    foreach ($vm in $vm_list) {
        $ctx_vm_id = ($CitrixVMMasterList | Where-Object {$_.Hosting.HostedMachineName -eq $vm.status.name}).Id
        $ctx_vm_name = ($CitrixVMMasterList | Where-Object {$_.Hosting.HostedMachineName -eq $vm.status.name}).Hosting.HostedMachineName
        $ctx_vm_tag_list = ($CitrixVMMasterList | Where-Object {$_.Hosting.HostedMachineName -eq $vm.status.name}).Tags
        #--------------------------------------------------------------
        # Assign the Nutanix Categories to the VM as Citrix Tags
        #--------------------------------------------------------------
        foreach ($category in $vm.metadata.categories_mapping.PSObject.Properties) { 
            foreach ($value in $category.Value) {
                $tag = $TagPrefix + $category.Name + "_" + $value
                # Check if the Tag is in the Citrix Tag List and not already assigned to the VM
                if (($CitrixTagMasterList -contains $tag) -and ($tag -notin $ctx_vm_tag_list)) {
                    # Assign the Tag to the VM
                    if ($Whatif) {
                        # we are in whatif mode
                        Write-Log -Message "[WHATIF] [VM: $($ctx_vm_name)] Would assign Tag: $($tag)" -Level Info
                        $ctx_vm_tag_list += $tag
                    } else {
                        # We are processing
                        Write-Log -Message "[VM: $($ctx_vm_name)] Assigning Tag: $($tag)" -Level Info
                        if ($DDC){
                            $TagAssigned = Set-CVADVMTagAPI -DDC $DDC -Headers $cvad_headers -VMID $ctx_vm_id -Tag $tag -Mode Add
                        } elseif ($CitrixDaaS) {
                            $TagAssigned = Set-CVADVMTagAPI -DDC $CloudUrl -Headers $daas_headers -VMID $ctx_vm_id -Tag $tag -Mode Add
                        }
                        
                        if ($null -ne $TagAssigned) {
                            Write-Log -Message "[VM: $($ctx_vm_name)] Successfully assigned Tag: $($tag)" -Level Info
                            $ctx_vm_tag_list += $tag
                        } else {
                            Write-Log -Message "[VM: $($ctx_vm_name)] Failed to assign Tag: $($tag)" -Level Error
                        }
                    }
                    
                } else {
                    Write-Log -Message "[VM: $($ctx_vm_name)] Tag: $($tag) already assigned. Skipping assignment" -Level Info
                }
            }
        }

        #--------------------------------------------------------------
        # Check to see if the VM has any tags that are no longer present in PC and need to be removed
        #--------------------------------------------------------------
        #region build a list of Nutanix Categories for this VM
        # Build a list of Nutanix Categories for this VM
        $nutanix_vm_categories_master_list = [System.Collections.ArrayList] @()
        # Learn about the machines categories
        $vm_categories_assigned = $VM.metadata.categories_mapping

        # Categories exist, loop through them and build a list of Nutanix Categories
        $vm_categories_assigned.PSObject.Properties | ForEach-Object {
            $propertyName = $_.Name 
            foreach ($value in $_.Value) { # values can be an array, build a nice paired object entry
                $CategoryObject = @{
                    "Pairing" = $TagPrefix + $propertyName + "_" + $value
                }
                [void]$nutanix_vm_categories_master_list.Add($CategoryObject)
            }
        }
        #endregion build a list of Nutanix Categories for this VM

        foreach ($tag in $ctx_vm_tag_list){
            if (($tag -match $TagPrefix -and $nutanix_vm_categories_master_list.Pairing -notcontains $Tag) ) {
                if ($RemoveOrphanedTags){
                    # Remove the Tag from the VM
                    if ($Whatif) {
                        # we are in whatif mode
                        Write-Log -Message "[WHATIF] [VM: $($ctx_vm_name)] Would remove Tag: $($tag)" -Level Info
                    } else {
                        # We are processing
                        Write-Log -Message "[VM: $($ctx_vm_name)] Removing Tag: $($tag)" -Level Info
                        if ($DDC){
                            $TagRemoved = Set-CVADVMTagAPI -DDC $DDC -Headers $cvad_headers -VMID $ctx_vm_id -Tag $tag -Mode Remove
                        } elseif ($CitrixDaaS) {
                            $TagRemoved = Set-CVADVMTagAPI -DDC $CloudUrl -Headers $daas_headers -VMID $ctx_vm_id -Tag $tag -Mode Remove
                        }

                        if ($null -ne $TagRemoved) {
                            Write-Log -Message "[VM: $($ctx_vm_name)] Successfully removed Tag: $($tag)" -Level Info
                        } else {
                            Write-Log -Message "[VM: $($ctx_vm_name)] Failed to remove Tag: $($tag)" -Level Error
                        }
                    }
                }
            }
        }
    }
    #endregion Assign Citrix Tags to VMs
}

#endregion Section: Prism to Citrix Tag Mapping

#------------------------------------------------------------
# Citrix Tag to Prism Central Category Mapping
#------------------------------------------------------------

#region Section Citrix Tag to Prism Central Category Mapping

if ($Mode -eq "CitrixToPrism") {
    #region get Nutanix Categories
    # We need an up to date list of all available Nutanix Categories - we want to know all the available categories ones that we can use
    #----------------------------------------------------------------------------------------------------------------------------
    # Set API call detail
    #----------------------------------------------------------------------------------------------------------------------------
    $Method = "Post"
    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/categories/list"
    $PayloadContent = @{
        kind   = "category"
        length = $length
    }
    $Payload = (ConvertTo-Json $PayloadContent)
    #----------------------------------------------------------------------------------------------------------------------------
    try {
        $nutanix_categories = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        $category_total_entity_count = $nutanix_categories.metadata.total_matches
    }
    catch {
        Write-Log -Message "[Category Retrieval] Failed to retrieve categories from $($pc_source)" -Level Warn
        Break
    }

    $nutanix_categories_master_list = $nutanix_categories.entities.name
    Write-Log -Message "[Category Retrieval] Successfully retrieved $($nutanix_categories_master_list.Count) categories from $($pc_source)" -Level Info

    #region bulk category retrieval from PC
    if ($category_total_entity_count -gt $length) {
        Write-Log -Message "[Category Retrieval] $($category_total_entity_count) categories exist under PC: $($pc_source). Looping through batch pulls" -Level Info
    
        $CategoryMasterList = [System.Collections.ArrayList] @()
        $CategoryMasterList.AddRange(@($nutanix_categories_master_list))
    
        # iterate through increments of 500 ($api_batch_increment) until the offset reaches or exceeds the value of $category_total_entity_count.
        for ($offset = $api_batch_increment; $offset -lt $category_total_entity_count; $offset += $api_batch_increment) {
            $category_offset = $offset
            $AdditionalCategories = Get-PCCategoryIncrements -offset $category_offset -length $length
            $CategoryMasterList.AddRange(@($AdditionalCategories))
    
            Write-Log -Message "[Category Retrieval] Retrieved Category count is $($Global:nutanix_categories_master_list.Count) under PC: $($pc_source)" -Level Info
        }
    
        $nutanix_categories_master_list = $CategoryMasterList
    }
    #endregion bulk category retrieval from PC

    #endregion get Nutanix Categories

    #region process the VMs
    # We want to check each VM in this list, to make sure that any tag flagged as Nutanix_ from Citrix, has a matching Category in Nutanix. If it does not, we want to assign it.
    foreach ($VM in $vm_list) {
        Write-Log -Message "[VM: $($VM.status.name)] Processsing VM for Citrix Tag to Nutanix Category match" -Level Info
        #region VM specific Nutanix Categories
        #--------------------------------------------------------------------------------------------------
        # Create a unique list of Nutanix Categories that are assigned to the VM
        #--------------------------------------------------------------------------------------------------
        $nutanix_vm_categories_master_list = [System.Collections.ArrayList] @()

        # Learn about the machines categories
        $vm_categories_assigned = $VM.metadata.categories_mapping

        if ($null -ne $vm_categories_assigned) {
            # Categories exist, loop through them and build a list of Nutanix Categories
            $vm_categories_assigned.PSObject.Properties | ForEach-Object {
                $propertyName = $_.Name 
                foreach ($value in $_.Value) { # values can be an array, build a nice paired object entry
                    $CategoryObject = @{
                        "Pairing" = $TagPrefix + $propertyName + "_" + $value
                    }
                    [void]$nutanix_vm_categories_master_list.Add($CategoryObject)
                }
            }
        } else {
            Write-Log -Message "[VM: $($VM.status.name)] No Categories found for VM" -Level Info
        }
        #endregion VM specific Nutanix Categories

        #region VM specific Citrix Tags
        #--------------------------------------------------------------------------------------------------
        # Create a list of Citrix Tags that are assigned to the VM
        #--------------------------------------------------------------------------------------------------
        $citrix_vm_tag_master_list = ($CitrixVMMasterList | Where-Object {$_.Hosting.HostedMachineName -eq $VM.status.name}).Tags
        #endregion VM specific Citrix Tags

        foreach ($Tag in $citrix_vm_tag_master_list | Where-Object {$_ -like "$TagPrefix*"}) {

            # Check if the Category actually exists in Nutanix - Clean up the values we have first
            $AlteredTag = $Tag -replace "$TagPrefix", ""
            $AlteredTag = $AlteredTag -split "_"
            $NtxCatName = $AlteredTag[0]
            $NtxCatValue = $AlteredTag[1]

            if ($nutanix_vm_categories_master_list.Pairing -notcontains $Tag) {

                Write-Log -Message "[VM: $($VM.status.name)] No Citrix Tag: $($Tag) assignment match found for Nutanix Category: $($NtxCatName):$($NtxCatValue) for VM. Checking Prism for eligibility" -Level Info
                
                if ($NtxCatName -in $nutanix_categories_master_list){
                    # The tag exists, so now we can go and assign to the Nutanix VM
                    Write-Log -Message "[VM: $($VM.status.name)] Match found for Nutanix Category: $($NtxCatName). Validating values" -Level Info
                    # Learn the values for that Category to make sure they align
                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Method = "Post"
                    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/categories/$($NtxCatName)/list"
                    $PayloadContent = @{
                        kind   = "category"
                        length = $length
                    }
                    $Payload = (ConvertTo-Json $PayloadContent)
                    #----------------------------------------------------------------------------------------------------------------------------
                    try {
                        $nutanix_category_values = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
                    }
                    catch {
                        Write-Log -Message "[Category Retrieval] Failed to retrieve category values from $($pc_source)" -Level Warn
                        Break
                    }

                    $nutanix_category_values = $nutanix_category_values.entities.value

                    if ($NtxCatValue -in $nutanix_category_values) {
                        Write-Log -Message "[VM: $($VM.status.name)] Will asssign Nutanix Category with Name: $($NtxCatName) and value: $($NtxCatValue) to the VM" -Level Info
                        #----------------------------------------------------------------------------------------------------------------------------
                        # Set API call detail
                        #----------------------------------------------------------------------------------------------------------------------------
                        $Method = "Get"
                        $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                        $PayLoad = $null
                        #----------------------------------------------------------------------------------------------------------------------------
                        try {
                            $nutanix_vm_detail = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $PayLoad -Credential $PrismCentralCredentials -ErrorAction Stop
                        }
                        catch {
                            Write-Log -Message "[VM: $($VM.status.name)] Failed to retrieve VM details from $($pc_source)" -Level Warn
                            Break
                        }
                        
                        # remove the status object so we can send the config back in
                        $nutanix_vm_detail.PSObject.Properties.Remove('status')

                        # Add the category mapping to the VM
                        $Null = $nutanix_vm_detail.metadata.categories_mapping | Add-Member -MemberType NoteProperty -Name $NtxCatName -Value @($NtxCatValue) -PassThru -ErrorAction Stop

                        if ($Whatif) {
                            # We are in whatif Mode
                            Write-Log -Message "[WHATIF] [VM: $($VM.status.name)] Would assign category $($NtxCatName) with value $($NtxCatValue) to VM" -Level Info
                        } else {
                            # We are processing
                            #----------------------------------------------------------------------------------------------------------------------------
                            # Set API call detail
                            #----------------------------------------------------------------------------------------------------------------------------
                            $Method = "PUT"
                            $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                            $Null = $nutanix_vm_detail.api_version | Add-Member -MemberType NoteProperty -Name "api_version" -Value "3.1" -Force -PassThru -ErrorAction Stop
                            $Null = $nutanix_vm_detail.metadata | Add-Member -MemberType NoteProperty -Name "use_categories_mapping" -Value $true -Force -PassThru -ErrorAction Stop
                            $Payload = (ConvertTo-Json $nutanix_vm_detail -Depth 6)
                            #----------------------------------------------------------------------------------------------------------------------------
                            do {
                                try {
                                    $nutanix_vm_detail_update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $PayLoad -Credential $PrismCentralCredentials -ErrorAction Stop
                                    #Get the status of the task above
                                    $TaskId = $nutanix_vm_detail_update.status.execution_context.task_uuid
                                    $Phase = "[VM: $($VM.status.name)]"
                                    $PhaseSuccessMessage = "VM $($VM.status.name) has been updated"

                                    Get-Prismv3Task -TaskID $TaskId -pc_source $pc_source -Credential $PrismCentralCredentials -Sleeptime $SleepTime

                                }
                                catch {
                                    $saved_error = $_.Exception
                                    $resp_return_code = $_.Exception.Response.StatusCode.value__
                                    if ($resp_return_code -eq 409) {
                                        Write-Log -Message "[VM Update] VM: $($vm) cannot be updated now. Retrying in $($SleepTime) seconds" -Level Warn
                                        Start-Sleep $SleepTime
                                    }
                                    else {
                                        Write-Log -Message $payload -Level Warn
                                        Write-Log -Message "$($saved_error.Message)" -Level Warn
                                        Break
                                    }
                                }
                            }
                            while ($resp_return_code -eq 409)
                        }
                    } else {
                        Write-Log -Message "[VM: $($VM.status.name)] The Nutanix Category $($NtxCatName) does not have a corresponding value: $($NtxCatValue) defined in Nutanix. Please create the value." -Level Warn
                    }
                    
                } else {
                    # The tag does not exist, and we are not creating it in Nutanix, so bye bye
                    Write-Log -Message "[VM: $($VM.status.name)] The defined tag $($Tag) does not have a corresponding Category defined in Prism Central. Please create the Category." -Level Warn
                }
                

            } else {
                # Nothing to do - The Tag in Citrix matches an assigned Category in Nutanix
                Write-Log -Message "[VM: $($VM.status.name)] Match found for Nutanix Category: $($NtxCatName):$($NtxCatValue) " -Level Info
            }
        }

        # Clear the Variables
        $nutanix_vm_categories_master_list = $null
        $citrix_vm_tag_master_list = $null
        
    }
    #endregion process the VMs
}

#endregion Section Citrix Tag to Prism Central Category Mapping

StopIteration
Exit 0
#endregion
