<#
.SYNOPSIS
    Queries a Nutanix environment and a Citrix Cloud DaaS deployment to ensure hosting connection details are accurate between the two.
    Used when migrating persistent workloads (not MCS or PVS provisioned) across different Nutanix Clusters with Prism Element hosting integration.
.DESCRIPTION
    The script is designed to simplify the migration or failover of workloads in a single Citrix DaaS tenant across different Nutanix Clusters.
    Examples include: 
        - A graceful migration of workloads via a Protection Domain migration where the Nutanix UUID is maintained, but the Citrix Hosting connection is different.
        - A disaster recovery scenario where a workload is activated in an alternate cluster and its UUID is changed, such as a Protection Domain Activation event. Both UUID and Hosting Connection will require changing.
    What the script does not do (by design):
        - Handle any form of VDA registration change. You must handle this within your environment as required (GPO etc).
        - Handle any form of Active Directory OU location changes etc (see above point).
        - Interact with a Nutanix Protection Domain outside of querying it for a list of machines if a Protection Domain is used as the source of truth (see parameter description).
    You will need to use a Secure client from Citrix Cloud to use this script https://docs.citrix.com/en-us/citrix-cloud/sdk-api.html#secure-clients
.PARAMETER LogPath
    Optional. Logpath output for all operations. Default is C:\Logs\UpdateDaaSHostedMachineId.log
.PARAMETER LogRollover
    Optional. Number of days before logfiles are rolled over. Default is 5.
.PARAMETER Region
    Mandatory. The Citrix Cloud DaaS Tenant Region. Either AP-S (Asia Pacific), US (USA), EU (Europe) or JP (Japan)
.PARAMETER CustomerID
    Mandatory. The Citrix Cloud Customer ID
.PARAMETER ClientID
    Optional. The Citrix Cloud Secure Client ID. Cannot be used with the SecureClientFile Parameter. Must be combined with the ClientSecret parameter.
.PARAMETER ClientSecret
    Optional. The Citrix Cloud Secure Client Secret. Cannot be used with the SecureClientFile Parameter. Must be used with the ClientID parameter.
.PARAMETER SecureClientFile
    Optional. Path to the Citrix Cloud Secure Client CSV. Cannot be used with ClientID or ClientSecret parameters.
.PARAMETER MaxDaaSVMCount
    Optional. The max number of DaaS VMs to query via API. Default is 1000.
.PARAMETER Domain
    Optional. The NETBIOS domain of the Machine. Used when exceeding 1000 DaaS VM retrieval.
.PARAMETER TargetMachineScope
    Mandatory. The method used to target machine scoping. Can be either:
        - MachineList (an array). used with the TargetMachineList parameter.
        - CSV (a CSV input). Used with the TargetmachineCSVList parameter.
        - NutanixPD (a Nutanix Protection Domain). Used with the NutanixPD parameter.
.PARAMETER TargetMachineList
    Optional. An array of machines to target. "Machine1","Machine2","Machine3". Use the name of the VM in Nutanix. Used with the TargetMachineScope parameter when set to MachineList.
.PARAMETER TargetMachineCSVList
    Optional. A CSV list of machines to target. CSV file must use the "Name" Header. Used with the TargetMachineScope parameter when set to CSV.
.PARAMETER TargetNutanixCluster
    Mandatory. The target Nutanix Cluster hosting the machines to target.
.PARAMETER NutanixPD
    Optional. The Nutanix Protection Domain to target machine scoping. Used with the TargetMachineScope parameter when set to NutanixPD.
.PARAMETER ExclusionList
    Optional. A list of machines to exclude from processing. Used regardless of the the TargetmachineScope parameter.
.PARAMETER TargetHostingConnectionName
    Mandatory The name of the hosting connection to target workload changes to in Citrix DaaS. The hosting connection pointing to the target Nutanix Cluster.
.PARAMETER ResetTargetHostingConnection
    Optional. Reset the Target Hosting Connection if any machine objects are altered. This removes the Sync delay between Citrix DaaS and the Nutanix Hosting platform and allows power status to be retrieved.
.PARAMETER BypassHypervisorTypeCheck
    Optional. An advanced parameter to bypass hypervisor checks. The script supports, by default, only Nutanix Hosting Connection Types: AcropolisPCFactory, AcropolisFactory, AcropolisXIFactory
.PARAMETER SwitchCatalogZoneID
    Optional. In some scenarios, it may be required to set the Catalog to the same ZoneID of the target hosting connection. This swith will align to the two. This impacts all vms in the catalog.
.PARAMETER CatalogNames
    Optional. If ussing the SwitchCatalogZoneID parameter, you must provide Catalog names.
.PARAMETER UseCustomCredentialFile
    Optional. Will call the Get-CustomCredentials function which keeps outputs and inputs a secure credential file base on Stephane Bourdeaud from Nutanix functions
.PARAMETER CredPath
    Optional. Used if using the UseCustomCredentialFile parameter. Defines the location of the credential file. The default is "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
.PARAMETER Whatif
    Optional. Will action the script in a whatif processing mode only.
.EXAMPLE
    .\UpdateDaaSHostedMachineId.ps1 -Region "US" -CustomerID "fakecustID" -SecureClientFile "C:\SecureFolder\secureclient.csv" -TargetMachineScope "NutanixPD" -TargetNutanixCluster "2.2.2.2" -NutanixPD "PD1" -ExclusionList "Machine1" -TargetHostingConnectionName "Nutanix AHV Cluster 2" -ResetTargetHostingConnection -UseCustomCredentialFile -Whatif
    Uses the Citrix Cloud DaaS `US` region. Auth with a SecureClient via CSV. Target machines in the Nutanix Protection Domain "PD1". Query the Nutanix Cluster at 2.2.2.2. Exclude Machine1. Set the Hosting Connection to "Nutanix AH Cluster 2". Reset/Refresh the Hosting Connection. Use a Custom Credential File for Nutanix Auth. Query DaaS for 1000 VMs. Process in whatif Mode
.EXAMPLE
    .\UpdateDaaSHostedMachineId.ps1 -Region "US" -CustomerID "fakecustID" -SecureClientFile "C:\SecureFolder\secureclient.csv" -TargetMachineScope "MachineList" -TargetMachineList "Machine1","Machine2","Machine3","Machine4" -TargetNutanixCluster "2.2.2.2" -TargetHostingConnectionName "Nutanix AHV Cluster 2" -ResetTargetHostingConnection -UseCustomCredentialFile -MaxDaaSVMCount "2000" -Whatif
    Uses the Citrix Cloud DaaS `US` region. Auth with a SecureClient via CSV. Target Machines "Machine1","Machine2","Machine3","Machine4". Query the Nutanix Cluster at 2.2.2.2. Set the Hosting Connection to "Nutanix AH Cluster 2". Reset/Refresh the Hosting Connection. Use a Custom Credential File for Nutanix Auth. Query DaaS for 2000 VMs. Process in whatif Mode
.EXAMPLE
    .\UpdateDaaSHostedMachineId.ps1 -Region "US" -CustomerID "fakecustID" -SecureClientFile "C:\SecureFolder\secureclient.csv" -TargetMachineScope "CSV" -TargetMachineCSVList "C:\Source\targets.csv" -TargetNutanixCluster "1.1.1.1" -TargetHostingConnectionName "Nutanix AHV Cluster 1" -ResetTargetHostingConnection -Whatif
    Uses the Citrix Cloud DaaS `US` region. Auth with a SecureClient via CSV. Import machines to target via the "C:\Source\targets.csv" file. Query the Nutanix Cluster at 1.1.1.1. Set the Hosting Connection to "Nutanix AH Cluster 1". Reset/Refresh the Hosting Connection. Process in whatif Mode
.EXAMPLE
    .\UpdateDaaSHostedMachineId.ps1 -Region "US" -CustomerID "fakecustID" -ClientID "FakeClientID" -ClientSecret "FakeSecret" -TargetMachineScope "NutanixPD" -TargetNutanixCluster "2.2.2.2" -NutanixPD "PD1" -TargetHostingConnectionName "Nutanix AHV Cluster 2" -ResetTargetHostingConnection -UseCustomCredentialFile -Whatif
    Uses the Citrix Cloud DaaS `US` region. Auth with a provided Client ID and Secret. Target machines in the Nutanix Protection Domain "PD1". Query the Nutanix Cluster at 2.2.2.2. Set the Hosting Connection to "Nutanix AH Cluster 2". Reset/Refresh the Hosting Connection. Use a Custom Credential File for Nutanix Auth. Query DaaS for 1000 VMs. Process in whatif Mode
.EXAMPLE
    .\UpdateDaaSHostedMachineId.ps1 -Region "US" -CustomerID "fakecustID" -ClientID "FakeClientID" -ClientSecret "FakeSecret" -TargetMachineScope "NutanixPD" -TargetNutanixCluster "2.2.2.2" -NutanixPD "PD1" -TargetHostingConnectionName "Nutanix AHV Cluster 2" -ResetTargetHostingConnection -MaxDaasVMCount "2000" -Domain "DOMAIN" -UseCustomCredentialFile -Whatif
    Uses the Citrix Cloud DaaS `US` region. Auth with a provided Client ID and Secret. Target machines in the Nutanix Protection Domain "PD1". Query the Nutanix Cluster at 2.2.2.2. Set the Hosting Connection to "Nutanix AH Cluster 2". Reset/Refresh the Hosting Connection. Use a Custom Credential File for Nutanix Auth. Query DaaS for 2000 VMs and use the DOMAIN value to match machines. Process in whatif Mode
.NOTES
    Author: James Kindon, Nutanix, 28.07.23.
#>

#region Params
# ============================================================================
# Parameters
# ============================================================================
Param(
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\UpdateDaaSHostedMachineId.log", # Where we log to

    [Parameter(Mandatory = $false)]
    [int]$LogRollover = 5, # Number of days before logfile rollover occurs

    [Parameter(Mandatory = $true)]
    [ValidateSet("AP-S", "EU", "US", "JP")]
    [string]$Region, # The Citrix DaaS Tenant region
    
    [Parameter(Mandatory = $true)]
    [string]$CustomerID, # The Citrix DaaS Customer ID

    [Parameter(Mandatory = $false)]
    [string]$ClientID, # The Citrix Cloud Secure Client ID.

    [Parameter(Mandatory = $false)]
    [string]$ClientSecret, # The Citrix Cloud Secure Client Secret.

    [Parameter(Mandatory = $false)]
    [string]$SecureClientFile, # Path to the Citrix Cloud Secure Client CSV.

    [Parameter(Mandatory = $false)]
    [int]$MaxDaaSVMCount = 1000, # The max number of DaaS VMs to query via API.

    [Parameter(Mandatory = $false)]
    [string]$Domain, # The NETBIOS domaing name of the machine accounts

    [Parameter(Mandatory = $true)]
    [ValidateSet("MachineList", "CSV", "NutanixPD")]
    [string]$TargetMachineScope, # The method used to target machine scoping.

    [Parameter(Mandatory = $false)]
    [Array]$TargetMachineList, # An array of machines to target.

    [Parameter(Mandatory = $false)]
    [string]$TargetMachineCSVList, # A CSV list of machines to target.

    [Parameter(Mandatory = $true)]
    [string]$TargetNutanixCluster, # The target Nutanix Cluster hosting the machines to target.

    [Parameter(Mandatory = $false)]
    [string]$NutanixPD, # The Nutanix Protection Domain to target machine scoping.

    [Parameter(Mandatory = $false)]
    [array]$ExclusionList, # List of vm names to exclude.

    [Parameter(Mandatory = $true)]
    [String]$TargetHostingConnectionName, # The Target Hosting Connection Name pointing to the Target Nutanix Cluster.

    [Parameter(Mandatory = $false)]
    [Switch]$ResetTargetHostingConnection, # Reset the target Hosting Connection.

    [parameter(mandatory = $false)] 
    [switch]$BypassHypervisorTypeCheck, # An advanced parameter to bypass hypervisor checks.

    [parameter(mandatory = $false)]
    [switch]$SwitchCatalogZoneID, # Align the Catalog to the target hosting connection ZoneID

    [parameter(mandatory = $false)] # An array of Catalogs to switch ZoneID
    [array]$CatalogNames,

    [Parameter(Mandatory = $false)]
    [switch]$UseCustomCredentialFile, # specifies that a credential file should be used

    [Parameter(Mandatory = $false)]
    [String]$CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials", # Default path for custom credential file

    [Parameter(Mandatory = $false)]
    [switch]$Whatif # will process in a whatif mode without actually altering anythin

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

#endregion

#region Variables
# ============================================================================
# Variables
# ============================================================================
$SupportedHypervisorPlugTypes = @("AcropolisPCFactory","AcropolisFactory","AcropolisXIFactory")
#endregion Variables

#Region Execute
# ============================================================================
# Execute
# ============================================================================
StartIteration

#region script parameter reporting
#------------------------------------------------------------
# Script processing detailed reporting
#------------------------------------------------------------
Write-Log -Message "[Script Params] Logging Script Parameter configurations" -Level Info
Write-Log -Message "[Script Params] Script LogPath = $($LogPath)" -Level Info
Write-Log -Message "[Script Params] Script LogRollover = $($LogRollover)" -Level Info
Write-Log -Message "[Script Params] Script Whatif = $($Whatif)" -Level Info
Write-Log -Message "[Script Params] Citrix Cloud Region = $($Region)" -Level Info
Write-Log -Message "[Script Params] Citrix Cloud CustomerID = $($CustomerID)" -Level Info
Write-Log -Message "[Script Params] Citrix Cloud ClientID = $($ClientID)" -Level Info
Write-Log -Message "[Script Params] Citrix Cloud SecureClientFile = $($SecureClientFile)" -Level Info
Write-Log -Message "[Script Params] Citrix MaxDaaSVMCount = $($MaxDaaSVMCount)" -Level Info
Write-Log -Message "[Script Params] Citrix Machine Account Domain = $($Domain)" -Level Info
Write-Log -Message "[Script Params] Citrix Target Machine Scope = $($TargetMachineScope)" -Level Info
Write-Log -Message "[Script Params] Citrix Target Machine List = $($TargetMachineList)" -Level Info
Write-Log -Message "[Script Params] Citrix Target Machine CSV List = $($TargetMachineCSVList)" -Level Info
Write-Log -Message "[Script Params] Citrix Target Hosting Connection Name = $($TargetHostingConnectionName)" -Level Info
Write-Log -Message "[Script Params] Citrix Reset Target Hosting Connection = $($ResetTargetHostingConnection)" -Level Info
Write-Log -Message "[Script Params] Citrix Supported Hypervisor Plugin Types = $($SupportedHypervisorPlugTypes)" -Level Info
Write-Log -Message "[Script Params] Citrix Bypass Hypervisor check = $($BypassHypervisorTypeCheck)" -Level Info
Write-Log -Message "[Script Params] Citrix Switch Catalog Zone ID = $($SwitchCatalogZoneID)" -Level Info
Write-Log -Message "[Script Params] Citrix Catalogs to Switch Zone = $($CatalogNames)" -Level Info
Write-Log -Message "[Script Params] Nutanix Cluster = $($TargetNutanixCluster)" -Level Info
Write-Log -Message "[Script Params] Nutanix Custom Credential File = $($UseCustomCredentialFile)" -Level Info
Write-Log -Message "[Script Params] Nutanix Custom Credential Path = $($CredPath)" -Level Info
Write-Log -Message "[Script Params] Nutanix Protection Domain = $($NutanixPD)" -Level Info
Write-Log -Message "[Script Params] VM ExclusionList = $($ExclusionList)" -Level Info
#endregion script parameter reporting

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) { throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)" }

#region Param Validation
if (!($SecureClientFile) -and !($ClientID)) {
    Write-Log -Message "[PARAM ERROR]: You must specify either SecureClientFile or ClientID parameters to continue" -Level Warn
    StopIteration
    Exit 0
}
if ($SecureClientFile -and ($ClientID -or $ClientSecret)) {
    Write-Log -Message "[PARAM ERROR]: You cannot specify both SecureClientFile and ClientID or ClientSecret together. Invalid parameter options" -Level Warn
    StopIteration
    Exit 0
}
if ($TargetMachineScope -eq "CSV" -and !($TargetMachineCSVList)) {
    Write-Log -Message "[PARAM ERROR]: You must specify a CSV path using the TargetMachineCSVList Parameter" -Level Warn
    StopIteration
    Exit 0
}
if ($TargetMachineScope -eq "MachineList" -and !($TargetMachineList)) {
    Write-Log -Message "[PARAM ERROR]: You must specify a list of machines using the MachineList Parameter" -Level Warn
    StopIteration
    Exit 0
}
if ($TargetMachineScope -eq "NutanixPD" -and !($NutanixPD)) {
    Write-Log -Message "[PARAM ERROR]: You must specify a Nutanix Protection Domain using the NutanixPD Parameter" -Level Warn
    StopIteration
    Exit 0
}
if ($MaxDaaSVMCount -gt 1000 -and !($Domain)) {
    Write-Log -Message "[PARAM ERROR]: You Have specified more than 1000 DaaS VM search criteria. You must include a Domain (NETBIOS) for the DaaS queries" -Level Warn
    StopIteration
    Exit 0
}
if ($SwitchCatalogZoneID -and !($CatalogNames)) {
    Write-Log -Message "[PARAM ERROR]: You must specify a list of Catalogs to align Zones on." -Level Warn
    StopIteration
    Exit 0
}

#endregion Param Validation

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

#region Nutanix Authentication
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
#endregion Nutanix Authentication

#region Citrix Cloud Info Gathering
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
$headers = @{
    Authorization       = "CwsAuth Bearer=$($AccessToken)"
    'Citrix-CustomerId' = $CustomerID
    Accept              = 'application/json'
}

#endregion Citrix Auth

#region Citrix Catalogs
#------------------------------------------------------------
# Validate Citrix Catalogs are supported
#------------------------------------------------------------
if ($SwitchCatalogZoneID) {
    Write-Log -Message "[Citrix Catalog] Validating Catalog details for Zone Switch" -Level Info
    foreach ($Catalog in $CatalogNames) {
        Write-Log -Message "[Citrix Catalog $($Catalog)] Validating Catalog" -Level Info
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Get"
        $RequestUri = "https://$($CloudUrl)/cvadapis/$SiteID/MachineCatalogs/$($Catalog)"
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $DaaSCatalog = Invoke-RestMethod -Method $Method -Headers $headers -Uri $RequestUri -ErrorAction Stop
            if ($DaaSCatalog.ProvisioningType -eq "Manual") {
                Write-Log -Message "[Citrix Catalog $($Catalog)] Catalog Provisioning type is: $($DaaSCatalog.ProvisioningType) and is supported" -Level Info
            }
            else {
                Write-Log -Message "[Citrix Catalog $($Catalog)] Catalog Provisioning type is: $($DaaSCatalog.ProvisioningType) and is not supported" -Level Warn
                StopIteration
                Exit 1
            }
        }
        catch {
            Write-Log -Message "[Citrix Catalog $($Catalog)] Failed to retreive Catalog" -Level Info
            Write-Log -Message $_ -Level Warn
            StopIteration
            Exit 1
        }
    }
}
#endregion Citrix Catalogs

#region Citrix Hosting
#------------------------------------------------------------
# Validate Citrix Hosting Connection Type is supported
#------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "Get"
$RequestUri = "https://$($CloudUrl)/cvadapis/$SiteID/hypervisors/$($TargetHostingConnectionName)"
#----------------------------------------------------------------------------------------------------------------------------
Write-Log -Message "[Citrix Hosting] Validating Hosting Connection: $($TargetHostingConnectionName)" -Level Info
try {
    $ntx_hosting_connection = Invoke-RestMethod -Method $Method -Headers $headers -Uri $RequestUri -ErrorAction Stop
}
catch {
    Write-Log -Message "[Citrix Hosting] Failed to retrieve Hosting Connection: $($TargetHostingConnectionName)" -level Warn
    Write-Log -Message $_ -Level Warn
    StopIteration
    Exit 1
}

if (!$BypassHypervisorTypeCheck) {
    if ($ntx_hosting_connection.PluginId -in $SupportedHypervisorPlugTypes) {
        Write-Log -Message "[Citrix Hosting] Hypervisor Plugin type is: $($ntx_hosting_connection.PluginId) and is supported" -Level Info
    }
    else {
        Write-Log -Message "[Citrix Hosting] Hypervisor Plugin type is: $($ntx_hosting_connection.PluginId) and is not supported. Only Nutanix Hosting Connections are supported" -Level Warn
        StopIteration
        Exit 1
    }
}
else {
    Write-Log -Message "[Citrix Hosting] BypassHypervisorTypeCheck has been enabled. This is an advanced use case only " -Level Warn
    Write-Log -Message "[Citrix Hosting] Hypervisor Plugin type is: $($ntx_hosting_connection.PluginId)" -Level Info
}

#endregion Citrix Hosting

#region Citrix Machines
if ($MaxDaaSVMCount -le 1000) {
    #------------------------------------------------------------
    # Get Citrix Machine Details and Filter out inappropriate machines
    #------------------------------------------------------------
    #----------------------------------------------------------------------------------------------------------------------------
    # Set API call detail
    #----------------------------------------------------------------------------------------------------------------------------
    $Method = "Get"
    $RequestUri = "https://$($CloudUrl)/cvadapis/$SiteID/Machines?limit=$($MaxDaaSVMCount)"
    #----------------------------------------------------------------------------------------------------------------------------
    Write-Log -Message "[Citrix Machines] Retrieving machines" -Level Info
    try {
        $ctx_machines = Invoke-RestMethod -Method $Method -Headers $headers -Uri $RequestUri
        $ctx_machines = $ctx_machines.Items
    }
    catch {
        Write-Log -Message "[Citrix Machines] Failed to retrieve machines" -Level Warn
        Write-Log -Message $_ -Level Warn
        StopIteration
        Exit 1
    }

    if ($ctx_machines.Count -gt 0) {
        Write-Log -Message "[Citrix Machines] There are $($ctx_machines.count) machines in the DaaS tenant" -Level Info
    }
    else {
        Write-Log -Message "[Citrix Machines] There are no machines in the DaaS tenant" -Level Warn
        StopIteration
        Exit 0
    }

    $ctx_machines_mcs = $ctx_machines | where-Object { $_.ProvisioningType -eq "MCS" }
    $ctx_machines_pvs = $ctx_machines | where-Object { $_.ProvisioningType -eq "PVS" }
    $ctx_machines_not_power_managed = $ctx_machines | Where-Object { $_.hosting.HostedMachineId -eq $null }
    $target_ctx_machines = $ctx_machines | Where-Object { $_.ProvisioningType -ne "MCS" -and $_.ProvisioningType -ne "PVS" -and $_.Hosting.HostedMachineId -ne $null }

    Write-Log -Message "[Citrix Machines] There are $($ctx_machines_mcs.count) MCS provisioned machines excluded from scope" -Level Info
    Write-Log -Message "[Citrix Machines] There are $($ctx_machines_pvs.count) PVS provisioned machines excluded from scope" -Level Info
    Write-Log -Message "[Citrix Machines] There are $($ctx_machines_not_power_managed.count) non power managed machines excluded from scope" -Level Info

    if ($target_ctx_machines.count -gt 0) {
        Write-Log -Message "[Citrix Machines] There are $($target_ctx_machines.count) manually provisioned power managed machines included in scope" -Level Info
    }
    else {
        Write-Log -Message "[Citrix Machines] There are no machines matching the appropriate requirements in the DaaS tenant" -Level Warn
        StopIteration
        Exit 0
    }
}
else {
    Write-Log -Message "[Citrix Machines] $($MaxDaaSVMCount) DaaS machine retrieval has been specified. Will require a direct machine call after gathering Nutanix VMs" -Level Info
}
#endregion Citrix Machines

#endregion Citrix Cloud Info Gathering

#region Nutanix Cluster Connection
#------------------------------------------------------------
# Connect to the Target Nutanix Cluster
#------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "GET"
$RequestUri = "https://$($TargetNutanixCluster):9440/PrismGateway/services/rest/v2.0/cluster"
$Payload = $null # we are on a get run
#----------------------------------------------------------------------------------------------------------------------------
try {
    Write-Log -Message "[Nutanix Cluster] Connecting to the Cluster: $($TargetNutanixCluster)" -Level Info
    $Cluster = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCredentials -ErrorAction Stop
    Write-Log -Message "[Nutanix Cluster] Successfully connected to the Cluser: $($TargetNutanixCluster)" -Level Info
}
catch {
    Write-Log -Message "[Nutanix Cluster] Could not connect to the Cluster: $($TargetNutanixCluster) " -Level Warn
    Write-Log -Message $_ -Level Warn
    StopIteration
    Exit 1
}
#endregion Nutanix Cluster Connection

#region Get Nutanix VM list
#------------------------------------------------------------
# Get Machine List from Nutanix (all virtual machines)
#------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "GET"
$RequestUri = "https://$($TargetNutanixCluster):9440/PrismGateway/services/rest/v2.0/vms"
$Payload = $null # we are on a get run
#----------------------------------------------------------------------------------------------------------------------------
try {
    $ntx_machines = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCredentials -ErrorAction Stop
    $ntx_machines = $ntx_machines.entities

    if ($ntx_machines.count -eq 0) {
        #couldn't find the VM
        Write-Log -Message "[Nutanix Cluster] Could not find any vms on the Nutanix Cluster $($TargetNutanixCluster)" -Level Warn
        StopIteration
        Exit 1
    }
}
catch {
    Write-Log -Message "[Nutanix Cluster] Could not retrieve Nutanix vms" -Level Warn
    Write-Log -Message $_ -Level Warn
    StopIteration
    Exit 1
}

Write-Log -Message "[Nutanix Cluster] There are $($ntx_machines.count) vms found on the Nutanix Cluster $($TargetNutanixCluster)" -Level Info
#endregion Get Nutanix VM list

#region Handle VM Filtering
#------------------------------------------------------------
# Handle VM Input Matching
#------------------------------------------------------------
if ($TargetMachineScope -eq "NutanixPD") {
    #----------------------------------------------------------------------------------------------------------------------------
    # Set API call detail
    #----------------------------------------------------------------------------------------------------------------------------
    $Method = "GET"
    $RequestUri = "https://$($TargetNutanixCluster):9440/PrismGateway/services/rest/v2.0/protection_domains/?names=$($NutanixPD)"
    $Payload = $null # we are on a get run
    #----------------------------------------------------------------------------------------------------------------------------
    Write-Log -Message "[Machine Scoping] Attempting to retrieve vms from Nutanix Protection Domain: $($NutanixPD)" -Level Info

    try {
        $ntx_pd = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCredentials -ErrorAction Stop
        if ($ntx_pd.entities.Active -ne $true) {
            Write-Log -Message "[Machine Scoping] Protection Domain: $($NutanixPD) is not Active on the Targeted Nutanix Cluster: $($TargetNutanixCluster). Please ensure the appropriate activation or migration steps have been taken." -Level Warn
            StopIteration
            Exit 1
        }
    }
    catch {
        Write-Log -Message "[Nutanix Protection Domain] Could not retrieve Nutanix Protection Domain" -Level Warn
        Write-Log -Message $_ -Level Warn
        StopIteration
        Exit 1
    }
    # Handle exclusion list
    foreach ($_ in $ntx_machines) {
        if ($_.name -in $ExclusionList) {
            Write-Log -Message "[Machine Scoping Exclusion] $($_.name) is in the exclusion list and will not be included for processing" -Level Info
        }
    }
    # Get the machines from the supplied protection domain
    $target_ntx_machines = $ntx_machines | Where-Object { $_.name -in $ntx_pd.entities.vms.vm_name -and $_.name -notin $ExclusionList }
}
elseif ($TargetMachineScope -eq "CSV") {
    Write-Log -Message "[Machine Scoping] Attempting to import CSV file $($TargetMachineCSVList)" -Level Info
    # get the machines from a CSV File
    try {
        $csv_MachineList = Import-CSV -path $TargetMachineCSVList -ErrorAction Stop
    }
    catch {
        Write-Log -Message "Failed to Import CSV File" -Level Warn
        Write-Log -Message $_ -Level Warn
        StopIteration
        Exit 1
    }
    # Handle exclusion list
    foreach ($_ in $ntx_machines) {
        if ($_.name -in $ExclusionList) {
            Write-Log -Message "[Machine Scoping Exclusion] $($_.name) is in the exclusion list and will not be included for processing" -Level Info
        }
    }
    $target_ntx_machines = $ntx_machines | Where-Object { $_.name -in $csv_MachineList.Name -and $_.name -notin $ExclusionList }
}
elseif ($TargetMachineScope -eq "MachineList") {
    Write-Log -Message "[Machine Scoping] Attempting to match machines based on input Machine List" -Level Info
    # Handle exclusion list
    foreach ($_ in $ntx_machines) {
        if ($_.name -in $ExclusionList) {
            Write-Log -Message "[Machine Scoping Exclusion] $($_.name) is in the exclusion list and will not be included for processing" -Level Info
        }
    }
    # Use the supplied TargetMachineList array
    $target_ntx_machines = $ntx_machines | Where-Object { $_.name -in $TargetMachineList -and $_.name -notin $ExclusionList }
}

Write-Log -Message "[Machine Scoping] There are $($target_ntx_machines.count) machines to process" -Level Info

#endregion Handle VM Filtering

#region Handle above 1000 VM Query
if ($MaxDaaSVMCount -gt 1000) {
    Write-Log -Message "[Citrix Machines] $($MaxDaaSVMCount) machine retrieval has been specified. Doing a direct machine match call" -level Info

    $ctx_machines = @() # Initiate the array

    foreach ($ntx_vm in $target_ntx_machines) {
        $DaaSVM = $null
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Get"
        $QueryMachineName = "$Domain%5c$($ntx_vm.name)" # API need this format
        $RequestUri = "https://$($CloudUrl)/cvadapis/$SiteID/Machines/$QueryMachineName"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
        Write-Log -Message "[Citrix Machine $($ntx_vm.name)] Querying Citrix DaaS for machine match" -level Info
        try {
            $DaaSVM = Invoke-RestMethod -Method $Method -Headers $headers -Uri $RequestUri -Body $Payload -ContentType "application/json" -ErrorAction Stop
            Write-Log -Message "[Citrix Machine $($ntx_vm.name)] Machine found. Adding to array" -level Info
            $ctx_machines += $DaaSVM
        }
        catch {
            Write-Log -Message "[Citrix Machine $($ntx_vm.name)] Machine not found in Citrix DaaS" -level Warn
        }
    }

    if ($ctx_machines.Count -gt 0) {
        Write-Log -Message "[Citrix Machines] There are $($ctx_machines.count) matched machines in the DaaS tenant" -Level Info
    } else {
        Write-Log -Message "[Citrix Machines] There are no matched machines in the DaaS tenant" -Level Warn
        StopIteration
        Exit 0
    }

    $ctx_machines_mcs = $ctx_machines | where-Object { $_.ProvisioningType -eq "MCS" }
    $ctx_machines_pvs = $ctx_machines | where-Object { $_.ProvisioningType -eq "PVS" }
    $ctx_machines_not_power_managed = $ctx_machines | Where-Object { $_.hosting.HostedMachineId -eq $null }
    $target_ctx_machines = $ctx_machines | Where-Object { $_.ProvisioningType -ne "MCS" -and $_.ProvisioningType -ne "PVS" -and $_.Hosting.HostedMachineId -ne $null }

    Write-Log -Message "[Citrix Machines] There are $($ctx_machines_mcs.count) MCS provisioned machines excluded from scope" -Level Info
    Write-Log -Message "[Citrix Machines] There are $($ctx_machines_pvs.count) PVS provisioned machines excluded from scope" -Level Info
    Write-Log -Message "[Citrix Machines] There are $($ctx_machines_not_power_managed.count) non power managed machines excluded from scope" -Level Info

    if ($target_ctx_machines.count -gt 0) {
        Write-Log -Message "[Citrix Machines] There are $($target_ctx_machines.count) manually provisioned power managed machines included in scope" -Level Info
    } else {
        Write-Log -Message "[Citrix Machines] There are no machines matching the appropriate requirements in the DaaS tenant" -Level Warn
        StopIteration
        Exit 0
    }
}

#endregion Handle above 1000 VM Query

#region Citrix Target Array
$target_ctx_machines_names = @()

foreach ($ctx_vm in $target_ctx_machines) {
    $target_ctx_machines_names += ($ctx_vm.name -split "\\")[1]
}
#endregion Citrix Target Array

#region VM Alteration
#------------------------------------------------------------
# loop through each Target Nutanix VM and match against Citrix DaaS VM
#------------------------------------------------------------
$Count = 1
$AlterationCount = 0

foreach ($ntx_vm in $target_ntx_machines) {
    Write-Log -Message "[Nutanix VM] Processing VM $($Count) of $($target_ntx_machines.count)" -Level Info 
    if ($ntx_vm.name -in $target_ctx_machines_names) {
        $CitrixHostedMachineId = ($target_ctx_machines | Where-Object { $_.name -match $ntx_vm.name }).Hosting.HostedMachineId
        $CitrixHostingConnectionId = ($target_ctx_machines | Where-Object { $_.name -match $ntx_vm.name }).Hosting.HypervisorConnection.uid
        $CitrixHostingConnectionName = ($target_ctx_machines | Where-Object { $_.name -match $ntx_vm.name }).Hosting.HypervisorConnection.Name
        $CitrixMachineId = ($target_ctx_machines | Where-Object { $_.name -match $ntx_vm.name }).Id
        $NutanixUUID = $ntx_vm.uuid
        Write-Log -Message "[Nutanix VM $($ntx_vm.name)] Has Nutanix UUID: $($NutanixUUID)" -Level Info
        Write-Log -Message "[Nutanix VM $($ntx_vm.name)] Has Citrix HostedMachineId: $($CitrixHostedMachineId)" -Level Info
        Write-Log -Message "[Nutanix VM $($ntx_vm.name)] Has Citrix HypervisorConnection name: $($CitrixHostingConnectionName) with Id: $($CitrixHostingConnectionId)" -Level Info

        # handle hosting connection changes
        if ($CitrixHostingConnectionName -eq $TargetHostingConnectionName) {
            Write-Log -Message "[Nutanix VM $($ntx_vm.name)] Hosting Connection is correct. No changes needed" -Level Info
        }
        else {
            Write-Log -Message "[Nutanix VM $($ntx_vm.name)] Hosting Connection is currently: $($CitrixHostingConnectionName) but should be: $($TargetHostingConnectionName). Processing Hosting Connection Change" -Level Info
            #------------------------------------------------------------
            # Process Hosting Connection change
            #------------------------------------------------------------
            if (!$Whatif) {
                #we are executing
                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "PATCH"
                $RequestUri = "https://$($CloudUrl)/cvadapis/$SiteID/Machines/$($CitrixMachineId)"
                $PayloadContent = @{
                    HypervisorConnection = $TargetHostingConnectionName
                }
                $Payload = (ConvertTo-Json $PayloadContent)
                #----------------------------------------------------------------------------------------------------------------------------
                try {
                    $response = Invoke-RestMethod -Method $Method -Headers $headers -Uri $RequestUri -Body $Payload -ContentType "application/json" -ErrorAction Stop
                    Write-Log -Message "[Nutanix VM $($ntx_vm.name)] Updated Hosting Connection: $($TargetHostingConnectionName)" -Level Info
                    $AlterationCount =+ 1
                }
                catch {
                    Write-Log -Message "[Nutanix VM $($ntx_vm.name)] Failed to update Hosting Connection" -Level Warn
                    Write-Log -Message $_ -Level Warn
                }
            }
            else {
                #we are in whatif mode
                Write-Log -Message "[WHATIF] [Nutanix VM $($ntx_vm.name)] Would update Hosting Connection to: $($TargetHostingConnectionName) " -Level Info
                $AlterationCount =+ 1
            }
        }
        # Handle HostedMachineID Change
        if ($NutanixUUID -eq $CitrixHostedMachineId) {
            Write-Log -Message "[Nutanix VM $($ntx_vm.name)] Nutanix UUID and Citrix HostedMachineID match. No changes needed" -Level Info
        }
        else {
            Write-Log -Message "[Nutanix VM $($ntx_vm.name)] Nutanix UUID and Citrix HostedMachineID do not match. Processing changes" -Level Info
            #------------------------------------------------------------
            # Process HostedMachineId change
            #------------------------------------------------------------
            if (!$Whatif) {
                #we are executing
                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "PATCH"
                $RequestUri = "https://$($CloudUrl)/cvadapis/$SiteID/Machines/$($CitrixMachineId)"
                $PayloadContent = @{
                    HostedMachineId = $NutanixUUID
                }
                $Payload = (ConvertTo-Json $PayloadContent)
                #----------------------------------------------------------------------------------------------------------------------------
                try {
                    $response = Invoke-RestMethod -Method $Method -Headers $headers -Uri $RequestUri -Body $Payload -ContentType "application/json" -ErrorAction Stop
                    Write-Log -Message "[Nutanix VM $($ntx_vm.name)] Updated HostedMachineId: $($NutanixUUID)" -Level Info
                    $AlterationCount =+ 1
                }
                catch {
                    Write-Log -Message "[Nutanix VM $($ntx_vm.name)] Failed to update HostedMachineId" -Level Warn
                    Write-Log -Message $_ -Level Warn
                }
            }
            else {
                #we are in whatif mode
                Write-Log -Message "[WHATIF] [Nutanix VM $($ntx_vm.name)] Would have updated HostedMachineId: $($NutanixUUID)" -Level Info
                $AlterationCount =+ 1
            }
        }
    }
    else {
        Write-Log -Message "[Nutanix VM $($ntx_vm.name)] is not in the Citrix DaaS Tenant" -Level Info
    }
    $Count += 1
}
#endregion VM Alteration

#region Hosting Connection Reset
#------------------------------------------------------------
# Reset the Citrix Hosting Connection to update power states (there is a 5-10 minute sync otherwise)
#------------------------------------------------------------
if ($ResetTargetHostingConnection) {
    if ($target_ntx_machines.count -gt 0 -and $AlterationCount -gt 0) {
        if (!$Whatif) {
            #we are executing
            Write-Log -Message "[Citrix Hosting] Resetting Citrix Hosting Connection: $($TargetHostingConnectionName)" -Level Info
            #----------------------------------------------------------------------------------------------------------------------------
            # Set API call detail
            #----------------------------------------------------------------------------------------------------------------------------
            $Method = "POST"
            $RequestUri = "https://$($CloudUrl)/cvadapis/$SiteID/hypervisors/$($TargetHostingConnectionName)/`$resetConnection"
            $Payload = $null
            #----------------------------------------------------------------------------------------------------------------------------
            try {
                $response = Invoke-RestMethod -Method $Method -Headers $headers -Uri $RequestUri -Body $Payload -ContentType "application/json" -ErrorAction Stop
            }
            catch {
                Write-Log -Message "[Citrix Hosting] Failed to reset Hosting Connection: $($TargetHostingConnectionName)" -Level Warn
                Write-Log -Message $_ -Level Warn
            }
        }
        else {
            #we are in whatif mode
            Write-Log -Message "[WHATIF] [Citrix Hosting] Would have reset Hosting Connection $($TargetHostingConnectionName)" -Level Info
        }
    }
    else {
        Write-Log -Message "[Citrix Hosting] No machines were altered so Hosting Connection has not been reset" -Level Info
    }
}
#endregion Hosting Connection Reset

#region Catalog Zone ID Switch
#------------------------------------------------------------
# Switch the Catalog Zone to that of the Target Hosting Connection ID
#------------------------------------------------------------
if ($SwitchCatalogZoneID) {
    Write-Log -Message "[Citrix Catalog] Processing Catalog Zone ID Switch" -Level Info
    foreach ($Catalog in $CatalogNames) {
        Write-Log -Message "[Citrix Catalog $($Catalog)] Processing Catalog" -Level Info
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "Get"
        $RequestUri = "https://$($CloudUrl)/cvadapis/$SiteID/MachineCatalogs/$($Catalog)"
        $Payload = $null
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $DaaSCatalog = Invoke-RestMethod -Method $Method -Headers $headers -Uri $RequestUri -ErrorAction Stop
            $DaaSCatalogZoneId = $DaaSCatalog.Zone.id
            Write-Log -Message "[Citrix Catalog $($Catalog)] Has Zone ID: $($DaaSCatalogZoneId)" -Level Info
            if ($DaaSCatalogZoneId -eq $ntx_hosting_connection.zone.id) {
                Write-Log -Message "[Citrix Catalog $($Catalog)] Zone ID matches Target Hosting Connection Zone ID. No changes needed" -Level Info
            }
            else {
                Write-Log -Message "[Citrix Catalog $($Catalog)] Zone ID does not match Target Hosting Connection Zone ID" -Level Info
                if (!$Whatif) {
                    #we are executing
                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail
                    #----------------------------------------------------------------------------------------------------------------------------
                    # non standard headers for this particular request
                    $CustomRequestZoneheaders = @{
                        Authorization       = "CwsAuth Bearer=$($AccessToken)"
                        'Citrix-CustomerId' = $CustomerID
                        Accept              = 'application/json'
                        'Citrix-InstanceId' = $SiteID
                    }

                    $Method = "POST"
                    $RequestUri = "https://$($CloudUrl)/cvad/manage/Zones/$($ntx_hosting_connection.zone.id)/`$moveItems?async=false"

                    $PayloadContent = @{
                        Items = @(
                            @{
                                Id = $DaaSCatalog.id
                                Name =  $DaaSCatalog.name
                                ItemType = "MachineCatalog"
                            }
                        )
                    }
                    $Payload = (ConvertTo-Json $PayloadContent -depth 4)

                    #----------------------------------------------------------------------------------------------------------------------------
                    try {
                        $Response = Invoke-RestMethod -Method $Method -Headers $CustomRequestZoneheaders -Uri $RequestUri -Body $Payload -ContentType "application/json" -ErrorAction Stop
                        Write-Log -Message "[Citrix Catalog $($Catalog)] Updated Catalog Zone ID to: $($ntx_hosting_connection.zone.id)" -Level Info
                    }
                    catch {
                        Write-Log -Message "[Citrix Catalog $($Catalog)] Failed to update Catalog Zone ID" -Level Warn
                        Write-Log -Message $_ -Level Warn
                    }
                }
                else {
                    #we are in whatif mode 
                    Write-Log -Message "[WHATIF] [Citrix Catalog $($Catalog)] Would have updated Catalog Zone ID to: $($ntx_hosting_connection.zone.id)" -Level Info
                }
            }
        }
        catch {
            Write-Log -Message "[Citrix Catalog $($Catalog)] Failed to retrieve Catalog details" -Level Warn
        }
    }
}
#endregion Catalog Zone ID Switch

StopIteration
Exit 0
#endregion