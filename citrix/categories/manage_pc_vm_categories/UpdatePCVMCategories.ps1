<#
.SYNOPSIS
    Handles Category Additions or Removals for VMs under Prism Central Management based on a naming pattern match.
.DESCRIPTION
    Designed to be able to add Categories based on specific naming convention matches. The vast majority of this code logic is credited to Stephane Bourdeaud at Nutanix who is always ahead of the game.
.PARAMETER LogPath
    Logpath output for all operations. Default path is C:\Logs\CategoyFun.log
.PARAMETER LogRollover
    Number of days before logfiles are rolled over. Default is 5.
.PARAMETER pc_source
    Mandatory. The Prism Central Source to target.
.PARAMETER Category
    Mandatory. The Name of the Category to assign or remove.
.PARAMETER Value
    Mandatory. The value of the Category to assign or remove.
.PARAMETER IncludeList
    Optional. An array of virtual machines to target. You must specify either this parameter or VM_Pattern_Match
.PARAMETER VM_Pattern_Match
    Optional. A pattern match string to filter virtual machine entities by. Eg, MCS* will match all vms' starting with MCS. You must use this parameter or IncludeList
.PARAMETER ExclusionList
    Optional. A list of names to exclude from the captured VM list.
.PARAMETER Mode
    Mandatory. What mode to operate in, either add or remove for the Category assignment.
.PARAMETER SleepTime
    The amount of time to sleep between API task retrieval. Defaults to 5 seconds.
.PARAMETER APICallVerboseLogging
    Optional. Switch to enable logging output for API calls.
.PARAMETER UseCustomCredentialFile
    Optional. Will call the Get-CustomCredentials function which keeps outputs and inputs a secure credential file base on Stephane Bourdeaud from Nutanix functions.
.PARAMETER CredPath
    Optional. Used if using the UseCustomCredentialFile parameter. Defines the location of the credential file. The default is "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials".
.PARAMETER Whatif
    Optional. Will action the script in a whatif processing mode only.
.PARAMETER async
  Switch to specify that you don't want to wait for the update tasks to complete. When categories are updated for vms in Prism Central, the API will return with success and a task uuid. That task may still fail for whatever reason, but if you're doing mass updates, it may also cause significant processing delays to wait for each task to return status.
.EXAMPLE
    .\UpdatePCVMCategories.ps1 -pc_source 1.1.1.1 -Category Citrix_Provisioning_Type -Value MCS -Mode Add -IncludeList "Server1","Server2","Server3" -UseCustomCredentialFile
    Update all machines matching Server1, Server2, Server3 under the PC 1.1.1.1 by adding a Category of Citrix_Provisioning_Type with value MCS using a custom credential file
.EXAMPLE
    .\UpdatePCVMCategories.ps1 -pc_source 1.1.1.1 -Category Citrix_Provisioning_Type -Value MCS -Mode Add -VM_Pattern_Match "*MCS" -UseCustomCredentialFile
    Update all machines matching the name *MCS under the PC 1.1.1.1 by adding a Category of Citrix_Provisioning_Type with value MCS using a custom credential file
.EXAMPLE
    .\UpdatePCVMCategories.ps1 -pc_source 1.1.1.1 -Category Citrix_Provisioning_Type -Value MCS -Mode Add -VM_Pattern_Match "*MCS" -UseCustomCredentialFile -ExclusionList "Server1","Server2"
    Update all machines matching the name *MCS under the PC 1.1.1.1 by adding a Category of Citrix_Provisioning_Type with value MCS using a custom credential file. Will Exclude Server1 and Server2 from the list of VMs
.EXAMPLE
    .\UpdatePCVMCategories.ps1 -pc_source 1.1.1.1 -Category Citrix_Provisioning_Type -Value MCS -Mode Add -VM_Pattern_Match "*MCS" -UseCustomCredentialFile -async
    Update all machines matching the name *MCS under the PC 1.1.1.1 by adding a Category of Citrix_Provisioning_Type with value MCS using a custom credential file in async mode (no task checking)
.EXAMPLE
    .\UpdatePCVMCategories.ps1 -pc_source 1.1.1.1 -Category Citrix_Provisioning_Type -Value MCS -Mode Remove -VM_Pattern_Match "*MCS" -UseCustomCredentialFile
    Update all machines matching the name *MCS under the PC 1.1.1.1 by removing a Category of Citrix_Provisioning_Type with value MCS using a custom credential file
.EXAMPLE
    .\UpdatePCVMCategories.ps1 -pc_source 1.1.1.1 -Category Citrix_Provisioning_Type -Value PVS -Mode Add -VM_Pattern_Match "*PVS" -UseCustomCredentialFile
    Update all machines matching the name *PVS under the PC 1.1.1.1 by adding a Category of Citrix_Provisioning_Type with value PVS using a custom credential file
.EXAMPLE
    .\UpdatePCVMCategories.ps1 -pc_source 1.1.1.1 -Category Citrix_Provisioning_Type -Value PVS -Mode Remove -VM_Pattern_Match "*PVS" -UseCustomCredentialFile
    Update all machines matching the name *PVS under the PC 1.1.1.1 by removing a Category of Citrix_Provisioning_Type with value PVS using a custom credential file
.EXAMPLE
    .\UpdatePCVMCategories.ps1 -pc_source 1.1.1.1 -Category Citrix_Provisioning_Type -Value MCS -Mode Add -VM_Pattern_Match "*MCS" -UseCustomCredentialFile -APICallVerboseLogging -Whatif
    Update all machines matching the name *MCS under the PC 1.1.1.1 by adding a Category of Citrix_Provisioning_Type with value MCS using a custom credential file in a whatif processing mode

.NOTES
    Author: James Kindon, Nutanix, 21.06.23. Most of the core logic via Stephane Bourdeaud at Nutanix
    10.07.23 - JK - Added ExclusionList capability
    17.07.23 - JK - Added IncludeList capability
    18.09.23 - JK - Fixed VM iteration for PCs with over 500 VMs
#>

#region Params
# ============================================================================
# Parameters
# ============================================================================
Param(
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\UpdatePCVMCategories.log", # Where we log to

    [Parameter(Mandatory = $false)]
    [int]$LogRollover = 5, # Number of days before logfile rollover occurs

    [Parameter(Mandatory = $true)]
    [string]$pc_source, # The Prism Central Instance hosting the Source VM and associated Protection Policy

    [Parameter(Mandatory = $false)]
    [switch]$UseCustomCredentialFile, # specifies that a credential file should be used

    [Parameter(Mandatory = $false)]
    [String]$CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials", # Default path for custom credential file

    [Parameter(Mandatory = $true)]
    [string]$Category, # the name of category

    [Parameter(Mandatory = $true)]
    [string]$Value, # the value of category

    [Parameter(Mandatory = $false)]
    [array]$IncludeList, # array of target virtual machines
    
    [Parameter(Mandatory = $false)]
    [string]$VM_Pattern_Match, # String to match VM targets on

    [Parameter(Mandatory = $false)]
    [array]$ExclusionList, # List of names to exclude

    [Parameter(Mandatory = $true)]
    [ValidateSet("Add","Remove")]
    [string]$Mode, # Category Assignment mode Add or Remove

    [Parameter(Mandatory = $false)]
    [int]$SleepTime = 5, # seconds to sleep between task retrieval

    [Parameter(Mandatory = $false)]
    [switch]$APICallVerboseLogging, # Show the API calls being made

    [Parameter(Mandatory = $false)]
    [switch]$Whatif, # will process in a whatif mode without actually altering anything

    [parameter(mandatory = $false)] 
    [switch]$async # Async Processing for Category actions (don't wait for task success)
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

function GetPCVMIncrements {
    param (
        [parameter(mandatory = $true)]
        [int]$offset
    )
    #----------------------------------------------------------------------------------------------------------------------------
    # Set API call detail
    #----------------------------------------------------------------------------------------------------------------------------
    $Method = "POST"
    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/list"
    $PayloadContent = @{
        kind   = "vm"
        length = 500
        offset = $offset
    }
    $Payload = (ConvertTo-Json $PayloadContent)
    #----------------------------------------------------------------------------------------------------------------------------
    Write-Log -Message "[VM Retrieval] Retrieving machines from offset $($offset) under PC: $($pc_source)" -Level Info
    try {
        $vm_list = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        $vm_list = $vm_list.entities
        Write-Log -Message "[VM Retrieval] Retrieved $($vm_list.Count) virtual machines from offset $($Offset) under PC: $($pc_source)" -Level Info
        #Now we need to add them to the existing $VirtualMachinesArray
        $Global:VirtualMachines = ($Global:VirtualMachines + $vm_list)
        Write-Log -Message "[VM Retrieval] Retrieved VM Count is $($Global:VirtualMachines.Count) under PC: $($pc_source)" -Level Info
    }
    catch {
        Write-Log -Message "[VM Retrieval] Failed to retrieve virtual machines from $($pc_source)" -Level Warn
        StopIteration
        Exit 1
    }
}

#endregion

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
Write-Log -Message "[Script Params] Script APICallVerboseLogging = $($APICallVerboseLogging)" -Level Info
Write-Log -Message "[Script Params] Script Whatif = $($Whatif)" -Level Info
Write-Log -Message "[Script Params] Script async = $($async)" -Level Info
Write-Log -Message "[Script Params] Script SleepTime = $($SleepTime)" -Level Info
Write-Log -Message "[Script Params] Nutanix pc_source = $($pc_source)" -Level Info
Write-Log -Message "[Script Params] NUtanix UseCustomCredentialFile = $($UseCustomCredentialFile)" -Level Info
Write-Log -Message "[Script Params] Nutanix CredPath = $($CredPath)" -Level Info
Write-Log -Message "[Script Params] Category Name = $($Category)" -Level Info
Write-Log -Message "[Script Params] Category Value = $($Value)" -Level Info
Write-Log -Message "[Script Params] Category Assignment Mode = $($Mode)" -Level Info
Write-Log -Message "[Script Params] VM IncludeList = $($IncludeList)" -Level Info
Write-Log -Message "[Script Params] VM VM_Pattern_Match = $($VM_Pattern_Match)" -Level Info
Write-Log -Message "[Script Params] VM ExclusionList = $($ExclusionList)" -Level Info

#endregion script parameter reporting

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 5) { throw "$(get-date) [ERROR] Please upgrade to Powershell v5 or above (https://www.microsoft.com/en-us/download/details.aspx?id=50395)" }

#region Param Validation
if (!($VM_Pattern_Match) -and !($IncludeList)) {
    Write-Log -Message "[PARAM ERROR]: You must specify either VM_Pattern_Match or IncludeList. Invalid parameter options" -Level Warn
    StopIteration
    Exit 0
}

if ($VM_Pattern_Match -and $IncludeList) {
    Write-Log -Message "[PARAM ERROR]: You cannot use both VM_Pattern_Match and IncludeList parameters together. Invalid parameter options" -Level Warn
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
}
#endregion Authentication

#region Check the Category Exists
#---------------------------------------------
# check category value pairs exists
#---------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "GET"
$RequestUri = "https://$($pc_source):9440/api/nutanix/v3/categories/$($category)/$($value)"
$Payload = $null
#----------------------------------------------------------------------------------------------------------------------------
Write-Log -Message "[Category Retrieval] Checking $($category):$($value) exists in $($pc_source)" -Level Info
try {
    $CategoryExists = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
    Write-Log -MEssage "[Category Retrieval] Found the category:value pair $($category):$($value) in $($pc_source)" -Level Info
}
catch {
    $saved_error = $_.Exception.Message
    if ($saved_error -like "*(404) Not Found*" -or $saved_error -like "*404 (NOT FOUND)*") {
        Write-Log -Message "[Category Retrieval] The category:value pair specified ($($category):$($value)) does not exist in Prism Central $($pc_source)" -Level Warn
        StopIteration
        Exit 1
    }
    else {
        Write-Log -Message "$($saved_error)" -Level Warn
        StopIteration
        Exit 1
    }
}
#endregion Check the Category Exists

#region Get VM list
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
    length = 500
}
$Payload = (ConvertTo-Json $PayloadContent)
#----------------------------------------------------------------------------------------------------------------------------
if ($VM_Pattern_Match) {
    Write-Log -Message "[VM Retrieval] Retrieving VMs and filtering on pattern match $($VM_Pattern_Match) from $($pc_source)" -Level Info
}
elseif ($IncludeList) {
    Write-Log -Message "[VM Retrieval] Retrieving VMs and filtering on the specified IncludeList from $($pc_source)" -Level Info
}

try {
    $VirtualMachines = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
    $vm_total_entity_count = $VirtualMachines.metadata.total_matches
    Write-Log -Message "[VM Retrieval] Sucessfully retrieved virtual machines from $($pc_source)" -Level Info
}
catch {
    Write-Log -Message "[VM Retrieval] Failed to retrieve virtual machines from $($pc_source)" -Level Warn
    Break
}

$VirtualMachines = $VirtualMachines.entities

if ($null -ne $VirtualMachines) {
    Write-Log -Message "[VM Retrieval] Retrieved $($VirtualMachines.Count) virtual machines under PC: $($pc_source)" -Level Info
}
else {
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

$api_batch_increment = 500

if ($vm_total_entity_count -gt 500) {
    # Set the variable to Global for this run
    $Global:VirtualMachines = $VirtualMachines
    Write-Log -Message "[VM Retrieval] $($vm_total_entity_count) virtual machines exist under PC: $($pc_source). Looping through batch pulls" -Level Info
    # iterate through increments of 500 until the offset reaches or exceeds the value of $vm_total_entity_count.
    for ($offset = 500; $offset -lt $vm_total_entity_count; $offset += $api_batch_increment) {
        $vm_offset = $offset
        GetPCVMIncrements -offset $vm_offset
    }
}

# Set the variable back to normal
if ($vm_total_entity_count -gt 500) {
    $VirtualMachines = $Global:VirtualMachines
}
#endregion bulk machine retrievale from PC

#region Handle VM Pattern Match
if ($VM_Pattern_Match) {
    $VirtualMachinesPatternMatch = $VirtualMachines | Where-Object { $_.status.name -like "$VM_Pattern_Match*" }
    $TargetCount = ($VirtualMachinesPatternMatch.status.name).count
}
elseif ($IncludeList) {
    $VirtualMachinesIncludeMatch = $VirtualMachines | Where-Object { $_.status.name -in $IncludeList }
    $TargetCount = ($VirtualMachinesIncludeMatch.status.name).count
}


if ($TargetCount -gt 0) {
    Write-Log -Message "[VM Retrieval] Sucessfully retrieved and matched $($TargetCount) machines from $($pc_source)"
}
else {
    if ($VM_Pattern_Match) {
        Write-Log -Message "[VM Retrieval] Failed to retrieve and match any machines using pattern match $($VM_Pattern_Match) from $($pc_source)" -Level Warn
    }
    elseif ($IncludeList) {
        Write-Log -Message "[VM Retrieval] Failed to retrieve and match any machines using the specified IncludeList from $($pc_source)" -Level Warn
    }
    StopIteration
    Exit 0
}
#endregion Handle VM Pattern Match

if ($VM_Pattern_Match) {
    $VirtualMachinesToProcess = $VirtualMachinesPatternMatch.status.name
}
elseif ($IncludeList) {
    $VirtualMachinesToProcess = $VirtualMachinesIncludeMatch.status.name
}

#---------------------------------------------
# Handle VM Exclusions
#---------------------------------------------
$ExclusionListCount = 0
foreach ($vm in $VirtualMachinesToProcess) {
    if ($vm -in $ExclusionList) {
        Write-Log -Message "[VM Retrieval] $($vm) is in the specified Exclusion List and will not be included for processing" -Level Info
        $ExclusionListCount += 1
    }
}
Write-Log -Message "[VM Retrieval] Excluding a total of $($ExclusionListCount) virtual machines" -Level Info
$TargetCount = $TargetCount - $ExclusionListCount #remove the excluded machines from the count
Write-Log -Message "[VM Retrieval] Will process $($TargetCount) machines from $($pc_source)" -Level Info
if ($VM_Pattern_Match) {
    $VirtualMachinesToProcess = $VirtualMachinesPatternMatch.status.name | Where-Object {$_ -notin $ExclusionList}
}
elseif ($IncludeList) {
    $VirtualMachinesToProcess = $VirtualMachinesIncludeMatch.status.name | Where-Object {$_ -notin $ExclusionList}
}
#endregion Get VM list

#region Process the VM list
#---------------------------------------------
# process the VirtualMachinesToProcess list
#---------------------------------------------
$VMProcessCount = 1
foreach ($vm in $VirtualMachinesToProcess) {
    Write-Log -Message "[VM Processing] Processing VM $($VMProcessCount) of $($TargetCount)"

    [System.Collections.ArrayList]$ListToProcess = New-Object System.Collections.ArrayList($null)
    #build dict with provided values
    $customItem = [ordered]@{
        "vm_name"        = $vm;
        "category_name"  = $category;
        "category_value" = $value
    }
    #store the results for this entity in our overall result variable
    $ListToProcess.Add((New-Object PSObject -Property $customItem)) | Out-Null

    foreach ($item in $ListToProcess) {
        $vm_already_tagged = $false
        $vm = $item.vm_name
        $category = $item.category_name
        $value = $item.category_value

        #---------------------------------------------
        # retrieve vm details
        #---------------------------------------------
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "POST"
        $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/list"
        $PayloadContent = @{
            kind   = "vm"
            filter = "vm_name==$($vm)";
        }
        $Payload = (ConvertTo-Json $PayloadContent)
        #----------------------------------------------------------------------------------------------------------------------------
        Write-Log -Message "[VM Retrieval] Retrieving the configuration of vm $($vm) from $($pc_source)" -Level Info
        try {
            $VMExists = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
            if ($VMExists.metadata.total_matches -eq 0) {
                Write-Log -Message "[VM Retrieval] VM $($vm) was not found on $($pc_source)" -Level Info
                Continue
            }
            elseif ($resp.metadata.total_matches -gt 1) {
                Write-Log -Message "[VM Retrieval] There are multiple VMs matching name $($vm) on $($pc_source)" -Level Warn
                Continue
            }
            $vm_config = $VMExists.entities[0]
            $vm_uuid = $vm_config.metadata.uuid
            Write-Log -Message "[VM Retrieval] Successfully retrieved the configuration of vm $vm from $($pc_source)" -Level Info
        }
        catch {
            $saved_error = $_.Exception.Message
            Write-Log -Message "$saved_error" -Level Warn
            Continue
        }
        #---------------------------------------------
        # prepare the json payload
        #---------------------------------------------
        $vm_config.PSObject.Properties.Remove('status')

        # process add
        if ($Mode -eq "add") {
            Write-Log -Message "[Category Assignment] Operating in Category Add mode" -Level Info
            try {
                #$Null = $vm_config.metadata.categories | Add-Member -MemberType NoteProperty -Name $category -Value $value -PassThru -ErrorAction Stop
                $Null = $vm_config.metadata.categories_mapping | Add-Member -MemberType NoteProperty -Name $category -Value @($value) -PassThru -ErrorAction Stop
            }
            catch {
                Write-Log -Message "[Category Assignment] Could not add category:value pair ($($category):$($value)). It may already be assigned to the vm $($vm) in $($pc_source)" -Level Warn
                $vm_already_tagged = $true
                continue
            }
        }

        # process remove
        if ($Mode -eq "remove") {
            Write-Log -Message "[Category Assignment] Operating in Category Remove mode" -Level Info
            #$Null = $vm_config.metadata.categories.PSObject.Properties.Remove($category)
            $Null = $vm_config.metadata.categories_mapping.PSObject.Properties.Remove($category)
        }
        #---------------------------------------------
        # update the vm object
        #---------------------------------------------
        if (!$vm_already_tagged) {
            if (!$Whatif) {
                #we are executing
                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "PUT"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($vm_uuid)"
                $Null = $vm_config | Add-Member -MemberType NoteProperty -Name "api_version" -Value "3.1" -PassThru -ErrorAction Stop
                $Null = $vm_config.metadata | Add-Member -MemberType NoteProperty -Name "use_categories_mapping" -Value $true -PassThru -ErrorAction Stop
                $Payload = (ConvertTo-Json $vm_config -Depth 6)
                #----------------------------------------------------------------------------------------------------------------------------
                Write-Log -Message "[VM Update] Updating the configuration of vm $($vm) in $($pc_source)" -Level Info
                do {
                    try {
                        $VMUpdate = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
                        if (!$async){
                            #Get the status of the task above
                            $TaskId = $VMUpdate.status.execution_context.task_uuid
                            $Phase = "[VM Update]"
                            $PhaseSuccessMessage = "VM $($vm) has been updated"
        
                            GetPrismv3Task -TaskID $TaskId -Cluster $pc_source -Credential $PrismCentralCredentials
                        }
                        else {
                            Write-Log -Message "[VM Update] Async processing is enabled, not waiting for a task status response for task $($VMUpdate.status.execution_context.task_uuid) from $($pc_source)" -Level Info
                        }
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
            else {
                #we are in whatif mode
                Write-Log -Message "[WHATIF] [VM Update] Would $($mode) the category: $($Category) with value: $($value) targeting vm: $($vm) in $($pc_source)" -Level Info
            }
        }
    }
    $VMProcessCount += 1
}
#endregion Process the VM list

StopIteration
Exit 0
#endregion

