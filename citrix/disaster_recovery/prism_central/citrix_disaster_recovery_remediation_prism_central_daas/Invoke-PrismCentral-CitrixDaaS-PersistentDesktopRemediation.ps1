<#
.SYNOPSIS
    This script is used to remediate the Citrix DaaS Persistent Desktops after a Nutanix Disaster Recovery has occured, this could be any form of failover to a second PC/AZ.
.DESCRIPTION
    The script uses the Citrix API and the Nutanix Prism Central v4 API. This script will:
    - Query Citrix DaaS for the list of machines in the Catalogs specified by the CatalogNames parameter.
    - Filter the list of machines to exclude any machines in the ExclusionList parameter.
    - Query Nutanix for the list of machines in the target PC/AZ as specified by the TargetPC parameter.
    - Compare the list of machines from Citrix DaaS and Nutanix to determine if any machines need to be updated.
    - Update the Citrix DaaS Machine Hosting Connection to the new target PC/AZ as specified by the HostingConnectionName parameter.
    - Update the Citrix DaaS Machine Hosted Machine ID to the new target PC/AZ if it has changed.
    - Reset the Target Hosting Connection if any machine objects are altered.
    - Switch the Catalog Zone ID to the target zone of the Hosting Connection if specified by the SwitchCatalogZoneID parameter.
.PARAMETER LogPath
    Optional. The path to the log file. Default is "C:\Logs\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.log".
.PARAMETER LogRollover
    Optional. The number of days before logfile rollover occurs. Default is 5.
.PARAMETER TargetPC
    Mandatory. The target Prism Central server. All operations occurs against this Prism Central Instance.
.PARAMETER PCUser
    Mandatory. The Prism Central User.
.PARAMETER PCPass
    Mandatory. The Prism Central Password.
.PARAMETER Region
    Optional. The Citrix DaaS Tenant region. This is the region of the Citrix DaaS Tenant. Default is "US".
.PARAMETER CustomerID
    Mandatory. The Citrix DaaS Customer ID. This is the Customer ID of the Citrix DaaS Tenant.
.PARAMETER ClientID
    Optional. The Citrix Cloud Secure Client ID. This is the Client ID of the Citrix Cloud Secure Client. Negates SecureClientFile parameter. Default is $null.
.PARAMETER ClientSecret
    Optional. The Citrix Cloud Secure Client Secret. This is the Client Secret of the Citrix Cloud Secure Client. Negates SecureClientFile parameter. Default is $null.
.PARAMETER SecureClientFile
    Mandatory. The path to the Secure Client file. This is the file that contains the Citrix Cloud Secure Client ID and Secret. Negates ClientID and ClientSecret parameters.
.PARAMETER CatalogNames
    Mandatory. The names of the Catalogs to use. This is an array of strings. Multiple Catalogs can be specified.
.PARAMETER ExclusionList
    Optional. A list of machines to ignore in the Citrix Catalog. This is an array of strings. Multiple machines can be specified. Do not use DOMAIN\MachineName, use MachineName only.
.PARAMETER HostingConnectionName
    Mandatory. The name of the Hosting Connection to use. This is the target Hosting Connection associated with the Target Prism Central Instance.
.PARAMETER ResetTargetHostingConnection
    Optional. Reset the Target Hosting Connection if any machine objects are altered. This removes the Sync delay between Citrix DaaS and the Nutanix Hosting platform and allows power status to be retrieved. Default is $true.
.PARAMETER SwitchCatalogZoneID
    Optional. Switch the Catalog Zone ID to the target zone of the Hosting Connection. Default is $false.
.PARAMETER Whatif
    Will process in a whatif mode without actually altering anything.
.PARAMETER SilentConsent
    Optional. Will not prompt for user consent to continue. Default is $false.
.PARAMETER Interactive
    Optional. Launch interactive WPF wizard mode. When specified, a multi-step GUI wizard collects Catalogs, Hosting Connection, Exclusions, and options.
    Authentication parameters (TargetPC, PCUser, PCPass, CustomerID, Region, ClientID/ClientSecret or SecureClientFile) are still required.
.EXAMPLE
    See README.md for examples.
.NOTES
    Assumes a form of failover has happened. Currently uses a list of Catalogs as the source of truth for the machines that need to be remediated.
    Could be expanded to use a Recovery Plan as the source of truth
    Could be expanded to use a CSV Import etc.
#>

[CmdletBinding(DefaultParameterSetName = 'CLI')]

param (
    [Parameter(Mandatory = $false)][string]$LogPath = "C:\Logs\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.log", # Where we log to
    [Parameter(Mandatory = $false)][int]$LogRollover = 5, # Number of days before logfile rollover occurs
    # Prism Central Params
    [Parameter(Mandatory = $true)][string]$TargetPC, # The target Prism Central server
    [Parameter(Mandatory = $true)][string]$PCUser, # The Prism Central User
    [Parameter(Mandatory = $true)][string]$PCPass, # The Prism Central Password
    # Citrix DaaS Params
    [Parameter(Mandatory = $false)][string]$Region = "US", # The Citrix DaaS Tenant region
    [Parameter(Mandatory = $true)][string]$CustomerID, # The Citrix DaaS Customer ID
    [Parameter(Mandatory = $false)][string]$ClientID, # The Citrix Cloud Secure Client ID.
    [Parameter(Mandatory = $false)][string]$ClientSecret, # The Citrix Cloud Secure Client Secret.
    [Parameter(Mandatory = $false)][string]$SecureClientFile, # The path to the Secure Client file. This is the file that contains the Citrix Cloud Secure Client ID and Secret.
    # CLI Mode Params (mandatory in CLI mode, collected by wizard in Interactive mode)
    [Parameter(Mandatory = $true, ParameterSetName = 'CLI')][Array]$CatalogNames, # The names of the Catalogs to use
    [Parameter(Mandatory = $false)][Array]$ExclusionList, # A list of machines to ignore in the Citrix Catalog
    [Parameter(Mandatory = $true, ParameterSetName = 'CLI')][string]$HostingConnectionName, # The name of the Hosting Connection to use
    # Optional Params (available in both modes)
    [Parameter(Mandatory = $false)][switch]$ResetTargetHostingConnection, # Reset the Target Hosting Connection if any machine objects are altered.
    [Parameter(Mandatory = $false)][switch]$SwitchCatalogZoneID, # Switch the Catalog Zone ID to the target zone of the Hosting Connection
    # General Options
    [Parameter(Mandatory = $false)][switch]$Whatif, # Will process in a whatif mode without actually altering anything
    [Parameter(Mandatory = $false, ParameterSetName = 'CLI')][switch]$SilentConsent, # Will not prompt for user consent to continue
    # Interactive Mode
    [Parameter(Mandatory = $false, ParameterSetName = 'Interactive')][switch]$Interactive # Launch interactive WPF wizard mode
)

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
        [Parameter(Mandatory = $false)][ValidateSet("Error", "Warn", "Info", "Whatif")][string]$Level = "Info",
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
                $LevelText = 'ERROR:'
                Write-Host "$FormattedDate $LevelText $Message" -ForegroundColor Red
                
            }
            'Warn' {
                $LevelText = 'WARNING:'
                Write-Host "$FormattedDate $LevelText $Message" -ForegroundColor Yellow
                
            }
            'Info' {
                $LevelText = 'INFO:'
                Write-Host "$FormattedDate $LevelText $Message" -ForegroundColor White
            }
            'Whatif' {
                $LevelText = 'WHATIF:'
                Write-Host "$FormattedDate $LevelText $Message" -ForegroundColor Blue
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
    elseif ($StopWatch.Elapsed.TotalMinutes -le 1) {
        Write-Log -Message "Script processing took $($StopWatch.Elapsed.TotalSeconds) seconds to complete." -Level Info
    }
    elseif ($StopWatch.Elapsed.TotalHours -le 1) {
        $minutes = [math]::Floor($StopWatch.Elapsed.TotalMinutes)
        $seconds = $StopWatch.Elapsed.Seconds
        Write-Log -Message "Script processing took $($minutes) minutes and $($seconds) seconds to complete." -Level Info
    }
    else {
        $hours = [math]::Floor($StopWatch.Elapsed.TotalHours)
        $minutes = $StopWatch.Elapsed.Minutes
        $seconds = $StopWatch.Elapsed.Seconds
        Write-Log -Message "Script processing took $($hours) hours, $($minutes) minutes, and $($seconds) seconds to complete." -Level Info
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
        Write-Log -Message "Querying for Clusters under the Prism Central Instance $($pc)" -Level Info
        try {
            $total_clusters = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "Could not connect to Prism Central Instance: $($pc)" -Level Warn
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
        Write-Log -Message "[Prism Central] Querying for Virtual Machines under the Prism Central Instance $($pc)" -Level Info
        try {
            $virtual_machines = Invoke-PrismAPIv4 -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Prism Central] Could not connect to Prism Central Instance: $($pc)" -Level Warn
            Write-Log $_ -Level Warn
            #StopIteration
            #Exit 1
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
                    #StopIteration
                    #Exit 1
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

#-----------------------------------------
# Citrix Functions
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
} 

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

Function Get-CVADHostingConnectionAPI {
    [CmdletBinding()]

    param(
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$HostingConnectionName,
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
        $RequestUri = "https://$DDC/cvad/manage/hypervisors/$($HostingConnectionName)"
        #----------------------------------------------------------------------------------------------------------------------------

        try {
            $cvad_hosting_connection = Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
        }
    }
    end {
        return $cvad_hosting_connection
    }
}

Function Get-CVADAllHostingConnectionsAPI {
    [CmdletBinding()]
    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential
    )
    begin {
        $Headers = Get-CVADAuthHeadersAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
    }
    process {
        $Method = "Get"
        $RequestUri = "https://$DDC/cvad/manage/hypervisors/"
        try {
            $hosting_connections = Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
        }
    }
    end {
        return $hosting_connections.items
    }
}

Function Get-CVADCatalogMachinesAPI {
    [CmdletBinding()]

    param (
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $false)][string]$CatalogNameOrId,
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
        $RequestUri = "https://$DDC/cvad/manage/MachineCatalogs/$($CatalogNameOrId)/Machines?limit=1000"
        #----------------------------------------------------------------------------------------------------------------------------

        try {
            $catalog_machines = [System.Collections.ArrayList]::new()
            $continuation_token = $null

            do {
                # Add continuation token to URI if present
                if ($continuation_token) {
                    $PaginatedUri = "$RequestUri&ContinuationToken=$continuation_token"
                } else {
                    $PaginatedUri = $RequestUri
                }
                
                $response = Invoke-RestMethod -Uri $PaginatedUri -Method $Method -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
                
                # Add items to collection
                [void]$catalog_machines.AddRange($response.Items)
                
                # Get continuation token for next iteration
                $continuation_token = $response.ContinuationToken
                                
            } while ($continuation_token)
        }
        catch {
            Write-Log -Message $_ -Level Error
        }
    }

    end {
        return $catalog_machines
    }
}

Function Invoke-CVADBatchAPI {
    [CmdletBinding()]

    Param(
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential,
        [Parameter(ValuefromPipelineByPropertyName = $true, Mandatory = $true)]$BatchRequests,
        [Parameter(ValuefromPipelineByPropertyName = $true, Mandatory = $false)][switch]$Async
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
        $Method = "POST"
        if ($Async) {
            $RequestUri = "https://$DDC/cvad/manage/`$Batch?async=true"
        } else {
            $RequestUri = "https://$DDC/cvad/manage/`$Batch?async=false"
        }
        $PayloadContent = @{
            Items = $BatchRequests
        }
        $Payload = $PayloadContent | ConvertTo-Json -Depth 10
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $batch_update = Invoke-RestMethod -Method $Method -Headers $headers -Uri $RequestUri -Body $Payload -SkipCertificateCheck -ResponseHeadersVariable ResponseHeaders -ContentType "application/json" -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
            Break
        }
    }
    end {
        return $responseHeaders
    }
} # unused Function for now

Function Get-CVADJobsAPI {

    [CmdletBinding()]

    param(
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $false)][string]$JobID
    )
    begin {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set Headers
        #----------------------------------------------------------------------------------------------------------------------------
        $Headers = Get-CVADAuthHeadersAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
    }
    process {
        #----------------------------------------------------------------------------------------------------------------------------
        # Set API call detail - if a JobID is provided, we will get the details for that job
        # Otherwise, we will get the list of jobs
        #----------------------------------------------------------------------------------------------------------------------------
        $Method = "GET"
        if ($JobID) {
            $RequestUri = "https://$DDC/cvad/manage/Jobs/$($JobID)"
        } else {
            $RequestUri = "https://$DDC/cvad/manage/Jobs/"
        }
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $job_details = Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
        }
    }
    end {
        if ($JobID) {
            return $job_details
        } else {
            return $job_details.Items
        }
    }
}

Function Update-CVADMachineHostingDetailsAPI {
    [CmdletBinding()]

    Param(
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential,
        [Parameter(Mandatory = $true)][string]$MachineId,
        [Parameter(Mandatory = $true)][string]$HostedMachineId,
        [Parameter(Mandatory = $true)][string]$HypervisorConnectionName
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
        $Method = "Patch"
        $RequestUri = "https://$DDC/cvad/manage/Machines/$($MachineId)"
        $PayloadContent = @{
            HostedMachineId = $HostedMachineId
            HypervisorConnection = $HypervisorConnectionName
        }
        $Payload = $PayloadContent | ConvertTo-Json
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $update_machine = Invoke-RestMethod -Method $Method -Headers $headers -Uri $RequestUri -Body $Payload -ContentType "application/json" -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
            Break
        }
    }
    end {
        return $update_machine
    }
}

Function Switch-CVADCatalogZoneIDAPI {
    [CmdletBinding()]

    param(
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$EncodedAdminCredential,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$CatalogName,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$CatalogId,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$ZoneId
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
        $Method = "POST"
        $RequestUri = "https://$DDC/cvad/manage/Zones/$($ZoneId)/`$moveItems?async=false"
        $Payload = @{
            Items = @(
                @{
                    Id = $CatalogId
                    Name = $CatalogName
                    ItemType = "MachineCatalog"
                }
            )
        }
        $Payload = $Payload | ConvertTo-Json -depth 10
        #----------------------------------------------------------------------------------------------------------------------------
        try {
            $catalog_zone_id_switch = Invoke-RestMethod -Method $Method -Headers $Headers -Body $Payload -Uri $RequestUri -SkipCertificateCheck -ContentType "application/json" -TimeoutSec 2400 -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
        }
    }
    end {
        return $catalog_zone_id_switch
    }
}

Function Reset-CVADHostingConnectionAPI {
    [CmdletBinding()]

    param(
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$DDC,
        [Parameter(ValuefromPipelineByPropertyName = $true, mandatory = $true)][string]$HostingConnectionNameOrId,
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
        $Method = "POST"
        $RequestUri = "https://$DDC/cvad/manage/hypervisors/$($HostingConnectionNameOrId)/`$resetConnection"
        #----------------------------------------------------------------------------------------------------------------------------

        try {
            $cvad_hosting_connection_reset = Invoke-RestMethod -Uri $RequestUri -Method $Method -Headers $Headers -ContentType "application/json" -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            Write-Log -Message $_ -Level Error
        }
    }
    end {
        return $cvad_hosting_connection_reset
    }
}

#-----------------------------------------
# WPF Interactive Functions
#-----------------------------------------
function Show-WPFMessageDialog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet("Info", "Error", "Warning", "Question")][string]$MessageType = "Info",
        [Parameter(Mandatory = $false)][ValidateSet("OK", "YesNo")][string]$Buttons = "OK"
    )
    switch ($MessageType) {
        "Error"    { $iconText = "!"; $iconColor = "#E74C3C"; $iconBg = "#2C1A1A" }
        "Warning"  { $iconText = "!"; $iconColor = "#F0A030"; $iconBg = "#2C2518" }
        "Question" { $iconText = "?"; $iconColor = "#22A7C0"; $iconBg = "#0E1926" }
        default    { $iconText = "i"; $iconColor = "#22A7C0"; $iconBg = "#0E1926" }
    }
    if ($Buttons -eq "YesNo") {
        $buttonXaml = @"
            <Button Name="btnYes" Grid.Column="1" Content="Yes" Width="120" Height="36" FontSize="13" FontWeight="SemiBold" Foreground="White" Cursor="Hand" BorderThickness="0">
                <Button.Template><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="#22A7C0" CornerRadius="4" Padding="20,8"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Opacity" Value="0.85"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Button.Template>
            </Button>
            <Button Name="btnNo" Grid.Column="3" Content="No" Width="120" Height="36" FontSize="13" Foreground="#CCDBE8" Cursor="Hand" BorderThickness="0">
                <Button.Template><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="#243A52" CornerRadius="4" Padding="20,8"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#2E4A64"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Button.Template>
            </Button>
"@
    } else {
        $buttonXaml = @"
            <Button Name="btnOKMsg" Grid.Column="1" Content="OK" Width="120" Height="36" FontSize="13" FontWeight="SemiBold" Foreground="White" Cursor="Hand" BorderThickness="0" IsDefault="True">
                <Button.Template><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="#22A7C0" CornerRadius="4" Padding="20,8"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Opacity" Value="0.85"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Button.Template>
            </Button>
"@
    }
    $safeMessage = $Message.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace('"', "&quot;").Replace("'", "&apos;")
    $safeTitle = $Title.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace('"', "&quot;").Replace("'", "&apos;")
    [xml]$msgXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$safeTitle" SizeToContent="Height" Width="460" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" Background="#121E2E" FontFamily="Segoe UI">
    <StackPanel Margin="24,20,24,24">
        <Border Background="#1A2D42" CornerRadius="8" Padding="20,16" BorderBrush="#243A52" BorderThickness="1" Margin="0,0,0,20">
            <DockPanel>
                <Border DockPanel.Dock="Left" Background="$iconBg" CornerRadius="20" Width="40" Height="40" Margin="0,0,16,0" BorderBrush="$iconColor" BorderThickness="2">
                    <TextBlock Text="$iconText" FontSize="20" FontWeight="Bold" Foreground="$iconColor" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                </Border>
                <StackPanel VerticalAlignment="Center">
                    <TextBlock Text="$safeTitle" FontSize="15" FontWeight="SemiBold" Foreground="#FFFFFF" Margin="0,0,0,6"/>
                    <TextBlock Text="$safeMessage" FontSize="12" Foreground="#B8CCDD" TextWrapping="Wrap"/>
                </StackPanel>
            </DockPanel>
        </Border>
        <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="10"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            $buttonXaml
        </Grid>
    </StackPanel>
</Window>
"@
    $msgReader = New-Object System.Xml.XmlNodeReader $msgXaml
    $msgWindow = [Windows.Markup.XamlReader]::Load($msgReader)
    if ($Buttons -eq "YesNo") {
        $msgWindow.FindName("btnYes").Add_Click({ $msgWindow.DialogResult = $true; $msgWindow.Close() })
        $msgWindow.FindName("btnNo").Add_Click({ $msgWindow.DialogResult = $false; $msgWindow.Close() })
    } else {
        $msgWindow.FindName("btnOKMsg").Add_Click({ $msgWindow.DialogResult = $true; $msgWindow.Close() })
    }
    $result = $msgWindow.ShowDialog()
    return ($result -eq $true)
}

function Show-ConfigurationWindow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PCServer,
        [Parameter(Mandatory = $true)][string]$PCVersion,
        [Parameter(Mandatory = $true)][int]$PCClusterCount,
        [Parameter(Mandatory = $true)][string]$CitrixSiteName,
        [Parameter(Mandatory = $true)][string]$CitrixVersion,
        [Parameter(Mandatory = $true)][array]$Catalogs,
        [Parameter(Mandatory = $true)][array]$HostingConnections,
        [Parameter(Mandatory = $false)][bool]$WhatIfFromParam = $false
    )
    $whatifStatusText = if ($WhatIfFromParam) { "WhatIf: Enabled (no changes will be made)" } else { "WhatIf: Disabled" }
    $whatifStatusColor = if ($WhatIfFromParam) { "#22A7C0" } else { "#9AACBE" }
    [xml]$cfgXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Disaster Recovery Remediation - Configuration" Height="820" Width="750" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" Background="#121E2E" FontFamily="Segoe UI">
    <Window.Resources>
        <Style TargetType="CheckBox"><Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="Margin" Value="0,3"/></Style>
        <ControlTemplate x:Key="DarkComboBoxToggle" TargetType="ToggleButton">
            <Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="20"/></Grid.ColumnDefinitions>
                <Border x:Name="Border" Grid.ColumnSpan="2" Background="#0E1926" BorderBrush="#2E4A64" BorderThickness="1" CornerRadius="3"/>
                <Path x:Name="Arrow" Grid.Column="1" Fill="#8899AB" HorizontalAlignment="Center" VerticalAlignment="Center" Data="M 0 0 L 4 4 L 8 0 Z"/>
            </Grid>
            <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Border" Property="BorderBrush" Value="#22A7C0"/><Setter TargetName="Arrow" Property="Fill" Value="#22A7C0"/></Trigger></ControlTemplate.Triggers>
        </ControlTemplate>
        <Style x:Key="ModernCombo" TargetType="ComboBox">
            <Setter Property="FontSize" Value="12"/><Setter Property="Height" Value="28"/><Setter Property="Margin" Value="0,0,0,8"/><Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="SnapsToDevicePixels" Value="True"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBox">
                        <Grid>
                            <ToggleButton Name="ToggleButton" Template="{StaticResource DarkComboBoxToggle}" Focusable="False" IsChecked="{Binding Path=IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}" ClickMode="Press"/>
                            <ContentPresenter Name="ContentSite" IsHitTestVisible="False" Content="{TemplateBinding SelectionBoxItem}" ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}" Margin="8,2,24,2" VerticalAlignment="Center" HorizontalAlignment="Left">
                                <ContentPresenter.Resources><Style TargetType="TextBlock"><Setter Property="Foreground" Value="#FFFFFF"/></Style></ContentPresenter.Resources>
                            </ContentPresenter>
                            <Popup Name="Popup" Placement="Bottom" IsOpen="{TemplateBinding IsDropDownOpen}" AllowsTransparency="True" Focusable="False" PopupAnimation="Slide">
                                <Grid Name="DropDown" SnapsToDevicePixels="True" MinWidth="{TemplateBinding ActualWidth}" MaxHeight="{TemplateBinding MaxDropDownHeight}">
                                    <Border Background="#0E1926" BorderThickness="1" BorderBrush="#2E4A64" CornerRadius="3"/>
                                    <ScrollViewer Margin="2" SnapsToDevicePixels="True"><StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Contained"/></ScrollViewer>
                                </Grid>
                            </Popup>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Setter Property="ItemContainerStyle">
                <Setter.Value>
                    <Style TargetType="ComboBoxItem">
                        <Setter Property="Background" Value="#0E1926"/><Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="Padding" Value="8,5"/><Setter Property="BorderThickness" Value="0"/>
                        <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ComboBoxItem"><Border x:Name="Bd" Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}" CornerRadius="2" Margin="2,1"><ContentPresenter/></Border><ControlTemplate.Triggers><Trigger Property="IsHighlighted" Value="True"><Setter TargetName="Bd" Property="Background" Value="#22A7C0"/></Trigger><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#1A3A50"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
                    </Style>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <ScrollViewer VerticalScrollBarVisibility="Auto">
    <StackPanel Margin="24,18,24,18">
        <Border Background="#1A2D42" CornerRadius="8" Padding="20,14" BorderBrush="#243A52" BorderThickness="1" Margin="0,0,0,12">
            <StackPanel>
                <TextBlock Text="Nutanix Prism Central for Citrix DaaS Remediation" FontSize="18" FontWeight="SemiBold" Foreground="#FFFFFF" Margin="0,0,0,4"/>
                <TextBlock Text="Step 1 of 2: Configuration" FontSize="12" Foreground="#8899AB" Margin="0,0,0,6"/>
                <TextBlock Text="$whatifStatusText" FontSize="12" FontWeight="SemiBold" Foreground="$whatifStatusColor"/>
            </StackPanel>
        </Border>
        <Grid Margin="0,0,0,8">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="8"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <Border Grid.Column="0" Background="#1A2D42" CornerRadius="8" Padding="18,12" BorderBrush="#243A52" BorderThickness="1">
                <StackPanel>
                    <TextBlock Text="PRISM CENTRAL" FontSize="13" FontWeight="SemiBold" Foreground="#22A7C0" Margin="0,0,0,8"/>
                    <Grid>
                        <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="8"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                        <Grid.RowDefinitions><RowDefinition Height="22"/><RowDefinition Height="22"/><RowDefinition Height="22"/></Grid.RowDefinitions>
                        <TextBlock Grid.Row="0" Grid.Column="0" Text="Status:" FontSize="12" Foreground="#B8CCDD"/>
                        <TextBlock Grid.Row="0" Grid.Column="2" Name="txtPCStatus" Text="Connected" FontSize="12" Foreground="#2E8B57" FontWeight="SemiBold"/>
                        <TextBlock Grid.Row="1" Grid.Column="0" Text="Version:" FontSize="12" Foreground="#B8CCDD"/>
                        <TextBlock Grid.Row="1" Grid.Column="2" Name="txtPCVersion" FontSize="12" Foreground="#FFFFFF"/>
                        <TextBlock Grid.Row="2" Grid.Column="0" Text="Clusters:" FontSize="12" Foreground="#B8CCDD"/>
                        <TextBlock Grid.Row="2" Grid.Column="2" Name="txtPCClusters" FontSize="12" Foreground="#FFFFFF"/>
                    </Grid>
                </StackPanel>
            </Border>
            <Border Grid.Column="2" Background="#1A2D42" CornerRadius="8" Padding="18,12" BorderBrush="#243A52" BorderThickness="1">
                <StackPanel>
                    <TextBlock Text="Citrix DaaS" FontSize="13" FontWeight="SemiBold" Foreground="#22A7C0" Margin="0,0,0,8"/>
                    <Grid>
                        <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="8"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                        <Grid.RowDefinitions><RowDefinition Height="22"/><RowDefinition Height="22"/><RowDefinition Height="22"/></Grid.RowDefinitions>
                        <TextBlock Grid.Row="0" Grid.Column="0" Text="Status:" FontSize="12" Foreground="#B8CCDD"/>
                        <TextBlock Grid.Row="0" Grid.Column="2" Name="txtCitrixStatus" Text="Connected" FontSize="12" Foreground="#2E8B57" FontWeight="SemiBold"/>
                        <TextBlock Grid.Row="1" Grid.Column="0" Text="Site:" FontSize="12" Foreground="#B8CCDD"/>
                        <TextBlock Grid.Row="1" Grid.Column="2" Name="txtCitrixSite" FontSize="12" Foreground="#FFFFFF"/>
                        <TextBlock Grid.Row="2" Grid.Column="0" Text="Version:" FontSize="12" Foreground="#B8CCDD"/>
                        <TextBlock Grid.Row="2" Grid.Column="2" Name="txtCitrixVersion" FontSize="12" Foreground="#FFFFFF"/>
                    </Grid>
                </StackPanel>
            </Border>
        </Grid>
        <Border Background="#1A2D42" CornerRadius="8" Padding="18,12" BorderBrush="#243A52" BorderThickness="1" Margin="0,0,0,8">
            <StackPanel>
                <TextBlock Text="Machine Catalogs (Manual)" FontSize="13" FontWeight="SemiBold" Foreground="#FFFFFF" Margin="0,0,0,6"/>
                <Border Background="#0E1926" CornerRadius="4" BorderBrush="#2E4A64" BorderThickness="1" Padding="6" MaxHeight="130">
                    <ScrollViewer VerticalScrollBarVisibility="Auto">
                        <StackPanel Name="pnlCatalogs"/>
                    </ScrollViewer>
                </Border>
            </StackPanel>
        </Border>
        <Border Background="#1A2D42" CornerRadius="8" Padding="18,12" BorderBrush="#243A52" BorderThickness="1" Margin="0,0,0,8">
            <StackPanel>
                <TextBlock Text="Hosting Connection" FontSize="13" FontWeight="SemiBold" Foreground="#FFFFFF" Margin="0,0,0,6"/>
                <ComboBox Name="cboHostingConnection" Style="{StaticResource ModernCombo}"/>
            </StackPanel>
        </Border>
        <Border Background="#1A2D42" CornerRadius="8" Padding="18,12" BorderBrush="#243A52" BorderThickness="1" Margin="0,0,0,8">
            <StackPanel>
                <DockPanel Margin="0,0,0,6">
                    <TextBlock DockPanel.Dock="Left" Text="Exclude Machines (optional)" FontSize="13" FontWeight="SemiBold" Foreground="#FFFFFF" VerticalAlignment="Center"/>
                    <Button Name="btnLoadMachines" DockPanel.Dock="Right" Content="Load Machines from Selected Catalogs" Width="250" Height="28" FontSize="12" FontWeight="SemiBold" Foreground="White" Cursor="Hand" BorderThickness="0" HorizontalAlignment="Right">
                        <Button.Template><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="#243A52" CornerRadius="3" Padding="8,4"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#2E4A64"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Button.Template>
                    </Button>
                </DockPanel>
                <Border Background="#0E1926" CornerRadius="4" BorderBrush="#2E4A64" BorderThickness="1" Padding="6" MaxHeight="150">
                    <ScrollViewer VerticalScrollBarVisibility="Auto">
                        <StackPanel Name="pnlExclusions">
                            <TextBlock Name="txtExclusionsPlaceholder" Text="Click 'Load Machines from Selected Catalogs' to populate this list." FontSize="11" Foreground="#8899AB" TextWrapping="Wrap" Margin="4,6"/>
                        </StackPanel>
                    </ScrollViewer>
                </Border>
            </StackPanel>
        </Border>
        <Border Background="#1A2D42" CornerRadius="8" Padding="18,12" BorderBrush="#243A52" BorderThickness="1" Margin="0,0,0,8">
            <StackPanel>
                <TextBlock Text="OPTIONS" FontSize="13" FontWeight="SemiBold" Foreground="#22A7C0" Margin="0,0,0,8"/>
                <CheckBox Name="chkResetHC" Content="Reset Target Hosting Connection after changes"/>
                <CheckBox Name="chkSwitchZone" Content="Switch Catalog Zone ID to target zone"/>
            </StackPanel>
        </Border>
        <Grid Margin="0,8,0,0">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="10"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <Button Name="btnCfgNext" Grid.Column="1" Content="Next" Width="120" Height="36" FontSize="13" FontWeight="SemiBold" Foreground="White" Cursor="Hand" BorderThickness="0">
                <Button.Template><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="#22A7C0" CornerRadius="4" Padding="20,8"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Opacity" Value="0.85"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Button.Template>
            </Button>
            <Button Name="btnCfgCancel" Grid.Column="3" Content="Cancel" Width="120" Height="36" FontSize="13" Foreground="#CCDBE8" Cursor="Hand" BorderThickness="0" IsCancel="True">
                <Button.Template><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="#243A52" CornerRadius="4" Padding="20,8"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#2E4A64"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Button.Template>
            </Button>
        </Grid>
    </StackPanel>
    </ScrollViewer>
</Window>
"@
    $cfgReader = New-Object System.Xml.XmlNodeReader $cfgXaml
    $cfgWindow = [Windows.Markup.XamlReader]::Load($cfgReader)

    # Populate PC status
    $cfgWindow.FindName("txtPCStatus").Text = "Connected to $($PCServer)"
    $cfgWindow.FindName("txtPCVersion").Text = $PCVersion
    $cfgWindow.FindName("txtPCClusters").Text = "$($PCClusterCount) cluster(s)"

    # Populate Citrix status
    $cfgWindow.FindName("txtCitrixSite").Text = $CitrixSiteName
    $cfgWindow.FindName("txtCitrixVersion").Text = $CitrixVersion

    # Populate Catalogs checkboxes (Tag = Id so we can use it for Get-CVADCatalogMachinesAPI)
    $pnlCatalogs = $cfgWindow.FindName("pnlCatalogs")
    $whiteBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FFFFFF")
    foreach ($cat in $Catalogs | Sort-Object name) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = $cat.name
        $cb.Tag = $cat
        $cb.Foreground = $whiteBrush
        $cb.Margin = [System.Windows.Thickness]::new(4, 3, 4, 3)
        $null = $pnlCatalogs.Children.Add($cb)
    }

    # Populate Hosting Connections
    $cboHC = $cfgWindow.FindName("cboHostingConnection")
    foreach ($hc in $HostingConnections | Sort-Object name) {
        $null = $cboHC.Items.Add($hc.name)
    }
    if ($cboHC.Items.Count -gt 0) { $cboHC.SelectedIndex = 0 }

    # Load Machines handler - rebuilds the exclusion checkbox panel based on currently-checked catalogs
    $pnlExclusions = $cfgWindow.FindName("pnlExclusions")
    $script:wizardExclusionCache = @{}
    $cfgWindow.FindName("btnLoadMachines").Add_Click({
        $selectedCatalogs = @()
        foreach ($child in $pnlCatalogs.Children) { if ($child.IsChecked -eq $true) { $selectedCatalogs += $child.Tag } }
        if ($selectedCatalogs.Count -eq 0) {
            $null = Show-WPFMessageDialog -Title "No Catalogs Selected" -Message "Please select one or more Machine Catalogs before loading machines." -MessageType "Warning"
            return
        }
        $pnlExclusions.Children.Clear()
        $loadingTxt = New-Object System.Windows.Controls.TextBlock
        $loadingTxt.Text = "Loading machines..."
        $loadingTxt.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#8899AB")
        $loadingTxt.FontSize = 11
        $loadingTxt.Margin = [System.Windows.Thickness]::new(4, 6, 4, 6)
        $null = $pnlExclusions.Children.Add($loadingTxt)
        $cfgWindow.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)

        $allMachines = [System.Collections.Generic.List[string]]::new()
        foreach ($cat in $selectedCatalogs) {
            if (-not $script:wizardExclusionCache.ContainsKey($cat.id)) {
                try {
                    $catMachines = Get-CVADCatalogMachinesAPI -DDC $Global:DDC -EncodedAdminCredential $Global:EncodedAdminCredential -CatalogNameOrId $cat.id
                    $shortNames = @()
                    foreach ($m in $catMachines) { $shortNames += ($m.name -split '\\')[-1] }
                    $script:wizardExclusionCache[$cat.id] = $shortNames
                } catch {
                    $script:wizardExclusionCache[$cat.id] = @()
                }
            }
            foreach ($n in $script:wizardExclusionCache[$cat.id]) { if (-not [string]::IsNullOrWhiteSpace($n)) { $allMachines.Add($n) } }
        }

        $pnlExclusions.Children.Clear()
        $uniqueMachines = $allMachines | Select-Object -Unique | Sort-Object
        if (-not $uniqueMachines -or $uniqueMachines.Count -eq 0) {
            $emptyTxt = New-Object System.Windows.Controls.TextBlock
            $emptyTxt.Text = "No machines found in the selected catalog(s)."
            $emptyTxt.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#8899AB")
            $emptyTxt.FontSize = 11
            $emptyTxt.Margin = [System.Windows.Thickness]::new(4, 6, 4, 6)
            $null = $pnlExclusions.Children.Add($emptyTxt)
            return
        }
        foreach ($name in $uniqueMachines) {
            $cb = New-Object System.Windows.Controls.CheckBox
            $cb.Content = $name
            $cb.Tag = $name
            $cb.Foreground = $whiteBrush
            $cb.Margin = [System.Windows.Thickness]::new(4, 2, 4, 2)
            $null = $pnlExclusions.Children.Add($cb)
        }
    })

    # Next button with validation
    $cfgWindow.FindName("btnCfgNext").Add_Click({
        $selCats = @()
        foreach ($child in $pnlCatalogs.Children) { if ($child.IsChecked -eq $true) { $selCats += $child.Tag.name } }
        if ($selCats.Count -eq 0) { $null = Show-WPFMessageDialog -Title "Validation" -Message "Please select at least one Catalog." -MessageType "Warning"; return }
        if ($null -eq $cboHC.SelectedItem) { $null = Show-WPFMessageDialog -Title "Validation" -Message "Please select a Hosting Connection." -MessageType "Warning"; return }
        $cfgWindow.DialogResult = $true
        $cfgWindow.Close()
    })
    $cfgWindow.FindName("btnCfgCancel").Add_Click({ $cfgWindow.DialogResult = $false; $cfgWindow.Close() })

    $result = $cfgWindow.ShowDialog()
    if ($result -eq $true) {
        $selectedCatalogs = @()
        foreach ($child in $pnlCatalogs.Children) { if ($child.IsChecked -eq $true) { $selectedCatalogs += $child.Tag.name } }
        $selectedExclusions = @()
        foreach ($child in $pnlExclusions.Children) {
            if ($child -is [System.Windows.Controls.CheckBox] -and $child.IsChecked -eq $true) { $selectedExclusions += $child.Tag }
        }
        return @{
            CatalogNames                 = $selectedCatalogs
            HostingConnectionName        = $cboHC.SelectedItem
            ResetTargetHostingConnection = ($cfgWindow.FindName("chkResetHC").IsChecked -eq $true)
            SwitchCatalogZoneID          = ($cfgWindow.FindName("chkSwitchZone").IsChecked -eq $true)
            ExclusionList                = $selectedExclusions
        }
    }
    return $null
}

function Show-ConfirmationWindow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][bool]$WhatIfEnabled,
        [Parameter(Mandatory = $true)][array]$CatalogNames,
        [Parameter(Mandatory = $true)][string]$HostingConnectionName,
        [Parameter(Mandatory = $true)][bool]$ResetHC,
        [Parameter(Mandatory = $true)][bool]$SwitchZone,
        [Parameter(Mandatory = $false)][array]$ExclusionList,
        [Parameter(Mandatory = $true)][int]$VMCount
    )
    $whatifText = if ($WhatIfEnabled) { "WhatIf - No changes will be made" } else { "Live - Changes WILL be applied" }
    $whatifColor = if ($WhatIfEnabled) { "#22A7C0" } else { "#F0A030" }
    $catalogsText = ($CatalogNames -join "`n")
    $resetText = if ($ResetHC) { "Yes" } else { "No" }
    $switchText = if ($SwitchZone) { "Yes" } else { "No" }
    if ($null -eq $ExclusionList -or $ExclusionList.Count -eq 0) {
        $exclusionText = "None"
    } else {
        $previewCount = [Math]::Min(10, $ExclusionList.Count)
        $preview = ($ExclusionList | Select-Object -First $previewCount) -join "`n"
        if ($ExclusionList.Count -gt $previewCount) {
            $exclusionText = "$preview`n... and $($ExclusionList.Count - $previewCount) more ($($ExclusionList.Count) total)"
        } else {
            $exclusionText = "$preview ($($ExclusionList.Count) total)"
        }
    }

    $safeCatalogs = $catalogsText.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
    $safeHC = $HostingConnectionName.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
    $safeExclusions = $exclusionText.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")

    [xml]$confXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Disaster Recovery Remediation - Confirmation" SizeToContent="Height" Width="640" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" Background="#121E2E" FontFamily="Segoe UI">
    <StackPanel Margin="24,20,24,20">
        <Border Background="#1A2D42" CornerRadius="8" Padding="20,14" BorderBrush="#243A52" BorderThickness="1" Margin="0,0,0,14">
            <StackPanel>
                <TextBlock Text="Nutanix Prism Central for Citrix DaaS Remediation" FontSize="18" FontWeight="SemiBold" Foreground="#FFFFFF" Margin="0,0,0,4"/>
                <TextBlock Text="Step 2 of 2: Review and Confirm" FontSize="12" Foreground="#8899AB"/>
            </StackPanel>
        </Border>
        <Border Background="#1A2D42" CornerRadius="8" Padding="20,16" BorderBrush="#243A52" BorderThickness="1" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="200"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Grid.Row="0" Grid.Column="0" Text="Execution Mode:" FontSize="12" Foreground="#B8CCDD" Margin="0,3"/>
                <TextBlock Grid.Row="0" Grid.Column="1" Text="$whatifText" FontSize="12" Foreground="$whatifColor" FontWeight="SemiBold" Margin="0,3"/>
                <TextBlock Grid.Row="1" Grid.Column="0" Text="Catalogs:" FontSize="12" Foreground="#B8CCDD" Margin="0,3"/>
                <TextBlock Grid.Row="1" Grid.Column="1" Text="$safeCatalogs" FontSize="12" Foreground="#FFFFFF" TextWrapping="Wrap" Margin="0,3"/>
                <TextBlock Grid.Row="2" Grid.Column="0" Text="Hosting Connection:" FontSize="12" Foreground="#B8CCDD" Margin="0,3"/>
                <TextBlock Grid.Row="2" Grid.Column="1" Text="$safeHC" FontSize="12" Foreground="#FFFFFF" Margin="0,3"/>
                <TextBlock Grid.Row="3" Grid.Column="0" Text="Reset Hosting Connection:" FontSize="12" Foreground="#B8CCDD" Margin="0,3"/>
                <TextBlock Grid.Row="3" Grid.Column="1" Text="$resetText" FontSize="12" Foreground="#FFFFFF" Margin="0,3"/>
                <TextBlock Grid.Row="4" Grid.Column="0" Text="Switch Catalog Zone:" FontSize="12" Foreground="#B8CCDD" Margin="0,3"/>
                <TextBlock Grid.Row="4" Grid.Column="1" Text="$switchText" FontSize="12" Foreground="#FFFFFF" Margin="0,3"/>
                <TextBlock Grid.Row="5" Grid.Column="0" Text="Exclusions:" FontSize="12" Foreground="#B8CCDD" Margin="0,3"/>
                <TextBlock Grid.Row="5" Grid.Column="1" Text="$safeExclusions" FontSize="12" Foreground="#FFFFFF" TextWrapping="Wrap" Margin="0,3"/>
                <TextBlock Grid.Row="6" Grid.Column="0" Text="Machines Impacted:" FontSize="12" Foreground="#B8CCDD" Margin="0,3"/>
                <TextBlock Grid.Row="6" Grid.Column="1" Text="$VMCount" FontSize="13" Foreground="#22A7C0" FontWeight="SemiBold" Margin="0,3"/>
            </Grid>
        </Border>
        <Border Background="#2C2518" CornerRadius="6" Padding="14,10" BorderBrush="#F0A030" BorderThickness="1" Margin="0,0,0,16">
            <DockPanel>
                <TextBlock DockPanel.Dock="Left" Text="!" FontSize="16" FontWeight="Bold" Foreground="#F0A030" Margin="0,0,10,0" VerticalAlignment="Center"/>
                <TextBlock Text="Please review the above settings carefully before proceeding. This operation will alter Citrix machine hosting information." FontSize="12" Foreground="#F0A030" TextWrapping="Wrap" VerticalAlignment="Center"/>
            </DockPanel>
        </Border>
        <Grid>
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="10"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <Button Name="btnProceed" Grid.Column="1" Content="Proceed" Width="130" Height="36" FontSize="13" FontWeight="SemiBold" Foreground="White" Cursor="Hand" BorderThickness="0">
                <Button.Template><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="#22A7C0" CornerRadius="4" Padding="20,8"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Opacity" Value="0.85"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Button.Template>
            </Button>
            <Button Name="btnConfCancel" Grid.Column="3" Content="Cancel" Width="130" Height="36" FontSize="13" Foreground="#CCDBE8" Cursor="Hand" BorderThickness="0" IsCancel="True">
                <Button.Template><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="#243A52" CornerRadius="4" Padding="20,8"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#2E4A64"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Button.Template>
            </Button>
        </Grid>
    </StackPanel>
</Window>
"@
    $confReader = New-Object System.Xml.XmlNodeReader $confXaml
    $confWindow = [Windows.Markup.XamlReader]::Load($confReader)
    $confWindow.FindName("btnProceed").Add_Click({ $confWindow.DialogResult = $true; $confWindow.Close() })
    $confWindow.FindName("btnConfCancel").Add_Click({ $confWindow.DialogResult = $false; $confWindow.Close() })
    $result = $confWindow.ShowDialog()
    return ($result -eq $true)
}

#endregion Functions

#region variables
# ============================================================================
# Variables
# ============================================================================
$Global:IsCitrixDaaS = $true
$SupportedHypervisorPlugTypes = @("AcropolisPCFactory", "AcropolisHypervisorPCFactory")
#endregion variables

# Fix Header Validation Issues. Specifically the way the ':' value is handled.
$PSDefaultParameterValues['Invoke-RestMethod:SkipHeaderValidation'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:SkipHeaderValidation'] = $true

#region Interactive Mode
# ============================================================================
# Interactive WPF Wizard Mode
# ============================================================================
if ($Interactive.IsPresent) {
    Write-Log -Message "[Interactive Mode] Starting WPF Wizard" -Level Info

    # PowerShell 7 guard (WPF assemblies still load via Add-Type on pwsh 7 on Windows)
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Log -Message "[Interactive Mode] This script only supports PowerShell 7" -Level Error
        Write-Log -Message "[Interactive Mode] PowerShell version is: $($PSVersionTable.PSVersion)" -Level Info
        Exit 1
    }

    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase

    # ---- Early Citrix Authentication (needed to query catalogs and hosting connections) ----
    Write-Log -Message "[Interactive Mode] Authenticating to Citrix DaaS" -Level Info
    if ($SecureClientFile) {
        try {
            $SecureClient = Import-Csv -Path $SecureClientFile -ErrorAction Stop
            $Global:ClientID = $SecureClient.ID
            $Global:ClientSecret = $SecureClient.Secret
        } catch {
            Write-Log -Message "[Interactive Mode] Failed to import Secure Client File" -Level Error
            $null = Show-WPFMessageDialog -Title "Authentication Error" -Message "Failed to import Secure Client File: $_" -MessageType "Error"
            Exit 1
        }
    } else {
        $Global:ClientID = $ClientID
        $Global:ClientSecret = $ClientSecret
    }
    $Global:CustomerID = $CustomerID
    $Global:Region = $Region
    switch ($Global:Region) {
        'AP-S' { $Global:CloudUrl = "api-ap-s.cloud.com" }
        'EU'   { $Global:CloudUrl = "api-eu.cloud.com" }
        'US'   { $Global:CloudUrl = "api-us.cloud.com" }
        'JP'   { $Global:CloudUrl = "api.citrixcloud.jp" }
    }
    $Global:DDC = $CloudUrl
    $Global:EncodedAdminCredential = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("ADummyValueBecauseThisIsNotNeededForDaaS"))

    # ---- Early PC Authentication ----
    $PrismCentralCredentials = New-Object System.Management.Automation.PSCredential ($PCUser, (ConvertTo-SecureString $PCPass -AsPlainText -Force))

    # ---- Query Prism Central ----
    Write-Log -Message "[Interactive Mode] Querying Prism Central: $($TargetPC)" -Level Info
    $wizard_cluster_list = Get-PCClusters -pc $TargetPC -PrismCentralCredentials $PrismCentralCredentials
    if ([string]::IsNullOrEmpty($wizard_cluster_list)) {
        Write-Log -Message "[Interactive Mode] Could not connect to Prism Central: $($TargetPC)" -Level Error
        $null = Show-WPFMessageDialog -Title "Connection Error" -Message "Could not connect to Prism Central at $($TargetPC). Please verify connectivity." -MessageType "Error"
        Exit 1
    }
    $wizard_pc_cluster = $wizard_cluster_list | Where-Object { $_.config.clusterFunction -eq "PRISM_CENTRAL" }
    $wizard_non_pc_clusters = $wizard_cluster_list | Where-Object { $_.config.clusterFunction -ne "PRISM_CENTRAL" }
    $wizard_pc_version = $wizard_pc_cluster.config.buildInfo.version
    $wizard_pc_cluster_count = $wizard_non_pc_clusters.Count
    Write-Log -Message "[Interactive Mode] PC Version: $($wizard_pc_version), Clusters: $($wizard_pc_cluster_count)" -Level Info

    # ---- Query Citrix DaaS ----
    Write-Log -Message "[Interactive Mode] Querying Citrix DaaS" -Level Info
    $wizard_site_details = Get-CVADSiteDetailAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
    if ([string]::IsNullOrEmpty($wizard_site_details)) {
        Write-Log -Message "[Interactive Mode] Failed to connect to Citrix DaaS" -Level Error
        $null = Show-WPFMessageDialog -Title "Connection Error" -Message "Failed to connect to Citrix DaaS. Please verify credentials." -MessageType "Error"
        Exit 1
    }
    $wizard_site_name = $wizard_site_details.cvad_site.name
    $wizard_site_version = $wizard_site_details.cvad_site.ProductVersion
    Write-Log -Message "[Interactive Mode] Citrix Site: $($wizard_site_name), Version: $($wizard_site_version)" -Level Info

    $wizard_all_catalogs = Get-CVADCatalogsAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
    $wizard_manual_catalogs = $wizard_all_catalogs | Where-Object { $_.ProvisioningType -eq "Manual" }
    if ($wizard_manual_catalogs.Count -eq 0) {
        Write-Log -Message "[Interactive Mode] No Manual Catalogs found" -Level Error
        $null = Show-WPFMessageDialog -Title "Configuration Error" -Message "No Manual Machine Catalogs found in the Citrix environment." -MessageType "Error"
        Exit 1
    }
    Write-Log -Message "[Interactive Mode] Found $($wizard_manual_catalogs.Count) Manual Catalogs" -Level Info

    $wizard_all_hosting_connections = Get-CVADAllHostingConnectionsAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
    $wizard_nutanix_hosting_connections = $wizard_all_hosting_connections | Where-Object { $_.PluginId -in $SupportedHypervisorPlugTypes }
    if ($wizard_nutanix_hosting_connections.Count -eq 0) {
        Write-Log -Message "[Interactive Mode] No supported Nutanix Hosting Connections found" -Level Error
        $null = Show-WPFMessageDialog -Title "Configuration Error" -Message "No supported Nutanix Hosting Connections found in the Citrix environment." -MessageType "Error"
        Exit 1
    }
    Write-Log -Message "[Interactive Mode] Found $($wizard_nutanix_hosting_connections.Count) supported Hosting Connections" -Level Info

    # ---- Window 1: Configuration ----
    Write-Log -Message "[Interactive Mode] Showing Configuration window" -Level Info
    $configResult = Show-ConfigurationWindow `
        -PCServer $TargetPC `
        -PCVersion $wizard_pc_version `
        -PCClusterCount $wizard_pc_cluster_count `
        -CitrixSiteName $wizard_site_name `
        -CitrixVersion $wizard_site_version `
        -Catalogs $wizard_manual_catalogs `
        -HostingConnections $wizard_nutanix_hosting_connections `
        -WhatIfFromParam ($Whatif.IsPresent)
    if (-not $configResult) {
        Write-Log -Message "[Interactive Mode] Wizard cancelled by user at Configuration" -Level Warn
        Exit 0
    }

    # Set script variables from wizard
    $CatalogNames = $configResult.CatalogNames
    $HostingConnectionName = $configResult.HostingConnectionName
    $ExclusionList = $configResult.ExclusionList
    if ($configResult.ResetTargetHostingConnection) { $ResetTargetHostingConnection = [switch]::new($true) }
    if ($configResult.SwitchCatalogZoneID) { $SwitchCatalogZoneID = [switch]::new($true) }

    # ---- Calculate machine impact count (machines in selected catalogs minus exclusions) ----
    Write-Log -Message "[Interactive Mode] Calculating impacted machine count" -Level Info
    $wizard_impact_machines = [System.Collections.Generic.List[string]]::new()
    foreach ($catName in $CatalogNames) {
        $matched_cat = $wizard_manual_catalogs | Where-Object { $_.name -eq $catName }
        if ($matched_cat) {
            # Reuse exclusion cache populated during the config window if available
            if ($script:wizardExclusionCache -and $script:wizardExclusionCache.ContainsKey($matched_cat.id)) {
                foreach ($n in $script:wizardExclusionCache[$matched_cat.id]) { if (-not [string]::IsNullOrWhiteSpace($n)) { $wizard_impact_machines.Add($n) } }
            } else {
                $cat_machines = Get-CVADCatalogMachinesAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential -CatalogNameOrId $matched_cat.id
                foreach ($m in $cat_machines) {
                    $shortName = ($m.name -split '\\')[-1]
                    if (-not [string]::IsNullOrWhiteSpace($shortName)) { $wizard_impact_machines.Add($shortName) }
                }
            }
        }
    }
    $wizard_unique_machines = $wizard_impact_machines | Select-Object -Unique
    if ($ExclusionList -and $ExclusionList.Count -gt 0) {
        $wizard_vm_count = ($wizard_unique_machines | Where-Object { $_ -notin $ExclusionList } | Measure-Object).Count
    } else {
        $wizard_vm_count = ($wizard_unique_machines | Measure-Object).Count
    }
    Write-Log -Message "[Interactive Mode] Estimated $($wizard_vm_count) machines impacted" -Level Info

    # ---- Window 2: Confirmation ----
    Write-Log -Message "[Interactive Mode] Showing Confirmation window" -Level Info
    $confirmed = Show-ConfirmationWindow `
        -WhatIfEnabled ($Whatif.IsPresent) `
        -CatalogNames $CatalogNames `
        -HostingConnectionName $HostingConnectionName `
        -ResetHC ($ResetTargetHostingConnection.IsPresent) `
        -SwitchZone ($SwitchCatalogZoneID.IsPresent) `
        -ExclusionList $ExclusionList `
        -VMCount $wizard_vm_count
    if (-not $confirmed) {
        Write-Log -Message "[Interactive Mode] Wizard cancelled by user at Confirmation" -Level Warn
        Exit 0
    }
    Write-Log -Message "[Interactive Mode] User confirmed. Proceeding with execution." -Level Info

    # Set SilentConsent to skip the Read-Host prompt since user already confirmed via wizard
    $SilentConsent = [switch]::new($true)
}
#endregion Interactive Mode

#region Param Validation
#-------------------------------------------------------------
# If CitrixDaaS, Must have CustomerID, ClientID, ClientSecret, and Region
if ($IsCitrixDaaS) {
    if (-not $SecureClientFile) {
        if ([string]::IsNullOrEmpty($ClientID)) { Write-Log -Message "[PARAM VALIDATION] ClientID is required for Citrix DaaS" -Level Error; Exit 1}
        if ([string]::IsNullOrEmpty($ClientSecret)) { Write-Log -Message "[PARAM VALIDATION] ClientSecret is required for Citrix DaaS" -Level Error; Exit 1 }
    }
    if ([string]::IsNullOrEmpty($CustomerID)) { Write-Log -Message "[PARAM VALIDATION] CustomerID is required for Citrix DaaS" -Level Error; Exit 1 }
    if ([string]::IsNullOrEmpty($Region)) { Write-Log -Message "[PARAM VALIDATION] Region is required for Citrix DaaS" -Level Error; Exit 1 }
}
# Check Exclusion List for invalid values
if ($ExclusionList) {
    Write-Log -Message "[PARAM VALIDATION] Exclusion List: $($ExclusionList)" -Level Info
    foreach ($exclusion in $ExclusionList) {
        if ($exclusion -like "*\*") {
            Write-Log -Message "[PARAM VALIDATION] Exclusion: $($exclusion) must not contain a backslash ('\')" -Level Error
            StopIteration
            Exit 1
        }
    }
} else {
    Write-Log -Message "[PARAM VALIDATION] No Exclusion List specified. Using all machines in the Citrix Catalogs" -Level Info
}
#endregion Param Validation

#region Mode Validation and Impacts Output
# ----------------------------------------------------------------------------------------------------------------------------
Write-Log -Message "[EXECUTION PARAMS] =================================================" -Level Info
Write-Log -Message "[EXECUTION PARAMS] Prism Central to be targeted for Migration/Recovery: $($TargetPC)" -Level Info
foreach ($CatalogName in $CatalogNames) {
    Write-Log -Message "[EXECUTION PARAMS] The Citrix Catalog: $($CatalogName) will be processed" -Level Info
}

Write-Log -Message "[EXECUTION PARAMS] Whatif Mode: $($Whatif)" -Level Info
if ($SwitchCatalogZoneID -eq $true) {
    Write-Log -Message "[EXECUTION PARAMS] The Catalog Zone ID will be switched after the Migration/Recovery" -Level Info
} else {
    Write-Log -Message "[EXECUTION PARAMS] The Catalog Zone ID will not be switched after the Migration/Recovery" -Level Info
}
if ($ResetHostingConnection -eq $true) {
    Write-Log -Message "[EXECUTION PARAMS] The Hosting Connection will be reset after the Migration/Recovery is complete if machines are altered" -Level Info
} else {
    Write-Log -Message "[EXECUTION PARAMS] The Hosting Connection will not be reset after the Migration/Recovery is complete if machines are not altered" -Level Info
}
Write-Log -Message "[EXECUTION PARAMS] =================================================" -Level Info

# Prompt for user consent
if ($SilentConsent -eq $false) {
    $consent = Read-Host "Review the above execution parameters. Do you want to continue? (Y/N)"
    if ($consent -ne 'Y' -and $consent -ne 'y') {
        Write-Log -Message "[USER CONSENT] Operation cancelled by user." -Level Error
        Exit 1
    } else {
        Write-Log -Message "[USER CONSENT] Continuing with operation..." -Level Info
    }
} else {
    Write-Log -Message "[USER CONSENT] User consent not required by Parameter. Continuing with operation..." -Level Info
}

#endregion Mode Validation and Impacts Output

#region Execute
# ============================================================================
# Validate and Execution Phases
# ============================================================================
StartIteration

if ($Whatif -eq $true) {
    Write-Log -Message "[PARAM VALIDATION] We are in WhatIf mode. No actions will be taken." -Level Whatif
}

# ===============================================
# Validation Phase
# ===============================================

#region check PoSH version
# ----------------------------------------------------------------------------------------------------------------------------
if ($PSVersionTable.PSVersion.Major -lt 7) { 
    Write-Log -message "[PoSH Validation] This script only supports PowerShell 7." -Level Error 
    Write-Log -Message "[PoSH Validation] PowerShell version is: $($PSVersionTable.PSVersion)" -Level Info
    StopIteration
    Exit 1
}
#endregion check PoSH version

#region Nutanix Prism Central Authentication
# ----------------------------------------------------------------------------------------------------------------------------
$PrismCentralCredentials = New-Object System.Management.Automation.PSCredential ($PCUser, (ConvertTo-SecureString $PCPass -AsPlainText -Force))
#endregion Nutanix Prism Central Authentication

#region Validate Access to Prism Central via API
# ----------------------------------------------------------------------------------------------------------------------------
$cluster_list = Get-PCClusters -pc $TargetPC -PrismCentralCredentials $PrismCentralCredentials

if ([string]::IsNullOrEmpty($cluster_list)) {
    Write-Log -Message "[Prism Central Validation] Could not connect to PC or no clusters found" -Level Error
    StopIteration
    Exit 1
}

$pc_cluster = $cluster_list | Where-Object {$_.config.clusterFunction -eq "PRISM_CENTRAL"}
$non_pc_clusters = $cluster_list | Where-Object {$_.config.clusterFunction -ne "PRISM_CENTRAL"}

if ([string]::IsNullOrEmpty($pc_cluster)) {
    Write-Log -Message "[Prism Central Validation] Could not find Prism Central cluster in cluster list" -Level Error
    StopIteration
    Exit 1
}

Write-Log -Message "[Prism Central Validation] Found $($non_pc_clusters.Count) clusters managed by this Prism Central Instance" -Level Info
Write-Log -Message "[Prism Central Validation] PC version is: $($pc_cluster.config.buildInfo.version)" -Level Info
#endregion Validate Access to Prism Central via API

#region Citrix Authentication
#-------------------------------------------------------------
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
} 
# else {
#     $Global:DDC = $ctx_AdminAddress
#     # Convert Username and Password to base64. This is used to talk to Citrix API. Note that we set this regardless of DaaS of CVAD so that we can use the same functions.
#     $AdminCredential = "$($DomainUser):$($DomainPassword)"
#     $Bytes = [System.Text.Encoding]::UTF8.GetBytes($AdminCredential)
#     $Global:EncodedAdminCredential = [Convert]::ToBase64String($Bytes)
# }
#endregion Citrix Authentication

#region Validate Citrix Site is contactable
# ----------------------------------------------------------------------------------------------------------------------------
Write-Log -Message "[Citrix Validation] Validating Citrix Site is contactable at Delivery Controller: $($DDC)" -Level Info
$cvad_site_details = Get-CVADSiteDetailAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
if ([string]::IsNullOrEmpty($cvad_site_details)) {
    Write-Log -Message "[Citrix Validation] Failed to validate Citrix Delivery Controller: $($DDC)" -Level Warn
    StopIteration
    Exit 1
} else {
    Write-Log -Message "[Citrix Validation] Successfully Validated Citrix Site: $($cvad_site_details.cvad_site.name) is contactable at Delivery Controller: $($DDC)" -Level Info
}  
#endregion Validate Citrix Site is contactable

#region Validate Citrix DaaS Catalog Names
# ----------------------------------------------------------------------------------------------------------------------------
$citrix_catalogs = Get-CVADCatalogsAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential
$supported_citrix_catalogs = $citrix_catalogs | Where-Object {$_.ProvisioningType -eq "Manual"}

if ($supported_citrix_catalogs.Count -eq 0) {
    Write-Log -Message "[Citrix Validation] No supported Citrix Catalogs found" -Level Error
    StopIteration
    Exit 1
} else {
    Write-Log -Message "[Citrix Validation] Found $($supported_citrix_catalogs.Count) supported Citrix Catalogs" -Level Info
}
# now we need to validate the catalog names that have been defined by parameter and that they exist in the target Citrix environment.
$supported_citrix_catalogs = $supported_citrix_catalogs | Where-Object {$_.name -in $CatalogNames}
if ($supported_citrix_catalogs.Count -eq 0) {
    Write-Log -Message "[Citrix Validation] Catalogs defined by parameter were not found in the target Citrix environment" -Level Error
    StopIteration
    Exit 1
} else {
    Write-Log -Message "[Citrix Validation] Found $($supported_citrix_catalogs.Count) supported Citrix Catalogs defined by parameter" -Level Info
}
#endregion Validate Citrix DaaS Catalog Names

#region Validate Citrix DaaS Hosting Connection Name
# ----------------------------------------------------------------------------------------------------------------------------
$cvad_hosting_connection = Get-CVADHostingConnectionAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential -HostingConnectionName $HostingConnectionName
if ([string]::IsNullOrEmpty($cvad_hosting_connection)) {
    Write-Log -Message "[Citrix Validation] Failed to validate Citrix Hosting Connection: $($HostingConnectionName)" -Level Warn
    StopIteration
    Exit 1
} else {
    if ($cvad_hosting_connection.PluginId -in $SupportedHypervisorPlugTypes) {
        Write-Log -Message "[Citrix Validation] Hypervisor Plugin type is: $($cvad_hosting_connection.PluginId) and is supported" -Level Info
    }
    else {
        Write-Log -Message "[Citrix Validation] Hypervisor Plugin type is: $($cvad_hosting_connection.PluginId) and is not supported. Only Nutanix Hosting Connections are supported" -Level Warn
        StopIteration
        Exit 1
    }
    
    #check for Maintenance Mode 
    if ($cvad_hosting_connection.InMaintenanceMode -eq "true") {
        Write-Log -Message "[Citrix Validation] Hosting Connection is in Maintenance Mode" -Level Warn
        StopIteration
        Exit 1
    }

    # consider doing a check against the target PC addresses and see if we can match for additional validation - challenge will be names/IP's/connection info could be different

    Write-Log -Message "[Citrix Validation] Successfully Validated Citrix Hosting Connection: $($cvad_hosting_connection.name)" -Level Info
}
#endregion Validate Citrix DaaS Hosting Connection Name

#region build the citrix machine list that will need to be altered during the recovery process
# ----------------------------------------------------------------------------------------------------------------------------
$master_citrix_machine_list = [System.Collections.ArrayList]::new()

foreach ($catalog in $supported_citrix_catalogs) {
    $citrix_machine_list = Get-CVADCatalogMachinesAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential -CatalogNameOrId $catalog.id
    foreach ($machine in $citrix_machine_list) {
        [void]$master_citrix_machine_list.Add($machine)
    }
}

# filter this list to only include machines that are not in the exclusion list
if (-not [string]::IsNullOrEmpty($ExclusionList)) {
    $master_citrix_machine_list = $master_citrix_machine_list | Where-Object {($_.name -split '\\')[-1] -notin $ExclusionList}
}
#endregion build the citrix machine list that will need to be altered during the recovery process

# ===============================================
# Execution Phase
# ===============================================

#region Get an updated list of VMs from the target PC after failover
# ----------------------------------------------------------------------------------------------------------------------------
Write-Log -Message "[Prism Central] Getting a list of VMs from the target PC: $($TargetPC)" -Level Info
$master_migrated_nutanix_vm_list = [System.Collections.ArrayList]::new() # this will be the source of truth for VMs to be altered during the recovery process post failover
# Get the VM List from Target PC. We might not be up to do date in the recovery plan here, so use the VM list
$target_pc_vm_list = Get-PCVM -pc $TargetPC -PrismCentralCredentials $PrismCentralCredentials
# Match to our master citrix machine list by name
$target_pc_vm_list = $target_pc_vm_list | Where-Object {$_.name -in ($master_citrix_machine_list.name | Split-Path -Leaf)}
# If we find duplicates here, filter and keep the first one by createTime
$target_pc_vm_list = $target_pc_vm_list | Group-Object -Property Name | ForEach-Object { 
    if ($_.Count -gt 1) {
        Write-Log -Message "[Prism Central] Found $($_.Count) duplicates for VM: $($_.Name), keeping most recent" -Level Warn
    }
    $_.Group | Sort-Object -Property createTime -Descending | Select-Object -First 1  ## Validate this is the correct order
}
# add the VMs to the master migrated nutanix vm list
foreach ($vm in $target_pc_vm_list) {
    [void]$master_migrated_nutanix_vm_list.Add($vm)
}
Write-Log -Message "[Prism Central] Found $($master_migrated_nutanix_vm_list.Count) VMs in the target Citrix environment under the target PC: $($TargetPC)" -Level Info

#endregion Get an updated list of VMs from the target PC after failover

#region Execute the update of the Citrix machines in the master migration list
# ----------------------------------------------------------------------------------------------------------------------------
$citrix_machines_updated_count = 0

foreach ($ctx_machine in $master_citrix_machine_list `
    | Where-Object { ($_.name -split '\\')[-1] -notin $ExclusionList } `
    | Sort-Object -Property { ($_.name -split '\\')[-1] }) {
    if ($Whatif -eq $true) {
        #Write-Log -Message "[Citrix] Would update Machine: $($ctx_machine.name | Split-Path -Leaf) in Citrix" -Level Whatif
    } else {
        Write-Log -Message "[Citrix] Updating Machine: $($ctx_machine.name | Split-Path -Leaf) in Citrix" -Level Info
    }
    # match the machines from Citrix to Nutanix
    $ntnx_matched_machine = $master_migrated_nutanix_vm_list | Where-Object {$_.name -eq ($ctx_machine.name | Split-Path -Leaf)}

    if ($ntnx_matched_machine) {
        $requires_changes_to_hosting = $false
        # now we will compare the HostedMachineId and the UUID to see if they have changed - if they change, we need to action an update
        if ($ntnx_matched_machine.extId -ne $ctx_machine.Hosting.HostedMachineId) {
            Write-Log -Message "[Citrix] Machine: $($ctx_machine.name | Split-Path -Leaf) has had it's UUID changed from $($ctx_machine.Hosting.HostedMachineId) to $($ntnx_matched_machine.extId)" -Level Info
            if ($Whatif -eq $true) {
                Write-Log -Message "[Citrix] Would update Machine: $($ctx_machine.name | Split-Path -Leaf) with new HostedMachineID: $($ntnx_matched_machine.extId)" -Level Whatif
            } else {
                Write-Log -Message "[Citrix] Updating Machine: $($ctx_machine.name | Split-Path -Leaf) with new HostedMachineID: $($ntnx_matched_machine.extId)" -Level Info
            }
            # We will update the Citrix VM with the new HostedMachineID
            $HostedMachineId = $ntnx_matched_machine.extId
            $requires_changes_to_hosting = $true
        } else {
            $HostedMachineId = $ctx_machine.Hosting.HostedMachineId
        }
        # now it's time to validate the Hypervisor Connection Name matches the target Hosting Connection
        if ($ctx_machine.Hosting.HypervisorConnection.Name -ne $cvad_hosting_connection.name) {
            if ($Whatif -eq $true) {
                Write-Log -Message "[Citrix] Would update Machine: $($ctx_machine.name | Split-Path -Leaf) with new Hypervisor Connection: $($cvad_hosting_connection.Name)" -Level Whatif
            } else {
                Write-Log -Message "[Citrix] Updating Machine: $($ctx_machine.name | Split-Path -Leaf) with new Hypervisor Connection: $($cvad_hosting_connection.Name)" -Level Info
                # We will update the Citrix VM with the new Hypervisor Connection UID
                $HypervisorConnectionName = $cvad_hosting_connection.name
            }
            $requires_changes_to_hosting = $true
        } else {
            $HypervisorConnectionName = $ctx_machine.Hosting.HypervisorConnection.Name
        }
        # If changes are required, we will action them
        if ($requires_changes_to_hosting -eq $true) {
            if ($Whatif -ne $true) {
                $null = Update-CVADMachineHostingDetailsAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential -MachineId $ctx_machine.id -HostedMachineId $HostedMachineId -HypervisorConnectionName $cvad_hosting_connection.name
                Start-Sleep -Milliseconds 100
            }
            $citrix_machines_updated_count++
        } else {
            Write-Log -Message "[Citrix] Machine: $($ctx_machine.name | Split-Path -Leaf) does not require changes to hosting details" -Level Info
        }
    } else {
        Write-Log -Message "[Citrix] Machine: $($ctx_machine.name | Split-Path -Leaf) does not require remediation" -Level Info
    }
}
#endregion Execute the update of the Citrix machines in the master migration list

#region Switch the Catalog Zone ID
# ----------------------------------------------------------------------------------------------------------------------------
if ($SwitchCatalogZoneID -eq $true) {
    foreach ($catalog in $supported_citrix_catalogs ) {
        $target_zone_id = $cvad_hosting_connection.Zone.id
        if ($catalog.Zone.id -ne $target_zone_id) {
            if ($Whatif -eq $true) {
                Write-Log -Message "[Citrix] Would switch Catalog Zone ID for Catalog: $($catalog.name) to $($target_zone_id)" -Level Whatif
            } else {
                Write-Log -Message "[Citrix] Switching Catalog Zone ID for Catalog: $($catalog.name)" -Level Info
                $null = Switch-CVADCatalogZoneIDAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential -CatalogName $catalog.name -CatalogId $catalog.id -ZoneId $target_zone_id    
            }
        } else {
            Write-Log -Message "[Citrix] Catalog Zone ID for Catalog: $($catalog.name) is already the target zone of the Hosting Connection" -Level Info
        }
    }
}
#endregion Switch the Catalog Zone ID

#region Hosting Connection Reset
# ----------------------------------------------------------------------------------------------------------------------------
# Reset the Citrix Hosting Connection to update power states (there can be a 5-10 minute sync otherwise)
if ($ResetTargetHostingConnection -eq $true) {
    if ($citrix_machines_updated_count -gt 0) {
        if ($Whatif -eq $true) {
            Write-Log -Message "[Citrix] Would reset Citrix Hosting Connection: $($HostingConnectionName)" -Level Whatif
        } else {
            Write-Log -Message "[Citrix] Resetting Citrix Hosting Connection: $($HostingConnectionName)" -Level Info
            $null = Reset-CVADHostingConnectionAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential -HostingConnectionNameOrId $cvad_hosting_connection.Id
            Write-Log -Message "[Citrix] Waiting for 30 seconds after first reset of Hosting Connection: $($HostingConnectionName)" -Level Info
            Start-Sleep -Seconds 30
            $null = Reset-CVADHostingConnectionAPI -DDC $DDC -EncodedAdminCredential $EncodedAdminCredential -HostingConnectionNameOrId $cvad_hosting_connection.Id
        }
    } else {
        Write-Log -Message "[Citrix] No Citrix machines were updated so Hosting Connection has not been reset" -Level Info
    }
}
#endregion Hosting Connection Reset

#endregion Execute

StopIteration
Exit 0
