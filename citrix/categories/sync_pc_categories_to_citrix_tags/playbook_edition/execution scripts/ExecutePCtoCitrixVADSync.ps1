#-----------------------
# Define Variables
#-----------------------
$pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"
$scriptToRun = "C:\Scripts\MapPCVMCategoriestoCitrixTagsPlaybookStyle.ps1"
$securePasswordPath = 'C:\automation\passwd.xml'
$SecretVaultName = "PlaybookSecretStore"
#-----------------------

if (-not (Test-Path $pwshPath)){ Write-Error "PowerShell 7 path not found at $($pwshPath)"; Exit 1}
if (-not (Test-Path $scriptToRun)){ Write-Error "Defined Script path not found at $($scriptToRun)"; Exit 1}
if (-not (Test-Path $securePasswordPath)){ Write-Error "Defined Secure Password path not found at $($securePasswordPath)"; Exit 1}

#region handle importing secret management modules
If (-not (Get-PackageProvider -ListAvailable -Name Nuget)) {
    try {
        $null = Install-PackageProvider -Name NuGet -Force -ErrorAction Stop
    }
    catch {
        Write-Error "Error installing Nuget Package Provider. Exit Script"
        Exit 1
    }
}

If (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretStore)) {
    try {
        Install-Module -Name Microsoft.PowerShell.SecretStore -Repository PSGallery -Force -ErrorAction Stop
        Import-Module Microsoft.PowerShell.SecretStore -ErrorAction Stop
    }
    catch {
        Write-Error "Error installing Microsoft.PowerShell.SecretStore Module. Exit Script"
        Exit 1
    }
} else {
    Import-Module Microsoft.PowerShell.SecretStore
}

if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement)) {
    try {
        Install-Module -Name Microsoft.PowerShell.SecretManagement -Repository PSGallery -Force -ErrorAction Stop
        Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
    }
    catch {
        Write-Error "Error installing Microsoft.PowerShell.SecretManagement. Exit Script"
        Exit 1
    }
} else {
    Import-Module Microsoft.PowerShell.SecretManagement
}
#endregion handle importing secret management modules

if ((Get-SecretVault -Name $SecretVaultName -ErrorAction SilentlyContinue).name -ne $SecretVaultName){ Write-Error "Secret Vault: $($SecretVaultName) not found"; Exit 1 }

#region secret retrieval
$VaultPassword = Import-CliXml -Path $securePasswordPath
Unlock-SecretVault -Name $SecretVaultName -Password $VaultPassword
$cvad_pass = Get-Secret -Name "cvad_pass" -Vault $SecretVaultName -AsPlainText
$prism_pass = Get-Secret -Name "prism_pass" -Vault $SecretVaultName -AsPlainText
#endregion secret retrieval

#region set job details
$Params = @{
    LogPath            = "C:\Logs\SyncPrismCategoriesToCitrixTags.log"
    pc_source          = "1.1.1.1"
    Whatif             = $false
    TagPrefix          = "Nutanix_"
    RemoveOrphanedTags = $false
    DDC                = "2.2.2.2"
    Mode               = "PrismToCitrix"
    PlaybookMode       = $true
    PrismUser          = "PC_User"
    PrismPass          = $prism_pass
    CVADUser           = "Domain\cvad_user"
    CVADPass           = $cvad_pass
}
#endregion set job details

#region build the argument list
# Build the argument list
$argList = @("-File", "`"$scriptToRun`"")  # Start with the -File parameter and the script

# Add parameters (handling switches and regular parameters)
$params.GetEnumerator() | ForEach-Object {
    if ($_.Value -eq $true) {
        # For switches, only include the key
        $argList += "-$($_.Key)"
    } elseif ($_.Value -ne $false) {
        # For regular parameters, add the key and value
        $argList += "-$($_.Key)"
        $argList += "$($_.Value)"
    }
}
#endregion build the argument list

#region execute the script
# Call PowerShell 7 using the & operator with the properly formatted argument list
& "$pwshPath" @argList
#endregion execute the script
