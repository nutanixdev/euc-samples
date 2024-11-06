
## Objective

`MapPCVMCategoriestoCitrixTagsPlaybookStyle.ps1` is a PowerShell script written in PowerShell 7, which synchronizes Categories assigned to a Nutanix virtual machines in Prism Central, to a Citrix Tag in either Citrix Virtual Apps and Desktops, or Citrix DaaS. It also allows a reverse sync, where a Tag can be defined on a machine in Citrix, and if that the appropriate Category exists in Nutanix Prism Central, the category will be assigned to the matching virtual machine instance.

The Script uses both the Prism Central V3 API's for Nutanix operations, and the Citrix DaaS or Virtual Apps and Desktops API for Citrix based operations.

This script is designed to be executed by a Nutanix Prism Central Playbook. It is based on this script [MapPCVMCategoriestoCitrixTags.ps1]() as a source, with alterations input as an example for Playbook extension.

## Controls and Guards

There are a few guiding principals in how this script executes and controls things. Let's define a list of existing Categories in Nutanix Prism Central for demonstration purposes. Assume the following Category/Value pairings exist:

| **Category Name** | **Values** |
| :--- | :--- |
| `ExampleCategory` | `Demo1` |
| `DisasterRecovery` | `Tier1`,`Tier2` |
| `Department` | `HR`,`Finance` |
| `Quarantine` | `Forensic`, `Strict` |

The script uses a `TagPrefix` logic to help ensure that we are only consuming, and including, Citrix tags specific to our requirement. This means that by default, any Citrix Tag we either create, assign, remove or assess in Citrix, by default, is prefixed with `Nutanix_`. If the Tag does not include this prefix value, it is ignored entirely. This is a parameter value that can be altered.

The script `TagPrefix` will ultimately map a Category in Prism Central to a Tag in Citrix using the following logic when you execute the script in `PrismToCitrix` mode:

| **Nutanix Category** | **Category Value** | **Final Citrix Tag** |
| :--- | :--- | :--- |
| `ExampleCategory` | `Demo1` | `Nutanix_ExampleCategory_Demo1` |
| `DisasterRecovery` | `Tier1` | `Nutanix_DisasterRecovery_Tier1` |
| `DisasterRecovery` | `Tier2` | `Nutanix_DisasterRecovery_Tier2` |
| `Department` | `HR` | `Nutanix_Department_HR` |
| `Department` | `Finance` | `Nutanix_Department_Finance` |
| `Quarantine` | `Forensic` | `Nutanix_Quarantine_Forensic` |

The script `TagPrefix` will also control the reverse logic when executing the script in `CitrixToPrism` mode. It filters matched Citrix machines (those that live in Citrix and in Prism) to those including Citrix Tags with `Nutanix_` initially.

| **Citrix Tag Name** | **Nutanix Category** | **Value** | **Valid Match** | **Action** |
| :--- | :--- | :--- | :--- | :--- |
| `Nutanix_NewCategory_MadValue` | `NewCategory` ❌ | `MadValue` ❌ | `no_match` ❌ | Category doesn't exist. Nothing will be done. ❌ |
| `Nutanix_ExampleCategory_Demo1` | `ExampleCategory` ✅ | `Demo1` ✅ | `match` ✅ | If the Nutanix VM is missing the Category `ExampleCategory` with value `Demo1`, it will be assigned. ✅ | 
| `Nutanix_DisasterRecovery_Tier1` | `DisasterRecovery` ✅ | `Tier1` ✅ | `match` ✅ | If the Nutanix VM is missing the Category `DisasterRecovery` with value `Tier1`, it will be assigned. ✅ |
| `Nutanix_DisasterRecovery_Tier3` | `DisasterRecovery` ✅ | `Tier3` ❌ | `no_match` ❌ | Does **not** have a corresponding value for `Tier3`. Nothing will be done. ❌ |
| `Nutanix_DisasterRecovery_Undefined` | `DisasterRecovery` ✅ | `Undefined` ❌ | `no_match` ❌ | Does **not** have a corresponding value for `Undefined`. Nothing will be done. ❌ |
| `Nutanix_Department_HR_People` | `Department` ✅ | `HR_People` ❌ | `no_match` ❌ | Does **not** have a corresponding value for `HR_People`. Nothing will be done. ❌ |
| `Nutanix_Department_Engineering` | `Department` ✅ | `Engineering` ❌ | `no_match` ❌ | Does **not** have a corresponding value for `Engineering`. Nothing will be done. ❌ |
| `Nutanix_Quarantine_Full` | `Quarantine` ✅ | `Strict` ✅ | `match` ✅ | If the Nutanix VM is missing the Category `Quarantine` with value `Strict`, it will be assigned. ✅ |  

The script handles Nutanix Category and Citrix Tag removal logic in the following fashion: 

 - If the script is operating in `CitrixToPrism` mode, and the Citrix Tag `Nutanix_Quarantine_Forensic` is removed from Citrix, the Category will be removed from the VM in Prism Central.
 - If the script is operating in `PrismToCitrix` mode, and the Prism Category Name: `DisasterRecovery` with value: `Tier1` is removed from the VM in Prism Central, the corresponding `Nutanix_DisasterRecovery_Tier1` Tag will be removed from the Citrix VM If the `RemoveOrphanedTags` switch is used.

Nutanix Prism Central is **always** king when it comes to Category definitions. The script will **never** attempt to create a Category, or Category value that doesn't already exist in Prism. Validation occurs before any actions are executed, if Prism Central does not contain a required match, then nothing is actioned. Output is logged accordingly.

The script will create missing Tags in Citrix. It will not however, delete a defined Tag if the Prism Category is deleted. The virtual machines, will have the category removed if the `RemoveOrphanedTags` switch is used. This keeps the machines in sync if a change is made in Prism Central where a Category is removed from a VM.

## Technical requirements for running the script

The script is compatible with Windows PowerShell 7.

This means that the technical requirements for the workstation or server running the script are as follows:

1. Any Windows or Linux version which can run Windows PowerShell 7.
2. Citrix Virtual Apps and Desktops 2402 has been validated. This script uses the API and no Citrix PowerShell modules or snapins. As such, if there is no API available for Citrix, the script will fail.
3. An appropriate credential with sufficient permissions to assign or remove categories to virtual machine entities within Prism Central.
4. An appropriate credential with sufficient permissions to manage tags in Citrix Virtual Apps and Desktops.
5. An appropriate SecureClient credential file for Citrix DaaS.
6. Nutanix Prism Central configured with Intelligent Operations for Playbook Execution.
7. A Windows Server 2022 (or equivalent) based execution machine. This VM is responsible for executing the code on behalf of the Playbook.

## Parameter Details

The following parameters exist to drive the behaviour of the script:

#### Mandatory and recommended parameters:

- **`pc_source`**: Mandatory. **`String`**. The Prism Central Source to target.
- **`DDC`**: Optional. **`String`**. The Citrix Delivery Controller to connect to. Is mandatory if not using the `CitrixDaaS` switch. You must use either `CitrixDaaS` or `DDC`
- **`Mode`**: Mandatory. **`String`**. Contains two options `PrismToCitrix` and `CitrixToPrism`. This controls which direction we are syncing

#### Optional Parameters

- **`LogPath`**: Optional. **`String`**. Log path output for all operations. The default is `C:\Logs\MapPCVMCategoriestoCitrixTags.log`
- **`LogRollover`**: Optional. **`Int`**.Number of days before log files are rolled over. Default is 5
- **`UseCustomCredentialFile`**: Optional. **`switch`**. Will call the `Get-CustomCredentials` function which keeps outputs and inputs a secure credential file based on Stephane Bourdeaud from Nutanix functions. If not used, the user will be prompted for credentials for both PC and Citrix VAD.
- **`CredPath`**: Optional. **`String`**. Used if using the `UseCustomCredentialFile` parameter. Defines the location of the credential file. The default is `"$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"`.
- **`Whatif`**: Optional. **`Switch`**. Will action the script in a whatif processing mode only.
- **`CitrixDaaS`**. Optional. **`Switch`**. Will action the script against Citrix DaaS rather than on-premises Virtual Apps and Desktops. Triggers the requirement for `SecureClientFile`, `Region` and `CustomerID`
- **`SecureClientFile`**. Optional. **`String`**. Path to the Citrix Cloud Secure Client CSV. Mandatory if `CitrixDaaS` is specified.
- **`Region`**. Optional. **`String`**. The Citrix Cloud DaaS Tenant Region. Either `AP-S` (Asia Pacific), `US` (USA), `EU` (Europe) or `JP` (Japan). Mandatory if `CitrixDaaS` is specified.
- **`CustomerID`**. Optional. **`String`**. The Citrix Cloud Customer ID. Mandatory if `CitrixDaaS` is specified.
- **`Catalog`**: Optional. **`String`**. Will filter Citrix machines to the specified Catalog.
- **`TagPrefix`**: Optional. **`String`**. Prefix to add to the Citrix Tag when mapped from Nutanix Categories. Default is `Nutanix_`.
- **`RemoveOrphanedTags`**: Optional. **`Switch`**. Remove Tags from Citrix Machines that are not present in Nutanix Prism Central if they match `TagPrefix`.

#### Playbook Mode Parameters

Being that this version of the script is designed to handle execution via a Nutanix Playbook, there are some additional parameters defined:

- **`PlaybookMode`**: Optional. **`Switch`**. Lets the script know this is in Playbook Mode.
- **`PrismUser`**: Optional. **`String`**. The Prism Central User to use for Playbook mode. Mandatory if PlaybookMode is specified.
- **`PrismPass`**: Optional. **`String`**. The Prism Central Password to use for Playbook mode. Mandatory if PlaybookMode is specified.
- **`cvadUser`**: Optional. **`String`**. The Citrix Virtual Apps and Desktops User to use for Playbook mode. Mandatory if PlaybookMode is specified.
- **`cvadPass`**: Optional. **`String`**. The Citrix Virtual Apps and Desktops Password to use for Playbook mode. Mandatory if PlaybookMode is specified.

## Setting up the Execution Machine

There are a few basic requirements for the machine being used to execute the `MapPCVMCategoriestoCitrixTagsPlaybookStyle.ps1` script

- Windows Server Operating System. We tested this on Windows Server 2022. This can be Windows Server Core.
- PowerShell Remoting must be enabled for the Nutanix Playbook to execute the script.
- PowerShell 7 must be installed and available.
- The `Microsoft.PowerShell.SecretStore` and `Microsoft.PowerShell.SecretManagement` PowerShell modules must be installed and available for both PowerShell 5 and PowerShell 7. The install of these modules depends on the `Nuget` Package Provider
- The service account being used to execute the script via the Nutanix Playbook, must have have logged on to the machine and created the `Secret Store` and encrypted the Secure Password File. This process by design uses the Windows Data Protection API (DAPI) and thus locks the encryption of the file to both the Windows Machine and the user account that encrypted it.

### Additional Hardening Considerations

Consider the following for the execution machine:

- Ensure only authorized to the server is granted.
- Consider limiting remote access to the machine to Prism Central. You could use the Windows Firewall, or Nutanix Flow Network Security to achieve this goal. Particularly if using Citrix DaaS and a secure credential file.

### Install the required modules

You can execute the following code to install the appropriate modules:

```
Install-PackageProvider -Name NuGet -Force
Install-Module -Name Microsoft.PowerShell.SecretStore -Repository PSGallery -Force
Import-Module Microsoft.PowerShell.SecretStore
Install-Module -Name Microsoft.PowerShell.SecretManagement -Repository PSGallery -Force
Import-Module Microsoft.PowerShell.SecretManagement
```

To configure the Secret Store Vault, you can run the code below:

```
$securePasswordPath = 'C:\automation\passwd.xml' # You should adjust this to where you want to store the xml file.
$SecretVaultName = "PlaybookSecretStore"

# create a password as a SecureString that's used to secure the SecretStore vault. Export to a file
$credential = Get-Credential -UserName 'SecureStore' # You can ignore the username, this is the credential to encrypt the password xml using DAPI
$credential.Password | Export-Clixml -Path $securePasswordPath -Force

# configure the SecretStore vault. The configuration sets user interaction to None, so that SecretStore never prompts the user
Register-SecretVault -Name $SecretVaultName -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
$VaultPassword = Import-CliXml -Path $securePasswordPath

$storeConfiguration = @{
    Authentication  = 'Password'
    PasswordTimeout = 3600 # 1 hour
    Interaction     = 'None'
    Password        = $VaultPassword
    Confirm         = $false
}
Set-SecretStoreConfiguration @storeConfiguration

# add the required entries to the vault. You will be prompted for the password
Unlock-SecretVault -Name $SecretVaultName -Password $VaultPassword
# This is for the user account you will be authenticating to the CVAD API
Set-Secret -vault $SecretVaultName -Name "cvad_pass"
# this is for the user account you will be authentication to the Prism Central v3 API
Set-Secret -vault $SecretVaultName -Name "prism_pass"
```

You now have a vault with two stored passwords. The only account that can access this vault is the one that created the encrypted password xml file.

### Setting up the execution scripts for Playbooks

Prism Central playbooks execute PowerShell scripts against execution machines via PowerShell 5. Given that our main script is written for PowerShell 7, and we need to pass through some credentials, we will leverage an execution script logic which will allow us do a few things:

- Import the appropriate `Microsoft.PowerShell.SecretStore` and `Microsoft.PowerShell.SecretManagement` modules and pull the secrets (passwords) stored in the `PlaybookSecretStore` vault for our service accounts.
- Define environment and task specific parameters for the main script. This allows us to have different synchronization configurations per execution script.
- Define the path to PowerShell 7, and invoke the main script using our defined parameters.

Our Prism Playbook ultimately calls these execution scripts. There are four main variables that need to be defined in the execution scripts:

```
$pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe" # Where is the PowerShell executable
$scriptToRun = "C:\Scripts\MapPCVMCategoriestoCitrixTagsPlaybookStyle.ps1" # Where is the main script stored
$securePasswordPath = 'C:\automation\passwd.xml' # Where is the password file we use to unlock the vault
$SecretVaultName = "PlaybookSecretStore" # What is the vault name containing the passwords
```

The scripts use the following logic to pull the passwords from the vault:

```
$VaultPassword = Import-CliXml -Path $securePasswordPath
Unlock-SecretVault -Name $SecretVaultName -Password $VaultPassword
$cvad_pass = Get-Secret -Name "cvad_pass" -Vault $SecretVaultName -AsPlainText
$prism_pass = Get-Secret -Name "prism_pass" -Vault $SecretVaultName -AsPlainText
```

We then define the appropriate parameters for our job:

```
$Params = @{
    LogPath                = "C:\Logs\SyncCitrixTagsToPrismCategories.log"
    pc_source              = "1.1.1.1"
    Whatif                 = $false
    TagPrefix              = "Nutanix_"
    RemoveOrphanedTags     = $false
    DDC                    = "2.2.2.2"
    Mode                   = "CitrixToPrism"
    PlaybookMode           = $true
    PrismUser              = "PrismUserName" # The user account that you stored the password in the vault for
    PrismPass              = $prism_pass # We have pulled this from the Vault
    CVADUser               = "Domain\UserName" # The user account that you stored the password in the vault for
    CVADPass               = $cvad_pass # We have pulled this from the Vault
}
```

Param splatting raises some slight challenges when using Switch params, so we have the following logic to handle this

```
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
```

And then we execute the script

```
# Call PowerShell 7 using the & operator with the properly formatted argument list
& "$pwshPath" @argList
```

There are four example scripts provided below, these can be used as templates

-  TBD
-  TBD
