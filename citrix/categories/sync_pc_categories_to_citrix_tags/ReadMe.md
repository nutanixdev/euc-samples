## Objective

`MapPCVMCategoriestoCitrixTags.ps1` is a PowerShell script written in PowerShell 7, which synchronizes Categories assigned to a Nutanix virtual machines in Prism Central, to a Citrix Tag in either Citrix Virtual Apps and Desktops, or Citrix DaaS. It also allows a reverse sync, where a Tag can be defined on a machine in Citrix, and if that the appropriate Category exists in Nutanix Prism Central, the category will be assigned to the matching virtual machine instance.

The Script uses both the Prism Central V3 API's for Nutanix operations, and the Citrix DaaS or Virtual Apps and Desktops API for Citrix based operations.

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

<!--CONFIRM WITH DAVE ON THE NAMING OF THE QUARANTINE POLICIES-->

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

## Scenarios

All scenarios below include the `WhatIf` parameter set to true. You should **always** use this parameter before executing in production and review the associated log files. You should also test against non-production environments first.

### Synchronize Prism Central Categories to Citrix Tags for Citrix Virtual Apps and Desktops 

Param Splatting: 

```
$scriptParams = @{
    Mode               = "PrismToCitrix"
    pc_source          = "1.1.1.1"
    TagPrefix          = "Nutanix_"
    RemoveOrphanedTags = $true
    DDC                = "2.2.2.2"
    Catalog            = "MagicalCatalog"
    WhatIf             = $true
}

& MapPCVMCategoriestoCitrixTags.ps1 @scriptParams
```

The direct script invocation via the command line with defined arguments would be:

```
.\MapPCVMCategoriestoCitrixTags.ps1 -Mode "PrismToCitrix" -pc_source "1.1.1.1" -TagPrefix "Nutanix_" -RemoveOrphanedTags -DDC "2.2.2.2" -Catalog "MagicalCatalog" -Whatif
```

The script will:

- Execute in a `PrismToCitrix` sync mode where the Prism Central source is `1.1.1.1`.
- Use the Tag Prefix `Nutanix_` which is also the default value.
- Execute against Citrix Virtual Apps and Desktops where the Delivery Controller is `2.2.2.2`.
- Filter Citrix machines to those in the Catalog `MagicalCatalog`
- Remove any orphaned Tags (Categories no longer assigned to a Nutanix VM but have a matching Citrix Tag) via the `RemoveOrphanedTags` switch.
- Prompt the user for Credentials for both Prism Central and Citrix Virtual Apps and Desktops because `UseCustomCredentialFile` is not specified..
- Operating in `WhatIf` mode with all logs output to `C:\Logs\MapPCVMCategoriestoCitrixTags.log`.

### Synchronize Prism Central Categories to Citrix Tags for Citrix DaaS

Param Splatting

```
$scriptParams = @{
    Mode               = "PrismToCitrix"
    pc_source          = "1.1.1.1"
    RemoveOrphanedTags = $true
    CitrixDaaS         = $true
    CustomerID         = "FakeCustomerID"
    SecureClientFile   = "c:\securestuff\SecureClient.csv"
    Region             = "US"
    WhatIf             = $true
}

& MapPCVMCategoriestoCitrixTags.ps1 @scriptParams
```

The direct script invocation via the command line with defined arguments would be:

```
.\MapPCVMCategoriestoCitrixTags.ps1 -Mode "PrismToCitrix" -pc_source "1.1.1.1" -RemoveOrphanedTags -CitrixDaaS -CustomerID "FakeCustomerID" -SecureClientFile "c:\securestuff\SecureClient.csv" -Region "US" -Whatif
```

The script will:

- Execute in a `PrismToCitrix` sync mode where the Prism Central source is `1.1.1.1`.
- Use the Tag Prefix `Nutanix_` which is the default value.
- Execute against Citrix DaaS using the CustomerID `FakeCustomerID`, SecureClientFile `c:\securestuff\SecureClient.csv` for authentication and specify the `US` region for the tenant.
- Retrieve all Citrix machines without filtering by Catalog.
- Remove any orphaned Tags (Categories no longer assigned to a Nutanix VM but have a matching Citrix Tag) via the `RemoveOrphanedTags` switch.
- Prompt the user for Credentials for Prism Central because `UseCustomCredentialFile` is not specified.
- Operating in `WhatIf` mode with all logs output to `C:\Logs\MapPCVMCategoriestoCitrixTags.log`.

### Synchronize Citrix Tags to Prism Central for Citrix Virtual Apps and Desktops

Param Splatting

```
$scriptParams = @{
    LogPath   = "C:\Logs\MapCitrixTagstoPCVMCategories.log"
    Mode      = "CitrixToPrism"
    pc_source = "1.1.1.1"
    TagPrefix = "Ntx_"
    DDC       = "2.2.2.2"
    Catalog   = "MagicalCatalog"
    WhatIf    = $true
}

& MapPCVMCategoriestoCitrixTags.ps1 @scriptParams
```

The direct script invocation via the command line with defined arguments would be:

```
.\MapPCVMCategoriestoCitrixTags.ps1 -Mode "CitrixToPrism" -pc_source "1.1.1.1" -TagPrefix "Ntx_" -DDC "2.2.2.2" -Catalog "MagicalCatalog" -Whatif -Logpath "C:\Logs\MapCitrixTagstoPCVMCategories.log"
```

The script will:

- Execute in a `CitrixToPrism` sync mode where the Prism Central source is `1.1.1.1`.
- Use the Tag Prefix `Ntx_`.
- Execute against Citrix Virtual Apps and Desktops where the Delivery Controller is `2.2.2.2`.
- Filter Citrix machines to those in the Catalog `MagicalCatalog`
- Prompt the user for Credentials for both Prism Central and Citrix Virtual Apps and Desktops because `UseCustomCredentialFile` is not specified..
- Operating in `WhatIf` mode with all logs output to `C:\Logs\MapCitrixTagstoPCVMCategories.log`.

### Synchronize Citrix Tags to Prism Central for Citrix DaaS

Param Splatting

```
$scriptParams = @{
    LogPath          = "C:\Logs\MapCitrixTagstoPCVMCategories.log"
    Mode             = "CitrixToPrism"
    pc_source        = "1.1.1.1"
    TagPrefix        = "Nutanix_"
    CitrixDaaS       = $true
    CustomerID       = "FakeCustomerID"
    SecureClientFile = "c:\securestuff\SecureClient.csv"
    Region           = "US"
    Catalog          = "MagicalCatalog"
    WhatIf           = $true
}

& MapPCVMCategoriestoCitrixTags.ps1 @scriptParams
```

The direct script invocation via the command line with defined arguments would be:

```
.\MapPCVMCategoriestoCitrixTags.ps1 -Mode "CitrixToPrism" -pc_source "1.1.1.1" -TagPrefix "Nutanix_" -CitrixDaaS -CustomerID "FakeCustomerID" -SecureClientFile "c:\securestuff\SecureClient.csv" -Region "US" -Catalog "MagicalCatalog" -Whatif -Logpath "C:\Logs\MapCitrixTagstoPCVMCategories.log"
```

The script will:

- Execute in a `CitrixToPrism` sync mode where the Prism Central source is `1.1.1.1`.
- Use the Tag Prefix `Nutanix_` which is the default value.
- Execute against Citrix DaaS using the CustomerID `FakeCustomerID`, SecureClientFile `c:\securestuff\SecureClient.csv` for authentication and specify the `US` region for the tenant.
- Filter Citrix machines to those in the Catalog `MagicalCatalog`
- Prompt the user for Credentials for Prism Central because `UseCustomCredentialFile` is not specified.
- Operating in `WhatIf` mode with all logs output to `C:\Logs\MapCitrixTagstoPCVMCategories.log`.

### Synchronize Citrix Tags to Prism Central for Citrix Virtual Apps and Desktops using stored Secure Credential Files

Param Splatting

```
$scriptParams = @{
    LogPath                 = "C:\Logs\MapCitrixTagstoPCVMCategories.log"
    Mode                    = "CitrixToPrism"
    pc_source               = "1.1.1.1"
    TagPrefix               = "Ntx_"
    DDC                     = "2.2.2.2"
    Catalog                 = "MagicalCatalog"
    UseCustomCredentialFile = $true
    WhatIf                  = $true
}

& MapPCVMCategoriestoCitrixTags.ps1 @scriptParams
```

The direct script invocation via the command line with defined arguments would be:

```
.\MapPCVMCategoriestoCitrixTags.ps1 -Mode "CitrixToPrism" -pc_source "1.1.1.1" -TagPrefix "Ntx_" -DDC "2.2.2.2" -Catalog "MagicalCatalog" -UseCustomCredentialFile -Whatif -Logpath "C:\Logs\MapCitrixTagstoPCVMCategories.log"
```

The script will:

- Execute in a `CitrixToPrism` sync mode where the Prism Central source is `1.1.1.1`.
- Use the Tag Prefix `Ntx_`.
- Execute against Citrix Virtual Apps and Desktops where the Delivery Controller is `2.2.2.2`.
- Filter Citrix machines to those in the Catalog `MagicalCatalog`
- Because `UseCustomCredentialFile` is specified, the user will be prompted once for credentials which will then be stored in `"$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"` for both Citrix and Prism.
- Operating in `WhatIf` mode with all logs output to `C:\Logs\MapCitrixTagstoPCVMCategories.log`.

### Synchronize Citrix Tags to Prism Central for Citrix DaaS using stored Secure Credential Files

Param Splatting

```
$scriptParams = @{
    LogPath                 = "C:\Logs\MapCitrixTagstoPCVMCategories.log"
    Mode                    = "CitrixToPrism"
    pc_source               = "1.1.1.1"
    TagPrefix               = "Nutanix_"
    CitrixDaaS              = $true
    CustomerID              = "FakeCustomerID"
    SecureClientFile        = "c:\securestuff\SecureClient.csv"
    Region                  = "US"
    Catalog                 = "MagicalCatalog"
    UseCustomCredentialFile = $true
    WhatIf                  = $true
}

& MapPCVMCategoriestoCitrixTags.ps1 @scriptParams
```

The direct script invocation via the command line with defined arguments would be:

```
.\MapPCVMCategoriestoCitrixTags.ps1 -Mode "CitrixToPrism" -pc_source "1.1.1.1" -TagPrefix "Nutanix_" -CitrixDaaS -CustomerID "FakeCustomerID" -SecureClientFile "c:\securestuff\SecureClient.csv" -Region "US" -Catalog "MagicalCatalog" -UseCustomCredentialFile -Whatif -Logpath "C:\Logs\MapCitrixTagstoPCVMCategories.log"
```

The script will:

- Execute in a `CitrixToPrism` sync mode where the Prism Central source is `1.1.1.1`.
- Use the Tag Prefix `Nutanix_` which is the default value.
- Execute against Citrix DaaS using the CustomerID `FakeCustomerID`, SecureClientFile `c:\securestuff\SecureClient.csv` for authentication and specify the `US` region for the tenant.
- Filter Citrix machines to those in the Catalog `MagicalCatalog`
- Because `UseCustomCredentialFile` is specified, the user will be prompted once for credentials which will then be stored in `"$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"` for Prism.
- Operating in `WhatIf` mode with all logs output to `C:\Logs\MapCitrixTagstoPCVMCategories.log`.

