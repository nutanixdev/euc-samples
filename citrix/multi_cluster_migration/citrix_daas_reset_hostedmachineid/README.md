# Reset VM Hosted Machine ID in Citrix DaaS

## Objective

The script is designed to assist in updating Citrix Cloud DaaS Hosting details for persistent machines living on Nutanix AHV. There are multiple scenarios where hosting details may become misaligned, some examples below:

- A planned migration to a new Nutanix Cluster which has a new Citrix DaaS Hosting Connection. This could be for maintenance windows, or cluster replacements etc.
- An unplanned disaster recovery event where a Nutanix Protection Domain is activated on a remote cluster which has a different Citrix DaaS Hosting Connection from the source cluster.

The script has the ability to alter both the Citrix DaaS Hosting Connection details so that DaaS understands where to locate the virtual machine from a power management perspective, and also the `HostedMachineId` which is the Nutanix VM `uuid` itself. The `HostedMachineId` in a graceful migration scenario will not change (The Protection Domain is Migrated), however will change if a Protection Domain is Activated (disaster recovery scenario).

The script only handles the update of the DaaS environment. It will not do any of the following:

- Interact with a Nutanix Protection Domain to perform any operations. This is assumed to have been completed as per existing processes.
- Interact with the virtual machine in any way.
- Interact with Active Directory or control any form of environment alteration. It is assumed that VDA registration is taken care of per existing processes.

The script caters for only non-provisioned, power-managed workloads. Use of MCS or PVS provisioning is not supported. For MCS provisioned persistent workloads (VDI), move the workload into a manual power-managed catalog first.

The script interacts with Citrix DaaS at the machine level. As such, Catalogs holding machines from multiple different Hosting Connections is supported. Only VMs found in both Citrix DaaS and the specified Nutanix cluster are impacted.

The script tries to minimise DaaS API calls. Unfortunately, DaaS limits the return of a single VM list call to `1000`. If the `MaxDaaSVMCount` is `1000` or less (default), then a single call is made to the DaaS tenant to retrieve all machines. If the DaaS tenant needs to be queried for more than `1000` Machines, and the `MaxDaaSVMCount` is above `1000`, then Nutanix Machines are retrieved first, and a call is made to each matched VM in DaaS. The same end result, but a larger number of API calls are made.

In some scenarios, it may be appropriate to move the Catalog hosting the power managed machines to the same Zone as the Hosting Connection. The `SwitchCatalogZoneID` and `CatalogNames` parameters support this requirement.

Nutanix Professional Services offers additional customised enhanced capability upon request. 

## Technical requirements for running the script

The script is compatible with Windows PowerShell 5.1 onwards.

This means that the technical requirements for the workstation or server running the script are as follows:

- Any Windows version which can run Windows PowerShell 5.1.
- An appropriate credential with sufficient permissions to connect to and retrieve virtual machine instances from Nutanix Prism Element including Protection Domain entities.
- A Citrix Cloud DaaS [Secure Client](https://docs.citrix.com/en-us/citrix-cloud/sdk-api.html#secure-clients).

## Parameter Details

The following parameters exist to drive the behaviour of the script:

#### Mandatory and recommended parameters:

- `Region`: Mandatory **`String`**. The Citrix Cloud DaaS Tenant Region. Either AP-S (Asia Pacific), US (USA), EU (Europe) or JP (Japan).
- `CustomerID`: Mandatory **`String`**. The Citrix Cloud Customer ID.
- `SecureClientFile`: Optional **`String`**. The path to the Citrix Cloud Secure Client CSV. Cannot be used with `ClientID` or `ClientSecret` parameters.
- `TargetMachineScope`: Mandatory **`String`**. The method used to target machine scoping. Can be either: `MachineList`,`CSV` or `NutanixPD`. See `TargetMachineList`, `TargetMachineCSVList` and `NutanixPD` parameters for detail.
- `TargetNutanixCluster`: Mandatory **`String`**. The target Nutanix cluster hosting the machines to target.
- `TargetHostingConnectionName`: Mandatory **`String`**. The name of the Hosting Connection to target workload changes to in Citrix DaaS. The Hosting Connection pointing to the target Nutanix Cluster.
- `ResetTargetHostingConnection`: Optional **`Switch`**. Reset the Target Hosting Connection if any machine objects are altered. This removes the sync delay between Citrix DaaS and the Nutanix Hosting platform and allows power status to be retrieved.

#### Optional Parameters

- `ClientID`: Optional **`String`**. The Citrix Cloud Secure Client ID. Cannot be used with the `SecureClientFile` Parameter. Must be combined with the `ClientSecret` parameter.
- `ClientSecret`: Optional **`String`**. The Citrix Cloud Secure Client Secret. Cannot be used with the `SecureClientFile` Parameter. Must be used with the `ClientID` parameter.
- `LogPath`: Optional **`String`**. Log path output for all operations. The default is `C:\Logs\UpdateDaaSHostedMachineId.log`
- `LogRollover`: Optional **`Int`**.Number of days before log files are rolled over. Default is 5.
- `UseCustomCredentialFile`: Optional. **`switch`**. Will call the `Get-CustomCredentials` function which keeps outputs and inputs a secure credential file base on Stephane Bourdeaud from Nutanix functions.
- `CredPath`: Optional **`String`**. Used if using the `UseCustomCredentialFile` parameter. Defines the location of the credential file. The default is `"$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"`.
- `Whatif`: Optional. **`Switch`**. Will action the script in a whatif processing mode only.
- `MaxDaaSVMCount`: Optional **`Integer`**. The max number of DaaS VMs to query via API. Default is `1000`. If above `1000`, then the `Domain` parameter is required.
- `Domain`: Optional. **`String`**. Used if the `MaxDaaSVMCount` is larger than `1000`. This is because we need to do a per VM API call and the match requires a Domain specified. This is the NETBIOS domain where the machine lives.
- `TargetMachineList`: Optional **`Array`**. An array of Nutanix machines to target. Use the name of the VM in Nutanix. Used with the `TargetMachineScope` parameter when set to `MachineList`.
- `TargetMachineCSVList`: Optional **`String`**. A CSV list of Nutanix machines to target. CSV file must use the `Name` Header. Used with the `TargetMachineScope` parameter when set to `CSV`.
- `NutanixPD`: Optional **`String`**. The Nutanix Protection Domain to target machine scoping. Used with the TargetMachineScope parameter when set to NutanixPD.
- `ExclusionList`: Optional **`Array`**. A list of machines to exclude from processing. Used regardless of the the `TargetmachineScope` parameter.
- `BypassHypervisorTypeCheck`: Optional **`Switch`**. An advanced parameter to bypass hypervisor checks. The script supports, by default, only Nutanix Hosting Connection Types: `AcropolisPCFactory`, `AcropolisFactory`, `AcropolisXIFactory`.
- `SwitchCatalogZoneID`: Optional **`Switch`**. An advanced parameter to allow the change of Catalog Zone ID to match the Target Hosting Connection. In some situations it may be preferable to have the Catalog in the same zone as the Hosting Connection. Must be used with the `CatalogNames` parameter.
- `CatalogNames`: Optional **`Array`**. An array of Catalogs to switch Zone IDs. Used in conjunction with the `SwitchCatalogZoneID` Parameter.

## Scenarios

### Scenario 1 

- Workloads have been moved to Nutanix Cluster `2.2.2.2` with a Citrix DaaS Hosting Connection named `Nutanix AHV Cluster 2`. 
- Nutanix virtual machines exist in a Protection Domain named `PD1`.
- Exclude a machine named `Machine1` as it is not important (be wary, this will leave the Hosting Connection details in tact entirely, so any power action from Citrix Cloud will be sent to the source hosting connection)

Param Splatting:

```
$Params = @{
    Region                       = "US"
    CustomerID                   = "fakecustID"
    SecureClientFile             = "C:\SecureFolder\secureclient.csv"
    TargetMachineScope           = "NutanixPD"
    TargetNutanixCluster         = "2.2.2.2"
    NutanixPD                    = "PD1"
    ExclusionList                = "Machine1"
    TargetHostingConnectionName  = "Nutanix AHV Cluster 2"
    ResetTargetHostingConnection = $true
    UseCustomCredentialFile      = $true
    Whatif                       = $true
}

& UpdateDaaSHostedMachineId.ps1 @params
```

The direct script invocation via the command line with defined arguments would be:

```
.\UpdateDaaSHostedMachineId.ps1 -Region "US" -CustomerID "fakecustID" -SecureClientFile "C:\SecureFolder\secureclient.csv" -TargetMachineScope "NutanixPD" -TargetNutanixCluster "2.2.2.2" -NutanixPD "PD1" -ExclusionList "Machine1" -TargetHostingConnectionName "Nutanix AHV Cluster 2" -ResetTargetHostingConnection -UseCustomCredentialFile -Whatif
```

The script will:

- Use the Citrix Cloud DaaS `US` region.
- Use the provided Customer ID `fakecustID` and Secure Client File in `c:\SecureFolder\secureclient.csv`.
- Connect to Citrix Cloud and query for machine and Hosting Details. Use the default `1000` machine retrieval count.
- Connect to the Nutanix Cluster `2.2.2.2` which holds the machines to target.
- Look at the Nutanix Protection Domain `PD1` as a source of machines. Exclude the machine named `Machine1`.
- Update the machines to use the Citrix DaaS Hosting Connection `Nutanix AHV Cluster 2` which is connected to the Nutanix Cluster at `2.2.2.2`.
- If the `HostedMachineId` attribute of the machine in Citrix DaaS does not align to the Nutanix `uuid`, it will be updated for each machine.
- Reset the Hosting Connection after any machine alterations if they are made.
- Use a custom credential file to authenticate against Nutanix (will prompt for creation if it does not exist).
- Process in a `whatif` mode with no changes made. Remove this switch to process the changes.

### Scenario 2

- Workloads have been moved to Nutanix Cluster `2.2.2.2` with a Citrix DaaS Hosting Connection named `Nutanix AHV Cluster 2`. 
- Nutanix virtual machines are being specified by a `MachineList`

Param Splatting:

```
$Params = @{
    Region                       = "US"
    CustomerID                   = "fakecustID"
    SecureClientFile             = "C:\SecureFolder\secureclient.csv"
    TargetMachineScope           = "MachineList"
    TargetMachineList            = "Machine1","Machine2","Machine3","Machine4"
    TargetNutanixCluster         = "2.2.2.2"
    TargetHostingConnectionName  = "Nutanix AHV Cluster 2"
    ResetTargetHostingConnection = $true
    UseCustomCredentialFile      = $true
    Whatif                       = $true
}

& UpdateDaaSHostedMachineId.ps1 @params
```

The direct script invocation via the command line with defined arguments would be:

```
.\UpdateDaaSHostedMachineId.ps1 -Region "US" -CustomerID "fakecustID" -SecureClientFile "C:\SecureFolder\secureclient.csv" -TargetMachineScope "MachineList" -TargetMachineList "Machine1","Machine2","Machine3","Machine4" -TargetNutanixCluster "2.2.2.2" -TargetHostingConnectionName "Nutanix AHV Cluster 2" -ResetTargetHostingConnection -UseCustomCredentialFile -Whatif
```

The script will:

- Use the Citrix Cloud DaaS `US` region.
- Use the provided Customer ID `fakecustID` and Secure Client File in `c:\SecureFolder\secureclient.csv`.
- Connect to Citrix Cloud and query for machine and Hosting Details. Use the default `1000` machine retrieval count.
- Connect to the Nutanix Cluster `2.2.2.2` which holds the machines to target.
- Look for machines in the `MachineList` array `"Machine1","Machine2","Machine3","Machine4"`
- Update the machines to use the Citrix DaaS Hosting Connection `Nutanix AHV Cluster 2` which is connected to the Nutanix Cluster at `2.2.2.2`.
- If the `HostedMachineId` attribute of the machine in Citrix DaaS does not align to the Nutanix `uuid`, it will be updated for each machine.
- Reset the Hosting Connection after any machine alterations if they are made.
- Use a custom credential file to authenticate against Nutanix (will prompt for creation if it does not exist).
- Process in a `whatif` mode with no changes made. Remove this switch to process the changes.

## Scenario 3

- Workloads have been moved to Nutanix Cluster `1.1.1.1` with a Citrix DaaS Hosting Connection named `Nutanix AHV Cluster 1`. 
- Nutanix virtual machines are being specified by a `CSV` list

Param Splatting:

```
$Params = @{
    Region                       = "US"
    CustomerID                   = "fakecustID"
    SecureClientFile             = "C:\SecureFolder\secureclient.csv"
    TargetMachineScope           = "CSV"
    TargetMachineCSVList         = "C:\Source\targets.csv"
    TargetNutanixCluster         = "1.1.1.1"
    TargetHostingConnectionName  = "Nutanix AHV Cluster 1"
    ResetTargetHostingConnection = $true
    Whatif                       = $true
}

& UpdateDaaSHostedMachineId.ps1 @params
```

The direct script invocation via the command line with defined arguments would be:

```
.\UpdateDaaSHostedMachineId.ps1 -Region "US" -CustomerID "fakecustID" -SecureClientFile "C:\SecureFolder\secureclient.csv" -TargetMachineScope "CSV" -TargetMachineCSVList "C:\Source\targets.csv" -TargetNutanixCluster "1.1.1.1" -TargetHostingConnectionName "Nutanix AHV Cluster 1" -ResetTargetHostingConnection -Whatif
```

The script will:

- Use the Citrix Cloud DaaS `US` region.
- Use the provided Customer ID `fakecustID` and Secure Client File in `c:\SecureFolder\secureclient.csv`.
- Connect to Citrix Cloud and query for machine and Hosting Details. Use the default `1000` machine retrieval count.
- Connect to the Nutanix Cluster `1.1.1.1` which holds the machines to target.
- Import the `C:\Source\targets.csv` and look for machines included.
- Update the machines to use the Citrix DaaS Hosting Connection `Nutanix AHV Cluster 1` which is connected to the Nutanix Cluster at `1.1.1.1`.
- If the `HostedMachineId` attribute of the machine in Citrix DaaS does not align to the Nutanix `uuid`, it will be updated for each machine.
- Reset the Hosting Connection after any machine alterations if they are made.
- Prompt for Nutanix Credentials.
- Process in a `whatif` mode with no changes made. Remove this switch to process the changes.

## Scenario 3

- Workloads have been moved to Nutanix Cluster `2.2.2.2` with a Citrix DaaS Hosting Connection named `Nutanix AHV Cluster 2`. 
- Nutanix virtual machines exist in a Protection Domain named `PD1`.
- Citrix Secure API credentials are being passed as parameters.

Param Splatting:

```
$Params = @{
    Region                       = "US"
    CustomerID                   = "fakecustID"
    ClientID                     = "FakeClientID"
    ClientSecret                 = "FakeSecret"
    TargetMachineScope           = "NutanixPD"
    TargetNutanixCluster         = "2.2.2.2"
    NutanixPD                    = "PD1"
    TargetHostingConnectionName  = "Nutanix AHV Cluster 2"
    ResetTargetHostingConnection = $true
    UseCustomCredentialFile      = $true
    Whatif                       = $true
}

& UpdateDaaSHostedMachineId.ps1 @params
```

The direct script invocation via the command line with defined arguments would be:

```
.\UpdateDaaSHostedMachineId.ps1 -Region "US" -CustomerID "fakecustID" -ClientID "FakeClientID" -ClientSecret "FakeSecret" -TargetMachineScope "NutanixPD" -TargetNutanixCluster "2.2.2.2" -NutanixPD "PD1" -TargetHostingConnectionName "Nutanix AHV Cluster 2" -ResetTargetHostingConnection -UseCustomCredentialFile -Whatif
```

The script will:

- Use the Citrix Cloud DaaS `US` region.
- Use the provided Customer ID `fakecustID` and provided ClientID `FakeClientID` with provided Client Secret `FakeSecret`
- Connect to Citrix Cloud and query for machine and Hosting Details. Use the default `1000` machine retrieval count.
- Connect to the Nutanix Cluster `2.2.2.2` which holds the machines to target.
- Look at the Nutanix Protection Domain `PD1` as a source of machines.
- Update the machines to use the Citrix DaaS Hosting Connection `Nutanix AHV Cluster 2` which is connected to the Nutanix Cluster at `2.2.2.2`.
- If the `HostedMachineId` attribute of the machine in Citrix DaaS does not align to the Nutanix `uuid`, it will be updated for each machine.
- Reset the Hosting Connection after any machine alterations if they are made.
- Use a custom credential file to authenticate against Nutanix (will prompt for creation if it does not exist).
- Process in a `whatif` mode with no changes made. Remove this switch to process the changes.

## Scenario 4

- Workloads have been moved to Nutanix Cluster `2.2.2.2` with a Citrix DaaS Hosting Connection named `Nutanix AHV Cluster 2`. 
- Nutanix virtual machines exist in a Protection Domain named `PD1`.
- Citrix Secure API credentials are being passed as parameters.
- Two Catalogs are being targeted to switch their Zone membership to match the Hosting Connection

Param Splatting:

```
$Params = @{
    Region                       = "US"
    CustomerID                   = "fakecustID"
    ClientID                     = "FakeClientID"
    ClientSecret                 = "FakeSecret"
    TargetMachineScope           = "NutanixPD"
    TargetNutanixCluster         = "2.2.2.2"
    NutanixPD                    = "PD1"
    TargetHostingConnectionName  = "Nutanix AHV Cluster 2"
    ResetTargetHostingConnection = $true
    SwitchCatalogZoneID          = $true
    CatalogNames                 = "Catalog1","Catalog1"
    UseCustomCredentialFile      = $true
    Whatif                       = $true
}

& UpdateDaaSHostedMachineId.ps1 @params
```

The direct script invocation via the command line with defined arguments would be:

```
.\UpdateDaaSHostedMachineId.ps1 -Region "US" -CustomerID "fakecustID" -ClientID "FakeClientID" -ClientSecret "FakeSecret" -TargetMachineScope "NutanixPD" -TargetNutanixCluster "2.2.2.2" -NutanixPD "PD1" -TargetHostingConnectionName "Nutanix AHV Cluster 2" -ResetTargetHostingConnection -SwitchCatalogZoneID -CatalogNames "Catalog1","Catalog1" -UseCustomCredentialFile -Whatif
```

The script will:

- Use the Citrix Cloud DaaS `US` region.
- Use the provided Customer ID `fakecustID` and provided ClientID `FakeClientID` with provided Client Secret `FakeSecret`
- Connect to Citrix Cloud and query for machine and Hosting Details. Use the default `1000` machine retrieval count.
- Connect to the Nutanix Cluster `2.2.2.2` which holds the machines to target.
- Look at the Nutanix Protection Domain `PD1` as a source of machines.
- Update the machines to use the Citrix DaaS Hosting Connection `Nutanix AHV Cluster 2` which is connected to the Nutanix Cluster at `2.2.2.2`.
- If the `HostedMachineId` attribute of the machine in Citrix DaaS does not align to the Nutanix `uuid`, it will be updated for each machine.
- Reset the Hosting Connection after any machine alterations if they are made.
- Switch the Catalogs `Catalog1` and `Catalog2` Zone IDs to the same as the Hosting Connection `Nutanix AHV Cluster 2`.
- Use a custom credential file to authenticate against Nutanix (will prompt for creation if it does not exist).
- Process in a `whatif` mode with no changes made. Remove this switch to process the changes.

### Scenario 5

- Workloads have been moved to Nutanix Cluster `2.2.2.2` with a Citrix DaaS Hosting Connection named `Nutanix AHV Cluster 2`. 
- Nutanix virtual machines exist in a Protection Domain named `PD1`.
- Include 2000 machines in DaaS.
- Exclude a machine named `Machine1` as it is not important (be wary, this will leave the Hosting Connection details in tact entirely, so any power action from Citrix Cloud will be sent to the source hosting connection)

Param Splatting:

```
$Params = @{
    Region                       = "US"
    CustomerID                   = "fakecustID"
    SecureClientFile             = "C:\SecureFolder\secureclient.csv"
    TargetMachineScope           = "NutanixPD"
    TargetNutanixCluster         = "2.2.2.2"
    NutanixPD                    = "PD1"
    ExclusionList                = "Machine1"
    TargetHostingConnectionName  = "Nutanix AHV Cluster 2"
    MaxDaaSVMCount               = "2000"
    Domain                       = "DOMAIN"
    ResetTargetHostingConnection = $true
    UseCustomCredentialFile      = $true
    Whatif                       = $true
}

& UpdateDaaSHostedMachineId.ps1 @params
```

The direct script invocation via the command line with defined arguments would be:

```
.\UpdateDaaSHostedMachineId.ps1 -Region "US" -CustomerID "fakecustID" -SecureClientFile "C:\SecureFolder\secureclient.csv" -TargetMachineScope "NutanixPD" -TargetNutanixCluster "2.2.2.2" -NutanixPD "PD1" -ExclusionList "Machine1" -TargetHostingConnectionName "Nutanix AHV Cluster 2" -ResetTargetHostingConnection -MaxDaaSVMCount "2000" -Domain "DOMAIN" -UseCustomCredentialFile -Whatif
```

The script will:

- Use the Citrix Cloud DaaS `US` region.
- Use the provided Customer ID `fakecustID` and Secure Client File in `c:\SecureFolder\secureclient.csv`.
- Connect to Citrix Cloud and query Hosting Details. Because the `MaxDaaSVMCount` is above `1000`, no machine queries will be actioned here.
- Connect to the Nutanix Cluster `2.2.2.2` which holds the machines to target.
- Look at the Nutanix Protection Domain `PD1` as a source of machines. Exclude the machine named `Machine1`.
- Manipulate the Nutanix Machine records to include the `Domain` and do an API call per VM to find the record in DaaS.
- Update the machines to use the Citrix DaaS Hosting Connection `Nutanix AHV Cluster 2` which is connected to the Nutanix Cluster at `2.2.2.2`.
- If the `HostedMachineId` attribute of the machine in Citrix DaaS does not align to the Nutanix `uuid`, it will be updated for each machine.
- Reset the Hosting Connection after any machine alterations if they are made.
- Use a custom credential file to authenticate against Nutanix (will prompt for creation if it does not exist).
- Process in a `whatif` mode with no changes made. Remove this switch to process the changes.