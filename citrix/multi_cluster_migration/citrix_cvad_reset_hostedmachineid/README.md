# Reset VM Hosted Machine ID in Citrix CVAD

## Objective

The script is designed to assist in updating Citrix VAD Hosting details for persistent machines living on Nutanix AHV. There are multiple scenarios where hosting details may become misaligned, some examples below:

- A planned migration to a new Nutanix Cluster which has a new Citrix Hosting Connection. This could be for maintenance windows, or cluster replacements etc.
- An unplanned disaster recovery event where a Nutanix Protection Domain is activated on a remote cluster which has a different Citrix Hosting Connection from the source cluster.

The script has the ability to alter both the Citrix Hosting Connection details so that CVAD understands where to locate the virtual machine from a power management perspective, and also the `HostedMachineId` which is the Nutanix VM `uuid` itself. The `HostedMachineId` in a graceful migration scenario will not change (The Protection Domain is Migrated), however will change if a Protection Domain is Activated (disaster recovery scenario).

The script only handles the update of the CVAD environment. It will not do any of the following:

- Interact with a Nutanix Protection Domain to perform any operations. This is assumed to have been completed as per existing processes.
- Interact with the virtual machine in any way.
- Interact with Active Directory or control any form of environment alteration. It is assumed that VDA registration is taken care of per existing processes.

The script caters for only non-provisioned, power-managed workloads. Use of MCS or PVS provisioning is not supported. For MCS provisioned persistent workloads (VDI), move the workload into a manual power-managed catalog first.

The script interacts with CVAD at the machine level. As such, Catalogs holding machines from multiple different Hosting Connections is supported. Only VMs found in both CVAD and the specified Nutanix cluster are impacted.

In some scenarios, it may be appropriate to move the Catalog hosting the power managed machines to the same Zone as the Hosting Connection. The `SwitchCatalogZoneID` and `CatalogNames` parameters support this requirement.

Nutanix Professional Services offers additional customised enhanced capability upon request. 

## Technical requirements for running the script

The script is compatible with Windows PowerShell 5.1. Due to requiring the Citrix Snapins, PowerShell core is not supported.

This means that the technical requirements for the workstation or server running the script are as follows:

- Any Windows version which can run Windows PowerShell 5.1.
- An appropriate credential with sufficient permissions to connect to and retrieve virtual machine instances from Nutanix Prism Element including Protection Domain entities.
- The script requires the Citrix PowerShell snapins are available. These can simply be installed by installing Citrix Studio. Alternatively, you can follow [Citrix guidance](https://support.citrix.com/article/CTX222326/how-to-configure-powershell-sdk-and-execute-commands-remotely-in-xenappxendesktop-7x) to install the required snapins manually.
- The script assumes that the user running the script, has appropriate rights in each Citrix site.

## Parameter Details

The following parameters exist to drive the behaviour of the script:

#### Mandatory and recommended parameters:

- `AdminAddress`: Mandatory**`String`**. The Citrix Controller to target.
- `TargetMachineScope`: Mandatory **`String`**. The method used to target machine scoping. Can be either: `MachineList`,`CSV` or `NutanixPD`. See `TargetMachineList`, `TargetMachineCSVList` and `NutanixPD` parameters for detail.
- `TargetNutanixCluster`: Mandatory **`String`**. The target Nutanix cluster hosting the machines to target.
- `TargetHostingConnectionName`: Mandatory **`String`**. The name of the Hosting Connection to target workload changes to in CVAD. The Hosting Connection pointing to the target Nutanix Cluster.
- `ResetTargetHostingConnection`: Optional **`Switch`**. Reset the Target Hosting Connection if any machine objects are altered. This removes the sync delay between CVAD and the Nutanix Hosting platform and allows power status to be retrieved.

#### Optional Parameters

- `LogPath`: Optional **`String`**. Log path output for all operations. The default is `C:\Logs\UpdateCVADHostedMachineId.log`
- `LogRollover`: Optional **`Int`**.Number of days before log files are rolled over. Default is 5/
- `UseCustomCredentialFile`: Optional. **`switch`**. Will call the `Get-CustomCredentials` function which keeps outputs and inputs a secure credential file base on Stephane Bourdeaud from Nutanix functions.
- `CredPath`: Optional **`String`**. Used if using the `UseCustomCredentialFile` parameter. Defines the location of the credential file. The default is `"$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"`.
- `Whatif`: Optional. **`Switch`**. Will action the script in a whatif processing mode only.
- `MaxCVADVMCount`: Optional **`Integer`**. The max number of CVAD VMs to query. Default is 1000.
- `TargetMachineList`: Optional **`Array`**. An array of Nutanix machines to target. Use the name of the VM in Nutanix. Used with the `TargetMachineScope` parameter when set to `MachineList`.
- `TargetMachineCSVList`: Optional **`String`**. A CSV list of Nutanix machines to target. CSV file must use the `Name` Header. Used with the `TargetMachineScope` parameter when set to `CSV`.
- `NutanixPD`: Optional **`String`**. The Nutanix Protection Domain to target machine scoping. Used with the TargetMachineScope parameter when set to NutanixPD.
- `ExclusionList`: Optional **`Array`**. A list of machines to exclude from processing. Used regardless of the the `TargetmachineScope` parameter.
- `BypassHypervisorTypeCheck`: Optional **`Switch`**. An advanced parameter to bypass hypervisor checks. The script supports, by default, only Nutanix Hosting Connection Types: `AcropolisPCFactory`, `AcropolisFactory`, `AcropolisXIFactory`.
- `SwitchCatalogZoneID`: Optional **`Switch`**. An advanced parameter to allow the change of Catalog Zone ID to match the Target Hosting Connection. In some situations it may be preferable to have the Catalog in the same zone as the Hosting Connection. Must be used with the `CatalogNames` parameter.
- `CatalogNames`: Optional **`Array`**. An array of Catalogs to switch Zone IDs. Used in conjunction with the `SwitchCatalogZoneID` Parameter.

## Scenarios

### Scenario 1 

- Workloads have been moved to Nutanix Cluster `2.2.2.2` with a Citrix Hosting Connection named `Nutanix AHV Cluster 2` on Controller `Controller1`
- Nutanix virtual machines exist in a Protection Domain named `PD1`.
- Exclude a machine named `Machine2` as it is not important (be wary, this will leave the Hosting Connection details in tact entirely, so any power action from Citrix will be sent to the source hosting connection)

Param Splatting:

```
$Params = @{
    AdminAddress                 = "Controller1"
    TargetMachineScope           = "NutanixPD"
    ExclusionList                = "Machine2"
    NutanixPD                    = "PD1"
    TargetNutanixCluster         = "2.2.2.2"
    TargetHostingConnectionName  = "Nutanix AHV Cluster 2"
    ResetTargetHostingConnection = $true
    UseCustomCredentialFile      = $true
    MaxCVADVMCount               = "2000"
}

& UpdateCVADHostedMachineId.ps1 @params
```

The direct script invocation via the command line with defined arguments would be:

```
.\UpdateCVADHostedMachineId.ps1 -AdminAddress "Controller1" -TargetMachineScope "NutanixPD" -NutanixPD "PD1" -ExclusionList "Machine2" -TargetNutanixCluster "2.2.2.2" -TargetHostingConnectionName "Nutanix AHV Cluster 2" -ResetTargetHostingConnection -UseCustomCredentialFile -MaxCVADVMCount "2000" -Whatif
```

The script will:

- Use the Citrix Controller `Controller1`.
- Connect to Citrix and query for machine and Hosting Details. Expand the search scope to `2000` machine retrieval count in Citrix.
- Connect to the Nutanix Cluster `2.2.2.2` which holds the machines to target.
- Look at the Nutanix Protection Domain `PD1` as a source of machines. Exclude the machine named `Machine2`.
- Update the machines to use the Citrix Hosting Connection `Nutanix AHV Cluster 2` which is connected to the Nutanix Cluster at `2.2.2.2`.
- If the `HostedMachineId` attribute of the machine in Citrix does not align to the Nutanix `uuid`, it will be updated for each machine.
- Reset the Hosting Connection after any machine alterations if they are made.
- Use a custom credential file to authenticate against Nutanix (will prompt for creation if it does not exist).
- Process in a `whatif` mode with no changes made. Remove this switch to process the changes.


### Scenario 2

- Workloads have been moved to Nutanix Cluster `2.2.2.2` with a Citrix Hosting Connection named `Nutanix AHV Cluster 2`. 
- Nutanix virtual machines are being specified by a `MachineList`

Param Splatting:

```
$Params = @{
    AdminAddress                 = "Controller1"
    TargetMachineScope           = "MachineList"
    TargetMachineList            = "Machine1","Machine2"
    TargetNutanixCluster         = "2.2.2.2"
    TargetHostingConnectionName  = "Nutanix AHV Cluster 2"
    ResetTargetHostingConnection = $true
    UseCustomCredentialFile      = $true
}

& UpdateCVADHostedMachineId.ps1 @params
```

The direct script invocation via the command line with defined arguments would be:

```
.\UpdateCVADHostedMachineId.ps1 -AdminAddress "Controller1" -TargetMachineScope "MachineList" -TargetMachineList "Machine1","Machine2" -TargetNutanixCluster "2.2.2.2" -TargetHostingConnectionName "Nutanix AHV Cluster 2" -ResetTargetHostingConnection -UseCustomCredentialFile -Whatif
```

The script will:

- Use the Citrix Controller `Controller1`.
- Connect to Citrix and query for machine and Hosting Details. Use the default `1000` machine retrieval count.
- Connect to the Nutanix Cluster `2.2.2.2` which holds the machines to target.
- Look for machines in the `MachineList` array `"Machine1","Machine2"`
- Update the machines to use the Citrix Hosting Connection `Nutanix AHV Cluster 2` which is connected to the Nutanix Cluster at `2.2.2.2`.
- If the `HostedMachineId` attribute of the machine in Citrix does not align to the Nutanix `uuid`, it will be updated for each machine.
- Reset the Hosting Connection after any machine alterations if they are made.
- Use a custom credential file to authenticate against Nutanix (will prompt for creation if it does not exist).
- Process in a `whatif` mode with no changes made. Remove this switch to process the changes.

### Scenario 3

- Workloads have been moved to Nutanix Cluster `1.1.1.1` with a Citrix Hosting Connection named `Nutanix AHV Cluster 1`. 
- Nutanix virtual machines are being specified by a `CSV` list

Param Splatting:

```
$Params = @{
    AdminAddress                 = "Controller1"
    TargetMachineScope           = "CSV"
    TargetMachineCSVList         = "C:\Source\targets.csv"
    TargetNutanixCluster         = "1.1.1.1"
    TargetHostingConnectionName  = "Nutanix AHV Cluster 1"
    ResetTargetHostingConnection = $true
}

& UpdateCVADHostedMachineId.ps1 @params
```

The direct script invocation via the command line with defined arguments would be:

```
.\UpdateCVADHostedMachineId.ps1 -AdminAddress "Controller1" -TargetMachineScope "CSV" -TargetMachineCSVList "C:\Source\targets.csv" -TargetNutanixCluster "1.1.1.1" -TargetHostingConnectionName "Nutanix AHV Cluster 1" -ResetTargetHostingConnection -Whatif
```

The script will:

- Use the Citrix Controller `Controller1`.
- Connect to Citrix and query for machine and Hosting Details. Use the default `1000` machine retrieval count.
- Connect to the Nutanix Cluster `1.1.1.1` which holds the machines to target.
- Import the `C:\Source\targets.csv` and look for machines included.
- Update the machines to use the Citrix Hosting Connection `Nutanix AHV Cluster 1` which is connected to the Nutanix Cluster at `1.1.1.1`.
- If the `HostedMachineId` attribute of the machine in Citrix does not align to the Nutanix `uuid`, it will be updated for each machine.
- Reset the Hosting Connection after any machine alterations if they are made.
- Prompt for Nutanix Credentials.
- Process in a `whatif` mode with no changes made. Remove this switch to process the changes.

### Scenario 4

- Workloads have been moved to Nutanix Cluster `1.1.1.1` with a Citrix Hosting Connection named `Nutanix AHV Cluster 1`. 
- Nutanix virtual machines are being specified by a `CSV` list
- Two Catalogs are being targeted to switch their Zone membership to match the Hosting Connection

Param Splatting:

```
$Params = @{
    AdminAddress                 = "Controller1"
    TargetMachineScope           = "CSV"
    TargetMachineCSVList         = "C:\Source\targets.csv"
    TargetNutanixCluster         = "1.1.1.1"
    TargetHostingConnectionName  = "Nutanix AHV Cluster 1"
    ResetTargetHostingConnection = $true
    SwitchCatalogZoneID          = $true
    CatalogNames                 = "Catalog1","Catalog1"
}

& UpdateCVADHostedMachineId.ps1 @params
```

The direct script invocation via the command line with defined arguments would be:

```
.\UpdateCVADHostedMachineId.ps1 -AdminAddress "Controller1" -TargetMachineScope "CSV" -TargetMachineCSVList "C:\Source\targets.csv" -TargetNutanixCluster "1.1.1.1" -TargetHostingConnectionName "Nutanix AHV Cluster 1" -ResetTargetHostingConnection -SwitchCatalogZoneID -CatalogNames "Catalog1","Catalog1" -Whatif
```

The script will:

- Use the Citrix Controller `Controller1`.
- Connect to Citrix and query for machine and Hosting Details. Use the default `1000` machine retrieval count.
- Connect to the Nutanix Cluster `1.1.1.1` which holds the machines to target.
- Import the `C:\Source\targets.csv` and look for machines included.
- Update the machines to use the Citrix Hosting Connection `Nutanix AHV Cluster 1` which is connected to the Nutanix Cluster at `1.1.1.1`.
- If the `HostedMachineId` attribute of the machine in Citrix does not align to the Nutanix `uuid`, it will be updated for each machine.
- Reset the Hosting Connection after any machine alterations if they are made.
- Switch the Catalogs `Catalog1` and `Catalog2` Zone IDs to the same as the Hosting Connection `Nutanix AHV Cluster 1`.
- Prompt for Nutanix Credentials.
- Process in a `whatif` mode with no changes made. Remove this switch to process the changes.