## Objective

Automate the distribution of a Prism Central `Recovery Point` across one or many clusters, under one of many Prism Centrals, leaving either a Prism Central `Template` or a Prism Element based `Snapshot` to be used for EUC solution provisioning.

The end state should be either an identical `snapshot` available on the source, and all remote clusters ready for Provisioning, or an identical `Template` if the solution integrates with Prism Central.

The script aims to provide an alternative to Prism Central `Protection Policy` based distribution when you need more cluster endpoints than what a `Protection Policy` can provide.

Optionally, and purely as an example on how you could integrate a workflow for both replication and platform updates, Citrix Integration is provided to update Catalogs with the created `snapshot`.

## Mesh Logic

The script is designed to discover, from the `SourcePC` defined, all clusters under this PC. It will also discover any additional Prism Centrals, and any clusters under those Prism Centrals.

The default behavior and assumption is that you want the script to output either a Template (per PC) or a Snapshot (per cluster) under all discovered entities.

If this is not the case, use the `AdditionalPrismCentrals`, `ExcludedPrismCentrals` and `ExcludedClusters` Params to customise your replication.

## Process Flow:

The script executes the following logic by default:

- Executes validation logic including discovery and authentication
- Finds the source VM
- Creates a new Recovery Point for the VM

If using `PC-Template` output, then per Prism Central:

- If this is not the source Prism Central, it replicates the Recovery Point from the Source PC, to this PC
- Restores the Recovery Point to a Temporary VM
- Learns about the Temp VM
- Creates a Template from this VM
- Deletes the Temp VM
- Cleans up older Templates
- Deletes the Recovery Point

If using `PE-Snapshot` output, then per Prism Central, it executes the following per Cluster:

- Replicates the Recovery Point to the Cluster from the source PC and Cluster. Replication always occurs from the source, to the target
- Restores this Recovery Point to a Temporary VM local to the Cluster
- Learns about the Temp VM in PC
- If required, migrates the VM disks to the defined container on the Cluster
- Switches to v2 API and 
    - Learns about the VM local to the cluster
    - Creates a snapshot for the Temp VM
    - Deletes the Temp VM
    - Cleans up older Snapshots
- Deletes the Recovery Point from the Cluster

Once all tasks are completed for all clusters, the source Recovery Point is deleted.

If integration with Citrix is enabled, the catalog update tasks now execute.

## Automation Requirements

- At least one `Prism Central` instance configured hosting a target Gold Image `VM`.
- All `Prism Central` instances must have the same `account` with the same permissions available. The script does not support differing accounts across `Prism Centrals` today.
- If using a `snapshot` output (`Prism Element`), each `Prism Element` instance must have the same `account` with the same permissions available. The script does not support differing accounts across `Prism Elements` today.
- If you choose to use the Citrix integration workflow, you must be running either CVAD on a version that supports consuming the Citrix API, or Citrix DaaS.

## Technical requirements for running the script

- The script is written 100% in PowerShell and uses the Nutanix APIs to action all Nutanix tasks. It supports PowerShell 7 only.
- For Prism Central operations, the `v4` API is used for all functions unless there is no available v4 endpoint today.
- For Prism Element operations, the `v2` API is used.
- The script assumes a username and password for Prism Central. A dedicated service account should be created to action these tasks.
- The script assumes the same username and password for all PE instances. A dedicated service account should be created to action these tasks.
- The script automates tasks that can be executed in the Prism Central GUI. It has all the same network requirements for replication of data between clusters.
- The script assumes that the user running the script, has appropriate rights in each Citrix site if Citrix Catalogs are processed.
- The script has been tested against a Prism Central instance with a paired Prism Central in a Single Availability zone configuration. The source Prism Central hosted 4 clusters, and the paired Prism Central hosted 3 clusters.
- The script was developed and tested in its final state against PC version `pc.2024.3.1.4` and AOS version `7.0.0.5`

## Validation and Discovery of Availability Zones

- The script will use the v3 API to identify Availability Zones. If you want more fine grained control, or find issues with the discovery process, you can use the `AdditionalPrismCentrals` parameter instead. This is an array of IP addresses. Specify the IP of the Prism Centrals you want to exclude.
- In the same vein, if you need to exclude any specific Prism Centrals, use the `ExcludedPrismCentrals` parameter. This is an array of IP addresses. Specify the IP of the Prism Centrals you want to exclude.
- It is assumed that the same credentials work for all PC's and all PE's.
- The script has relatively strict validation logic and will halt on most errors. This is designed for consistency, however, you can override this behavior with `BypassAllValidationErrors` being set. Be warned that by using this switch, you may end up with inconsistent results across clusters. The script is designed to give you consistency. Use this switch for troubleshooting only. Terminating errors are still Terminating errors.
- You should always, always, always run this script with the `ValidateOnly` switch at least once to identify any potential failure points without making changes.

## Parameter and Scenario Details

Due to number of parameters available, the script supports a JSON based configuration approach. To enable this functionality, all parameters have been made optional outside of the `SourcePC`. Validation of parameter configurations are handled in code. If you customise or enhance this script, you should also consider the parameter validation.

The following parameters exist to drive the behaviour of the script. All `Mandatory` parameters are still defined as `Mandatory` below, even though the above configuration option and impacts exist.

#### Mandatory and Critical parameters:

- `SourcePC`: Mandatory **`String`**. This is the Source PC that owns the BaseVM. It is always mandatory.
- `BaseVM`: Mandatory **`String`**. The name of the base image VM. This is CASE SENSITIVE. This machine is used as the source for `Recovery Points`
- `OutputType`: Mandatory. **`String`**. The output type of the Recovery Point. Either "`PE-Snapshot`" or "`PC-Template`". Default is "`PC-Template`". If you select `PE-Snapshot`, then all discovered clusters will be processed with a snapshot left.
- `ValidateOnly`: Optional. **`Switch`**. If set, the script will only validate the environment and not make any changes.

#### Optional and Default Value Parameters

- `ConfigPath`: Optional **`String`**. A JSON configuration file containing all parameters for the script. See the example file stored alongside this script. Overrides all other params.
- `LogPath`: Optional **`String`**. Log path output for all operations. The default is `C:\Logs\DistributePCRecoveryPoints.log`
- `LogRollover`: Optional **`Integer`**. Number of days before the log files are rolled over. The default is 5.
- `AdditionalPrismCentrals`: Optional **`Array`**. A manually defined array of Prism Centrals IP addresses. These should be aligned to availability zones. This will override PC auto discovery of Prism Centrals via Availability Zone Pairings. This is an advanced param.
- `ExcludedPrismCentrals`: Optional **`Array`**. A manually defined array of Prism Centrals IP addresses to ignore from processing. This is an advanced param. This will exclude PCs discovered from Availability Zone Pairins.
- `ExcludedClusters`: Optional. **`Array`**. Used for cases where a cluster should not, or could not during validation, be queried. This is an advanced param. Use this to exclude specific clusters from processing (IP address of the Cluster).
- `VMPrefix`: Optional. **`String`**. The prefix name to create for the restored entity and the created snapshots or templates. Default is "`ctx_`"
- `TempVMName`: Optional. **`string`**. The name of the temporary VM created for the snapshot (`ctx_TempAPIVM`). Default is "`TempAPIVM`".
- `RecoveryPoint`: Optional **`string`**. The name of the Recovery Point used for a custom restore. It not specified, the latest is used. This is an advanced parameter. This is typically the name in brackets when looking at PC.
- `UseLatestRecoveryPoint`: Optional **`Switch`**. If specified, will use the latest existing Recovery Point on the VM instead of taking a new one. This is an advanced parameter. Typically not needed.
- `ImageSnapsOrTemplatesToRetain`: Optional. **`Integer`**. The number of Snapshots or Templates to retain. Effectively a cleanup mode. Default is 5. Anything older than this that meets the naming critera (based on VMPrefix) will be deleted.
- `UseCustomCredentialFile` Optional: **`Switch`**: Will call the `Get-CustomCredentials` function which keeps outputs and inputs a secure credential file base on `Stephane Bourdeaud` from Nutanix functions.
- `CredPath`: Optional **`String`**. Used if using the `UseCustomCredentialFile` parameter. Defines the location of the credential file. The default is `"$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"`
- `OverrideStorageContainer`: Optional **`String`**. If set, will migrate the temp VM to this storage container before the snapshot is created. This is useful if you want to ensure that the snapshot is created in a specific storage container. See the limitation notes for more info.
- `SleepTime`: Optional **`Integer`**. The amount of time to sleep between task status polling in both v2, v4 functions. Default is `2 seconds`.
- `APICallVerboseLogging`: Optional. **`Switch`**. Show the API calls being made.
- `BypassAllValidationErrors`: Optional. **`Switch`**. If set, the script will bypass all validation errors and proceed with the script execution. Dangermouse.

#### Citrix Integration Parameters

The script supports both Citrix VAD and DaaS deployments using the Citrix API

CVAD Params:
- `DomainUser`: Optional. **`String`**. The domain user to use for API calls for Citrix (VAD) processing. Used for API auth. If UseCustomCredentialFile is set, this is ignored. If neither this, nor UseCustomCredentialFile is set, the script will exit.
- `DomainPassword`: Optional. **`String`**. The domain password to use for API calls for Citrix (VAD) processing. Used for API auth. If UseCustomCredentialFile is set, this is ignored. If neither this, nor UseCustomCredentialFile is set, the script will exit.
- `ctx_AdminAddress`: Optional **`String`**. The Delivery Controller to target for Citrix Catalog updates. Single Citrix Site parameter only. For multi-site, use `ctx_siteConfigJSON` switch.
- `ctx_Catalogs`: Optional **`Array`**. A list of Citrix Catalogs to update after the Snapshot replication has finished. User running the script must have sufficient rights on the Citrix Site. Single Citrix Site parameter only. For multi-site, use `ctx_siteConfigJSON` switch.
- `ctx_SiteConfigJSON`: Optional **`String`**. A JSON file containing a list of Catalogs and associated Delivery Controllers for a multi-site environment. This will override the `ctx_AdminAddress` and `ctx_Catalogs` parameters.

An example JSON configuration for the multi-site citrix integration:
```
[
    {
        "Catalog": "W11-CL1-Test",
        "Controller": "DDC1.domain.com"
    },
    {
        "Catalog": "W11-CL5-Test",
        "Controller": "DDC2.domain.com"
    }
]
```

DaaS Params:

- `IsCitrixDaaS`: Optional. **`Switch`**. Defines that we are processing Citrix DaaS environments and not CVAD On Prem.
- `CustomerID`: Optional. **`String`**. The Customer ID to use for DaaS API calls.
- `ClientID`: Optional. **`String`**. The Client ID to use for DaaS API calls.
- `ClientSecret`: Optional. **`String`**. The Client Secret to use for DaaS API calls.
- `Region`: Optional. **`String`**. The Citrix Cloud DaaS Tenant Region. Either AP-S (Asia Pacific), US (USA), EU (Europe) or JP (Japan). Default is "US".
- `SecureClientFile`: Optional. **`String`**. SecureClientFile to use for API calls. Optional in place of credentials being passed.

## Limitation Notes

- The script example has been developed, and tested against `pc.2024.3.1.4`
- The way that Recovery Points are restored when replicated, does not allow a container to be defined. As such, an RP restore outside of its home cluster will land on a container with as close characterstics as its source as possible.
- If you want to override this container location, the script offers the ability to migrate the temp VM before a snapshot or Template is created. All clusters must have the same named container for this to work
- The temp VM when restored will have no NIC. This is fine for MCS provisioning.
- The script requires that all Prism Centrals have the same authentication account (if you need different accounts per PC, update the script logic)
- The script required that all Prism Elements have the same authentication account (if you need different accounts per PE, update the script logic)
- If you choose to use Citrix integration, this integration is currently limited to PE based plugins.

## Tests Completed

The following scenarios were validated during the build of this script example:

- 2 PCs, 7 clusters, full replication with Autodiscover of Prism Centrals [✅]
- 2 PCs, 7 clusters, full replication with Autodiscover of Prism Centrals - with JSON Configuration [✅]
- 2 PCs, 7 clusters, full replication with Manual Addition of Prism Centrals [✅]
- 2 Pcs, 7 clusters, full replication with exclusion of a cluster under each PC [✅]
- 2 PCs, 7 clusters, full replication with exclusion of a cluster and exclusion of a PC [✅]
- 2 PCs, 7 clusters, full replication using the latest RP [✅]
- 2 PCs, 7 clusters, full replication with Template output type [✅]
- 2 PCs, 7 clusters, full replication with Snapshot output type [✅]
- 2 PCs, 7 clusters, full replication with Template and cleanup Specified [✅]
- 2 PCs, 7 clusters, full replication with Snapshot and cleanup Specified [✅]
- 2 PCs, 7 clusters, full replication with StorageContainerOverride configured [✅]
- 2 PCs, 7 clusters, full replication with 6 x Citrix Hosting Connections under one Site [✅]
- 2 PCs, 7 clusters, full replication with 6 x Citrix Hosting Connections under two Sites [✅]
- 2 PCs, 7 clusters, full replication with 6 x Citrix Hosting Connections under two Sites - with JSON Configuration [✅]
- 2 PCs, 7 clusters, full replication with 6 x Citrix Hosting Connections under Citrix DaaS [✅]

## Example Scenarios and Use Cases

The following examples use parameter splatting to make reading easier. A corresponding param based example is also included:

### Simple Mesh replication resulting in a Snapshot per Cluster.

```
$params = @{
    LogPath = "C:\Logs\DistributePCRecoveryPoints.log"
    LogRollover = 5
    SourcePC = "1.1.1.1"
    BaseVM = "W11-JK-GLD"
    VMPrefix = "ctx_"
    TempVMName = "TempAPIVM"
    OutputType = "PE-Snapshot"
    ImageSnapsOrTemplatesToRetain = 5
    UseCustomCredentialFile = $true
    CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
    ValidateOnly = $true
}

& "DistributePCRecoveryPoints.ps1" @params
```

```
& "DistributePCRecoveryPoints.ps1" -LogPath "C:\Logs\DistributePCRecoveryPoints.log" -LogRollover 5 -SourcePC "1.1.1.1" -BaseVM "W11-JK-GLD" -VMPrefix "ctx_" -TempVMName "TempAPIVM" -OutputType "PE-Snapshot" -ImageSnapsOrTemplatesToRetain 5 -UseCustomCredentialFile -CredPath "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials" -ValidateOnly
```

The above example will:

- Use PC `1.1.1.1` as the source PC. It will learn any additional PCs configured in an AZ pairing.
- Output a PE based `snapshot` by looping through all clusters and Prism Centrals.
- Use the `W11-JK-GLD` VM as the source VM, and output snapshots with the `ctx_` prefix. The last `5 snapshots` matching this prefix will be retained, older snapshots will be `deleted`.
- Will prompt and store credentials in the specified `CredPath`. Second runs will use the stored credentials. If they need to be deleted or reset, delete the files in the `CredPath`.
- Will log to `C:\Logs\DistributePCRecoveryPoints.log`.
- Run the script in `validation` mode. It will `not` make any changes to the environment.

### Simple Mesh replication resulting in a Snapshot per Cluster on a defined Storage Container.

```
$params = @{
    LogPath = "C:\Logs\DistributePCRecoveryPoints.log"
    LogRollover = 5
    SourcePC = "1.1.1.1"
    BaseVM = "W11-JK-GLD"
    VMPrefix = "ctx_"
    TempVMName = "TempAPIVM"
    OutputType = "PE-Snapshot"
    ImageSnapsOrTemplatesToRetain = 5
    UseCustomCredentialFile = $true
    CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
    OverrideStorageContainer = "EUC-Container-Name"
}

& "DistributePCRecoveryPoints.ps1" @params
```

```
& "DistributePCRecoveryPoints.ps1" -LogPath "C:\Logs\DistributePCRecoveryPoints.log" -LogRollover 5 -SourcePC "1.1.1.1" -BaseVM "W11-JK-GLD" -VMPrefix "ctx_" -TempVMName "TempAPIVM" -OutputType "PE-Snapshot" -ImageSnapsOrTemplatesToRetain 5 -UseCustomCredentialFile -CredPath "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials" -OverrideStorageContainer "EUC-Container-Name"
```

The above example will:

- Use PC `1.1.1.1` as the source PC. It will learn any additional PCs configured in an AZ pairing.
- Output a PE based `snapshot` by looping through all clusters and Prism Centrals.
- Use the `W11-JK-GLD` VM as the source VM, and output snapshots with the `ctx_` prefix. The last `5 snapshots` matching this prefix will be retained, older snapshots will be `deleted`.
- Will prompt and store credentials in the specified `CredPath`. Second runs will use the stored credentials. If they need to be deleted or reset, delete the files in the `CredPath`.
- Will log to `C:\Logs\DistributePCRecoveryPoints.log`.
- Will `migrate` the temporary VM to the specified `storage container` before creating the `snapshot`. It will be validated beforehand to ensure that the storage container exists on `all clusters`.

### Simple Mesh replication across two PCs resulting in a Template per PC

```
$params = @{
    LogPath = "C:\Logs\DistributePCRecoveryPoints.log"
    LogRollover = 5
    SourcePC = "1.1.1.1"
    BaseVM = "W11-JK-GLD"
    VMPrefix = "ctx_"
    TempVMName = "TempAPIVM"
    OutputType = "PC-Template"
    ImageSnapsOrTemplatesToRetain = 5
    UseCustomCredentialFile = $true
    CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
}

& "DistributePCRecoveryPoints.ps1" @params
```

```
& "DistributePCRecoveryPoints.ps1" -LogPath "C:\Logs\DistributePCRecoveryPoints.log" -LogRollover 5 -SourcePC "1.1.1.1" -BaseVM "W11-JK-GLD" -VMPrefix "ctx_" -TempVMName "TempAPIVM" -OutputType "PC-Template" -ImageSnapsOrTemplatesToRetain 5 -UseCustomCredentialFile -CredPath "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
```

The above example will:

- Use PC `1.1.1.1` as the source PC. It will learn any additional PCs configured in an AZ pairing.
- Output a `PC Template `for each Prism Central.
- Use the `W11-JK-GLD` VM as the source VM, and output Template with the `ctx_` prefix. The last 5` Templates` matching this prefix will be retained, older Templates will be `deleted`.
- Will prompt and store credentials in the specified `CredPath`. Second runs will use the stored credentials. If they need to be deleted or reset, delete the files in the `CredPath`.
- Will log to `C:\Logs\DistributePCRecoveryPoints.log`.

### Advanced replication manually defining an additional Prism Central and excluding a Cluster

```
$params = @{
    LogPath = "C:\Logs\DistributePCRecoveryPoints.log"
    LogRollover = 5
    SourcePC = "1.1.1.1"
    BaseVM = "W11-JK-GLD"
    AdditionalPrismCentrals = @("2.2.2.2")
    ExcludedClusters = @("5.5.5.5")
    VMPrefix = "ctx_"
    TempVMName = "TempAPIVM"
    OutputType = "PE-Snapshot"
    ImageSnapsOrTemplatesToRetain = 5
    UseCustomCredentialFile = $true
    CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials" # Default path for custom credential file
}

& "DistributePCRecoveryPoints.ps1" @params
```

```
& "DistributePCRecoveryPoints.ps1" -LogPath "C:\Logs\DistributePCRecoveryPoints.log" -LogRollover 5 -SourcePC "1.1.1.1" -BaseVM "W11-JK-GLD" -AdditionalPrismCentrals "2.2.2.2" -ExcludedClusters "5.5.5.5" -VMPrefix "ctx_" -TempVMName "TempAPIVM" -OutputType "PE-Snapshot" -ImageSnapsOrTemplatesToRetain 5 -UseCustomCredentialFile -CredPath "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
```

The above example will:

- Use PC `1.1.1.1` as the source PC. It will `include` PC `2.2.2.2` and not discover any other PCs.
- It will `exclude` the cluster `5.5.5.5` from the replication process.
- Use the `W11-JK-GLD` VM as the source VM, and output `snapshots` with the `ctx_` prefix. The last `5 snapshots` matching this prefix will be retained, older snapshots will be `deleted`.
- Will prompt and store credentials in the specified `CredPath`. Second runs will use the stored credentials. If they need to be deleted or reset, delete the files in the `CredPath`.
- Will log to `C:\Logs\DistributePCRecoveryPoints.log`.

### Simple Mesh replication updating Citrix Catalogs in a single Citrix Site

```
$params = @{
    LogPath = "C:\Logs\DistributePCRecoveryPoints.log"
    LogRollover = 5 
    SourcePC = "1.1.1.1"
    BaseVM = "W11-JK-GLD"
    VMPrefix = "ctx_"
    TempVMName = "TempAPIVM"
    OutputType = "PE-Snapshot"
    ImageSnapsOrTemplatesToRetain = 5
    UseCustomCredentialFile = $true
    CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
    ctx_Catalogs = @("Catalog1","Catalog2")
    ctx_AdminAddress = "DDC1.shnazzydomain.com"
}

& "DistributePCRecoveryPoints.ps1" @params
```

```
& "DistributePCRecoveryPoints.ps1" -LogPath "C:\Logs\DistributePCRecoveryPoints.log" -LogRollover 5 -SourcePC "1.1.1.1" -BaseVM "W11-JK-GLD" -VMPrefix "ctx_" -TempVMName "TempAPIVM" -OutputType "PE-Snapshot" -ImageSnapsOrTemplatesToRetain 5 -UseCustomCredentialFile -CredPath "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials" -ctx_Catalogs @("Catalog1","Catalog2") -ctx_AdminAddress "DDC1.shnazzydomain.com"
```

The above example will:
- Use PC `1.1.1.1` as the source PC. It will learn any additional PCs configured in an AZ pairing.
- Use the `W11-JK-GLD` VM as the source VM, and output snapshots with the `ctx_` prefix. The last `5 snapshots` matching this prefix will be retained, older snapshots will be `deleted`.
- Will prompt and store credentials in the specified `CredPath`. Second runs will use the stored credentials. If they need to be deleted or reset, delete the files in the `CredPath`.
- Will process the Citrix Catalogs `Catalog1` and `Catalog2` on the `DDC1.shnazzydomain.com` Delivery Controller. Will store credentials and use them for authenticating against the Citrix API. Use `admin@shnazzydomain.com` as the username format when prompted.
- Will log to `C:\Logs\DistributePCRecoveryPoints.log`.

### Simple Mesh Topology updating Citrix Catalogs in Citrix DaaS useing a Secure Client

```
$params = @{
    LogPath = "C:\Logs\DistributePCRecoveryPoints.log" 
    LogRollover = 5 
    SourcePC = "1.1.1.1" 
    BaseVM = "W11-JK-GLD"
    VMPrefix = "ctx_" 
    TempVMName = "TempAPIVM"
    OutputType = "PE-Snapshot"
    ImageSnapsOrTemplatesToRetain = 5
    UseCustomCredentialFile = $true
    CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"
    ctx_Catalogs = @("Catalog1","Catalog2")
    IsCitrixDaaS = $true
    CustomerID = "CUSID"
    Region = "US"
    SecureClientFile  = "c:\securelocation\secureclient.csv"
}

& "DistributePCRecoveryPoints.ps1" @params
```

```
& "DistributePCRecoveryPoints.ps1" -LogPath "C:\Logs\DistributePCRecoveryPoints.log" -LogRollover 5 -SourcePC "1.1.1.1" -BaseVM "W11-JK-GLD" -VMPrefix "ctx_" -TempVMName "TempAPIVM" -OutputType "PE-Snapshot" -ImageSnapsOrTemplatesToRetain 5 -UseCustomCredentialFile -CredPath "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials" -ctx_Catalogs @("Catalog1","Catalog2") -IsCitrixDaaS -CustomerID "CUSID" -Region "US" -SecureClientFile "c:\securelocation\secureclient.csv"

```

The above example will:
- Use PC `1.1.1.1` as the source PC. It will learn any additional PCs configured in an AZ pairing.
- Use the `W11-JK-GLD` VM as the source VM, and output snapshots with the `ctx_` prefix. The last `5 snapshots` matching this prefix will be retained, older snapshots will be `deleted`.
- Will prompt and store credentials in the specified `CredPath`. Second runs will use the stored credentials. If they need to be deleted or reset, delete the files in the `CredPath`.
- Will process the Citrix Catalogs `Catalog1` and `Catalog2` against Citrix DaaS. using the `SecureClientFile` provided.
- Will log to `C:\Logs\DistributePCRecoveryPoints.log`.

### Configuration provided using a master configuration JSON file

```
$params = @{
    ConfigPath = "c:\temp\master_config.json"
    SourcePC = "1.1.1.1"
}

& "DistributePCRecoveryPoints.ps1" @params
```

```
& "DistributePCRecoveryPoints.ps1" -SourcePC "1.1.1.1" -ConfigPath "c:\temp\master_config.json"
```

The above example will:

- Use PC `1.1.1.1` as the source PC.
- Use the configuration file at `c:\temp\master_config.json` to set all other parameters. See the example config base file provided in the Github Repo.
