## Objective

Automate the replication of Citrix base images using a `Protection Policy` based `Recovery Point` replication methodology with Prism Central. 

Citrix Machine Creation Services uses Nutanix Prism Element `Snapshots` for Catalog creation and updates when integrated with Prism Element.

The end state should be an identical `snapshot` available on the source, and all remote clusters ready for Citrix Machine Creation Services Provisioning.

Optionally, Citrix Catalogs should be updated with the created `snapshot`.

## Automation Requirements

- A single Prism Central instance configured with a `Protection Policy` protecting base image virtual machine (vm) with scheduled replications.
- A single Nutanix cluster holding the base image virtual machine (vm) should be the single update point for Citrix images.
- All clusters associated with a `Protection Policy` hosting the base image should ultimately have a `Snapshot` ready for Citrix Provisioning.

## Technical requirements for running the script

- The script is written 100% in PowerShell and uses the Nutanix APIs to action all Nutanix tasks. It has been tested on PowerShell 7 and PowerShell 5
- For Prism Central operations, the v3 API is used.
- For Prism Element operations, the v2 API is used.
- The script assumes a username and password for Prism Central. A dedicated service account should be created to action these tasks.
- The script assumes the same username and password for all PE instances. A dedicated service account should be created to action these tasks.
- The script assumes at a minimum, there is a `Protection Policy` protecting the base image virtual machine. `Recovery Point` replication should be configured to all appropriate clusters.
- The script requires the Citrix PowerShell snapins are available. These can simply be installed by installing Citrix Studio. Alternatively, you can follow [Citrix guidance](https://support.citrix.com/article/CTX222326/how-to-configure-powershell-sdk-and-execute-commands-remotely-in-xenappxendesktop-7x) to install the required snapins manually.
- The script assumes that the user running the script, has appropriate rights in each Citrix site if Citrix Catalogs are processed.
- The script has only been tested against a Prism Central Instance with a Single Availability zone.

## A note on Availability Zones

- The script will use the v3 API to identify Availability Zones. 
- It is assumed that credentials work for all PC's and all PE's under those PC's.
- If there are any issues with an associated Availability Zone or PC instance, the `ExcludedPrismCentrals` parameter can be used to exclude them. This is an array of IP addresses. Specify the IP of the Prism Centrals you want to exclude.
- If you want to override the list of Prism Centrals as learned by the default queries, you can use the `AdditionalPrismCentrals` parameter. This is an array of IP addresses of Prism Centrals. Do not include the `pc_source` IP in this list, it will be included by default.
- The script has relatively strict validation logic and will halt on most errors. This is designed for consistency, however, you can override this behavior with `IgnoreRecoveryPointDistributionValidation` being set. Be warned that by using this switch, you may end up with inconsistent results across clusters. The script is designed to give you consistency. Use this switch for troubleshooting only. Terminating errors are still Terminating errors.
- The script does not change the functional limits or considerations of Protection Policies. It just uses Protection Policies as the source of truth for Recovery Point Distribution.

## Parameter and Scenario Details

The following parameters exist to drive the behaviour of the script:

#### Mandatory and recommended parameters:
- `pc_source`: Mandatory **`String`**.
- `ProtectionPolicyName`: Mandatory **`String`**.
- `BaseVM`: Mandatory **`String`**. The name of the Citrix base image VM. This is CASE SENSITIVE.
- `ImageSnapsToRetain`: Optional **`Integer`**. The number of snapshots to retain on each target Cluster. This is limited only to snaps meeting the `BaseVM` and `VMPrefix` naming patterns (Snapshots the script created).

#### Optional Parameters

- `LogPath`: Optional **`String`**. Log path output for all operations. The default is `C:\Logs\MCSReplicateBaseImage.log`
- `LogRollover`: Optional **`Integer`**. Number of days before the log files are rolled over. The default is 5.
- `VMPrefix`: Optional **`String`**. The prefix used for both the restored VM (temp) and the associated Snapshot. The default is `ctx_`
- `RecoveryPoint`: Optional **`string`**. The name of the Recovery Point used for a custom restore. It not specified, the latest is used. This is an advanced parameter. This is typically the name in brackets when looking at PC.
- `SleepTime`: Optional **`Integer`**. The amount of time to sleep between task status polling in both v2 and v3 functions. Default is `2 seconds`.
- `UseCustomCredentialFile` Optional: **`Switch`**: Will call the `Get-CustomCredentials` function which keeps outputs and inputs a secure credential file base on `Stephane Bourdeaud` from Nutanix functions.
- `CredPath`: Optional **`String`**. Used if using the `UseCustomCredentialFile` parameter. Defines the location of the credential file. The default is `"$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials"`
- `ctx_Catalogs`: Optional **`Array`**. A list of Citrix Catalogs to update after the Snapshot replication has finished. User running the script must have sufficient rights on the Citrix Site. Single Citrix Site parameter only. For multi-site, use ctx_siteConfigJSON switch.
- `ctx_AdminAddress`: Optional **`String`**. The Delivery Controller to target for Citrix Catalog updates. Single Citrix Site parameter only. For multi-site, use `ctx_siteConfigJSON` switch.
- `ctx_SiteConfigJSON`: Optional **`String`**. A JSON file containing a list of Catalogs and associated Delivery Controllers for a multi-site environment. This will override the `ctx_AdminAddress` and `ctx_Catalogs` parameters.
- `ctx_ProcessCitrixEnvironmentOnly`: Optional **`Switch`**. Switch parameter to indicate that we are purely updating Citrix Catalogs and not interacting with Nutanix. Used in a scenario where maybe some remediation work as been undertaken and only Citrix needs updating. Advanced Parameter for specific used cases.
- `ctx_Snapshot`: Optional **`String`**. The name of the snapshot to be used with the `ctx_ProcessCitrixEnvironmentOnly` switch. This has no validation against Nutanix. Purely used to bring Citrix catalogs into line.
- `APICallVerboseLogging`: Optional **`Switch`**.
- `AdditionalPrismCentrals`: Optional **`Array`**. A manually defined array of Prism Centrals IP addresses. These should be aligned to availability zones. This should only be used when the default disocvery behaviors for Multi-AZ environments are problematic. This is an advanced param for troubleshooting or odd scenarios.
- `ExcludedPrismCentrals`: Optional **`Array`**. A manually defined array of Prism Centrals IP addresses to ignore from processing. This is an advanced param for troubleshooting or odd scenarios.
- `IgnoreRecoveryPointDistributionValidation`: Optional **`Switch`**. A troubleshooting switch to ignore scenarios where Recovery Points are not available for all target clusters. This is an advanced param for troubleshooting or odd scenarios.

The following examples use parameter splatting to make reading easier. A corresponding commandline example is also included:

## Scenarios

### General Basic Suggested Use

This scenario is the optimal and most generic use case for this script.

```
$params = @{
    pc_source                          = "1.1.1.1" # The source Prism Central Instance holding the base image vm
    ProtectionPolicyName               = "Citrix-Image-Replication" # The Protection Policy domain holding the base image vm
    BaseVM                             = "CTX-Gold-01" # The name of the Base image VM. Case sensitive.
    ImageSnapsToRetain                 = 10 # The number of snapshots to retain in each PE cluster.
    UseCustomCredentialFile            = $true # Will look for a custom credential file. If not found, will create
}
& ReplicateCitrixBaseImageRP.ps1 @params 
```

```
.\ReplicateCitrixBaseImageRP.ps1 -pc_source "1.1.1.1" -ProtectionPolicyName "Citrix-Image-Replication" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10 -UseCustomCredentialFile
```

The script will:

- Connect to the source `1.1.1.1` Prism Central Instance, and authenticate using a custom credential file. If that does not exist, it will be created and used next time. A credential file will also be created for Prism Element connections.
- Query Prism Central for Availability Zones, clusters, and virtual machines. Validates that the `CTX-Gold-01` virtual machine exists
- Looks for the `Citrix-Image-Replication` Protection Policy which should be hosting the associated `CTX-Gold-01` virtual machine
- Confirm that the `Citrix-Image-Replication` Protection Policy has the `CTX-Gold-01` virtual machine
- Queries the `Citrix-Image-Replication` Protection Policy for the number of included clusters. It does this by filtering the `ordered_availability_zone_list.cluster_uuid` data on the Protection Policy and does a count
- Queries the Protection Policy `Citrix-Image-Replication` for the latest Recovery Point based on timestamp. It then counts the number of Recovery Points matching this Recovery Point date. This should match the number of included clusters count from above.
- For each Recovery Point, the script attempts a validation to ensure the Recovery Point is ok for restore.
- Restores each identified Recovery Point. This will restore the Recovery Point into the appropriate cluster and capture the restored VMs `uuid` into an array.
- Loops through each Cluster under the Prism Central instance `1.1.1.1` and connects via API v2 and the provided Prism Element Credentials
- Locates the restored VM by comparing gathered vm entities against the restored vm array populated by the Recovery Point restoration
- Creates a snapshot with an identical name based on the default `VMPrefix` value of `ctx_` + `BaseVM` + `Date`. For example: `ctx_CTX-Gold-01_2023-05-15-16-55-41`.
- Delete all snapshots matching the above naming pattern older than `10` based on the `ImageSnapsToRetain` parameter
- Deletes the temporary virtual machine created by the Recovery Point.
- Log all output to the default `LogPath` directory of `C:\Logs\MCSReplicateBaseImageRP.log` and rollover logs after `5 days` based on the default `LogRollover` value.
 
### General Basic Suggested Use With Citrix Catalog updates across multiple Citrix Sites

This scenario builds upon the above, by allowing a multi Citrix Site update based on a JSON input:

```
$params = @{
    pc_source                          = "1.1.1.1" # The source Prism Central Instance holding the base image vm
    ProtectionPolicyName               = "Citrix-Image-Replication" # The Protection Policy domain holding the base image vm
    BaseVM                             = "CTX-Gold-01" # The name of the Base image VM. Case sensitive.
    ImageSnapsToRetain                 = 10 # The number of snapshots to retain in each PE cluster.
    UseCustomCredentialFile            = $true # Will look for a custom credential file. If not found, will create
    ctx_SiteConfigJSON                 = "C:\temp\ctx_catalogs.json" # JSON file specifying a Catalog to Controller list
}
& ReplicateCitrixBaseImageRP.ps1 @params 
```

```
.\ReplicateCitrixBaseImageRP.ps1 -pc_source "1.1.1.1" -ProtectionPolicyName "Citrix-Image-Replication" -BaseVM "CTX-Gold-01" -ImageSnapsToRetain 10 -UseCustomCredentialFile -ctx_SiteConfigJSON "C:\temp\ctx_catalogs.json"
```

Note that the JSON file must be structured as per below:

```
[
    {
        "Catalog": "Catalog1",
        "Controller": "Controller1"
    },
    {
        "Catalog": "Catalog2",
        "Controller": "Controller1"
    },
    {
        "Catalog": "Catalog3",
        "Controller": "Controller2"
    },
    {
        "Catalog": "Catalog4",
        "Controller": "Controller2"
    }
]
```

The script will:

- Validate the Citrix environment can be reached at each unique Delivery Controller in the JSON file via the `ctx_SiteConfigJSON` parameter. Then validate all Catalogs specified in the JSON file `ctx_SiteConfigJSON` exist and are of the MCS provisioning type.
- Connect to the source `1.1.1.1` Prism Central Instance, and authenticate using a custom credential file. If that does not exist, it will be created and used next time. A credential file will also be created for Prism Element connections.
- Query Prism Central for Availability Zones, clusters, and virtual machines. Validates that the `CTX-Gold-01` virtual machine exists
- Looks for the `Citrix-Image-Replication` Protection Policy which should be hosting the associated `CTX-Gold-01` virtual machine
- Confirm that the `Citrix-Image-Replication` Protection Policy has the `CTX-Gold-01` virtual machine
- Queries the `Citrix-Image-Replication` Protection Policy for the number of included clusters. It does this by filtering the `ordered_availability_zone_list.cluster_uuid` data on the Protection Policy and does a count
- Queries the Protection Policy `Citrix-Image-Replication` for the latest Recovery Point based on timestamp. It then counts the number of Recovery Points matching this Recovery Point date. This should match the number of included clusters count from above.
- For each Recovery Point, the script attempts a validation to ensure the Recovery Point is ok for restore.
- Restores each identified Recovery Point. This will restore the Recovery Point into the appropriate cluster and capture the restored VMs `uuid` into an array.
- Loops through each Cluster under the Prism Central instance `1.1.1.1` and connects via API v2 and the provided Prism Element Credentials
- Locates the restored VM by comparing gathered vm entities against the restored vm array populated by the Recovery Point restoration
- Creates a snapshot with an identical name based on the default `VMPrefix` value of `ctx_` + `BaseVM` + `Date`. For example: `ctx_CTX-Gold-01_2023-05-15-16-55-41`.
- Delete all snapshots matching the above naming pattern older than `10` based on the `ImageSnapsToRetain` parameter
- Deletes the temporary virtual machine created by the Recovery Point.
- Log all output to the default `LogPath` directory of `C:\Logs\MCSReplicateBaseImageRP.log` and rollover logs after `5 days` based on the default `LogRollover` value.
- If no replication failures have occurred in the Nutanix phase, update each Catalog listed in the `ctx_SiteConfigJSON` file.

### 

These scenarios handles some intricasies associated with Availability Zone configurations.

```
$params = @{
    pc_source                                 = "1.1.1.1" # The source Prism Central Instance holding the base image vm
    ProtectionPolicyName                      = "Citrix-Image-Replication" # The Protection Policy domain holding the base image vm
    BaseVM                                    = "CTX-Gold-01" # The name of the Base image VM. Case sensitive.
    ImageSnapsToRetain                        = 10 # The number of snapshots to retain in each PE cluster.
    UseCustomCredentialFile                   = $true # Will look for a custom credential file. If not found, will create
    AdditionalPrismCentrals                   = @("2.2.2.2") # will override source pc based discovery and add PC 2.2.2.2 to the mix resulting in 1.1.1.1 and 2.2.2.2 being processed
    IgnoreRecoveryPointDistributionValidation = $true # will allow non terminating continuation if the recovery points are not distributed evenly or validation fails
}
& ReplicateCitrixBaseImageRP.ps1 @params 
```
The script will
- Override the Prism Central discovered Availability Zone list with Prism Central 2.2.2.2. The source PC will still be processed.
- Ignore validation issues that are non terminating.

```
$params = @{
    pc_source                                 = "1.1.1.1" # The source Prism Central Instance holding the base image vm
    ProtectionPolicyName                      = "Citrix-Image-Replication" # The Protection Policy domain holding the base image vm
    BaseVM                                    = "CTX-Gold-01" # The name of the Base image VM. Case sensitive.
    ImageSnapsToRetain                        = 10 # The number of snapshots to retain in each PE cluster.
    UseCustomCredentialFile                   = $true # Will look for a custom credential file. If not found, will create
    ExcludedPrismCentrals                     = @("3.3.3.3") # will use source pc based discovery and exclude PC 3.3.3.3 from being processed
    IgnoreRecoveryPointDistributionValidation = $true # will allow non terminating continuation if the recovery points are not distributed evenly or validation fails
}
& ReplicateCitrixBaseImageRP.ps1 @params 
```

The script will
- Remove the Prism Central 3.3.3.3 from the discovered list of PCs.
- Ignore validation issues that are non terminating.