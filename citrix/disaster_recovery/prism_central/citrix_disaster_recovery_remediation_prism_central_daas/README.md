# Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.ps1

## Overview

This PowerShell script automates the remediation of Nutanix VMs in Citrix after a failover of some type has occured resulting in changes to VM IDs and/or Hosting.

It is not tied to any failover type, failover could have been executed by any form of Nutanix Protection, including Metro/SyncRep.

It compares VM ID and Hosting Connection details, and remediates persistent power-managed Citrix machines. It does not support MCS today.

The script supports two execution modes: **CLI mode** for automated/scripted execution with all parameters passed on the command line, and **Interactive mode** which launches a multi-step WPF wizard for guided configuration.

### Key Features

- **Interactive Wizard Mode**: Dark-themed WPF wizard for guided configuration across two steps (Configuration, Confirmation)
- **CLI Mode**: Full command-line parameter support for scripted/automated execution
- **Citrix Machine Updates**: Automatically updates Citrix machine hosting details (HostedMachineId, HypervisorConnection)
- **Zone Management**: Switches Citrix catalog zones to match target hosting connection
- **WhatIf Support**: Dry-run capability to validate changes before execution

## Prerequisites

- **PowerShell 7.x** or higher (script validates version at runtime)
- **Nutanix Prism Central** as the source of machines after a failover event
- **Citrix Cloud** (DaaS) subscription with:
  - Secure Client credentials (ID and Secret) or Secure Client CSV file (recommended)
  - Customer ID
  - Manual (non-MCS) machine catalogs
- **Nutanix AHV Prism Central Hosting Connection** in Citrix DaaS. This must be a Prism Central Connection.
- **Network Connectivity** to:
  - Target Prism Central API (port 9440)
  - Citrix Cloud API endpoints
- **Permissions**:
  - Prism Central: Admin or equivalent RBAC role with sufficient permissions
  - Citrix Cloud: Full Administrator or custom role with sufficient permissions (Machines, Catalogs, Hosting Connections)

## Execution Modes

### Interactive Mode

Interactive mode launches a WPF-based wizard with a Nutanix Prism Central dark theme. It guides the user through configuration in two steps, querying live data from Prism Central and Citrix DaaS to populate selectable options.

**Launch Interactive Mode:**

```powershell
.\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.ps1 `
    -TargetPC "1.1.1.1" `
    -PCUser "svc-dr-admin" `
    -PCPass "MySecurePassword123!" `
    -CustomerID "cust-id-here" `
    -SecureClientFile "C:\Secure\CitrixClient.csv" `
    -Interactive
```

**With WhatIf (dry-run):**

```powershell
.\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.ps1 `
    -TargetPC "1.1.1.1" `
    -PCUser "svc-dr-admin" `
    -PCPass "MySecurePassword123!" `
    -CustomerID "cust-id-here" `
    -SecureClientFile "C:\Secure\CitrixClient.csv" `
    -Interactive `
    -Whatif
```

#### Step 1: Configuration

The configuration window displays:

- **Prism Central Status** (side-by-side): Connection status, version, and managed cluster count
- **Citrix DaaS Status** (side-by-side): Connection status, site name, and version
- **Machine Catalogs**: Checkboxes populated from Citrix DaaS manual catalogs
- **Hosting Connection**: Dropdown populated from Citrix DaaS Nutanix hosting connections
- **Exclude Machines** (optional): A `Load Machines from Selected Catalogs` button fetches all machines from the currently-checked catalogs on demand and presents them as a multi-select checkbox list. Results are cached per catalog to avoid repeat API calls when catalog selections change.
- **Options**:
  - Reset Target Hosting Connection
  - Switch Catalog Zone ID

The WhatIf status is inherited from the command-line `-Whatif` parameter and displayed as a read-only indicator at the top of the window.

#### Step 2: Confirmation

A summary screen displays all selected options including:

- Execution mode (WhatIf/Live)
- Selected Catalogs and Hosting Connection
- Reset Hosting Connection, Switch Catalog Zone states
- Exclusion list preview and total count
- Estimated number of impacted machines (catalog machines minus exclusions)

The user must confirm before execution proceeds. Upon confirmation, the script executes with `SilentConsent` automatically enabled (the wizard confirmation replaces the CLI consent prompt).

### CLI Mode

CLI mode is the traditional command-line execution where all parameters are provided directly. This is suitable for automated/scripted execution, CI/CD pipelines, or when the interactive wizard is not needed.

All configuration parameters (`CatalogNames`, `HostingConnectionName`) are mandatory in CLI mode.

## Parameters

### Logging Parameters

| Parameter | Type | Mandatory | Default | Description |
|-----------|------|----------|---------|-------------|
| `LogPath` | String | No | `C:\Logs\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.log` | Path to the log file |
| `LogRollover` | Int | No | `5` | Number of days before log rollover occurs |

### Authentication Parameters (Required in Both Modes)

| Parameter | Type | Mandatory | Default | Description |
|-----------|------|----------|---------|-------------|
| `TargetPC` | String | **Yes** | - | Target Prism Central server IP or FQDN |
| `PCUser` | String | **Yes** | - | Prism Central username |
| `PCPass` | String | **Yes** | - | Prism Central password |
| `Region` | String | No | `US` | Citrix Cloud region (US, EU, AP-S, JP) |
| `CustomerID` | String | **Yes** | - | Citrix Cloud Customer ID |
| `ClientID` | String | No* | - | Citrix Cloud Secure Client ID |
| `ClientSecret` | String | No* | - | Citrix Cloud Secure Client Secret |
| `SecureClientFile` | String | No* | - | Path to CSV file with Client ID and Secret |

*Either `SecureClientFile` OR both `ClientID` and `ClientSecret` must be provided.

### CLI Mode Parameters (Mandatory in CLI mode, collected by wizard in Interactive mode)

| Parameter | Type | Mandatory | Default | Description |
|-----------|------|----------|---------|-------------|
| `CatalogNames` | Array | **Yes (CLI)** | - | Array of Citrix catalog names to process. Catalogs are the source of machines to remediate |
| `HostingConnectionName` | String | **Yes (CLI)** | - | Target hosting connection name (the hosting connection to the Target PC) |

### Optional Parameters (Available in Both Modes)

| Parameter | Type | Mandatory | Default | Description |
|-----------|------|----------|---------|-------------|
| `ExclusionList` | Array | No | - | Array of machine names to exclude from being actioned. In Interactive mode, this is collected by the wizard's multi-select panel after clicking `Load Machines from Selected Catalogs`. |
| `ResetTargetHostingConnection` | Switch | No | `$false` | Reset hosting connection after updates |
| `SwitchCatalogZoneID` | Switch | No | `$false` | Switch catalog zone to match hosting connection |

### General Options

| Parameter | Type | Mandatory | Default | Description |
|-----------|------|----------|---------|-------------|
| `Whatif` | Switch | No | `$false` | Dry-run mode without making changes (available in both modes; in Interactive mode it is surfaced as a read-only status) |
| `SilentConsent` | Switch | No | `$false` | Skip user consent prompt (CLI mode only; Interactive mode auto-sets this after the user confirms in the wizard) |
| `Interactive` | Switch | No | `$false` | Launch the WPF wizard (Interactive mode) |

## Usage Examples

### Interactive Mode - Basic Launch

```powershell
.\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.ps1 `
    -TargetPC "1.1.1.1" `
    -PCUser "svc-dr-admin" `
    -PCPass "MySecurePassword123!" `
    -CustomerID "cust-id-here" `
    -SecureClientFile "C:\Secure\CitrixClient.csv" `
    -Interactive
```

This will:

- Authenticate to Prism Central and Citrix DaaS using the provided credentials
- Launch the WPF wizard for guided configuration and confirmation
- All operational parameters (Catalogs, Hosting Connection, Exclusions, Reset HC, Switch Zone) are selected interactively

### Interactive Mode - WhatIf Dry Run

```powershell
.\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.ps1 `
    -TargetPC "1.1.1.1" `
    -PCUser "svc-dr-admin" `
    -PCPass "MySecurePassword123!" `
    -CustomerID "cust-id-here" `
    -SecureClientFile "C:\Secure\CitrixClient.csv" `
    -Interactive `
    -Whatif
```

This will:

- Launch the wizard in WhatIf mode (displayed as "WhatIf: Enabled (no changes will be made)" on the configuration screen)
- The confirmation screen will show "Execution Mode: WhatIf - No changes will be made"
- All operations will be logged without making actual changes

### CLI Mode - Remediation of Recovered Machines with Secure Client File using Whatif mode

**Command Line Format:**

```powershell
.\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.ps1 `
    -TargetPC "1.1.1.1" `
    -PCUser "svc-dr-admin" `
    -PCPass "MySecurePassword123!" `
    -Region "US" `
    -CustomerID "cust-id-here" `
    -SecureClientFile "C:\Secure\CitrixClient.csv" `
    -CatalogNames @("Persistent-Desktop-Catalog") `
    -HostingConnectionName "Nutanix-AHV-PrismCentral-DR" `
    -ResetTargetHostingConnection `
    -SwitchCatalogZoneID `
    -Whatif
```

**Parameter Splat Format:**

```powershell
$params = @{
    TargetPC                      = "1.1.1.1"
    PCUser                        = "svc-dr-admin"
    PCPass                        = "MySecurePassword123!"
    Region                        = "US"
    CustomerID                    = "cust-id-here"
    SecureClientFile              = "C:\Secure\CitrixClient.csv"
    CatalogNames                  = @("Persistent-Desktop-Catalog")
    HostingConnectionName         = "Nutanix-AHV-PrismCentral-DR"
    ResetTargetHostingConnection  = $true
    SwitchCatalogZoneID           = $true
    WhatIf                        = $true
}

.\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.ps1 @params
```

This example will:

- Operate in a planning mode only, no changes will occur
- Action all Nutanix jobs against the PC `1.1.1.1`
- Authenticate to Prism Central using the `svc-dr-admin` user and password `MySecurePassword123!`
- Authenticate to Citrix DaaS against the US region using the `C:\Secure\CitrixClient.csv` and specified `CustomerID`
- Validate the `Persistent-Desktop-Catalog` Catalog and use it as a source of machines
- Validate each machine `HostedMachineId` against the current Nutanix VM `UUID` and update if changed
- validate each machine Hosting Connection info is accurate and updates if needed
- Reset the `Nutanix-AHV-PrismCentral-DR` Hosting Connection to refresh power states, and switch the Catalog `Persistent-Desktop-Catalog` to the same Zone as the `Nutanix-AHV-PrismCentral-DR` Hosting Connection

### CLI Mode - Remediation of Recovered Machines with Secure Client File

**Command Line Format:**

```powershell
.\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.ps1 `
    -TargetPC "1.1.1.1" `
    -PCUser "svc-dr-admin" `
    -PCPass "MySecurePassword123!" `
    -Region "US" `
    -CustomerID "cust-id-here" `
    -SecureClientFile "C:\Secure\CitrixClient.csv" `
    -CatalogNames @("Persistent-Desktop-Catalog") `
    -HostingConnectionName "Nutanix-AHV-PrismCentral-DR" `
    -ResetTargetHostingConnection `
    -SwitchCatalogZoneID
```

**Parameter Splat Format:**

```powershell
$params = @{
    TargetPC                      = "1.1.1.1"
    PCUser                        = "svc-dr-admin"
    PCPass                        = "MySecurePassword123!"
    Region                        = "US"
    CustomerID                    = "cust-id-here"
    SecureClientFile              = "C:\Secure\CitrixClient.csv"
    CatalogNames                  = @("Persistent-Desktop-Catalog")
    HostingConnectionName         = "Nutanix-AHV-PrismCentral-DR"
    ResetTargetHostingConnection  = $true
    SwitchCatalogZoneID           = $true
}

.\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.ps1 @params
```

This example will:

- Action all Nutanix jobs against the PC `1.1.1.1`
- Authenticate to Prism Central using the `svc-dr-admin` user and password `MySecurePassword123!`
- Authenticate to Citrix DaaS against the US region using the `C:\Secure\CitrixClient.csv` and specified `CustomerID`
- Validate the `Persistent-Desktop-Catalog` Catalog and use it as a source of machines
- Validate each machine `HostedMachineId` against the current Nutanix VM `UUID` and update if changed
- validate each machine Hosting Connection info is accurate and updates if needed
- Reset the `Nutanix-AHV-PrismCentral-DR` Hosting Connection to refresh power states, and switch the Catalog `Persistent-Desktop-Catalog` to the same Zone as the `Nutanix-AHV-PrismCentral-DR` Hosting Connection

### CLI Mode - Remediation of Recovered Machines with Secure Client File filtering out machines using an Exclusion List

**Command Line Format:**

```powershell
.\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.ps1 `
    -TargetPC "1.1.1.1" `
    -PCUser "svc-dr-admin" `
    -PCPass "MySecurePassword123!" `
    -Region "US" `
    -CustomerID "cust-id-here" `
    -SecureClientFile "C:\Secure\CitrixClient.csv" `
    -CatalogNames @("Persistent-Desktop-Catalog") `
    -ExclusionList @("VM1","VM5") `
    -HostingConnectionName "Nutanix-AHV-PrismCentral-DR" `
    -ResetTargetHostingConnection `
    -SwitchCatalogZoneID
```

**Parameter Splat Format:**

```powershell
$params = @{
    TargetPC                      = "1.1.1.1"
    PCUser                        = "svc-dr-admin"
    PCPass                        = "MySecurePassword123!"
    Region                        = "US"
    CustomerID                    = "cust-id-here"
    SecureClientFile              = "C:\Secure\CitrixClient.csv"
    CatalogNames                  = @("Persistent-Desktop-Catalog")
    ExclusionList                 = @("VM1","VM5")
    HostingConnectionName         = "Nutanix-AHV-PrismCentral-DR"
    ResetTargetHostingConnection  = $true
    SwitchCatalogZoneID           = $true
}

.\Invoke-PrismCentral-CitrixDaaS-PersistentDesktopRemediation.ps1 @params
```

This example will:

- Action all Nutanix jobs against the PC `1.1.1.1`
- Authenticate to Prism Central using the `svc-dr-admin` user and password `MySecurePassword123!`
- Authenticate to Citrix DaaS against the US region using the `C:\Secure\CitrixClient.csv` and specified `CustomerID`
- Validate the `Persistent-Desktop-Catalog` Catalog and use it as a source of machines
- Filter out `VM1` and `VM5` from the targed machines
- Validate each machine `HostedMachineId` against the current Nutanix VM `UUID` and update if changed
- validate each machine Hosting Connection info is accurate and updates if needed
- Reset the `Nutanix-AHV-PrismCentral-DR` Hosting Connection to refresh power states, and switch the Catalog `Persistent-Desktop-Catalog` to the same Zone as the `Nutanix-AHV-PrismCentral-DR` Hosting Connection

## Workflow

### High-Level Process Flow (CLI Mode)

1. **Validation Phase**
   - Validate PowerShell version (7.x required)
   - Authenticate to Prism Central
   - Validate Prism Central connectivity
   - Authenticate to Citrix Cloud
   - Validate Citrix Site connectivity
   - Validate Catalog names
   - Validate Hosting Connection

2. **Execution Phase**
   - Query VM list from Prism Central
   - Update Citrix machine hosting details
   - Switch Catalog Zone IDs (if specified)
   - Reset Hosting Connection (if specified and machines updated)

3. **Completion**
   - Log execution summary
   - Report timing statistics

### Interactive Mode Flow

When launched with `-Interactive`, the workflow is modified:

1. **WPF Wizard Phase** (replaces parameter input for operational values)
   - PowerShell 7 guard check
   - Load WPF assemblies (PresentationFramework, PresentationCore, WindowsBase)
   - Authenticate to Prism Central and Citrix DaaS using command-line credentials
   - Query Prism Central for clusters and version
   - Query Citrix DaaS for site details, manual catalogs, and Nutanix hosting connections
   - **Window 1**: Configuration - user selects catalogs, hosting connection, exclusions (lazy-loaded from selected catalogs), and options from live data
   - Calculate impacted machine count from selected catalogs minus exclusions
   - **Window 2**: Confirmation - user reviews full summary and confirms execution

2. **Standard Execution** (same as CLI mode from this point)
   - `SilentConsent` is automatically set by the wizard so the downstream CLI consent prompt is skipped
   - Validation and Execution phases proceed identically

## Important Notes

### Security Considerations

- **Secure Client File**: You must ensure that the SecureClient has appropriate permissions in Citrix DaaS - you should always secure this file.
- **Authentication Parameters**: In interactive mode, authentication credentials (`TargetPC`, `PCUser`, `PCPass`, `CustomerID`, `ClientID`/`ClientSecret`/`SecureClientFile`) are still passed via the command line. The wizard only collects operational parameters.

### Best Practices

1. **Always Test First**: Use `-Whatif` parameter before production execution (both CLI and Interactive modes)
2. **Interactive Mode for Unfamiliar Environments**: Use `-Interactive` when working with environments where you need to discover available catalogs and hosting connections, or where you want to visually pick machines to exclude
3. **CLI Mode for Automation**: Use CLI mode with `-SilentConsent` for scripted/scheduled execution
4. **Manual Catalogs Only**: This script only supports Manual (non-MCS) catalogs
5. **Monitor Logs**: Review logs for warnings and errors
6. **Staged Approach**: Consider migrating catalogs in batches rather than all at once

### Limitations and Considerations

- Only supports **Manual (non-MCS)** machine catalogs
- Only supports **Citrix DaaS** (Cloud), not CVAD on-premises (currently)
- Interactive mode requires a Windows desktop environment with WPF support (PowerShell 7 on Windows)

### Error Handling

- Script validates all prerequisites before execution
- Failed operations are logged with detailed error messages
- In interactive mode, validation errors are displayed via themed WPF message dialogs

## Output and Logging

All operations are logged to the specified log file with timestamps and severity levels:

- **INFO**: Normal operational messages
- **WARN**: Warnings that don't stop execution
- **ERROR**: Critical errors that halt execution
- **WHATIF**: Messages indicating actions that would be taken in WhatIf mode

**Example Log Output:**

```
2026-01-14 17:28:29 INFO: --------Starting Iteration--------
2026-01-14 17:28:29 INFO: Starting Timer
2026-01-14 17:28:29 INFO: Querying for Clusters under the Prism Central Instance 10.57.64.138
2026-01-14 17:28:29 INFO: [Prism Central Validation] Found 1 clusters managed by this Prism Central Instance
2026-01-14 17:28:29 INFO: [Prism Central Validation] PC version is: 7.3
2026-01-14 17:28:29 INFO: [Citrix Cloud] Importing Secure Client: C:\Temp\SecureClient.csv
2026-01-14 17:28:29 INFO: [Citrix Validation] Validating Citrix Site is contactable at Delivery Controller: api-us.cloud.com
2026-01-14 17:28:30 INFO: Getting Citrix Site Info                                                                      
2026-01-14 17:28:31 INFO: Successfully Returned Citrix Site Detail. Site version is 7.38                                
2026-01-14 17:28:31 INFO: [Citrix Validation] Successfully Validated Citrix Site: cloudxdsite is contactable at Delivery Controller: api-us.cloud.com
2026-01-14 17:28:33 INFO: [Citrix Validation] Found 7 supported Manual Citrix Catalogs                                  
2026-01-14 17:28:33 INFO: [Citrix Validation] Found 1 supported Citrix Catalogs defined by parameter
2026-01-14 17:28:34 INFO: [Citrix Validation] Hypervisor Plugin type is: AcropolisHypervisorPCFactory and is supported  
2026-01-14 17:28:34 INFO: [Citrix Validation] Successfully Validated Citrix Hosting Connection: Nutanix-AHV-PrismCentral-138
2026-01-14 17:28:35 INFO: [Prism Central] Getting a list of VMs from the target PC: 10.57.64.138                        
2026-01-14 17:28:35 INFO: [Prism Central] Querying for Virtual Machines under the Prism Central Instance 10.57.64.138
2026-01-14 17:28:35 INFO: [Prism Central] Found 2 VMs in the target Citrix environment under the target PC: 10.57.64.138
2026-01-14 17:28:35 INFO: [Citrix] Updating Machine: KIN-DR-SR-01 in Citrix
2026-01-14 17:28:35 INFO: [Citrix] Updating Machine: KIN-DR-SR-01 with new Hypervisor Connection: Nutanix-AHV-PrismCentral-138
2026-01-14 17:28:35 INFO: [Citrix] Updating Machine: KIN-DR-SR-02 in Citrix
2026-01-14 17:28:35 INFO: [Citrix] Updating Machine: KIN-DR-SR-02 with new Hypervisor Connection: Nutanix-AHV-PrismCentral-138                                                           
2026-01-14 17:28:58 INFO: [Citrix] Resetting Citrix Hosting Connection: Nutanix-AHV-PrismCentral-138
2026-01-14 17:28:59 INFO: [Citrix] Waiting for 30 seconds after first reset of Hosting Connection: Nutanix-AHV-PrismCentral-138
2026-01-14 17:29:30 INFO: Stopping Timer                                                                                
2026-01-14 17:29:30 INFO: Script processing took 1 minutes and 0 seconds to complete.
```

## Version History

- **v1.0**: Initial release to address immediate demand for recovery operations post-failover.
- **v1.1**: Added Interactive Mode with a two-step WPF wizard (Configuration, Confirmation). Adds `-Interactive` switch and `Get-CVADAllHostingConnectionsAPI` helper. CLI behaviour is unchanged and remains the default parameter set.

## License

This script is provided as-is without warranty. Test thoroughly in non-production environments before production use.

