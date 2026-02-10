# EUC Samples

A collection of End User Computing (EUC) code samples and automation solutions, specifically designed for Citrix Virtual Apps and Desktops (CVAD/DaaS) environments running on Nutanix infrastructure.

## Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Solutions](#solutions)
  - [Citrix Solutions](#citrix-solutions)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Support](#support)

## Overview

This repository provides enterprise-grade PowerShell automation samples for:

- **Category Management**: Automated synchronization between Nutanix Prism Central categories and Citrix tags
- **MCS Base Image Replication**: Solutions for replicating Citrix MCS base images using Nutanix protection mechanisms
- **Multi-Cluster Migration**: Tools for updating hosting details during cross-cluster migrations
- **Recovery Point Distribution**: Automated distribution of Prism Central Recovery Points across availability zones

All solutions are designed to integrate seamlessly with **Nutanix infrastructure** and leverage native Nutanix data protection and categorization capabilities.

## Repository Structure

```
euc-samples/
├── citrix/
│   ├── categories/
│   │   ├── manage_pc_vm_categories/
│   │   │   ├── UpdatePCVMCategories.ps1
│   │   │   └── ReadMe.md
│   │   └── sync_pc_categories_to_citrix_tags/
│   │       ├── MapPCVMCategoriestoCitrixTags.ps1
│   │       ├── ReadMe.md
│   │       └── playbook_edition/
│   │           ├── MapPCVMCategoriestoCitrixTagsPlaybookStyle.ps1
│   │           ├── ReadMe.md
│   │           └── execution scripts/
│   │               ├── ExecuteCitrixDaaStoPCSync.ps1
│   │               ├── ExecuteCitrixVADtoPCSync.ps1
│   │               ├── ExecutePCtoCitrixDaaSSync.ps1
│   │               ├── ExecutePCtoCitrixVADSync.ps1
│   │               └── ExecutePCtoCitrixVADSyncCleanOrphans.ps1
│   ├── mcs/
│   │   ├── replicate_citrix_base_image_pc/
│   │   │   └── recovery_point_replication/
│   │   │       ├── ReplicateCitrixBaseImageRP.ps1
│   │   │       └── READMe.md
│   │   ├── replicate_citrix_base_image_pd/
│   │   │   ├── ReplicateCitrixBaseImageVM.ps1
│   │   │   ├── ctx_catalogs.json
│   │   │   └── READMe.md
│   │   └── replicate_citrix_base_image_pd_api/
│   │       ├── ReplicateCitrixBaseImageVMAPI.ps1
│   │       ├── ctx_catalogs.json
│   │       └── README.md
│   └── multi_cluster_migration/
│       ├── citrix_cvad_reset_hostedmachineid/
│       │   ├── UpdateCVADHostedMachineId.ps1
│       │   └── README.md
│       └── citrix_daas_reset_hostedmachineid/
│           ├── UpdateDaaSHostedMachineId.ps1
│           └── README.md
└── DistributePCRecoveryPoints/
    ├── DistributePCRecoveryPoints.ps1
    ├── MasterConfig.json
    └── READMe.md
```

## Solutions

### Citrix Solutions

#### Category Management

##### 1. Manage Prism Central VM Categories

**Location**: `citrix/categories/manage_pc_vm_categories/`

**Purpose**: Automates the management and assignment of Nutanix Prism Central VM categories for Citrix workloads.

**Key Features**:
- Automated category assignment to VMs
- Bulk category management operations
- Integration with Prism Central API
- Support for custom category schemas

**Supported Platforms**:
- Nutanix Prism Central
- PowerShell 5.1+

**Documentation**: [View detailed README](citrix/categories/manage_pc_vm_categories/ReadMe.md)

---

##### 2. Sync Prism Central Categories to Citrix Tags

**Location**: `citrix/categories/sync_pc_categories_to_citrix_tags/`

**Purpose**: Provides bi-directional synchronization between Nutanix Prism Central VM categories and Citrix machine tags, enabling consistent tagging across both platforms.

**Key Features**:
- Bi-directional sync (PC to Citrix and Citrix to PC)
- Support for both CVAD and DaaS deployments
- Playbook-style execution with pre-configured scenarios
- Orphan cleanup capabilities
- Multiple execution scripts for different sync directions
- Scheduled synchronization support

**Supported Platforms**:
- Citrix CVAD (on-premises)
- Citrix DaaS (Cloud)
- Nutanix Prism Central
- PowerShell 5.1+

**Documentation**: 
- [Standard Edition README](citrix/categories/sync_pc_categories_to_citrix_tags/ReadMe.md)
- [Playbook Edition README](citrix/categories/sync_pc_categories_to_citrix_tags/playbook_edition/ReadMe.md)

---

#### MCS Base Image Replication

##### 3. Replicate Citrix Base Image (Prism Central Recovery Points)

**Location**: `citrix/mcs/replicate_citrix_base_image_pc/recovery_point_replication/`

**Purpose**: Automates replication of Citrix MCS base images using Nutanix Prism Central Recovery Points for disaster recovery scenarios.

**Key Features**:
- Recovery Point-based replication
- Integration with Prism Central protection policies
- Automated failover/failback support
- Cross-site base image availability

**Supported Platforms**:
- Citrix CVAD/DaaS with MCS
- Nutanix Prism Central
- PowerShell 5.1+

**Documentation**: [View detailed README](citrix/mcs/replicate_citrix_base_image_pc/recovery_point_replication/READMe.md)

---

##### 4. Replicate Citrix Base Image (Protection Domains)

**Location**: `citrix/mcs/replicate_citrix_base_image_pd/`

**Purpose**: Replicates Citrix MCS base images using Nutanix Protection Domains (Prism Element) for async disaster recovery.

**Key Features**:
- Protection Domain-based replication
- VM-level replication control
- JSON configuration support for multiple catalogs
- Scheduled replication workflows

**Supported Platforms**:
- Citrix CVAD/DaaS with MCS
- Nutanix Protection Domains (Prism Element)
- PowerShell 5.1+

**Documentation**: [View detailed README](citrix/mcs/replicate_citrix_base_image_pd/READMe.md)

---

##### 5. Replicate Citrix Base Image (Protection Domains API)

**Location**: `citrix/mcs/replicate_citrix_base_image_pd_api/`

**Purpose**: API-driven approach to replicating Citrix MCS base images using Nutanix Protection Domains.

**Key Features**:
- Direct Nutanix API integration
- Enhanced control and customization
- JSON-based catalog configuration
- Programmatic replication workflows

**Supported Platforms**:
- Citrix CVAD/DaaS with MCS
- Nutanix Protection Domains (Prism Element)
- PowerShell 5.1+

**Documentation**: [View detailed README](citrix/mcs/replicate_citrix_base_image_pd_api/README.md)

---

#### Multi-Cluster Migration

##### 6. Update CVAD Hosted Machine ID

**Location**: `citrix/multi_cluster_migration/citrix_cvad_reset_hostedmachineid/`

**Purpose**: Updates Citrix CVAD (on-premises) machine hosting details after cross-cluster migrations or failover events.

**Key Features**:
- Automated HostedMachineId updates
- Cross-cluster migration support
- Batch processing capabilities
- Validation and error handling

**Supported Platforms**:
- Citrix CVAD (on-premises)
- Nutanix AHV (Prism Element and Prism Central)
- PowerShell 5.1+

**Documentation**: [View detailed README](citrix/multi_cluster_migration/citrix_cvad_reset_hostedmachineid/README.md)

---

##### 7. Update DaaS Hosted Machine ID

**Location**: `citrix/multi_cluster_migration/citrix_daas_reset_hostedmachineid/`

**Purpose**: Updates Citrix DaaS (Cloud) machine hosting details after cross-cluster migrations or failover events.

**Key Features**:
- Cloud API integration
- Automated HostedMachineId updates
- Cross-cluster migration support
- Resource location management

**Supported Platforms**:
- Citrix DaaS (Cloud)
- Nutanix AHV (Prism Element and Prism Central)
- PowerShell 7.x+

**Documentation**: [View detailed README](citrix/multi_cluster_migration/citrix_daas_reset_hostedmachineid/README.md)

---

### Infrastructure Solutions

##### 8. Distribute Prism Central Recovery Points

**Location**: `DistributePCRecoveryPoints/`

**Purpose**: Automates the distribution and management of Nutanix Prism Central Recovery Points across multiple availability zones for comprehensive disaster recovery coverage.

**Key Features**:
- Multi-zone recovery point distribution
- JSON-based master configuration
- Automated scheduling support
- Cross-site recovery point management
- Integration with Prism Central protection policies

**Supported Platforms**:
- Nutanix Prism Central
- PowerShell 5.1+

**Documentation**: [View detailed README](DistributePCRecoveryPoints/READMe.md)

---

## Prerequisites

### Platform-Specific Requirements

Refer to individual solution README files for detailed prerequisites.

### General Requirements

- PowerShell 5.1 or higher (PowerShell 7.x+ recommended for DaaS solutions)
- Network connectivity to Nutanix Prism Central/Element
- Network connectivity to Citrix Cloud or Delivery Controllers
- Appropriate administrative credentials for both platforms

---

## Getting Started

### 1. Clone the Repository

```powershell
git clone <repository-url>
cd euc-samples
```

### 2. Choose Your Solution

Navigate to the appropriate solution directory based on your use case:

- **Category/Tag Synchronization**: `citrix/categories/sync_pc_categories_to_citrix_tags/`
- **MCS Base Image Replication (Recovery Points)**: `citrix/mcs/replicate_citrix_base_image_pc/recovery_point_replication/`
- **MCS Base Image Replication (Protection Domains)**: `citrix/mcs/replicate_citrix_base_image_pd/`
- **CVAD Cross-Cluster Migration**: `citrix/multi_cluster_migration/citrix_cvad_reset_hostedmachineid/`
- **DaaS Cross-Cluster Migration**: `citrix/multi_cluster_migration/citrix_daas_reset_hostedmachineid/`
- **Recovery Point Distribution**: `DistributePCRecoveryPoints/`

### 3. Review Documentation

Each solution has a detailed README with:
- Prerequisites
- Parameter descriptions
- Usage examples
- Configuration file formats
- Best practices

### 4. Configure Solution Parameters

Most solutions support configuration files (JSON) or command-line parameters. Review the solution-specific documentation for configuration details.

### 5. Test Before Production

Test thoroughly in non-production environments before production use. Many solutions include validation modes or dry-run capabilities.

### 6. Execute in Production

Once validated, execute the solution with appropriate parameters:

```powershell
.\ScriptName.ps1 <parameters>
```

---

## Best Practices

1. **Test Thoroughly**: Always test in non-production environments first
2. **Review Logs**: Monitor script output and logs for warnings and errors
3. **Backup Configurations**: Maintain backups of configuration files and current states
4. **Document Parameters**: Keep records of parameter values and configurations used
5. **Schedule Appropriately**: For replication and sync solutions, establish appropriate schedules
6. **Validate Connectivity**: Ensure network connectivity to all required endpoints
7. **Use Secure Credentials**: Leverage PowerShell secure strings and credential management
8. **Monitor Performance**: Track execution times and optimize batch sizes as needed

---

## Support

These scripts are provided as-is without warranty. Please see the `.disclaimer` file accompanying this repository.

- **Testing**: Test thoroughly in non-production environments before production use
- **Documentation**: Refer to individual solution README files for detailed information
- **Issues**: Review logs for detailed error messages and troubleshooting information
- **Nutanix Support**: For Nutanix-specific issues, consult [Nutanix Portal](https://portal.nutanix.com/)
- **Citrix Support**: For Citrix-specific issues, consult [Citrix Documentation](https://docs.citrix.com/)

---

## Legal

- [Nutanix Privacy Statement](https://www.nutanix.com/legal/privacy-statement "Nutanix Privacy Statement")
- [Terms of Use](https://www.nutanix.com/legal/terms-of-use "Terms of Use")

Please refer to the `LICENSE` and `NOTICE` files in this repository for additional legal information.

---

## Version Information

Individual solutions maintain their own version history. Refer to each solution's README for version details.

---

## Contributing

This repository contains code samples for enterprise EUC automation solutions. For contributions or feature requests, please contact the repository maintainers.

---

*Last Updated: February 2026*