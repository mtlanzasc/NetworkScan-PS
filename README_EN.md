# Network Scan PS

> Local network scanner written in PowerShell with an interactive menu, device discovery, open ports, MAC address lookup, vendor detection, and Excel/CSV/JSON reports.

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Language](#language)
- [Parameters](#parameters)
- [Examples](#examples)
- [Reports](#reports)
- [Historical Comparison](#historical-comparison)
- [Performance Notes](#performance-notes)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)

## Description

`Network Scan PS` scans a local network and identifies active devices, host names, MAC addresses, vendors, device types, and open ports.

Main script:

```text
Network Scan PS.txt
```

The file currently uses a `.txt` extension, but its content is PowerShell. You may rename it to `.ps1` if you want to run it as a standard PowerShell script.

## Features

- Interactive menu in Spanish or English.
- Automatic scan based on the active network interface.
- Manual scan by `/24` base or CIDR.
- `Fast` mode for quick discovery.
- `Deep` mode for richer detection:
  - Open TCP ports.
  - PTR name.
  - NetBIOS name.
  - HTTP title.
  - TLS CN/name.
  - SSH banner.
  - MAC address.
  - Vendor.
- Vendor detection by OUI and by device signals.
- Report formats: `Excel`, `CSV`, `JSON`, or `All`.
- Historical comparison against a previous snapshot.
- Press `Q` during the scan to cancel.
- Robust JSON/CSV writes with retries when files are locked.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+.
- Windows is recommended for:
  - `Get-NetAdapter`
  - `Get-NetNeighbor`
  - `ping.exe`
  - `arp.exe`
  - `nbtstat.exe`
- Optional `ImportExcel` module for `.xlsx` output.

Optional `ImportExcel` installation:

```powershell
Install-Module ImportExcel -Scope CurrentUser
```

If `ImportExcel` is not available and you select `Excel`, the script generates CSV files as a fallback.

## Quick Start

Open PowerShell in the script folder:

```powershell
cd "C:\Users\mario.lanzas\OneDrive - Sera Scandia A S\Documentos\Desarrollos\SCAN"
```

Run the interactive menu:

```powershell
& ".\Network Scan PS.txt" -Menu
```

If script execution is blocked:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\Network Scan PS.txt" -Menu
```

## Language

Set the language with `-Language`:

```powershell
& ".\Network Scan PS.txt" -Language ES -Menu
& ".\Network Scan PS.txt" -Language EN -Menu
```

You can also change it from the menu:

```text
12. Idioma / Language
```

## Parameters

| Parameter | Value / Range | Description |
| --- | --- | --- |
| `-InterfaceName` | Text | Network interface to use. If omitted, it is auto-detected. |
| `-NetworkBase` | `192.168.1` or CIDR | Manual `/24` base or CIDR range. |
| `-CIDR` | CIDR | Explicit range, for example `192.168.1.0/24`. |
| `-TimeoutMs` | `200` to `5000` | Per-host timeout in milliseconds. |
| `-Throttle` | `10` to `512` | Maximum concurrent workers. |
| `-MaxHosts` | `1` to `65534` | Host limit to prevent accidental large scans. |
| `-PortsToScan` | TCP ports | TCP ports to test in `Mode Deep`. |
| `-Mode` | `Fast` or `Deep` | Scan depth. |
| `-Deep` | Switch | Forces `Mode Deep`. |
| `-Language` | `ES` or `EN` | Menu, messages, and report header language. |
| `-Output` | Base path | Base path for generated files. |
| `-OutputFormat` | `Excel`, `CSV`, `JSON`, `All` | Output format. |
| `-SnapshotPath` | JSON path | Historical snapshot path. |
| `-CompareWithPrevious` | Switch | Compares against a previous snapshot. |
| `-LiveView` | Boolean | Shows active devices while scanning. |
| `-MaxRuntimeSeconds` | `0` to `86400` | Maximum runtime. `0` means no limit. |
| `-Menu` | Switch | Opens the interactive menu. |

## Examples

### Interactive menu in English

```powershell
& ".\Network Scan PS.txt" -Language EN -Menu
```

### Fast scan of a network

```powershell
& ".\Network Scan PS.txt" `
  -CIDR "192.168.1.0/24" `
  -Mode Fast `
  -OutputFormat CSV
```

### Deep scan with custom ports

```powershell
& ".\Network Scan PS.txt" `
  -CIDR "192.168.1.0/24" `
  -Mode Deep `
  -PortsToScan 22,80,443,445,3389,8080,8443 `
  -OutputFormat All
```

### English report

```powershell
& ".\Network Scan PS.txt" `
  -CIDR "192.168.1.0/24" `
  -Mode Deep `
  -Language EN `
  -OutputFormat CSV `
  -Output ".\Reports\LAN_Scan"
```

### Limit scan runtime

```powershell
& ".\Network Scan PS.txt" `
  -CIDR "192.168.1.0/24" `
  -Mode Deep `
  -MaxRuntimeSeconds 60
```

## Reports

### English columns

```text
IP, DeviceName, Active, Type, NameSource, NameScore,
PTRName, NBNSName, TLSName, HTTPTitle, SSHBanner,
OpenPorts, MAC, OUI, Vendor, VendorOUI, VendorSource
```

### Generated files

For `Language EN`:

```text
Scan-LAN_yyyyMMdd_HHmm_All.csv
Scan-LAN_yyyyMMdd_HHmm_Active.csv
Scan-LAN_yyyyMMdd_HHmm.json
Scan-LAN_latest.json
```

If the scan is cancelled:

```text
Scan-LAN_yyyyMMdd_HHmm_Partial_All.csv
Scan-LAN_yyyyMMdd_HHmm_Partial_Active.csv
```

> Note: `OpenPorts` is populated only in `Mode Deep`.

## Historical Comparison

The script stores a snapshot at:

```text
.\Scan-LAN_latest.json
```

If a previous snapshot exists and `-CompareWithPrevious` is enabled, it generates:

```text
Scan-LAN_yyyyMMdd_HHmm_Diff.json
```

It detects:

- New devices.
- Down devices.
- Name changes.
- MAC changes.

## Performance Notes

- Use `Mode Fast` for a quick first pass.
- Use `Mode Deep` only when you need ports, MAC addresses, vendors, and banners.
- Reduce `-PortsToScan` to speed up deep scans.
- Lower `-Throttle` if the network or computer becomes saturated.
- Use `-MaxHosts` to avoid accidentally scanning very large ranges.

## Security Notes

- Run this script only on networks you own or are authorized to assess.
- `Mode Deep` opens TCP connections to the configured ports.
- No internet access is required; the OUI/vendor knowledge base is local.
- Relative output paths are resolved against the script folder to avoid accidental writes to `C:\Windows\System32`.

## Troubleshooting

### JSON file is locked

If another process has the snapshot open, the script retries. If the file is still locked, it creates a copy:

```text
Scan-LAN_latest_bloqueado_yyyyMMdd_HHmmssfff.json
```

### Open ports are empty

Make sure you are using `Mode Deep`:

```powershell
& ".\Network Scan PS.txt" -CIDR "192.168.1.0/24" -Mode Deep
```

### Excel is not generated

Install `ImportExcel` or use CSV:

```powershell
Install-Module ImportExcel -Scope CurrentUser
```

```powershell
& ".\Network Scan PS.txt" -OutputFormat CSV
```
