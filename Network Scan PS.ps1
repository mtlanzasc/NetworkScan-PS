#requires -Version 5.1
[CmdletBinding()]
# Parametros principales del escaneo, salida y modo interactivo.
param(
    [string]$InterfaceName = "",
    [string]$NetworkBase = "",
    [string]$CIDR = "",
    [ValidateRange(200,5000)][int]$TimeoutMs = 1000,
    [ValidateRange(10,512)][int]$Throttle = 120,
    [ValidateRange(1,65534)][int]$MaxHosts = 65534,
    [ValidateRange(1,65535)][int[]]$PortsToScan = @(22,80,443,445,3389,8080),
    [ValidateSet('Fast','Deep')][string]$Mode = 'Deep',
    [switch]$Deep,
    [ValidateSet('ES','EN')][string]$Language = 'ES',
    [string]$Output = ".\\Scan-LAN_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmm'),
    [ValidateSet('Excel','CSV','JSON','All')][string]$OutputFormat = 'Excel',
    [string]$SnapshotPath = ".\\Scan-LAN_latest.json",
    [switch]$CompareWithPrevious = $true,
    [bool]$LiveView = $true,
    [ValidateRange(0,86400)][int]$MaxRuntimeSeconds = 0,
    [switch]$Menu
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Funciones base de validacion, conversion de IP y manejo de menus.

# Valida que una cadena tenga formato IPv4 valido (0-255 por octeto).
function Test-IPv4 {
    param([string]$Address)
    return ($Address -match '^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$')
}

# Convierte una IPv4 en entero UInt32 para facilitar ordenamientos y calculos de red.
function Convert-IPv4ToUInt32 {
    param([string]$IpAddress)
    $bytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
    [array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

# Convierte un entero UInt32 de vuelta a notacion IPv4.
function Convert-UInt32ToIPv4 {
    param([uint32]$Value)
    $bytes = [BitConverter]::GetBytes($Value)
    [array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

# Expande un CIDR (ej. 10.0.5.0/24) a la lista de hosts utilizables (sin red ni broadcast).
function Get-CIDRHosts {
    param(
        [string]$InputCIDR,
        [int]$MaxHosts = 65534
    )

    if ($InputCIDR -notmatch '^(.+)/(\d{1,2})$') { throw "CIDR inválido: $InputCIDR" }
    $ipString = $Matches[1]
    $prefix = [int]$Matches[2]
    if (-not (Test-IPv4 -Address $ipString)) { throw "IPv4 inválida en CIDR: $ipString" }
    if ($prefix -lt 1 -or $prefix -gt 30) { throw "Prefijo CIDR fuera de rango soportado (1..30): /$prefix" }

    $ipInt = Convert-IPv4ToUInt32 -IpAddress $ipString
    [uint32]$mask = 0
    for ($i = 0; $i -lt $prefix; $i++) { $mask = $mask -bor ([uint32]1 -shl (31 - $i)) }

    $network = $ipInt -band $mask
    $hostCount = [uint32][math]::Pow(2, (32 - $prefix))
    $broadcast = $network + $hostCount - 1
    $usableHosts = [int]($hostCount - 2)
    if ($usableHosts -gt $MaxHosts) {
        throw "El rango $InputCIDR contiene $usableHosts hosts utilizables y excede el limite MaxHosts=$MaxHosts. Usa un rango mas pequeno o aumenta -MaxHosts."
    }

    $hosts = New-Object System.Collections.Generic.List[string]
    for ($addr = $network + 1; $addr -lt $broadcast; $addr++) {
        [void]$hosts.Add((Convert-UInt32ToIPv4 -Value ([uint32]$addr)))
    }
    return $hosts
}

# Obtiene adaptadores fisicos activos, con fallback para entornos sin cmdlets de red completos.
function Get-PhysicalAdapters {
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true })
        if ($adapters.Count -eq 0) {
            $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Status -eq 'Up' -and
                    ($_.InterfaceDescription -notmatch 'Hyper-V|Virtual|VMware|VirtualBox|vEthernet|Loopback|Container|Pseudo|TAP|Npcap|Bluetooth|Wi-Fi Direct|RAS|Miniport')
                })
        }
    } catch {
        $nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' }
        $adapters = foreach ($n in $nics) {
            [PSCustomObject]@{ Name=$n.Name; InterfaceDescription=$n.Description; Status=$n.OperationalStatus; HardwareInterface=$true }
        }
    }
    return $adapters
}

# Resuelve la IPv4 de una interfaz concreta, evitando APIPA y loopback.
function Get-IPv4ForInterface {
    param([string]$AdapterName)
    try {
        $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $AdapterName -ErrorAction Stop |
            Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
            Select-Object -First 1
        if ($ip) { return $ip.IPAddress }
    } catch {
        $nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            Where-Object { $_.Name -eq $AdapterName -or $_.Description -eq $AdapterName }
        foreach ($n in $nics) {
            $props = $n.GetIPProperties().UnicastAddresses |
                Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' -and $_.Address.ToString() -notlike '169.254.*' }
            if ($props) { return $props[0].Address.ToString() }
        }
    }
    return $null
}

# Lee una opcion numerica de menu y valida que exista.
function Read-MenuChoice {
    param(
        [string]$Title,
        [array]$Options,
        [int]$DefaultIndex = 1,
        [ValidateSet('ES','EN')][string]$Language = 'ES'
    )

    while ($true) {
        Write-Host ""
        Write-Host $Title
        for ($i = 0; $i -lt $Options.Count; $i++) {
            $markerText = if ($Language -eq 'EN') { "recommended" } else { "recomendado" }
            $marker = if (($i + 1) -eq $DefaultIndex) { " ($markerText)" } else { "" }
            Write-Host ("  {0}. {1}{2}" -f ($i + 1), $Options[$i], $marker)
        }

        $prompt = if ($Language -eq 'EN') { "Choose an option [{0}]" } else { "Elige una opcion [{0}]" }
        $answer = Read-Host ($prompt -f $DefaultIndex)
        if ([string]::IsNullOrWhiteSpace($answer)) { return $DefaultIndex }
        if ($answer -match '^\d+$') {
            $selected = [int]$answer
            if ($selected -ge 1 -and $selected -le $Options.Count) { return $selected }
        }
        $invalidText = if ($Language -eq 'EN') { "Invalid option. Try again." } else { "Opcion invalida. Intenta nuevamente." }
        Write-Host $invalidText -ForegroundColor Yellow
    }
}

# Lee texto permitiendo conservar un valor recomendado/predeterminado.
function Read-MenuText {
    param(
        [string]$Prompt,
        [string]$DefaultValue = ""
    )

    $suffix = if ($DefaultValue) { " [$DefaultValue]" } else { "" }
    $answer = Read-Host "$Prompt$suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $DefaultValue }
    return $answer.Trim()
}

# Lee enteros del menu y aplica limites seguros.
function Read-MenuInt {
    param(
        [string]$Prompt,
        [int]$DefaultValue,
        [int]$Min,
        [int]$Max,
        [ValidateSet('ES','EN')][string]$Language = 'ES'
    )

    while ($true) {
        $answer = Read-Host "$Prompt [$DefaultValue]"
        if ([string]::IsNullOrWhiteSpace($answer)) { return $DefaultValue }
        if ($answer -match '^\d+$') {
            $value = [int]$answer
            if ($value -ge $Min -and $value -le $Max) { return $value }
        }
        $invalidText = if ($Language -eq 'EN') { "Invalid value. Use a number between $Min and $Max." } else { "Valor invalido. Usa un numero entre $Min y $Max." }
        Write-Host $invalidText -ForegroundColor Yellow
    }
}

# Muestra una pantalla inicial con valores actuales y permite editar solo lo necesario.
function Show-InteractiveMenu {
    param(
        [string]$CurrentInterfaceName,
        [string]$CurrentNetworkBase,
        [string]$CurrentCIDR,
        [int]$CurrentTimeoutMs,
        [int]$CurrentThrottle,
        [string]$CurrentMode,
        [string]$CurrentOutputFormat,
        [string]$CurrentOutput,
        [string]$CurrentSnapshotPath,
        [bool]$CurrentCompareWithPrevious,
        [bool]$CurrentLiveView,
        [int]$CurrentMaxRuntimeSeconds,
        [ValidateSet('ES','EN')][string]$CurrentLanguage = 'ES'
    )

    $selection = [PSCustomObject]@{
        InterfaceName = $CurrentInterfaceName
        NetworkBase = $CurrentNetworkBase
        CIDR = $CurrentCIDR
        TimeoutMs = $CurrentTimeoutMs
        Throttle = $CurrentThrottle
        Mode = $CurrentMode
        OutputFormat = $CurrentOutputFormat
        Output = $CurrentOutput
        SnapshotPath = $CurrentSnapshotPath
        CompareWithPrevious = $CurrentCompareWithPrevious
        LiveView = $CurrentLiveView
        MaxRuntimeSeconds = $CurrentMaxRuntimeSeconds
        Language = $CurrentLanguage
    }

    while ($true) {
        $isEnglish = ($selection.Language -eq 'EN')
        $rangeText = if ($selection.CIDR) { "CIDR: $($selection.CIDR)" } elseif ($selection.NetworkBase) { "Base /24: $($selection.NetworkBase)" } elseif ($isEnglish) { "Automatic /24 from interface" } else { "Automatico /24 desde interfaz" }
        $interfaceText = if ($selection.InterfaceName) { $selection.InterfaceName } elseif ($isEnglish) { "Auto detect" } else { "Detectar automaticamente" }
        $maxRuntimeText = if ($selection.MaxRuntimeSeconds -gt 0) { "$($selection.MaxRuntimeSeconds) s" } elseif ($isEnglish) { "No limit" } else { "Sin limite" }
        $languageText = if ($selection.Language -eq 'EN') { "English" } else { "Espanol" }

        Clear-Host
        Write-Host "=== Network Scan PS ===" -ForegroundColor Cyan
        Write-Host $(if ($isEnglish) { "Current values. Choose what to change or start the scan." } else { "Valores actuales. Elige que deseas cambiar o inicia el escaneo." }) -ForegroundColor DarkGray
        Write-Host ""
        Write-Host ("  1. {0,-23}: {1}" -f $(if ($isEnglish) { "Interface" } else { "Interfaz" }), $interfaceText)
        Write-Host ("  2. {0,-23}: {1}" -f $(if ($isEnglish) { "Network range" } else { "Rango de red" }), $rangeText)
        Write-Host "  3. Timeout                : $($selection.TimeoutMs) ms"
        Write-Host ("  4. {0,-23}: {1}" -f $(if ($isEnglish) { "Concurrency" } else { "Concurrencia" }), $selection.Throttle)
        Write-Host ("  5. {0,-23}: {1}" -f $(if ($isEnglish) { "Mode" } else { "Modo" }), $selection.Mode)
        Write-Host ("  6. {0,-23}: {1}" -f $(if ($isEnglish) { "Output format" } else { "Formato de salida" }), $selection.OutputFormat)
        Write-Host ("  7. {0,-23}: {1}" -f $(if ($isEnglish) { "Live view" } else { "Vista en vivo" }), $selection.LiveView)
        Write-Host ("  8. {0,-23}: {1}" -f $(if ($isEnglish) { "Max runtime" } else { "Tiempo maximo" }), $maxRuntimeText)
        Write-Host ("  9. {0,-23}: {1}" -f $(if ($isEnglish) { "Historical compare" } else { "Comparacion historica" }), $selection.CompareWithPrevious)
        Write-Host (" 10. {0,-23}: {1}" -f $(if ($isEnglish) { "Output path" } else { "Ruta de salida" }), $selection.Output)
        Write-Host (" 11. {0,-23}: {1}" -f $(if ($isEnglish) { "Snapshot path" } else { "Snapshot historico" }), $selection.SnapshotPath)
        Write-Host (" 12. {0,-23}: {1}" -f $(if ($isEnglish) { "Language" } else { "Idioma" }), $languageText)
        Write-Host ""
        Write-Host $(if ($isEnglish) { "  I. Start scan" } else { "  I. Iniciar escaneo" }) -ForegroundColor Green
        Write-Host $(if ($isEnglish) { "  S. Exit" } else { "  S. Salir" }) -ForegroundColor Yellow
        Write-Host ""

        $choice = (Read-Host $(if ($isEnglish) { "Selection" } else { "Seleccion" })).Trim().ToUpperInvariant()
        switch ($choice) {
            "1" {
                $adapters = @(Get-PhysicalAdapters)
                $interfaceOptions = New-Object System.Collections.Generic.List[string]
                [void]$interfaceOptions.Add($(if ($isEnglish) { "Auto detect" } else { "Detectar automaticamente" }))
                foreach ($adapter in $adapters) { [void]$interfaceOptions.Add(("{0} - {1}" -f $adapter.Name, $adapter.InterfaceDescription)) }
                $selected = Read-MenuChoice -Title $(if ($isEnglish) { "Network interface" } else { "Interfaz de red" }) -Options $interfaceOptions -DefaultIndex 1 -Language $selection.Language
                $selection.InterfaceName = if ($selected -gt 1) { $adapters[$selected - 2].Name } else { "" }
            }
            "2" {
                $rangeOptions = if ($isEnglish) {
                    @("Automatic /24 from selected interface", "Manual /24 base (ex. 192.168.1)", "Manual CIDR (ex. 192.168.1.0/24)")
                } else {
                    @("Automatico /24 desde la interfaz seleccionada", "Base /24 manual (ej. 192.168.1)", "CIDR manual (ej. 192.168.1.0/24)")
                }
                $rangeChoice = Read-MenuChoice -Title $(if ($isEnglish) { "Network range" } else { "Rango de red" }) -Options $rangeOptions -DefaultIndex 1 -Language $selection.Language
                if ($rangeChoice -eq 1) {
                    $selection.NetworkBase = ""
                    $selection.CIDR = ""
                } elseif ($rangeChoice -eq 2) {
                    $selection.NetworkBase = Read-MenuText -Prompt $(if ($isEnglish) { "Base /24" } else { "Base /24" }) -DefaultValue $(if ($selection.NetworkBase) { $selection.NetworkBase } else { "192.168.1" })
                    $selection.CIDR = ""
                } else {
                    $selection.CIDR = Read-MenuText -Prompt "CIDR" -DefaultValue $(if ($selection.CIDR) { $selection.CIDR } else { "192.168.1.0/24" })
                    $selection.NetworkBase = ""
                }
            }
            "3" {
                $timeoutOptions = if ($isEnglish) {
                    @("1000 ms - recommended", "600 ms - faster for stable LAN", "2000 ms - better for slow links", "Custom value")
                } else {
                    @("1000 ms - recomendado", "600 ms - rapido para LAN estable", "2000 ms - mejor para enlaces lentos", "Valor personalizado")
                }
                $timeoutChoice = Read-MenuChoice -Title $(if ($isEnglish) { "Timeout per host" } else { "Timeout por host" }) -Options $timeoutOptions -DefaultIndex 1 -Language $selection.Language
                $selection.TimeoutMs = switch ($timeoutChoice) {
                    1 { 1000 }
                    2 { 600 }
                    3 { 2000 }
                    default { Read-MenuInt -Prompt $(if ($isEnglish) { "Timeout in ms" } else { "Timeout en ms" }) -DefaultValue $selection.TimeoutMs -Min 200 -Max 5000 -Language $selection.Language }
                }
            }
            "4" {
                $throttleOptions = if ($isEnglish) {
                    @("120 - recommended", "80 - conservative", "150 - faster", "Custom value")
                } else {
                    @("120 - recomendado", "80 - conservador", "150 - mas rapido", "Valor personalizado")
                }
                $throttleChoice = Read-MenuChoice -Title $(if ($isEnglish) { "Concurrency" } else { "Concurrencia" }) -Options $throttleOptions -DefaultIndex 1 -Language $selection.Language
                $selection.Throttle = switch ($throttleChoice) {
                    1 { 120 }
                    2 { 80 }
                    3 { 150 }
                    default { Read-MenuInt -Prompt $(if ($isEnglish) { "Concurrency" } else { "Concurrencia" }) -DefaultValue $selection.Throttle -Min 10 -Max 512 -Language $selection.Language }
                }
            }
            "5" {
                $modeOptions = if ($isEnglish) { @("Deep - more data", "Fast - faster") } else { @("Deep - mas datos", "Fast - mas rapido") }
                $selection.Mode = if ((Read-MenuChoice -Title $(if ($isEnglish) { "Scan mode" } else { "Modo de escaneo" }) -Options $modeOptions -DefaultIndex 1 -Language $selection.Language) -eq 1) { "Deep" } else { "Fast" }
            }
            "6" {
                $formatMap = @('Excel','CSV','JSON','All')
                $selected = Read-MenuChoice -Title $(if ($isEnglish) { "Output format" } else { "Formato de salida" }) -Options @("Excel", "CSV", "JSON", "All") -DefaultIndex 1 -Language $selection.Language
                $selection.OutputFormat = $formatMap[$selected - 1]
            }
            "7" { $selection.LiveView = -not $selection.LiveView }
            "8" { $selection.MaxRuntimeSeconds = Read-MenuInt -Prompt $(if ($isEnglish) { "Max runtime in seconds (0 = no limit)" } else { "Tiempo maximo en segundos (0 = sin limite)" }) -DefaultValue $selection.MaxRuntimeSeconds -Min 0 -Max 86400 -Language $selection.Language }
            "9" { $selection.CompareWithPrevious = -not $selection.CompareWithPrevious }
            "10" { $selection.Output = Read-MenuText -Prompt $(if ($isEnglish) { "Output base path" } else { "Ruta base de salida" }) -DefaultValue $selection.Output }
            "11" { $selection.SnapshotPath = Read-MenuText -Prompt $(if ($isEnglish) { "Snapshot path" } else { "Snapshot historico" }) -DefaultValue $selection.SnapshotPath }
            "12" {
                $languageOptions = @("Espanol", "English")
                $selected = Read-MenuChoice -Title $(if ($isEnglish) { "Language" } else { "Idioma" }) -Options $languageOptions -DefaultIndex $(if ($selection.Language -eq 'EN') { 2 } else { 1 }) -Language $selection.Language
                $selection.Language = if ($selected -eq 2) { "EN" } else { "ES" }
            }
            "I" { return $selection }
            "S" { throw $(if ($isEnglish) { "Operation cancelled from menu." } else { "Operacion cancelada desde el menu." }) }
            default {
                Write-Host $(if ($isEnglish) { "Invalid option. Press Enter to continue." } else { "Opcion invalida. Presiona Enter para continuar." }) -ForegroundColor Yellow
                [void](Read-Host)
            }
        }
    }
}

# Agrega o actualiza prefijos OUI en el mapa local de fabricantes.
function Add-OuiKnowledge {
    param(
        [hashtable]$TargetMap,
        [hashtable]$AdditionalMap
    )

    foreach ($entry in $AdditionalMap.GetEnumerator()) {
        $TargetMap[$entry.Key.ToUpperInvariant()] = $entry.Value
    }
}

# Mapa local de prefijos OUI comunes para inferir fabricantes sin depender de internet.
$OUIMap = @{
  '00-05-9A'='Cisco'; '00-0A-B7'='Cisco'; '00-14-22'='Dell'; '00-16-3E'='Xen'; '00-17-88'='Philips Hue'
  '00-18-4D'='Netgear'; '00-1A-11'='Google'; '00-1A-2B'='Ayecom'; '00-1B-63'='Apple'; '00-1C-14'='Cisco'
  '00-1D-7E'='Cisco-Linksys'; '00-21-5A'='HP'; '00-22-15'='Asustek'; '00-23-24'='Apple'; '00-24-2B'='Hon Hai/Foxconn'
  '00-25-9C'='Cisco-Linksys'; '00-26-B9'='Dell'; '00-50-56'='VMware'; '00-90-A9'='Western Digital'; '00-E0-4C'='Realtek'
  '08-00-27'='VirtualBox'; '08-3E-8E'='Hon Hai/Foxconn'; '10-7B-44'='Asustek'; '14-CC-20'='TP-Link'; '18-31-BF'='ASRock'
  '18-64-72'='Aruba'; '18-E8-29'='Ubiquiti'; '20-4E-7F'='Netgear'; '24-5E-BE'='QNAP'; '28-C6-8E'='Netgear'
  '2C-3A-E8'='Cisco'; '2C-F0-5D'='MikroTik'; '30-B5-C2'='TP-Link'; '34-97-F6'='Asustek'; '3C-5A-B4'='Cisco'
  '3C-84-6A'='TP-Link'; '40-8D-5C'='Giga-Byte'; '44-D9-E7'='Ubiquiti'; '48-5F-99'='Cloud Network Technology'; '50-C7-BF'='TP-Link'
  '54-27-1E'='AzureWave'; '58-9C-FC'='Freebox'; '5C-E9-31'='Apple'; '60-45-CB'='Ubiquiti'; '64-16-66'='Nest'
  '68-FF-7B'='TP-Link'; '6C-3B-6B'='Routerboard/MikroTik'; '70-4F-57'='TP-Link'; '74-83-C2'='Ubiquiti'; '78-8A-20'='Ubiquiti'
  '7C-10-C9'='TP-Link'; '80-2A-A8'='Ubiquiti'; '84-16-F9'='TP-Link'; '88-36-6C'='Epson'; '8C-85-90'='Apple'
  '90-09-D0'='Synology'; '94-83-C4'='Ubiquiti'; '98-DA-C4'='TP-Link'; '9C-93-4E'='Xiaomi'; 'A0-36-9F'='Intel'
  'A4-34-D9'='Hikvision'; 'A4-2B-B0'='TP-Link'; 'A8-5E-45'='Huawei'; 'AC-84-C6'='TP-Link'; 'B0-4E-26'='TP-Link'
  'B8-27-EB'='Raspberry Pi'; 'B8-69-F4'='Routerboard/MikroTik'; 'B8-EC-A3'='Xiaomi'; 'BC-5F-F4'='ASRock'; 'C0-25-E9'='TP-Link'
  'C0-56-27'='Belkin'; 'C4-6E-1F'='TP-Link'; 'C8-3A-35'='Tenda'; 'D4-6A-6A'='MikroTik'; 'D8-32-14'='Tenda'
  'DC-A6-32'='Raspberry Pi'; 'E0-63-DA'='Ubiquiti'; 'E4-5F-01'='Raspberry Pi'; 'E8-94-F6'='TP-Link'; 'EC-08-6B'='TP-Link'
  'F0-18-98'='HP'; 'F0-9F-C2'='Ubiquiti'; 'F4-F5-D8'='Google'; 'F8-1A-67'='TP-Link'; 'FC-EC-DA'='Ubiquiti'
}

# Base OUI ampliada con fabricantes frecuentes en redes domesticas, oficinas y equipos IoT.
Add-OuiKnowledge -TargetMap $OUIMap -AdditionalMap @{
  '00-03-93'='Apple'; '00-0A-95'='Apple'; '00-0D-93'='Apple'; '00-11-24'='Apple'; '00-14-51'='Apple'
  '00-16-CB'='Apple'; '00-17-F2'='Apple'; '00-19-E3'='Apple'; '00-1E-C2'='Apple'; '00-1F-5B'='Apple'
  '00-1F-F3'='Apple'; '00-21-E9'='Apple'; '00-22-41'='Apple'; '00-23-12'='Apple'; '00-23-32'='Apple'
  '00-23-6C'='Apple'; '00-25-00'='Apple'; '00-25-4B'='Apple'; '00-26-08'='Apple'; '00-26-4A'='Apple'
  '28-CF-E9'='Apple'; '3C-07-54'='Apple'; '40-A6-D9'='Apple'; '44-00-10'='Apple'; '58-B0-35'='Apple'
  '60-F8-1D'='Apple'; '68-A8-6D'='Apple'; '70-56-81'='Apple'; '78-31-C1'='Apple'; '7C-6D-62'='Apple'
  '84-38-35'='Apple'; '8C-7B-9D'='Apple'; 'A4-C3-61'='Apple'; 'AC-BC-32'='Apple'; 'B8-53-AC'='Apple'
  'C8-2A-14'='Apple'; 'D0-03-4B'='Apple'; 'D8-30-62'='Apple'; 'E0-AC-CB'='Apple'; 'F0-99-BF'='Apple'
  'F4-31-C3'='Apple'; 'FC-25-3F'='Apple'
  '00-13-02'='Intel'; '00-15-00'='Intel'; '00-16-76'='Intel'; '00-18-DE'='Intel'; '00-19-D1'='Intel'
  '00-1B-21'='Intel'; '00-1C-BF'='Intel'; '00-1D-E0'='Intel'; '00-21-5C'='Intel'; '00-22-FB'='Intel'
  '00-24-D7'='Intel'; '00-26-C6'='Intel'; '18-56-80'='Intel'; '34-02-86'='Intel'; '3C-A9-F4'='Intel'
  '48-51-B7'='Intel'; '58-91-CF'='Intel'; '5C-51-4F'='Intel'; '68-5D-43'='Intel'; '70-1C-E7'='Intel'
  '74-E5-0B'='Intel'; '84-3A-4B'='Intel'; 'A0-A8-CD'='Intel'; 'AC-67-5D'='Intel'; 'B4-6D-83'='Intel'
  'BC-17-B8'='Intel'; 'D8-F2-CA'='Intel'; 'F4-06-69'='Intel'
  '00-06-5B'='Dell'; '00-08-74'='Dell'; '00-0B-DB'='Dell'; '00-11-43'='Dell'; '00-12-3F'='Dell'
  '00-13-72'='Dell'; '00-14-22'='Dell'; '00-18-8B'='Dell'; '00-19-B9'='Dell'; '00-1A-A0'='Dell'
  '00-1C-23'='Dell'; '00-21-70'='Dell'; '00-24-E8'='Dell'; '18-03-73'='Dell'; '34-17-EB'='Dell'
  '74-86-7A'='Dell'; '84-2B-2B'='Dell'; 'B8-AC-6F'='Dell'; 'D0-67-E5'='Dell'; 'F8-B1-56'='Dell'
  '00-01-E6'='HP'; '00-08-02'='HP'; '00-0B-CD'='HP'; '00-0E-7F'='HP'; '00-10-83'='HP'
  '00-11-85'='HP'; '00-12-79'='HP'; '00-14-38'='HP'; '00-16-35'='HP'; '00-17-08'='HP'
  '00-18-71'='HP'; '00-1A-4B'='HP'; '00-1B-78'='HP'; '00-1F-29'='HP'; '00-21-5A'='HP'
  '00-23-7D'='HP'; '00-25-B3'='HP'; '10-60-4B'='HP'; '2C-41-38'='HP'; '3C-52-82'='HP'
  '40-B0-34'='HP'; '68-B5-99'='HP'; '78-AC-C0'='HP'; 'A0-48-1C'='HP'; 'B4-99-BA'='HP'
  'D4-85-64'='HP'; 'EC-B1-D7'='HP'
  '00-04-AC'='IBM/Lenovo'; '00-06-29'='IBM/Lenovo'; '00-09-6B'='IBM/Lenovo'; '00-0D-60'='IBM/Lenovo'
  '00-11-25'='IBM/Lenovo'; '00-15-58'='IBM/Lenovo'; '00-17-31'='IBM/Lenovo'; '00-19-81'='IBM/Lenovo'
  '00-1A-6B'='IBM/Lenovo'; '00-1E-37'='IBM/Lenovo'; '00-21-86'='IBM/Lenovo'; '00-23-24'='Apple'
  '20-47-47'='Lenovo'; '28-D2-44'='Lenovo'; '3C-97-0E'='Lenovo'; '50-7B-9D'='Lenovo'; '54-EE-75'='Lenovo'
  '6C-0B-84'='Lenovo'; '98-FA-9B'='Lenovo'; 'B8-88-E3'='Lenovo'; 'C8-DD-C9'='Lenovo'; 'E8-6A-64'='Lenovo'
  '00-0C-6E'='Asus'; '00-11-2F'='Asus'; '00-13-D4'='Asus'; '00-15-F2'='Asus'
  '00-1B-FC'='Asus'; '00-1D-60'='Asus'; '00-22-15'='Asus'; '08-62-66'='Asus'; '10-BF-48'='Asus'
  '1C-87-2C'='Asus'; '2C-56-DC'='Asus'; '30-5A-3A'='Asus'; '38-2C-4A'='Asus'; '50-46-5D'='Asus'
  '60-A4-4C'='Asus'; '70-8B-CD'='Asus'; '88-D7-F6'='Asus'; 'AC-22-0B'='Asus'; 'BC-EE-7B'='Asus'
  'D8-50-E6'='Asus'; 'F0-79-59'='Asus'
  '00-12-17'='Cisco'; '00-13-19'='Cisco'; '00-15-63'='Cisco'; '00-17-0E'='Cisco'; '00-18-BA'='Cisco'
  '00-19-A9'='Cisco'; '00-1A-A1'='Cisco'; '00-1B-0C'='Cisco'; '00-1C-58'='Cisco'; '00-1D-A1'='Cisco'
  '00-1E-13'='Cisco'; '00-1F-9E'='Cisco'; '00-21-A0'='Cisco'; '00-22-90'='Cisco'; '00-23-04'='Cisco'
  '00-24-14'='Cisco'; '00-25-45'='Cisco'; '00-26-0B'='Cisco'; '04-18-D6'='Ubiquiti'; '04-D9-F5'='Ubiquiti'
  '18-E8-29'='Ubiquiti'; '24-A4-3C'='Ubiquiti'; '44-D9-E7'='Ubiquiti'; '68-72-51'='Ubiquiti'; '74-83-C2'='Ubiquiti'
  '78-8A-20'='Ubiquiti'; '80-2A-A8'='Ubiquiti'; '9C-05-D6'='Ubiquiti'; 'A8-9F-BA'='Ubiquiti'; 'B4-FB-E4'='Ubiquiti'
  'DC-9F-DB'='Ubiquiti'; 'E0-63-DA'='Ubiquiti'; 'F0-9F-C2'='Ubiquiti'; 'FC-EC-DA'='Ubiquiti'
  '00-0C-42'='MikroTik'; '4C-5E-0C'='MikroTik'; '64-D1-54'='MikroTik'; '74-4D-28'='MikroTik'; 'B8-69-F4'='MikroTik'
  'CC-2D-E0'='MikroTik'; 'D4-01-C3'='MikroTik'; 'D4-CA-6D'='MikroTik'; 'DC-2C-6E'='MikroTik'; 'E4-8D-8C'='MikroTik'
  '00-03-7F'='Atheros/TP-Link'; '14-CC-20'='TP-Link'; '18-A6-F7'='TP-Link'; '1C-61-B4'='TP-Link'; '30-B5-C2'='TP-Link'
  '50-C7-BF'='TP-Link'; '54-A7-03'='TP-Link'; '5C-62-8B'='TP-Link'; '60-E3-27'='TP-Link'; '68-FF-7B'='TP-Link'
  '84-16-F9'='TP-Link'; '98-DA-C4'='TP-Link'; 'AC-84-C6'='TP-Link'; 'C0-25-E9'='TP-Link'; 'E8-94-F6'='TP-Link'
  'F8-1A-67'='TP-Link'; '00-09-5B'='Netgear'; '00-0F-B5'='Netgear'; '00-14-6C'='Netgear'; '00-18-4D'='Netgear'
  '00-1B-2F'='Netgear'; '00-1E-2A'='Netgear'; '00-22-3F'='Netgear'; '20-4E-7F'='Netgear'; '28-C6-8E'='Netgear'
  '44-94-FC'='Netgear'; '6C-B0-CE'='Netgear'; '84-1B-5E'='Netgear'; '9C-3D-CF'='Netgear'; 'A0-04-60'='Netgear'
  'C4-04-15'='Netgear'; 'E0-46-9A'='Netgear'
  '00-08-9B'='ICP/D-Link'; '00-0D-88'='D-Link'; '00-11-95'='D-Link'; '00-13-46'='D-Link'; '00-15-E9'='D-Link'
  '00-17-9A'='D-Link'; '00-19-5B'='D-Link'; '00-1B-11'='D-Link'; '00-1C-F0'='D-Link'; '00-21-91'='D-Link'
  '00-22-B0'='D-Link'; '00-24-01'='D-Link'; '14-D6-4D'='D-Link'; '1C-7E-E5'='D-Link'; '28-10-7B'='D-Link'
  '90-94-E4'='D-Link'; 'B8-A3-86'='D-Link'; 'C0-A0-BB'='D-Link'; 'CC-B2-55'='D-Link'
  '00-12-BF'='Samsung'; '00-15-99'='Samsung'; '00-16-32'='Samsung'; '00-17-C9'='Samsung'; '00-1A-8A'='Samsung'
  '00-1D-25'='Samsung'; '00-21-19'='Samsung'; '00-23-39'='Samsung'; '00-24-54'='Samsung'; '08-08-C2'='Samsung'
  '14-89-F6'='Samsung'; '24-4B-03'='Samsung'; '34-BE-00'='Samsung'; '5C-0A-5B'='Samsung'; '78-1F-DB'='Samsung'
  '84-25-DB'='Samsung'; '98-52-B1'='Samsung'; 'A0-07-98'='Samsung'; 'C0-65-99'='Samsung'; 'E8-50-8B'='Samsung'
  '00-9A-CD'='Huawei'; '04-BD-70'='Huawei'; '08-19-A6'='Huawei'; '10-47-80'='Huawei'; '18-C5-8A'='Huawei'
  '20-F3-A3'='Huawei'; '28-31-52'='Huawei'; '2C-AB-00'='Huawei'; '38-BC-1A'='Huawei'; '48-46-FB'='Huawei'
  '54-89-98'='Huawei'; '5C-4C-A9'='Huawei'; '78-D7-52'='Huawei'; '80-71-7A'='Huawei'; 'A8-5E-45'='Huawei'
  'B4-15-13'='Huawei'; 'BC-76-70'='Huawei'; 'CC-96-A0'='Huawei'; 'F8-4A-BF'='Huawei'
  '04-CF-8C'='Xiaomi'; '0C-1D-AF'='Xiaomi'; '18-59-36'='Xiaomi'; '28-E3-1F'='Xiaomi'; '34-CE-00'='Xiaomi'
  '40-31-3C'='Xiaomi'; '50-8F-4C'='Xiaomi'; '64-09-80'='Xiaomi'; '78-02-F8'='Xiaomi'; '8C-BE-BE'='Xiaomi'
  '9C-99-A0'='Xiaomi'; 'A4-50-46'='Xiaomi'; 'B0-E2-35'='Xiaomi'; 'C4-0B-CB'='Xiaomi'; 'D4-97-0B'='Xiaomi'
  'E4-46-DA'='Xiaomi'; 'F8-A4-5F'='Xiaomi'
  '00-11-32'='Synology'; '00-27-19'='QNAP'; '24-5E-BE'='QNAP'; '90-09-D0'='Synology'
  '00-1F-33'='QNAP'; '00-90-A9'='Western Digital'; '00-14-EE'='Western Digital'; '00-1D-7E'='Cisco-Linksys'
  'B8-27-EB'='Raspberry Pi'; 'DC-A6-32'='Raspberry Pi'; 'E4-5F-01'='Raspberry Pi'; 'D8-3A-DD'='Raspberry Pi'
  '00-1E-C0'='LG'; '00-21-FC'='LG'; '00-26-E2'='LG'; '10-F1-F2'='LG'; '20-6B-E7'='LG'; '34-95-DB'='LG'
  '3C-CD-5A'='LG'; '40-B0-FA'='LG'; '58-A2-B5'='LG'; '64-BC-0C'='LG'; '78-5D-C8'='LG'; 'A0-91-69'='LG'
  'C8-08-E9'='LG'; 'E8-92-A4'='LG'
  '00-01-4A'='Sony'; '00-04-1F'='Sony'; '00-0A-D9'='Sony'; '00-13-A9'='Sony'; '00-16-B8'='Sony'
  '00-18-13'='Sony'; '00-19-C5'='Sony'; '00-1D-0D'='Sony'; '00-21-9E'='Sony'; '00-24-BE'='Sony'
  '18-00-2D'='Sony'; '30-75-12'='Sony'; '54-42-49'='Sony'; 'AC-9B-0A'='Sony'
  '00-08-22'='Brother'; '00-0B-5D'='Brother'; '00-80-77'='Brother'; '30-05-5C'='Brother'; '3C-2A-F4'='Brother'
  '7C-D3-0A'='Brother'; '80-77-82'='Brother'; 'A0-8C-FD'='Brother'; 'B0-2A-43'='Brother'; 'E8-DA-AA'='Brother'
  '00-00-85'='Canon'; '00-1E-8F'='Canon'; '00-BB-C1'='Canon'
  '08-00-37'='Epson'; '08-00-48'='Epson'; '40-8D-5C'='Giga-Byte'; '44-8A-5B'='Micro-Star/MSI'; '4C-CC-6A'='Micro-Star/MSI'
  '00-05-69'='VMware'; '00-0C-29'='VMware'; '00-1C-14'='VMware'; '00-50-56'='VMware'; '08-00-27'='VirtualBox'
  '52-54-00'='QEMU/KVM'; '00-16-3E'='Xen'; '00-15-5D'='Microsoft Hyper-V'; '7C-1E-52'='Microsoft'; '00-17-FA'='Microsoft'
  '00-50-F2'='Microsoft'; '28-18-78'='Microsoft'; '5C-BA-37'='Microsoft'; 'B4-AE-2B'='Microsoft'
  '00-18-82'='Amazon'; '44-65-0D'='Amazon'; '50-F5-DA'='Amazon'; '68-54-F5'='Amazon'; '74-C2-46'='Amazon'
  'F0-27-2D'='Amazon'; 'F4-03-2A'='Amazon'; '00-1A-11'='Google'; '3C-5A-B4'='Google/Nest'; '64-16-66'='Google/Nest'
  'A4-77-33'='Google/Nest'; 'F4-F5-D8'='Google/Nest'; '48-D6-D5'='Google/Nest'; '20-DF-B9'='Google/Nest'
  '00-0E-58'='Sonos'; '5C-AA-FD'='Sonos'; '78-28-CA'='Sonos'; '94-9F-3E'='Sonos'; 'B8-E9-37'='Sonos'
  '00-0D-4B'='Roku'; '08-05-81'='Roku'; '2C-54-91'='Roku'; '88-DE-A9'='Roku'; 'B8-3E-59'='Roku'
  '18-B4-30'='Nest'; '54-27-1E'='AzureWave'; '60-45-CB'='Ubiquiti'; '88-36-6C'='Epson'; 'A4-34-D9'='Hikvision'
}

# Bloque ejecutado por cada trabajador: descubre estado, nombres, servicios, MAC, fabricante y tipo.
$ScanBlock = {
    param(
        [string]$ip,
        [int]$TimeoutMs,
        [hashtable]$OUIMap,
        [string]$Mode,
        [string]$PingPath,
        [string]$NbtstatPath,
        [string]$ArpPath,
        [int[]]$PortsToScan,
        [bool]$CanResolveDnsName,
        [bool]$CanGetNetNeighbor
    )

    # Comprueba conectividad ICMP usando ping.exe cuando existe para respetar timeouts en milisegundos.
    function Test-HostReachable {
        param(
            [string]$Target,
            [int]$TimeoutMilliseconds,
            [string]$PingExecutable
        )

        try {
            if ($PingExecutable) {
                $null = & $PingExecutable -n 1 -w $TimeoutMilliseconds $Target 2>$null
                return ($LASTEXITCODE -eq 0)
            }

            $timeoutSeconds = [Math]::Max(1, [int][Math]::Ceiling($TimeoutMilliseconds / 1000))
            return [bool](Test-Connection -TargetName $Target -Count 1 -Quiet -TimeoutSeconds $timeoutSeconds -ErrorAction SilentlyContinue)
        } catch {
            return $false
        }
    }

    # Verifica si un puerto TCP acepta conexion dentro del timeout indicado sin bloquear el hilo.
    function Test-Port {
        param(
            [string]$Target,
            [int]$Port,
            [int]$TimeoutMilliseconds
        )

        $client = $null
        $asyncResult = $null
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $client.BeginConnect($Target, $Port, $null, $null)
            $connected = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)
            if ($connected -and $client.Connected) {
                $client.EndConnect($asyncResult)
                return $true
            }
            return $false
        } catch {
            return $false
        } finally {
            if ($asyncResult -and $asyncResult.AsyncWaitHandle) { $asyncResult.AsyncWaitHandle.Close() }
            if ($client) { $client.Close() }
        }
    }

    # Resuelve el nombre PTR del host cuando el cmdlet DNS esta disponible.
    function Get-PtrName {
        param(
            [string]$Target,
            [bool]$CanResolve
        )

        if (-not $CanResolve) { return "" }
        try {
            $records = @(Resolve-DnsName -Name $Target -Type PTR -ErrorAction SilentlyContinue)
            $record = $records | Where-Object { $_.NameHost } | Select-Object -First 1
            if ($record) { return ($record.NameHost -replace '\.$','').Trim() }
        } catch {}
        return ""
    }

    # Lee el nombre NetBIOS con nbtstat cuando el binario esta disponible.
    function Get-NetBiosName {
        param(
            [string]$Target,
            [string]$NbtstatExecutable
        )

        if (-not $NbtstatExecutable) { return "" }
        try {
            $output = & $NbtstatExecutable -A $Target 2>$null
            $line = ($output | Select-String -Pattern 'Nombre de host|Host Name|<00>' | Select-Object -First 1).Line
            if ($line) {
                return ($line -replace '.*Nombre de host\s+','' -replace '.*Host Name\s+','' -replace '\s+<00>.*','').Trim()
            }
        } catch {}
        return ""
    }

    # Extrae y limpia el titulo HTML de un servicio HTTP.
    function Get-HttpTitle {
        param(
            [string]$Target,
            [int]$Port,
            [int]$TimeoutSeconds
        )

        try {
            $uri = if ($Port -eq 80) { "http://$Target/" } else { "http://{0}:{1}/" -f $Target, $Port }
            $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec $TimeoutSeconds -MaximumRedirection 2 -ErrorAction Stop
            foreach ($content in @($response.Content, $response.RawContent)) {
                if (-not [string]::IsNullOrWhiteSpace($content) -and $content -match '(?is)<title>\s*(.*?)\s*</title>') {
                    return ([System.Net.WebUtility]::HtmlDecode($Matches[1]) -replace '\s+', ' ').Trim()
                }
            }
        } catch {}
        return ""
    }

    # Obtiene el nombre principal del certificado TLS desde SAN o CN.
    function Get-TlsCertificateName {
        param(
            [string]$Target,
            [int]$ConnectTimeoutMilliseconds,
            [int]$StreamTimeoutMilliseconds
        )

        $tcp = $null
        $ssl = $null
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.ReceiveTimeout = $StreamTimeoutMilliseconds
            $tcp.SendTimeout = $StreamTimeoutMilliseconds
            if (-not $tcp.ConnectAsync($Target, 443).Wait($ConnectTimeoutMilliseconds)) { return "" }

            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, ({ $true }))
            $ssl.ReadTimeout = $StreamTimeoutMilliseconds
            $ssl.WriteTimeout = $StreamTimeoutMilliseconds
            $ssl.AuthenticateAsClient($Target)

            if (-not $ssl.RemoteCertificate) { return "" }
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $commonName = ""
            if ($cert.Subject -match 'CN=([^,]+)') { $commonName = $Matches[1].Trim() }

            $sanExtension = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
            if ($sanExtension) {
                $san = $sanExtension.Format($false)
                if ($san -match 'DNS Name=([^,\s]+)') { return $Matches[1].Trim() }
            }
            return $commonName
        } catch {
            return ""
        } finally {
            if ($ssl) { $ssl.Close() }
            if ($tcp) { $tcp.Close() }
        }
    }

    # Lee el banner inicial de SSH usando el numero real de bytes recibidos.
    function Get-SshBanner {
        param(
            [string]$Target,
            [int]$TimeoutMilliseconds
        )

        $client = $null
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            if (-not $client.ConnectAsync($Target, 22).Wait($TimeoutMilliseconds)) { return "" }

            $stream = $client.GetStream()
            $buffer = New-Object byte[] 256
            $readTask = $stream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $readTask.Wait($TimeoutMilliseconds)) { return "" }
            if ($readTask.Result -le 0) { return "" }

            $text = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $readTask.Result)
            return (($text -split "`r?`n" | Select-Object -First 1).Trim())
        } catch {
            return ""
        } finally {
            if ($client) { $client.Close() }
        }
    }

    # Normaliza cualquier formato comun de MAC a AA-BB-CC-DD-EE-FF.
    function Format-MacAddress {
        param([string]$MacAddress)

        if ([string]::IsNullOrWhiteSpace($MacAddress)) { return "" }
        $hex = ($MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        if ($hex.Length -ne 12) { return "" }

        $pairs = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt 12; $i += 2) {
            [void]$pairs.Add($hex.Substring($i, 2))
        }
        return ($pairs -join '-')
    }

    # Recupera la MAC desde la tabla de vecinos ARP/ND si el cmdlet esta disponible.
    function Get-NeighborMac {
        param(
            [string]$Target,
            [bool]$CanReadNeighbors
        )

        if (-not $CanReadNeighbors) { return "" }
        try {
            $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -IPAddress $Target -ErrorAction SilentlyContinue)
            $neighbor = $neighbors |
                Where-Object { $_.MacAddress -and $_.MacAddress -ne '00-00-00-00-00-00' } |
                Sort-Object @{ Expression = { if ($_.State -eq 'Reachable') { 0 } else { 1 } } } |
                Select-Object -First 1
            if ($neighbor) { return (Format-MacAddress -MacAddress $neighbor.MacAddress) }
        } catch {}
        return ""
    }

    # Recupera la MAC desde arp.exe como respaldo cuando Get-NetNeighbor no devuelve datos.
    function Get-ArpMac {
        param(
            [string]$Target,
            [string]$ArpExecutable
        )

        if (-not $ArpExecutable) { return "" }
        try {
            $output = & $ArpExecutable -a $Target 2>$null
            $escapedTarget = [Regex]::Escape($Target)
            foreach ($line in @($output)) {
                if ($line -match $escapedTarget -and $line -match '([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}') {
                    return (Format-MacAddress -MacAddress $Matches[0])
                }
            }
        } catch {}
        return ""
    }

    # Intenta obtener la MAC por los metodos disponibles y devuelve la primera valida.
    function Get-DeviceMac {
        param(
            [string]$Target,
            [bool]$CanReadNeighbors,
            [string]$ArpExecutable
        )

        $neighborMac = Get-NeighborMac -Target $Target -CanReadNeighbors $CanReadNeighbors
        if ($neighborMac) { return $neighborMac }

        $arpMac = Get-ArpMac -Target $Target -ArpExecutable $ArpExecutable
        if ($arpMac) { return $arpMac }

        return ""
    }

    # Normaliza una MAC y devuelve el prefijo OUI en formato AA-BB-CC.
    function Get-OuiPrefix {
        param([string]$MacAddress)

        $normalized = Format-MacAddress -MacAddress $MacAddress
        if ($normalized.Length -ge 8) { return $normalized.Substring(0, 8) }
        return ""
    }

    # Convierte el mapa de puertos abiertos en una cadena compacta separada solo por comas.
    function Get-OpenPortsText {
        param([hashtable]$PortState)

        $ports = New-Object System.Collections.Generic.List[int]
        foreach ($entry in $PortState.GetEnumerator()) {
            if ($entry.Value -eq $true) {
                [void]$ports.Add([int]$entry.Key)
            }
        }

        if ($ports.Count -eq 0) { return "" }

        $orderedPorts = @($ports | Sort-Object -Unique | ForEach-Object { $_.ToString([System.Globalization.CultureInfo]::InvariantCulture) })
        return [string]::Join(',', [string[]]$orderedPorts)
    }

    # Identifica fabricante por palabras clave visibles en nombres, banners, titulos HTTP o certificados.
    function Get-VendorFromSignals {
        param([string]$Signals)

        if ([string]::IsNullOrWhiteSpace($Signals)) { return "" }

        $rules = @(
            @{ Pattern='(?i)\b(unifi|ubiquiti|airmax|edgeos|uisp)\b'; Vendor='Ubiquiti' },
            @{ Pattern='(?i)\b(mikrotik|routerboard|routeros)\b'; Vendor='MikroTik' },
            @{ Pattern='(?i)\b(tp-link|tplink|omada)\b'; Vendor='TP-Link' },
            @{ Pattern='(?i)\b(netgear|readynas)\b'; Vendor='Netgear' },
            @{ Pattern='(?i)\b(cisco|meraki|linksys)\b'; Vendor='Cisco' },
            @{ Pattern='(?i)\b(aruba|procurve)\b'; Vendor='HP/Aruba' },
            @{ Pattern='(?i)\b(fortinet|fortigate)\b'; Vendor='Fortinet' },
            @{ Pattern='(?i)\b(pfsense|netgate)\b'; Vendor='Netgate/pfSense' },
            @{ Pattern='(?i)\b(opnsense|deciso)\b'; Vendor='OPNsense/Deciso' },
            @{ Pattern='(?i)\b(synology|diskstation|rackstation)\b'; Vendor='Synology' },
            @{ Pattern='(?i)\b(qnap|qts|quts)\b'; Vendor='QNAP' },
            @{ Pattern='(?i)\b(truenas|freenas)\b'; Vendor='TrueNAS' },
            @{ Pattern='(?i)\b(wdmycloud|western digital|my cloud)\b'; Vendor='Western Digital' },
            @{ Pattern='(?i)\b(hikvision|hiwatch|ezviz|nvr|dvr)\b'; Vendor='Hikvision' },
            @{ Pattern='(?i)\b(dahua|imou)\b'; Vendor='Dahua' },
            @{ Pattern='(?i)\b(axis communications|axis camera)\b'; Vendor='Axis' },
            @{ Pattern='(?i)\b(reolink)\b'; Vendor='Reolink' },
            @{ Pattern='(?i)\b(epson|ecotank|workforce)\b'; Vendor='Epson' },
            @{ Pattern='(?i)\b(brother)\b'; Vendor='Brother' },
            @{ Pattern='(?i)\b(canon|pixma|imageclass)\b'; Vendor='Canon' },
            @{ Pattern='(?i)\b(laserjet|officejet|deskjet|hewlett|hp\b)\b'; Vendor='HP' },
            @{ Pattern='(?i)\b(dell|idrac|wyse)\b'; Vendor='Dell' },
            @{ Pattern='(?i)\b(lenovo|thinkpad|thinkcentre)\b'; Vendor='Lenovo' },
            @{ Pattern='(?i)\b(asus|asustek|rog)\b'; Vendor='Asus' },
            @{ Pattern='(?i)\b(gigabyte|giga-byte|aorus)\b'; Vendor='Giga-Byte' },
            @{ Pattern='(?i)\b(msi|micro-star)\b'; Vendor='MSI' },
            @{ Pattern='(?i)\b(apple|macbook|imac|iphone|ipad|airport|bonjour)\b'; Vendor='Apple' },
            @{ Pattern='(?i)\b(samsung|galaxy|smartthings)\b'; Vendor='Samsung' },
            @{ Pattern='(?i)\b(lg webos|webos|lg electronics)\b'; Vendor='LG' },
            @{ Pattern='(?i)\b(sony|bravia|playstation)\b'; Vendor='Sony' },
            @{ Pattern='(?i)\b(xiaomi|miwifi|redmi|yeelight)\b'; Vendor='Xiaomi' },
            @{ Pattern='(?i)\b(huawei|honor)\b'; Vendor='Huawei' },
            @{ Pattern='(?i)\b(google|nest|chromecast)\b'; Vendor='Google/Nest' },
            @{ Pattern='(?i)\b(amazon|alexa|echo|kindle|firetv|ring)\b'; Vendor='Amazon' },
            @{ Pattern='(?i)\b(roku)\b'; Vendor='Roku' },
            @{ Pattern='(?i)\b(sonos)\b'; Vendor='Sonos' },
            @{ Pattern='(?i)\b(philips hue|hue bridge)\b'; Vendor='Philips Hue' },
            @{ Pattern='(?i)\b(raspberry|raspberrypi)\b'; Vendor='Raspberry Pi' },
            @{ Pattern='(?i)\b(vmware|esxi|vcenter)\b'; Vendor='VMware' },
            @{ Pattern='(?i)\b(virtualbox)\b'; Vendor='VirtualBox' },
            @{ Pattern='(?i)\b(hyper-v|microsoft)\b'; Vendor='Microsoft' },
            @{ Pattern='(?i)\b(qemu|kvm|proxmox)\b'; Vendor='QEMU/KVM' }
        )

        foreach ($rule in $rules) {
            if ($Signals -match $rule.Pattern) { return $rule.Vendor }
        }
        return ""
    }

    # Detecta si una MAC es local/aleatoria y no representa un fabricante OUI publico confiable.
    function Test-LocallyAdministeredMac {
        param([string]$MacAddress)

        $normalized = Format-MacAddress -MacAddress $MacAddress
        if (-not $normalized) { return $false }

        $firstOctet = [Convert]::ToInt32($normalized.Substring(0, 2), 16)
        return (($firstOctet -band 2) -eq 2)
    }

    # Decide el fabricante reportado priorizando OUI, luego senales de software/nombre.
    function Resolve-ReportedVendor {
        param(
            [string]$OuiVendor,
            [string]$SignalVendor,
            [string]$MacAddress
        )

        if ($OuiVendor) { return $OuiVendor }
        if ($SignalVendor) { return $SignalVendor }
        if ($MacAddress -and (Test-LocallyAdministeredMac -MacAddress $MacAddress)) { return "MAC local/aleatoria" }
        if ($MacAddress) { return "No identificado" }
        return ""
    }

    # Clasifica el dispositivo combinando nombres, fabricantes, banners y puertos abiertos.
    function Get-DeviceType {
        param(
            [bool]$IsActive,
            [string]$Signals,
            [string]$SshBanner,
            [string]$OpenPorts
        )

        if (-not $IsActive) { return "Inactivo" }
        if ($Signals -match '(?i)router|gateway|openwrt|dd-wrt|mikrotik|routerboard|ubiquiti|unifi|tplink|tp-link|netgear|tenda|linksys|aruba|firewall|pfsense|opnsense') { return "Router/AP" }
        if ($Signals -match '(?i)hikvision|camera|camara|ipcam|webcam|nvr|dvr|surveillance') { return "Camara/IoT" }
        if ($Signals -match '(?i)printer|impresora|laserjet|officejet|deskjet|epson|brother|canon|xerox') { return "Impresora" }
        if ($Signals -match '(?i)raspberry|arduino|esp32|xiaomi|philips hue|nest|iot|smart') { return "IoT" }
        if ($Signals -match '(?i)vmware|virtualbox|hyper-v|xen|qemu') { return "Maquina virtual" }
        if ($SshBanner -or $Signals -match '(?i)server|srv|nas|synology|qnap|truenas|freenas|linux|ubuntu|debian|centos') { return "Servidor/NAS" }
        if ($Signals -match '(?i)laptop|notebook|desktop|workstation|pc-|win|windows|dell|hp|lenovo|intel|asus|asustek|apple|macbook|imac') { return "Laptop/PC" }
        if ($OpenPorts -match '(^|,)3389(,|$)|(^|,)445(,|$)') { return "Laptop/PC" }
        if ($Signals.Trim()) { return "Laptop/PC" }
        return "Desconocido"
    }

    # Escoge el mejor nombre disponible y asigna una puntuacion por confiabilidad.
    function Get-BestDeviceName {
        param(
            [string]$PtrName,
            [string]$NetBiosName,
            [string]$TlsName,
            [string]$HttpTitle,
            [string]$Vendor,
            [string]$SshBanner
        )

        if ($PtrName) { return [PSCustomObject]@{ Name=$PtrName; Source='PTR'; Score=90 } }
        if ($NetBiosName) { return [PSCustomObject]@{ Name=$NetBiosName; Source='NBNS'; Score=80 } }
        if ($TlsName) { return [PSCustomObject]@{ Name=$TlsName; Source='TLS CN'; Score=70 } }
        if ($HttpTitle) { return [PSCustomObject]@{ Name=$HttpTitle; Source='HTTP'; Score=60 } }
        if ($Vendor) { return [PSCustomObject]@{ Name=$Vendor; Source='OUI'; Score=40 } }
        if ($SshBanner) { return [PSCustomObject]@{ Name=$SshBanner; Source='SSH'; Score=35 } }
        return [PSCustomObject]@{ Name=''; Source=''; Score=0 }
    }

    # Calcula timeouts derivados para que las pruebas profundas no excedan demasiado el timeout base.
    $serviceTimeoutMs = [Math]::Min(900, [Math]::Max(300, $TimeoutMs))
    $webTimeoutSeconds = [Math]::Max(1, [int][Math]::Ceiling($serviceTimeoutMs / 1000))
    $portState = @{}
    foreach ($port in $PortsToScan) {
        $portState[[string]$port] = $false
    }

    # Primero se intenta ICMP; en modo Deep tambien se usan puertos comunes para detectar hosts que bloquean ping.
    $activo = Test-HostReachable -Target $ip -TimeoutMilliseconds $TimeoutMs -PingExecutable $PingPath
    if ($Mode -eq 'Deep') {
        foreach ($port in $PortsToScan) {
            $isOpen = Test-Port -Target $ip -Port $port -TimeoutMilliseconds $serviceTimeoutMs
            $portState[[string]$port] = $isOpen
            if ($isOpen) { $activo = $true }
        }
    }

    # Las variables de identidad se mantienen vacias para hosts inactivos.
    $ptrName = ""
    $nbName = ""
    $tlsCN = ""
    $httpTitle = ""
    $sshBanner = ""
    $mac = ""
    $oui = ""

    if ($activo) {
        $ptrName = Get-PtrName -Target $ip -CanResolve $CanResolveDnsName

        if ($Mode -eq 'Deep') {
            $nbName = Get-NetBiosName -Target $ip -NbtstatExecutable $NbtstatPath
            if ($portState['80']) { $httpTitle = Get-HttpTitle -Target $ip -Port 80 -TimeoutSeconds $webTimeoutSeconds }
            if (-not $httpTitle -and $portState['8080']) { $httpTitle = Get-HttpTitle -Target $ip -Port 8080 -TimeoutSeconds $webTimeoutSeconds }
            if ($portState['443']) { $tlsCN = Get-TlsCertificateName -Target $ip -ConnectTimeoutMilliseconds $serviceTimeoutMs -StreamTimeoutMilliseconds 2000 }
            if ($portState['22']) { $sshBanner = Get-SshBanner -Target $ip -TimeoutMilliseconds $serviceTimeoutMs }
        }

        $mac = Get-DeviceMac -Target $ip -CanReadNeighbors $CanGetNetNeighbor -ArpExecutable $ArpPath
        $oui = Get-OuiPrefix -MacAddress $mac
    }

    # Se combinan todas las señales para clasificar el equipo y elegir el nombre final.
    $vendor = ""
    if ($oui -and $OUIMap -and $OUIMap.ContainsKey($oui)) { $vendor = $OUIMap[$oui] }

    $openPorts = Get-OpenPortsText -PortState $portState
    $rawSignals = @($ptrName, $nbName, $tlsCN, $httpTitle, $sshBanner, $openPorts) -join " "
    $signalVendor = Get-VendorFromSignals -Signals $rawSignals
    $reportedVendor = Resolve-ReportedVendor -OuiVendor $vendor -SignalVendor $signalVendor -MacAddress $mac
    $vendorSource = if ($vendor) { "OUI" } elseif ($signalVendor) { "Senales" } elseif ($mac -and (Test-LocallyAdministeredMac -MacAddress $mac)) { "MAC local" } elseif ($mac) { "No identificado" } else { "" }
    $signals = @($rawSignals, $reportedVendor) -join " "
    $tipo = Get-DeviceType -IsActive ([bool]$activo) -Signals $signals -SshBanner $sshBanner -OpenPorts $openPorts
    $bestName = Get-BestDeviceName -PtrName $ptrName -NetBiosName $nbName -TlsName $tlsCN -HttpTitle $httpTitle -Vendor $vendor -SshBanner $sshBanner

    [PSCustomObject]@{
        IP              = $ip
        NombrePTR       = $ptrName
        NombreNBNS      = $nbName
        NombreTLS       = $tlsCN
        NombreHTTP      = $httpTitle
        SSHBanner       = $sshBanner
        MAC             = $mac
        OUI             = $oui
        Fabricante      = $reportedVendor
        FabricanteOUI   = $vendor
        FuenteFabricante = $vendorSource
        PuertosAbiertos = $openPorts
        Tipo            = $tipo
        NombreFinal     = $bestName.Name
        FuenteNombre    = $bestName.Source
        ScoreNombre     = $bestName.Score
        Activo          = [bool]$activo
    }
}

# Crea la carpeta padre de una salida cuando todavia no existe.
function Ensure-OutputDirectory {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    if ($directory -and -not [System.IO.Directory]::Exists($directory)) {
        [void][System.IO.Directory]::CreateDirectory($directory)
    }
}

# Devuelve la ruta base de salida sin extension y sin puntos finales accidentales.
function Get-OutputBasePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'La ruta de salida no puede estar vacia.' }

    $extension = [System.IO.Path]::GetExtension($Path)
    if ([string]::IsNullOrWhiteSpace($extension)) { return $Path.TrimEnd('.') }

    $directory = [System.IO.Path]::GetDirectoryName($Path)
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    if ($directory) { return (Join-Path -Path $directory -ChildPath $fileName) }
    return $fileName
}

# Obtiene la carpeta del script para evitar que rutas relativas terminen en C:\Windows\System32.
function Get-ScriptBasePath {
    $root = Get-Variable -Name PSScriptRoot -Scope Script -ErrorAction SilentlyContinue
    if ($root -and -not [string]::IsNullOrWhiteSpace([string]$root.Value)) {
        return [string]$root.Value
    }

    $commandPath = Get-Variable -Name PSCommandPath -Scope Script -ErrorAction SilentlyContinue
    if ($commandPath -and -not [string]::IsNullOrWhiteSpace([string]$commandPath.Value)) {
        return [System.IO.Path]::GetDirectoryName([string]$commandPath.Value)
    }

    return (Get-Location).Path
}

# Convierte rutas relativas de salida a rutas absolutas basadas en la carpeta del script.
function Resolve-ScanPath {
    param(
        [string]$Path,
        [string]$BasePath
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'La ruta no puede estar vacia.' }

    $expandedPath = [Environment]::ExpandEnvironmentVariables($Path)
    if ([System.IO.Path]::IsPathRooted($expandedPath)) { return [System.IO.Path]::GetFullPath($expandedPath) }

    return [System.IO.Path]::GetFullPath((Join-Path -Path $BasePath -ChildPath $expandedPath))
}

# Exporta resultados a Excel usando ImportExcel (si esta disponible).
function Export-ToExcel {
    param(
        $DataAll,
        $DataUp,
        [string]$Path,
        [ValidateSet('ES','EN')][string]$Language = 'ES'
    )

    Ensure-OutputDirectory -Path $Path
    $activeSheetName = if ($Language -eq 'EN') { 'Active' } else { 'Activos' }
    $allSheetName = if ($Language -eq 'EN') { 'All' } else { 'Todos' }

    if (Get-Module -ListAvailable -Name ImportExcel) {
        try {
            Import-Module ImportExcel -ErrorAction Stop
            if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
            $DataUp | Export-Excel -Path $Path -WorksheetName $activeSheetName -AutoSize
            $DataAll | Export-Excel -Path $Path -WorksheetName $allSheetName -AutoSize -Append
            Write-Host $(if ($Language -eq 'EN') { "Exported to Excel (ImportExcel): $Path" } else { "Exportado a Excel (ImportExcel): $Path" })
            return $true
        } catch {
            Write-Warning $(if ($Language -eq 'EN') { "ImportExcel failed: $_" } else { "Fallo con ImportExcel: $_" })
        }
    }
    return $false
}

# Exporta CSV con encabezados consistentes aunque la coleccion no tenga filas.
function Export-CsvWithHeaders {
    param(
        [object[]]$Data,
        [string]$Path,
        [string[]]$Columns
    )

    Ensure-OutputDirectory -Path $Path
    if ($Data -and $Data.Count -gt 0) {
        $csvContent = ($Data | Select-Object -Property $Columns | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
        [void](Save-TextFileWithRetry -Content $csvContent -Path $Path)
        return
    }

    $header = ($Columns | ForEach-Object { '"' + ($_ -replace '"','""') + '"' }) -join ','
    [void](Save-TextFileWithRetry -Content $header -Path $Path)
}

# Exporta resultados en CSV separados para todos los hosts y solo activos.
function Export-ToCsvFiles {
    param(
        [object[]]$DataAll,
        [object[]]$DataUp,
        [string]$AllPath,
        [string]$ActivePath,
        [string[]]$Columns,
        [ValidateSet('ES','EN')][string]$Language = 'ES'
    )

    Export-CsvWithHeaders -Data $DataAll -Path $AllPath -Columns $Columns
    Export-CsvWithHeaders -Data $DataUp -Path $ActivePath -Columns $Columns
    Write-Host $(if ($Language -eq 'EN') { "Exported CSV: $AllPath and $ActivePath" } else { "Exportado CSV: $AllPath y $ActivePath" })
}

# Serializa y guarda objetos en JSON UTF-8.
function Save-JsonFile {
    param([object]$Data, [string]$Path)
    Ensure-OutputDirectory -Path $Path

    if ($Data -is [array] -and $Data.Count -eq 0) {
        return (Save-TextFileWithRetry -Content '[]' -Path $Path)
    }

    $json = $Data | ConvertTo-Json -Depth 8
    return (Save-TextFileWithRetry -Content $json -Path $Path)
}

# Guarda texto con reintentos y respaldo si el destino esta bloqueado.
function Save-TextFileWithRetry {
    param(
        [string]$Content,
        [string]$Path,
        [int]$Retries = 8,
        [int]$DelayMs = 250
    )

    Ensure-OutputDirectory -Path $Path

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($fullPath)
    $extension = [System.IO.Path]::GetExtension($fullPath)
    $encoding = New-Object System.Text.UTF8Encoding $false
    $lastError = $null

    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        try {
            [System.IO.File]::WriteAllText($fullPath, $Content, $encoding)
            return $fullPath
        } catch {
            $lastError = $_
            if ($attempt -lt $Retries) {
                Start-Sleep -Milliseconds $DelayMs
            }
        }
    }

    $fallbackPath = Join-Path -Path $directory -ChildPath ("{0}_bloqueado_{1}{2}" -f $baseName, (Get-Date -Format 'yyyyMMdd_HHmmssfff'), $extension)
    [System.IO.File]::WriteAllText($fallbackPath, $Content, $encoding)
    Write-Warning ("No se pudo escribir {0} porque esta bloqueado por otro proceso. Se guardo una copia en {1}. Detalle: {2}" -f $fullPath, $fallbackPath, $lastError.Exception.Message)
    return $fallbackPath
}

# Normaliza cualquier valor de puertos a texto con formato 22,80,443.
function Convert-PortListToCommaText {
    param([object]$Value)

    if ($null -eq $Value) { return "" }

    $rawItems = @()
    if ($Value -is [array]) {
        $rawItems = @($Value)
    } else {
        $text = ([string]$Value).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { return "" }
        $rawItems = @($text -split '[,;|\s]+')
    }

    $ports = New-Object System.Collections.Generic.List[int]
    foreach ($item in $rawItems) {
        $candidate = ([string]$item).Trim()
        $port = 0
        if ([int]::TryParse($candidate, [ref]$port) -and $port -ge 1 -and $port -le 65535) {
            [void]$ports.Add($port)
        }
    }

    if ($ports.Count -eq 0) { return "" }
    $orderedPorts = @($ports | Sort-Object -Unique | ForEach-Object { $_.ToString([System.Globalization.CultureInfo]::InvariantCulture) })
    return [string]::Join(',', [string[]]$orderedPorts)
}

# Devuelve las columnas visibles del reporte segun el idioma seleccionado.
function Get-ReportColumns {
    param([ValidateSet('ES','EN')][string]$Language = 'ES')

    if ($Language -eq 'EN') {
        return @(
            'IP',
            'DeviceName',
            'Active',
            'Type',
            'NameSource',
            'NameScore',
            'PTRName',
            'NBNSName',
            'TLSName',
            'HTTPTitle',
            'SSHBanner',
            'OpenPorts',
            'MAC',
            'OUI',
            'Vendor',
            'VendorOUI',
            'VendorSource'
        )
    }

    return @(
        'IP',
        'NombreEquipo',
        'Activo',
        'Tipo',
        'FuenteNombre',
        'ScoreNombre',
        'NombrePTR',
        'NombreNBNS',
        'NombreTLS',
        'NombreHTTP',
        'SSHBanner',
        'PuertosAbiertos',
        'MAC',
        'OUI',
        'Fabricante',
        'FabricanteOUI',
        'FuenteFabricante'
    )
}

# Traduce el tipo de equipo para reportes en ingles sin alterar el modelo interno.
function Convert-DeviceTypeForReport {
    param(
        [string]$Value,
        [ValidateSet('ES','EN')][string]$Language = 'ES'
    )

    if ($Language -ne 'EN') { return $Value }

    switch ($Value) {
        'Inactivo' { return 'Inactive' }
        'Camara/IoT' { return 'Camera/IoT' }
        'Impresora' { return 'Printer' }
        'Maquina virtual' { return 'Virtual machine' }
        'Servidor/NAS' { return 'Server/NAS' }
        'Desconocido' { return 'Unknown' }
        default { return $Value }
    }
}

# Traduce etiquetas de fabricante calculadas por el script cuando el reporte esta en ingles.
function Convert-VendorTextForReport {
    param(
        [string]$Value,
        [ValidateSet('ES','EN')][string]$Language = 'ES'
    )

    if ($Language -ne 'EN') { return $Value }

    switch ($Value) {
        'No identificado' { return 'Unidentified' }
        'MAC local/aleatoria' { return 'Local/random MAC' }
        default { return $Value }
    }
}

# Traduce la fuente usada para identificar fabricante en reportes en ingles.
function Convert-VendorSourceForReport {
    param(
        [string]$Value,
        [ValidateSet('ES','EN')][string]$Language = 'ES'
    )

    if ($Language -ne 'EN') { return $Value }

    switch ($Value) {
        'Senales' { return 'Signals' }
        'MAC local' { return 'Local MAC' }
        'No identificado' { return 'Unidentified' }
        default { return $Value }
    }
}

# Convierte los resultados internos al idioma y columnas finales del reporte.
function Convert-ToLocalizedReport {
    param(
        [object[]]$Data,
        [ValidateSet('ES','EN')][string]$Language = 'ES'
    )

    if ($Language -eq 'EN') {
        return @($Data | ForEach-Object {
            [PSCustomObject]@{
                IP           = $_.IP
                DeviceName   = $_.NombreFinal
                Active       = $_.Activo
                Type         = Convert-DeviceTypeForReport -Value $_.Tipo -Language $Language
                NameSource   = $_.FuenteNombre
                NameScore    = $_.ScoreNombre
                PTRName      = $_.NombrePTR
                NBNSName     = $_.NombreNBNS
                TLSName      = $_.NombreTLS
                HTTPTitle    = $_.NombreHTTP
                SSHBanner    = $_.SSHBanner
                OpenPorts    = Convert-PortListToCommaText -Value $_.PuertosAbiertos
                MAC          = $_.MAC
                OUI          = $_.OUI
                Vendor       = Convert-VendorTextForReport -Value $_.Fabricante -Language $Language
                VendorOUI    = $_.FabricanteOUI
                VendorSource = Convert-VendorSourceForReport -Value $_.FuenteFabricante -Language $Language
            }
        })
    }

    return @($Data | ForEach-Object {
        [PSCustomObject]@{
            IP               = $_.IP
            NombreEquipo     = $_.NombreFinal
            Activo           = $_.Activo
            Tipo             = $_.Tipo
            FuenteNombre     = $_.FuenteNombre
            ScoreNombre      = $_.ScoreNombre
            NombrePTR        = $_.NombrePTR
            NombreNBNS       = $_.NombreNBNS
            NombreTLS        = $_.NombreTLS
            NombreHTTP       = $_.NombreHTTP
            SSHBanner        = $_.SSHBanner
            PuertosAbiertos  = Convert-PortListToCommaText -Value $_.PuertosAbiertos
            MAC              = $_.MAC
            OUI              = $_.OUI
            Fabricante       = $_.Fabricante
            FabricanteOUI    = $_.FabricanteOUI
            FuenteFabricante = $_.FuenteFabricante
        }
    })
}

# Recorta texto para mantener legible la vista en vivo.
function Format-LiveValue {
    param(
        [object]$Value,
        [int]$Width
    )

    $text = if ($null -eq $Value) { "" } else { [string]$Value }
    if ($text.Length -gt $Width) { return $text.Substring(0, [Math]::Max(0, $Width - 1)) + "~" }
    return $text.PadRight($Width)
}

# Muestra en consola una linea compacta por cada equipo activo detectado.
function Write-LiveDevice {
    param([object]$Device)

    if (-not $Device.Activo) { return }

    $name = if ($Device.NombreFinal) { $Device.NombreFinal } else { "(sin nombre)" }
    $line = "{0}  {1}  {2}  {3,3}  {4}  {5}  {6}" -f `
        (Format-LiveValue -Value $Device.IP -Width 15),
        (Format-LiveValue -Value $name -Width 28),
        (Format-LiveValue -Value $Device.FuenteNombre -Width 8),
        $Device.ScoreNombre,
        (Format-LiveValue -Value $Device.MAC -Width 17),
        (Format-LiveValue -Value $Device.Fabricante -Width 14),
        (Format-LiveValue -Value $Device.Tipo -Width 14)

    Write-Host $line -ForegroundColor Green
}

# Compara snapshot actual vs anterior y detecta hosts nuevos, caidos y modificados.
function Compare-ScanSnapshots {
    param([array]$CurrentData, [array]$PreviousData)
    $currentActive = @($CurrentData | Where-Object { $_.Activo -eq $true })
    $previousActive = @($PreviousData | Where-Object { $_.Activo -eq $true })

    $currByIp = @{}; $prevByIp = @{}
    foreach ($h in $currentActive) { $currByIp[$h.IP] = $h }
    foreach ($h in $previousActive) { $prevByIp[$h.IP] = $h }

    $newHosts = New-Object System.Collections.Generic.List[object]
    $downHosts = New-Object System.Collections.Generic.List[object]
    $changedHosts = New-Object System.Collections.Generic.List[object]

    foreach ($ip in $currByIp.Keys) {
        if (-not $prevByIp.ContainsKey($ip)) {
            [void]$newHosts.Add([PSCustomObject]@{ IP=$ip; NombreEquipo=$currByIp[$ip].NombreFinal; MAC=$currByIp[$ip].MAC; Cambio='Nuevo' })
        } else {
            $old = $prevByIp[$ip]; $new = $currByIp[$ip]
            if ($old.NombreFinal -ne $new.NombreFinal -or $old.MAC -ne $new.MAC) {
                [void]$changedHosts.Add([PSCustomObject]@{ IP=$ip; NombreAntes=$old.NombreFinal; NombreAhora=$new.NombreFinal; MACAntes=$old.MAC; MACAhora=$new.MAC; Cambio='Modificado' })
            }
        }
    }

    foreach ($ip in $prevByIp.Keys) {
        if (-not $currByIp.ContainsKey($ip)) {
            [void]$downHosts.Add([PSCustomObject]@{ IP=$ip; NombreEquipo=$prevByIp[$ip].NombreFinal; MAC=$prevByIp[$ip].MAC; Cambio='Caido' })
        }
    }

    return [PSCustomObject]@{ NewHosts=$newHosts; DownHosts=$downHosts; ChangedHosts=$changedHosts }
}

# Determina objetivos de escaneo desde CIDR, NetworkBase o deteccion automatica de interfaz.
function Resolve-Targets {
    param(
        [string]$CIDRInput,
        [string]$NetworkBaseInput,
        [string]$InterfaceNameInput,
        [int]$MaxHostsInput = 65534
    )

    if ($CIDRInput) {
        $ips = Get-CIDRHosts -InputCIDR $CIDRInput -MaxHosts $MaxHostsInput
        return [PSCustomObject]@{ Ips=$ips; Label=$CIDRInput; Interface='N/A (CIDR explicito)' }
    }

    $phys = Get-PhysicalAdapters
    if ($InterfaceNameInput) {
        $chosen = $phys | Where-Object { $_.Name -eq $InterfaceNameInput -or $_.InterfaceDescription -eq $InterfaceNameInput } | Select-Object -First 1
        if (-not $chosen) { throw "Interfaz no encontrada: $InterfaceNameInput" }
    } else {
        $chosen = $phys | Select-Object -First 1
        if (-not $chosen) { throw 'No hay adaptador fisico Up. Especifica -InterfaceName.' }
    }

    if ($NetworkBaseInput) {
        if ($NetworkBaseInput -match '^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){2}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$') {
            $base = $NetworkBaseInput
            $ips = 1..254 | ForEach-Object { "$base.$_" }
            return [PSCustomObject]@{ Ips=$ips; Label="$base.0/24"; Interface=$chosen.Name }
        }
        if ($NetworkBaseInput -match '^.+/\d{1,2}$') {
            $ips = Get-CIDRHosts -InputCIDR $NetworkBaseInput -MaxHosts $MaxHostsInput
            return [PSCustomObject]@{ Ips=$ips; Label=$NetworkBaseInput; Interface=$chosen.Name }
        }
        throw 'NetworkBase invalido. Usa 192.168.1 o 192.168.1.0/24'
    }

    $localIP = Get-IPv4ForInterface -AdapterName $chosen.Name
    if (-not $localIP) { throw 'No se pudo obtener IPv4 de la interfaz. Usa -NetworkBase o -CIDR.' }
    $baseAuto = ($localIP.Split('.')[0..2] -join '.')
    $ipsAuto = 1..254 | ForEach-Object { "$baseAuto.$_" }
    return [PSCustomObject]@{ Ips=$ipsAuto; Label="$baseAuto.0/24"; Interface=$chosen.Name }
}

# Inicia un trabajador dentro del pool de runspaces para escanear una IP.
function Start-ScanWorker {
    param(
        [System.Management.Automation.Runspaces.RunspacePool]$RunspacePool,
        [string]$ScanScript,
        [string]$Ip,
        [int]$TimeoutMilliseconds,
        [hashtable]$VendorMap,
        [string]$ScanMode,
        [string]$PingExecutable,
        [string]$NbtstatExecutable,
        [string]$ArpExecutable,
        [int[]]$ScanPorts,
        [bool]$CanResolveDns,
        [bool]$CanReadNeighbors
    )

    $worker = [PowerShell]::Create()
    $worker.RunspacePool = $RunspacePool
    [void]$worker.AddScript($ScanScript).
        AddArgument($Ip).
        AddArgument($TimeoutMilliseconds).
        AddArgument($VendorMap).
        AddArgument($ScanMode).
        AddArgument($PingExecutable).
        AddArgument($NbtstatExecutable).
        AddArgument($ArpExecutable).
        AddArgument($ScanPorts).
        AddArgument($CanResolveDns).
        AddArgument($CanReadNeighbors)

    return [PSCustomObject]@{
        IP         = $Ip
        PowerShell = $worker
        Handle     = $worker.BeginInvoke()
    }
}

# Recibe el resultado de un trabajador terminado y libera su instancia PowerShell.
function Receive-ScanWorker {
    param([object]$Worker)

    try {
        $output = @($Worker.PowerShell.EndInvoke($Worker.Handle))
        foreach ($streamError in @($Worker.PowerShell.Streams.Error)) {
            Write-Verbose ("Error escaneando {0}: {1}" -f $Worker.IP, $streamError)
        }
        return $output
    } catch {
        Write-Verbose ("Fallo escaneando {0}: {1}" -f $Worker.IP, $_)
        return @()
    } finally {
        if ($Worker -and $Worker.PowerShell) { $Worker.PowerShell.Dispose() }
    }
}

# Detiene trabajadores pendientes y cierra el pool de runspaces de forma ordenada.
function Stop-ScanWorkers {
    param(
        [array]$Workers,
        [System.Management.Automation.Runspaces.RunspacePool]$RunspacePool
    )

    foreach ($worker in @($Workers)) {
        if (-not $worker -or -not $worker.PowerShell) { continue }
        try { $worker.PowerShell.Stop() } catch {}
        try { $worker.PowerShell.Dispose() } catch {}
    }

    if ($RunspacePool) {
        try { $RunspacePool.Close() } catch {}
        try { $RunspacePool.Dispose() } catch {}
    }
}

# Actualiza la barra de progreso con cifras de completados, pendientes y ejecucion actual.
function Write-ScanProgress {
    param(
        [string]$Activity,
        [int]$Completed,
        [int]$Total,
        [int]$Running,
        [int]$Started
    )

    $percent = if ($Total -gt 0) { [int](($Completed / [double]$Total) * 100) } else { 100 }
    $status = "Completado: $Completed de $Total | Ejecutando: $Running | Iniciados: $Started"
    Write-Progress -Activity $Activity -Status $status -PercentComplete $percent
}

# Detecta cancelacion manual con Q sin bloquear el escaneo.
function Test-ScanCancelKey {
    try {
        if ([Console]::IsInputRedirected -or -not [Console]::KeyAvailable) { return $false }
        $key = [Console]::ReadKey($true)
        return ($key.Key -eq [ConsoleKey]::Q)
    } catch {
        return $false
    }
}

# Compatibilidad: -Deep fuerza el modo profundo aunque tambien exista -Mode.
if ($Deep) {
    $Mode = 'Deep'
}

# Si no se pasan parametros o se solicita -Menu, se abre el asistente interactivo.
if ($Menu -or $PSBoundParameters.Count -eq 0) {
    $menuSelection = Show-InteractiveMenu `
        -CurrentInterfaceName $InterfaceName `
        -CurrentNetworkBase $NetworkBase `
        -CurrentCIDR $CIDR `
        -CurrentTimeoutMs $TimeoutMs `
        -CurrentThrottle $Throttle `
        -CurrentMode $Mode `
        -CurrentOutputFormat $OutputFormat `
        -CurrentOutput $Output `
        -CurrentSnapshotPath $SnapshotPath `
        -CurrentCompareWithPrevious ([bool]$CompareWithPrevious) `
        -CurrentLiveView $LiveView `
        -CurrentMaxRuntimeSeconds $MaxRuntimeSeconds `
        -CurrentLanguage $Language

    $InterfaceName = $menuSelection.InterfaceName
    $NetworkBase = $menuSelection.NetworkBase
    $CIDR = $menuSelection.CIDR
    $TimeoutMs = $menuSelection.TimeoutMs
    $Throttle = $menuSelection.Throttle
    $Mode = $menuSelection.Mode
    $OutputFormat = $menuSelection.OutputFormat
    $Output = $menuSelection.Output
    $SnapshotPath = $menuSelection.SnapshotPath
    $CompareWithPrevious = $menuSelection.CompareWithPrevious
    $LiveView = $menuSelection.LiveView
    $MaxRuntimeSeconds = $menuSelection.MaxRuntimeSeconds
    $Language = $menuSelection.Language
}

# Las rutas relativas de salida se fijan a la carpeta del script y no al directorio activo de PowerShell.
$scriptBasePath = Get-ScriptBasePath
$Output = Resolve-ScanPath -Path $Output -BasePath $scriptBasePath
$SnapshotPath = Resolve-ScanPath -Path $SnapshotPath -BasePath $scriptBasePath
$isEnglish = ($Language -eq 'EN')

# Se resuelven las IP objetivo antes de iniciar trabajadores concurrentes.
$target = Resolve-Targets -CIDRInput $CIDR -NetworkBaseInput $NetworkBase -InterfaceNameInput $InterfaceName -MaxHostsInput $MaxHosts
$ips = @($target.Ips)
if (-not $ips -or $ips.Count -eq 0) { throw $(if ($isEnglish) { 'There are no IP addresses to scan.' } else { 'No hay IPs para escanear.' }) }

# Se usa una concurrencia efectiva menor cuando el rango tiene menos IPs que el throttle solicitado.
$effectiveThrottle = [Math]::Min($Throttle, $ips.Count)
$targetInterfaceText = if ($isEnglish) { $target.Interface -replace 'CIDR explicito', 'explicit CIDR' } else { $target.Interface }

Write-Host $(if ($isEnglish) { "Interface: $targetInterfaceText" } else { "Interfaz: $targetInterfaceText" })
Write-Host $(if ($isEnglish) { "Scanning: $($target.Label) | Hosts: $($ips.Count) | Timeout=$TimeoutMs | Throttle=$effectiveThrottle | Mode=$Mode`n" } else { "Escaneando: $($target.Label) | Hosts: $($ips.Count) | Timeout=$TimeoutMs | Throttle=$effectiveThrottle | Mode=$Mode`n" })
Write-Host $(if ($isEnglish) { "During the scan you can press Q to cancel and clean up workers." } else { "Durante el escaneo puedes presionar Q para cancelar y limpiar trabajos." }) -ForegroundColor DarkGray
if ($MaxRuntimeSeconds -gt 0) {
    Write-Host $(if ($isEnglish) { "Maximum runtime: $MaxRuntimeSeconds seconds" } else { "Tiempo maximo de ejecucion: $MaxRuntimeSeconds segundos" }) -ForegroundColor DarkGray
}

# La vista en vivo imprime solo equipos activos para no saturar la consola.
if ($LiveView) {
    Write-Host $(if ($isEnglish) { "Active devices detected live:" } else { "Equipos activos detectados en vivo:" }) -ForegroundColor Cyan
    Write-Host ("{0}  {1}  {2}  {3}  {4}  {5}  {6}" -f `
        (Format-LiveValue -Value "IP" -Width 15),
        (Format-LiveValue -Value $(if ($isEnglish) { "Name" } else { "Nombre" }) -Width 28),
        (Format-LiveValue -Value $(if ($isEnglish) { "Source" } else { "Fuente" }) -Width 8),
        "Scr",
        (Format-LiveValue -Value "MAC" -Width 17),
        (Format-LiveValue -Value $(if ($isEnglish) { "Vendor" } else { "Fabricante" }) -Width 14),
        (Format-LiveValue -Value $(if ($isEnglish) { "Type" } else { "Tipo" }) -Width 14)) -ForegroundColor DarkGray
}

# Se detectan herramientas del sistema una sola vez y se comparten con todos los trabajadores.
$pingCommand = Get-Command ping.exe -ErrorAction SilentlyContinue
$nbtstatCommand = Get-Command nbtstat.exe -ErrorAction SilentlyContinue
$arpCommand = Get-Command arp.exe -ErrorAction SilentlyContinue
$pingPath = if ($pingCommand) { $pingCommand.Source } else { "" }
$nbtstatPath = if ($nbtstatCommand) { $nbtstatCommand.Source } else { "" }
$arpPath = if ($arpCommand) { $arpCommand.Source } else { "" }
$canResolveDnsName = [bool](Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)
$canGetNetNeighbor = [bool](Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue)

# El pool de runspaces evita el coste de crear un proceso/job nuevo por cada direccion IP.
$results = New-Object 'System.Collections.Generic.List[object]' $ips.Count
$runningWorkers = @()
$started = 0
$completed = 0
$scanStoppedEarly = $false
$activity = "Escaneo de red $($target.Label)"
$scanStartedAt = Get-Date
$scanScriptText = $ScanBlock.ToString()
$runspacePool = $null
$lastProgressAt = Get-Date

try {
    $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $effectiveThrottle)
    $runspacePool.Open()

    while ($completed -lt $ips.Count) {
        if (Test-ScanCancelKey) {
            Write-Warning $(if ($isEnglish) { "Cancellation requested with Q. Stopping pending workers..." } else { "Cancelacion solicitada con Q. Deteniendo trabajos pendientes..." })
            $scanStoppedEarly = $true
            break
        }

        if ($MaxRuntimeSeconds -gt 0 -and ((Get-Date) - $scanStartedAt).TotalSeconds -ge $MaxRuntimeSeconds) {
            Write-Warning $(if ($isEnglish) { "Maximum runtime reached. Cancelling pending workers..." } else { "Tiempo maximo alcanzado. Cancelando trabajos pendientes..." })
            $scanStoppedEarly = $true
            break
        }

        while ($started -lt $ips.Count -and $runningWorkers.Count -lt $effectiveThrottle) {
            $runningWorkers += Start-ScanWorker `
                -RunspacePool $runspacePool `
                -ScanScript $scanScriptText `
                -Ip $ips[$started] `
                -TimeoutMilliseconds $TimeoutMs `
                -VendorMap $OUIMap `
                -ScanMode $Mode `
                -PingExecutable $pingPath `
                -NbtstatExecutable $nbtstatPath `
                -ArpExecutable $arpPath `
                -ScanPorts $PortsToScan `
                -CanResolveDns $canResolveDnsName `
                -CanReadNeighbors $canGetNetNeighbor
            $started++
        }

        $done = @($runningWorkers | Where-Object { $_.Handle.IsCompleted })
        if ($done.Count -gt 0) {
            foreach ($worker in @($done)) {
                $outputs = Receive-ScanWorker -Worker $worker
                foreach ($result in @($outputs)) {
                    [void]$results.Add($result)
                    if ($LiveView) { Write-LiveDevice -Device $result }
                }
                $runningWorkers = @($runningWorkers | Where-Object { $_.IP -ne $worker.IP })
                $completed++
            }
        } else {
            Start-Sleep -Milliseconds 60
        }

        $now = Get-Date
        if ($done.Count -gt 0 -or ($now - $lastProgressAt).TotalMilliseconds -ge 500) {
            Write-ScanProgress -Activity $activity -Completed $completed -Total $ips.Count -Running $runningWorkers.Count -Started $started
            $lastProgressAt = $now
        }
    }
} catch [System.Management.Automation.PipelineStoppedException] {
    $scanStoppedEarly = $true
    Write-Warning $(if ($isEnglish) { "Scan interrupted. Cleaning up pending workers..." } else { "Escaneo interrumpido. Limpiando trabajadores pendientes..." })
} catch [System.OperationCanceledException] {
    $scanStoppedEarly = $true
    Write-Warning $(if ($isEnglish) { "Scan cancelled. Cleaning up pending workers..." } else { "Escaneo cancelado. Limpiando trabajadores pendientes..." })
} catch {
    $scanStoppedEarly = $true
    throw
} finally {
    Write-Progress -Activity $activity -Completed
    Stop-ScanWorkers -Workers $runningWorkers -RunspacePool $runspacePool
}

# Se ordenan resultados por valor numerico de IP para que los reportes sean faciles de leer.
$ordered = @($results | Sort-Object { Convert-IPv4ToUInt32 -IpAddress $_.IP })

# Columnas finales del reporte en el orden e idioma esperado por Excel, CSV y JSON.
$exportColumns = Get-ReportColumns -Language $Language
$all = Convert-ToLocalizedReport -Data $ordered -Language $Language
$activeColumn = if ($Language -eq 'EN') { 'Active' } else { 'Activo' }
$activos = @($all | Where-Object { $_.PSObject.Properties[$activeColumn].Value -eq $true })

# Se calculan todas las rutas de salida a partir de una misma ruta base.
$outputBase = Get-OutputBasePath -Path $Output
$exportBase = $outputBase
if ($scanStoppedEarly) {
    $partialSuffix = if ($isEnglish) { "Partial" } else { "Parcial" }
    $exportBase = "${outputBase}_$partialSuffix"
    Write-Warning $(if ($isEnglish) { "Scan cancelled or incomplete. Partial reports will be saved with the _Partial suffix." } else { "Escaneo cancelado o incompleto. Los reportes parciales se guardaran con sufijo _Parcial." })
}

$excelPath = "$exportBase.xlsx"
$allSuffix = if ($isEnglish) { "All" } else { "Todos" }
$activeSuffix = if ($isEnglish) { "Active" } else { "Activos" }
$csvAll = "${exportBase}_$allSuffix.csv"
$csvUp = "${exportBase}_$activeSuffix.csv"
$jsonPath = "${exportBase}.json"
$diffJsonPath = "${outputBase}_Diff.json"

# Se exporta Excel cuando ImportExcel existe; si Excel falla y era el unico formato, se genera CSV de respaldo.
$excelExported = $false
if ($OutputFormat -in @('Excel','All')) {
    $excelExported = Export-ToExcel -DataAll $all -DataUp $activos -Path $excelPath -Language $Language
    if (-not $excelExported) { Write-Warning $(if ($isEnglish) { 'Could not generate Excel with ImportExcel.' } else { 'No se pudo generar Excel con ImportExcel.' }) }
}

$shouldExportCsv = ($OutputFormat -in @('CSV','All')) -or ($OutputFormat -eq 'Excel' -and -not $excelExported)
if ($shouldExportCsv) {
    if ($OutputFormat -eq 'Excel' -and -not $excelExported) {
        Write-Warning $(if ($isEnglish) { 'CSV was generated as a fallback because Excel is not available.' } else { 'Se genero CSV como respaldo porque Excel no esta disponible.' })
    }
    Export-ToCsvFiles -DataAll $all -DataUp $activos -AllPath $csvAll -ActivePath $csvUp -Columns $exportColumns -Language $Language
}
if ($OutputFormat -in @('JSON','All')) {
    $savedJsonPath = Save-JsonFile -Data $all -Path $jsonPath
    Write-Host $(if ($isEnglish) { "Exported JSON: $savedJsonPath" } else { "Exportado JSON: $savedJsonPath" })
}

# La comparacion historica usa el snapshot previo solo si el escaneo termino completo.
$previousSnapshot = $null
if (-not $scanStoppedEarly -and $CompareWithPrevious -and (Test-Path -LiteralPath $SnapshotPath)) {
    try { $previousSnapshot = Get-Content -Raw -LiteralPath $SnapshotPath | ConvertFrom-Json } catch { Write-Warning $(if ($isEnglish) { "Could not read previous snapshot: $SnapshotPath" } else { "No se pudo leer snapshot previo: $SnapshotPath" }) }
}

if (-not $scanStoppedEarly -and $CompareWithPrevious -and $previousSnapshot) {
    $diff = Compare-ScanSnapshots -CurrentData $ordered -PreviousData @($previousSnapshot)
    $savedDiffPath = Save-JsonFile -Data $diff -Path $diffJsonPath
    Write-Host $(if ($isEnglish) { "Historical comparison completed: $savedDiffPath" } else { "Comparacion historica completada: $savedDiffPath" })
    Write-Host $(if ($isEnglish) { ("New: {0} | Down: {1} | Modified: {2}" -f $diff.NewHosts.Count, $diff.DownHosts.Count, $diff.ChangedHosts.Count) } else { ("Nuevos: {0} | Caidos: {1} | Modificados: {2}" -f $diff.NewHosts.Count, $diff.DownHosts.Count, $diff.ChangedHosts.Count) })
}

# El snapshot se actualiza solo con escaneos completos para no guardar estados parciales.
if ($scanStoppedEarly) {
    Write-Warning $(if ($isEnglish) { "Partial scan: snapshot and historical comparison were not updated." } else { "Escaneo parcial: no se actualizo el snapshot ni la comparacion historica." })
} else {
    $savedSnapshotPath = Save-JsonFile -Data $ordered -Path $SnapshotPath
    Write-Host $(if ($isEnglish) { "Snapshot saved: $savedSnapshotPath" } else { "Snapshot guardado: $savedSnapshotPath" })
}
Write-Host $(if ($isEnglish) { "Scan finished. Active: $($activos.Count) / $($all.Count)" } else { "Escaneo finalizado. Activos: $($activos.Count) / $($all.Count)" })
