# Network Scan PS

> Escaner de red local en PowerShell con menu interactivo, deteccion de equipos, puertos, MAC, fabricante y reportes en Excel, CSV o JSON.

## Tabla de Contenido

- [Descripcion](#descripcion)
- [Caracteristicas](#caracteristicas)
- [Requisitos](#requisitos)
- [Ejecucion Rapida](#ejecucion-rapida)
- [Idioma](#idioma)
- [Parametros](#parametros)
- [Ejemplos](#ejemplos)
- [Reportes](#reportes)
- [Comparacion Historica](#comparacion-historica)
- [Rendimiento](#rendimiento)
- [Seguridad](#seguridad)
- [Solucion de Problemas](#solucion-de-problemas)

## Descripcion

`Network Scan PS` permite escanear una red local para identificar dispositivos activos, nombres de equipo, direcciones MAC, fabricantes, tipo de dispositivo y puertos abiertos.

El script principal es:

```text
Network Scan PS.txt
```

Aunque la extension actual es `.txt`, el contenido es PowerShell. Puedes renombrarlo a `.ps1` si quieres ejecutarlo como script estandar.

## Caracteristicas

- Menu interactivo en espanol o ingles.
- Escaneo automatico desde la interfaz de red activa.
- Escaneo manual por base `/24` o CIDR.
- Modo `Fast` para descubrimiento rapido.
- Modo `Deep` para obtener mas informacion:
  - Puertos TCP abiertos.
  - Nombre PTR.
  - Nombre NetBIOS.
  - Titulo HTTP.
  - Nombre TLS/CN.
  - Banner SSH.
  - MAC.
  - Fabricante.
- Deteccion de fabricante por OUI y por senales del dispositivo.
- Reportes en `Excel`, `CSV`, `JSON` o `All`.
- Comparacion contra snapshot historico.
- Cancelacion con tecla `Q`.
- Guardado robusto si un archivo esta bloqueado por otro proceso.

## Requisitos

- Windows PowerShell 5.1 o PowerShell 7+.
- Windows recomendado para usar:
  - `Get-NetAdapter`
  - `Get-NetNeighbor`
  - `ping.exe`
  - `arp.exe`
  - `nbtstat.exe`
- Modulo opcional `ImportExcel` para generar `.xlsx`.

Instalacion opcional de `ImportExcel`:

```powershell
Install-Module ImportExcel -Scope CurrentUser
```

Si `ImportExcel` no esta disponible y seleccionas `Excel`, el script genera CSV como respaldo.

## Ejecucion Rapida

Abre PowerShell en la carpeta del script:

```powershell
cd "C:\Users\mario.lanzas\OneDrive - Sera Scandia A S\Documentos\Desarrollos\SCAN"
```

Ejecuta el menu:

```powershell
& ".\Network Scan PS.txt" -Menu
```

Si PowerShell bloquea la ejecucion:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\Network Scan PS.txt" -Menu
```

## Idioma

Puedes seleccionar el idioma por parametro:

```powershell
& ".\Network Scan PS.txt" -Language ES -Menu
& ".\Network Scan PS.txt" -Language EN -Menu
```

Tambien puedes cambiarlo dentro del menu:

```text
12. Idioma / Language
```

## Parametros

| Parametro | Valor / Rango | Descripcion |
| --- | --- | --- |
| `-InterfaceName` | Texto | Interfaz de red a usar. Si se omite, se detecta automaticamente. |
| `-NetworkBase` | `192.168.1` o CIDR | Base `/24` o rango CIDR manual. |
| `-CIDR` | CIDR | Rango explicito, por ejemplo `192.168.1.0/24`. |
| `-TimeoutMs` | `200` a `5000` | Timeout por host en milisegundos. |
| `-Throttle` | `10` a `512` | Cantidad maxima de trabajadores concurrentes. |
| `-MaxHosts` | `1` a `65534` | Limite de hosts para evitar rangos demasiado grandes. |
| `-PortsToScan` | Puertos TCP | Puertos a probar en `Mode Deep`. |
| `-Mode` | `Fast` o `Deep` | Profundidad del escaneo. |
| `-Deep` | Switch | Fuerza `Mode Deep`. |
| `-Language` | `ES` o `EN` | Idioma de menu, mensajes y encabezados del reporte. |
| `-Output` | Ruta base | Ruta base para los archivos generados. |
| `-OutputFormat` | `Excel`, `CSV`, `JSON`, `All` | Formato de salida. |
| `-SnapshotPath` | Ruta JSON | Snapshot historico. |
| `-CompareWithPrevious` | Switch | Compara contra el snapshot previo. |
| `-LiveView` | Booleano | Muestra equipos activos en vivo. |
| `-MaxRuntimeSeconds` | `0` a `86400` | Tiempo maximo de ejecucion. `0` significa sin limite. |
| `-Menu` | Switch | Abre el menu interactivo. |

## Ejemplos

### Menu interactivo en espanol

```powershell
& ".\Network Scan PS.txt" -Language ES -Menu
```

### Escaneo rapido de una red

```powershell
& ".\Network Scan PS.txt" `
  -CIDR "192.168.1.0/24" `
  -Mode Fast `
  -OutputFormat CSV
```

### Escaneo profundo con puertos personalizados

```powershell
& ".\Network Scan PS.txt" `
  -CIDR "192.168.1.0/24" `
  -Mode Deep `
  -PortsToScan 22,80,443,445,3389,8080,8443 `
  -OutputFormat All
```

### Reporte en ingles

```powershell
& ".\Network Scan PS.txt" `
  -CIDR "192.168.1.0/24" `
  -Mode Deep `
  -Language EN `
  -OutputFormat CSV `
  -Output ".\Reports\LAN_Scan"
```

### Limitar tiempo de ejecucion

```powershell
& ".\Network Scan PS.txt" `
  -CIDR "192.168.1.0/24" `
  -Mode Deep `
  -MaxRuntimeSeconds 60
```

## Reportes

### Columnas en espanol

```text
IP, NombreEquipo, Activo, Tipo, FuenteNombre, ScoreNombre,
NombrePTR, NombreNBNS, NombreTLS, NombreHTTP, SSHBanner,
PuertosAbiertos, MAC, OUI, Fabricante, FabricanteOUI, FuenteFabricante
```

### Archivos generados

Para `Language ES`:

```text
Scan-LAN_yyyyMMdd_HHmm_Todos.csv
Scan-LAN_yyyyMMdd_HHmm_Activos.csv
Scan-LAN_yyyyMMdd_HHmm.json
Scan-LAN_latest.json
```

Si se cancela el escaneo:

```text
Scan-LAN_yyyyMMdd_HHmm_Parcial_Todos.csv
Scan-LAN_yyyyMMdd_HHmm_Parcial_Activos.csv
```

> Nota: `PuertosAbiertos` solo se llena en `Mode Deep`.

## Comparacion Historica

El script guarda un snapshot en:

```text
.\Scan-LAN_latest.json
```

Si existe un snapshot anterior y `-CompareWithPrevious` esta activo, genera:

```text
Scan-LAN_yyyyMMdd_HHmm_Diff.json
```

Detecta:

- Equipos nuevos.
- Equipos caidos.
- Cambios de nombre.
- Cambios de MAC.

## Rendimiento

- Usa `Mode Fast` para una primera revision rapida.
- Usa `Mode Deep` solo cuando necesites puertos, MAC, fabricante y banners.
- Reduce `-PortsToScan` para acelerar el escaneo profundo.
- Baja `-Throttle` si la red se satura.
- Usa `-MaxHosts` para evitar escanear rangos demasiado grandes por accidente.

## Seguridad

- Ejecuta el script solo en redes propias o autorizadas.
- `Mode Deep` abre conexiones TCP a los puertos configurados.
- No requiere internet; la base OUI/fabricantes es local.
- Las rutas relativas se resuelven contra la carpeta del script para evitar escrituras accidentales en `C:\Windows\System32`.

## Solucion de Problemas

### El JSON esta bloqueado

Si el snapshot esta abierto por otro proceso, el script reintenta guardar. Si sigue bloqueado, crea una copia:

```text
Scan-LAN_latest_bloqueado_yyyyMMdd_HHmmssfff.json
```

### No aparecen puertos abiertos

Verifica que uses `Mode Deep`:

```powershell
& ".\Network Scan PS.txt" -CIDR "192.168.1.0/24" -Mode Deep
```

### No se genera Excel

Instala `ImportExcel` o usa CSV:

```powershell
Install-Module ImportExcel -Scope CurrentUser
```

```powershell
& ".\Network Scan PS.txt" -OutputFormat CSV
```
