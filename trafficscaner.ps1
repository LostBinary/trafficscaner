# ================================================================
# trafficscaner.ps1 (v3 - Servicio)
# Descripción: Automatiza capturas Wireshark (dumpcap) + análisis tshark
# Se ejecuta cada 2 horas y limpia logs antiguos (>3 días)
# ================================================================

# --- Configuración general ---
$DumpcapPath = "C:\Program Files\Wireshark\dumpcap.exe"
$TsharkPath  = "C:\Program Files\Wireshark\tshark.exe"
$CaptureDir  = "C:\Caps"
# Detectar/interfaz: permite override manual (definir $Iface), override por entorno (TRAFFIC_IFACE_INDEX),
# o detección por patrón ($IfacePattern). No pide input interactivo (útil para servicio).
$EnvIface = $null
if ($env:TRAFFIC_IFACE_INDEX) {
    try {
        $EnvIface = [int]$env:TRAFFIC_IFACE_INDEX
    } catch {
        Write-Host "Aviso: la variable de entorno TRAFFIC_IFACE_INDEX no es un entero válido: $($env:TRAFFIC_IFACE_INDEX)"
        $Iface = $null
    }
}

# Opciones de configuración: si quieres forzar una interfaz, asigna $Iface arriba manualmente.
# Patrón por defecto para buscar adaptador (coincide con Name o InterfaceDescription)
$IfacePattern = "(Wi-Fi)"

# Si ya se definió $Iface explícitamente en la configuración, lo respetamos.
if (-not ($PSBoundParameters.ContainsKey('Iface')) -and (-not (Get-Variable -Name Iface -Scope Script -ErrorAction SilentlyContinue))) {
    # No hay override manual en configuración: intentar variable de entorno primero
    if ($EnvIface) {
        $Iface = $EnvIface
        Write-Host "Usando índice de interfaz desde variable de entorno: $Iface"
    } else {
        # Intentar buscar adaptador por patrón en Name o InterfaceDescription
        $Adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceDescription -like "*$IfacePattern*" -or $_.Name -like "*$IfacePattern*" } |
            Select-Object -First 1

        if ($null -ne $Adapter) {
            $Iface = $Adapter.InterfaceIndex
            Write-Host "Seleccionada interfaz '$($Adapter.Name)' (Index $Iface) por patrón '$IfacePattern'."
        } else {
            # Si no hubo coincidencias, intentar elegir la primera interfaz 'Up', si ninguna tomar 1
            $UpAdapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
            if ($null -ne $UpAdapter) {
                $Iface = $UpAdapter.InterfaceIndex
                Write-Host "No se encontró adaptador por patrón '$IfacePattern'. Usando primera interfaz 'Up': '$($UpAdapter.Name)' (Index $Iface)."
            } else {
                $Iface = $IfacePattern
                Write-Host "No se encontraron interfaces activas. Se usará índice por defecto: $Iface. Recomendado configurar manualmente la variable `\$Iface` o TRAFFIC_IFACE_INDEX."
            }
        }
    }
} else {
    # Si $Iface ya estaba definido, mostrarlo
    if (-not $EnvIface) { Write-Host "Usando valor de configuración manual de `\$Iface`: $Iface" }
}

# Número de interfaz (ver con 'dumpcap -D' si es necesario)
# $Iface ya contiene un entero válido en este punto
$Duration    = 60       #  (en segundos)
$Durmiente = 60       #  (en segundos)
$FileSizeKB  = 102400     # 100 MB por archivo
$MaxFiles    = 10         # Número máximo de archivos rotativos
$LogDays     = 3          # Borrar archivos más antiguos de 3 días

# ================================================================
# 🧩 FILTROS BPF (elige uno descomentando la línea que quieras)
# ================================================================

# 🔹 1. Capturar tráfico TCP, UDP e ICMP excepto HTTPS
$CaptureFilter = 'tcp or udp or icmp and not port 443'

# 🔹 2. Solo DNS y HTTP
# $CaptureFilter = 'port 53 or port 80'

# 🔹 3. Todo el tráfico TCP excepto HTTPS
# $CaptureFilter = 'tcp and not port 443'

# 🔹 4. Solo tráfico interno LAN
# $CaptureFilter = 'net 192.168.0.0/16'

# 🔹 5. Diagnóstico (ICMP + ARP)
# $CaptureFilter = 'icmp or arp'

# 🔹 6. SSH y RDP
# $CaptureFilter = 'port 22 or port 3389'

# 🔹 7. Web completa (HTTP + HTTPS + DNS)
# $CaptureFilter = 'port 53 or port 80 or port 443'

# ================================================================

# --- Crear carpeta si no existe ---
if (-not (Test-Path $CaptureDir)) {
    New-Item -ItemType Directory -Force -Path $CaptureDir | Out-Null
}

# --- Bucle infinito ---
while ($true) {

    $timestamp = (Get-Date).ToString("ddMMyyyy_HHmmss")
    $PcapFile  = Join-Path $CaptureDir "capture_$timestamp.pcapng"
    $CsvFile   = Join-Path $CaptureDir "report_$timestamp.csv"

    Write-Host ">>> [$timestamp] Iniciando captura..."
    Write-Host ">>> Usando filtro: $CaptureFilter"

    # --- Iniciar captura ---
    Start-Process -FilePath $DumpcapPath `
        -ArgumentList "-i $Iface -a duration:$Duration -b filesize:$FileSizeKB -b files:$MaxFiles -f `"$CaptureFilter`" -w `"$PcapFile`"" `
        -NoNewWindow -Wait

    Write-Host ">>> [$timestamp] Captura finalizada. Analizando..."

    # --- Analizar con tshark ---
    & $TsharkPath -r $PcapFile -Y "dns or http" -T fields `
        -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -e dns.qry.name -e http.host `
        -E header=y -E separator=',' | Out-File -Encoding utf8 -FilePath $CsvFile

    Write-Host ">>> [$timestamp] Análisis guardado en $CsvFile"

    # --- Limpiar logs antiguos (>3 días) ---
    Get-ChildItem $CaptureDir -Include *.pcapng,*.csv -Recurse |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$LogDays) } |
        Remove-Item -Force

    Write-Host ">>> [$timestamp] Análisis completado. En reposo "$Durmiente" segs."
    Write-Host "----------------------------------------------------"

    Start-Sleep -Seconds $Durmiente
}
