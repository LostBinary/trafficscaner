# ================================================================
# trafficscaner.ps1 (v3 - Servicio)
# Descripción: Automatiza capturas Wireshark (dumpcap) + análisis tshark
# Se ejecuta cada 2 horas y limpia logs antiguos (>3 días)
# ================================================================

# --- Configuración general ---
$DumpcapPath = "C:\Program Files\Wireshark\dumpcap.exe"
$TsharkPath  = "C:\Program Files\Wireshark\tshark.exe"
$CaptureDir  = "C:\Caps"
$Iface       = 4          # Número de interfaz (ver con 'dumpcap -D')
$Duration    = 7200       # 2 horas (en segundos)
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

    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
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
        -E header=y -E separator=, | Out-File -Encoding utf8 -FilePath $CsvFile

    Write-Host ">>> [$timestamp] Análisis guardado en $CsvFile"

    # --- Limpiar logs antiguos (>3 días) ---
    Get-ChildItem $CaptureDir -Include *.pcapng,*.csv -Recurse |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$LogDays) } |
        Remove-Item -Force

    Write-Host ">>> [$timestamp] Limpieza completada. Esperando 2 horas..."
    Write-Host "----------------------------------------------------"

    Start-Sleep -Seconds 7200
}
