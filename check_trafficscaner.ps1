# ================================================================
# check-trafficscaner.ps1
# Descripción: Comprueba el estado del servicio trafficscaner,
# Muestra proceso activo, tiempo en ejecución y últimos ficheros generados
# ================================================================
============

$ServiceName = "trafficscaner"
$CaptureDir  = "C:\Caps"

Write-Host "Comprobando servicio $ServiceName ..."

# --- Estado del servicio ---
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($null -ne $service) {
    Write-Host "Estado del servicio: $($service.Status)"
} else {
    Write-Host "El servicio no está instalado o no se encuentra."
    exit
}

# --- Proceso activo (dumpcap) ---
$proc = Get-Process -Name "dumpcap" -ErrorAction SilentlyContinue

if ($null -ne $proc) {
    $startTime = $proc.StartTime
    $uptime = (Get-Date) - $startTime
    Write-Host ""
    Write-Host "Proceso dumpcap.exe activo desde: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Host "Tiempo en ejecución: $([math]::Round($uptime.TotalMinutes,1)) minutos"
} else {
    Write-Host ""
    Write-Host "No hay proceso dumpcap activo actualmente."
}

# --- Últimos archivos generados ---
if (Test-Path $CaptureDir) {
    $latestPcap = Get-ChildItem -Path $CaptureDir -Filter "*.pcapng" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $latestCsv  = Get-ChildItem -Path $CaptureDir -Filter "*.csv" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($null -ne $latestPcap) {
        Write-Host ""
        Write-Host "Último archivo PCAP:"
        Write-Host "    $($latestPcap.Name)  ($([math]::Round($latestPcap.Length / 1KB, 1)) KB)"
        Write-Host "    Fecha: $($latestPcap.LastWriteTime)"
    } else {
        Write-Host ""
        Write-Host "No hay archivos .pcapng aún."
    }

    if ($null -ne $latestCsv) {
        Write-Host ""
        Write-Host "Último informe CSV:"
        Write-Host "    $($latestCsv.Name)  ($([math]::Round($latestCsv.Length / 1KB, 1)) KB)"
        Write-Host "    Fecha: $($latestCsv.LastWriteTime)"
    } else {
        Write-Host ""
        Write-Host "No hay informes CSV generados todavía."
    }
} else {
    Write-Host ""
    Write-Host "No se encontró el directorio de capturas: $CaptureDir"
}

Write-Host ""
Write-Host "Comprobación completada."