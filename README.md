# trafficscaner
Es un sniffer/servicio 24/7 que automatiza el monitoreo del tráfico de una interfaz, he añadido un script "check", para revisar el estado del servicio.

//*En desarrollo*//

El ciclo del servicio es:

🟢 Ejecuta dumpcap durante 2 h

🧠 Procesa el .pcapng con tshark → crea el .csv en "C:\Caps"

🧹 Limpia archivos >3 días

😴 Hace un Start-Sleep de 7200 s (2 h)

🔁 Repite desde el paso 1


· Requisitos:
  - Windows 10/11
  - Wireshark (dumpcap y tshark)
  - NSSM
    

· Instalación:
   Ejecuta PowerShell como Administrador y escribe:

         nssm install trafficscaner

   Se abrirá una ventana:

   Path:
          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

   Arguments:
          -ExecutionPolicy Bypass -File "C:\(RUTA)\trafficscaner.ps1"

   Startup directory:
          C:\(RUTA)

   Service name: trafficscaner

   Ahora inicia el servicio:
   
        nssm start trafficscaner
