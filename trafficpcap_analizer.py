import pyshark
import pandas as pd
import os
from datetime import datetime

CAPTURE_DIR = r"C:\Caps"  # o C:\Capturas según tu caso
REPORT_FILE = os.path.join(CAPTURE_DIR, "analisis_pcapS.csv")
DURATION = 7500 # en segs

def analyze_pcap(pcap_file):
    print(f"Analizando: {pcap_file}")
    cap = pyshark.FileCapture(pcap_file, display_filter="ip")

    records = []
    for pkt in cap:
        try:
            src = pkt.ip.src
            dst = pkt.ip.dst
            proto = pkt.highest_layer
            length = int(pkt.length)
            records.append((src, dst, proto, length))
        except AttributeError:
            continue
    cap.close()
    return pd.DataFrame(records, columns=["src", "dst", "proto", "length"])

def detect_suspicious(df):
    if df.empty:
        return []

    alerts = []

    # 1️⃣ Paquetes excesivamente grandes
    big_packets = df[df["length"] > 1500]
    if not big_packets.empty:
        alerts.append(f"[!] Paquetes grandes detectados: {len(big_packets)}")

    # 2️⃣ Conexiones repetidas a un mismo destino
    repeats = df["dst"].value_counts()
    for ip, count in repeats.items():
        if count > 100:
            alerts.append(f"[!] Posible escaneo o flood hacia {ip} ({count} conexiones)")

    # 3️⃣ Protocolos raros (no TCP/UDP/ICMP)
    weird = df[~df["proto"].isin(["TCP", "UDP", "ICMP", "HTTP", "DNS", "TLS"])]
    if not weird.empty:
        alerts.append(f"[!] Protocolos inusuales detectados: {weird['proto'].unique()}")

    return alerts

def main():
    all_pcaps = [f for f in os.listdir(CAPTURE_DIR) if f.endswith(".pcapng")]
    all_pcaps.sort(key=lambda f: os.path.getmtime(os.path.join(CAPTURE_DIR, f)))

    results = []
    for pcap in all_pcaps:
        full_path = os.path.join(CAPTURE_DIR, pcap)
        df = analyze_pcap(full_path)
        alerts = detect_suspicious(df)

        results.append({
            "archivo": pcap,
            "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_paquetes": len(df),
            "alertas": "; ".join(alerts) if alerts else "Sin alertas"
        })

    pd.DataFrame(results).to_csv(REPORT_FILE, index=False)
    print(f"\n✅ Análisis completado. Resultados en: {REPORT_FILE}")

if __name__ == "__main__":
    main()
